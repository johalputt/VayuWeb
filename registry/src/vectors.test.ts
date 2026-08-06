import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  buildVectors,
  buildConvergenceVectors,
  buildReplicationVectors,
  buildResolutionVectors,
  fromHex,
  type Vector,
} from './vectors.ts';
import { resolveConflict, type Candidate } from './converge.ts';
import { resolveName } from './resolve.ts';
import { decodeMessage, ReplicationError } from './replicate.ts';
import { recordHashFromBytes } from './domain.ts';
import { compareBytes } from './cbor.ts';
import { verify, predecessorFrom, type RegistryView, type Verdict } from './verify.ts';
import { parseRecordBytes } from './record.ts';

const ARTIFACT = fileURLToPath(new URL('../../conformance/vectors.json', import.meta.url));

/**
 * Run one vector exactly as an independent implementation would: bytes in, verdict out, with
 * registry state supplied from the vector rather than from any local log.
 */
function run(vector: Vector): Verdict {
  const predecessor =
    vector.state.predecessor === null
      ? null
      : (() => {
          const bytes = fromHex(vector.state.predecessor);
          const transferor = vector.state.transferorKey;
          return predecessorFrom(
            parseRecordBytes(bytes),
            bytes,
            transferor === undefined ? undefined : fromHex(transferor),
          );
        })();

  const view: RegistryView = {
    current: () => predecessor,
    fullyReleased: () => vector.state.fullyReleased,
    revoked: () => vector.state.revoked,
    powVerified: () => vector.state.powVerified,
  };

  return verify(fromHex(vector.record), view, vector.now);
}

const describe = (v: Verdict): string =>
  v.outcome === 'accept'
    ? 'accept'
    : v.outcome === 'defer'
      ? `defer:${v.reason}`
      : `reject:${v.code}`;

const expected = (v: Vector): string =>
  v.expect.outcome === 'accept'
    ? 'accept'
    : v.expect.outcome === 'defer'
      ? `defer:${v.expect.reason}`
      : `reject:${v.expect.code}`;

/* -------------------------------------------------------------------------- */

test('every vector produces the verdict the specification requires', () => {
  const failures: string[] = [];
  for (const vector of buildVectors()) {
    const actual = describe(run(vector));
    if (actual !== expected(vector)) {
      failures.push(
        `${vector.name}\n      rule:     ${vector.rule}` +
          `\n      expected: ${expected(vector)}\n      actual:   ${actual}`,
      );
    }
  }
  assert.deepEqual(failures, [], `\n  ${failures.join('\n  ')}\n`);
});

test('the committed vector artifact matches what this implementation generates', () => {
  // The artifact is the interoperability contract: another implementation is tested against
  // the committed file, not against this code. If an encoding rule changes, the diff has to be
  // visible in the file, because every implementation built against it needs to know.
  const onDisk = JSON.parse(readFileSync(ARTIFACT, 'utf8')) as { vectors: Vector[] };
  const generated = buildVectors();

  assert.equal(
    onDisk.vectors.length,
    generated.length,
    'vector count differs — regenerate with: npm run vectors',
  );

  for (let i = 0; i < generated.length; i += 1) {
    assert.deepEqual(
      onDisk.vectors[i],
      generated[i],
      `vector ${generated[i]!.name} differs from the committed artifact — ` +
        'regenerate with: npm run vectors',
    );
  }
});

test('the vector set covers every rejection code the verifier can return', () => {
  // A vector set that silently stops covering a rule is worse than a smaller one that says so.
  // This fails when a new rejection code is added without a vector to pin it.
  const covered = new Set(
    buildVectors().map((v) => (v.expect.outcome === 'reject' ? v.expect.code : v.expect.outcome)),
  );

  const mustCover = [
    'NON_CANONICAL',
    'UNSUPPORTED_VERSION',
    'UNKNOWN_OP',
    'BAD_LABEL',
    'UNKNOWN_TLD',
    'BAD_KEY',
    'BAD_TERM',
    'BAD_CHAIN',
    'BAD_SEQ',
    'BAD_RECORD_ENTRY',
    'BAD_POW_SHAPE',
    'UNEXPECTED_POW',
    'BAD_COSIG',
    'NAME_TAKEN',
    'BACKDATED',
    'BAD_SIG',
    'BAD_POW',
    'NO_PREDECESSOR',
    'TOO_SOON',
    'REVOKED',
    'BAD_OWNER',
    'EXPIRED',
  ];

  const missing = mustCover.filter((code) => !covered.has(code));
  assert.deepEqual(missing, [], `rejection codes with no vector: ${missing.join(', ')}`);
});

test('the vector set covers accept and defer, not only rejection', () => {
  const outcomes = new Set(buildVectors().map((v) => v.expect.outcome));
  assert.ok(outcomes.has('accept'), 'a suite that only refuses things cannot detect over-refusal');
  assert.ok(outcomes.has('defer'), 'deferral is a third verdict and must be pinned too');
});

test('vector names are unique, so a failure names exactly one case', () => {
  const names = buildVectors().map((v) => v.name);
  assert.equal(new Set(names).size, names.length);
});

/* -------------------------------------------------------------------------- */
/* The three suites that pin what implementations must AGREE about             */
/* -------------------------------------------------------------------------- */

test('every convergence vector picks the same winner, whichever way round it is given', () => {
  // The pair and its mirror. An implementation that decided by argument position, by arrival, or
  // by its own log index gives one answer to the first and a different answer to the second —
  // which is exactly the fork that shipped here and survived every record vector.
  const failures: string[] = [];
  for (const vector of buildConvergenceVectors()) {
    const a = candidate(vector.a);
    const b = candidate(vector.b);
    const resolution = resolveConflict([a, b]);
    const winner = compareBytes(resolution.winner.hash, a.hash) === 0 ? 'a' : 'b';
    if (winner !== vector.expect.winner || resolution.rule !== vector.expect.rule) {
      failures.push(
        `${vector.name}\n      rule:     ${vector.rule}` +
          `\n      expected: ${vector.expect.winner} by ${vector.expect.rule}` +
          `\n      actual:   ${winner} by ${resolution.rule}`,
      );
    }
  }
  assert.deepEqual(failures, []);
});

test('every resolution vector returns the outcome the specification requires', () => {
  const failures: string[] = [];
  for (const vector of buildResolutionVectors()) {
    const record = vector.record === null ? null : parseRecordBytes(fromHex(vector.record));
    const outcome = resolveName(
      vector.host,
      { lookup: () => record, hasVerifiedHead: () => vector.hasVerifiedHead },
      vector.now,
    );
    const actual = outcome.ok ? `ok:${outcome.entry.type}` : `error:${outcome.error}`;
    const want =
      vector.expect.outcome === 'ok' ? `ok:${vector.expect.source}` : `error:${vector.expect.code}`;
    if (actual !== want) {
      failures.push(
        `${vector.name}\n      rule:     ${vector.rule}` +
          `\n      expected: ${want}\n      actual:   ${actual}`,
      );
    }
  }
  assert.deepEqual(failures, []);
});

test('every replication vector decodes, or is refused with the code the specification names', () => {
  const failures: string[] = [];
  for (const vector of buildReplicationVectors()) {
    let actual: string;
    try {
      actual = `ok:${decodeMessage(fromHex(vector.message)).t}`;
    } catch (error) {
      actual =
        error instanceof ReplicationError ? `reject:${error.code}` : `threw:${String(error)}`;
    }
    const want =
      vector.expect.decode === 'ok' ? `ok:${vector.expect.type}` : `reject:${vector.expect.code}`;
    if (actual !== want) {
      failures.push(
        `${vector.name}\n      rule:     ${vector.rule}` +
          `\n      expected: ${want}\n      actual:   ${actual}`,
      );
    }
  }
  assert.deepEqual(failures, []);
});

test('the committed artifact carries all four suites', () => {
  // A suite that exists in code and not in the artifact is a suite no second implementation can
  // run, which makes it a test of this implementation rather than a contract between two.
  const artifact = JSON.parse(readFileSync(ARTIFACT, 'utf8')) as Record<string, unknown>;
  for (const suite of ['vectors', 'convergence', 'resolution', 'replication']) {
    assert.ok(Array.isArray(artifact[suite]), `${suite} must be an array in the artifact`);
    assert.ok((artifact[suite] as unknown[]).length > 0, `${suite} must not be empty`);
  }
});

/** Build a convergence candidate from a record's hex, as a second implementation would. */
function candidate(hex: string): Candidate {
  const bytes = fromHex(hex);
  return {
    record: parseRecordBytes(bytes),
    hash: recordHashFromBytes(bytes),
    // Deliberately null. A vector cannot carry a local log position, and the whole point of the
    // convergence contract is that no implementation needs one.
    logIndex: null,
    valid: true,
  };
}
