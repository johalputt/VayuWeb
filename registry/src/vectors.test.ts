import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { buildVectors, fromHex, type Vector } from './vectors.ts';
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
          return predecessorFrom(parseRecordBytes(bytes), bytes);
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
