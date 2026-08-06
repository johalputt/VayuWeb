import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  buildVectors,
  buildConvergenceVectors,
  buildReplicationVectors,
  buildResolutionVectors,
  buildEquivocationVectors,
  buildPowVectors,
  fromHex,
  toHex,
  type Vector,
  type PowVector,
} from './vectors.ts';
import { resolveConflict, type Candidate } from './converge.ts';
import { resolveName } from './resolve.ts';
import { decodeMessage, verifyEquivocation, ReplicationError } from './replicate.ts';
import { recordHashFromBytes } from './domain.ts';
import { compareBytes, decode, type CborMap } from './cbor.ts';
import {
  verify,
  predecessorFrom,
  VERIFY_REJECTIONS,
  type RegistryView,
  type Verdict,
} from './verify.ts';
import { parseRecordBytes } from './record.ts';
import { baseBits, requiredBits, rateWindow, powSalt, tagSatisfies, RATE_FLOOR } from './pow.ts';

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
  //
  // This list used to be typed out by hand, and it passed because it only asked about the 22
  // codes somebody remembered — six were absent from both the list and the artifact
  // (`NOT_A_MAP`, `MISSING_FIELD`, `BAD_FIELD_TYPE`, `TOO_MANY_RECORDS`, `MISSING_POW`,
  // `TOO_LARGE`), all six genuinely returnable, while `conformance/README.md` claimed "at least
  // one vector for every rejection code the verifier can return — a test fails if a code is
  // added without one". The test that was supposed to make that true was the reason it was
  // false: a hand-written expectation cannot detect the thing it forgot.
  //
  // It is now derived from the codes themselves, so adding one without a vector fails here.
  const covered = new Set(
    buildVectors().map((v) => (v.expect.outcome === 'reject' ? v.expect.code : v.expect.outcome)),
  );

  // Exemptions are named, with a reason, and there is exactly one. A code that cannot be reached
  // on the wire today is not a coverage gap; a code with no reason written down is.
  const exempt = new Map<string, string>([
    [
      'SUITE_DOWNGRADE',
      'a vector states its predecessor as bytes, and CRYPTO-AGILITY.md 4.2 makes a record naming ' +
        'an inactive suite unparseable — so the suite-3 predecessor a downgrade needs is not a ' +
        'record any conforming peer can hold. Unit-tested against a constructed predecessor; the ' +
        'VWIP that activates a second suite must add the wire vector.',
    ],
  ]);

  const missing = VERIFY_REJECTIONS.filter((code) => !covered.has(code) && !exempt.has(code));
  assert.deepEqual(missing, [], `rejection codes with no vector: ${missing.join(', ')}`);

  // An exemption for a code that is now covered, or that no longer exists, is a stale excuse.
  for (const [code, why] of exempt) {
    assert.ok(
      (VERIFY_REJECTIONS as readonly string[]).includes(code),
      `${code} is exempted but is no longer a rejection code`,
    );
    assert.equal(covered.has(code), false, `${code} has a vector now — drop the exemption: ${why}`);
  }
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
/* The five suites that pin what implementations must AGREE about              */
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

test('every equivocation vector is judged the same way by every implementation', () => {
  // The suite the record vectors are structurally blind to. Neither half of a forged report is a
  // record any verifier would accept, and neither half of a genuine one need be either — so what
  // separates them is a question no record vector asks. Two implementations answering it
  // differently do not merely disagree about a code: one of them republishes, at every peer it
  // talks to, that a name of the attacker's choosing is compromised.
  const failures: string[] = [];
  for (const vector of buildEquivocationVectors()) {
    const actual = verifyEquivocation({
      t: 'EQUIVOCATION',
      a: fromHex(vector.a),
      b: fromHex(vector.b),
    });
    if (actual !== vector.expect.equivocation) {
      failures.push(
        `${vector.name}\n      rule:     ${vector.rule}` +
          `\n      expected: ${vector.expect.equivocation}\n      actual:   ${actual}`,
      );
    }
  }
  assert.deepEqual(failures, [], `\n  ${failures.join('\n  ')}\n`);
});

test('the equivocation suite pins both answers, not only refusals', () => {
  // A suite of nothing but forgeries passes against an implementation that never reports
  // anything, which is the failure mode this whole area has: under-reporting is silent.
  const answers = new Set(buildEquivocationVectors().map((v) => v.expect.equivocation));
  assert.ok(answers.has(true), 'evidence that IS equivocation must be pinned');
  assert.ok(answers.has(false), 'and evidence that is not');
});

test('every proof-of-work vector produces the value the specification requires', () => {
  // Read from the COMMITTED artifact, not from `buildPowVectors()`. A second implementation runs
  // against the file, so running against the file is the only version of this test that means
  // what it says — and the salt vector, which is the one expectation a human cannot transcribe
  // from the specification, is pinned by nothing else.
  const onDisk = JSON.parse(readFileSync(ARTIFACT, 'utf8')) as { pow: PowVector[] };
  const failures: string[] = [];
  for (const vector of onDisk.pow) {
    let actual: unknown;
    switch (vector.check) {
      case 'baseBits':
        actual = baseBits(vector.labelLength);
        break;
      case 'requiredBits':
        actual = requiredBits(vector.labelLength, vector.windowCount);
        break;
      case 'rateWindow':
        actual = rateWindow(vector.notBefore);
        break;
      case 'salt':
        actual = toHex(powSalt(decode(fromHex(vector.record)) as CborMap));
        break;
      case 'tagSatisfies':
        actual = tagSatisfies(fromHex(vector.tag), vector.bits);
        break;
    }
    let same: boolean;
    try {
      assert.deepEqual(actual, vector.expect);
      same = true;
    } catch {
      same = false;
    }
    if (!same) {
      failures.push(
        `${vector.name}\n      rule:     ${vector.rule}` +
          `\n      expected: ${JSON.stringify(vector.expect)}` +
          `\n      actual:   ${JSON.stringify(actual)}`,
      );
    }
  }
  assert.deepEqual(failures, [], `\n  ${failures.join('\n  ')}\n`);
});

test('the rate term never depends on how accurate a language’s log2 is', () => {
  // PROOF-OF-WORK.md 4 writes the rate as `floor(log2(n / 512))`. `log2` is
  // implementation-approximated in most languages — ECMAScript requires only that it be an
  // implementation-approximated function, and the same is true of C, Python and Go. A result one
  // ulp below an integer at an exact doubling floors to one less, which is a one-bit difficulty
  // DISAGREEMENT between two peers that both believe they conform: one rejects a record the
  // other accepted, permanently, on a record that is otherwise entirely valid.
  //
  // This implementation happens to agree across the whole reachable range, and that is a fact to
  // be established rather than assumed — the vectors pin the boundaries for everyone else, and
  // this test pins the range for this one.
  const exact = (n: number): number => {
    if (n < RATE_FLOOR) return 0;
    // Integer-only: how many times can n be halved before it drops below the floor.
    let doublings = 0;
    let value = Math.floor(n / RATE_FLOOR);
    while (value >= 2) {
      value = Math.floor(value / 2);
      doublings += 1;
    }
    return Math.min(8, doublings);
  };

  const disagreements: string[] = [];
  // Past the eighth doubling the clamp makes them agree trivially, so the range that matters is
  // the one below it, walked exhaustively rather than sampled.
  for (let n = 0; n <= RATE_FLOOR * 300; n += 1) {
    const viaFloat = requiredBits(16, n) - baseBits(16);
    if (viaFloat !== exact(n)) {
      disagreements.push(`n=${n}: float ${viaFloat}, integer ${exact(n)}`);
    }
  }
  assert.deepEqual(disagreements.slice(0, 5), []);
});

test('the committed artifact carries all six suites', () => {
  // A suite that exists in code and not in the artifact is a suite no second implementation can
  // run, which makes it a test of this implementation rather than a contract between two.
  const artifact = JSON.parse(readFileSync(ARTIFACT, 'utf8')) as Record<string, unknown>;
  for (const suite of [
    'vectors',
    'convergence',
    'resolution',
    'replication',
    'equivocation',
    'pow',
  ]) {
    assert.ok(Array.isArray(artifact[suite]), `${suite} must be an array in the artifact`);
    assert.ok((artifact[suite] as unknown[]).length > 0, `${suite} must not be empty`);
  }

  // And the artifact's own copy must match, not merely exist. The record suite has had this check
  // since the beginning; the three that pin agreement did not, so a generator change could move
  // their bytes without the diff appearing in the committed file.
  assert.deepEqual(artifact['equivocation'], buildEquivocationVectors());
  assert.deepEqual(artifact['pow'], buildPowVectors());
  assert.deepEqual(artifact['convergence'], buildConvergenceVectors());
  assert.deepEqual(artifact['resolution'], buildResolutionVectors());
  assert.deepEqual(artifact['replication'], buildReplicationVectors());
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
