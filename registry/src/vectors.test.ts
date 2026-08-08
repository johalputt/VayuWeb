import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  buildVectors,
  buildConvergenceVectors,
  buildReplicationVectors,
  buildBlockExchangeVectors,
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
import { compareBytes, decode, encode, type CborMap, type CborValue } from './cbor.ts';
import {
  verify,
  predecessorFrom,
  VERIFY_REJECTIONS,
  type RegistryView,
  type Verdict,
} from './verify.ts';
import { parseRecordBytes } from './record.ts';
import { baseBits, requiredBits, rateWindow, powSalt, tagSatisfies, RATE_FLOOR } from './pow.ts';
import { BlockExchangeError, decodeBlockMessage, encodeBlockMessage } from './blockx.ts';

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
    // The VALUE is compared as well as the type, where the vector names one. Comparing only the
    // type is why a record carrying two `cid` entries had no expressible answer here, and two
    // conforming implementations could fetch different content from the same signed record with
    // the whole suite green.
    const selected =
      outcome.ok && outcome.entry.value instanceof Uint8Array ? toHex(outcome.entry.value) : null;
    const actual = outcome.ok
      ? `ok:${outcome.entry.type}${vector.expect.outcome === 'ok' && vector.expect.value !== undefined ? `:${selected}` : ''}`
      : `error:${outcome.error}`;
    const want =
      vector.expect.outcome === 'ok'
        ? `ok:${vector.expect.source}${vector.expect.value !== undefined ? `:${vector.expect.value}` : ''}`
        : `error:${vector.expect.code}`;
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

test('every block-exchange vector decodes, or is refused with the code VWIP-0005 names', () => {
  const failures: string[] = [];
  for (const vector of buildBlockExchangeVectors()) {
    // A vector published as a recipe is built here, exactly as a second implementation would
    // build it. The alternative is 2.1 MB of hex zeros in the artifact, of which every byte after
    // the first carries no information — see BlockExchangeVector.construct.
    const bytes =
      vector.message !== undefined
        ? fromHex(vector.message)
        : encode(
            new Map<string | Uint8Array, CborValue>([
              ['t', 'BLOCKS'],
              [
                'blks',
                Array.from(
                  { length: vector.construct!.count },
                  () => new Uint8Array(vector.construct!.bytes),
                ),
              ],
            ]),
          );

    let actual: string;
    try {
      actual = `ok:${decodeBlockMessage(bytes).t}`;
    } catch (error) {
      actual =
        error instanceof BlockExchangeError ? `reject:${error.code}` : `threw:${String(error)}`;
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

test('AUDIT: BDONE has no field that could vary with what a peer holds', () => {
  // VWIP-0005 6.2: a peer that lacks a block and one that declines to send it emit the identical
  // message, because a distinguishable refusal is an oracle for enumerating what a machine hosts.
  //
  // **The obvious test for this is a tautology and was written first.** Comparing the two
  // published vectors byte for byte compares two identical calls to the same encoder — it passes
  // no matter what the encoder does, and a mutation that added a `why: "absent"` field to BDONE
  // sailed through it, because the field was added to both. The property is not that two equal
  // things are equal. It is that the message type has NOWHERE to put the difference.
  //
  // So the assertion is structural: BDONE's encoding carries exactly `t` and `cids`, and any new
  // key is a channel for the state the specification says must not be observable.
  const encoded = encodeBlockMessage({ t: 'BDONE', cids: [new Uint8Array(36).fill(7)] });
  const decoded = decode(encoded);
  assert.ok(decoded instanceof Map);
  assert.deepEqual([...decoded.keys()].sort(), ['cids', 't']);

  // The published pair must still agree, because for a SECOND implementation the two vectors are
  // built from genuinely different peer states and matching bytes is the contract. Asserted
  // against the committed artifact, which is the file such an implementation reads.
  const artifact = JSON.parse(readFileSync(ARTIFACT, 'utf8')) as {
    blockExchange: { name: string; message?: string }[];
  };
  const held = artifact.blockExchange.find((v) => v.name === 'blockx/bdone-held');
  const absent = artifact.blockExchange.find((v) => v.name === 'blockx/bdone-absent');
  assert.ok(held?.message, 'blockx/bdone-held must be in the artifact');
  assert.ok(absent?.message, 'blockx/bdone-absent must be in the artifact');
  assert.equal(held.message, absent.message);
  assert.ok(held.message.length > 16, 'not vacuously equal because both are empty');
  assert.equal(decodeBlockMessage(fromHex(held.message)).t, 'BDONE');
});

test('the committed artifact carries all seven suites', () => {
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
    'blockExchange',
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
  assert.deepEqual(artifact['blockExchange'], buildBlockExchangeVectors());
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

/* -------------------------------------------------------------------------- */
/* The artifact has to stand on its own                                        */
/* -------------------------------------------------------------------------- */

test('AUDIT: every field a runner must act on is explained inside the artifact', () => {
  // `docs/ROADMAP.md` tells contributors that `conformance/vectors.json` "is readable without any
  // of this repository". That is the artifact's entire reason to exist — it is a contract for a
  // second implementation, and a contract whose terms are defined in the other party's source code
  // is not one.
  //
  // The claim went stale the moment a `construct` recipe was added to the block-exchange suite. A
  // reader outside this repository meets `{"kind":"blocks-of-zeros","count":1,"bytes":1048577}`
  // with no `message` beside it and no statement anywhere of what to build from it. The vector is
  // not wrong; it is unusable, which for a conformance artifact is the same thing.
  //
  // Every test in this file until now imported the generator and the decoder, so all of them
  // proved the implementation agrees with ITSELF. This one deliberately reads nothing but the
  // file.
  const artifact = JSON.parse(readFileSync(ARTIFACT, 'utf8')) as Record<string, unknown>;
  const notes = artifact['notes'] as Record<string, string>;
  const prose = Object.values(notes).join('\n');

  // A suite is an array OF VECTORS, and a vector is an object with a name. "Any top-level array"
  // was the first rule here and it was wrong the moment `generatedFor` became a list of source
  // documents — the same loose heuristic that made `scripts/check-counts.py` announce an eighth
  // suite and fail two accurate sentences.
  const suites = Object.entries(artifact).filter(
    ([, v]) =>
      Array.isArray(v) &&
      v.length > 0 &&
      v.every((e) => typeof e === 'object' && e !== null && 'name' in e),
  ) as [string, Record<string, unknown>[]][];
  assert.equal(suites.length, 7, 'the artifact carries exactly its seven vector suites');

  // Every recipe kind a runner would have to implement is named in the notes.
  const kinds = new Set<string>();
  for (const [, vectors] of suites) {
    for (const vector of vectors) {
      const construct = vector['construct'] as { kind?: string } | undefined;
      if (construct?.kind !== undefined) kinds.add(construct.kind);
    }
  }
  assert.ok(kinds.size > 0, 'this check is vacuous unless at least one recipe exists');
  for (const kind of kinds) {
    assert.ok(
      prose.includes(kind),
      `a runner must build "${kind}" and the artifact never says what it is`,
    );
  }

  // A vector carries either the bytes or a recipe. Neither is a vector nobody can run.
  for (const [suite, vectors] of suites) {
    for (const vector of vectors) {
      if (suite !== 'blockExchange' && suite !== 'replication') continue;
      assert.ok(
        vector['message'] !== undefined || vector['construct'] !== undefined,
        `${suite}/${String(vector['name'])} carries neither a message nor a recipe`,
      );
    }
  }

  // And the document pointer must name the documents the suites actually come from. It said
  // `docs/spec/REGISTRY.md` while the file carried vectors for six other specifications — true
  // when written, and steadily less true afterwards, which is this corpus's most reliable defect.
  const generatedFor = artifact['generatedFor'];
  assert.ok(Array.isArray(generatedFor), 'generatedFor must name every source document');
  for (const doc of [
    'REGISTRY.md',
    'RESOLUTION.md',
    'REPLICATION.md',
    'PROOF-OF-WORK.md',
    'VWIP-0005.md',
  ]) {
    assert.ok(
      (generatedFor as string[]).some((d) => d.endsWith(doc)),
      `generatedFor omits ${doc}, which has vectors in this file`,
    );
  }
});

test('AUDIT: no published BWANT vector names the same identifier twice', () => {
  // **The artifact published the attack VWIP-0005 3.6.a was written to close, marked valid.**
  //
  // `blockx/bwant-at-the-limit` was `Array.from({length: 64}, () => cid)` — sixty-four copies of
  // ONE identifier, which 3.6.a describes in as many words as "a request for one block and a
  // demand for sixty-four, inside a message that passes every limit in section 5". Its `expect`
  // was `{decode: 'ok'}`, and `conformance/README.md` says of that column: "The verdict every
  // conforming implementation must return." So the artifact made 3.6.a's own recommended
  // mitigation — "A receiver MAY refuse a `BWANT` containing a repeat" — a conformance failure.
  //
  // The neighbouring over-limit vector was 65 copies of the same identifier, which additionally
  // forbade the natural implementation of 3.6.a: deduplicate, then bound. After dedup that message
  // names one identifier and must be accepted, while the vector demands LIMIT_EXCEEDED. A second
  // implementer following both could not write a conforming receiver at all.
  //
  // The in-repo test that was meant to cover this asserted on the document's prose — `MUST NOT
  // name the same identifier twice` appears in VWIP-0005 — while the artifact next to it did the
  // opposite. A vector set that names types rather than values is the recurring shape here.
  const artifact = JSON.parse(readFileSync(ARTIFACT, 'utf8')) as {
    blockExchange: { name: string; message?: string }[];
  };
  let checked = 0;
  for (const vector of artifact.blockExchange) {
    if (vector.message === undefined) continue;
    let decoded: unknown;
    try {
      decoded = decode(fromHex(vector.message));
    } catch {
      continue; // A vector that is deliberately not decodable has nothing to say here.
    }
    if (!(decoded instanceof Map)) continue;
    if (decoded.get('t') !== 'BWANT' && decoded.get('t') !== 'BDONE') continue;
    const cids = decoded.get('cids');
    assert.ok(Array.isArray(cids), `${vector.name} must carry an identifier array`);
    const seen = new Set(cids.map((c) => String(c)));
    assert.equal(
      seen.size,
      cids.length,
      `${vector.name} names ${cids.length - seen.size} repeated identifier(s), which 3.6.a forbids`,
    );
    checked += 1;
  }
  // Without this the test passes on an artifact with no identifier list in it at all, which is
  // the same failure mode as the check it replaces.
  assert.ok(checked >= 3, `only ${checked} identifier-carrying vectors were examined`);
});
