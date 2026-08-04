import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  compareHashes,
  conflicts,
  isEquivocation,
  resolveConflict,
  voidedChain,
  ConvergeError,
  type Candidate,
} from './converge.ts';
import { parseRecord, type RegistryRecord } from './record.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH } from './pow.ts';
import { type CborMap, type CborValue } from './cbor.ts';

const NOW = 1_782_518_400;
const TERM = 31_536_000;

const OWNER_A = new Uint8Array(32).fill(0x11);
const OWNER_B = new Uint8Array(32).fill(0x22);

const pow = (): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['alg', POW_ALGORITHM],
    ['nonce', new Uint8Array(POW_NONCE_LENGTH).fill(7)],
    ['bits', 10],
  ]);

function rec(over: Record<string, CborValue> = {}): RegistryRecord {
  const m = new Map<string | Uint8Array, CborValue>([
    ['version', 1],
    ['op', 'REGISTER'],
    ['name', 'atlas'],
    ['tld', 'vayu'],
    ['ownerKey', OWNER_A],
    ['seq', 0],
    ['notBefore', NOW],
    ['notAfter', NOW + TERM],
    ['records', []],
    ['powProof', pow()],
    ['prevHash', new Uint8Array(32)],
    ['sig', new Uint8Array(64).fill(0xaa)],
  ]);
  for (const [k, v] of Object.entries(over)) m.set(k, v);
  return parseRecord(m);
}

const hash = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

const cand = (
  h: number,
  over: Record<string, CborValue> = {},
  logIndex: number | null = null,
  valid = true,
): Candidate => ({ record: rec(over), hash: hash(h), logIndex, valid });

/* -------------------------------------------------------------------------- */
/* The tie-break comparison                                                    */
/* -------------------------------------------------------------------------- */

test('hashes compare as big-endian unsigned integers', () => {
  // Normative phrasing. An implementation comparing them as signed bytes would order 0x80..
  // before 0x01.., disagreeing with everyone else at precisely the tie-break — a permanent fork
  // at the one point the protocol is already undecidable.
  const low = new Uint8Array(32);
  low[0] = 0x01;
  const high = new Uint8Array(32);
  high[0] = 0x80;
  assert.ok(compareHashes(low, high) < 0, '0x01.. must sort before 0x80..');

  // The most significant byte dominates, whatever follows it.
  const a = new Uint8Array(32);
  a[0] = 0x02;
  const b = new Uint8Array(32).fill(0xff);
  b[0] = 0x01;
  assert.ok(compareHashes(b, a) < 0);

  assert.equal(compareHashes(hash(5), hash(5)), 0);
});

test('comparing hashes of different lengths is an error, not a verdict', () => {
  assert.throws(() => compareHashes(new Uint8Array(32), new Uint8Array(31)), ConvergeError);
});

/* -------------------------------------------------------------------------- */
/* What counts as a conflict                                                   */
/* -------------------------------------------------------------------------- */

test('a conflict is two different records at the same seq for one name', () => {
  assert.ok(conflicts(cand(1), cand(2)));
});

test('identical records are not a conflict — a duplicate is dropped silently', () => {
  assert.equal(conflicts(cand(1), cand(1)), false);
});

test('different seq is a chain, not a fork', () => {
  const a = cand(1);
  const b = cand(2, { seq: 1, prevHash: hash(1) });
  assert.equal(conflicts(a, b), false);
});

test('different names never conflict, however similar', () => {
  assert.equal(conflicts(cand(1), cand(2, { name: 'zenith' })), false);
  assert.equal(conflicts(cand(1), cand(2, { tld: 'p2p' })), false);
});

/* -------------------------------------------------------------------------- */
/* Equivocation                                                                */
/* -------------------------------------------------------------------------- */

test('equivocation is one owner signing two futures for one name', () => {
  // Distinct from an honest partition conflict, where two DIFFERENT owners each registered a
  // free name and neither did anything wrong.
  assert.ok(isEquivocation(cand(1), cand(2)), 'same owner, same seq, different records');
  assert.equal(
    isEquivocation(cand(1), cand(2, { ownerKey: OWNER_B })),
    false,
    'two owners racing for a free name is not equivocation',
  );
  assert.equal(isEquivocation(cand(1), cand(1)), false, 'a duplicate is not equivocation');
});

/* -------------------------------------------------------------------------- */
/* The three rules, in order                                                   */
/* -------------------------------------------------------------------------- */

test('rule 1: if exactly one is valid, that one wins whatever its hash', () => {
  // The invalid candidate has the smaller hash, so rule 3 would pick it. Rule 1 must run first.
  const invalidLowHash = cand(1, {}, 0, false);
  const validHighHash = cand(9, { ownerKey: OWNER_B }, 1, true);
  const r = resolveConflict([invalidLowHash, validHighHash]);
  assert.equal(r.rule, 'SOLE_VALID');
  assert.deepEqual(r.winner.hash, hash(9));
  assert.equal(r.losers.length, 1);
});

test('rule 2: the earlier linearised position wins, even with a larger hash', () => {
  const earlyHighHash = cand(9, {}, 3, true);
  const lateLowHash = cand(1, { ownerKey: OWNER_B }, 7, true);
  const r = resolveConflict([lateLowHash, earlyHighHash]);
  assert.equal(r.rule, 'EARLIER_IN_LOG');
  assert.deepEqual(r.winner.hash, hash(9));
});

test('rule 2 is skipped when any candidate has no linearised position', () => {
  // A peer that has not linearised both cannot know the order agrees everywhere. Guessing from
  // arrival order is exactly how two peers reach different answers about the same pair.
  const positioned = cand(9, {}, 3, true);
  const unpositioned = cand(1, { ownerKey: OWNER_B }, null, true);
  const r = resolveConflict([positioned, unpositioned]);
  assert.equal(r.rule, 'SMALLER_HASH');
  assert.deepEqual(r.winner.hash, hash(1));
});

test('rule 2 requires STRICTLY earlier: a tie falls through to the hash', () => {
  const a = cand(9, {}, 4, true);
  const b = cand(1, { ownerKey: OWNER_B }, 4, true);
  const r = resolveConflict([a, b]);
  assert.equal(r.rule, 'SMALLER_HASH');
  assert.deepEqual(r.winner.hash, hash(1));
});

test('rule 3: the smaller hash wins, and the result never depends on arrival order', () => {
  // The property that matters: two peers receiving the same pair in opposite orders must agree.
  const a = cand(3, {}, null, true);
  const b = cand(7, { ownerKey: OWNER_B }, null, true);
  const forward = resolveConflict([a, b]);
  const reverse = resolveConflict([b, a]);
  assert.equal(forward.rule, 'SMALLER_HASH');
  assert.deepEqual(forward.winner.hash, hash(3));
  assert.deepEqual(reverse.winner.hash, forward.winner.hash, 'arrival order must not matter');
});

test('a three-way conflict still resolves to exactly one winner', () => {
  const r = resolveConflict([
    cand(7, {}, null, true),
    cand(2, { ownerKey: OWNER_B }, null, true),
    cand(5, { ownerKey: new Uint8Array(32).fill(0x33) }, null, true),
  ]);
  assert.deepEqual(r.winner.hash, hash(2));
  assert.equal(r.losers.length, 2, 'every other candidate is void');
});

test('resolution refuses inputs that are not a conflict at all', () => {
  assert.throws(() => resolveConflict([]), ConvergeError);
  assert.throws(() => resolveConflict([cand(1), cand(2, { name: 'zenith' })]), ConvergeError);
  assert.throws(() => resolveConflict([cand(1), cand(2, { seq: 1 })]), ConvergeError);
  assert.throws(
    () => resolveConflict([cand(1, {}, null, false), cand(2, {}, null, false)]),
    ConvergeError,
  );
});

test('a sole candidate is not a conflict and wins trivially', () => {
  const r = resolveConflict([cand(1)]);
  assert.equal(r.rule, 'SOLE_VALID');
  assert.equal(r.losers.length, 0);
});

/* -------------------------------------------------------------------------- */
/* The loser's chain                                                           */
/* -------------------------------------------------------------------------- */

test('everything chained onto a loser is void, transitively', () => {
  // A single lost registration can void a year of updates. The client has to surface that
  // rather than silently refresh: someone registered a name, watched it work, and lost it
  // through no fault of their own.
  const loser = cand(1);
  const second = cand(2, { seq: 1, prevHash: hash(1), powProof: null, op: 'UPDATE' });
  const third = cand(3, { seq: 2, prevHash: hash(2), powProof: null, op: 'UPDATE' });
  const unrelated = cand(8, { seq: 1, prevHash: hash(9), powProof: null, op: 'UPDATE' });

  const voided = voidedChain(loser, [second, third, unrelated]);
  assert.equal(voided.length, 3, 'the loser and both successors');
  assert.deepEqual(
    voided.map((v) => v.hash[0]),
    [1, 2, 3],
  );
  assert.ok(!voided.includes(unrelated), 'a record chained elsewhere survives');
});

test('the voided set is computed in sequence order, not input order', () => {
  const loser = cand(1);
  const second = cand(2, { seq: 1, prevHash: hash(1), powProof: null, op: 'UPDATE' });
  const third = cand(3, { seq: 2, prevHash: hash(2), powProof: null, op: 'UPDATE' });

  // Feed the successors in reverse. A pass that walked input order would stop at `third`,
  // because its predecessor had not yet been marked void.
  const voided = voidedChain(loser, [third, second]);
  assert.equal(voided.length, 3);
});

test('a loser with no successors voids only itself', () => {
  assert.equal(voidedChain(cand(1), []).length, 1);
});
