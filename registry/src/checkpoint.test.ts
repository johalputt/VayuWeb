import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  CHECKPOINT_INTERVAL,
  isCheckpointLength,
  indexRoot,
  checkpointOf,
  compareCheckpoints,
  verifyNameInclusion,
  greatestCorroboratedLength,
  CheckpointError,
} from './checkpoint.ts';
import { treeOf, proveInclusion } from './merkle.ts';
import { parseRecord, type RegistryRecord } from './record.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH } from './pow.ts';
import { type CborMap, type CborValue } from './cbor.ts';

const NOW = 1_782_518_400;
const TERM = 31_536_000;

const pow = (): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['alg', POW_ALGORITHM],
    ['nonce', new Uint8Array(POW_NONCE_LENGTH).fill(7)],
    ['bits', 10],
  ]);

function rec(name: string, over: Record<string, CborValue> = {}): RegistryRecord {
  const m = new Map<string | Uint8Array, CborValue>([
    ['version', 1],
    ['op', 'REGISTER'],
    ['name', name],
    ['tld', 'vayu'],
    ['ownerKey', new Uint8Array(32).fill(0x11)],
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

const entries = (n: number): Uint8Array[] =>
  Array.from({ length: n }, (_, i) => new Uint8Array(6).fill(i + 1));

const h = (n: number): Uint8Array => new Uint8Array(32).fill(n);

/* -------------------------------------------------------------------------- */

test('a checkpoint falls every 10,000 entries', () => {
  assert.equal(CHECKPOINT_INTERVAL, 10_000);
  assert.equal(isCheckpointLength(0), false, 'an empty log is not a checkpoint');
  assert.equal(isCheckpointLength(9_999), false);
  assert.equal(isCheckpointLength(10_000), true);
  assert.equal(isCheckpointLength(20_000), true);
  assert.equal(isCheckpointLength(20_001), false);
});

test('the index root is independent of insertion order', () => {
  // Two peers that accepted the same records in different orders must agree, or the checkpoint
  // compares arrival order rather than state — and arrival order differs between every pair of
  // peers, which would make every comparison report a false divergence.
  const forward = new Map([
    ['atlas.vayu', h(1)],
    ['zenith.vayu', h(2)],
    ['beacon.p2p', h(3)],
  ]);
  const reverse = new Map([
    ['beacon.p2p', h(3)],
    ['zenith.vayu', h(2)],
    ['atlas.vayu', h(1)],
  ]);
  assert.deepEqual(indexRoot(forward), indexRoot(reverse));
});

test('the index root changes when any name or target changes', () => {
  const base = new Map([['atlas.vayu', h(1)]]);
  assert.notDeepEqual(indexRoot(base), indexRoot(new Map([['atlas.vayu', h(2)]])), 'target');
  assert.notDeepEqual(indexRoot(base), indexRoot(new Map([['zenith.vayu', h(1)]])), 'name');
  assert.notDeepEqual(indexRoot(base), indexRoot(new Map([['atlas.p2p', h(1)]])), 'tld');
  assert.notDeepEqual(indexRoot(base), indexRoot(new Map()), 'emptiness');
});

test('a malformed index key is refused rather than hashed', () => {
  assert.throws(() => indexRoot(new Map([['novld', h(1)]])), CheckpointError);
});

test('liveNames counts names that resolve, not names that exist', () => {
  // A name in grace or quarantine is still in the index. Counting it as live would make the
  // figure describe storage rather than the namespace.
  const log = entries(3);
  const index = new Map([['atlas.vayu', h(1)]]);
  const records = new Map([['atlas.vayu', rec('atlas')]]);

  assert.equal(checkpointOf(log, index, records, NOW).liveNames, 1);
  assert.equal(checkpointOf(log, index, records, NOW + TERM + 1).liveNames, 0, 'grace');
  assert.equal(checkpointOf(log, index, records, NOW - 1).liveNames, 0, 'not yet started');
});

test('a checkpoint is derivable by anyone from the same log', () => {
  // It carries no signature, deliberately: a signed checkpoint would be an attestation other
  // peers could be asked to trust rather than recompute, which is the privileged authority the
  // charter forbids.
  const log = entries(5);
  const index = new Map([['atlas.vayu', h(1)]]);
  const records = new Map([['atlas.vayu', rec('atlas')]]);

  const a = checkpointOf(log, index, records, NOW);
  const b = checkpointOf(log, index, records, NOW);
  assert.deepEqual(a, b);
  assert.equal(a.logLength, 5);
  assert.deepEqual(a.treeRoot, treeOf(log).root());
  assert.equal(Object.keys(a).includes('signature'), false, 'never signed');
});

/* -------------------------------------------------------------------------- */
/* Comparison                                                                  */
/* -------------------------------------------------------------------------- */

test('comparison separates real divergence from ordinary progress', () => {
  const index = new Map([['atlas.vayu', h(1)]]);
  const records = new Map([['atlas.vayu', rec('atlas')]]);
  const at5 = checkpointOf(entries(5), index, records, NOW);
  const at6 = checkpointOf(entries(6), index, records, NOW);

  assert.equal(compareCheckpoints(at5, at5), 'IDENTICAL');
  // Different lengths say nothing at all — one peer is simply further along.
  assert.equal(compareCheckpoints(at5, at6), 'DIFFERENT_LENGTH');

  // Same length, different history: one of the two is wrong.
  const forked = entries(5);
  forked[4] = new Uint8Array(6).fill(0xff);
  assert.equal(
    compareCheckpoints(at5, checkpointOf(forked, index, records, NOW)),
    'DIVERGED',
  );
});

test('identical history with different derived state is its own verdict', () => {
  // Collapsing this into DIVERGED would send someone hunting the log for a defect that is in
  // the indexer instead.
  const log = entries(5);
  const records = new Map([['atlas.vayu', rec('atlas')]]);
  const a = checkpointOf(log, new Map([['atlas.vayu', h(1)]]), records, NOW);
  const b = checkpointOf(log, new Map([['atlas.vayu', h(9)]]), records, NOW);
  assert.equal(compareCheckpoints(a, b), 'INDEX_DIVERGED');
});

/* -------------------------------------------------------------------------- */
/* Light client                                                                */
/* -------------------------------------------------------------------------- */

test('a name verifies against a claimed tree root without holding the log', () => {
  const log = entries(8);
  const root = treeOf(log).root();
  const answer = verifyNameInclusion('atlas.vayu', log[3]!, proveInclusion(log, 3), root, 8, NOW, 3);

  assert.equal(answer.verified, true);
  assert.equal(answer.peersAgreeing, 3);
  assert.equal(answer.observedAt, NOW);
  // Always true, whatever else happened. No inclusion proof establishes that the length handed
  // over is current, and the type makes that impossible to omit from a rendered answer.
  assert.equal(answer.freshnessUnproven, true);
});

test('a single-peer answer says plainly that withholding is undetectable', () => {
  const log = entries(8);
  const answer = verifyNameInclusion(
    'atlas.vayu', log[0]!, proveInclusion(log, 0), treeOf(log).root(), 8, NOW, 1,
  );
  assert.equal(answer.verified, true);
  assert.match(answer.detail, /single peer/);
});

test('a proof pointing past the claimed length is refused', () => {
  // Either a bug or a peer trying to have a record counted at a length that does not contain it.
  const log = entries(8);
  const answer = verifyNameInclusion(
    'atlas.vayu', log[7]!, proveInclusion(log, 7), treeOf(log).root(), 4, NOW, 2,
  );
  assert.equal(answer.verified, false);
  assert.match(answer.detail, /leaf 7 but the log is 4/);
});

test('a bad proof and a zero-peer claim both fail closed', () => {
  const log = entries(8);
  const root = treeOf(log).root();
  assert.equal(
    verifyNameInclusion('a.vayu', log[4]!, proveInclusion(log, 3), root, 8, NOW, 2).verified,
    false,
  );
  assert.equal(
    verifyNameInclusion('a.vayu', log[3]!, proveInclusion(log, 3), root, 8, NOW, 0).verified,
    false,
  );
});

/* -------------------------------------------------------------------------- */
/* Which length to trust                                                       */
/* -------------------------------------------------------------------------- */

test('the trusted length is the greatest one corroborated, not the greatest claimed', () => {
  // Taking the greatest claim outright lets one lying peer set it.
  assert.deepEqual(greatestCorroboratedLength([100, 100, 500]), { length: 100, peersAgreeing: 3 });
  assert.deepEqual(greatestCorroboratedLength([100, 200, 200]), { length: 200, peersAgreeing: 2 });
});

test('a peer claiming a longer log corroborates every shorter length', () => {
  assert.deepEqual(greatestCorroboratedLength([90, 100, 110]), { length: 100, peersAgreeing: 2 });
});

test('with nothing corroborated it fails toward staleness rather than trust', () => {
  // A stale answer is wrong about WHEN; a forged one is wrong about WHAT. Failing toward the
  // first is the safer direction.
  assert.equal(greatestCorroboratedLength([500]), null);
  assert.equal(greatestCorroboratedLength([]), null);
  assert.deepEqual(greatestCorroboratedLength([500], 1), { length: 500, peersAgreeing: 1 });
});
