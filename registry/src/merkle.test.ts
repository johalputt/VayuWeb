import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  MerkleTree,
  treeOf,
  leafHash,
  parentHash,
  treeHash,
  flatIndex,
  proveInclusion,
  verifyInclusion,
  MerkleError,
  LEAF_TYPE,
  PARENT_TYPE,
  HASH_LENGTH,
} from './merkle.ts';

const entry = (n: number, size = 8): Uint8Array => new Uint8Array(size).fill(n);
const entries = (count: number): Uint8Array[] =>
  Array.from({ length: count }, (_, i) => entry(i + 1, 4 + (i % 5)));

const eq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => b[i] === x);

/* -------------------------------------------------------------------------- */
/* Domain separation — the second-preimage defence                             */
/* -------------------------------------------------------------------------- */

test('a leaf and a parent over the same bytes hash differently', () => {
  // Without the type byte, a leaf whose data happened to be two concatenated hashes could be
  // presented as an interior node. That is the classic second-preimage attack on merkle trees,
  // and the separation is the whole defence.
  const left = { hash: new Uint8Array(32).fill(1), index: 0, size: 4 };
  const right = { hash: new Uint8Array(32).fill(2), index: 2, size: 4 };

  const asParent = parentHash(left, right);
  const concatenated = new Uint8Array(64);
  concatenated.set(left.hash, 0);
  concatenated.set(right.hash, 32);
  const asLeaf = leafHash(concatenated);

  assert.ok(!eq(asParent, asLeaf), 'a leaf must never collide with a parent');
  assert.notEqual(LEAF_TYPE, PARENT_TYPE);
});

test('the covered byte size is bound into every hash', () => {
  // Omitting it would let an attacker present a differently shaped tree over the same leaves
  // and reach the same root.
  const a = { hash: new Uint8Array(32).fill(7), index: 0, size: 4 };
  const b = { hash: new Uint8Array(32).fill(7), index: 0, size: 5 };
  const other = { hash: new Uint8Array(32).fill(9), index: 2, size: 4 };
  assert.ok(!eq(parentHash(a, other), parentHash(b, other)), 'size must change the hash');
});

test('leaf hashes are 32 bytes and depend on the data', () => {
  assert.equal(leafHash(entry(1)).length, HASH_LENGTH);
  assert.ok(!eq(leafHash(entry(1)), leafHash(entry(2))));
  assert.ok(!eq(leafHash(new Uint8Array(4)), leafHash(new Uint8Array(5))), 'length matters');
});

/* -------------------------------------------------------------------------- */
/* Flat-tree indices                                                           */
/* -------------------------------------------------------------------------- */

test('flat-tree indices place leaves on even positions', () => {
  assert.equal(flatIndex(0, 1), 0);
  assert.equal(flatIndex(1, 1), 2);
  assert.equal(flatIndex(2, 1), 4);
  // Interior nodes take the odd positions, which is what lets a proof be a bare list of
  // siblings with no shape metadata.
  assert.equal(flatIndex(0, 2), 1);
  assert.equal(flatIndex(2, 2), 5);
  assert.equal(flatIndex(0, 4), 3);
  assert.equal(flatIndex(0, 8), 7);
});

/* -------------------------------------------------------------------------- */
/* The tree itself                                                             */
/* -------------------------------------------------------------------------- */

test('an empty log has a defined root, not a special case', () => {
  // Two peers with empty logs must still be able to compare checkpoints — that is when the
  // comparison is cheapest and most useful.
  const tree = new MerkleTree();
  assert.equal(tree.length, 0);
  assert.equal(tree.root().length, HASH_LENGTH);
  assert.ok(eq(tree.root(), treeHash([])));
});

test('appending incrementally equals rebuilding from scratch, at every length', () => {
  // The property the whole design rests on: a peer that has been running and a peer that just
  // replayed the log must agree. If these diverged at any length, checkpoints would be
  // worthless and the divergence would show up only in production.
  const all = entries(40);
  const incremental = new MerkleTree();
  for (let n = 0; n <= all.length; n += 1) {
    if (n > 0) incremental.append(all[n - 1]!);
    const rebuilt = treeOf(all.slice(0, n));
    assert.ok(
      eq(incremental.root(), rebuilt.root()),
      `incremental and rebuilt roots differ at length ${n}`,
    );
    assert.equal(incremental.length, n);
  }
});

test('the root changes when any entry changes', () => {
  const base = entries(9);
  const baseRoot = treeOf(base).root();
  for (let i = 0; i < base.length; i += 1) {
    const tampered = [...base];
    tampered[i] = new Uint8Array(base[i]!.length).fill(0xff);
    assert.ok(!eq(treeOf(tampered).root(), baseRoot), `changing entry ${i} must change the root`);
  }
});

test('the root changes when entries are reordered', () => {
  // Order is the log's meaning: the same records in a different order are a different history.
  const base = entries(6);
  const swapped = [...base];
  [swapped[2], swapped[3]] = [swapped[3]!, swapped[2]!];
  assert.ok(!eq(treeOf(swapped).root(), treeOf(base).root()));
});

test('a longer log never shares a root with a shorter prefix of itself', () => {
  // Otherwise a peer could withhold entries and present a root the client already accepted.
  const all = entries(20);
  const roots = new Set<string>();
  for (let n = 0; n <= all.length; n += 1) {
    roots.add(Buffer.from(treeOf(all.slice(0, n)).root()).toString('hex'));
  }
  assert.equal(roots.size, all.length + 1, 'every length must have a distinct root');
});

test('peak count matches the binary weight of the log length', () => {
  // A merkle mountain range has one peak per set bit in the leaf count.
  for (const n of [1, 2, 3, 4, 5, 7, 8, 15, 16, 23, 32]) {
    const bits = n
      .toString(2)
      .split('')
      .filter((b) => b === '1').length;
    assert.equal(treeOf(entries(n)).roots().length, bits, `length ${n}`);
  }
});

test('byteLength totals every entry appended', () => {
  const all = entries(11);
  const expected = all.reduce((t, e) => t + e.length, 0);
  assert.equal(treeOf(all).byteLength, expected);
});

/* -------------------------------------------------------------------------- */
/* Inclusion proofs — what a light client actually runs                        */
/* -------------------------------------------------------------------------- */

test('every leaf proves inclusion, at every log length', () => {
  for (const n of [1, 2, 3, 5, 8, 13, 16]) {
    const all = entries(n);
    const root = treeOf(all).root();
    for (let i = 0; i < n; i += 1) {
      const proof = proveInclusion(all, i);
      assert.ok(verifyInclusion(all[i]!, proof, root), `leaf ${i} of ${n} must verify`);
    }
  }
});

test('a proof does not verify against a different root', () => {
  const all = entries(8);
  const proof = proveInclusion(all, 3);
  const otherRoot = treeOf(entries(9)).root();
  assert.equal(verifyInclusion(all[3]!, proof, otherRoot), false);
});

test('a proof does not verify for data it was not made for', () => {
  // The proof deliberately does not carry the leaf: the verifier supplies it. A proof carrying
  // its own leaf could prove inclusion of something the client never asked about.
  const all = entries(8);
  const root = treeOf(all).root();
  const proof = proveInclusion(all, 3);
  assert.equal(verifyInclusion(all[4]!, proof, root), false, 'wrong leaf must fail');
  assert.equal(verifyInclusion(new Uint8Array(all[3]!.length).fill(0xee), proof, root), false);
});

test('a tampered sibling breaks the proof', () => {
  const all = entries(8);
  const root = treeOf(all).root();
  const proof = proveInclusion(all, 5);
  assert.ok(proof.siblings.length > 0);

  for (let i = 0; i < proof.siblings.length; i += 1) {
    const siblings = proof.siblings.map((s, j) =>
      j === i ? { ...s, hash: new Uint8Array(32).fill(0xab) } : s,
    );
    assert.equal(
      verifyInclusion(all[5]!, { ...proof, siblings }, root),
      false,
      `tampering with sibling ${i} must be caught`,
    );
  }
});

test('flipping a sibling’s side breaks the proof', () => {
  // Left and right are not interchangeable: parent(a,b) != parent(b,a). If they were, an
  // attacker could reorder a path and keep the root.
  const all = entries(8);
  const root = treeOf(all).root();
  const proof = proveInclusion(all, 5);
  const flipped = proof.siblingIsLeft.map((v, i) => (i === 0 ? !v : v));
  assert.equal(verifyInclusion(all[5]!, { ...proof, siblingIsLeft: flipped }, root), false);
});

test('substituting a peak is caught even when the root still matches', () => {
  // The verifier checks the reconstructed peak against the claimed one, not only the final
  // root. Checking the root alone would let a proof point at a different peak that was itself
  // supplied in `roots`, and still reach the right answer.
  const all = entries(7);
  const root = treeOf(all).root();
  const proof = proveInclusion(all, 0);
  assert.ok(proof.roots.length > 1, 'this log has several peaks');

  const wrongPeak = { ...proof, rootIndex: proof.roots.length - 1 };
  assert.equal(verifyInclusion(all[0]!, wrongPeak, root), false);
});

test('a proof with mismatched sibling metadata is refused, not guessed at', () => {
  const all = entries(8);
  const root = treeOf(all).root();
  const proof = proveInclusion(all, 2);
  assert.equal(
    verifyInclusion(all[2]!, { ...proof, siblingIsLeft: proof.siblingIsLeft.slice(1) }, root),
    false,
  );
  assert.equal(verifyInclusion(all[2]!, { ...proof, rootIndex: 99 }, root), false);
  assert.equal(verifyInclusion(all[2]!, { ...proof, leafSize: 999 }, root), false);
});

test('proving a leaf outside the log is an error rather than a fabrication', () => {
  const all = entries(4);
  assert.throws(() => proveInclusion(all, 4), MerkleError);
  assert.throws(() => proveInclusion(all, -1), MerkleError);
  assert.throws(() => proveInclusion([], 0), MerkleError);
});

/* -------------------------------------------------------------------------- */
/* AUDIT: what an inclusion proof does NOT bind, said out loud                  */
/* -------------------------------------------------------------------------- */

test('AUDIT: leafIndex selects a leaf and is not authenticated by the fold', () => {
  // Found by moving it on a real proof and watching `light-verify` still print `verified`.
  //
  // **This is the specification working, not a defect** — REGISTRY.md's hash construction is
  // normative and `parent(left, right)` hashes `0x01 || uint64be(lsize + rsize) || lhash || rhash`
  // with no index in it, precisely so that "an inclusion proof be a bare list of sibling hashes
  // carrying no shape metadata". The position is a selector the verifier is told; it is not a
  // claim the fold checks.
  //
  // It is pinned here because the verifier used to LOOK as though it checked. It computed
  // `index: flatIndex(proof.leafIndex, 1)` into the leaf node and then never read the field again
  // — the first parent overwrites it with 0 and `parentHash` ignores it on every path. A line that
  // consumes an untrusted field inside a verifier and discards the result is worse than no line:
  // the next reader takes the position for authenticated because the code appears to use it.
  const leaves = entries(5);
  const root = treeOf(leaves).root();
  const proof = proveInclusion(leaves, 2);

  assert.equal(verifyInclusion(leaves[2]!, proof, root), true);
  // Any in-range position verifies, because none of them is hashed.
  for (const moved of [0, 1, 3, 4]) {
    assert.equal(
      verifyInclusion(leaves[2]!, { ...proof, leafIndex: moved }, root),
      true,
      `leafIndex ${moved}: the fold cannot see it, so it must not appear to`,
    );
  }
  // A sibling's `index` is the same: carried in the structure, never hashed.
  const siblings = proof.siblings.map((s, i) => (i === 0 ? { ...s, index: 999 } : s));
  assert.equal(verifyInclusion(leaves[2]!, { ...proof, siblings }, root), true);

  // What IS bound, so the line above is a statement about indices and not about proofs. Sizes go
  // into every parent hash, and the leaf's own size is checked against the data before anything.
  assert.equal(
    verifyInclusion(leaves[2]!, { ...proof, leafSize: proof.leafSize + 1 }, root),
    false,
  );
  assert.equal(
    verifyInclusion(
      leaves[2]!,
      { ...proof, siblings: proof.siblings.map((s, i) => (i === 0 ? { ...s, size: 9999 } : s)) },
      root,
    ),
    false,
  );
});

test('AUDIT: comparing the reconstructed peak by hash alone is enough, and only because of treeHash', () => {
  // The peak comparison reads `claimed.hash` and nothing else, under a comment that said the peak
  // must match "byte for byte". It does not compare `index` or `size` — and it does not need to,
  // because `treeHash` hashes `hash || uint64be(index) || uint64be(size)` for every peak, so a
  // roots array with a doctored index or size cannot reach the expected root. The comment claimed
  // a check the function does not perform; the guarantee comes from one line further down.
  //
  // Asserted rather than reasoned about, because "it is covered elsewhere" is exactly the sentence
  // that turns out to be false.
  const leaves = entries(5);
  const root = treeOf(leaves).root();
  const proof = proveInclusion(leaves, 2);

  const doctoredIndex = proof.roots.map((r, i) =>
    i === proof.rootIndex ? { ...r, index: r.index + 2 } : r,
  );
  assert.equal(
    verifyInclusion(leaves[2]!, { ...proof, roots: doctoredIndex }, root),
    false,
    "a peak's index is bound by treeHash even though the peak comparison ignores it",
  );

  const doctoredSize = proof.roots.map((r, i) =>
    i === proof.rootIndex ? { ...r, size: r.size + 1 } : r,
  );
  assert.equal(verifyInclusion(leaves[2]!, { ...proof, roots: doctoredSize }, root), false);
});
