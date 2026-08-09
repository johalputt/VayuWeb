/**
 * The log's merkle tree: what makes an entry self-authenticating.
 *
 * docs/spec/REGISTRY.md, "Checkpoints, Compaction and Light Clients". That section requires a
 * `treeRoot` and says a light client fetches "Hypercore inclusion proofs" — but it never states
 * the tree's construction, so an implementer reading VayuWeb's specifications alone cannot
 * compute a `treeRoot` at all. Constitution Article 44.6 requires exactly that they can. The
 * construction is therefore written down normatively in REGISTRY.md alongside this module,
 * rather than delegated to an external project's source code.
 *
 * It is the flat-tree / merkle-mountain-range construction Hypercore uses, reproduced here so
 * the two agree:
 *
 *     leaf(data)          = BLAKE2b-256( 0x00 || uint64be(len(data))        || data )
 *     parent(left, right) = BLAKE2b-256( 0x01 || uint64be(lsize + rsize)    || lhash || rhash )
 *     tree(roots)         = BLAKE2b-256( 0x02 || for each root in order:
 *                                                  hash || uint64be(index) || uint64be(size) )
 *
 * The three leading bytes are domain separation between node kinds. Without them a leaf whose
 * data happened to equal a concatenation of two hashes could be presented as an interior node,
 * which is the classic second-preimage attack on unseparated merkle trees.
 *
 * `size` is the **byte length** of the data a node covers, not a count of leaves, and it is
 * bound into every hash. A tree that omitted it would let an attacker present a differently
 * shaped tree over the same leaves with the same root.
 *
 * `index` is the node's position in flat-tree ordering: leaf `k` sits at index `2k`, and a
 * subtree covering `size` leaves starting at leaf `start` sits at `2 * start + size - 1`.
 * Interior nodes therefore occupy the odd indices, which is what lets a proof be a plain list of
 * sibling hashes with no shape metadata.
 */

import { blake2b } from '@noble/hashes/blake2';

export const LEAF_TYPE = 0x00;
export const PARENT_TYPE = 0x01;
export const ROOT_TYPE = 0x02;

export const HASH_LENGTH = 32;

export class MerkleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MerkleError';
  }
}

/** A subtree peak: its hash, its flat-tree index, and the byte length it covers. */
export interface Root {
  readonly hash: Uint8Array;
  readonly index: number;
  readonly size: number;
}

function uint64be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
    throw new MerkleError(`size out of range: ${value}`);
  }
  const out = new Uint8Array(8);
  let remaining = value;
  for (let i = 7; i >= 0; i -= 1) {
    out[i] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  return out;
}

function hash(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const buffer = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    buffer.set(p, at);
    at += p.length;
  }
  return blake2b(buffer, { dkLen: HASH_LENGTH });
}

export function leafHash(data: Uint8Array): Uint8Array {
  return hash([Uint8Array.of(LEAF_TYPE), uint64be(data.length), data]);
}

export function parentHash(left: Root, right: Root): Uint8Array {
  return hash([
    Uint8Array.of(PARENT_TYPE),
    uint64be(left.size + right.size),
    left.hash,
    right.hash,
  ]);
}

/**
 * The tree root over a set of peaks.
 *
 * An empty log has a defined root rather than a special case: the hash of the type byte alone.
 * Leaving it undefined would mean two peers with empty logs could not compare checkpoints, which
 * is exactly when comparison is cheapest and most useful.
 */
export function treeHash(roots: readonly Root[]): Uint8Array {
  const parts: Uint8Array[] = [Uint8Array.of(ROOT_TYPE)];
  for (const root of roots) {
    parts.push(root.hash, uint64be(root.index), uint64be(root.size));
  }
  return hash(parts);
}

/** The flat-tree index of a subtree covering `count` leaves starting at leaf `start`. */
export function flatIndex(start: number, count: number): number {
  return 2 * start + count - 1;
}

/**
 * An append-only merkle tree over the log's entries.
 *
 * Peaks are maintained incrementally: appending is O(log n) amortised, and the root is computed
 * from the peaks rather than by rebuilding. Recomputing the whole tree per entry would make
 * replay O(n log n) on top of the O(n) verification a newcomer already pays, and this project
 * has already had one quadratic replay cost that priced newcomers out of verifying.
 */
export class MerkleTree {
  private readonly peaks: Root[] = [];
  /** Leaf count covered by each peak, index-aligned with `peaks`. */
  private readonly spans: number[] = [];
  private leafCount = 0;
  private bytes = 0;

  /** Append one entry and return its leaf node. */
  append(data: Uint8Array): Root {
    const leaf: Root = {
      hash: leafHash(data),
      index: flatIndex(this.leafCount, 1),
      size: data.length,
    };
    this.leafCount += 1;
    this.bytes += data.length;

    // Carry: while the rightmost peak covers the same number of LEAVES as the node being
    // carried, combine them. Equality is tracked by leaf span rather than byte size — entries
    // differ in length, so byte size would pair the wrong subtrees and produce a tree whose
    // shape depends on the data rather than on the count.
    let carry: Root = leaf;
    let span = 1;
    while (this.spans.length > 0 && this.spans[this.spans.length - 1] === span) {
      const left = this.peaks.pop()!;
      this.spans.pop();
      span *= 2;
      carry = {
        hash: parentHash(left, carry),
        index: flatIndex(this.leafCount - span, span),
        size: left.size + carry.size,
      };
    }
    this.peaks.push(carry);
    this.spans.push(span);
    return leaf;
  }

  /** The peaks, left to right. */
  roots(): readonly Root[] {
    return [...this.peaks];
  }

  /** The checkpoint's `treeRoot`. */
  root(): Uint8Array {
    return treeHash(this.peaks);
  }

  get length(): number {
    return this.leafCount;
  }

  /** Total byte length of every entry appended. */
  get byteLength(): number {
    return this.bytes;
  }
}

/**
 * Build a tree from a complete list of entries.
 *
 * Deterministic in the entries alone: two peers holding the same log in the same order compute
 * the same root, which is the entire property a checkpoint trades on.
 */
export function treeOf(entries: readonly Uint8Array[]): MerkleTree {
  const tree = new MerkleTree();
  for (const entry of entries) tree.append(entry);
  return tree;
}

/**
 * An inclusion proof: the sibling hashes on the path from a leaf to its subtree peak, plus every
 * other peak so the verifier can reconstruct the root.
 *
 * The proof carries no shape metadata beyond flat-tree indices, and it does NOT carry the leaf
 * data — the verifier supplies that. A proof that carried its own leaf would let a peer prove
 * inclusion of something the light client never asked about.
 */
export interface Proof {
  readonly leafIndex: number;
  readonly leafSize: number;
  /** Sibling nodes from the leaf upward, nearest first. */
  readonly siblings: readonly Root[];
  /** True when each sibling is the LEFT child at that level. */
  readonly siblingIsLeft: readonly boolean[];
  /** Every peak of the tree, left to right, including the one this leaf sits under. */
  readonly roots: readonly Root[];
  /** Index of this leaf's peak within `roots`. */
  readonly rootIndex: number;
}

/**
 * Build an inclusion proof for one leaf.
 *
 * Rebuilds the covering subtree to collect siblings. That is O(subtree) rather than O(log n),
 * which is honest about what this implementation does: a production node keeps interior nodes
 * and walks them. The verification side — which is what a light client runs, and the side that
 * must be cheap — is O(log n) regardless.
 */
export function proveInclusion(entries: readonly Uint8Array[], leafIndex: number): Proof {
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= entries.length) {
    throw new MerkleError(`leaf ${leafIndex} is outside a log of ${entries.length}`);
  }

  // Decompose the log into peaks, largest first, and find the one covering this leaf.
  const peakSpans: Array<{ start: number; span: number }> = [];
  let remaining = entries.length;
  let start = 0;
  for (let bit = 52; bit >= 0; bit -= 1) {
    const span = 2 ** bit;
    if (remaining >= span) {
      peakSpans.push({ start, span });
      start += span;
      remaining -= span;
    }
  }

  const rootIndex = peakSpans.findIndex(
    (p) => leafIndex >= p.start && leafIndex < p.start + p.span,
  );
  const covering = peakSpans[rootIndex]!;

  const siblings: Root[] = [];
  const siblingIsLeft: boolean[] = [];

  // Walk down the covering subtree, recording the sibling at each level.
  let lo = covering.start;
  let span = covering.span;
  while (span > 1) {
    const half = span / 2;
    const leftRange = { start: lo, span: half };
    const rightRange = { start: lo + half, span: half };
    const goRight = leafIndex >= lo + half;
    const sibling = goRight ? leftRange : rightRange;
    siblings.push(subtreeRoot(entries, sibling.start, sibling.span));
    siblingIsLeft.push(goRight);
    if (goRight) lo += half;
    span = half;
  }

  return {
    leafIndex,
    leafSize: entries[leafIndex]!.length,
    siblings,
    siblingIsLeft,
    roots: peakSpans.map((p) => subtreeRoot(entries, p.start, p.span)),
    rootIndex,
  };
}

/** The root node of a complete subtree covering `span` leaves from `start`. */
function subtreeRoot(entries: readonly Uint8Array[], start: number, span: number): Root {
  if (span === 1) {
    const data = entries[start]!;
    return { hash: leafHash(data), index: flatIndex(start, 1), size: data.length };
  }
  const half = span / 2;
  const left = subtreeRoot(entries, start, half);
  const right = subtreeRoot(entries, start + half, half);
  return {
    hash: parentHash(left, right),
    index: flatIndex(start, span),
    size: left.size + right.size,
  };
}

/**
 * Verify that `data` is the leaf at `proof.leafIndex` in a log whose root is `expectedRoot`.
 *
 * The light client's whole security rests on this: it proves presence at a given length without
 * the client holding the log. What it does NOT prove is freshness — a peer withholding recent
 * entries can present a stale but internally consistent view, and nothing in this function can
 * detect that. REGISTRY.md says so too. Callers must query several independent peers, take the
 * greatest verified length, and show that length with every answer.
 */
export function verifyInclusion(data: Uint8Array, proof: Proof, expectedRoot: Uint8Array): boolean {
  if (data.length !== proof.leafSize) return false;
  if (proof.siblings.length !== proof.siblingIsLeft.length) return false;
  if (proof.rootIndex < 0 || proof.rootIndex >= proof.roots.length) return false;

  // `index: 0`, deliberately, and the same value every parent below uses. It used to be
  // `flatIndex(proof.leafIndex, 1)` — computed from an untrusted field, assigned, and then never
  // read on any path: the first parent overwrites it and `parentHash` does not look at it. A line
  // that consumes an untrusted input inside a verifier and discards the result is worse than no
  // line, because the next reader takes the position for authenticated on the strength of it.
  //
  // Nothing here binds `proof.leafIndex`, and that is REGISTRY.md's construction rather than an
  // omission: `parent(left, right)` is `0x01 || uint64be(lsize + rsize) || lhash || rhash`, with no
  // index, "which is what lets an inclusion proof be a bare list of sibling hashes carrying no
  // shape metadata". The index selects which leaf the caller is asking about; the fold proves that
  // THIS data is in the tree, not where. `checkpoint.ts` bounds it against the log length; nothing
  // else may treat it as evidence.
  let node: Root = { hash: leafHash(data), index: 0, size: data.length };

  // Fold upward. Siblings are ordered nearest-first, so they are consumed in reverse.
  for (let i = proof.siblings.length - 1; i >= 0; i -= 1) {
    const sibling = proof.siblings[i]!;
    const siblingLeft = proof.siblingIsLeft[i]!;
    const left = siblingLeft ? sibling : node;
    const right = siblingLeft ? node : sibling;
    node = {
      hash: parentHash(left, right),
      index: 0,
      size: left.size + right.size,
    };
  }

  // The reconstructed peak must be the one the proof claims. Comparing only the final root would
  // let a proof substitute a different peak and still reach the same root when the substituted
  // peak was itself supplied in `roots`.
  //
  // By HASH, and only by hash — this said "byte for byte" while reading one field of three. The
  // peak's `index` and `size` are bound one line further down, where `treeHash` hashes
  // `hash || uint64be(index) || uint64be(size)` for every peak, so a doctored roots array cannot
  // reach the expected root. That is a real guarantee and it is not this comparison's; saying so
  // is the difference between a check and the appearance of one.
  const claimed = proof.roots[proof.rootIndex]!;
  if (claimed.hash.length !== node.hash.length) return false;
  let mismatch = 0;
  for (let i = 0; i < claimed.hash.length; i += 1) mismatch |= claimed.hash[i]! ^ node.hash[i]!;
  if (mismatch !== 0) return false;

  const root = treeHash(proof.roots);
  if (root.length !== expectedRoot.length) return false;
  let rootMismatch = 0;
  for (let i = 0; i < root.length; i += 1) rootMismatch |= root[i]! ^ expectedRoot[i]!;
  return rootMismatch === 0;
}
