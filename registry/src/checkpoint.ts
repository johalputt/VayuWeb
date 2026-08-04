/**
 * Checkpoints and light-client verification.
 *
 * docs/spec/REGISTRY.md, "Checkpoints, Compaction and Light Clients".
 *
 * Every 10,000 entries a node computes `{logLength, treeRoot, indexRoot, liveNames}`. Anyone can
 * derive it from the same log, so it is **not an authority** and carries no signature that would
 * make it one. Signing it would create exactly the privileged attestation the charter forbids: a
 * thing other peers could be asked to trust rather than recompute. It is a comparison aid — two
 * peers agreeing on `treeRoot` at a `logLength` have identical history to that point, which
 * reduces a divergence check to 32 bytes.
 *
 * ## Freshness is not proved, and this module says so in its types
 *
 * A light client cannot tell that the `logLength` it was handed is current. A peer withholding
 * recent entries can present a stale but internally consistent view, and no amount of proof
 * checking detects it — the withheld entries are simply not there to contradict anything.
 *
 * The mitigation is partial and procedural: query several independent peers, take the greatest
 * verified length, and show that length and the observation time with every answer.
 * {@link LightClientAnswer} therefore carries `observedAt` and `peersAgreeing` as required
 * fields rather than optional metadata, so a caller cannot render an answer without having the
 * information that qualifies it.
 */

import { treeOf, verifyInclusion, type Proof } from './merkle.ts';
import { currentKey } from './keys.ts';
import { lifecycleOf } from './lifecycle.ts';
import type { RegistryRecord } from './record.ts';
import { blake2b } from '@noble/hashes/blake2';

/** REGISTRY.md: a checkpoint every 10,000 entries. */
export const CHECKPOINT_INTERVAL = 10_000;

export const INDEX_ROOT_PREFIX = 'VayuWeb-Registry-Index-v1';
const INDEX_PREFIX_BYTES = new TextEncoder().encode(INDEX_ROOT_PREFIX);

export class CheckpointError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CheckpointError';
  }
}

export interface Checkpoint {
  readonly logLength: number;
  readonly treeRoot: Uint8Array;
  readonly indexRoot: Uint8Array;
  readonly liveNames: number;
}

/** Should a checkpoint be taken at this length? */
export function isCheckpointLength(logLength: number): boolean {
  return logLength > 0 && logLength % CHECKPOINT_INTERVAL === 0;
}

/**
 * The index root: a hash over the current-name index, so two peers can compare derived state and
 * not only raw history.
 *
 * Keys are the `n` keyspace entries from keys.ts, sorted bytewise — the same order Hyperbee
 * stores them in — and each is bound to the record hash it points at. Sorting is what makes this
 * independent of insertion order; two peers that accepted the same records in different orders
 * must still agree, or the checkpoint compares arrival order rather than state.
 */
export function indexRoot(current: ReadonlyMap<string, Uint8Array>): Uint8Array {
  const rows: Uint8Array[] = [];
  for (const [name, recordHash] of current) {
    const dot = name.lastIndexOf('.');
    if (dot <= 0) throw new CheckpointError(`index key '${name}' is not label.tld`);
    const key = currentKey(name.slice(dot + 1), name.slice(0, dot));
    const row = new Uint8Array(key.length + recordHash.length);
    row.set(key, 0);
    row.set(recordHash, key.length);
    rows.push(row);
  }

  rows.sort((a, b) => {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i += 1) {
      if (a[i] !== b[i]) return a[i]! - b[i]!;
    }
    return a.length - b.length;
  });

  let total = INDEX_PREFIX_BYTES.length + 1;
  for (const row of rows) total += row.length;
  const buffer = new Uint8Array(total);
  buffer.set(INDEX_PREFIX_BYTES, 0);
  buffer[INDEX_PREFIX_BYTES.length] = 0x00;
  let at = INDEX_PREFIX_BYTES.length + 1;
  for (const row of rows) {
    buffer.set(row, at);
    at += row.length;
  }
  return blake2b(buffer, { dkLen: 32 });
}

/**
 * Compute a checkpoint from a complete log and the index derived from it.
 *
 * `liveNames` counts names that resolve at `now` — not names that exist. A name in grace or
 * quarantine is in the index but does not resolve, and reporting it as live would make the
 * figure describe storage rather than the namespace.
 */
export function checkpointOf(
  entries: readonly Uint8Array[],
  current: ReadonlyMap<string, Uint8Array>,
  records: ReadonlyMap<string, RegistryRecord>,
  now: number,
): Checkpoint {
  let liveNames = 0;
  for (const record of records.values()) {
    const life = lifecycleOf(record);
    if (!life.revoked && now >= life.liveFrom && now < life.liveUntil) liveNames += 1;
  }
  return {
    logLength: entries.length,
    treeRoot: treeOf(entries).root(),
    indexRoot: indexRoot(current),
    liveNames,
  };
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i]! ^ b[i]!;
  return diff === 0;
};

export type ComparisonResult =
  | 'IDENTICAL'
  | 'DIVERGED'
  | 'DIFFERENT_LENGTH'
  | 'INDEX_DIVERGED';

/**
 * Compare two checkpoints.
 *
 * The distinction that matters: at the **same** length a differing `treeRoot` is a genuine
 * divergence — the two peers have accepted different histories and one of them is wrong. At
 * different lengths it is ordinary progress and says nothing.
 *
 * A matching `treeRoot` with a differing `indexRoot` is the interesting case: identical history
 * producing different derived state, which means one peer's indexing is buggy rather than its
 * log. Collapsing that into DIVERGED would send someone hunting the log for a defect that is not
 * in it.
 */
export function compareCheckpoints(a: Checkpoint, b: Checkpoint): ComparisonResult {
  if (a.logLength !== b.logLength) return 'DIFFERENT_LENGTH';
  if (!sameBytes(a.treeRoot, b.treeRoot)) return 'DIVERGED';
  if (!sameBytes(a.indexRoot, b.indexRoot)) return 'INDEX_DIVERGED';
  return 'IDENTICAL';
}

/**
 * What a light client is allowed to conclude.
 *
 * `observedAt` and `peersAgreeing` are required, not optional. A light client's answer is only
 * as good as its freshness assumption, and an interface that let a caller drop that context
 * would let a UI present a possibly-stale answer as a current one.
 */
export interface LightClientAnswer {
  readonly name: string;
  readonly verified: boolean;
  readonly logLength: number;
  readonly observedAt: number;
  readonly peersAgreeing: number;
  /** Always true: no inclusion proof establishes that the length handed over is current. */
  readonly freshnessUnproven: true;
  readonly detail: string;
}

/**
 * Verify one name against a claimed `treeRoot` without holding the log.
 *
 * REGISTRY.md's light-client procedure, steps 1 and 2. Step 3 — verifying the name's record
 * chain — is the existing verifier's job and is not repeated here.
 */
export function verifyNameInclusion(
  name: string,
  recordBytes: Uint8Array,
  proof: Proof,
  treeRoot: Uint8Array,
  logLength: number,
  observedAt: number,
  peersAgreeing: number,
): LightClientAnswer {
  const base = {
    name,
    logLength,
    observedAt,
    peersAgreeing,
    freshnessUnproven: true as const,
  };

  if (peersAgreeing < 1) {
    return { ...base, verified: false, detail: 'no peer supplied this length' };
  }
  if (proof.leafIndex >= logLength) {
    // A proof pointing past the claimed length is either a bug or a peer trying to have a
    // record counted at a length that does not contain it.
    return {
      ...base,
      verified: false,
      detail: `proof is for leaf ${proof.leafIndex} but the log is ${logLength} long`,
    };
  }
  if (!verifyInclusion(recordBytes, proof, treeRoot)) {
    return { ...base, verified: false, detail: 'inclusion proof does not check out' };
  }
  return {
    ...base,
    verified: true,
    detail:
      peersAgreeing === 1
        ? 'present at this length, from a single peer — a withholding peer is undetectable'
        : `present at this length, corroborated by ${peersAgreeing} peers`,
  };
}

/**
 * Choose the length to trust from several peers' claims: the greatest that is corroborated.
 *
 * Taking the greatest claimed length outright would let one lying peer set it. Taking the most
 * common would let a majority of cheap sybils hold the client back. This takes the greatest
 * length claimed by at least `quorum` peers, which fails toward staleness rather than toward
 * believing a single stranger — the safer direction, since a stale answer is wrong about *when*
 * and a forged one is wrong about *what*.
 */
export function greatestCorroboratedLength(
  claims: readonly number[],
  quorum = 2,
): { length: number; peersAgreeing: number } | null {
  if (claims.length === 0) return null;
  const counts = new Map<number, number>();
  for (const claim of claims) counts.set(claim, (counts.get(claim) ?? 0) + 1);

  let best: { length: number; peersAgreeing: number } | null = null;
  for (const [length, exact] of counts) {
    // A peer claiming a longer log also corroborates every shorter length, since it has those
    // entries too.
    let agreeing = 0;
    for (const claim of claims) if (claim >= length) agreeing += 1;
    void exact;
    if (agreeing >= quorum && (best === null || length > best.length)) {
      best = { length, peersAgreeing: agreeing };
    }
  }
  return best;
}
