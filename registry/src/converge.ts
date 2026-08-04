/**
 * Convergence: deciding which of two conflicting records wins.
 *
 * docs/spec/REGISTRY.md, "Convergence". Two peers on either side of a partition can each accept
 * a valid first registration of the same free name. Both did the work, both are correctly
 * signed, and neither is wrong. When the partition heals, every peer must independently reach
 * the *same* answer without asking anyone — a rule that needs a coordinator is a rule that has
 * a coordinator, which is the thing this registry exists not to have.
 *
 * The rule, applied to any conflicting pair at the same `seq` for one `name.tld`:
 *
 *   1. If exactly one is valid, that one wins.
 *   2. Otherwise, if the linearised order places one strictly before the other on every peer
 *      holding both, the earlier wins.
 *   3. Otherwise, the smaller `record_hash` as a big-endian unsigned integer wins.
 *
 * Rule 3 is grindable in principle: an attacker expecting a tie can vary `powProof.nonce` to
 * lower their hash. Each attempt costs a full proof of work, and it only matters in the case
 * that is genuinely undecidable, so the cost is paid for a chance at a coin flip. It is recorded
 * as a weakness in docs/THREAT-MODEL.md rather than defended against here, because there is no
 * defence that does not reintroduce a coordinator.
 *
 * ## The loser is void, not absent
 *
 * A losing record and everything chained onto it become void on merge, and REGISTRY.md requires
 * a client to surface that rather than hide it behind a silent refresh. Someone registered a
 * name, saw it succeed, and then lost it through no fault of their own; a UI that quietly
 * updates is lying about what happened. {@link resolveConflict} therefore returns the voided
 * chain explicitly instead of just the winner — a caller that wants to ignore it has to do so
 * deliberately.
 */

import { compareBytes } from './cbor.ts';
import type { RegistryRecord } from './record.ts';

/** A candidate in a conflict: the record, its hash, and where the local log places it. */
export interface Candidate {
  readonly record: RegistryRecord;
  /** `record_hash` over the exact accepted bytes. */
  readonly hash: Uint8Array;
  /**
   * Position in this peer's linearised log, or null when the peer has not linearised it.
   *
   * Nullable because rule 2 requires the order to agree on *every* peer holding both records.
   * A peer that has only just received one of them cannot answer that, and must fall through
   * to rule 3 rather than guess from its own arrival order — arrival order is not linearised
   * order, and treating it as such is how two peers reach different answers.
   */
  readonly logIndex: number | null;
  /** Whether this peer's verifier accepted the record. */
  readonly valid: boolean;
}

export type ConflictRule = 'SOLE_VALID' | 'EARLIER_IN_LOG' | 'SMALLER_HASH';

export interface Resolution {
  readonly winner: Candidate;
  /** Every candidate that lost. Their chains are void and a client MUST surface that. */
  readonly losers: readonly Candidate[];
  /** Which rule decided it, so the decision can be explained rather than merely applied. */
  readonly rule: ConflictRule;
}

export class ConvergeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConvergeError';
  }
}

/**
 * Compare two record hashes as big-endian unsigned integers.
 *
 * Both are 32 bytes, so this is bytewise comparison — but it is written out rather than assumed,
 * because "as a big-endian unsigned integer" is the normative phrasing and an implementation
 * that compared them as signed, or as strings, would disagree with everyone else exactly at the
 * tie-break where disagreement is a permanent fork.
 */
export function compareHashes(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) {
    throw new ConvergeError(`record hashes differ in length: ${a.length} vs ${b.length}`);
  }
  return compareBytes(a, b);
}

/**
 * Do two records conflict?
 *
 * A conflict is two *different* records at the same `seq` for one `name.tld`. Identical bytes
 * are not a conflict — REGISTRY.md requires a peer receiving a record it already holds to drop
 * it silently — and records at different `seq` are a chain, not a fork.
 */
export function conflicts(a: Candidate, b: Candidate): boolean {
  if (a.record.name !== b.record.name || a.record.tld !== b.record.tld) return false;
  if (a.record.seq !== b.record.seq) return false;
  return compareHashes(a.hash, b.hash) !== 0;
}

/**
 * Equivocation: one owner signing two different records at the same `seq`.
 *
 * Distinct from an honest partition conflict, which is two *different* owners each registering
 * a free name. Here the same key has signed two futures for one name, which no honest client
 * does — it is either a compromised key or a deliberate attempt to show different states to
 * different peers.
 *
 * This detects it; it does not punish it. There is no penalty mechanism in the protocol, and
 * inventing one here would be inventing consensus. What a peer does with the evidence is a
 * policy question, and the evidence is what this returns.
 */
export function isEquivocation(a: Candidate, b: Candidate): boolean {
  if (!conflicts(a, b)) return false;
  return compareBytes(a.record.ownerKey, b.record.ownerKey) === 0;
}

/**
 * Resolve a conflict between two or more candidates for one `name.tld` at one `seq`.
 *
 * Deterministic in its inputs: given the same candidates every peer returns the same winner,
 * which is the entire requirement. The candidate list is sorted internally so that the caller's
 * ordering — which is arrival order, and differs between peers — cannot influence the result.
 */
export function resolveConflict(candidates: readonly Candidate[]): Resolution {
  if (candidates.length === 0) throw new ConvergeError('no candidates to resolve');
  if (candidates.length === 1) {
    return { winner: candidates[0]!, losers: [], rule: 'SOLE_VALID' };
  }

  const first = candidates[0]!;
  for (const c of candidates.slice(1)) {
    if (c.record.name !== first.record.name || c.record.tld !== first.record.tld) {
      throw new ConvergeError('candidates are for different names');
    }
    if (c.record.seq !== first.record.seq) {
      throw new ConvergeError('candidates are at different sequence numbers');
    }
  }

  // Rule 1: if exactly one is valid, that one wins.
  const valid = candidates.filter((c) => c.valid);
  if (valid.length === 0) throw new ConvergeError('no candidate is valid');
  if (valid.length === 1) {
    return { winner: valid[0]!, losers: others(candidates, valid[0]!), rule: 'SOLE_VALID' };
  }

  // Rule 2: the earlier in the linearised order, but only when every candidate has a position.
  // A missing position means this peer cannot know the order agrees everywhere, and guessing
  // from arrival order is how two peers reach different answers about the same pair.
  const positioned = valid.every((c) => c.logIndex !== null);
  if (positioned) {
    const sorted = [...valid].sort((a, b) => a.logIndex! - b.logIndex!);
    // "strictly before": a tie in position is not an ordering, and falls through to rule 3.
    if (sorted[0]!.logIndex! < sorted[1]!.logIndex!) {
      return { winner: sorted[0]!, losers: others(candidates, sorted[0]!), rule: 'EARLIER_IN_LOG' };
    }
  }

  // Rule 3: the smaller record_hash. Total and deterministic, which is why it is last.
  const byHash = [...valid].sort((a, b) => compareHashes(a.hash, b.hash));
  return { winner: byHash[0]!, losers: others(candidates, byHash[0]!), rule: 'SMALLER_HASH' };
}

function others(candidates: readonly Candidate[], winner: Candidate): Candidate[] {
  return candidates.filter((c) => c !== winner);
}

/**
 * Everything voided by a losing record: the record itself and every successor chained onto it.
 *
 * `chain` is this peer's records for the name in sequence order. A successor is void when it
 * chains onto a void predecessor, which is transitive — so a single lost registration can void
 * a year of updates, and the client has to say so.
 */
export function voidedChain(
  loser: Candidate,
  chain: readonly Candidate[],
): readonly Candidate[] {
  const voided: Candidate[] = [loser];
  const voidHashes = [loser.hash];

  // Sequence order, so a successor is always considered after its predecessor.
  const ordered = [...chain].sort((a, b) => a.record.seq - b.record.seq);
  for (const candidate of ordered) {
    if (candidate === loser) continue;
    const chainsOntoVoid = voidHashes.some(
      (h) => compareBytes(candidate.record.prevHash, h) === 0,
    );
    if (chainsOntoVoid) {
      voided.push(candidate);
      voidHashes.push(candidate.hash);
    }
  }
  return voided;
}
