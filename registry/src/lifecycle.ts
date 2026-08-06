/**
 * Name lifecycle: live, grace, quarantine, free.
 *
 * docs/spec/REGISTRY.md, "Operations". The verifier delegates two questions here —
 * "may this name be registered?" and "may this name still be renewed?" — and both are pure
 * functions of the predecessor record and the clock.
 *
 * The states, and why each exists:
 *
 *   LIVE        notBefore <= now < notAfter          the name resolves
 *   GRACE       notAfter <= now < notAfter + 30d     only the owner may renew
 *   QUARANTINE  grace end <= now < grace end + 30d   nobody may register
 *   FREE        after quarantine                     open pool
 *
 * Grace protects an owner who missed a renewal. Quarantine protects everyone else from the
 * owner's misfortune becoming someone else's opportunity: without it, watching the log for
 * expiries and registering the instant grace lapses is a profitable business, and the value of
 * a name would accrue to whoever runs the fastest bot rather than to whoever built something on
 * it. It is deliberately not skippable, including by the owner.
 *
 * Two operations change the shape:
 *
 * - RELINQUISH skips grace, because the owner has said they are done, but NOT quarantine, whose
 *   purpose is front-running rather than protecting the owner.
 * - REVOKE freezes the name for the remainder of its term and then quarantines it. A revoked
 *   name accepts no further record from anyone, which is what makes it a deadman switch for a
 *   compromised key. It destroys rather than recovers: a registry with no identity layer cannot
 *   tell an owner from a thief holding the same key.
 */

import type { Operation, RegistryRecord } from './record.ts';

/** Grace and quarantine are 30 days each. */
export const GRACE_SECONDS = 2_592_000;
export const QUARANTINE_SECONDS = 2_592_000;

export type NameState = 'LIVE' | 'GRACE' | 'QUARANTINE' | 'FREE' | 'PENDING';

/**
 * The instants at which a name changes state, derived from its most recent accepted record.
 *
 * Computed as a whole rather than answered question by question, so that the boundaries cannot
 * drift between the "can it be registered" path and the "can it be renewed" path — the two
 * places that would silently disagree.
 */
export interface Lifecycle {
  readonly liveFrom: number;
  readonly liveUntil: number;
  readonly graceUntil: number;
  readonly quarantineUntil: number;
  /** True when the name will never accept another record from anyone. */
  readonly revoked: boolean;
}

export function lifecycleOf(record: RegistryRecord): Lifecycle {
  const op: Operation = record.op;

  // RELINQUISH sets notAfter == notBefore, so the name expires at the moment of the act. Grace is
  // skipped; quarantine still runs from that instant.
  if (op === 'RELINQUISH') {
    const at = record.notAfter;
    return {
      liveFrom: record.notBefore,
      liveUntil: at,
      graceUntil: at,
      quarantineUntil: at + QUARANTINE_SECONDS,
      revoked: false,
    };
  }

  // REVOKE stops resolution at once but holds the name frozen for the rest of its term, then
  // quarantines it. Freezing rather than freeing is the point: releasing a name the moment a
  // key is known-compromised would hand it to whoever is watching.
  if (op === 'REVOKE') {
    return {
      liveFrom: record.notBefore,
      liveUntil: record.notBefore,
      graceUntil: record.notAfter,
      quarantineUntil: record.notAfter + QUARANTINE_SECONDS,
      revoked: true,
    };
  }

  const graceUntil = record.notAfter + GRACE_SECONDS;
  return {
    liveFrom: record.notBefore,
    liveUntil: record.notAfter,
    graceUntil,
    quarantineUntil: graceUntil + QUARANTINE_SECONDS,
    revoked: false,
  };
}

export function stateAt(record: RegistryRecord, now: number): NameState {
  const life = lifecycleOf(record);
  if (now < life.liveFrom) return 'PENDING';
  if (now < life.liveUntil) return 'LIVE';
  if (now < life.graceUntil) return 'GRACE';
  if (now < life.quarantineUntil) return 'QUARANTINE';
  return 'FREE';
}

/**
 * May a fresh REGISTER take this name?
 *
 * Only once quarantine has fully elapsed. A revoked name is not special-cased: its quarantine
 * runs from the end of its frozen term, so this returns false throughout and true afterwards,
 * which is what "the name stays frozen for the rest of its term plus 30 days of quarantine
 * before returning to the open pool" means.
 */
export function isFullyReleased(record: RegistryRecord, now: number): boolean {
  return now >= lifecycleOf(record).quarantineUntil;
}

/**
 * May a successor of this operation still be accepted?
 *
 * Operation-aware, because REGISTRY.md draws the line in two places. `RENEW` names its
 * precondition as "`prev` live or within its 30-day grace period" — grace exists so that a
 * missed renewal is recoverable. Every other operation names "a live `prev`": there is nothing
 * to update, transfer or release once the term has run out.
 *
 * Past grace the name is nobody's to act on. It is on its way back to the pool, and accepting a
 * record then would let the expired holder reclaim it ahead of everyone waiting out quarantine
 * — the one party who must not be able to.
 */
export function acceptsSuccessor(record: RegistryRecord, now: number, op: Operation): boolean {
  const life = lifecycleOf(record);
  if (life.revoked) return false;
  if (now < life.liveFrom) return false;
  return op === 'RENEW' ? now < life.graceUntil : now < life.liveUntil;
}

/**
 * Does this name resolve right now?
 *
 * Distinct from {@link acceptsSuccessor}: a name in grace still accepts a renewal but MUST NOT
 * resolve, or an expired registration would keep serving content indefinitely to anyone who
 * never re-queried.
 */
export function resolves(record: RegistryRecord, now: number): boolean {
  return stateAt(record, now) === 'LIVE';
}
