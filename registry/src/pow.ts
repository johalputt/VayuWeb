/**
 * Argon2id proof of work.
 *
 * docs/spec/PROOF-OF-WORK.md. Two properties carry the whole construction, and both are
 * properties of what is NOT in the record:
 *
 * 1. **The cost parameters are protocol constants, not record fields.** A record that carried
 *    its own `m`, `t` and `p` would let the registrant choose them, and `m = 8` KiB reduces a
 *    memory-hard function to a cheap one. The proof would still verify, because the verifier
 *    would be evaluating the function the attacker specified.
 *
 * 2. **The salt is derived from the record, not carried by it.** A carried salt is a free
 *    parameter, and a free parameter breaks the binding this construction exists to create:
 *    grind one (salt, nonce) pair to any difficulty, then attach that single proof to every
 *    record you ever sign. One proof of work would buy unlimited names.
 *
 * Deriving the salt from the record's own canonical bytes means a proof is valid for exactly
 * one record. Change the name, the owner, the term, the sequence number or the predecessor
 * hash, and the salt changes, so the tag changes, so the work must be redone.
 */

import { argon2id } from '@noble/hashes/argon2';
import { sha256 } from '@noble/hashes/sha2';

import { encode, type CborMap, type CborValue } from './cbor.ts';

/**
 * The algorithm identifier names the parameters it was produced under.
 *
 * It is a single opaque string rather than separate fields precisely so that the parameters
 * cannot be varied per record. A future VWIP that changes the cost changes this identifier,
 * which makes proofs from the two regimes distinguishable rather than silently comparable.
 */
export const POW_ALGORITHM = 'argon2id-v19-m65536-t2-p1';

/** RFC 9106 Argon2id, version 0x13. Memory in KiB. */
export const POW_MEMORY_KIB = 65_536;
export const POW_ITERATIONS = 2;
export const POW_LANES = 1;
export const POW_VERSION = 0x13;
export const POW_TAG_LENGTH = 32;

/** The nonce searched by the registrant. */
export const POW_NONCE_LENGTH = 16;

/** Salt derivation is domain-separated from every other hash in the protocol. */
export const POW_SALT_PREFIX = 'vayuweb-pow-v1';
export const POW_SALT_LENGTH = 16;

/** Difficulty is capped so a land rush cannot make a TLD permanently unusable. */
export const MAX_DIFFICULTY_BITS = 20;

/** Difficulty epochs are one hour, so peers with skewed clocks agree on the window. */
export const EPOCH_SECONDS = 3_600;
export const RATE_WINDOW_SECONDS = 2_592_000;

/** Registrations in the trailing window below which the rate term contributes nothing. */
export const RATE_FLOOR = 512;

const SALT_PREFIX_BYTES = new TextEncoder().encode(POW_SALT_PREFIX);

/**
 * Base difficulty by label length. Short labels are the ones worth hoarding, so a two-character
 * name costs 64 times a **sixteen**-character one: 10 bits against 4, the widest spread this
 * table produces.
 *
 * This comment said "fifteen", which is 5 bits and therefore 32 times. The two figures come from
 * different rows -- 64 is the gap to the 16-and-above branch, fifteen is the last length still
 * on 5 bits -- and PROOF-OF-WORK.md carried the same pairing. A test derives both from this
 * function rather than trusting either restatement.
 */
export function baseBits(labelLength: number): number {
  if (labelLength <= 2) return 10;
  if (labelLength === 3) return 9;
  if (labelLength === 4) return 8;
  if (labelLength <= 6) return 7;
  if (labelLength <= 9) return 6;
  if (labelLength <= 15) return 5;
  return 4;
}

/**
 * Required difficulty for a label, given how many registrations and renewals the TLD accepted
 * in the trailing 30 days.
 *
 * `windowCount` is supplied by the caller rather than read here: it is index state, and this
 * function must stay a pure function of its arguments so every peer computes the same answer.
 */
export function requiredBits(labelLength: number, windowCount: number): number {
  const base = baseBits(labelLength);
  // Every doubling of a TLD's thirty-day volume above the floor adds a bit, so a bulk
  // registrant raises the price of its own remaining work.
  const rate =
    windowCount < RATE_FLOOR ? 0 : Math.min(8, Math.floor(Math.log2(windowCount / RATE_FLOOR)));
  return Math.min(MAX_DIFFICULTY_BITS, base + rate);
}

/** The half-open trailing window whose registrations feed the rate term. */
export function rateWindow(notBefore: number): { start: number; end: number } {
  const epoch = Math.floor(notBefore / EPOCH_SECONDS);
  const end = epoch * EPOCH_SECONDS;
  return { start: end - RATE_WINDOW_SECONDS, end };
}

/**
 * The salt preimage: the record without `sig` and without `powProof.nonce`.
 *
 * `powProof.bits` stays in the preimage deliberately. The claimed difficulty is therefore
 * bound into the salt, so a proof produced for a low difficulty cannot be relabelled as
 * satisfying a higher one, nor the reverse.
 */
export function powSaltPreimage(record: CborMap): Uint8Array {
  const stripped = new Map<string | Uint8Array, CborValue>(record);
  stripped.delete('sig');

  const proof = stripped.get('powProof');
  if (proof instanceof Map) {
    const withoutNonce = new Map<string | Uint8Array, CborValue>(proof);
    withoutNonce.delete('nonce');
    stripped.set('powProof', withoutNonce);
  }

  const body = encode(stripped);
  const preimage = new Uint8Array(SALT_PREFIX_BYTES.length + body.length);
  preimage.set(SALT_PREFIX_BYTES, 0);
  preimage.set(body, SALT_PREFIX_BYTES.length);
  return preimage;
}

/** `salt = SHA-256(preimage)[0..16]`. */
export function powSalt(record: CborMap): Uint8Array {
  return sha256(powSaltPreimage(record)).slice(0, POW_SALT_LENGTH);
}

/** One Argon2id evaluation at the protocol's fixed parameters. */
export function powTag(nonce: Uint8Array, salt: Uint8Array): Uint8Array {
  return argon2id(nonce, salt, {
    m: POW_MEMORY_KIB,
    t: POW_ITERATIONS,
    p: POW_LANES,
    version: POW_VERSION,
    dkLen: POW_TAG_LENGTH,
  });
}

/**
 * Leading-zero-bit test over the whole tag, most-significant bit first, with **no early exit**.
 *
 * PROOF-OF-WORK.md makes the absence of an early exit normative. The tag is not secret, so this
 * is hygiene rather than a defence against a concrete attack — but a uniform test costs nothing,
 * and a loop that returns as soon as it sees a one bit leaks how close a rejected candidate came.
 */
export function tagSatisfies(tag: Uint8Array, bits: number): boolean {
  let leading = 0;
  let stillZero = 1;
  // Indexed rather than `for...of`: the iterator on a typed array reads through internal slots,
  // which makes "every byte was examined" unobservable to a test. Indexing keeps the normative
  // property testable instead of merely asserted in a comment.
  for (let i = 0; i < tag.length; i += 1) {
    const byte = tag[i]!;
    for (let shift = 7; shift >= 0; shift -= 1) {
      const isZero = ((byte >>> shift) & 1) === 0 ? 1 : 0;
      stillZero &= isZero;
      leading += stillZero;
    }
  }
  return leading >= bits;
}

export type PowRejection =
  | 'POW_BAD_ALGORITHM'
  | 'POW_BAD_NONCE'
  | 'POW_INSUFFICIENT_DIFFICULTY'
  | 'POW_TAG_FAILS';

/**
 * Verify a record's proof against the difficulty the verifier independently computes.
 *
 * `requiredBitsForRecord` is recomputed by the caller from its own log; the record's claimed
 * `bits` is never trusted as the requirement, only as a claim that must meet or exceed it.
 * Over-payment is valid and harmless.
 */
export function verifyPow(
  record: CborMap,
  requiredBitsForRecord: number,
): { ok: true } | { ok: false; code: PowRejection } {
  const proof = record.get('powProof');
  if (!(proof instanceof Map)) return { ok: false, code: 'POW_BAD_ALGORITHM' };

  if (proof.get('alg') !== POW_ALGORITHM) return { ok: false, code: 'POW_BAD_ALGORITHM' };

  const nonce = proof.get('nonce');
  if (!(nonce instanceof Uint8Array) || nonce.length !== POW_NONCE_LENGTH) {
    return { ok: false, code: 'POW_BAD_NONCE' };
  }

  const claimed = proof.get('bits');
  if (typeof claimed !== 'number' || claimed < requiredBitsForRecord) {
    return { ok: false, code: 'POW_INSUFFICIENT_DIFFICULTY' };
  }

  const tag = powTag(nonce, powSalt(record));
  if (!tagSatisfies(tag, claimed)) return { ok: false, code: 'POW_TAG_FAILS' };
  return { ok: true };
}

/**
 * The composition a `RegistryView.powVerified` implementation should use: recompute the
 * required difficulty from the log, then verify the proof against it.
 *
 * Offered as a function rather than left to each caller because the two halves are only sound
 * together. Verifying the tag without recomputing the requirement accepts a proof at whatever
 * difficulty its author felt like claiming, and that mistake looks like working code.
 *
 * `windowCount` is the number of accepted registrations and renewals in the record's TLD over
 * the window returned by {@link rateWindow} — index state the caller supplies.
 *
 * PROOF-OF-WORK.md permits the epoch of `notBefore` or the one immediately before it, so a
 * caller MAY pass the lower of the two counts to absorb propagation delay.
 */
export function checkRecordPow(
  record: CborMap,
  labelLength: number,
  windowCount: number,
): { ok: true } | { ok: false; code: PowRejection } {
  return verifyPow(record, requiredBits(labelLength, windowCount));
}

/**
 * Search for a nonce satisfying `bits`. Used by the registrant, never by the verifier.
 *
 * The expected number of evaluations is 2^bits and the distribution is geometric, so an
 * unlucky registrant pays several times the mean. `onAttempt` exists so a client can show
 * progress rather than a countdown, which would be a lie about a memoryless process.
 */
export function solvePow(
  record: CborMap,
  bits: number,
  options: { readonly limit?: number; readonly onAttempt?: (attempts: number) => void } = {},
): Uint8Array | null {
  const limit = options.limit ?? Number.MAX_SAFE_INTEGER;
  const proof = record.get('powProof');
  if (!(proof instanceof Map)) throw new Error('solvePow: record has no powProof map');

  const nonce = new Uint8Array(POW_NONCE_LENGTH);
  // The salt does not depend on the nonce, so it is computed once and reused across the search.
  const salt = powSalt(record);

  for (let attempts = 1; attempts <= limit; attempts += 1) {
    incrementNonce(nonce);
    if (tagSatisfies(powTag(nonce, salt), bits)) return nonce.slice();
    options.onAttempt?.(attempts);
  }
  return null;
}

/** Big-endian increment, so a search walks the nonce space without repeating. */
function incrementNonce(nonce: Uint8Array): void {
  for (let i = nonce.length - 1; i >= 0; i -= 1) {
    nonce[i] = (nonce[i]! + 1) & 0xff;
    if (nonce[i] !== 0) return;
  }
}
