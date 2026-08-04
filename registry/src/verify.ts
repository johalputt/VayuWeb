/**
 * Record verification against registry state.
 *
 * docs/spec/REGISTRY.md, "Verification". That section's pseudocode is normative down to the
 * order of its checks, and this module follows it in order deliberately: a record with two
 * defects must produce the same rejection code on every implementation, or the code stops
 * being a fact about the record and becomes a fact about whose verifier you asked.
 *
 * Verification makes no network call. A verifier that asks a peer for a verdict has replaced
 * verification with trust, which is the property the whole registry exists to avoid.
 *
 * The clock enters only through the `now` parameter, and registry state only through the
 * {@link RegistryView} the caller supplies. Both are injected rather than read here so that a
 * test can place a record at any instant against any history, and so that this module has no
 * ambient authority to consult anything it was not handed.
 */

import { encode, decode } from './cbor.ts';
import {
  MAX_RECORD_BYTES,
  parseRecord,
  RecordError,
  type Operation,
  type RecordRejection,
  type RegistryRecord,
} from './record.ts';
import { recordHashFromBytes, signingInput, isZeroHash, bytesEqual } from './domain.ts';
import { verifyStrict } from './signature.ts';

/** A registration term is exactly one year. Not "about" a year: an exact equality is checked. */
export const TERM_SECONDS = 31_536_000;

/** The renewal window opens 60 days before expiry. */
export const RENEWAL_WINDOW_SECONDS = 5_184_000;

/** Minimum gap between a record and its predecessor, and the tolerated clock skew. */
export const MIN_INTERVAL_SECONDS = 300;
export const MAX_CLOCK_SKEW_SECONDS = 300;

/** A record whose term begins more than a day in the past is refused outright. */
export const MAX_BACKDATE_SECONDS = 86_400;

export type VerifyRejection =
  | RecordRejection
  | 'NAME_TAKEN'
  | 'BACKDATED'
  | 'BAD_SIG'
  | 'BAD_POW'
  | 'NO_PREDECESSOR'
  | 'TOO_SOON'
  | 'REVOKED'
  | 'BAD_OWNER';

/**
 * A record whose term starts beyond the skew tolerance is neither accepted nor rejected: the
 * verifier's clock may simply be behind. It is held and reconsidered later.
 */
export type DeferralReason = 'CLOCK_SKEW';

export type Verdict =
  | { readonly outcome: 'accept'; readonly record: RegistryRecord }
  | { readonly outcome: 'reject'; readonly code: VerifyRejection; readonly detail: string }
  | { readonly outcome: 'defer'; readonly reason: DeferralReason; readonly detail: string };

/** The accepted predecessor for one `name.tld`, with the hash of its exact serialised bytes. */
export interface Predecessor {
  readonly record: RegistryRecord;
  /** `record_hash` over the bytes as they were accepted, not a re-encoding of a parsed copy. */
  readonly hash: Uint8Array;
}

/**
 * The verifier's own linearised log. Every method answers from local state only.
 *
 * There is deliberately no default implementation. A view that answered permissively — a
 * `difficulty` of zero, a `powVerified` of true — would make every caller that forgot to supply
 * one silently accept unproven records, and that failure is invisible in a passing test suite.
 */
export interface RegistryView {
  /** The current accepted record for this name, or null when the name has no history. */
  current(name: string, tld: string): Predecessor | null;
  /**
   * True when a prior registration has expired and finished quarantine, so the name is once
   * more in the open pool and a fresh REGISTER may take it.
   */
  fullyReleased(previous: Predecessor, now: number): boolean;
  /** True once a REVOKE has been accepted for this name; no later record is ever accepted. */
  revoked(name: string, tld: string): boolean;
  /**
   * Verify the proof of work against the difficulty currently required for this name's TLD.
   *
   * Separate from this module because difficulty is a function of the trailing 30 days of
   * registrations, which is index state, and because the Argon2id evaluation is the one part of
   * verification that is deliberately expensive.
   */
  powVerified(record: RegistryRecord): boolean;
}

const reject = (code: VerifyRejection, detail: string): Verdict =>
  ({ outcome: 'reject', code, detail }) as const;

const defer = (reason: DeferralReason, detail: string): Verdict =>
  ({ outcome: 'defer', reason, detail }) as const;

/**
 * Clock discipline, applied to every operation rather than to REGISTER alone.
 *
 * REGISTRY.md's pseudocode places the skew and backdating checks inside the REGISTER branch.
 * Implementing it that way leaves RENEW's term start unbounded above: the window check
 * (`notBefore >= prev.notAfter - 5184000`) is a lower bound only, and `notAfter` is then
 * derived as `max(prev.notAfter, notBefore) + 31536000`. A renewal naming a `notBefore` far in
 * the future therefore buys a term ending far in the future, for one proof of work — defeating
 * the property RENEW exists to create, that holding ten thousand names is a recurring annual
 * cost rather than a one-off.
 *
 * Applying the same bound to every operation closes it without touching the intended
 * semantics: for every operation the term begins at the moment of the act, so `notBefore` is
 * always approximately `now`. Early renewal is unaffected, because "early" there means early
 * relative to the predecessor's expiry, not in the future relative to the clock.
 */
function clockVerdict(notBefore: number, now: number): Verdict | null {
  if (notBefore > now + MAX_CLOCK_SKEW_SECONDS) {
    return defer('CLOCK_SKEW', `notBefore ${notBefore} is ahead of the verifier clock`);
  }
  if (notBefore < now - MAX_BACKDATE_SECONDS) {
    return reject('BACKDATED', `notBefore ${notBefore} is more than a day in the past`);
  }
  return null;
}

/**
 * Verify a record as received, in its exact serialised bytes.
 *
 * Taking bytes rather than a parsed record is not a convenience: `record_hash` is computed over
 * bytes, and a verifier that parsed elsewhere and verified here could be handed a parsed object
 * that no longer corresponds to the bytes its hash was taken over.
 */
export function verify(
  bytes: Uint8Array,
  state: RegistryView,
  now: number,
): Verdict {
  // Framing first. A record that is not the unique deterministic encoding of its own content
  // has a malleable record_hash, and record_hash is the convergence tie-break.
  if (bytes.length > MAX_RECORD_BYTES) {
    return reject('TOO_LARGE', `${bytes.length} bytes exceeds ${MAX_RECORD_BYTES}`);
  }

  let record: RegistryRecord;
  try {
    const decoded = decode(bytes);
    if (!(decoded instanceof Map)) return reject('NOT_A_MAP', 'record must be a CBOR map');
    record = parseRecord(decoded);
    // Belt and braces against a decoder that normalises where it should refuse: re-encode and
    // require the bytes back. decode() already rejects non-canonical input, so this can only
    // fire if that guarantee regresses — which is exactly when it matters.
    if (!bytesEqual(encode(decoded), bytes)) {
      return reject('NON_CANONICAL', 'bytes are not the deterministic encoding of their content');
    }
  } catch (error) {
    if (error instanceof RecordError) return reject(error.code, error.message);
    return reject('NON_CANONICAL', error instanceof Error ? error.message : 'undecodable');
  }

  // parseRecord has already enforced version, op closure, the label grammar, the ratified TLD
  // set, the entry cap and entry shapes, in that order.

  const input = signingInput(record.map);
  const previous = state.current(record.name, record.tld);

  const clock = clockVerdict(record.notBefore, now);
  if (record.op === 'REGISTER') {
    if (record.seq !== 0 || !isZeroHash(record.prevHash)) {
      return reject('BAD_CHAIN', 'REGISTER must carry seq 0 and a zero prevHash');
    }
    if (previous !== null && !state.fullyReleased(previous, now)) {
      return reject('NAME_TAKEN', `${record.name}.${record.tld} is held`);
    }
    if (record.notAfter - record.notBefore !== TERM_SECONDS) {
      return reject('BAD_TERM', 'a registration term is exactly one year');
    }
    if (clock !== null) return clock;
    if (!verifyStrict(record.ownerKey, input, record.sig)) {
      return reject('BAD_SIG', 'signature does not verify under ownerKey');
    }
    if (!state.powVerified(record)) {
      return reject('BAD_POW', 'proof of work does not meet the required difficulty');
    }
    return { outcome: 'accept', record };
  }

  if (previous === null) {
    return reject('NO_PREDECESSOR', `${record.name}.${record.tld} has no accepted history`);
  }
  const prev = previous.record;

  if (record.seq !== prev.seq + 1) {
    return reject('BAD_SEQ', `seq ${record.seq} does not follow ${prev.seq}`);
  }
  if (!bytesEqual(record.prevHash, previous.hash)) {
    return reject('BAD_CHAIN', 'prevHash does not match the predecessor');
  }
  if (record.notBefore < prev.notBefore + MIN_INTERVAL_SECONDS) {
    return reject('TOO_SOON', 'notBefore is less than 300s after the predecessor');
  }
  // See clockVerdict: this bound is absent from the pseudocode outside REGISTER, and its
  // absence is what makes a single RENEW able to buy an unbounded term.
  if (clock !== null) return clock;
  if (state.revoked(record.name, record.tld)) {
    return reject('REVOKED', 'the name has been revoked and accepts no further records');
  }
  // Authority comes from the PREDECESSOR's key. On a TRANSFER the incoming key signs the
  // countersignature, never the record itself.
  if (!verifyStrict(prev.ownerKey, input, record.sig)) {
    return reject('BAD_SIG', 'signature does not verify under the predecessor ownerKey');
  }
  if (record.op !== 'TRANSFER' && !bytesEqual(record.ownerKey, prev.ownerKey)) {
    return reject('BAD_OWNER', `${record.op} must not change ownerKey`);
  }
  if (record.op !== 'RENEW' && record.powProof !== null) {
    return reject('UNEXPECTED_POW', `${record.op} must carry powProof null`);
  }

  return verifyOperation(record, prev, input, state);
}

function verifyOperation(
  record: RegistryRecord,
  prev: RegistryRecord,
  input: Uint8Array,
  state: RegistryView,
): Verdict {
  const op: Operation = record.op;
  switch (op) {
    case 'UPDATE':
      if (record.notAfter !== prev.notAfter) {
        return reject('BAD_TERM', 'UPDATE must not change notAfter');
      }
      break;

    case 'RENEW': {
      if (record.powProof === null) {
        return reject('MISSING_POW', 'RENEW requires a proof of work');
      }
      if (record.notBefore < prev.notAfter - RENEWAL_WINDOW_SECONDS) {
        return reject('TOO_SOON', 'the renewal window opens 60 days before expiry');
      }
      // Renewing early extends from the existing expiry and never truncates a term; renewing
      // inside grace restarts from the moment of renewal.
      const base = Math.max(prev.notAfter, record.notBefore);
      if (record.notAfter !== base + TERM_SECONDS) {
        return reject('BAD_TERM', `RENEW must set notAfter to ${base + TERM_SECONDS}`);
      }
      if (!state.powVerified(record)) {
        return reject('BAD_POW', 'proof of work does not meet the required difficulty');
      }
      break;
    }

    case 'TRANSFER': {
      if (bytesEqual(record.ownerKey, prev.ownerKey)) {
        return reject('BAD_OWNER', 'TRANSFER must name a different ownerKey');
      }
      if (record.notAfter !== prev.notAfter) {
        return reject('BAD_TERM', 'TRANSFER must not change notAfter');
      }
      // The countersignature is what makes transfer-to-a-key-nobody-holds impossible. Without
      // it the outgoing owner could send a name into a black hole indistinguishable from a burn.
      if (record.coSig === null || !verifyStrict(record.ownerKey, input, record.coSig)) {
        return reject('BAD_COSIG', 'coSig does not verify under the incoming ownerKey');
      }
      break;
    }

    case 'RELEASE':
      if (record.entries.length !== 0) {
        return reject('BAD_RECORD_ENTRY', 'RELEASE must carry no entries');
      }
      if (record.notAfter !== record.notBefore) {
        return reject('BAD_TERM', 'RELEASE must expire immediately');
      }
      break;

    case 'REVOKE':
      if (record.entries.length !== 0) {
        return reject('BAD_RECORD_ENTRY', 'REVOKE must carry no entries');
      }
      if (record.notAfter !== prev.notAfter) {
        return reject('BAD_TERM', 'REVOKE must not change notAfter');
      }
      break;

    case 'REGISTER':
      // Handled before the predecessor branch; unreachable.
      return reject('UNKNOWN_OP', 'REGISTER reached the successor path');

    default: {
      // Exhaustiveness: adding an operation without a branch here fails to compile rather than
      // falling through to an accept.
      const unreachable: never = op;
      return reject('UNKNOWN_OP', `unhandled operation: ${String(unreachable)}`);
    }
  }

  return { outcome: 'accept', record };
}

/**
 * Build a predecessor from the exact bytes it was accepted as.
 *
 * The hash is taken over those bytes rather than over a re-encoding of the parsed record, so a
 * caller cannot accidentally chain onto a hash of something it merely believes is equivalent.
 */
export function predecessorFrom(record: RegistryRecord, bytes: Uint8Array): Predecessor {
  return { record, hash: recordHashFromBytes(bytes) };
}
