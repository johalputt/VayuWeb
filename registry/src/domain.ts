/**
 * Domain separation, record hashing and signing input.
 *
 * docs/spec/REGISTRY.md, "Canonical Serialisation and Signing":
 *
 *   signing_input = "VayuWeb-Registry-Record-v1" || 0x00 || uint8(suite) || det_cbor(core)
 *   record_hash   = BLAKE2b-256("VayuWeb-Registry-Hash-v1" || 0x00 || det_cbor(full))
 *
 * `core` is the record map with `sig` and `coSig` removed; `full` is the complete map
 * including them.
 *
 * The prefixes are what stop a signature made over one VayuWeb structure being replayed as
 * another, and stop a signing input being read as a hash preimage. They are therefore
 * consensus-critical constants: an implementation that gets a single byte wrong produces
 * signatures no other implementation will accept, which is a silent fork rather than a visible
 * error. The byte lengths are asserted at module load and pinned again in the tests, because
 * this is a value that must never drift, and a specification prose error about it has already
 * happened once — REGISTRY.md described these as 23 and 21 bytes when the literal strings are
 * 26 and 24. The literal strings in the normative code block are authoritative; the prose
 * count was the error.
 */

import { blake2b } from '@noble/hashes/blake2';

import { encode, type CborMap, type CborValue } from './cbor.ts';

/** Domain-separation prefix for the Ed25519 signing input over a registry record. */
export const RECORD_SIGNING_PREFIX = 'VayuWeb-Registry-Record-v1';

/** Domain-separation prefix for the BLAKE2b-256 record hash. */
export const RECORD_HASH_PREFIX = 'VayuWeb-Registry-Hash-v1';

/** Length of a record hash in bytes. BLAKE2b-256, matching Hypercore's own primitive. */
export const RECORD_HASH_LENGTH = 32;

/** The all-zero hash used as `prevHash` when `seq` is 0. */
export const ZERO_HASH: Uint8Array = new Uint8Array(RECORD_HASH_LENGTH);

/** Fields excluded from the signing input, because they carry the signatures themselves. */
const SIGNATURE_FIELDS = ['sig', 'coSig'] as const;

const asciiPrefix = (literal: string): Uint8Array => {
  const bytes = new TextEncoder().encode(literal);
  for (const b of bytes) {
    if (b < 0x20 || b > 0x7e) {
      throw new Error(`domain prefix must be printable ASCII: ${literal}`);
    }
  }
  return bytes;
};

const SIGNING_PREFIX_BYTES = asciiPrefix(RECORD_SIGNING_PREFIX);
const HASH_PREFIX_BYTES = asciiPrefix(RECORD_HASH_PREFIX);

// Fail at load rather than at first divergence. A wrong prefix length is not something to
// discover from a peer refusing your records.
if (SIGNING_PREFIX_BYTES.length !== 26) {
  throw new Error(`signing prefix must be 26 bytes, got ${SIGNING_PREFIX_BYTES.length}`);
}
if (HASH_PREFIX_BYTES.length !== 24) {
  throw new Error(`hash prefix must be 24 bytes, got ${HASH_PREFIX_BYTES.length}`);
}

// The two prefixes must not share a prefix relationship, or a crafted body could make one
// domain's input parse as another's. Distinct lengths plus distinct content is sufficient here,
// but the check is cheap and survives someone editing the literals later.
if (
  RECORD_SIGNING_PREFIX.startsWith(RECORD_HASH_PREFIX) ||
  RECORD_HASH_PREFIX.startsWith(RECORD_SIGNING_PREFIX)
) {
  throw new Error('domain prefixes must not be prefixes of one another');
}

/** Concatenate a domain prefix, its 0x00 separator, optional extra bytes, and a body. */
function withDomain(
  prefix: Uint8Array,
  body: Uint8Array,
  extra: readonly number[] = [],
): Uint8Array {
  const out = new Uint8Array(prefix.length + 1 + extra.length + body.length);
  out.set(prefix, 0);
  out[prefix.length] = 0x00;
  out.set(extra, prefix.length + 1);
  out.set(body, prefix.length + 1 + extra.length);
  return out;
}

/**
 * Return a copy of `record` with the signature fields removed — the `core` map.
 *
 * A copy is returned rather than mutating in place: the caller's record is frequently the
 * object about to be stored or replicated, and silently stripping its signature would be a
 * spectacular action at a distance.
 */
export function core(record: CborMap): CborMap {
  const stripped: CborMap = new Map();
  for (const [key, value] of record) {
    if (typeof key === 'string' && (SIGNATURE_FIELDS as readonly string[]).includes(key)) {
      continue;
    }
    stripped.set(key, value);
  }
  return stripped;
}

/**
 * The exact bytes an Ed25519 signature is made over.
 *
 * Unknown fields are deliberately retained: REGISTRY.md requires that a record carrying fields
 * this version does not understand still verifies downstream, so the signing input covers
 * whatever the author actually signed rather than only the fields we recognise.
 */
export function signingInput(record: CborMap): Uint8Array {
  // CRYPTO-AGILITY.md 4.3 puts the suite identifier inside the domain-separated prefix, so a
  // signature made under one suite cannot be replayed as another. Belt and braces: `suite` is
  // also a field inside `core` and so already covered. The requirement is kept because the cost
  // is one byte and the failure it prevents — a cross-suite replay during the one migration this
  // protocol gets — is not recoverable.
  //
  // A missing or malformed `suite` throws rather than defaulting. This function is called to
  // BUILD records as well as to check them, and a builder that omitted the field would otherwise
  // produce a signature over the pre-agility input — valid-looking bytes that no verifier
  // implementing 4.3 will accept, discovered only when a peer refuses them.
  const suite = record.get('suite');
  if (typeof suite !== 'number' || !Number.isInteger(suite) || suite < 0 || suite > 255) {
    throw new Error(
      'signingInput: a record needs an integer `suite` in 0..255 (CRYPTO-AGILITY 4.3)',
    );
  }
  return withDomain(SIGNING_PREFIX_BYTES, encode(core(record)), [suite]);
}

/**
 * The record hash: BLAKE2b-256 over the domain-separated bytes, hashed as they arrived.
 *
 * It covers the full record including `sig` and `coSig`, because the hash identifies the record as
 * it exists on the wire — which is what `prevHash` chains to and what the convergence tie-break
 * compares.
 *
 * REGISTRY.md: "A peer MUST NOT re-serialise a record it did not author: received bytes are
 * stored and replicated verbatim". Decoding and re-encoding to compute a hash would defeat that,
 * so this takes bytes and there is no longer a sibling that takes a map.
 *
 * **There was one, called `recordHash`, and the shorter name did the forbidden thing.** Anyone
 * reaching for "hash a record" found it first and got a hash that is right only if the record
 * re-encodes byte-identically — true here, but only because `cbor.ts` refuses non-canonical input
 * on decode, which is a guarantee made in another module and stated in neither. Nothing authored a
 * record and needed its hash from the map, so the trap went rather than being documented.
 */
export function recordHashFromBytes(recordBytes: Uint8Array): Uint8Array {
  return blake2b(withDomain(HASH_PREFIX_BYTES, recordBytes), { dkLen: RECORD_HASH_LENGTH });
}

/** Constant-time equality for hashes and other fixed-length secrets-adjacent values. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** True when `hash` is the all-zero hash required of a `REGISTER` record's `prevHash`. */
export function isZeroHash(hash: Uint8Array): boolean {
  return bytesEqual(hash, ZERO_HASH);
}

export type { CborMap, CborValue };
