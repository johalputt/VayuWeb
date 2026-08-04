/**
 * Ed25519 signing and strict verification.
 *
 * docs/spec/REGISTRY.md, "Canonical Serialisation and Signing":
 *
 *   `sig` is Ed25519 (RFC 8032) over `signing_input`. Verifiers MUST verify strictly: reject
 *   non-canonical encodings of `S`, small-order public keys, and small-order `R`. Permissive
 *   verification makes a signature malleable and therefore the record hash malleable, which
 *   hands an attacker a free grinding surface at the tie-break.
 *
 * That last sentence is the whole reason this module is not a one-line wrapper. Ed25519 has a
 * notoriously wide range of "valid" depending on which paper an implementation followed, and
 * the permissive end of that range lets a third party take a signature that verifies and
 * produce a *different* byte string that also verifies over the same message and key. For most
 * protocols that is a curiosity. Here the record hash covers `sig`, so a second valid
 * signature is a second valid record hash for the same logical record — and the convergence
 * tie-break in REGISTRY.md awards a contested name to the *smaller* record hash. Malleability
 * would therefore let an attacker who expects a tie grind the tie-break for free, without
 * redoing the proof-of-work that is supposed to price exactly that attack.
 *
 * Strictness here means three things, and they are enforced in this order:
 *
 *   1. `S` must be canonically reduced (`S < L`). A non-canonical `S` is the classic
 *      malleability vector: add the group order and you have a second signature.
 *   2. The public key must not be a small-order point. A small-order key makes signatures
 *      verify for messages the key holder never signed.
 *   3. `R` must not be small-order, and cofactorless verification is used rather than the
 *      cofactored variant, so the set of accepted signatures is the narrow RFC 8032 set
 *      rather than the wider ZIP-215 set.
 *
 * Items 1 and 3 come from the underlying library's RFC 8032 mode. Item 2 is asserted here as
 * well rather than assumed, because the cost is a table lookup and the failure is silent.
 */

import { ed25519 } from '@noble/curves/ed25519';

/** Length of an Ed25519 public key in bytes. */
export const PUBLIC_KEY_LENGTH = 32;

/** Length of an Ed25519 secret (seed) in bytes. */
export const SECRET_KEY_LENGTH = 32;

/** Length of an Ed25519 signature in bytes. */
export const SIGNATURE_LENGTH = 64;

/**
 * Points of order 1, 2, 4 or 8 on Curve25519, in their encoded forms, including the
 * non-canonical encodings that decode to the same points.
 *
 * A public key that is one of these accepts signatures the key holder never produced, so a
 * record signed by such a key proves nothing about who authored it. There is no legitimate
 * reason for one to appear as an owner key: it cannot have been produced by key generation
 * from a seed. Its presence means either a bug or an attempt.
 */
const SMALL_ORDER_ENCODINGS: ReadonlySet<string> = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '0100000000000000000000000000000000000000000000000000000000000080',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
]);

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** Reasons a signature or key can be refused. Distinct so callers can log precisely. */
export type SignatureRejection =
  | 'BAD_KEY_LENGTH'
  | 'SMALL_ORDER_KEY'
  | 'BAD_SIGNATURE_LENGTH'
  | 'BAD_SIG';

export class SignatureError extends Error {
  readonly code: SignatureRejection;
  constructor(code: SignatureRejection, message: string) {
    super(`${code}: ${message}`);
    this.name = 'SignatureError';
    this.code = code;
  }
}

/**
 * True when `key` is a small-order point and therefore unusable as an owner key.
 *
 * Exported because the record validator needs to reject such a key at schema level, before it
 * reaches signature verification: REGISTER carries `ownerKey` and the signature is checked
 * against it, so a small-order key would otherwise be self-certifying.
 */
export function isSmallOrderKey(key: Uint8Array): boolean {
  return key.length === PUBLIC_KEY_LENGTH && SMALL_ORDER_ENCODINGS.has(toHex(key));
}

/**
 * Verify an Ed25519 signature strictly, returning a boolean rather than throwing.
 *
 * Returns false for every failure mode, including malformed lengths, so a caller in a
 * validation loop cannot accidentally treat a structural error as a pass. Use
 * {@link assertValidSignature} when the reason matters.
 */
export function verifyStrict(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== PUBLIC_KEY_LENGTH) return false;
  if (signature.length !== SIGNATURE_LENGTH) return false;
  if (isSmallOrderKey(publicKey)) return false;

  try {
    // zip215: false selects RFC 8032 cofactorless verification, which rejects non-canonical
    // S and small-order R. The permissive ZIP-215 rules accept a strictly wider set and are
    // the wrong choice wherever a signature is covered by a hash that decides an outcome.
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    // A malformed point or scalar throws rather than returning false. Both are refusals.
    return false;
  }
}

/** Verify strictly, throwing {@link SignatureError} with the specific reason on failure. */
export function assertValidSignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): void {
  if (publicKey.length !== PUBLIC_KEY_LENGTH) {
    throw new SignatureError('BAD_KEY_LENGTH', `expected 32 bytes, got ${publicKey.length}`);
  }
  if (signature.length !== SIGNATURE_LENGTH) {
    throw new SignatureError('BAD_SIGNATURE_LENGTH', `expected 64 bytes, got ${signature.length}`);
  }
  if (isSmallOrderKey(publicKey)) {
    throw new SignatureError('SMALL_ORDER_KEY', 'public key is a small-order point');
  }
  if (!verifyStrict(publicKey, message, signature)) {
    throw new SignatureError('BAD_SIG', 'signature does not verify under RFC 8032 strict rules');
  }
}

/**
 * Sign a message.
 *
 * The secret key never leaves this process and is never placed in a record, an index or the
 * log. The desktop client is specified to hold it in the operating system keychain; nothing
 * in the registry layer should accept one from a config file.
 */
export function sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  if (secretKey.length !== SECRET_KEY_LENGTH) {
    throw new SignatureError(
      'BAD_KEY_LENGTH',
      `secret key must be 32 bytes, got ${secretKey.length}`,
    );
  }
  return ed25519.sign(message, secretKey);
}

/** Derive the public key for a secret key. */
export function publicKeyFrom(secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== SECRET_KEY_LENGTH) {
    throw new SignatureError(
      'BAD_KEY_LENGTH',
      `secret key must be 32 bytes, got ${secretKey.length}`,
    );
  }
  return ed25519.getPublicKey(secretKey);
}

/** The Ed25519 group order L, as a bigint. A canonical `S` satisfies `0 <= S < L`. */
export const GROUP_ORDER = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;

/**
 * True when the `S` half of a signature is canonically reduced.
 *
 * Exposed for the conformance vectors: a test that asserts "this malleated signature is
 * rejected" is only meaningful if it can also assert that the malleation actually produced a
 * non-canonical `S` rather than random bytes.
 */
export function isCanonicalScalar(signature: Uint8Array): boolean {
  if (signature.length !== SIGNATURE_LENGTH) return false;
  // S is the second 32 bytes, little-endian.
  let s = 0n;
  for (let i = SIGNATURE_LENGTH - 1; i >= 32; i--) {
    s = (s << 8n) | BigInt(signature[i]);
  }
  return s < GROUP_ORDER;
}
