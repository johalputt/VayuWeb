/**
 * The cryptographic suite registry.
 *
 * docs/spec/CRYPTO-AGILITY.md section 3. Its section 1 states the rule this module exists to
 * make true:
 *
 *   "No primitive is named in the protocol. Only suites are, and every signed object carries the
 *    identifier of the suite that produced it."
 *
 * That rule was unimplementable until this existed. The record schema had no `suite` field, so
 * section 4.2 ("reject a record whose suite it does not know"), section 5.1 (a name's suite moves
 * forward only) and conformance items 2, 3, 6 and 7 each tested a field that was not there —
 * while the schema pinned `ownerKey` to 32 bytes and `sig` to 64, which the same document calls
 * defective in terms. Two documents also asserted the field existed: CRYPTO-AGILITY.md's own
 * "See also" described REGISTRY.md as "the record format that carries `suite`", and LONGEVITY.md
 * recorded as a verdict that it "is present from record zero".
 *
 * It matters more than an ordinary gap because the document says why: "a record format without a
 * suite identifier is a record format that can never migrate". Every other future-proofing
 * decision can be made later. This one cannot.
 *
 * ## Why the sizes are here rather than in the verifier
 *
 * A verifier that hard-codes 32 and 64 works perfectly until the day it must not. ML-DSA-65 is
 * roughly 1,952 and 3,309 bytes; SLH-DSA-SHAKE-128s signs in about 7,856. A record grows by one
 * to two orders of magnitude on migration, so the record size limit is a property of the suite
 * and not of the protocol — CRYPTO-AGILITY.md 3.2 says so directly, against REGISTRY.md's former
 * flat 4096.
 *
 * The reserved rows carry real figures rather than placeholders for one reason: a placeholder
 * that has never been compared against anything is how a limit turns out to be wrong on the day
 * it is first used, which is the day of an emergency migration.
 */

/** One entry in the suite registry. Every field is what a verifier reads instead of assuming. */
export interface Suite {
  /** Assigned only by VWIP, never reused, never renumbered (CRYPTO-AGILITY.md 3). */
  readonly id: number;
  readonly signature: string;
  /**
   * The record hash this suite uses.
   *
   * BLAKE2b-256 for suite 1, matching REGISTRY.md and Hypercore's own primitive. The suite table
   * in CRYPTO-AGILITY.md said SHA-256, which disagreed with the specification that defines record
   * bytes, with the conformance vectors and with every implementation; corrected there.
   */
  readonly hash: string;
  readonly publicKeyLength: number;
  readonly signatureLength: number;
  /**
   * The largest serialised record this suite admits.
   *
   * Per suite rather than global, per CRYPTO-AGILITY.md 3.2. The reserved figures are suite 1's
   * 4096 bytes of non-signature content plus that suite's own key and signature material, rounded
   * up to a whole number of KiB: enough for the same record, not a new allowance.
   */
  readonly maxRecordBytes: number;
  /**
   * False for a reserved suite. A reserved suite is one the format can carry and no record may
   * name; activating it is a VWIP with an activation epoch (CRYPTO-AGILITY.md 3.1).
   */
  readonly active: boolean;
  /** Why the suite exists, in the registry's own terms. */
  readonly status: string;
}

/** The suite every record carries today. */
export const LAUNCH_SUITE = 1;

const TABLE: readonly Suite[] = [
  {
    id: 1,
    signature: 'Ed25519',
    hash: 'BLAKE2b-256',
    publicKeyLength: 32,
    signatureLength: 64,
    maxRecordBytes: 4096,
    active: true,
    status: 'Launch default. Fast, small, universally implemented. Not quantum-resistant.',
  },
  {
    id: 2,
    signature: 'Ed25519 + ML-DSA-65 (hybrid)',
    hash: 'BLAKE2b-256',
    // A hybrid carries both, and both MUST verify (4.4). The lengths are the concatenation, so
    // that a verifier reading this table cannot size a buffer for one component and lose the
    // other — which is the shape of the classic hybrid implementation error 4.4 warns about.
    publicKeyLength: 32 + 1952,
    signatureLength: 64 + 3309,
    maxRecordBytes: 12288,
    active: false,
    status: 'Reserved — transition. Both signatures MUST verify; secure if either survives.',
  },
  {
    id: 3,
    signature: 'ML-DSA-65',
    hash: 'SHA3-256',
    publicKeyLength: 1952,
    signatureLength: 3309,
    maxRecordBytes: 12288,
    active: false,
    status: 'Reserved — post-quantum. FIPS 204.',
  },
  {
    id: 4,
    signature: 'SLH-DSA-SHAKE-128s',
    hash: 'SHAKE-256',
    publicKeyLength: 32,
    signatureLength: 7856,
    maxRecordBytes: 16384,
    active: false,
    status: 'Reserved — conservative fallback. FIPS 205; the break-glass suite.',
  },
];

export const SUITES: ReadonlyMap<number, Suite> = new Map(TABLE.map((s) => [s.id, s]));

/**
 * The suite a record may name, or null.
 *
 * Returns null for a reserved suite as well as for an unknown one, because CRYPTO-AGILITY.md 3.1
 * makes "reserved" mean the format can carry it and no record may use it. Answering with a
 * reserved suite would let a record name a signature scheme nothing can verify, and 4.2 forbids
 * accepting such a record provisionally.
 */
export function suiteOf(id: number): Suite | null {
  if (!Number.isSafeInteger(id)) return null;
  const suite = SUITES.get(id);
  return suite !== undefined && suite.active ? suite : null;
}

/** Every active suite. One today; the plural is the point. */
export function activeSuites(): readonly Suite[] {
  return TABLE.filter((s) => s.active);
}

/**
 * The largest record any ACTIVE suite admits — the bound a verifier applies before decoding.
 *
 * The size check has to happen twice, and the reason is worth stating because a second
 * implementation will meet it: the suite is a field *inside* the record, so nothing can consult
 * a per-suite limit until the bytes have been decoded, and decoding unbounded input is the
 * denial-of-service the outer limit exists to stop. So the outer bound is the maximum over
 * active suites, and the suite's own bound is applied after parsing.
 *
 * Deliberately not the maximum over ALL suites. Sizing it to suite 4 would hand an attacker four
 * times the parsing work per record for suites no key can sign with today.
 */
export const MAX_ACTIVE_RECORD_BYTES: number = activeSuites().reduce(
  (max, s) => Math.max(max, s.maxRecordBytes),
  0,
);

// A table nobody can read is not a table. Fail at load rather than at the first record.
if (SUITES.get(LAUNCH_SUITE)?.active !== true) {
  throw new Error(`suite ${LAUNCH_SUITE} must be active`);
}
