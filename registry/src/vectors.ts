/**
 * Conformance test vectors.
 *
 * docs/ROADMAP.md, Phase 0: "Test vectors for every wire-visible rule", and Constitution
 * Article 44.6 — a competent implementer must be able to read the specifications alone and
 * produce a client that interoperates. Prose cannot establish that. Bytes can.
 *
 * Each vector is a record's exact serialised bytes, the registry state to verify it against,
 * the instant to verify it at, and the verdict every conforming implementation must return.
 * A second implementation that disagrees on any vector has found either its own bug or a
 * genuine ambiguity in the specification, and both are worth knowing about.
 *
 * Two deliberate choices about scope:
 *
 * - **The rejection CODE is part of the vector, not just the accept/reject outcome.** A record
 *   with two defects must produce the same code everywhere, or the code is a fact about whose
 *   verifier you asked rather than about the record. That is what makes check ORDER testable.
 *
 * - **Proof-of-work verification is injected here rather than evaluated.** A vector set whose
 *   every entry costs a 64 MiB Argon2id evaluation is a vector set nobody runs. The proof
 *   construction has its own vectors, with real solved nonces, in pow.test.ts. Mixing the two
 *   would make this file slow without making it stronger.
 *
 * The vectors are generated rather than written by hand, and the generated artifact is
 * committed. A test regenerates and compares, so a change to any encoding rule fails CI as a
 * diff in the vector file — which is the point. If the bytes move, every implementation built
 * against them needs to know.
 */

import { encode, decode, compareBytes, type CborMap, type CborValue } from './cbor.ts';
import { LIMITS, PROTOCOL_VERSION, encodeMessage } from './replicate.ts';
import { signingInput, recordHashFromBytes } from './domain.ts';
import { sign, publicKeyFrom } from './signature.ts';
import {
  POW_ALGORITHM,
  POW_NONCE_LENGTH,
  POW_TAG_LENGTH,
  RATE_FLOOR,
  MAX_DIFFICULTY_BITS,
  EPOCH_SECONDS,
  RATE_WINDOW_SECONDS,
  // Deliberately NOT importing baseBits, requiredBits or rateWindow. Every expectation in the
  // pow suite is a literal transcribed from PROOF-OF-WORK.md; computing one by calling the
  // function under test is what made the first version of this suite survive four of five
  // mutations to `pow.ts`. `powSalt` is the sole exception, and it is pinned by the artifact.
  powSalt,
} from './pow.ts';
import { TERM_SECONDS, RENEWAL_WINDOW_SECONDS, SETTLEMENT_SECONDS } from './verify.ts';
import { GRACE_SECONDS } from './lifecycle.ts';
import { RESERVED_LABELS } from './names.ts';
import { CID_PARAMETERS, cidBytes, sha256 } from './content.ts';
import { BLOCK_EXCHANGE_VERSION, BX_LIMITS, encodeBlockMessage } from './blockx.ts';

/**
 * Fixed keys. Not secret, never to be used for anything real, and constant so that the vector
 * file is byte-identical on every machine that regenerates it.
 */
export const VECTOR_OWNER_SECRET = new Uint8Array(32).fill(0x42);
export const VECTOR_OWNER_KEY = publicKeyFrom(VECTOR_OWNER_SECRET);
export const VECTOR_OTHER_SECRET = new Uint8Array(32).fill(0x77);
export const VECTOR_OTHER_KEY = publicKeyFrom(VECTOR_OTHER_SECRET);

/** A fixed instant: 2026-06-27T00:00:00Z. Vectors never depend on when they are run. */
export const VECTOR_NOW = 1_782_518_400;

export interface VectorState {
  /** Hex of the predecessor record's bytes, or null when the name has no history. */
  readonly predecessor: string | null;
  /**
   * Hex of the key that signed the predecessor. Present only when that record is a TRANSFER.
   *
   * A TRANSFER's `ownerKey` names the recipient, and Article 33.4 leaves the transferor in
   * control until the record settles — so "who may sign next" is not recoverable from the
   * predecessor's bytes alone. Without this field a vector whose predecessor is a pending
   * transfer would not be self-contained, and a second implementation could not reproduce it.
   */
  readonly transferorKey?: string;
  readonly revoked: boolean;
  readonly fullyReleased: boolean;
  /** What the injected proof-of-work verifier returns. See the note above. */
  readonly powVerified: boolean;
}

export interface Vector {
  readonly name: string;
  /** What rule this vector pins, in the specification's own terms. */
  readonly rule: string;
  readonly record: string;
  readonly now: number;
  readonly state: VectorState;
  readonly expect:
    | { readonly outcome: 'accept' }
    | { readonly outcome: 'reject'; readonly code: string }
    | { readonly outcome: 'defer'; readonly reason: string };
}

export const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export const fromHex = (hex: string): Uint8Array => {
  if (hex.length % 2 !== 0) throw new Error('hex string has an odd length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at byte ${i}`);
    out[i] = byte;
  }
  return out;
};

const powProof = (bits = 10): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['alg', POW_ALGORITHM],
    ['nonce', new Uint8Array(POW_NONCE_LENGTH).fill(7)],
    ['bits', bits],
  ]);

const entry = (type: string, value: CborValue): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['type', type],
    ['value', value],
  ]);

/** Build a record and sign it. Signatures go on last, since they are excluded from the input. */
function build(
  fields: Record<string, CborValue>,
  secret: Uint8Array = VECTOR_OWNER_SECRET,
  coSecret?: Uint8Array,
): Uint8Array {
  const map = new Map<string | Uint8Array, CborValue>(Object.entries(fields));
  const input = signingInput(map);
  map.set('sig', sign(secret, input));
  if (coSecret !== undefined) map.set('coSig', sign(coSecret, input));
  return encode(map);
}

const registration = (over: Record<string, CborValue> = {}): Uint8Array =>
  build({
    version: 1,
    suite: 1,
    op: 'REGISTER',
    name: 'atlas',
    tld: 'vayu',
    ownerKey: VECTOR_OWNER_KEY,
    seq: 0,
    notBefore: VECTOR_NOW,
    notAfter: VECTOR_NOW + TERM_SECONDS,
    records: [entry('txt', 'v=vayuweb1')],
    powProof: powProof(),
    prevHash: new Uint8Array(32),
    ...over,
  });

const PREV_BYTES = registration();
const PREV_HASH = recordHashFromBytes(PREV_BYTES);

const successor = (
  over: Record<string, CborValue>,
  secret: Uint8Array = VECTOR_OWNER_SECRET,
  coSecret?: Uint8Array,
): Uint8Array =>
  build(
    {
      version: 1,
      suite: 1,
      op: 'UPDATE',
      name: 'atlas',
      tld: 'vayu',
      ownerKey: VECTOR_OWNER_KEY,
      seq: 1,
      notBefore: VECTOR_NOW + 600,
      notAfter: VECTOR_NOW + TERM_SECONDS,
      records: [entry('txt', 'v=vayuweb1')],
      powProof: null,
      prevHash: PREV_HASH,
      ...over,
    },
    secret,
    coSecret,
  );

/** A copy of `map` with one key removed, for the missing-field vector. */
const stripField = (bytes: Uint8Array, key: string): CborMap => {
  const map = decode(bytes) as CborMap;
  map.delete(key);
  return map;
};

/**
 * The same record with its signature replaced by bytes that verify under nothing.
 *
 * Used to build two-defect vectors, which are what make check ORDER testable across
 * implementations: a record with one defect only ever produces one code, so it says nothing about
 * the sequence the checks run in.
 */
function forge(bytes: Uint8Array): Uint8Array {
  const map = decode(bytes);
  if (!(map instanceof Map)) throw new Error('a record encodes to a map');
  map.set('sig', new Uint8Array(64).fill(0xff));
  return encode(map);
}

const FRESH: VectorState = {
  predecessor: null,
  revoked: false,
  fullyReleased: false,
  powVerified: true,
};

const HELD: VectorState = { ...FRESH, predecessor: toHex(PREV_BYTES) };

/**
 * A TRANSFER of `atlas.vayu` to the other key, accepted but not yet settled.
 *
 * `SETTLING` is the state a peer holds for the fourteen days of Article 33.4's settlement delay:
 * `ownerKey` names the recipient, `transferorKey` names who still controls the name.
 */
const HANDOVER_BYTES = successor(
  {
    op: 'TRANSFER',
    ownerKey: VECTOR_OTHER_KEY,
    notAfter: VECTOR_NOW + TERM_SECONDS,
    records: [],
  },
  VECTOR_OWNER_SECRET,
  VECTOR_OTHER_SECRET,
);
const HANDOVER_HASH = recordHashFromBytes(HANDOVER_BYTES);
const HANDOVER_AT = VECTOR_NOW + 600;
const SETTLED_AT = HANDOVER_AT + SETTLEMENT_SECONDS;

const SETTLING: VectorState = {
  ...FRESH,
  predecessor: toHex(HANDOVER_BYTES),
  transferorKey: toHex(VECTOR_OWNER_KEY),
};

/** A record chaining onto the pending transfer. */
const afterHandover = (
  over: Record<string, CborValue>,
  secret: Uint8Array,
  coSecret?: Uint8Array,
): Uint8Array =>
  build(
    {
      version: 1,
      suite: 1,
      op: 'UPDATE',
      name: 'atlas',
      tld: 'vayu',
      ownerKey: VECTOR_OTHER_KEY,
      seq: 2,
      notBefore: HANDOVER_AT + 600,
      notAfter: VECTOR_NOW + TERM_SECONDS,
      records: [entry('txt', 'v=vayuweb1')],
      powProof: null,
      prevHash: HANDOVER_HASH,
      ...over,
    },
    secret,
    coSecret,
  );

const accept = { outcome: 'accept' } as const;
const rejectWith = (code: string) => ({ outcome: 'reject', code }) as const;
const deferWith = (reason: string) => ({ outcome: 'defer', reason }) as const;

/** One vector per named reserved label, built from the set the verifier enforces. */
const RESERVED_LABEL_VECTORS: Vector[] = [...RESERVED_LABELS].sort().map((label) => ({
  name: `reserved/${label}`,
  rule: `NAMES.md: ${label} is withheld in every extension and MUST be rejected by every peer`,
  record: toHex(registration({ name: label })),
  now: VECTOR_NOW,
  state: FRESH,
  expect: rejectWith('BAD_LABEL'),
}));

/**
 * Every vector. Ordered by the stage of verification it exercises, so a failing implementation
 * fails early on the coarsest thing it got wrong.
 */
export function buildVectors(): Vector[] {
  const graceStart = VECTOR_NOW + TERM_SECONDS;
  const quarantineStart = graceStart + GRACE_SECONDS;

  return [
    /* -- framing ------------------------------------------------------------ */
    {
      name: 'framing/indefinite-length-map',
      rule: 'REGISTRY.md: received bytes MUST be deterministic CBOR',
      record: 'bf616101616102ff',
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('NON_CANONICAL'),
    },
    {
      name: 'framing/non-shortest-integer',
      rule: 'RFC 8949 §4.2.1: shortest-form integer encoding',
      record: 'a161611817',
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('NON_CANONICAL'),
    },
    {
      name: 'framing/trailing-bytes',
      rule: 'REGISTRY.md: one record is one complete encoding',
      record: `${toHex(PREV_BYTES)}00`,
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('NON_CANONICAL'),
    },

    /* -- schema shape -------------------------------------------------------- */
    //
    // Six codes a verifier genuinely returns and no vector measured, because the coverage test
    // compared the artifact against a hand-typed list rather than against the codes themselves.
    // They are the cheapest possible vectors and the most likely to be got wrong by a second
    // implementation, which tends to conflate "malformed" into one verdict.
    {
      name: 'schema/not-a-map',
      rule: 'REGISTRY.md: a record is a CBOR map',
      record: '83010203',
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('NOT_A_MAP'),
    },
    {
      name: 'schema/missing-field',
      rule: 'REGISTRY.md: every field is REQUIRED unless marked otherwise',
      record: toHex(encode(stripField(registration(), 'tld'))),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('MISSING_FIELD'),
    },
    {
      name: 'schema/bad-field-type',
      rule: 'REGISTRY.md: seq is a CBOR uint',
      record: toHex(registration({ seq: 'zero' })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('BAD_FIELD_TYPE'),
    },
    {
      name: 'schema/too-many-records',
      rule: 'REGISTRY.md: the records array holds at most 32 entries',
      record: toHex(
        registration({
          records: Array.from({ length: 33 }, (_, i) => entry('txt', `v=${i}`)),
        }),
      ),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('TOO_MANY_RECORDS'),
    },
    {
      name: 'schema/missing-pow',
      rule: 'REGISTRY.md: powProof is REQUIRED for REGISTER and RENEW',
      record: toHex(registration({ powProof: null })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('MISSING_POW'),
    },
    {
      name: 'schema/too-large',
      rule: "REGISTRY.md: a record is at most its suite's limit; 4096 bytes under suite 1",
      // Built to exceed the cap by padding txt entries, so the bytes are otherwise well-formed
      // and the size is the only thing wrong with them.
      record: toHex(
        registration({
          records: Array.from({ length: 20 }, () => entry('txt', 'x'.repeat(250))),
        }),
      ),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('TOO_LARGE'),
    },

    /* -- cryptographic suites (CRYPTO-AGILITY.md) ---------------------------- */
    //
    // The agility mechanism is the one property the design says cannot be retrofitted, and
    // until these existed no vector measured it at all: a second implementation could omit the
    // `suite` field entirely and pass the whole suite.
    {
      name: 'suite/unknown',
      rule: 'CRYPTO-AGILITY.md 4.2: reject a record whose suite the verifier does not know',
      record: toHex(registration({ suite: 99 })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('UNKNOWN_SUITE'),
    },
    {
      name: 'suite/reserved-is-not-active',
      rule: 'CRYPTO-AGILITY.md 3.1: suites 2, 3 and 4 are reserved, not active',
      record: toHex(registration({ suite: 3 })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('UNKNOWN_SUITE'),
    },
    {
      name: 'suite/zero',
      rule: 'CRYPTO-AGILITY.md 3: suite identifiers are assigned by VWIP; 0 is not one',
      record: toHex(registration({ suite: 0 })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('UNKNOWN_SUITE'),
    },
    //
    // **There is deliberately no `suite/downgrade` vector, and there cannot be one yet.**
    // CRYPTO-AGILITY.md 5.1 requires a name's suite to move forward only, and its conformance
    // item 3 asks for exactly that test. A vector states a predecessor as bytes, and 4.2 makes
    // a verifier reject any record naming an inactive suite — so the suite-3 predecessor a
    // downgrade needs is not a record any conforming implementation can hold. The rule is
    // therefore unit-tested against a constructed predecessor instead, and the VWIP that
    // activates a second suite MUST add the wire vector in the same change. Saying so here is
    // the point: an absent vector that nobody wrote down reads exactly like a covered rule.

    /* -- reserved labels ----------------------------------------------------- */
    //
    // A vector per named reservation. Without these, a second implementation is not measured on
    // the rule at all — which is how this one shipped: NAMES.md withheld the labels, the module's
    // own header claimed to implement them, and every one of them was registrable.
    //
    // `wpad` and `pac` are the sharp end. A browser looking for its proxy fetches
    // `wpad.<domain>/wpad.dat` and runs the JavaScript it finds there to decide where every
    // request goes, so a stranger holding that name configures the reader's proxy.
    ...RESERVED_LABEL_VECTORS,

    /* -- schema ------------------------------------------------------------- */
    {
      name: 'schema/valid-registration',
      rule: 'REGISTRY.md REGISTER: a well-formed first registration of a free name',
      record: toHex(PREV_BYTES),
      now: VECTOR_NOW,
      state: FRESH,
      expect: accept,
    },
    {
      name: 'schema/unsupported-version',
      rule: 'REGISTRY.md: a verifier MUST reject a major version it does not implement',
      record: toHex(registration({ version: 2 })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('UNSUPPORTED_VERSION'),
    },
    {
      name: 'schema/unknown-operation',
      rule: 'REGISTRY.md: the operation set is closed',
      record: toHex(registration({ op: 'DELETE' })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('UNKNOWN_OP'),
    },
    {
      name: 'schema/uppercase-label',
      rule: 'NAMES.md: labels are lowercase [a-z0-9-]',
      record: toHex(registration({ name: 'Atlas' })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('BAD_LABEL'),
    },
    {
      name: 'schema/leading-hyphen',
      rule: 'NAMES.md: a label may not begin with a hyphen',
      record: toHex(registration({ name: '-atlas' })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('BAD_LABEL'),
    },
    {
      name: 'schema/unratified-tld',
      rule: 'NAMES.md: the TLD must be a member of the Namespace Annex',
      record: toHex(registration({ tld: 'example' })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('UNKNOWN_TLD'),
    },
    {
      // VWIP-0004 vectors. `example` above proves a well-shaped non-member is refused; these
      // prove the Annex is enforced across its range rather than only at its famous entries.
      // Sort-order endpoints specifically: an off-by-one in a generated list truncates at an end,
      // and a spot check in the middle passes against exactly that bug.
      name: 'schema/annex-first-entry',
      rule: 'VWIP-0004: the first Annex entry in sort order is ratified',
      record: toHex(registration({ tld: 'abacus' })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: accept,
    },
    {
      name: 'schema/annex-last-entry',
      rule: 'VWIP-0004: the last Annex entry in sort order is ratified',
      record: toHex(registration({ tld: 'zine' })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: accept,
    },
    {
      name: 'schema/annex-two-letter-entry',
      rule: 'VWIP-0004: two-letter extensions are ratified despite colliding with ccTLD strings',
      record: toHex(registration({ tld: 'io' })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: accept,
    },
    {
      // A badly shaped TLD is refused as UNKNOWN_TLD rather than by a separate shape code.
      // REGISTRY.md's verify() has one TLD rule — `if rec.tld not in RATIFIED_TLDS` — and
      // membership subsumes shape, because nothing malformed can be in the Annex. NAMES.md's
      // BAD_TLD_SHAPE exists for the VWIP path, where a *proposed* string must satisfy the
      // grammar before it can be considered; it is deliberately not a wire code. Pinned as a
      // vector because a second implementation that re-derives the grammar on the wire would
      // report a different code for the same record, and two verifiers disagreeing about why
      // they refused something is how a conformance suite stops being a contract.
      name: 'schema/malformed-tld-is-unknown-not-malformed',
      rule: 'REGISTRY.md: the wire has one TLD rule — membership — and it subsumes shape',
      record: toHex(registration({ tld: '2p2' })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('UNKNOWN_TLD'),
    },
    {
      name: 'schema/small-order-owner-key',
      rule: 'A small-order point certifies signatures its holder never produced',
      record: toHex(
        registration({
          ownerKey: (() => {
            const k = new Uint8Array(32);
            k[0] = 1;
            return k;
          })(),
        }),
      ),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('BAD_KEY'),
    },
    {
      name: 'schema/pow-carrying-cost-parameters',
      rule: 'REGISTRY.md: powProof is {alg, nonce, bits}; cost parameters are protocol constants',
      record: toHex(
        registration({
          powProof: (() => {
            const p = powProof();
            p.set('m', 8);
            return p;
          })(),
        }),
      ),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('BAD_POW_SHAPE'),
    },
    {
      name: 'schema/pow-carrying-salt',
      rule: 'PROOF-OF-WORK.md: the salt is derived from the record, never carried by it',
      record: toHex(
        registration({
          powProof: (() => {
            const p = powProof();
            p.set('salt', new Uint8Array(16));
            return p;
          })(),
        }),
      ),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('BAD_POW_SHAPE'),
    },
    {
      name: 'schema/alias-beside-another-entry',
      rule: 'REGISTRY.md: a name is either a pointer or a destination',
      record: toHex(registration({ records: [entry('alias', 'zenith.vayu'), entry('txt', 'x')] })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('BAD_RECORD_ENTRY'),
    },
    {
      name: 'schema/unknown-entry-type-is-retained',
      rule: 'REGISTRY.md: unknown entry types are stored and replicated unchanged',
      record: toHex(registration({ records: [entry('future', 'whatever')] })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: accept,
    },
    {
      name: 'schema/unknown-top-level-field-is-retained',
      rule: 'REGISTRY.md: a record carrying unknown fields still verifies downstream',
      record: toHex(registration({ futureField: 'kept' })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: accept,
    },

    /* -- registration ------------------------------------------------------- */
    {
      name: 'register/term-must-be-exactly-one-year',
      rule: 'REGISTRY.md REGISTER: notAfter - notBefore == 31536000',
      record: toHex(registration({ notAfter: VECTOR_NOW + TERM_SECONDS + 1 })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('BAD_TERM'),
    },
    {
      name: 'register/name-already-held',
      rule: 'REGISTRY.md REGISTER: the name must be free',
      record: toHex(PREV_BYTES),
      now: VECTOR_NOW,
      state: HELD,
      expect: rejectWith('NAME_TAKEN'),
    },
    {
      name: 'register/after-quarantine-the-name-is-free-again',
      rule: 'REGISTRY.md: free means past notAfter plus 30 days grace plus 30 days quarantine',
      record: toHex(PREV_BYTES),
      now: VECTOR_NOW,
      state: { ...HELD, fullyReleased: true },
      expect: accept,
    },
    {
      name: 'register/backdated',
      rule: 'REGISTRY.md REGISTER: notBefore at most 86400 seconds behind the clock',
      record: toHex(
        registration({
          notBefore: VECTOR_NOW - 86_401,
          notAfter: VECTOR_NOW - 86_401 + TERM_SECONDS,
        }),
      ),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('BACKDATED'),
    },
    {
      // The two-defect case that pins CHECK ORDER, which is the whole reason the record suite
      // records a code rather than only an outcome. A postdated record with a garbage signature
      // must be REJECTED, not held: `defer` is the one verdict that costs the verifier memory, so
      // it has to be earned by a valid signature and a solved proof of work. Reached before those
      // two, it was free storage — 1,024 such records filled the entire deferral queue for the
      // price of the bytes on the wire.
      //
      // No vector combined these two defects, so reordering the checks changed no published
      // expectation and a second implementation was free to disagree.
      name: 'register/postdated-junk-is-rejected-not-deferred',
      rule: 'REGISTRY.md: a deferral costs memory, so signature and proof of work are checked first',
      record: toHex(
        forge(
          registration({
            notBefore: VECTOR_NOW + 301,
            notAfter: VECTOR_NOW + 301 + TERM_SECONDS,
          }),
        ),
      ),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('BAD_SIG'),
    },
    {
      name: 'register/clock-skew-is-deferred-not-rejected',
      rule: 'REGISTRY.md: a postdated record is held, since the verifier clock may be behind',
      record: toHex(
        registration({
          notBefore: VECTOR_NOW + 301,
          notAfter: VECTOR_NOW + 301 + TERM_SECONDS,
        }),
      ),
      now: VECTOR_NOW,
      state: FRESH,
      expect: deferWith('CLOCK_SKEW'),
    },
    {
      name: 'register/seq-must-be-zero',
      rule: 'REGISTRY.md REGISTER: seq == 0 and prevHash all-zero',
      record: toHex(registration({ seq: 1 })),
      now: VECTOR_NOW,
      state: FRESH,
      expect: rejectWith('BAD_CHAIN'),
    },
    {
      name: 'register/unproven-work-is-refused',
      rule: 'PROOF-OF-WORK.md: the verifier recomputes the requirement and checks the tag',
      record: toHex(PREV_BYTES),
      now: VECTOR_NOW,
      state: { ...FRESH, powVerified: false },
      expect: rejectWith('BAD_POW'),
    },

    /* -- chain -------------------------------------------------------------- */
    {
      name: 'chain/valid-update',
      rule: 'REGISTRY.md UPDATE: a live predecessor, owner-signed, notAfter unchanged',
      record: toHex(successor({})),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: accept,
    },
    {
      name: 'chain/no-predecessor',
      rule: 'REGISTRY.md: every operation but REGISTER needs an accepted predecessor',
      record: toHex(successor({})),
      now: VECTOR_NOW + 600,
      state: FRESH,
      expect: rejectWith('NO_PREDECESSOR'),
    },
    {
      name: 'chain/sequence-gap',
      rule: 'REGISTRY.md: seq == prev.seq + 1, exactly',
      record: toHex(successor({ seq: 2 })),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: rejectWith('BAD_SEQ'),
    },
    {
      name: 'chain/replayed-record',
      rule: 'REGISTRY.md: replay fails because seq is no longer next',
      record: toHex(PREV_BYTES),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: rejectWith('NAME_TAKEN'),
    },
    {
      name: 'chain/substituted-predecessor',
      rule: 'REGISTRY.md: prevHash binds a record to the exact bytes of its predecessor',
      record: toHex(successor({ prevHash: new Uint8Array(32).fill(9) })),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: rejectWith('BAD_CHAIN'),
    },
    {
      name: 'chain/minimum-interval',
      rule: 'REGISTRY.md: notBefore >= prev.notBefore + 300',
      record: toHex(successor({ notBefore: VECTOR_NOW + 299 })),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: rejectWith('TOO_SOON'),
    },

    /* -- authority ---------------------------------------------------------- */
    {
      name: 'authority/signed-by-another-key',
      rule: 'REGISTRY.md: sig must verify against prev.ownerKey',
      record: toHex(successor({}, VECTOR_OTHER_SECRET)),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: rejectWith('BAD_SIG'),
    },
    {
      name: 'authority/silent-owner-change',
      rule: 'REGISTRY.md: only TRANSFER may change ownerKey',
      record: toHex(successor({ ownerKey: VECTOR_OTHER_KEY })),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: rejectWith('BAD_OWNER'),
    },
    {
      name: 'authority/transfer-without-countersignature',
      rule: 'REGISTRY.md TRANSFER: coSig must verify under the incoming ownerKey',
      record: toHex(
        successor({
          op: 'TRANSFER',
          ownerKey: VECTOR_OTHER_KEY,
          notAfter: VECTOR_NOW + TERM_SECONDS,
          records: [],
        }),
      ),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: rejectWith('BAD_COSIG'),
    },
    {
      name: 'authority/valid-transfer',
      rule: 'REGISTRY.md TRANSFER: outgoing owner signs, incoming owner countersigns',
      record: toHex(
        successor(
          {
            op: 'TRANSFER',
            ownerKey: VECTOR_OTHER_KEY,
            notAfter: VECTOR_NOW + TERM_SECONDS,
            records: [],
          },
          VECTOR_OWNER_SECRET,
          VECTOR_OTHER_SECRET,
        ),
      ),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: accept,
    },

    /* -- settlement (Article 33.4) ------------------------------------------ */
    //
    // A TRANSFER is accepted at once and takes effect fourteen days later. Without these
    // vectors an implementation that hands the name over on acceptance passes the whole suite,
    // which is exactly how this one shipped: `authority/valid-transfer` above measures that the
    // record is accepted and says nothing about when it takes effect.
    {
      name: 'settlement/recipient-cannot-act-before-settlement',
      rule: 'Art 33.4: a TRANSFER takes effect only after fourteen days',
      record: toHex(afterHandover({}, VECTOR_OTHER_SECRET)),
      now: HANDOVER_AT + 600,
      state: SETTLING,
      expect: rejectWith('UNSETTLED'),
    },
    {
      name: 'settlement/transferor-may-cancel',
      rule: 'Art 33.4: the transfer MAY be revoked by signed record inside the delay',
      record: toHex(
        afterHandover(
          { op: 'TRANSFER', ownerKey: VECTOR_OWNER_KEY, records: [] },
          VECTOR_OWNER_SECRET,
          VECTOR_OWNER_SECRET,
        ),
      ),
      now: HANDOVER_AT + 600,
      state: SETTLING,
      expect: accept,
    },
    {
      name: 'settlement/recipient-cannot-redirect',
      rule: 'Art 33.4: authority stays with the transferor until settlement',
      record: toHex(
        afterHandover(
          { op: 'TRANSFER', ownerKey: VECTOR_OWNER_KEY, records: [] },
          VECTOR_OTHER_SECRET,
          VECTOR_OWNER_SECRET,
        ),
      ),
      now: HANDOVER_AT + 600,
      state: SETTLING,
      expect: rejectWith('BAD_SIG'),
    },
    {
      name: 'settlement/one-second-early',
      rule: 'Art 33.4: the delay is 1209600 seconds from the TRANSFER notBefore',
      record: toHex(afterHandover({ notBefore: SETTLED_AT - 1 }, VECTOR_OTHER_SECRET)),
      now: SETTLED_AT - 1,
      state: SETTLING,
      expect: rejectWith('UNSETTLED'),
    },
    {
      name: 'settlement/at-the-instant',
      rule: 'Art 33.4: authority moves to the recipient at the settlement instant',
      record: toHex(afterHandover({ notBefore: SETTLED_AT }, VECTOR_OTHER_SECRET)),
      now: SETTLED_AT,
      state: SETTLING,
      expect: accept,
    },
    {
      name: 'settlement/transferor-loses-control-at-the-instant',
      rule: 'Art 33.4: the delay ends for both parties at the same instant',
      record: toHex(afterHandover({ notBefore: SETTLED_AT }, VECTOR_OWNER_SECRET)),
      now: SETTLED_AT,
      state: SETTLING,
      expect: rejectWith('BAD_SIG'),
    },
    {
      name: 'settlement/term-too-short-to-settle',
      rule: 'Art 33.4: a transfer that cannot settle inside its term is refused',
      record: toHex(
        successor(
          {
            op: 'TRANSFER',
            ownerKey: VECTOR_OTHER_KEY,
            notBefore: VECTOR_NOW + TERM_SECONDS - 10 * 86_400,
            notAfter: VECTOR_NOW + TERM_SECONDS,
            records: [],
          },
          VECTOR_OWNER_SECRET,
          VECTOR_OTHER_SECRET,
        ),
      ),
      now: VECTOR_NOW + TERM_SECONDS - 10 * 86_400,
      state: HELD,
      expect: rejectWith('UNSETTLED'),
    },

    {
      name: 'authority/revoked-name-accepts-nothing',
      rule: 'REGISTRY.md REVOKE: no later record for the name is ever accepted',
      record: toHex(successor({})),
      now: VECTOR_NOW + 600,
      state: { ...HELD, revoked: true },
      expect: rejectWith('REVOKED'),
    },

    /* -- lifecycle ---------------------------------------------------------- */
    {
      name: 'lifecycle/renew-inside-grace',
      rule: 'REGISTRY.md RENEW: prev live or within its 30-day grace period',
      record: toHex(
        successor({
          op: 'RENEW',
          notBefore: graceStart + 1,
          notAfter: graceStart + 1 + TERM_SECONDS,
          powProof: powProof(),
        }),
      ),
      now: graceStart + 1,
      state: HELD,
      expect: accept,
    },
    {
      name: 'lifecycle/renew-after-grace-is-refused',
      rule: 'Quarantine exists so that nobody may take the name during it, including the holder',
      record: toHex(
        successor({
          op: 'RENEW',
          notBefore: quarantineStart + 1,
          notAfter: quarantineStart + 1 + TERM_SECONDS,
          powProof: powProof(),
        }),
      ),
      now: quarantineStart + 1,
      state: HELD,
      expect: rejectWith('EXPIRED'),
    },
    {
      name: 'lifecycle/renewal-before-the-window-opens',
      rule: 'REGISTRY.md RENEW: the window opens 60 days before expiry',
      record: toHex(
        successor({
          op: 'RENEW',
          notBefore: VECTOR_NOW + TERM_SECONDS - RENEWAL_WINDOW_SECONDS - 1,
          notAfter: VECTOR_NOW + 2 * TERM_SECONDS,
          powProof: powProof(),
        }),
      ),
      now: VECTOR_NOW + TERM_SECONDS - RENEWAL_WINDOW_SECONDS - 1,
      state: HELD,
      expect: rejectWith('TOO_SOON'),
    },
    /* -- the term a renewal must PRODUCE ------------------------------------ */
    //
    // **The suite checked what an implementation accepts and never what it computes.** Every
    // lifecycle vector above hands the verifier a finished record carrying a `notAfter` and asks
    // for a verdict. None says which `notAfter` is the right one, so a second implementation could
    // derive a renewal's expiry by any rule at all -- always from the renewal instant, always from
    // the old expiry -- and pass the whole file. Two peers would then hold different expiries for
    // one name, disagree about when it lapses, and therefore about whether it resolves and whether
    // a stranger may take it: a permanent fork neither side ever rejected anything to reach.
    //
    // Found by measuring a running binary across the boundary, not by re-reading the suite. Each
    // case is emitted three times -- the specified value accepted, one second either side refused
    // -- because a rule that only rejects downward is one two implementations drift apart under.
    ...((): Vector[] => {
      const expiry = VECTOR_NOW + TERM_SECONDS;
      // REGISTRY.md: `notAfter == max(prev.notAfter, notBefore) + 31536000`. Spelled out rather
      // than imported from the checker, because a `pow` vector that computed its expectation by
      // calling the function under test survived four of five mutations.
      const required = (notBefore: number): number => Math.max(expiry, notBefore) + 31_536_000;
      const cases: Array<[string, number, string]> = [
        [
          'sixty-days-early',
          -RENEWAL_WINDOW_SECONDS,
          'the window opens here, and the base is still the old expiry',
        ],
        ['one-day-early', -86_400, 'the base does not move toward the request'],
        ['one-second-early', -1, 'still before the expiry, so still based on it'],
        ['at-the-expiry-instant', 0, 'notBefore == prev.notAfter, where both readings coincide'],
        ['one-second-into-grace', 1, 'past the expiry, the term restarts from the renewal instant'],
        ['late-in-grace', 2_505_600, 'twenty-nine days in, and it still runs from that instant'],
      ];
      return cases.flatMap(([label, offset, why]): Vector[] => {
        const notBefore = expiry + offset;
        const at = required(notBefore);
        const one = (suffix: string, notAfter: number, expect: Vector['expect']): Vector => ({
          name: `lifecycle/term-${label}${suffix}`,
          rule: `REGISTRY.md RENEW: notAfter == max(prev.notAfter, notBefore) + 31536000 — ${why}`,
          record: toHex(successor({ op: 'RENEW', notBefore, notAfter, powProof: powProof() })),
          now: notBefore,
          state: HELD,
          expect,
        });
        return [
          one('', at, accept),
          one('-a-second-short', at - 1, rejectWith('BAD_TERM')),
          one('-a-second-long', at + 1, rejectWith('BAD_TERM')),
        ];
      });
    })(),
    {
      name: 'lifecycle/renewal-cannot-buy-an-unbounded-term',
      rule: 'clock_check applies to every operation, not to REGISTER alone',
      record: toHex(
        successor({
          op: 'RENEW',
          notBefore: VECTOR_NOW + 100 * TERM_SECONDS,
          notAfter: VECTOR_NOW + 101 * TERM_SECONDS,
          powProof: powProof(),
        }),
      ),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: deferWith('CLOCK_SKEW'),
    },
    {
      name: 'lifecycle/update-must-not-move-the-expiry',
      rule: 'REGISTRY.md UPDATE: notAfter == prev.notAfter',
      record: toHex(successor({ notAfter: VECTOR_NOW + TERM_SECONDS + 1 })),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: rejectWith('BAD_TERM'),
    },
    {
      name: 'lifecycle/release-expires-immediately',
      rule: 'REGISTRY.md RELINQUISH: records empty and notAfter == notBefore',
      record: toHex(successor({ op: 'RELINQUISH', records: [], notAfter: VECTOR_NOW + 600 })),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: accept,
    },
    {
      name: 'lifecycle/only-renew-may-carry-a-proof',
      rule: 'REGISTRY.md: rec.op != RENEW and rec.powProof != null -> UNEXPECTED_POW',
      record: toHex(successor({ powProof: powProof() })),
      now: VECTOR_NOW + 600,
      state: HELD,
      expect: rejectWith('UNEXPECTED_POW'),
    },
  ];
}

/* -------------------------------------------------------------------------- */
/* Convergence, resolution and replication                                     */
/* -------------------------------------------------------------------------- */
//
// The record suite above pins what a verifier accepts. These three pin what implementations must
// AGREE about after that — which is where a fork lives.
//
// The distinction is not academic here. Every consensus-critical defect this project has found
// was invisible to record verification and visible only to the question "what would a second
// implementation do": the convergence rule decided conflicts by local arrival order, so two peers
// kept different owners forever; the rule was then found to be called by nothing; and the
// resolver preferred the frozen snapshot over the living pointer, so a conforming publisher and a
// conforming resolver together froze every site. Record vectors passed throughout.

/** Two candidate records for one name at one seq, and which one every implementation must pick. */
export interface ConvergenceVector {
  readonly name: string;
  readonly rule: string;
  readonly a: string;
  readonly b: string;
  /** Which record wins. Stated as a label rather than a hash so a failure names the loser. */
  readonly expect: { readonly winner: 'a' | 'b'; readonly rule: string };
}

/** A host and the registry state behind it, and the outcome every implementation must return. */
export interface ResolutionVector {
  readonly name: string;
  readonly rule: string;
  readonly host: string;
  /** The record the local index holds for that name, or null. */
  readonly record: string | null;
  readonly hasVerifiedHead: boolean;
  readonly now: number;
  readonly expect:
    | {
        readonly outcome: 'ok';
        readonly source: string;
        /**
         * The selected entry's value in hex, where naming the type is not enough.
         *
         * The suite could only say *which type* won, so a record carrying two `cid` entries had
         * no expressible answer — and that is precisely the case in which two conforming
         * implementations fetch different content from the same signed record. A vector set that
         * cannot state the disagreement cannot catch it.
         */
        readonly value?: string;
      }
    | { readonly outcome: 'error'; readonly code: string };
}

/** One replication message, and whether it decodes. */
export interface ReplicationVector {
  readonly name: string;
  readonly rule: string;
  readonly message: string;
  readonly expect:
    | { readonly decode: 'ok'; readonly type: string }
    | { readonly decode: 'reject'; readonly code: string };
}

/**
 * A pair of record encodings, and whether they constitute equivocation.
 *
 * The two records and nothing else — that is the whole claim of REPLICATION.md 6.2, so the vector
 * carries no state, no clock and no prior view. A vector that needed any of those would be
 * describing something other than what the specification says an EQUIVOCATION report is.
 */
export interface EquivocationVector {
  readonly name: string;
  readonly rule: string;
  readonly a: string;
  readonly b: string;
  readonly expect: { readonly equivocation: boolean };
}

/**
 * One proof-of-work derivation, stated as inputs and the single answer every implementation
 * must produce.
 *
 * **No Argon2id.** That is the whole reason this suite can exist, and it is not a compromise:
 * the evaluation is a standard primitive with its own published vectors, while the parts two
 * implementations actually diverge on are the ones around it — how difficulty is derived from a
 * label and a rate, which bytes go into the salt, and how leading zero bits are counted. Get any
 * of those wrong and your records are refused by everyone, having cost you 64 MiB per attempt to
 * produce. `conformance/README.md` has said since the beginning that verifying the record
 * vectors "does not demonstrate a correct proof-of-work implementation"; this is the suite that
 * demonstrates the checkable half of it.
 */
export type PowVector = {
  readonly name: string;
  readonly rule: string;
} & (
  | { readonly check: 'baseBits'; readonly labelLength: number; readonly expect: number }
  | {
      readonly check: 'requiredBits';
      readonly labelLength: number;
      readonly windowCount: number;
      readonly expect: number;
    }
  | {
      readonly check: 'rateWindow';
      readonly notBefore: number;
      readonly expect: { readonly start: number; readonly end: number };
    }
  | { readonly check: 'salt'; readonly record: string; readonly expect: string }
  | {
      readonly check: 'tagSatisfies';
      readonly tag: string;
      readonly bits: number;
      readonly expect: boolean;
    }
);

/** A registration by the other key, so a race is between strangers rather than equivocation. */
const byOther = (over: Record<string, CborValue> = {}): Uint8Array =>
  build(
    {
      version: 1,
      suite: 1,
      op: 'REGISTER',
      name: 'atlas',
      tld: 'vayu',
      ownerKey: VECTOR_OTHER_KEY,
      seq: 0,
      notBefore: VECTOR_NOW,
      notAfter: VECTOR_NOW + TERM_SECONDS,
      records: [entry('txt', 'v=vayuweb1;other')],
      powProof: powProof(),
      prevHash: new Uint8Array(32),
      ...over,
    },
    VECTOR_OTHER_SECRET,
  );

const withEntries = (entries: CborValue[]): Uint8Array => registration({ records: entries });

export function buildConvergenceVectors(): ConvergenceVector[] {
  const mine = registration();
  const theirs = byOther();
  const lower =
    compareBytes(recordHashFromBytes(mine), recordHashFromBytes(theirs)) < 0 ? 'a' : 'b';

  return [
    {
      name: 'converge/smaller-digest-wins',
      rule: 'REGISTRY.md: otherwise, the smaller record_hash as a big-endian unsigned integer wins',
      a: toHex(mine),
      b: toHex(theirs),
      expect: { winner: lower, rule: 'SMALLER_HASH' },
    },
    {
      // The same pair with the arguments swapped. An implementation that decided by position,
      // by arrival, or by its own log index gives a different answer here and the same answer
      // above, which is precisely the fork that shipped.
      name: 'converge/order-does-not-decide',
      rule: 'REGISTRY.md: a peer MUST NOT use its own log position or arrival order',
      a: toHex(theirs),
      b: toHex(mine),
      expect: { winner: lower === 'a' ? 'b' : 'a', rule: 'SMALLER_HASH' },
    },
  ];
}

export function buildResolutionVectors(): ResolutionVector[] {
  // The BINARY CID, which is what a `cid` entry carries: version 1, raw codec, sha2-256, then
  // the digest. The text form belongs in a URL bar, not in a record — and REGISTRY.md's entry
  // rule says so by typing the value as a byte string, which a first draft of these vectors got
  // wrong by passing the base32 text and being refused as BAD_RECORD_ENTRY.
  const CID = Uint8Array.from([0x01, 0x55, 0x12, 0x20, ...new Uint8Array(32).fill(0xab)]);
  return [
    {
      // Two entries of one type, which the selection rule ordered across types and never within
      // one. First in record order wins; deterministic CBOR fixes that order on the wire.
      name: 'resolve/first-of-two-same-type',
      rule: 'RESOLUTION.md: with more than one entry of the selected type, take the first in record order',
      host: 'atlas.vayu',
      record: toHex(withEntries([entry('cid', CID), entry('cid', new Uint8Array(36).fill(0xee))])),
      hasVerifiedHead: true,
      now: VECTOR_NOW + 60,
      expect: { outcome: 'ok', source: 'cid', value: toHex(CID) },
    },
    {
      // The same record with the entries reversed must select the other one, or the vector above
      // passes against an implementation that happened to prefer those bytes.
      name: 'resolve/first-of-two-same-type-reversed',
      rule: 'RESOLUTION.md: record order is what decides, not the value',
      host: 'atlas.vayu',
      record: toHex(withEntries([entry('cid', new Uint8Array(36).fill(0xee)), entry('cid', CID)])),
      hasVerifiedHead: true,
      now: VECTOR_NOW + 60,
      expect: { outcome: 'ok', source: 'cid', value: toHex(new Uint8Array(36).fill(0xee)) },
    },
    {
      name: 'resolve/pointer-beats-snapshot',
      rule: 'RESOLUTION.md: with several content entries present, select ipns before cid',
      host: 'atlas.vayu',
      record: toHex(withEntries([entry('cid', CID), entry('ipns', 'k51qzi5uqu5d')])),
      hasVerifiedHead: true,
      now: VECTOR_NOW + 60,
      expect: { outcome: 'ok', source: 'ipns' },
    },
    {
      name: 'resolve/snapshot-without-pointer',
      rule: 'RESOLUTION.md: cid is the content source when no pointer is present',
      host: 'atlas.vayu',
      record: toHex(withEntries([entry('txt', 'v=vayuweb1'), entry('cid', CID)])),
      hasVerifiedHead: true,
      now: VECTOR_NOW + 60,
      expect: { outcome: 'ok', source: 'cid' },
    },
    {
      name: 'resolve/txt-is-never-a-source',
      rule: 'RESOLUTION.md: a txt entry is never a content source',
      host: 'atlas.vayu',
      record: toHex(withEntries([entry('txt', 'v=vayuweb1')])),
      hasVerifiedHead: true,
      now: VECTOR_NOW + 60,
      expect: { outcome: 'error', code: 'NO_USABLE_RECORD' },
    },
    {
      name: 'resolve/unratified-tld',
      rule: 'RESOLUTION.md step 2: only a member of the Namespace Annex is resolved',
      host: 'atlas.example',
      record: null,
      hasVerifiedHead: true,
      now: VECTOR_NOW,
      expect: { outcome: 'error', code: 'TLD_UNKNOWN' },
    },
    {
      name: 'resolve/subdomains-are-refused-not-guessed',
      rule: 'RESOLUTION.md step 1: more than two dot-separated components is refused',
      host: 'a.atlas.vayu',
      record: null,
      hasVerifiedHead: true,
      now: VECTOR_NOW,
      expect: { outcome: 'error', code: 'LABEL_INVALID' },
    },
    {
      // Not 1404. A resolver that has never synchronised does not know the name is absent, and
      // answering "no one has registered this" would be inventing a fact from its own ignorance.
      name: 'resolve/unsynchronised-is-not-absent',
      rule: 'RESOLUTION.md step 7: no verified head gives 1502, not 1404',
      host: 'atlas.vayu',
      record: null,
      hasVerifiedHead: false,
      now: VECTOR_NOW,
      expect: { outcome: 'error', code: 'REGISTRY_UNAVAILABLE' },
    },
    {
      name: 'resolve/absent-name',
      rule: 'RESOLUTION.md step 7: a synchronised resolver reports an unregistered name as 1404',
      host: 'atlas.vayu',
      record: null,
      hasVerifiedHead: true,
      now: VECTOR_NOW,
      expect: { outcome: 'error', code: 'NAME_NOT_FOUND' },
    },
  ];
}

export function buildReplicationVectors(): ReplicationVector[] {
  const hello = encodeMessage({
    t: 'HELLO',
    v: PROTOCOL_VERSION,
    len: 7,
    root: new Uint8Array(32).fill(9),
  });
  const want = encodeMessage({ t: 'WANT', from: 0, count: LIMITS.wantCount });
  const oversizedBatch = encode(
    new Map<string | Uint8Array, CborValue>([
      ['t', 'RECORDS'],
      ['from', 0],
      ['recs', Array.from({ length: LIMITS.recordsPerBatch + 1 }, () => Uint8Array.of(1))],
    ]),
  );
  const unknown = encode(new Map<string | Uint8Array, CborValue>([['t', 'GOSSIP']]));

  // The three that had no positive vector. A suite that only shows a message type being REFUSED
  // lets a second implementation pass having never once decoded it — and `RECORDS` is how records
  // move, `CHECKPOINT` is the whole of what a light client is given, and `EQUIVOCATION` is the
  // report 6.3 makes a MUST. Two peers agreeing about the two easy messages is not agreement.
  const records = encodeMessage({ t: 'RECORDS', from: 3, recs: [registration()] });
  const checkpoint = encodeMessage({
    t: 'CHECKPOINT',
    len: 7,
    treeRoot: new Uint8Array(32).fill(0x11),
    indexRoot: new Uint8Array(32).fill(0x22),
    liveNames: 4,
  });
  const equivocation = encodeMessage({
    t: 'EQUIVOCATION',
    a: registration(),
    b: registration({ records: [entry('txt', 'v=vayuweb1;two')] }),
  });

  return [
    {
      name: 'replicate/hello',
      rule: 'REPLICATION.md 3.2: HELLO carries the protocol version, log length and tree root',
      message: toHex(hello),
      expect: { decode: 'ok', type: 'HELLO' },
    },
    {
      name: 'replicate/want-at-the-limit',
      rule: 'REPLICATION.md 5: WANT.count is bounded at 256',
      message: toHex(want),
      expect: { decode: 'ok', type: 'WANT' },
    },
    {
      // Carrying a REAL record, not filler. A `RECORDS` whose payload is arbitrary bytes decodes
      // perfectly, so a vector built that way pins the envelope and says nothing about what a
      // runner does next — and what it does next is the only part that matters.
      name: 'replicate/records-one',
      rule: 'REPLICATION.md 4.3: RECORDS carries the encodings for a requested range',
      message: toHex(records),
      expect: { decode: 'ok', type: 'RECORDS' },
    },
    {
      name: 'replicate/checkpoint',
      rule: 'REPLICATION.md 7: a CHECKPOINT states a length, both roots and the live-name count',
      message: toHex(checkpoint),
      expect: { decode: 'ok', type: 'CHECKPOINT' },
    },
    {
      // The envelope, which the equivocation suite does not pin: that suite judges a PAIR and
      // never asks whether the message carrying it decodes.
      name: 'replicate/equivocation-report',
      rule: 'REPLICATION.md 6.3: a peer SHOULD forward the evidence, which means encoding it',
      message: toHex(equivocation),
      expect: { decode: 'ok', type: 'EQUIVOCATION' },
    },
    {
      name: 'replicate/batch-over-the-limit',
      rule: 'REPLICATION.md 5: a batch larger than 256 is refused at decode',
      message: toHex(oversizedBatch),
      expect: { decode: 'reject', code: 'LIMIT_EXCEEDED' },
    },
    {
      // Ignored rather than fatal: refusing to speak to a peer that knows a message you do not is
      // how a protocol becomes unextendable.
      name: 'replicate/unknown-type',
      rule: 'REPLICATION.md 3.2: an unknown message type is named as unknown',
      message: toHex(unknown),
      expect: { decode: 'reject', code: 'UNKNOWN_TYPE' },
    },
  ];
}

/**
 * Equivocation evidence, verifiable from the two encodings alone.
 *
 * The suite exists because the honest cases and the forgeries are indistinguishable to a record
 * verifier: neither half of a forged report is a record any peer would accept, and neither half of
 * a genuine one need be either. What separates them is a question no record vector asks — is this
 * pair attributable to the key it accuses? Two implementations answering that differently do not
 * merely disagree about a rejection code; one of them republishes, at every peer it talks to, that
 * a name of the attacker's choosing is compromised.
 */
export function buildEquivocationVectors(): EquivocationVector[] {
  /** A record naming VECTOR_OWNER_KEY as owner that VECTOR_OWNER_SECRET never signed. */
  const forged = (over: Record<string, CborValue> = {}): Uint8Array =>
    build(
      {
        version: 1,
        suite: 1,
        op: 'REGISTER',
        name: 'atlas',
        tld: 'vayu',
        ownerKey: VECTOR_OWNER_KEY,
        seq: 0,
        notBefore: VECTOR_NOW,
        notAfter: VECTOR_NOW + TERM_SECONDS,
        records: [entry('txt', 'v=vayuweb1;forged')],
        powProof: powProof(),
        prevHash: new Uint8Array(32),
        ...over,
      },
      VECTOR_OTHER_SECRET,
    );

  const one = registration();
  const two = registration({ records: [entry('txt', 'v=vayuweb1;two')] });
  const laterSeq = successor({ records: [entry('txt', 'v=vayuweb1;two')] });
  const otherName = registration({ name: 'boreal' });
  const otherTld = registration({ tld: 'web' });

  /** Two TRANSFERs of one name at one seq, both countersigned by the recipient they name. */
  const handover = (at: number): Uint8Array =>
    successor(
      {
        op: 'TRANSFER',
        ownerKey: VECTOR_OTHER_KEY,
        notBefore: at,
        notAfter: VECTOR_NOW + TERM_SECONDS,
        records: [],
      },
      VECTOR_OWNER_SECRET,
      VECTOR_OTHER_SECRET,
    );

  return [
    {
      name: 'equivocation/two-futures-for-one-name',
      rule: 'REPLICATION.md 6.1: one owner key signing two different records at the same seq for one name.tld',
      a: toHex(one),
      b: toHex(two),
      expect: { equivocation: true },
    },
    {
      name: 'equivocation/two-owners-racing-is-not',
      rule: 'REPLICATION.md 6.1: an honest partition conflict is two DIFFERENT owners racing for a free name',
      a: toHex(one),
      b: toHex(byOther()),
      expect: { equivocation: false },
    },
    {
      name: 'equivocation/duplicate-is-not',
      rule: 'REPLICATION.md 6.3: a report whose two records do not in fact equivocate MUST be discarded',
      a: toHex(one),
      b: toHex(one),
      expect: { equivocation: false },
    },
    {
      name: 'equivocation/different-seq-is-a-chain',
      rule: 'REPLICATION.md 6.1: records at different seq are a chain, not two futures',
      a: toHex(one),
      b: toHex(laterSeq),
      expect: { equivocation: false },
    },
    {
      name: 'equivocation/different-name-is-not',
      rule: 'REPLICATION.md 6.1: equivocation is about one name.tld; one owner holding two names is ordinary',
      a: toHex(one),
      b: toHex(otherName),
      expect: { equivocation: false },
    },
    {
      name: 'equivocation/different-extension-is-not',
      rule: 'REPLICATION.md 6.1: the same label in two extensions is two names',
      a: toHex(one),
      b: toHex(otherTld),
      expect: { equivocation: false },
    },
    {
      // The forgery, and the reason 6.2 lists signatures first. An owner key is public — it is in
      // every record its holder ever published — so a pair that is checked for everything except
      // who signed it can be minted by anyone, against anyone.
      name: 'equivocation/neither-half-signed-by-the-accused',
      rule: 'REPLICATION.md 6.2: a recipient checks BOTH SIGNATURES, both seq values, both names and that the owner keys are equal',
      a: toHex(forged()),
      b: toHex(forged({ records: [entry('txt', 'v=vayuweb1;forged2')] })),
      expect: { equivocation: false },
    },
    {
      // The halfway case an implementation checking "a signature" rather than "both" would pass:
      // one genuine published record of the victim's, paired with one the attacker minted.
      name: 'equivocation/one-half-signed-by-the-accused',
      rule: 'REPLICATION.md 6.2: BOTH signatures, so a genuine record paired with a minted one is not evidence',
      a: toHex(one),
      b: toHex(forged()),
      expect: { equivocation: false },
    },
    {
      // The other side of the line. Neither of these would be ACCEPTED by any verifier — the
      // successor carries no proof of work and chains onto a record the recipient may not hold —
      // and both are genuinely signed by the key they name. An equivocator who could escape the
      // record by breaking their own proof of work would have a one-line evasion.
      name: 'equivocation/unacceptable-records-still-equivocate',
      rule: 'REPLICATION.md 6.2: the evidence is the two encodings; acceptance is a separate question',
      a: toHex(successor({ records: [entry('txt', 'v=vayuweb1;a')] })),
      b: toHex(successor({ records: [entry('txt', 'v=vayuweb1;b')] })),
      expect: { equivocation: true },
    },
    {
      // TRANSFER is the one operation whose `sig` is not the named owner's: it is the
      // transferor's, whose key is nowhere in these bytes. `coSig` is, and verifies under
      // `ownerKey`. An implementation reading `sig` for every operation refuses every report
      // involving a transfer — silently, and precisely in the window Article 33.4 leaves a name
      // in flux.
      name: 'equivocation/transfer-attributed-by-cosig',
      rule: 'REGISTRY.md: a TRANSFER is signed by the transferor and countersigned by the incoming owner under coSig',
      a: toHex(handover(VECTOR_NOW + 600)),
      b: toHex(handover(VECTOR_NOW + 1200)),
      expect: { equivocation: true },
    },
    {
      name: 'equivocation/undecodable-halves',
      rule: 'REPLICATION.md 6.2: evidence that does not decode as two records is not evidence',
      a: toHex(Uint8Array.of(0x01)),
      b: toHex(Uint8Array.of(0x02)),
      expect: { equivocation: false },
    },
  ];
}

/**
 * Proof-of-work derivation, without a single Argon2id evaluation.
 *
 * The suite exists because the expensive part is the part two implementations are least likely
 * to get wrong. Argon2id is a standard with its own vectors; what is local to this protocol is
 * the arithmetic around it, and every piece of that arithmetic is consensus-critical. A rate
 * term off by one bit means one peer rejects a record another accepted, permanently, on a record
 * that is otherwise entirely valid — and the registrant paid 64 MiB per attempt to produce it.
 *
 * ## Every expectation here is a literal, and that is not a style choice
 *
 * The first draft of this suite wrote `expect: baseBits(labelLength)` — computing the answer by
 * calling the function under test. It passed, and it was worthless: four of five deliberate
 * mutations to `pow.ts` survived it, because breaking the implementation moved the expectation
 * with it. A vector whose expected value is derived from the implementation is a snapshot of
 * whatever that implementation currently does, which is the opposite of a specification.
 *
 * So the figures below are transcribed from PROOF-OF-WORK.md section 4 and can be checked
 * against it by reading. The one exception is the salt, which is a SHA-256 digest that no human
 * derives by hand; it is pinned by the committed artifact instead, and the runner reads the
 * committed file rather than regenerating — so a change to the preimage rule appears as a diff
 * in `conformance/vectors.json` and fails the comparison.
 */
export function buildPowVectors(): PowVector[] {
  const baseRule =
    'PROOF-OF-WORK.md 4: base difficulty by label length — 10 bits at 1-2 characters, 9 at 3, ' +
    '8 at 4, 7 at 5-6, 6 at 7-9, 5 at 10-15, 4 at 16 and above';
  const rateRule =
    'PROOF-OF-WORK.md 4: rate = 0 below 512, else min(8, floor(log2(n / 512))); total = ' +
    'min(20, base + rate)';

  /** `[labelLength, bits]`, read off the table in PROOF-OF-WORK.md 4 — every boundary and its neighbours. */
  const BASE: readonly (readonly [number, number])[] = [
    [1, 10],
    [2, 10],
    [3, 9],
    [4, 8],
    [5, 7],
    [6, 7],
    [7, 6],
    [9, 6],
    [10, 5],
    [15, 5],
    [16, 4],
    [63, 4],
  ];

  /**
   * `[windowCount, totalBitsForA16CharacterLabel]`. Base is 4 at sixteen characters, so the
   * figure past the first is `4 + rate` and the rate term is readable straight off it.
   *
   * The exact doublings are the interesting ones, and the reason is a hazard the specification's
   * pseudocode does not mention: it writes the rate as `floor(log2(n / 512))`, and `log2` is an
   * implementation-approximated function in most languages — ECMAScript, C, Python and Go all
   * say so in terms. A result one ulp below an integer at an exact doubling floors to one less,
   * which is a one-bit difficulty DISAGREEMENT between two peers that both believe they conform.
   * Stated as vectors, an implementation whose `log2` does that fails here rather than in the
   * field, on somebody's valid record.
   */
  const RATE: readonly (readonly [number, number])[] = [
    [0, 4],
    [1, 4],
    [511, 4],
    [512, 4],
    [513, 4],
    [1023, 4],
    [1024, 5],
    [2048, 6],
    [4096, 7],
    [8192, 8],
    [16_384, 9],
    [32_768, 10],
    [65_536, 11],
    [131_072, 12],
    // Past the rate clamp: the eighth doubling is the last that buys a bit, so these are equal.
    [262_144, 12],
    [51_200_000, 12],
  ];

  /**
   * `[label, notBefore, start, end]` for the trailing window.
   *
   * The quantisation exists, in the specification's own words, "so that two peers with slightly
   * different clocks agree on `n`". One second either side of an epoch boundary is where an
   * implementation rounding the wrong way stops agreeing, and the window is half-open, so the
   * instant at the boundary belongs to the NEW epoch and its window ends there.
   */
  const WINDOWS: readonly (readonly [string, number, number, number])[] = [
    ['epoch-boundary', VECTOR_NOW, 1_779_926_400, 1_782_518_400],
    ['one-second-before', VECTOR_NOW - 1, 1_779_922_800, 1_782_514_800],
    ['one-second-after', VECTOR_NOW + 1, 1_779_926_400, 1_782_518_400],
    ['mid-epoch', VECTOR_NOW + EPOCH_SECONDS / 2, 1_779_926_400, 1_782_518_400],
  ];

  /** A record whose salt preimage exercises both strip rules: `sig` out, `powProof.nonce` out. */
  const saltSubject = registration();

  const vectors: PowVector[] = [];

  for (const [labelLength, expect] of BASE) {
    vectors.push({
      name: `pow/base-bits-length-${labelLength}`,
      rule: baseRule,
      check: 'baseBits',
      labelLength,
      expect,
    });
  }

  for (const [windowCount, expect] of RATE) {
    // A sixteen-character label sits on the flat part of the base table, so the vector isolates
    // the rate term instead of measuring the two together.
    vectors.push({
      name: `pow/required-bits-rate-${windowCount}`,
      rule: rateRule,
      check: 'requiredBits',
      labelLength: 16,
      windowCount,
      expect,
    });
  }

  // The hardest registration the schedule can ask for: the shortest label under the busiest
  // extension. 10 + 8 is 18, so the `min(20, ...)` ceiling never binds — the reachable maximum
  // is 18 bits, roughly 262,000 evaluations, and a reader sizing worst-case cost from the 20 in
  // the formula would overstate it fourfold. Pinned as 18 rather than 20 for exactly that
  // reason: the vector states what the schedule does, not what its clamp allows for.
  vectors.push({
    name: 'pow/required-bits-hardest-reachable',
    rule: `${rateRule} — and 10 + 8 = 18, so the ${MAX_DIFFICULTY_BITS}-bit ceiling is a headroom allowance rather than a limit the schedule reaches`,
    check: 'requiredBits',
    labelLength: 2,
    windowCount: RATE_FLOOR * 256,
    expect: 18,
  });

  for (const [label, notBefore, start, end] of WINDOWS) {
    vectors.push({
      name: `pow/rate-window-${label}`,
      rule: `PROOF-OF-WORK.md 4: the window is the ${RATE_WINDOW_SECONDS}s before the start of notBefore's ${EPOCH_SECONDS}s epoch, half-open`,
      check: 'rateWindow',
      notBefore,
      expect: { start, end },
    });
  }

  vectors.push({
    // The salt is what binds a proof to one record. REGISTRY.md refuses to let a record carry
    // one precisely because a carried salt is a free parameter, and a single ground
    // `(salt, nonce)` pair would then satisfy every record an attacker cared to mint. An
    // implementation deriving it from different bytes produces proofs nobody accepts.
    //
    // The one computed expectation in this suite, because it is a digest. The committed artifact
    // is what pins it: change the preimage rule and the diff shows up in `vectors.json`.
    name: 'pow/salt-derivation',
    rule: 'REGISTRY.md: salt = SHA-256("vayuweb-pow-v1" || record without sig and without powProof.nonce)[0..16]',
    check: 'salt',
    record: toHex(saltSubject),
    expect: toHex(powSalt(decode(saltSubject) as CborMap)),
  });

  // The leading-zero-bit test, most significant bit first. The divergence to catch is an
  // implementation that counts whole zero BYTES rather than bits: it agrees on a tag beginning
  // `00 80` (eight either way) and disagrees on one beginning `0f`, which has four leading zero
  // bits and no leading zero bytes at all. Both vectors are here, because a suite carrying only
  // the first would pass against the wrong implementation.
  for (const [label, bytes, bits, expect] of [
    ['all-zero-tag-meets-any', new Uint8Array(POW_TAG_LENGTH), MAX_DIFFICULTY_BITS, true],
    ['exactly-eight-bits', withLeadingByte(0x00, 0x80), 8, true],
    ['eight-bits-is-not-nine', withLeadingByte(0x00, 0x80), 9, false],
    ['four-bits-within-a-byte', withLeadingByte(0x0f, 0xff), 4, true],
    ['four-bits-is-not-five', withLeadingByte(0x0f, 0xff), 5, false],
    ['zero-bits-is-satisfied-by-anything', withLeadingByte(0xff, 0xff), 0, true],
  ] as const) {
    vectors.push({
      name: `pow/tag-${label}`,
      rule: 'PROOF-OF-WORK.md: leading zero bits over the whole tag, most-significant bit first, counted without early exit',
      check: 'tagSatisfies',
      tag: toHex(bytes),
      bits,
      expect,
    });
  }

  return vectors;
}

/** A tag of the protocol's length whose first two bytes are given and whose rest is 0xff. */
function withLeadingByte(first: number, second: number): Uint8Array {
  const tag = new Uint8Array(POW_TAG_LENGTH).fill(0xff);
  tag[0] = first;
  tag[1] = second;
  return tag;
}

/* -------------------------------------------------------------------------- */
/* Block exchange (VWIP-0005)                                                  */
/* -------------------------------------------------------------------------- */

/**
 * A block-exchange message, and what a conforming decoder must do with it.
 *
 * Same shape as {@link ReplicationVector} deliberately: the two protocols share a transport
 * contract and a message discipline, so a runner that can execute one suite can execute both.
 */
export interface BlockExchangeVector {
  readonly name: string;
  readonly rule: string;
  /** The message in hex, when publishing the bytes is publishing the vector. */
  readonly message?: string;
  /**
   * A recipe, when it is not.
   *
   * One vector's content is a block one octet over the megabyte limit — 2.1 MB of hex zeros in
   * the artifact, of which every byte after the first carries no information at all. The
   * information in that vector is its LENGTH, and a runner that builds the buffer from a stated
   * length tests exactly what a runner reading two million zeros would, while leaving the
   * artifact something a reviewer can read. A vector nobody can read is a vector nobody checks.
   */
  readonly construct?: {
    readonly kind: 'blocks-of-zeros';
    readonly count: number;
    readonly bytes: number;
  };
  readonly expect:
    | { readonly decode: 'ok'; readonly type: string }
    | { readonly decode: 'reject'; readonly code: string };
}

/**
 * Vectors for the block-exchange wire format.
 *
 * VWIP-0000 section 3 makes test vectors mandatory for anything observable on the wire, and
 * VWIP-0005 is observable on the wire in its entirety. These are **generated**, not transcribed:
 * an earlier draft of VWIP-0005 carried a hand-typed hex block as an illustration, which is the
 * artefact this corpus has most reliably found to be wrong.
 *
 * Every vector is built from the encoder where an honest peer would build it, and from `encode`
 * directly where the point is a message an honest peer cannot produce.
 */
export function buildBlockExchangeVectors(): BlockExchangeVector[] {
  const digest = sha256(new TextEncoder().encode('atlas observatory'));
  const cid = cidBytes({ version: 1, codec: CID_PARAMETERS.codecRaw, digest });
  const emptyLeaf = new Uint8Array(0);

  /**
   * `n` identifiers that differ from each other.
   *
   * Written as a helper because the alternative — `Array.from({length: n}, () => cid)` — reads
   * identically at a glance and publishes an amplification demand instead of a request. Each is a
   * real CIDv1 over a distinct preimage, so a receiver that verifies identifiers before decoding
   * them sees what it would see from an honest peer.
   */
  const distinctCids = (n: number): Uint8Array[] =>
    Array.from({ length: n }, (_, i) =>
      cidBytes({
        version: 1,
        codec: CID_PARAMETERS.codecRaw,
        digest: sha256(new TextEncoder().encode(`atlas observatory ${i}`)),
      }),
    );

  const overLimit = (key: string, entries: CborValue[], t: string): Uint8Array =>
    encode(
      new Map<string | Uint8Array, CborValue>([
        ['t', t],
        [key, entries],
      ]),
    );

  const vectors: BlockExchangeVector[] = [
    {
      name: 'blockx/bhello-v1',
      rule: 'VWIP-0005 3.3: BHELLO opens the session, carrying the version and the largest block this peer accepts',
      message: toHex(
        encodeBlockMessage({
          t: 'BHELLO',
          v: BLOCK_EXCHANGE_VERSION,
          max: BX_LIMITS.blockBytes,
        }),
      ),
      expect: { decode: 'ok', type: 'BHELLO' },
    },
    {
      // Decodes fine and must cost nothing. The defect this pins is not a decode failure; it is a
      // receiver that sizes a buffer from a number a stranger asserted.
      //
      // Built with `encode` rather than `encodeBlockMessage`, because 3.4.a forbids a PEER to
      // declare a `max` above the block limit and the encoder now enforces that. This vector used
      // to be produced by calling the encoder with a value the specification forbids — which was
      // the proof that the encoder was not checking, published as though it were a valid message
      // an honest peer might send. It is neither: it is a message only a hostile peer emits, and
      // the receiver's obligation is to cost nothing for it rather than to reject it.
      name: 'blockx/bhello-absurd-max',
      rule: 'VWIP-0005 5.1: BHELLO.max is a claim, not a measurement — a peer declaring 2^53 costs the receiver nothing beyond the message. 3.4.a forbids an honest peer to declare it at all.',
      message: toHex(
        encode(
          new Map<string | Uint8Array, CborValue>([
            ['t', 'BHELLO'],
            ['v', BLOCK_EXCHANGE_VERSION],
            ['max', 2 ** 53 - 1],
          ]),
        ),
      ),
      expect: { decode: 'ok', type: 'BHELLO' },
    },
    {
      name: 'blockx/bwant-one',
      rule: 'VWIP-0005 3.2: BWANT names the identifiers the requester wants',
      message: toHex(encodeBlockMessage({ t: 'BWANT', cids: [cid] })),
      expect: { decode: 'ok', type: 'BWANT' },
    },
    {
      // **Sixty-four DISTINCT identifiers, and the distinctness is the point.** This vector was
      // sixty-four copies of one identifier — which is 3.6.a's own description of an attack, "a
      // request for one block and a demand for sixty-four, inside a message that passes every
      // limit in section 5" — published with `expect: {decode: 'ok'}` in an artifact whose README
      // calls that column "the verdict every conforming implementation must return". It made the
      // specification's own recommended mitigation a conformance failure.
      name: 'blockx/bwant-at-the-limit',
      rule: 'VWIP-0005 5: BWANT.cids is bounded at 64, and 64 distinct identifiers are accepted',
      message: toHex(
        encodeBlockMessage({
          t: 'BWANT',
          cids: distinctCids(BX_LIMITS.wantCids),
        }),
      ),
      expect: { decode: 'ok', type: 'BWANT' },
    },
    {
      // Distinct for a second reason. As 65 copies of one identifier this vector forbade the
      // natural implementation of 3.6.a — deduplicate, then bound — because after dedup it names
      // one identifier and must be ACCEPTED, while the vector demands LIMIT_EXCEEDED. A second
      // implementer following both clauses could not write a conforming receiver at all.
      name: 'blockx/bwant-over-the-limit',
      rule: 'VWIP-0005 5: an array over the limit is refused at decode, without iterating it — and refused for its length, not for a repeat',
      message: toHex(overLimit('cids', distinctCids(BX_LIMITS.wantCids + 1), 'BWANT')),
      expect: { decode: 'reject', code: 'LIMIT_EXCEEDED' },
    },
    {
      // A file of zero bytes is a file, it has an identifier, and a wire format that cannot carry
      // it makes a published placeholder unfetchable.
      name: 'blockx/blocks-empty-leaf',
      rule: 'VWIP-0005 3.5: BLOCKS carries block octets without their identifiers',
      message: toHex(encodeBlockMessage({ t: 'BLOCKS', blks: [emptyLeaf] })),
      expect: { decode: 'ok', type: 'BLOCKS' },
    },
    {
      name: 'blockx/blocks-over-the-block-limit',
      rule: 'VWIP-0005 5: a block one octet over the limit is refused before its identifier is computed',
      construct: { kind: 'blocks-of-zeros', count: 1, bytes: BX_LIMITS.blockBytes + 1 },
      expect: { decode: 'reject', code: 'LIMIT_EXCEEDED' },
    },
    {
      name: 'blockx/unknown-type',
      rule: 'VWIP-0005 3.2: an unknown message type is named as unknown and drops the message, not the connection',
      message: toHex(encode(new Map<string | Uint8Array, CborValue>([['t', 'BHAVE']]))),
      expect: { decode: 'reject', code: 'UNKNOWN_TYPE' },
    },
  ];

  // The pair that matters most, and the only one whose assertion is an EQUALITY rather than a
  // rejection. VWIP-0005 6.2: a peer that lacks a block and a peer that declines to send one emit
  // the identical message. If these two encodings ever differ, the refusal has become an oracle
  // for enumerating what a peer holds, and 6.1 is defeated by a side channel rather than by an
  // argument. Equality assertions are the ones that pass for the wrong reason, so both are
  // published rather than one plus a claim.
  for (const label of ['bdone-held', 'bdone-absent']) {
    vectors.push({
      name: `blockx/${label}`,
      rule: 'VWIP-0005 6.2: BDONE carries no reason — a peer that holds the block and one that does not emit byte-identical messages',
      message: toHex(encodeBlockMessage({ t: 'BDONE', cids: [cid] })),
      expect: { decode: 'ok', type: 'BDONE' },
    });
  }

  return vectors;
}

/* -------------------------------------------------------------------------- */
/* When a name returns to the pool — the derivation every vector was handed    */
/* -------------------------------------------------------------------------- */

/**
 * A predecessor record and the instant at which a second implementation must agree the name is
 * claimable again.
 *
 * **`VectorState.fullyReleased` is an INPUT to every other vector in this file.** The suite hands
 * the verifier the answer and checks what it does with it, so an implementation deriving that
 * answer by any rule at all passes. The derivation is the one that decides who owns a name: it is
 * the difference between `NAME_TAKEN` and an accepted registration, so two peers computing it
 * differently accept different owners for the same name and neither ever rejects anything.
 *
 * REVOKE is the case that makes this worth publishing rather than assuming. REGISTRY.md gives an
 * ordinary expiry `notAfter + 2592000 + 2592000` — grace, then quarantine — and gives a revoked
 * name `notAfter + 2592000`, quarantine alone, because "grace would be a window in which a
 * compromised key could renew". An implementation that applied the ordinary rule to both would
 * hold a revoked name for **thirty days longer** than its peers, refusing registrations they
 * accept, for a month, without either side reporting an error.
 *
 * Only `fullyReleased` is stated, deliberately. The internal state label is not wire-visible —
 * `stateAt` reports `GRACE` for a revoked name's frozen remainder, which is an accurate reading of
 * its own boundaries and a poor thing to publish as a contract. What peers must agree on is
 * whether the name is available, and that is what this says.
 */
export interface ReleaseVector {
  readonly name: string;
  readonly rule: string;
  /** The record a peer holds for the name. */
  readonly predecessor: string;
  readonly at: number;
  readonly expectFullyReleased: boolean;
}

export function buildReleaseVectors(): ReleaseVector[] {
  const GRACE = 2_592_000;
  const QUARANTINE = 2_592_000;
  const expiry = VECTOR_NOW + TERM_SECONDS;

  // An ordinary registration: grace, then quarantine, then the pool.
  const held = toHex(registration());
  // A revocation of it. `notAfter` is copied from the predecessor — REGISTRY.md requires it —
  // so the two records expire together and only the interval AFTER expiry differs.
  const revoked = toHex(
    successor({ op: 'REVOKE', records: [], notAfter: expiry, notBefore: VECTOR_NOW + 600 }),
  );

  const cases: Array<[string, string, number, boolean, string]> = [
    ['ordinary/during-the-term', held, expiry - 1, false, 'a live name is nobody else’s'],
    ['ordinary/at-expiry', held, expiry, false, 'grace has begun; the holder may still renew'],
    ['ordinary/last-second-of-grace', held, expiry + GRACE - 1, false, 'grace runs a full 30 days'],
    [
      'ordinary/first-second-of-quarantine',
      held,
      expiry + GRACE,
      false,
      'quarantine holds it back too',
    ],
    [
      'ordinary/last-second-of-quarantine',
      held,
      expiry + GRACE + QUARANTINE - 1,
      false,
      'still held',
    ],
    [
      'ordinary/released',
      held,
      expiry + GRACE + QUARANTINE,
      true,
      'and released on the instant, not after it',
    ],
    ['revoked/during-the-frozen-term', revoked, expiry - 1, false, 'frozen, and not yet anyone’s'],
    [
      'revoked/at-expiry',
      revoked,
      expiry,
      false,
      'quarantine begins here — a revoked name gets no grace',
    ],
    [
      'revoked/last-second-of-quarantine',
      revoked,
      expiry + QUARANTINE - 1,
      false,
      'the one interval it does get',
    ],
    [
      'revoked/released-thirty-days-early',
      revoked,
      expiry + QUARANTINE,
      true,
      'released a full month before an ordinary expiry would be',
    ],
    [
      'revoked/still-released-later',
      revoked,
      expiry + GRACE + QUARANTINE,
      true,
      'and does not become held again',
    ],
  ];

  return cases.map(([name, predecessor, at, expectFullyReleased, why]) => ({
    name: `release/${name}`,
    rule:
      'REGISTRY.md: an ordinary record is released at notAfter + 2592000 + 2592000, a REVOKE at ' +
      `notAfter + 2592000 — ${why}`,
    predecessor,
    at,
    expectFullyReleased,
  }));
}
