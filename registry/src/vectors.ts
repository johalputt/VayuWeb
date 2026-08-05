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

import { encode, compareBytes, type CborMap, type CborValue } from './cbor.ts';
import { LIMITS, PROTOCOL_VERSION, encodeMessage } from './replicate.ts';
import { signingInput, recordHashFromBytes } from './domain.ts';
import { sign, publicKeyFrom } from './signature.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH } from './pow.ts';
import { TERM_SECONDS, RENEWAL_WINDOW_SECONDS } from './verify.ts';
import { GRACE_SECONDS } from './lifecycle.ts';
import { RESERVED_LABELS } from './names.ts';

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

const FRESH: VectorState = {
  predecessor: null,
  revoked: false,
  fullyReleased: false,
  powVerified: true,
};

const HELD: VectorState = { ...FRESH, predecessor: toHex(PREV_BYTES) };

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
      rule: 'REGISTRY.md RELEASE: records empty and notAfter == notBefore',
      record: toHex(successor({ op: 'RELEASE', records: [], notAfter: VECTOR_NOW + 600 })),
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
    | { readonly outcome: 'ok'; readonly source: string }
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

/** A registration by the other key, so a race is between strangers rather than equivocation. */
const byOther = (over: Record<string, CborValue> = {}): Uint8Array =>
  build(
    {
      version: 1,
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
