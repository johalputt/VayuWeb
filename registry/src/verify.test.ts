import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  verify,
  predecessorFrom,
  TERM_SECONDS,
  RENEWAL_WINDOW_SECONDS,
  MAX_CLOCK_SKEW_SECONDS,
  SETTLEMENT_SECONDS,
  type Predecessor,
  type RegistryView,
  type Verdict,
} from './verify.ts';
import { parseRecordBytes } from './record.ts';
import { encode, type CborMap, type CborValue } from './cbor.ts';
import { signingInput } from './domain.ts';
import { sign, publicKeyFrom } from './signature.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH } from './pow.ts';
import { lifecycleOf } from './lifecycle.ts';

const OWNER_SECRET = new Uint8Array(32).fill(0x42);
const OWNER_KEY = publicKeyFrom(OWNER_SECRET);
const THIEF_SECRET = new Uint8Array(32).fill(0x77);
const THIEF_KEY = publicKeyFrom(THIEF_SECRET);

/** A fixed instant, so nothing in this file depends on when it runs. */
const NOW = 1_782_518_400;

const pow = (): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['alg', POW_ALGORITHM],
    ['nonce', new Uint8Array(POW_NONCE_LENGTH).fill(7)],
    ['bits', 10],
  ]);

const entry = (type: string, value: CborValue): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['type', type],
    ['value', value],
  ]);

/**
 * Build and sign a record. `secret` signs `sig`; `coSecret`, when given, signs `coSig`.
 * Signing happens over the record minus both signatures, so the fields are set last.
 */
function build(
  fields: Record<string, CborValue>,
  secret: Uint8Array = OWNER_SECRET,
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
    ownerKey: OWNER_KEY,
    seq: 0,
    notBefore: NOW,
    notAfter: NOW + TERM_SECONDS,
    records: [entry('txt', 'v=vayuweb1')],
    powProof: pow(),
    prevHash: new Uint8Array(32),
    ...over,
  });

/** A permissive-but-explicit view. Each test narrows exactly what it is testing. */
function view(over: Partial<RegistryView> = {}): RegistryView {
  return {
    current: () => null,
    fullyReleased: () => false,
    revoked: () => false,
    powVerified: () => true,
    ...over,
  };
}

function accepted(bytes: Uint8Array): Predecessor {
  return predecessorFrom(parseRecordBytes(bytes), bytes);
}

const code = (v: Verdict): string =>
  v.outcome === 'accept' ? 'accept' : v.outcome === 'defer' ? `defer:${v.reason}` : v.code;

/** The registered predecessor every successor test chains onto. */
const PREV_BYTES = registration();
const PREV = accepted(PREV_BYTES);
const prevView = (over: Partial<RegistryView> = {}) => view({ current: () => PREV, ...over });

const successor = (
  over: Record<string, CborValue>,
  secret: Uint8Array = OWNER_SECRET,
  coSecret?: Uint8Array,
): Uint8Array =>
  build(
    {
      version: 1,
      op: 'UPDATE',
      name: 'atlas',
      tld: 'vayu',
      ownerKey: OWNER_KEY,
      seq: 1,
      notBefore: NOW + 600,
      notAfter: NOW + TERM_SECONDS,
      records: [entry('txt', 'v=vayuweb1')],
      powProof: null,
      prevHash: PREV.hash,
      ...over,
    },
    secret,
    coSecret,
  );

/* -------------------------------------------------------------------------- */
/* Baseline                                                                    */
/* -------------------------------------------------------------------------- */

test('a signed first registration of a free name is accepted', () => {
  assert.equal(code(verify(registration(), view(), NOW)), 'accept');
});

test('a signed update by the owner is accepted', () => {
  assert.equal(code(verify(successor({}), prevView(), NOW + 600)), 'accept');
});

/* -------------------------------------------------------------------------- */
/* AUDIT FINDING: an unbounded term for one proof of work                      */
/* -------------------------------------------------------------------------- */

test('AUDIT: a RENEW cannot buy a century of ownership with one proof of work', () => {
  // The attacker's move. REGISTRY.md's renewal window is a LOWER bound only —
  // `notBefore >= prev.notAfter - 5184000` — and notAfter is then derived as
  // `max(prev.notAfter, notBefore) + 31536000`. Nothing in the pseudocode's successor path
  // bounds notBefore from above, because the clock checks sit inside the REGISTER branch.
  //
  // So: name a notBefore a century out. The window check passes trivially (it only asks that
  // you are not renewing too EARLY). notAfter becomes notBefore + one year. One proof of work,
  // and the name is held past every participant's lifetime.
  //
  // The consequence is not a stuck record. It is the destruction of the property RENEW exists
  // to create: "Proof-of-work is required again, which makes holding ten thousand names a
  // recurring annual cost rather than a one-off." A squatter renewing a portfolio once, a
  // century forward, pays that cost exactly once.
  const century = NOW + 100 * TERM_SECONDS;
  const landGrab = successor({
    op: 'RENEW',
    notBefore: century,
    notAfter: century + TERM_SECONDS,
    powProof: pow(),
  });

  const verdict = verify(landGrab, prevView(), NOW + 600);
  assert.notEqual(verdict.outcome, 'accept', 'a century-long term must not be accepted');
  assert.equal(code(verdict), 'defer:CLOCK_SKEW');
});

test('AUDIT: the same bound applies to every operation, not just RENEW', () => {
  // Fixing RENEW alone would leave the others able to postdate a term start, which pushes the
  // floor for every later record (TOO_SOON is measured against prev.notBefore) and freezes the
  // name for the rest of its term. The bound belongs to the record, not to one operation.
  //
  // The postdate has to stay structurally well-formed to reach the clock check at all: UPDATE
  // and REVOKE must not move notAfter, so notBefore can only run up to the existing expiry
  // before `notAfter < notBefore` refuses it earlier and for a different reason. Just short of
  // the expiry is still a year in the future, which is the whole point.
  const cases = [
    {
      op: 'UPDATE',
      notBefore: PREV.record.notAfter - 1,
      notAfter: PREV.record.notAfter,
      records: [entry('txt', 'x')] as CborValue,
    },
    {
      op: 'REVOKE',
      notBefore: PREV.record.notAfter - 1,
      notAfter: PREV.record.notAfter,
      records: [] as CborValue,
    },
    {
      op: 'RELEASE',
      notBefore: NOW + 10 * TERM_SECONDS,
      notAfter: NOW + 10 * TERM_SECONDS,
      records: [] as CborValue,
    },
  ];
  for (const c of cases) {
    assert.equal(code(verify(successor(c), prevView(), NOW + 600)), 'defer:CLOCK_SKEW', c.op);
  }
});

test('the bound does not break legitimate early renewal', () => {
  // "Early" means early relative to the predecessor's expiry, not ahead of the clock. Renewing
  // on the first day of the window must still work, or the fix has broken the feature.
  const windowOpens = PREV.record.notAfter - RENEWAL_WINDOW_SECONDS;
  const renewal = successor({
    op: 'RENEW',
    notBefore: windowOpens,
    notAfter: PREV.record.notAfter + TERM_SECONDS,
    powProof: pow(),
  });
  assert.equal(code(verify(renewal, prevView(), windowOpens)), 'accept');
});

test('renewing inside grace restarts the term from the moment of renewal', () => {
  const late = PREV.record.notAfter + 86_400;
  const renewal = successor({
    op: 'RENEW',
    notBefore: late,
    notAfter: late + TERM_SECONDS,
    powProof: pow(),
  });
  assert.equal(code(verify(renewal, prevView(), late)), 'accept');
});

test('a renewal before the window opens is refused', () => {
  const tooEarly = PREV.record.notAfter - RENEWAL_WINDOW_SECONDS - 1;
  const renewal = successor({
    op: 'RENEW',
    notBefore: tooEarly,
    notAfter: PREV.record.notAfter + TERM_SECONDS,
    powProof: pow(),
  });
  assert.equal(code(verify(renewal, prevView(), tooEarly)), 'TOO_SOON');
});

test('a clock-skewed record is deferred, never rejected', () => {
  // Deferral matters: rejecting would make a verifier whose clock is a minute slow permanently
  // disagree with its peers about a valid record.
  const skewed = successor({ notBefore: NOW + 600 });
  assert.equal(
    code(verify(skewed, prevView(), NOW + 600 - MAX_CLOCK_SKEW_SECONDS - 1)),
    'defer:CLOCK_SKEW',
  );
  assert.equal(code(verify(skewed, prevView(), NOW + 600 - MAX_CLOCK_SKEW_SECONDS)), 'accept');
});

/* -------------------------------------------------------------------------- */
/* Authority                                                                   */
/* -------------------------------------------------------------------------- */

test('a successor signed by anyone but the predecessor owner is refused', () => {
  const forged = successor({}, THIEF_SECRET);
  assert.equal(code(verify(forged, prevView(), NOW + 600)), 'BAD_SIG');
});

test('a successor may not silently change ownerKey', () => {
  // Authority is checked against the PREDECESSOR key, so a record naming a new ownerKey and
  // signed by the real owner would otherwise hand the name over with no countersignature.
  const handover = successor({ ownerKey: THIEF_KEY });
  assert.equal(code(verify(handover, prevView(), NOW + 600)), 'BAD_OWNER');
});

test('TRANSFER requires a countersignature from the incoming key', () => {
  const base = {
    op: 'TRANSFER',
    ownerKey: THIEF_KEY,
    notAfter: PREV.record.notAfter,
    records: [] as CborValue,
  };

  // Signed by the outgoing owner alone: the name would land on a key nobody has proven to hold.
  assert.equal(code(verify(successor(base), prevView(), NOW + 600)), 'BAD_COSIG');

  // Countersigned by the wrong key.
  assert.equal(
    code(verify(successor(base, OWNER_SECRET, OWNER_SECRET), prevView(), NOW + 600)),
    'BAD_COSIG',
  );

  // Countersigned by the incoming key: accepted.
  assert.equal(
    code(verify(successor(base, OWNER_SECRET, THIEF_SECRET), prevView(), NOW + 600)),
    'accept',
  );
});

/* -------------------------------------------------------------------------- */
/* AUDIT FINDING: transfer took effect instantly, against Article 33.4         */
/* -------------------------------------------------------------------------- */

/** A TRANSFER of `atlas.vayu` from the owner to `to`, signed by `from`. */
const transfer = (
  to: Uint8Array,
  fromSecret: Uint8Array,
  toSecret: Uint8Array,
  over: Record<string, CborValue> = {},
): Uint8Array =>
  successor(
    {
      op: 'TRANSFER',
      ownerKey: to,
      notAfter: PREV.record.notAfter,
      records: [] as CborValue,
      ...over,
    },
    fromSecret,
    toSecret,
  );

/** The accepted TRANSFER, and the view a record chaining onto it sees. */
const HANDOVER_BYTES = transfer(THIEF_KEY, OWNER_SECRET, THIEF_SECRET);
const HANDOVER = predecessorFrom(parseRecordBytes(HANDOVER_BYTES), HANDOVER_BYTES, OWNER_KEY);
const SETTLED_AT = HANDOVER.record.notBefore + SETTLEMENT_SECONDS;
const handoverView = () => view({ current: () => HANDOVER });

/** A record chaining onto the pending TRANSFER. */
const afterHandover = (
  over: Record<string, CborValue>,
  secret: Uint8Array,
  coSecret?: Uint8Array,
): Uint8Array =>
  build(
    {
      version: 1,
      op: 'UPDATE',
      name: 'atlas',
      tld: 'vayu',
      ownerKey: THIEF_KEY,
      seq: 2,
      notBefore: HANDOVER.record.notBefore + 600,
      notAfter: PREV.record.notAfter,
      records: [entry('txt', 'v=vayuweb1')],
      powProof: null,
      prevHash: HANDOVER.hash,
      ...over,
    },
    secret,
    coSecret,
  );

test('AUDIT: a stolen name cannot be gone the same second the thief signs', () => {
  // The attack Article 33.4 exists to slow. A thief who obtains the ownership key signs one
  // TRANSFER to a key of their own and countersigns it themselves — both signatures are theirs,
  // so the countersignature is no obstacle at all. Under the rules as they stood, the moment
  // that record was accepted the thief's key was the ownership key, the real holder had no
  // authority left, and REVOKE — the only deadman switch on offer — destroys the name rather
  // than returning it.
  //
  // 33.4: "A TRANSFER record SHALL take effect only after a mandatory settlement delay of
  // fourteen days." The record is accepted at once; its EFFECT is what waits. So the test is
  // not on the transfer, it is on what the recipient's key can do with the name the next
  // minute — which must be nothing.
  assert.equal(code(verify(HANDOVER_BYTES, prevView(), NOW + 600)), 'accept');

  const grab = afterHandover({ records: [entry('txt', 'v=stolen')] }, THIEF_SECRET);
  assert.equal(
    code(verify(grab, handoverView(), HANDOVER.record.notBefore + 600)),
    'UNSETTLED',
    'the recipient must not be able to act on the name inside the settlement delay',
  );
});

test('AUDIT: the transferor still controls the name throughout settlement', () => {
  // The other half of 33.4. Deferring the effect is only a protection if the outgoing key can
  // still act during the delay; a window in which NOBODY controls the name would be a worse
  // outcome than an instant transfer, not a better one.
  //
  // The cancellation is a TRANSFER back to the transferor's own key, signed and countersigned
  // by the transferor. It needs no new record type — Article 29.4's set is closed and has no
  // "cancel" — and it satisfies the differing-key rule, because the key it names differs from
  // the pending recipient's.
  const cancel = afterHandover(
    { op: 'TRANSFER', ownerKey: OWNER_KEY, records: [] as CborValue },
    OWNER_SECRET,
    OWNER_SECRET,
  );
  assert.equal(code(verify(cancel, handoverView(), HANDOVER.record.notBefore + 600)), 'accept');
});

test('AUDIT: the recipient cannot redirect a transfer it has not yet received', () => {
  // If the pending recipient could sign during settlement, the delay would protect nothing: the
  // thief would simply chain a second transfer onward and the name would be two keys away
  // before anyone noticed. Authority during settlement is the transferor's, so a record signed
  // by the incoming key fails on the signature, not on the operation.
  const onward = afterHandover(
    { op: 'TRANSFER', ownerKey: OWNER_KEY, records: [] as CborValue },
    THIEF_SECRET,
    OWNER_SECRET,
  );
  assert.equal(code(verify(onward, handoverView(), HANDOVER.record.notBefore + 600)), 'BAD_SIG');
});

test('settlement hands control over, and takes it away, at exactly fourteen days', () => {
  // The boundary in both directions, because a one-sided assertion here would pass against an
  // off-by-one that gave the recipient a day too many or the transferor a day too few.
  const byRecipient = (at: number) =>
    code(verify(afterHandover({ notBefore: at }, THIEF_SECRET), handoverView(), at));
  const byTransferor = (at: number) =>
    code(verify(afterHandover({ notBefore: at }, OWNER_SECRET), handoverView(), at));

  assert.equal(byRecipient(SETTLED_AT - 1), 'UNSETTLED');
  assert.equal(byRecipient(SETTLED_AT), 'accept');
  assert.equal(byTransferor(SETTLED_AT), 'BAD_SIG');
});

test('settlement is judged on the record, not on the verifier clock', () => {
  // Article 29.6 requires every record to be verifiable offline from the record and the chain
  // alone. If settlement were measured against the verifier's own clock, one record would get
  // different verdicts on two honest peers whose clocks differ, and the same record would flip
  // verdict as a peer's clock crossed the settlement instant — so a log accepted on Tuesday
  // would fail to replay on Wednesday. Different owners for one name, permanently.
  //
  // Making that visible needs a case where `now` and `notBefore` disagree about settlement
  // WITHOUT tripping the clock rules, which bound notBefore to [now - 86400, now + 300]. So the
  // settlement instant has to fall inside that gap. Both directions, because each catches a
  // different half: a first attempt at this test compared the same bytes at two very distant
  // instants and proved nothing at all, because BACKDATED is checked long before authority is.
  //
  // Settled by the record, not yet by the clock. The recipient signs.
  const early = afterHandover({ notBefore: SETTLED_AT }, THIEF_SECRET);
  assert.equal(
    code(verify(early, handoverView(), SETTLED_AT - 200)),
    'accept',
    'the record settled at its own notBefore; a verifier running 200s behind must agree',
  );

  // Settled by the clock, not yet by the record. The transferor cancels, one second inside the
  // window, on a peer whose clock is an hour past it.
  const lateCancel = afterHandover(
    { op: 'TRANSFER', ownerKey: OWNER_KEY, records: [] as CborValue, notBefore: SETTLED_AT - 1 },
    OWNER_SECRET,
    OWNER_SECRET,
  );
  assert.equal(
    code(verify(lateCancel, handoverView(), SETTLED_AT + 3600)),
    'accept',
    'the cancellation was inside the window when it was signed, and stays inside it',
  );
});

test('a TRANSFER predecessor without its transferor key is refused, not defaulted', () => {
  // The guard on predecessorFrom, which is load-bearing rather than defensive. `ownerKey` on a
  // TRANSFER is the RECIPIENT, so a caller that omits the signer gets a Predecessor claiming the
  // recipient already controls the name — instant transfer, reintroduced silently, by whichever
  // call site forgot the argument rather than by any change to the rule.
  assert.throws(
    () => predecessorFrom(parseRecordBytes(HANDOVER_BYTES), HANDOVER_BYTES),
    /transferor key/,
  );
  // Every other operation names its own signer, so the default is right there and stays.
  assert.deepEqual(accepted(PREV_BYTES).signerKey, OWNER_KEY);
});

test('a TRANSFER that cannot settle before the term ends is refused', () => {
  // A transfer signed with ten days left settles four days after the name has expired, so the
  // recipient receives a name they never controlled and cannot renew — RENEW during settlement
  // is refused like everything else. Worse, the name is frozen for the whole of that window:
  // the transferor no longer wants it and the recipient may not act on it yet.
  const nearExpiry = PREV.record.notAfter - 10 * 86_400;
  const doomed = transfer(THIEF_KEY, OWNER_SECRET, THIEF_SECRET, { notBefore: nearExpiry });
  assert.equal(code(verify(doomed, prevView(), nearExpiry)), 'UNSETTLED');
});

test('AUDIT: an expired holder cannot reclaim the name during quarantine', () => {
  // REGISTRY.md states among the chain rules that prev must be "still inside its term or grace
  // period", but its verify() pseudocode omits the check entirely — it carries only revoked().
  //
  // Implemented literally, a holder whose grace has lapsed can still sign an UPDATE or a
  // TRANSFER while the name sits in quarantine. That reclaims it ahead of everyone waiting the
  // window out, and quarantine exists precisely so that nobody may take the name during it. The
  // former holder would be the one party able to.
  const life = lifecycleOf(PREV.record);
  const renewal = (at: number) =>
    successor({
      op: 'RENEW',
      notBefore: at,
      notAfter: Math.max(PREV.record.notAfter, at) + TERM_SECONDS,
      powProof: pow(),
    });

  // Inside grace a renewal is still the owner's right — that is what grace is for.
  const inGrace = life.liveUntil + 1;
  assert.equal(code(verify(renewal(inGrace), prevView(), inGrace)), 'accept');

  // Once grace lapses the name is on its way back to the pool, and the former holder is the
  // one party who must not be able to take it back.
  const inQuarantine = life.graceUntil + 1;
  assert.equal(code(verify(renewal(inQuarantine), prevView(), inQuarantine)), 'EXPIRED');
});

test('only RENEW may act during grace; the others need a live predecessor', () => {
  // REGISTRY.md draws the line in two places: RENEW names "prev live or within its 30-day grace
  // period", every other operation names "a live prev". There is nothing to update, transfer or
  // release once the term has run out.
  const life = lifecycleOf(PREV.record);
  const inGrace = life.liveUntil + 1;

  const transfer = successor(
    {
      op: 'TRANSFER',
      ownerKey: THIEF_KEY,
      notAfter: PREV.record.notAfter,
      records: [],
      notBefore: PREV.record.notAfter - 1,
    },
    OWNER_SECRET,
    THIEF_SECRET,
  );
  assert.equal(code(verify(transfer, prevView(), inGrace)), 'EXPIRED');
});

test('a revoked name accepts nothing further, whoever signs it', () => {
  const verdict = verify(successor({}), prevView({ revoked: () => true }), NOW + 600);
  assert.equal(code(verdict), 'REVOKED');
});

/* -------------------------------------------------------------------------- */
/* Chain integrity                                                             */
/* -------------------------------------------------------------------------- */

test('the chain refuses gaps, replays and substituted predecessors', () => {
  assert.equal(code(verify(successor({ seq: 2 }), prevView(), NOW + 600)), 'BAD_SEQ');
  assert.equal(code(verify(successor({ seq: 0 }), prevView(), NOW + 600)), 'BAD_SEQ');
  assert.equal(
    code(verify(successor({ prevHash: new Uint8Array(32).fill(9) }), prevView(), NOW + 600)),
    'BAD_CHAIN',
  );
});

test('a replayed record is no longer next in sequence', () => {
  // Accept an update, then feed the very same bytes back with it as the predecessor.
  const update = successor({});
  const afterUpdate = accepted(update);
  assert.equal(code(verify(update, view({ current: () => afterUpdate }), NOW + 1200)), 'BAD_SEQ');
});

test('a successor without an accepted predecessor is refused', () => {
  assert.equal(code(verify(successor({}), view(), NOW + 600)), 'NO_PREDECESSOR');
});

test('a successor must be at least 300s after its predecessor', () => {
  assert.equal(
    code(verify(successor({ notBefore: NOW + 299 }), prevView(), NOW + 600)),
    'TOO_SOON',
  );
  assert.equal(code(verify(successor({ notBefore: NOW + 300 }), prevView(), NOW + 600)), 'accept');
});

/* -------------------------------------------------------------------------- */
/* Registration                                                                */
/* -------------------------------------------------------------------------- */

test('a held name cannot be registered over', () => {
  const verdict = verify(registration(), view({ current: () => PREV }), NOW);
  assert.equal(code(verdict), 'NAME_TAKEN');
});

test('a name that finished quarantine returns to the open pool', () => {
  const verdict = verify(
    registration(),
    view({ current: () => PREV, fullyReleased: () => true }),
    NOW,
  );
  assert.equal(code(verdict), 'accept');
});

test('a REGISTER must carry seq 0 and a zero prevHash', () => {
  assert.equal(code(verify(registration({ seq: 1 }), view(), NOW)), 'BAD_CHAIN');
  assert.equal(
    code(verify(registration({ prevHash: new Uint8Array(32).fill(1) }), view(), NOW)),
    'BAD_CHAIN',
  );
});

test('a registration term is exactly one year, not merely positive', () => {
  assert.equal(
    code(verify(registration({ notAfter: NOW + TERM_SECONDS + 1 }), view(), NOW)),
    'BAD_TERM',
  );
  assert.equal(
    code(verify(registration({ notAfter: NOW + 10 * TERM_SECONDS }), view(), NOW)),
    'BAD_TERM',
  );
});

test('a backdated registration is refused', () => {
  const old = NOW - 86_401;
  const stale = registration({ notBefore: old, notAfter: old + TERM_SECONDS });
  assert.equal(code(verify(stale, view(), NOW)), 'BACKDATED');
});

test('an unproven registration is refused', () => {
  const verdict = verify(registration(), view({ powVerified: () => false }), NOW);
  assert.equal(code(verdict), 'BAD_POW');
});

test('proof of work is checked last, so an invalid signature never costs an Argon2id run', () => {
  // Ordering is a denial-of-service property here: verifying the proof before the signature
  // would let an unsigned record spend the verifier's memory-hard budget for free.
  let powRuns = 0;
  const forged = build({
    version: 1,
    op: 'REGISTER',
    name: 'atlas',
    tld: 'vayu',
    ownerKey: THIEF_KEY, // signed below by OWNER_SECRET, so the signature will not verify
    seq: 0,
    notBefore: NOW,
    notAfter: NOW + TERM_SECONDS,
    records: [entry('txt', 'x')],
    powProof: pow(),
    prevHash: new Uint8Array(32),
  });
  const verdict = verify(
    forged,
    view({
      powVerified: () => {
        powRuns += 1;
        return true;
      },
    }),
    NOW,
  );
  assert.equal(code(verdict), 'BAD_SIG');
  assert.equal(powRuns, 0, 'the proof must not be evaluated for an unsigned record');
});

/* -------------------------------------------------------------------------- */
/* Per-operation term rules                                                    */
/* -------------------------------------------------------------------------- */

test('UPDATE, TRANSFER and REVOKE may not move the expiry', () => {
  assert.equal(
    code(verify(successor({ notAfter: PREV.record.notAfter + 1 }), prevView(), NOW + 600)),
    'BAD_TERM',
  );
  assert.equal(
    code(
      verify(
        successor({ op: 'REVOKE', records: [], notAfter: PREV.record.notAfter + 1 }),
        prevView(),
        NOW + 600,
      ),
    ),
    'BAD_TERM',
  );
});

test('RELEASE expires the name at once and carries no entries', () => {
  const at = NOW + 600;
  assert.equal(
    code(verify(successor({ op: 'RELEASE', records: [], notAfter: at }), prevView(), at)),
    'accept',
  );
  assert.equal(
    code(
      verify(
        successor({ op: 'RELEASE', records: [entry('txt', 'x')], notAfter: at }),
        prevView(),
        at,
      ),
    ),
    'BAD_RECORD_ENTRY',
  );
});

test('only RENEW may carry a proof of work on the successor path', () => {
  const verdict = verify(successor({ powProof: pow() }), prevView(), NOW + 600);
  assert.equal(code(verdict), 'UNEXPECTED_POW');
});

/* -------------------------------------------------------------------------- */
/* Framing                                                                     */
/* -------------------------------------------------------------------------- */

test('a record above the size cap is refused before it is decoded', () => {
  const huge = new Uint8Array(5000);
  assert.equal(code(verify(huge, view(), NOW)), 'TOO_LARGE');
});

test('non-canonical bytes are refused rather than normalised', () => {
  // An indefinite-length map encodes the same content as a definite-length one. If both were
  // accepted, one record would have two record_hash values, and record_hash is the convergence
  // tie-break — free grinding at the exact point the protocol is undecidable.
  const indefinite = Uint8Array.of(0xbf, 0x61, 0x61, 0x01, 0xff);
  const verdict = verify(indefinite, view(), NOW);
  assert.notEqual(verdict.outcome, 'accept');
});
