import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Store, StoreError, frame, unframe, writeLog } from './store.ts';
import { encode, type CborMap, type CborValue } from './cbor.ts';
import { signingInput } from './domain.ts';
import { sign, publicKeyFrom } from './signature.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH, solvePow, requiredBits } from './pow.ts';
import { TERM_SECONDS, SETTLEMENT_SECONDS } from './verify.ts';

const SECRET = new Uint8Array(32).fill(0x42);
const OWNER = publicKeyFrom(SECRET);
const NOW = 1_782_518_400;

/** 16 characters, so the base difficulty is 4 bits and a test solves in ~16 evaluations. */
const LABEL = 'atlasobservatory';

const RECIPIENT_SECRET = new Uint8Array(32).fill(0x77);
const RECIPIENT = publicKeyFrom(RECIPIENT_SECRET);

const scratch = (): string => join(mkdtempSync(join(tmpdir(), 'vayuweb-')), 'log');

/**
 * Build and sign a successor record. No proof of work: none of the operations that use this
 * carry one, so nothing here costs an Argon2id search.
 */
function successorBytes(
  over: Record<string, CborValue>,
  secret: Uint8Array,
  coSecret?: Uint8Array,
): Uint8Array {
  const map = new Map<string | Uint8Array, CborValue>([
    ['version', 1],
    ['op', 'UPDATE'],
    ['name', LABEL],
    ['tld', 'vayu'],
    ['ownerKey', OWNER],
    ['seq', 1],
    ['notBefore', NOW + 600],
    ['notAfter', NOW + TERM_SECONDS],
    ['records', [entry('txt', 'v=vayuweb1')]],
    ['powProof', null],
    ['prevHash', new Uint8Array(32)],
    ...Object.entries(over),
  ]);
  const input = signingInput(map);
  map.set('sig', sign(secret, input));
  if (coSecret !== undefined) map.set('coSig', sign(coSecret, input));
  return encode(map);
}

const entry = (type: string, value: CborValue): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['type', type],
    ['value', value],
  ]);

/**
 * Solved registrations, memoised by their inputs.
 *
 * Every entry costs a real Argon2id search at 64 MiB per evaluation, and most tests here want
 * the same record. Solving it once per distinct input keeps the suite inside CI's timeout
 * without weakening anything: the proof is still genuine, still verified by the store, and
 * `solvePow` is still exercised — just not ten times for one answer.
 */
const solved = new Map<string, Uint8Array>();

function registration(over: Record<string, CborValue> = {}, at = NOW): Uint8Array {
  const key = JSON.stringify([
    at,
    Object.keys(over).sort(),
    String(over['name']),
    String(over['records']),
    String(over['notBefore']),
  ]);
  const hit = solved.get(key);
  if (hit !== undefined) return hit;
  const built = solveRegistration(over, at);
  solved.set(key, built);
  return built;
}

/** Build, solve and sign a registration that the store will actually accept. */
function solveRegistration(over: Record<string, CborValue>, at: number): Uint8Array {
  const bits = requiredBits(LABEL.length, 0);
  const skeleton = (nonce: Uint8Array): CborMap =>
    new Map<string | Uint8Array, CborValue>([
      ['version', 1],
      ['op', 'REGISTER'],
      ['name', (over['name'] as string | undefined) ?? LABEL],
      ['tld', 'vayu'],
      ['ownerKey', OWNER],
      ['seq', 0],
      ['notBefore', at],
      ['notAfter', at + TERM_SECONDS],
      ['records', [entry('txt', 'v=vayuweb1')]],
      [
        'powProof',
        new Map<string | Uint8Array, CborValue>([
          ['alg', POW_ALGORITHM],
          ['nonce', nonce],
          ['bits', bits],
        ]),
      ],
      ['prevHash', new Uint8Array(32)],
      ...Object.entries(over),
    ]);

  const nonce = solvePow(skeleton(new Uint8Array(POW_NONCE_LENGTH)), bits, { limit: 8192 });
  assert.ok(nonce, 'the test registration must be solvable');
  const map = skeleton(nonce);
  map.set('sig', sign(SECRET, signingInput(map)));
  return encode(map);
}

/* -------------------------------------------------------------------------- */
/* Framing                                                                     */
/* -------------------------------------------------------------------------- */

test('framing round-trips and is length-prefixed big-endian', () => {
  const payload = Uint8Array.of(1, 2, 3);
  const framed = frame(payload);
  assert.deepEqual(Array.from(framed.subarray(0, 4)), [0, 0, 0, 3]);
  assert.deepEqual(unframe(framed), [payload]);
});

test('a truncated or corrupt frame is refused, never guessed at', () => {
  assert.throws(() => unframe(Uint8Array.of(0, 0)), StoreError);
  assert.throws(() => unframe(Uint8Array.of(0, 0, 0, 9, 1, 2)), StoreError);
  assert.throws(() => unframe(Uint8Array.of(0, 0, 0, 0)), StoreError);
  // A corrupt length prefix must not become a huge allocation.
  assert.throws(() => unframe(Uint8Array.of(0xff, 0xff, 0xff, 0xff)), StoreError);
});

/* -------------------------------------------------------------------------- */
/* Append and replay                                                           */
/* -------------------------------------------------------------------------- */

test('a registration is accepted, persisted, and still there after reopening', () => {
  const path = scratch();
  const bytes = registration();

  const store = Store.open(path, NOW);
  assert.equal(store.append(bytes, NOW).outcome, 'accept');
  assert.equal(store.length, 1);

  const reopened = Store.open(path, NOW);
  assert.equal(reopened.length, 1);
  assert.equal(reopened.lookup(LABEL, 'vayu')?.current.record.name, LABEL);
});

test('replay re-verifies rather than trusting what is already on disk', () => {
  // A file on an ordinary disk is not evidence of anything. Flipping a byte inside a stored
  // record must be caught when the log is next opened, not carried forward as state.
  const path = scratch();
  const store = Store.open(path, NOW);
  store.append(registration(), NOW);

  const file = readFileSync(path);
  // Corrupt a byte inside the record body, past the 4-byte length prefix.
  file[file.length - 1] ^= 0xff;
  writeFileSync(path, file);

  assert.throws(
    () => Store.open(path, NOW),
    (e: unknown) => e instanceof Error,
  );
});

test('a record appended to the log out of band is refused on reopen', () => {
  // The attack this defends: append a well-formed but unauthorised record straight to the file,
  // bypassing append(). Replay must reject it exactly as arrival would have.
  const path = scratch();
  const store = Store.open(path, NOW);
  store.append(registration(), NOW);

  // A second registration of the same name, appended directly.
  appendFileSync(
    path,
    frame(registration({ notBefore: NOW + 600, notAfter: NOW + 600 + TERM_SECONDS }, NOW + 600)),
  );

  assert.throws(
    () => Store.open(path, NOW),
    (e: unknown) => e instanceof StoreError && /no longer verifies/.test((e as Error).message),
  );
});

test('replay verifies each record at its own notBefore, not at the current clock', () => {
  // Otherwise every stored registration becomes BACKDATED the moment it is a day old, and no
  // log could ever be reopened.
  const path = scratch();
  const store = Store.open(path, NOW);
  store.append(registration(), NOW);

  const muchLater = NOW + 200 * 86_400;
  const reopened = Store.open(path, muchLater);
  assert.equal(reopened.length, 1);
});

test('a duplicate arrival is dropped silently rather than rejected', () => {
  // REGISTRY.md: "a peer receiving a record it already holds MUST drop it silently, and only a
  // different record at the same seq is a conflict".
  const path = scratch();
  const bytes = registration();
  const store = Store.open(path, NOW);

  assert.equal(store.append(bytes, NOW).outcome, 'accept');
  assert.equal(store.append(bytes, NOW).outcome, 'accept', 'a duplicate is not an error');
  assert.equal(store.length, 1, 'and must not be appended twice');
});

test('a rejected record leaves the log untouched', () => {
  const path = scratch();
  const store = Store.open(path, NOW);
  store.append(registration(), NOW);
  const before = readFileSync(path).length;

  // Same name again: held.
  const verdict = store.append(registration({ records: [entry('txt', 'other')] }), NOW);
  assert.equal(verdict.outcome, 'reject');
  assert.equal(readFileSync(path).length, before, 'nothing may be written on a rejection');
  assert.equal(store.length, 1);
});

/* -------------------------------------------------------------------------- */
/* Index                                                                       */
/* -------------------------------------------------------------------------- */

test('an empty log is a valid log', () => {
  const store = Store.open(scratch(), NOW);
  assert.equal(store.length, 0);
  assert.equal(store.lookup(LABEL, 'vayu'), null);
  assert.deepEqual(store.list(NOW), []);
});

test('difficulty rises with the registration rate the log has seen', () => {
  const path = scratch();
  writeLog(path, []);
  const store = Store.open(path, NOW);
  // With an empty log the rate term contributes nothing.
  assert.equal(store.difficultyFor('ab', 'vayu', NOW), requiredBits(2, 0));
  assert.equal(store.registrationsInWindow('vayu', NOW), 0);
});

test('AUDIT: the difficulty window is not a linear scan of the log', () => {
  // Found by asking what an attacker gains by adding records rather than by reading them.
  //
  // Difficulty depends on the trailing 30 days of registrations in a TLD, and verifying one
  // record consults that twice. Computing it by scanning every entry makes replaying a log of
  // N records cost O(N^2) — and REGISTRY.md gives no way out, since the log is never truncated
  // and "a peer that has never verified the history and wants full assurance MUST pay the full
  // cost once". Adding a record costs the attacker one proof of work; the replay cost imposed
  // on every peer that ever joins grows quadratically. That prices newcomers out of verifying,
  // and a registry only newcomers-who-trust-someone can join is a different thing entirely.
  //
  // A timing assertion would be the obvious test and would be flaky in CI. What actually
  // protects the fix is that the incremental index agrees with the naive computation under
  // every arrival order — including out-of-order, which replication produces and which a
  // sorted-array optimisation gets wrong if it appends instead of inserting.
  const path = scratch();
  const store = Store.open(path, NOW);
  store.append(registration(), NOW);

  // The fast index must agree with the reference implementation at every probe, including the
  // window boundaries and instants far outside it.
  const probes = [
    0,
    NOW - 40 * 86_400,
    NOW - 1,
    NOW,
    NOW + 1,
    NOW + 3600,
    NOW + 29 * 86_400,
    NOW + 31 * 86_400,
    NOW + 10_000_000,
  ];
  for (const probe of probes) {
    assert.equal(
      store.registrationsInWindow('vayu', probe),
      store.registrationsInWindowNaive('vayu', probe),
      `fast and reference disagree at ${probe}`,
    );
  }

  // And the record does fall inside its own window, so the probes above are not all zero.
  assert.equal(store.registrationsInWindow('vayu', NOW + 3600), 1);
});

test('the sorted rate index survives out-of-order arrival', () => {
  // Binary search is correct only on a sorted array. Replication delivers records in arrival
  // order, not in time order, so an implementation that appends instead of inserting returns
  // wrong counts — and a wrong count is a wrong difficulty, which is a fork.
  const store = Store.open(scratch(), NOW);
  const at = NOW + 7200;

  // Distinct names so both are accepted, and — the point of the test — the SECOND record's
  // notBefore is genuinely EARLIER than the first's. Backdating by 7200s is within the 86400s
  // the verifier allows, so both are valid; only the index ordering is exercised.
  store.append(
    registration({ name: 'atlasobservatory', notBefore: at, notAfter: at + TERM_SECONDS }, at),
    at,
  );
  store.append(
    registration({ name: 'zenithobservatory', notBefore: NOW, notAfter: NOW + TERM_SECONDS }, NOW),
    at,
  );

  // Sanity: the two really are out of order, or this test proves nothing.
  assert.equal(store.length, 2, 'both registrations must have been accepted');

  for (const probe of [NOW, NOW + 3600, at, at + 1, NOW + 20 * 86_400, NOW + 40 * 86_400]) {
    assert.equal(
      store.registrationsInWindow('vayu', probe),
      store.registrationsInWindowNaive('vayu', probe),
      `fast and reference disagree at ${probe}`,
    );
  }
});

test('the rate window counts only the same TLD', () => {
  const path = scratch();
  const store = Store.open(path, NOW);
  store.append(registration(), NOW);
  // The registration sits in .vayu, so .p2p must be unaffected.
  assert.equal(store.registrationsInWindow('p2p', NOW + 7200), 0);
});

test('list reports the lifecycle state at the instant asked about', () => {
  const path = scratch();
  const store = Store.open(path, NOW);
  store.append(registration(), NOW);

  assert.equal(store.list(NOW)[0]?.state, 'LIVE');
  assert.equal(store.list(NOW + TERM_SECONDS + 1)[0]?.state, 'GRACE');
  assert.equal(store.list(NOW + TERM_SECONDS + 5_184_000 + 1)[0]?.state, 'FREE');
});

/* -------------------------------------------------------------------------- */
/* AUDIT FINDING: the index has to agree with the verifier about who controls  */
/* -------------------------------------------------------------------------- */

test('AUDIT: a settled transfer replays, and the index knows who controls it meanwhile', () => {
  // The store computes the controlling key a second time — once in the verifier to check a
  // signature, once here to index the accepted record — and a TRANSFER is the only operation
  // where that answer is not simply `ownerKey`. If the two ever disagree, the log accepts a
  // record it will refuse to replay, and `Store.open` throws on a file it wrote itself.
  //
  // Replay is the sharp end: `Store.open` re-verifies at each record's own `notBefore`, so this
  // exercises the whole chain — pending transfer, refusal during settlement, acceptance after —
  // against a verifier that has no memory of having accepted any of it.
  const path = scratch();
  const store = Store.open(path, NOW);
  const reg = registration();
  assert.equal(store.append(reg, NOW).outcome, 'accept');

  const prev = store.lookup(LABEL, 'vayu')!;
  const handoverAt = NOW + 600;
  const handover = successorBytes(
    {
      op: 'TRANSFER',
      ownerKey: RECIPIENT,
      seq: 1,
      notBefore: handoverAt,
      notAfter: prev.current.record.notAfter,
      records: [],
      prevHash: prev.current.hash,
    },
    SECRET,
    RECIPIENT_SECRET,
  );
  assert.equal(store.append(handover, handoverAt).outcome, 'accept');

  // Indexed as pending: ownerKey names the recipient, signerKey still names the transferor.
  const pending = store.lookup(LABEL, 'vayu')!;
  assert.deepEqual(pending.current.record.ownerKey, RECIPIENT);
  assert.deepEqual(pending.current.signerKey, OWNER);

  // The recipient acting inside the window is refused by the store, not merely by the verifier.
  const tooEarly = successorBytes(
    {
      seq: 2,
      ownerKey: RECIPIENT,
      notBefore: handoverAt + 600,
      notAfter: prev.current.record.notAfter,
      records: [entry('txt', 'v=early')],
      prevHash: store.lookup(LABEL, 'vayu')!.current.hash,
    },
    RECIPIENT_SECRET,
  );
  const early = store.append(tooEarly, handoverAt + 600);
  assert.equal(early.outcome === 'reject' ? early.code : early.outcome, 'UNSETTLED');

  // And accepted once the fourteen days have run.
  const settledAt = handoverAt + SETTLEMENT_SECONDS;
  const afterSettlement = successorBytes(
    {
      seq: 2,
      ownerKey: RECIPIENT,
      notBefore: settledAt,
      notAfter: prev.current.record.notAfter,
      records: [entry('txt', 'v=settled')],
      prevHash: store.lookup(LABEL, 'vayu')!.current.hash,
    },
    RECIPIENT_SECRET,
  );
  assert.equal(store.append(afterSettlement, settledAt).outcome, 'accept');

  // The whole log, re-verified from bytes by a store with no history.
  const reopened = Store.open(path, settledAt);
  assert.equal(reopened.length, 3);
  assert.deepEqual(reopened.lookup(LABEL, 'vayu')?.current.record.ownerKey, RECIPIENT);
});
