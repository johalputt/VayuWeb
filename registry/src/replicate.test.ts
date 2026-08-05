import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  LIMITS,
  PROTOCOL_VERSION,
  ReplicationError,
  ReplicationSession,
  decodeMessage,
  encodeMessage,
  verifyEquivocation,
  type Message,
  type ReplicationSink,
} from './replicate.ts';
import { Store } from './store.ts';
import { encode, compareBytes, type CborMap, type CborValue } from './cbor.ts';
import { signingInput, recordHashFromBytes } from './domain.ts';
import { sign, publicKeyFrom } from './signature.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH, solvePow, requiredBits } from './pow.ts';
import { TERM_SECONDS } from './verify.ts';

const NOW = 1_782_518_400;

/** Two owners, so a race between strangers is distinguishable from one owner equivocating. */
const SECRET_A = new Uint8Array(32).fill(0x42);
const SECRET_B = new Uint8Array(32).fill(0x43);
const OWNER_A = publicKeyFrom(SECRET_A);
const OWNER_B = publicKeyFrom(SECRET_B);

/** 16 characters, so the base difficulty is 4 bits and a proof solves in ~16 evaluations. */
const LABEL = 'atlasobservatory';

const scratch = (): string => join(mkdtempSync(join(tmpdir(), 'vayuweb-repl-')), 'log');

const entry = (type: string, value: CborValue): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['type', type],
    ['value', value],
  ]);

/**
 * Solved registrations, memoised.
 *
 * Every one costs a real Argon2id search at 64 MiB per evaluation. The proofs are genuine and the
 * stores verify them; memoising only avoids solving the same input twice.
 */
const solved = new Map<string, Uint8Array>();

interface Build {
  readonly secret?: Uint8Array;
  readonly owner?: Uint8Array;
  readonly label?: string;
  readonly txt?: string;
  readonly at?: number;
}

function registration(build: Build = {}): Uint8Array {
  const key = JSON.stringify([
    build.label ?? LABEL,
    build.txt ?? 'v=vayuweb1',
    build.at ?? NOW,
    Array.from(build.owner ?? OWNER_A).slice(0, 4),
  ]);
  const hit = solved.get(key);
  if (hit !== undefined) return hit;

  const label = build.label ?? LABEL;
  const at = build.at ?? NOW;
  const owner = build.owner ?? OWNER_A;
  const secret = build.secret ?? SECRET_A;
  const bits = requiredBits(label.length, 0);

  const skeleton = (nonce: Uint8Array): CborMap =>
    new Map<string | Uint8Array, CborValue>([
      ['version', 1],
      ['op', 'REGISTER'],
      ['name', label],
      ['tld', 'vayu'],
      ['ownerKey', owner],
      ['seq', 0],
      ['notBefore', at],
      ['notAfter', at + TERM_SECONDS],
      ['records', [entry('txt', build.txt ?? 'v=vayuweb1')]],
      [
        'powProof',
        new Map<string | Uint8Array, CborValue>([
          ['alg', POW_ALGORITHM],
          ['nonce', nonce],
          ['bits', bits],
        ]),
      ],
      ['prevHash', new Uint8Array(32)],
    ]);

  const nonce = solvePow(skeleton(new Uint8Array(POW_NONCE_LENGTH)), bits, { limit: 8192 });
  assert.ok(nonce, 'the test registration must be solvable');
  const map = skeleton(nonce);
  map.set('sig', sign(secret, signingInput(map)));
  const bytes = encode(map);
  solved.set(key, bytes);
  return bytes;
}

/**
 * A registration with a deliberately unsolved proof of work, varied by `salt`.
 *
 * Used to probe which code path a conflicting claim reaches: a peer that verifies the proof says
 * BAD_POW, one that exits on the digest comparison says NAME_TAKEN. Cheap to build precisely
 * because no proof is searched for.
 */
function unsolvedRegistration(
  label: string,
  salt: number,
  at: number = NOW,
  owner: Uint8Array = OWNER_B,
  secret: Uint8Array = SECRET_B,
): Uint8Array {
  const bits = requiredBits(label.length, 0);
  const nonce = new Uint8Array(POW_NONCE_LENGTH);
  nonce[0] = salt & 0xff;
  nonce[1] = (salt >> 8) & 0xff;
  const map: CborMap = new Map<string | Uint8Array, CborValue>([
    ['version', 1],
    ['op', 'REGISTER'],
    ['name', label],
    ['tld', 'vayu'],
    ['ownerKey', owner],
    ['seq', 0],
    ['notBefore', at],
    ['notAfter', at + TERM_SECONDS],
    ['records', [entry('txt', `v=vayuweb1;probe${salt}`)]],
    [
      'powProof',
      new Map<string | Uint8Array, CborValue>([
        ['alg', POW_ALGORITHM],
        ['nonce', nonce],
        ['bits', bits],
      ]),
    ],
    ['prevHash', new Uint8Array(32)],
  ]);
  map.set('sig', sign(secret, signingInput(map)));
  return encode(map);
}

function lengthOf(store: Store): number {
  let count = 0;
  while (store.entryAt(count) !== null) count += 1;
  return count;
}

/** A peer: its own store, its own session. */
function peer(): { store: Store; session: ReplicationSession; sink: ReplicationSink } {
  const store = Store.open(scratch(), NOW);
  const sink: ReplicationSink = {
    append: (bytes, now) => store.append(bytes, now),
    encodingAt: (index) => store.entryAt(index)?.bytes ?? null,
    length: () => lengthOf(store),
    treeRoot: () => new Uint8Array(32),
  };
  return { store, session: new ReplicationSession(sink), sink };
}

/** Every `name.tld` this store holds, with its owner — the comparable form of "registry state". */
function stateOf(store: Store): string[] {
  return store
    .list(NOW)
    .map((n) => {
      const held = store.lookup(n.name, n.tld);
      const owner = held
        ? Buffer.from(held.current.record.ownerKey).toString('hex').slice(0, 16)
        : '-';
      return `${n.name}.${n.tld}=${owner}`;
    })
    .sort();
}

/* -------------------------------------------------------------------------- */
/* Encoding                                                                    */
/* -------------------------------------------------------------------------- */

test('every message round-trips through deterministic CBOR', () => {
  const messages: Message[] = [
    { t: 'HELLO', v: PROTOCOL_VERSION, len: 7, root: new Uint8Array(32).fill(9) },
    { t: 'WANT', from: 3, count: 64 },
    { t: 'RECORDS', from: 3, recs: [Uint8Array.of(1, 2, 3), Uint8Array.of(4)] },
    {
      t: 'CHECKPOINT',
      len: 10_000,
      treeRoot: new Uint8Array(32).fill(1),
      indexRoot: new Uint8Array(32).fill(2),
      liveNames: 42,
    },
    { t: 'EQUIVOCATION', a: Uint8Array.of(1), b: Uint8Array.of(2) },
  ];
  for (const message of messages) {
    assert.deepEqual(decodeMessage(encodeMessage(message)), message, message.t);
  }
});

test('an oversized message is refused before it is decoded', () => {
  // Before, not after: a decoder is the first thing a hostile peer's bytes reach, and asking it
  // to chew through a megabyte to discover the message was too big is the denial of service the
  // limit exists to prevent.
  const huge = new Uint8Array(LIMITS.messageBytes + 1);
  assert.throws(
    () => decodeMessage(huge),
    (error: unknown) => error instanceof ReplicationError && error.code === 'TOO_LARGE',
  );
});

test('a message that is not canonical CBOR is refused', () => {
  // Same non-malleability rule records are held to: an encoding a peer can vary without changing
  // the content is an encoding two peers can disagree about while both being right.
  const canonical = encodeMessage({ t: 'WANT', from: 1, count: 2 });
  // Re-encode `from` in a longer-than-minimal form. Every byte after stays valid CBOR.
  const sloppy = Uint8Array.from([...canonical]);
  assert.throws(() => decodeMessage(Uint8Array.of(0xa2, ...sloppy.subarray(1))), ReplicationError);
});

test('an unknown message type is named as unknown, not guessed at', () => {
  const map: CborMap = new Map<string | Uint8Array, CborValue>([['t', 'GOSSIP']]);
  assert.throws(
    () => decodeMessage(encode(map)),
    (error: unknown) => error instanceof ReplicationError && error.code === 'UNKNOWN_TYPE',
  );
});

test('a batch larger than the limit is refused at decode', () => {
  const map: CborMap = new Map<string | Uint8Array, CborValue>([
    ['t', 'RECORDS'],
    ['from', 0],
    ['recs', Array.from({ length: LIMITS.recordsPerBatch + 1 }, () => Uint8Array.of(1))],
  ]);
  assert.throws(
    () => decodeMessage(encode(map)),
    (error: unknown) => error instanceof ReplicationError && error.code === 'LIMIT_EXCEEDED',
  );
});

/* -------------------------------------------------------------------------- */
/* REPLICATION.md 8.1 — order independence                                     */
/* -------------------------------------------------------------------------- */

test('8.1 the same record set produces the same state in every arrival order', () => {
  // The property the whole design rests on. State is a function of the SET of valid records, not
  // of which peer sent one or when. Exhaustive over the permutations of three records, because
  // three is small enough to be exhaustive and a sampled check on this property would be a
  // sampled check on whether the registry forks.
  const records = [
    registration({ label: 'atlasobservatory' }),
    registration({ label: 'bellwetherworks' }),
    registration({ label: 'cartographersguild' }),
  ];

  const permutations = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
  ];

  const states = permutations.map((order) => {
    const p = peer();
    const outcome = p.session.receive(
      { t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) },
      NOW,
    );
    assert.equal(outcome.applied, 0);
    p.session.receive({ t: 'RECORDS', from: 0, recs: order.map((i) => records[i]!) }, NOW);
    return stateOf(p.store).join('|');
  });

  for (const state of states) {
    assert.equal(state, states[0]!, 'arrival order must not change the resulting state');
  }
  assert.equal(states[0]!.split('|').length, 3, 'all three must have landed');
});

/* -------------------------------------------------------------------------- */
/* REPLICATION.md 8.2 — partition convergence                                  */
/* -------------------------------------------------------------------------- */

test('8.2 two peers fed disjoint sets converge once they exchange', () => {
  const left = peer();
  const right = peer();

  const onlyLeft = registration({ label: 'atlasobservatory' });
  const onlyRight = registration({ label: 'bellwetherworks' });

  // The partition: each peer learns one registration and neither hears the other.
  assert.equal(left.store.append(onlyLeft, NOW).outcome, 'accept');
  assert.equal(right.store.append(onlyRight, NOW).outcome, 'accept');
  assert.notEqual(stateOf(left.store).join('|'), stateOf(right.store).join('|'));

  // The heal. Both introduce themselves, both ask, both apply.
  const leftHello = left.session.open();
  const rightHello = right.session.open();
  left.session.receive(rightHello, NOW);
  right.session.receive(leftHello, NOW);

  const wantFromLeft = left.session.nextWant(0);
  const wantFromRight = right.session.nextWant(0);
  assert.ok(wantFromLeft && wantFromRight, 'each peer must want what the other announced');

  const toLeft = right.session.receive(wantFromLeft, NOW).replies;
  const toRight = left.session.receive(wantFromRight, NOW).replies;
  for (const reply of toLeft) left.session.receive(reply, NOW);
  for (const reply of toRight) right.session.receive(reply, NOW);

  assert.deepEqual(stateOf(left.store), stateOf(right.store), 'peers must converge');
  assert.equal(stateOf(left.store).length, 2);
});

test('I take any name I like, a year later, for two proofs of work', () => {
  // The attack that wiring convergence in creates if nothing bounds when a conflicting claim may
  // arrive. Nothing in the digest rule mentions time, so "first valid signature wins" would decay
  // into "lowest digest ever produced wins".
  //
  // I do not need to race anyone. I wait until a name I want is well established, then grind
  // registrations until one has a digest below the incumbent's. That costs about two attempts on
  // average, because the incumbent's digest is uniform over 256 bits and I only need to be under
  // it. Roughly half of every name in the registry is available to me for a couple of proofs of
  // work, and the owner sees their name change hands with no record of wrongdoing anywhere.
  //
  // That would destroy Article 11's non-revocability, which Article 9.7 entrenches, and Article
  // 30.1's whole allocation policy along with it.
  //
  // The window is MAX_BACKDATE_SECONDS, taken rather than invented: it is already the protocol's
  // answer to how far apart two records can be and still both be arrivable now. And deciding by
  // `notBefore` is not a delivery-order rule — it is in the record, identical on every peer.
  const incumbent = registration({ label: 'settledname', owner: OWNER_A, secret: SECRET_A });
  const store = Store.open(scratch(), NOW);
  assert.equal(store.append(incumbent, NOW).outcome, 'accept');
  const held = store.lookup('settledname', 'vayu');
  assert.ok(held);

  const muchLater = NOW + 365 * 86_400;
  let lower: Uint8Array | null = null;
  for (let attempt = 0; attempt < 64 && lower === null; attempt += 1) {
    const candidate = unsolvedRegistration('settledname', attempt, muchLater);
    if (compareBytes(recordHashFromBytes(candidate), held.rootHash) < 0) lower = candidate;
  }
  assert.ok(lower, 'a lower-digest claim must be constructible — that is the point');

  const verdict = store.append(lower, muchLater);
  assert.equal(verdict.outcome, 'reject');
  assert.equal(
    verdict.outcome === 'reject' && verdict.code,
    'NAME_TAKEN',
    'a claim made a year after the registration is not a partition, and must not displace it',
  );
  const after = store.lookup('settledname', 'vayu');
  assert.deepEqual(after?.current.record.ownerKey, OWNER_A, 'the name must not have moved');
});

test('an owner cannot rewrite their own registration by grinding a lower digest', () => {
  // Equivocation is not a race. One key signing two registrations for one name is that party
  // rewriting their own history, or a compromised key — not two strangers who each did the work.
  // Resolving it by digest would let an owner replace their own registration at will, and would
  // silently apply exactly the evidence Article 38 wants surfaced instead.
  const first = registration({ label: 'ownedtwice', owner: OWNER_A, secret: SECRET_A });
  const store = Store.open(scratch(), NOW);
  assert.equal(store.append(first, NOW).outcome, 'accept');
  const held = store.lookup('ownedtwice', 'vayu');
  assert.ok(held);

  let lower: Uint8Array | null = null;
  for (let attempt = 0; attempt < 64 && lower === null; attempt += 1) {
    const candidate = unsolvedRegistration('ownedtwice', attempt, NOW, OWNER_A, SECRET_A);
    if (compareBytes(recordHashFromBytes(candidate), held.rootHash) < 0) lower = candidate;
  }
  assert.ok(lower, 'a lower-digest self-claim must be constructible');

  const verdict = store.append(lower, NOW);
  assert.equal(verdict.outcome, 'reject');
  assert.equal(
    verdict.outcome === 'reject' && verdict.code,
    'NAME_TAKEN',
    'the incumbent stands: this is equivocation to be reported, not a race to be resolved',
  );
});

test('a hopeless claim on a held name is refused before any proof of work is verified', () => {
  // The economics of the conflict path, tested directly rather than inferred.
  //
  // Judging a conflict properly means asking whether the newcomer would have been accepted had it
  // arrived first, which means verifying its signature and its Argon2id proof at 64 MiB. If a peer
  // did that for every registration aimed at a name it already holds, spamming claims on popular
  // names would be a cheap way to burn everyone's memory bandwidth — the attacker sends bytes,
  // the network does the hashing.
  //
  // So the digest is compared first. Under the convergence rule a newcomer with the larger digest
  // cannot win, so there is nothing to learn from verifying it. An attacker must grind their
  // digest below the incumbent's before a peer will spend anything, and each attempt costs them a
  // full proof of work.
  //
  // The assertion is on the rejection CODE, which is what makes this test able to fail. This
  // record carries a deliberately broken proof of work, so a peer that reached the expensive path
  // would say BAD_POW. Saying NAME_TAKEN is only possible if it never got there.
  const incumbent = registration({ label: 'contestedname', owner: OWNER_A, secret: SECRET_A });
  const store = Store.open(scratch(), NOW);
  assert.equal(store.append(incumbent, NOW).outcome, 'accept');

  const held = store.lookup('contestedname', 'vayu');
  assert.ok(held);
  const incumbentHash = held.rootHash;

  // Search for a claim whose digest is larger than the incumbent's, with an unsolved nonce.
  let hopeless: Uint8Array | null = null;
  for (let attempt = 0; attempt < 64 && hopeless === null; attempt += 1) {
    const candidate = unsolvedRegistration('contestedname', attempt);
    if (compareBytes(recordHashFromBytes(candidate), incumbentHash) > 0) hopeless = candidate;
  }
  assert.ok(hopeless, 'a larger-digest claim must be constructible');

  const verdict = store.append(hopeless, NOW);
  assert.equal(verdict.outcome, 'reject');
  assert.equal(
    verdict.outcome === 'reject' && verdict.code,
    'NAME_TAKEN',
    'a claim that cannot win must cost a map lookup, not an Argon2id verification',
  );
});

test('a winning claim IS verified properly, so the cheap path is not a way in', () => {
  // The other half. The digest gate must not become a way to be accepted without a valid proof:
  // a claim with a *smaller* digest and a broken proof must be rejected on the proof, having
  // actually been checked.
  const incumbent = registration({ label: 'racedname', owner: OWNER_A, secret: SECRET_A });
  const store = Store.open(scratch(), NOW);
  assert.equal(store.append(incumbent, NOW).outcome, 'accept');
  const held = store.lookup('racedname', 'vayu');
  assert.ok(held);

  let promising: Uint8Array | null = null;
  for (let attempt = 0; attempt < 64 && promising === null; attempt += 1) {
    const candidate = unsolvedRegistration('racedname', attempt);
    if (compareBytes(recordHashFromBytes(candidate), held.rootHash) < 0) promising = candidate;
  }
  assert.ok(promising, 'a smaller-digest claim must be constructible');

  const verdict = store.append(promising, NOW);
  assert.equal(verdict.outcome, 'reject');
  assert.notEqual(
    verdict.outcome === 'reject' && verdict.code,
    'NAME_TAKEN',
    'a claim that could win must be judged on its merits, not waved through or waved off',
  );
});

test('8.2 a race between strangers resolves the same way on both sides of the partition', () => {
  // Two different owners, same free name, one each side. Both records are valid and neither party
  // did anything wrong. The peers must award it to the same key without asking anyone — and
  // crucially, must do so whichever order each of them happens to see the pair in.
  const byA = registration({ label: 'contestedname', owner: OWNER_A, secret: SECRET_A });
  const byB = registration({
    label: 'contestedname',
    owner: OWNER_B,
    secret: SECRET_B,
    txt: 'v=vayuweb1;b',
  });
  assert.notDeepEqual(recordHashFromBytes(byA), recordHashFromBytes(byB), 'must be distinct');

  const left = peer();
  const right = peer();
  const hello = { t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) } as const;
  left.session.receive(hello, NOW);
  right.session.receive(hello, NOW);

  // Opposite delivery orders — the exact thing a relay chooses for free.
  left.session.receive({ t: 'RECORDS', from: 0, recs: [byA, byB] }, NOW);
  right.session.receive({ t: 'RECORDS', from: 0, recs: [byB, byA] }, NOW);

  assert.deepEqual(
    stateOf(left.store),
    stateOf(right.store),
    'a relay choosing delivery order must not choose who owns the name',
  );
});

/* -------------------------------------------------------------------------- */
/* REPLICATION.md 8.3 — nothing is trusted on receipt                          */
/* -------------------------------------------------------------------------- */

test('8.3 records that fail local verification change no state', () => {
  const p = peer();
  p.session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 9, root: new Uint8Array(32) }, NOW);

  const valid = registration({ label: 'atlasobservatory' });
  const tampered = Uint8Array.from(valid);
  tampered[tampered.length - 1] ^= 0xff; // breaks the signature

  const outcome = p.session.receive(
    { t: 'RECORDS', from: 0, recs: [tampered, Uint8Array.of(0xff, 0xff), valid] },
    NOW,
  );

  assert.equal(outcome.applied, 1, 'only the valid record lands');
  assert.equal(outcome.rejected, 2);
  assert.equal(stateOf(p.store).length, 1);
});

test('8.3 one malformed record does not discard the rest of its batch', () => {
  // An attacker's cheapest denial of service: put one bad record at the front of a batch of two
  // hundred and watch the other hundred and ninety-nine vanish.
  const p = peer();
  p.session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);

  const outcome = p.session.receive(
    {
      t: 'RECORDS',
      from: 0,
      recs: [
        Uint8Array.of(0x00),
        registration({ label: 'atlasobservatory' }),
        new Uint8Array(LIMITS.recordBytes + 1),
        registration({ label: 'bellwetherworks' }),
      ],
    },
    NOW,
  );

  assert.equal(outcome.applied, 2, 'both valid records survive the malformed ones around them');
  assert.equal(outcome.rejected, 2);
});

test('8.3 a record already held is dropped silently, not counted as a conflict', () => {
  const p = peer();
  p.session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);
  const record = registration({ label: 'atlasobservatory' });

  const first = p.session.receive({ t: 'RECORDS', from: 0, recs: [record] }, NOW);
  const second = p.session.receive({ t: 'RECORDS', from: 0, recs: [record] }, NOW);

  assert.equal(first.applied, 1);
  assert.equal(second.applied, 0, 'a duplicate applies nothing');
  assert.equal(second.duplicates, 1, 'and is reported as what it is');
  assert.equal(second.rejected, 0, 'a duplicate is not an error either');
  assert.equal(stateOf(p.store).length, 1, 'and changes nothing');
});

/* -------------------------------------------------------------------------- */
/* REPLICATION.md 8.4 — limits                                                 */
/* -------------------------------------------------------------------------- */

test('8.4 an enormous claimed length costs one bounded request, not an allocation', () => {
  // HELLO.len is a claim, not a measurement. A peer announcing 2^53 records must cost us the
  // message and nothing else — in particular no array sized to what they said.
  const p = peer();
  p.session.receive(
    { t: 'HELLO', v: PROTOCOL_VERSION, len: Number.MAX_SAFE_INTEGER, root: new Uint8Array(32) },
    NOW,
  );
  assert.equal(p.session.remoteClaimedLength, Number.MAX_SAFE_INTEGER);

  const want = p.session.nextWant(0);
  assert.ok(want);
  assert.equal(want.count, LIMITS.wantCount, 'we ask for a bounded window, not what they claimed');
});

test('8.4 outstanding requests are capped', () => {
  const p = peer();
  p.session.receive(
    { t: 'HELLO', v: PROTOCOL_VERSION, len: 1_000_000, root: new Uint8Array(32) },
    NOW,
  );

  let issued = 0;
  for (let i = 0; i < LIMITS.outstandingWants + 5; i += 1) {
    if (p.session.nextWant(i * LIMITS.wantCount) !== null) issued += 1;
  }
  assert.equal(issued, LIMITS.outstandingWants, 'no more than the cap may be in flight');
});

test('8.4 a WANT beyond the count limit is declined rather than served', () => {
  const p = peer();
  p.store.append(registration({ label: 'atlasobservatory' }), NOW);
  p.session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);

  const overLimit = p.session.receive({ t: 'WANT', from: 0, count: LIMITS.wantCount + 1 }, NOW);
  assert.equal(overLimit.replies.length, 0);

  const withinLimit = p.session.receive({ t: 'WANT', from: 0, count: 8 }, NOW);
  assert.equal(withinLimit.replies.length, 1, 'a lawful request is still served');
});

test('8.4 nothing is accepted before the remote has introduced itself', () => {
  const p = peer();
  const outcome = p.session.receive(
    { t: 'RECORDS', from: 0, recs: [registration({ label: 'atlasobservatory' })] },
    NOW,
  );
  assert.equal(outcome.applied, 0, 'records before HELLO are ignored');
  assert.equal(stateOf(p.store).length, 0);
  assert.equal(p.session.nextWant(0), null, 'and there is nothing to want yet');
});

test('8.4 a second HELLO is ignored, so a peer cannot rewind mid-session', () => {
  const p = peer();
  p.session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 100, root: new Uint8Array(32) }, NOW);
  p.session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 5, root: new Uint8Array(32) }, NOW);
  assert.equal(p.session.remoteClaimedLength, 100, 'the restated length must not take effect');
});

test('8.4 a peer speaking another protocol version is not engaged with', () => {
  const p = peer();
  p.session.receive(
    { t: 'HELLO', v: PROTOCOL_VERSION + 1, len: 10, root: new Uint8Array(32) },
    NOW,
  );
  assert.equal(p.session.ready, false);
  assert.equal(p.session.nextWant(0), null);
});

test('8.4 deferred records are bounded, oldest evicted first', () => {
  // Clock-skewed records are memory an attacker allocates by dating records into the near future.
  // Each costs them a proof-of-work; the bound is what makes refusing them cost us nothing.
  const held: Array<{ bytes: Uint8Array }> = [];
  const sink: ReplicationSink = {
    append: () => ({ outcome: 'defer', reason: 'CLOCK_SKEW', detail: 'test' }) as const,
    encodingAt: () => null,
    length: () => 0,
    treeRoot: () => new Uint8Array(32),
  };
  const session = new ReplicationSession(sink);
  session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);

  for (let batch = 0; batch < 8; batch += 1) {
    const recs = Array.from({ length: LIMITS.recordsPerBatch }, (_, i) =>
      Uint8Array.of(batch, i & 0xff),
    );
    session.receive({ t: 'RECORDS', from: 0, recs }, NOW);
  }
  held.length = 0;
  assert.equal(session.deferredCount, LIMITS.deferred, 'the queue must not grow past its bound');
});

/* -------------------------------------------------------------------------- */
/* REPLICATION.md 8.5 — equivocation                                           */
/* -------------------------------------------------------------------------- */

test('8.5 equivocation is verifiable from the two encodings alone', () => {
  // The property that makes the message worth forwarding: a third party checks it without
  // trusting the sender, without prior state, and without having been online at the time.
  const one = registration({ label: 'atlasobservatory', txt: 'v=vayuweb1;one' });
  const two = registration({ label: 'atlasobservatory', txt: 'v=vayuweb1;two' });
  assert.ok(verifyEquivocation({ t: 'EQUIVOCATION', a: one, b: two }));
});

test('8.5 two different owners racing for a free name is not equivocation', () => {
  const byA = registration({ label: 'contestedname', owner: OWNER_A, secret: SECRET_A });
  const byB = registration({
    label: 'contestedname',
    owner: OWNER_B,
    secret: SECRET_B,
    txt: 'v=vayuweb1;b',
  });
  assert.equal(verifyEquivocation({ t: 'EQUIVOCATION', a: byA, b: byB }), false);
});

test('8.5 a report that does not in fact equivocate is discarded, not recorded', () => {
  // A report taken on trust is a way to get any name reported as compromised by anyone who can
  // send a message.
  const p = peer();
  p.session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);

  const same = registration({ label: 'atlasobservatory' });
  const bogus = p.session.receive({ t: 'EQUIVOCATION', a: same, b: same }, NOW);
  assert.equal(bogus.equivocations.length, 0, 'a duplicate is not two futures');
  assert.equal(bogus.rejected, 1);

  const garbage = p.session.receive(
    { t: 'EQUIVOCATION', a: Uint8Array.of(1), b: Uint8Array.of(2) },
    NOW,
  );
  assert.equal(garbage.equivocations.length, 0);
});

test('8.5 genuine evidence is surfaced for the caller to record', () => {
  const p = peer();
  p.session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);
  const one = registration({ label: 'atlasobservatory', txt: 'v=vayuweb1;one' });
  const two = registration({ label: 'atlasobservatory', txt: 'v=vayuweb1;two' });

  const outcome = p.session.receive({ t: 'EQUIVOCATION', a: one, b: two }, NOW);
  assert.equal(outcome.equivocations.length, 1);
  // Detection produces a legible record and nothing else. No penalty, no exclusion, no loss of
  // the name: a mechanism able to strip a name on evidence is a mechanism able to strip a name on
  // manufactured evidence.
  assert.equal(outcome.applied, 0);
  assert.equal(stateOf(p.store).length, 0);
});

/* -------------------------------------------------------------------------- */
/* Serving                                                                     */
/* -------------------------------------------------------------------------- */

test('serving is voluntary: an unservable range is silence, not an error', () => {
  // REPLICATION.md 4.3. No peer owes another bandwidth, and reporting a decline as a failure
  // would create a duty that can be failed and therefore enforced.
  const p = peer();
  p.session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);
  const outcome = p.session.receive({ t: 'WANT', from: 500, count: 10 }, NOW);
  assert.deepEqual(outcome.replies, []);
  assert.equal(outcome.rejected, 0, 'declining is not a rejection');
});

test('a WANT is served with what is held, truncated rather than padded', () => {
  const p = peer();
  p.store.append(registration({ label: 'atlasobservatory' }), NOW);
  p.store.append(registration({ label: 'bellwetherworks' }), NOW);
  p.session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);

  const outcome = p.session.receive({ t: 'WANT', from: 0, count: 50 }, NOW);
  assert.equal(outcome.replies.length, 1);
  const reply = outcome.replies[0]!;
  assert.equal(reply.t, 'RECORDS');
  assert.equal(reply.t === 'RECORDS' && reply.recs.length, 2);
});

test('a CHECKPOINT changes no local state', () => {
  // A checkpoint is evidence for a light client to weigh, not an instruction. Accepting one here
  // would make a remote assertion part of our state.
  const p = peer();
  p.session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);
  const outcome = p.session.receive(
    {
      t: 'CHECKPOINT',
      len: 10_000,
      treeRoot: new Uint8Array(32).fill(1),
      indexRoot: new Uint8Array(32).fill(2),
      liveNames: 99,
    },
    NOW,
  );
  assert.equal(outcome.applied, 0);
  assert.equal(stateOf(p.store).length, 0);
});

test('HELLO may only be sent once', () => {
  const p = peer();
  p.session.open();
  assert.throws(
    () => p.session.open(),
    (error: unknown) => error instanceof ReplicationError && error.code === 'HELLO_REPEATED',
  );
});
