import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
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
  type Records,
  type ReplicationSink,
} from './replicate.ts';
import { Store } from './store.ts';
import { encode, compareBytes, type CborMap, type CborValue } from './cbor.ts';
import { signingInput, recordHashFromBytes } from './domain.ts';
import { sign, publicKeyFrom } from './signature.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH, solvePow, requiredBits } from './pow.ts';
import { TERM_SECONDS, type Verdict } from './verify.ts';

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
      ['suite', 1],
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
    ['suite', 1],
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

/**
 * A TRANSFER of `LABEL` from OWNER_A to OWNER_B, signed by the transferor and countersigned by
 * the recipient — the one operation whose `sig` is not the key it names as owner.
 *
 * No proof of work is searched for: TRANSFER carries `powProof` null, and nothing on this path
 * evaluates one in any case.
 */
function handover(build: { at: number; coSecret?: Uint8Array }): Uint8Array {
  const map: CborMap = new Map<string | Uint8Array, CborValue>([
    ['version', 1],
    ['suite', 1],
    ['op', 'TRANSFER'],
    ['name', LABEL],
    ['tld', 'vayu'],
    ['ownerKey', OWNER_B],
    ['seq', 1],
    ['notBefore', build.at],
    ['notAfter', NOW + TERM_SECONDS],
    ['records', []],
    ['powProof', null],
    ['prevHash', recordHashFromBytes(registration())],
  ]);
  const input = signingInput(map);
  map.set('sig', sign(SECRET_A, input));
  map.set('coSig', sign(build.coSecret ?? SECRET_B, input));
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

  const wantFromLeft = left.session.nextWant(0, NOW);
  const wantFromRight = right.session.nextWant(0, NOW);
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

  const want = p.session.nextWant(0, NOW);
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
    if (p.session.nextWant(i * LIMITS.wantCount, NOW) !== null) issued += 1;
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
  assert.equal(p.session.nextWant(0, NOW), null, 'and there is nothing to want yet');
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
  assert.equal(p.session.nextWant(0, NOW), null);
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

test('8.5 evidence nobody signed is a forgery, not a report', () => {
  // The attack, in full: an owner key is public — it is in every record its holder ever
  // published. Take a victim's, mint two records naming it as `ownerKey` for one name at one
  // `seq`, sign both with a key of your own, and send the pair as EQUIVOCATION. Nothing in the
  // pair is the victim's but the twelve bytes of their public key.
  //
  // Section 6.2 says what a recipient checks: "both signatures, both `seq` values, both names
  // and that the owner keys are equal". Signatures are first on that list, and 6.4 names the
  // exact consequence of dropping them — "a mechanism able to strip a name on evidence is a
  // mechanism able to strip a name on *manufactured* evidence". A report that is recorded and
  // forwarded on nothing but a public key is a way to publish, at any peer, that any name you
  // choose is compromised.
  //
  // This is narrower than the validity check `verifyEquivocation` is right to refuse. Expiry,
  // proof of work and chain position are all reasons a record would not be ACCEPTED, and
  // requiring them would let an equivocator escape the record by making both halves invalid in
  // some unrelated way. A signature is different in kind: it is the only thing that makes a
  // record ATTRIBUTABLE, and equivocation is a claim about who signed.
  const forgedOne = unsolvedRegistration('victimname', 1, NOW, OWNER_A, SECRET_B);
  const forgedTwo = unsolvedRegistration('victimname', 2, NOW, OWNER_A, SECRET_B);

  assert.equal(
    verifyEquivocation({ t: 'EQUIVOCATION', a: forgedOne, b: forgedTwo }),
    false,
    'two records the named owner never signed do not in fact equivocate',
  );

  const p = peer();
  p.session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);
  const outcome = p.session.receive({ t: 'EQUIVOCATION', a: forgedOne, b: forgedTwo }, NOW);
  assert.equal(outcome.equivocations.length, 0, 'a forged report must not be recorded');
  assert.equal(outcome.rejected, 1, 'and must be counted as refused, not silently dropped');
});

test('8.5 one genuine half and one forged half is still a forgery', () => {
  // The halfway case, because it is the one an implementation checking "a signature" rather than
  // "both signatures" would pass: the attacker takes a real published record of the victim's and
  // pairs it with one they minted themselves. The victim signed one future for that name, which
  // is what every honest owner does.
  const genuine = registration({ label: 'atlasobservatory', txt: 'v=vayuweb1;real' });
  const minted = unsolvedRegistration('atlasobservatory', 9, NOW, OWNER_A, SECRET_B);

  assert.equal(verifyEquivocation({ t: 'EQUIVOCATION', a: genuine, b: minted }), false);
  assert.equal(verifyEquivocation({ t: 'EQUIVOCATION', a: minted, b: genuine }), false);
});

test('8.5 a TRANSFER is attributed by its countersignature, not by its signature', () => {
  // TRANSFER is the one operation whose `sig` is not the named owner's — it is the transferor's,
  // and the transferor's key is nowhere in these bytes. The named owner's own signature is
  // `coSig`. A check that reads `sig` for every operation would therefore refuse every report
  // involving a transfer, which is a silent hole in exactly the window Article 33.4 leaves a
  // name in flux.
  const first = handover({ at: NOW + 60 });
  const second = handover({ at: NOW + 120 });
  assert.ok(
    verifyEquivocation({ t: 'EQUIVOCATION', a: first, b: second }),
    'two transfers of one name at one seq, both countersigned by the named owner',
  );

  // And the forgery still fails on the same operation: a coSig by anyone but the named owner is
  // not that owner's signature, whatever the transferor did.
  const forged = handover({ at: NOW + 180, coSecret: SECRET_A });
  assert.equal(verifyEquivocation({ t: 'EQUIVOCATION', a: first, b: forged }), false);
});

test('8.5 an otherwise-invalid record still equivocates if its owner signed it', () => {
  // The other side of the line, and the reason the fix is a signature check rather than a
  // validity check. Both of these carry an unsolved proof of work, so neither would be accepted
  // by any verifier — and both are genuinely signed by the key they name. An equivocator who
  // could escape the record by breaking their own proof of work would have a one-line evasion.
  const one = unsolvedRegistration('atlasobservatory', 21, NOW, OWNER_A, SECRET_A);
  const two = unsolvedRegistration('atlasobservatory', 22, NOW, OWNER_A, SECRET_A);
  assert.ok(verifyEquivocation({ t: 'EQUIVOCATION', a: one, b: two }));
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

/* -------------------------------------------------------------------------- */
/* A reply this peer cannot send                                               */
/* -------------------------------------------------------------------------- */

test('AUDIT: an honest reply to the commonest WANT can actually be encoded', () => {
  // **This kills the first WANT of every cold sync on any real registry.**
  //
  // `nextWant` asks for `LIMITS.wantCount` — 256 — whenever a peer is that far behind, which is
  // every peer starting from nothing. `onWant` then gathers up to 256 encodings with no size
  // accounting at all and hands them back as a `RECORDS`. `encodeMessage` refuses it, because 256
  // records do not fit in the 65,536-byte message bound: only **15** maximum-size records fit, and
  // even 256 records at 258 bytes — the smallest encoding in this project's own conformance
  // vectors — is 66,048 bytes and over the limit.
  //
  // The throw is then swallowed by `send` in swarm.ts, whose catch destroys the stream under the
  // comment "A write that fails is a connection that is gone". It was not gone. Our own encoder
  // refused our own message, and the connection was dropped with the failure attributed to the
  // peer — a silent stall that looks like the network.
  //
  // Nothing caught it because every existing test syncs a handful of records, where 256 never
  // arises and the sizes fit. So this builds a sink big enough for the bug rather than big enough
  // for the test.
  const encodings: Uint8Array[] = [];
  for (let i = 0; i < LIMITS.wantCount; i += 1) {
    // 300 bytes is COST.md's own per-record figure, so this is an ordinary log rather than an
    // adversarial one. The defect does not need maximal records.
    encodings.push(new Uint8Array(300).fill(i & 0xff));
  }
  const sink: ReplicationSink = {
    append: () => {
      throw new Error('this test never appends; it only asks what we would send');
    },
    encodingAt: (index) => encodings[index] ?? null,
    length: () => encodings.length,
    treeRoot: () => new Uint8Array(32),
  };
  const session = new ReplicationSession(sink);
  session.open();
  session.receive(
    { t: 'HELLO', v: PROTOCOL_VERSION, len: encodings.length, root: new Uint8Array(32) },
    NOW,
  );

  // Exactly what a peer starting from nothing sends.
  const want = session.nextWant(0, NOW);
  assert.ok(want, 'a peer behind by a full batch must ask for one');
  assert.equal(want.count, LIMITS.wantCount);

  const outcome = session.receive(want, NOW);
  assert.equal(outcome.replies.length, 1, 'a peer holding the records must answer');

  // The assertion that matters: what we decided to send, we can send.
  assert.doesNotThrow(
    () => encodeMessage(outcome.replies[0]!),
    'onWant produced a RECORDS this peer cannot encode',
  );
});

test('AUDIT: the reply bound is a byte count, and the specification says so', () => {
  // Two halves that must not drift apart. The behavioural half above proves this peer can send
  // what it decided to send; this one proves the document requires it, and that the limits table
  // no longer carries the justification that was false by more than 16x.
  const spec = readFileSync(new URL('../../docs/spec/REPLICATION.md', import.meta.url), 'utf8');
  assert.match(spec, /MUST\*\* truncate a `RECORDS` reply to fit the message bound/);
  assert.match(spec, /counting bytes rather than records/);
  assert.doesNotMatch(spec, /Holds a full `RECORDS` batch/);
  // And the inverted promise is gone: a reply IS split for a reason the requester cannot predict.
  assert.doesNotMatch(spec, /an honest reply is never split/);

  // A short reply must not be readable as "there is no more". The requester keeps asking, which
  // is what makes truncation safe rather than a silent truncation of the sync itself.
  assert.match(spec, /MUST NOT infer that the responder holds no more/);
});

test('a truncated reply still makes progress, and the next want resumes where it stopped', () => {
  // Truncation is only safe if the requester comes back for the rest. A responder that returns
  // fewer records than asked, and a requester that treats that as the end of the log, is a sync
  // that silently stops at whatever fits in one message — which would be a worse bug than the one
  // being fixed, and is exactly the shape a careless fix takes.
  const encodings: Uint8Array[] = [];
  for (let i = 0; i < LIMITS.wantCount; i += 1) encodings.push(new Uint8Array(300).fill(i & 0xff));
  const sink: ReplicationSink = {
    append: () => {
      throw new Error('this test never appends');
    },
    encodingAt: (index) => encodings[index] ?? null,
    length: () => encodings.length,
    treeRoot: () => new Uint8Array(32),
  };
  const session = new ReplicationSession(sink);
  session.open();
  session.receive(
    { t: 'HELLO', v: PROTOCOL_VERSION, len: encodings.length, root: new Uint8Array(32) },
    NOW,
  );

  const first = session.receive(session.nextWant(0, NOW)!, NOW).replies[0] as Records;
  assert.ok(first.recs.length > 0 && first.recs.length < LIMITS.wantCount, 'the reply is short');
  assert.doesNotThrow(() => encodeMessage(first));

  // The requester asks again from where it got to, and the rest arrives. Walk it to the end so a
  // fix that made progress but never terminated would fail here rather than pass.
  let have = first.recs.length;
  for (let round = 0; round < 32 && have < encodings.length; round += 1) {
    const want = session.nextWant(have, NOW);
    assert.ok(want, `a peer at ${have} of ${encodings.length} must still ask`);
    const reply = session.receive(want, NOW).replies[0] as Records;
    assert.equal(reply.from, have, 'the reply resumes where the requester stopped');
    assert.ok(reply.recs.length > 0, 'a responder holding records must not answer with none');
    assert.doesNotThrow(() => encodeMessage(reply));
    have += reply.recs.length;
  }
  assert.equal(have, encodings.length, 'the whole log is reachable in bounded rounds');
});

test('AUDIT: a reply encodes at every record size, not just the one a test happened to pick', () => {
  // **The margin in `onWant`'s budget survived its first mutation, which means the first test was
  // inadequate rather than the fix unnecessary.** Removing `RECORDS_ENVELOPE_BYTES` changed
  // nothing, because 300-byte records stop the greedy loop well short of the boundary and the
  // envelope never mattered. Ninety-one record sizes between 200 and 4,096 bytes DO land in that
  // band, and at each of them a budget without the margin fills to the byte limit and then the
  // message header pushes the encoding over it.
  //
  // A single size is a sample. The bug is a boundary, so the test has to sweep.
  const failures: string[] = [];
  for (let size = 200; size <= 1200; size += 1) {
    const encodings: Uint8Array[] = [];
    for (let i = 0; i < LIMITS.wantCount; i += 1)
      encodings.push(new Uint8Array(size).fill(i & 0xff));
    const sink: ReplicationSink = {
      append: () => {
        throw new Error('this test never appends');
      },
      encodingAt: (index) => encodings[index] ?? null,
      length: () => encodings.length,
      treeRoot: () => new Uint8Array(32),
    };
    const session = new ReplicationSession(sink);
    session.open();
    session.receive(
      { t: 'HELLO', v: PROTOCOL_VERSION, len: encodings.length, root: new Uint8Array(32) },
      NOW,
    );
    const reply = session.receive(session.nextWant(0, NOW)!, NOW).replies[0];
    if (reply === undefined) {
      failures.push(`size ${size}: a peer holding records answered with none`);
      continue;
    }
    try {
      const bytes = encodeMessage(reply);
      if (bytes.length > LIMITS.messageBytes) {
        failures.push(`size ${size}: encoded to ${bytes.length}`);
      }
    } catch (error) {
      failures.push(`size ${size}: ${String(error)}`);
    }
  }
  assert.deepEqual(failures.slice(0, 5), []);
});

test('AUDIT: a peer that greets and then declines everything does not freeze the sync forever', () => {
  // **The same hole VWIP-0005 4.5.a closes for block exchange, still open in the older protocol
  // that actually ships.** Three clauses combine and each is individually right:
  //
  //   5. eight outstanding WANTs per connection, so memory is bounded;
  //   4.3 "It MAY reply with fewer records than requested, and MAY decline entirely.
  //       **Declining is not an error condition**" -- serving is voluntary, deliberately;
  //   and nothing anywhere requires a requester to give up on a WANT it sent.
  //
  // `this.outstanding` is decremented in exactly one place: `onRecords`. A peer that greets and
  // then answers nothing takes all eight slots and never returns them, so `nextWant` returns null
  // for the rest of the connection's life while breaking no rule at all. The absence of a duty on
  // one side has to be paid for by a bound on the other, and it was not.
  //
  // Cheap to cause, invisible when caused: from the outside it is a peer that connects and then
  // sits there, which is exactly what a slow honest peer looks like.
  const sink: ReplicationSink = {
    append: () => {
      throw new Error('this test never appends');
    },
    encodingAt: () => null,
    length: () => 0,
    treeRoot: () => new Uint8Array(32),
  };
  const session = new ReplicationSession(sink);
  session.open();
  session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 100_000, root: new Uint8Array(32) }, NOW);

  // Fill every slot. The peer declines each one, which 4.3 permits and which produces no message.
  for (let i = 0; i < LIMITS.outstandingWants; i += 1) {
    assert.ok(session.nextWant(0, NOW), `slot ${i} must be available`);
  }
  assert.equal(session.nextWant(0, NOW), null, 'the budget is exhausted, which is correct');

  // A year later, still asking for a log of a hundred thousand records it has none of.
  const later = NOW + 365 * 86_400;
  assert.ok(
    session.nextWant(0, later),
    'a requester must release a slot the remote was never obliged to answer',
  );
});

test('a slot is released by a reply as well as by the deadline, and is not released twice', () => {
  // The deadline must not become the only path, or an honest fast peer pays a timeout for every
  // batch. And releasing on both paths is where a naive fix double-counts: a reply that arrives
  // just after its own deadline would return two slots for one request, and the budget quietly
  // stops being a budget.
  const encodings = [new Uint8Array(300)];
  const sink: ReplicationSink = {
    append: (): Verdict => ({
      outcome: 'reject',
      code: 'NOT_A_MAP',
      detail: 'this test never supplies a real record',
    }),
    encodingAt: (i) => encodings[i] ?? null,
    length: () => encodings.length,
    treeRoot: () => new Uint8Array(32),
  };
  const session = new ReplicationSession(sink);
  session.open();
  session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 10, root: new Uint8Array(32) }, NOW);

  const want = session.nextWant(0, NOW);
  assert.ok(want);
  // The reply arrives promptly: the slot comes back without any deadline being involved.
  session.receive({ t: 'RECORDS', from: 0, recs: [new Uint8Array(10)] }, NOW);

  // Now exhaust the budget and confirm it is still exactly the stated size — not one larger
  // because the reply and a later expiry both released the same request.
  let issued = 0;
  while (session.nextWant(0, NOW) !== null) {
    issued += 1;
    assert.ok(issued <= LIMITS.outstandingWants, 'the budget must not exceed its stated size');
  }
  assert.equal(issued, LIMITS.outstandingWants);
});

test('the WANT deadline is required by the specification, not only by this implementation', () => {
  const spec = readFileSync(new URL('../../docs/spec/REPLICATION.md', import.meta.url), 'utf8');
  assert.match(spec, /MUST bound how long a `WANT` stays outstanding/);
  assert.match(spec, /whether or not a reply ever arrives/);
  // And the reason the oldest slot is the one released, which is what keeps the budget a budget.
  assert.match(spec, /releases the \*\*oldest\*\* outstanding slot/);
});

test('AUDIT: a late reply may overshoot the budget by one, and never by more', () => {
  // Found by a mutation that SURVIVED. Swapping `shift` for `pop` in the reply path changed
  // nothing, which the project's rule says means the test was inadequate — and chasing it showed
  // the comment beside that line was the inadequate thing: it claimed releasing the oldest slot
  // "cannot release the same slot twice". It can, and so can any other choice.
  //
  // No message carries a request identifier, so a reply cannot be matched to its own WANT. If a
  // deadline elapses and the reply then arrives, the deadline has already reclaimed one slot and
  // the reply reclaims a second, for one completed request. Measured: nine issuable against a
  // budget of eight.
  //
  // It is bounded rather than closed, and this pins the bound. Each overshoot costs the peer one
  // late message, so N late replies permit at most N extra — never an unbounded drift, which is
  // the failure that would matter.
  const sink: ReplicationSink = {
    append: () => {
      throw new Error('this test never appends');
    },
    encodingAt: () => null,
    length: () => 0,
    treeRoot: () => new Uint8Array(32),
  };
  const session = new ReplicationSession(sink);
  session.open();
  session.receive(
    { t: 'HELLO', v: PROTOCOL_VERSION, len: 1_000_000, root: new Uint8Array(32) },
    NOW,
  );

  let issued = 0;
  while (session.nextWant(0, NOW) !== null) issued += 1;
  assert.equal(issued, LIMITS.outstandingWants);

  // Every deadline elapses, then three late replies arrive for requests already reclaimed.
  const late = NOW + LIMITS.wantDeadlineSeconds + 1;
  const lateReplies = 3;
  let extra = 0;
  while (session.nextWant(0, late) !== null) extra += 1;
  assert.equal(extra, LIMITS.outstandingWants, 'expiry returns the whole budget and no more');

  for (let i = 0; i < lateReplies; i += 1) {
    session.receive({ t: 'RECORDS', from: 0, recs: [] }, late);
  }
  let afterLate = 0;
  while (session.nextWant(0, late) !== null) afterLate += 1;
  assert.equal(afterLate, lateReplies, 'the overshoot is exactly one slot per late reply');

  // And it does not accumulate: with no further late replies the budget is the stated size again.
  const later = late + LIMITS.wantDeadlineSeconds + 1;
  let settled = 0;
  while (session.nextWant(0, later) !== null) settled += 1;
  assert.equal(settled, LIMITS.outstandingWants, 'the window closes when the late replies stop');
});

test('AUDIT: one postdated record resent cannot evict every other deferred record', () => {
  // The deferral queue holds records that arrived slightly ahead of this peer's clock, so they get
  // a second chance instead of being lost to skew. Its bound counts **held encodings, not distinct
  // records**, and `holdDeferred` pushes unconditionally — nothing dedupes.
  //
  // So one postdated record, resent 1,024 times, fills the entire queue with copies of itself and
  // evicts every genuine deferred record from the front. The cost to the attacker is one record it
  // already has, sent repeatedly; the cost to the peer is the whole skew-tolerance mechanism, for
  // everybody. 4.6's silent-drop rule does not help: it covers records the peer "already holds",
  // and a deferred record is precisely one that has not been held.
  //
  // The bound was doing what it said — bounding memory — while the thing it was protecting was
  // capacity, and capacity is only bounded if the entries are distinct.
  const deferrals = new Set<string>();
  const sink: ReplicationSink = {
    append: (bytes): Verdict =>
      deferrals.has(bytes.join(','))
        ? { outcome: 'accept', record: null as never, duplicate: true }
        : { outcome: 'defer', reason: 'CLOCK_SKEW', detail: 'ahead of this clock' },
    encodingAt: () => null,
    length: () => 0,
    treeRoot: () => new Uint8Array(32),
  };
  const session = new ReplicationSession(sink);
  session.open();
  session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);

  // One genuine deferral from an honest peer.
  const honest = Uint8Array.from([1, 2, 3, 4]);
  session.receive({ t: 'RECORDS', from: 0, recs: [honest] }, NOW);
  assert.equal(session.deferredCount, 1);

  // Now the flood: the same postdated record, over and over.
  const flood = Uint8Array.from([9, 9, 9, 9]);
  for (let i = 0; i < LIMITS.deferred * 2; i += 1) {
    session.receive({ t: 'RECORDS', from: 0, recs: [flood] }, NOW);
  }

  // The queue must not have become 1,024 copies of one record, and the honest deferral must
  // still be in it.
  assert.ok(
    session.deferredCount <= 2,
    `one repeated record occupies ${session.deferredCount} slots`,
  );
});

test('deduplication does not break the mechanism it protects', () => {
  // The dangerous fix here is one that makes the queue useless: dedup that swallows genuinely
  // different records, or that never releases a key so a record deferred once can never be
  // deferred again after its retry. Both would look like a passing flood test and a broken
  // skew tolerance, which is a worse bug than the one being fixed.
  let deferAll = true;
  const sink: ReplicationSink = {
    append: (): Verdict =>
      deferAll
        ? { outcome: 'defer', reason: 'CLOCK_SKEW', detail: 'ahead of this clock' }
        : { outcome: 'reject', code: 'NOT_A_MAP', detail: 'settled' },
    encodingAt: () => null,
    length: () => 0,
    treeRoot: () => new Uint8Array(32),
  };
  const session = new ReplicationSession(sink);
  session.open();
  session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);

  // Distinct records are all held — dedup must key on content, not merely on arrival.
  const distinct = Array.from({ length: 50 }, (_, i) => Uint8Array.from([i, i + 1, i + 2]));
  session.receive({ t: 'RECORDS', from: 0, recs: distinct }, NOW);
  assert.equal(session.deferredCount, 50, 'every distinct deferral is held');

  // And the queue still fills to its stated bound with distinct records, so the cap was not
  // accidentally lowered by keying on something coarser.
  const more = Array.from({ length: LIMITS.deferred }, (_, i) =>
    Uint8Array.from([(i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff, 0xaa]),
  );
  session.receive({ t: 'RECORDS', from: 0, recs: more.slice(0, LIMITS.recordsPerBatch) }, NOW);
  assert.ok(session.deferredCount > 50, 'the queue keeps accepting distinct records');

  // After a retry drains the queue, the same record may be deferred again — the key set must be
  // released, or a transient skew becomes a permanent refusal to hold that record ever again.
  deferAll = false;
  session.retryDeferred(NOW + 1);
  assert.equal(session.deferredCount, 0, 'the retry drained it');
  deferAll = true;
  session.receive({ t: 'RECORDS', from: 0, recs: [distinct[0]!] }, NOW + 2);
  assert.equal(session.deferredCount, 1, 'a record may be deferred again after a retry');
});

test('AUDIT: an evicted record can be deferred again, and the key set never outgrows the queue', () => {
  // Found by a mutation that SURVIVED: deleting the evicted entry's key from the dedup set failed
  // no test. It matters twice over. The key set would grow without bound — the very thing the
  // queue's own limit exists to prevent, reintroduced beside it — and a record evicted once could
  // never be deferred again, so a transient skew would become a permanent refusal to hold that
  // record while its own retry window was still open.
  //
  // **`deferredCount` cannot see this**, which is why the first attempt at this test failed
  // against correct code. Once the queue is at its bound the count is at its bound whatever
  // happens next: a re-held record evicts another and the total is unchanged. What distinguishes
  // a leak from a re-hold is *which* records are in the queue, so the sink is used as the probe —
  // it accepts exactly one record on retry, and `retryDeferred` reports whether that record was
  // there to be retried.
  let acceptOnly: Uint8Array | null = null;
  const sink: ReplicationSink = {
    append: (bytes): Verdict =>
      acceptOnly !== null && bytes.join(',') === acceptOnly.join(',')
        ? { outcome: 'accept', record: null as never }
        : { outcome: 'defer', reason: 'CLOCK_SKEW', detail: 'ahead of this clock' },
    encodingAt: () => null,
    length: () => 0,
    treeRoot: () => new Uint8Array(32),
  };
  const session = new ReplicationSession(sink);
  session.open();
  session.receive({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }, NOW);

  const record = (i: number): Uint8Array =>
    Uint8Array.from([(i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff, 0x5a]);
  const first = record(0);

  session.receive({ t: 'RECORDS', from: 0, recs: [first] }, NOW);
  for (
    let sent = 1;
    sent < LIMITS.deferred + LIMITS.recordsPerBatch;
    sent += LIMITS.recordsPerBatch
  ) {
    const batch = Array.from({ length: LIMITS.recordsPerBatch }, (_, k) => record(sent + k));
    session.receive({ t: 'RECORDS', from: 0, recs: batch }, NOW);
  }
  assert.equal(session.deferredCount, LIMITS.deferred, 'the queue holds exactly its stated bound');

  // `first` has been evicted. Send it again: if its key leaked at eviction this is silently
  // dropped, and if it did not the record is back in the queue. The count is identical either way.
  session.receive({ t: 'RECORDS', from: 0, recs: [first] }, NOW);
  assert.equal(session.deferredCount, LIMITS.deferred, 'still exactly the bound after a re-defer');

  // The probe. Exactly one record can now be accepted, and it is `first`.
  acceptOnly = first;
  assert.equal(
    session.retryDeferred(NOW),
    1,
    'a record evicted earlier must still be deferrable — its key leaked at eviction',
  );
});
