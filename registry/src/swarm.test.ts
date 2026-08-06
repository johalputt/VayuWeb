import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import {
  Deframer,
  FramingError,
  SWARM_LIMITS,
  TOPIC_PREIMAGE,
  drivePeer,
  frame,
  replicationTopic,
  type PeerStream,
} from './swarm.ts';
import { LIMITS, PROTOCOL_VERSION, decodeMessage, encodeMessage } from './replicate.ts';
import { Store } from './store.ts';
import { encode, type CborMap, type CborValue } from './cbor.ts';
import { signingInput } from './domain.ts';
import { sign, publicKeyFrom } from './signature.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH, solvePow, requiredBits } from './pow.ts';
import { TERM_SECONDS } from './verify.ts';

const NOW = 1_782_518_400;
const SECRET = new Uint8Array(32).fill(0x42);
const OWNER = publicKeyFrom(SECRET);

const refusal = (run: () => unknown): string => {
  try {
    run();
    return 'accepted';
  } catch (error) {
    return error instanceof FramingError ? error.code : `threw:${String(error)}`;
  }
};

/* -------------------------------------------------------------------------- */
/* The topic                                                                   */
/* -------------------------------------------------------------------------- */

test('the topic is BLAKE2b-256 of the string the specification names', () => {
  // Derived rather than written down, so it cannot drift from the preimage. Recomputed here from
  // the constant, which is what makes this a check rather than a restatement of the same line.
  const expected = createHash('blake2b512').update(TOPIC_PREIMAGE).digest().subarray(0, 32);
  assert.deepEqual(Buffer.from(replicationTopic()), Buffer.from(expected));
  assert.equal(replicationTopic().length, 32);
  assert.equal(TOPIC_PREIMAGE, 'VayuWeb-Replication-v1');
});

/* -------------------------------------------------------------------------- */
/* Framing — the gap between "ordered stream" and "framed channel"             */
/* -------------------------------------------------------------------------- */

test('a framed message round-trips through the deframer', () => {
  const payload = Uint8Array.from([1, 2, 3, 4, 5]);
  const out = new Deframer().push(frame(payload));
  assert.equal(out.length, 1);
  assert.deepEqual(out[0], payload);
});

test('frames arriving split across arbitrary chunk boundaries still reassemble', () => {
  // A stream gives no guarantee about where a chunk ends, and an implementation that assumes one
  // message per read works perfectly until the day the network disagrees. Byte-at-a-time is the
  // worst case and therefore the one worth pinning.
  const a = frame(Uint8Array.from([9, 9, 9]));
  const b = frame(Uint8Array.from([7]));
  const wire = new Uint8Array(a.length + b.length);
  wire.set(a, 0);
  wire.set(b, a.length);

  const deframer = new Deframer();
  const got: Uint8Array[] = [];
  for (const byte of wire) got.push(...deframer.push(Uint8Array.of(byte)));
  assert.equal(got.length, 2);
  assert.deepEqual(got[0], Uint8Array.from([9, 9, 9]));
  assert.deepEqual(got[1], Uint8Array.from([7]));
  assert.equal(deframer.pending, 0, 'nothing is left buffered');
});

test('two frames in one chunk both emerge, in order', () => {
  const a = frame(Uint8Array.from([1]));
  const b = frame(Uint8Array.from([2]));
  const wire = new Uint8Array(a.length + b.length);
  wire.set(a, 0);
  wire.set(b, a.length);
  const out = new Deframer().push(wire);
  assert.deepEqual(out.map((p) => p[0]), [1, 2]);
});

test('a declared length over the limit is refused before anything is buffered against it', () => {
  // The cheapest denial of service a framed protocol offers: four bytes naming a gigabyte. The
  // check is on the DECLARATION, so refusing costs nothing and believing it costs everything.
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, SWARM_LIMITS.frameBytes + 1, false);
  const deframer = new Deframer();
  assert.equal(refusal(() => deframer.push(prefix)), 'FRAME_TOO_LARGE');
  assert.equal(deframer.pending, 4, 'and no allocation was made against the claim');
});

test('a zero-length frame is refused rather than looping', () => {
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, 0, false);
  assert.equal(refusal(() => new Deframer().push(prefix)), 'FRAME_EMPTY');
});

test('framing an over-sized payload is refused at the sender too', () => {
  assert.equal(
    refusal(() => frame(new Uint8Array(SWARM_LIMITS.frameBytes + 1))),
    'FRAME_TOO_LARGE',
  );
});

/* -------------------------------------------------------------------------- */
/* Driving a peer                                                              */
/* -------------------------------------------------------------------------- */

/**
 * A stream that records what was written and lets a test feed bytes in.
 *
 * Satisfies `PeerStream` structurally, with no cast. That is not a stylistic preference: a test
 * double that only type-checks behind `as unknown as` is a double whose shape has stopped being
 * checked against the interface, which is exactly the drift the double exists to catch.
 */
interface FakeStream extends PeerStream {
  readonly written: Uint8Array[];
  destroyed: boolean;
  feed(bytes: Uint8Array): void;
}

function fakeStream(): FakeStream {
  const listeners = new Map<string, ((chunk: Uint8Array) => void)[]>();
  const written: Uint8Array[] = [];
  const self: FakeStream = {
    written,
    destroyed: false,
    write(bytes: Uint8Array) {
      written.push(bytes);
    },
    on(event: 'data' | 'error' | 'close', listener: (chunk: Uint8Array) => void) {
      const list = listeners.get(event) ?? [];
      list.push(listener);
      listeners.set(event, list);
    },
    destroy() {
      self.destroyed = true;
      for (const l of listeners.get('close') ?? []) l(new Uint8Array(0));
    },
    feed(bytes: Uint8Array) {
      for (const l of listeners.get('data') ?? []) l(bytes);
    },
  };
  return self;
}

const emptySink = () => ({
  append: () => ({ outcome: 'reject', code: 'BAD_SIG', detail: 'test sink' }) as never,
  length: () => 0,
  encodingAt: () => null,
  treeRoot: () => new Uint8Array(32),
});

test('a peer connection opens with HELLO before anything is asked of it', () => {
  const stream = fakeStream();
  drivePeer(stream, emptySink(), () => NOW);
  assert.equal(stream.written.length, 1, 'exactly one message, unprompted');
  const sent = stream.written[0]!;
  // The frame is the prefix plus the message, and the message decodes as HELLO.
  assert.ok(sent.length > SWARM_LIMITS.prefixBytes);
});

test('a message this peer cannot decode drops the message, not the connection', () => {
  // REPLICATION.md 3.2: refusing to speak to a peer that knows a message you do not is how a
  // protocol becomes unextendable. The distinction between a bad MESSAGE and a bad FRAME is the
  // whole point — one is a future extension, the other is a desynchronised stream.
  const stream = fakeStream();
  const outcome = drivePeer(stream, emptySink(), () => NOW);
  stream.feed(frame(encode(new Map<string | Uint8Array, CborValue>([['t', 'FROM_THE_FUTURE']]))));
  assert.equal(stream.destroyed, false, 'the connection survives an unknown message type');
  assert.equal(outcome.rejected, 1);
});

test('a bad frame drops the connection, because a stream cannot resynchronise', () => {
  const stream = fakeStream();
  drivePeer(stream, emptySink(), () => NOW);
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, SWARM_LIMITS.frameBytes + 1, false);
  stream.feed(prefix);
  assert.equal(stream.destroyed, true);
});

test('the remote public key is never consulted', async () => {
  // REPLICATION.md 2.3, and the rule this module is most able to break: Hyperswarm hands over an
  // authenticated remote key, and it is exactly what an implementer reaches for when they want to
  // skip work for a peer they have seen before. A record's authority is its signature.
  const source = await import('node:fs').then((fs) =>
    fs.readFileSync(new URL('./swarm.ts', import.meta.url), 'utf8'),
  );
  for (const forbidden of ['remotePublicKey', 'publicKey', '.info.', 'peerInfo']) {
    assert.doesNotMatch(
      source.replace(/\/\*\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, ''),
      new RegExp(forbidden.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
      `${forbidden} appears in swarm.ts outside a comment`,
    );
  }
});

/* -------------------------------------------------------------------------- */
/* Two peers, real records, over the driver                                    */
/* -------------------------------------------------------------------------- */

const scratch = (): string => join(mkdtempSync(join(tmpdir(), 'vayuweb-swarm-')), 'log');

const entry = (type: string, value: CborValue): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['type', type],
    ['value', value],
  ]);

/** A registration with a real proof of work. 16 characters, so 4 bits. */
function registration(label: string, txt: string): Uint8Array {
  const bits = requiredBits(label.length, 0);
  const skeleton = (nonce: Uint8Array): CborMap =>
    new Map<string | Uint8Array, CborValue>([
      ['version', 1],
      ['suite', 1],
      ['op', 'REGISTER'],
      ['name', label],
      ['tld', 'vayu'],
      ['ownerKey', OWNER],
      ['seq', 0],
      ['notBefore', NOW],
      ['notAfter', NOW + TERM_SECONDS],
      ['records', [entry('txt', txt)]],
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
  assert.ok(nonce, 'the fixture must solve');
  const map = skeleton(nonce);
  map.set('sig', sign(SECRET, signingInput(map)));
  return encode(map);
}

/** Wire two drivers to each other directly, which is what a transport is. */
function pipePair(): [FakeStream, FakeStream] {
  const a = fakeStream();
  const b = fakeStream();
  const pump = (from: FakeStream, to: FakeStream): void => {
    const original = from.write.bind(from);
    from.write = (bytes: Uint8Array): void => {
      original(bytes);
      // Deliver on a later turn, so neither side can rely on synchronous delivery.
      queueMicrotask(() => {
        if (!to.destroyed) to.feed(bytes);
      });
    };
  };
  pump(a, b);
  pump(b, a);
  return [a, b];
}

test('two peers over the driver converge on identical registry state', async () => {
  // Phase 2's property, exercised rather than asserted: one peer holds a record, the other does
  // not, and after they talk both hold it — with the receiver having verified it locally against
  // its own clock and its own view, exactly as a locally created record is verified.
  const one = Store.open(scratch(), NOW);
  const two = Store.open(scratch(), NOW);

  const bytes = registration('atlasobservatory', 'v=vayuweb1;one');
  assert.equal(one.append(bytes, NOW).outcome, 'accept');
  assert.equal(two.lookup('atlasobservatory', 'vayu'), null, 'the second peer starts empty');

  const sinkFor = (store: Store) => ({
    append: (b: Uint8Array, now: number) => store.append(b, now),
    length: () => {
      let n = 0;
      while (store.entryAt(n) !== null) n += 1;
      return n;
    },
    encodingAt: (i: number) => store.entryAt(i)?.bytes ?? null,
    treeRoot: () => new Uint8Array(32),
  });

  const [a, b] = pipePair();
  drivePeer(a, sinkFor(one), () => NOW);
  drivePeer(b, sinkFor(two), () => NOW);

  // Let the exchange settle. Each turn of the loop delivers one round of queued microtasks.
  for (let i = 0; i < 50; i += 1) await Promise.resolve();
  await new Promise((r) => setTimeout(r, 50));

  const held = two.lookup('atlasobservatory', 'vayu');
  assert.ok(held !== null, 'the record reached the second peer');
  assert.equal(held.current.record.name, 'atlasobservatory');
  assert.deepEqual(
    Buffer.from(held.current.record.ownerKey),
    Buffer.from(OWNER),
    'and it is the same owner, verified locally rather than taken on trust',
  );
});

test('a driver that greets but never asks is a permanently diverged peer', async () => {
  // The defect the convergence test found, pinned directly so it cannot come back quietly. The
  // session ANSWERS questions and never asks them: `nextWant` exists so the transport decides
  // when to pull, because how aggressively to sync is a resource decision rather than a protocol
  // one. A driver that only sends HELLO and replies looks exactly like a working connection --
  // handshake completes, no error, no warning -- and can never catch up. Two of them sit there
  // permanently diverged.
  const stream = fakeStream();
  drivePeer(stream, emptySink(), () => NOW);
  stream.written.length = 0;

  // A peer announces a log of three records. A driver that asks must now send a WANT.
  stream.feed(
    frame(encodeMessage({ t: 'HELLO', v: PROTOCOL_VERSION, len: 3, root: new Uint8Array(32) })),
  );
  await new Promise((r) => setTimeout(r, 20));

  const sent = stream.written.map((f) => decodeMessage(f.subarray(SWARM_LIMITS.prefixBytes)));
  assert.ok(
    sent.some((m) => m.t === 'WANT'),
    `after a HELLO announcing 3 records the driver must ask for them; it sent ${JSON.stringify(sent.map((m) => m.t))}`,
  );
});

test('a peer sending a record that fails local verification changes nothing', async () => {
  // REPLICATION.md 8.3. The transport is not evidence, so a record that would be refused if it
  // had been created locally is refused when it arrives over a connection.
  const store = Store.open(scratch(), NOW);
  const stream = fakeStream();
  const outcome = drivePeer(
    stream,
    {
      append: (b: Uint8Array, now: number) => store.append(b, now),
      length: () => 0,
      encodingAt: () => null,
      treeRoot: () => new Uint8Array(32),
    },
    () => NOW,
  );

  const genuine = registration('atlasobservatory', 'v=vayuweb1');
  const tampered = Uint8Array.from(genuine);
  tampered[tampered.length - 1] ^= 0xff; // break the signature

  stream.feed(frame(encodeMessage({ t: 'HELLO', v: PROTOCOL_VERSION, len: 1, root: new Uint8Array(32) })));
  stream.feed(frame(encodeMessage({ t: 'RECORDS', from: 0, recs: [tampered] })));
  await new Promise((r) => setTimeout(r, 20));

  assert.equal(outcome.applied, 0, 'nothing was applied');
  assert.equal(store.lookup('atlasobservatory', 'vayu'), null, 'and the state is unchanged');
});

test('an oversized batch is refused at decode rather than iterated', () => {
  const stream = fakeStream();
  const outcome = drivePeer(stream, emptySink(), () => NOW);
  const oversized = encode(
    new Map<string | Uint8Array, CborValue>([
      ['t', 'RECORDS'],
      ['from', 0],
      ['recs', Array.from({ length: LIMITS.recordsPerBatch + 1 }, () => Uint8Array.of(1))],
    ]),
  );
  stream.feed(frame(oversized));
  assert.equal(outcome.applied, 0);
  assert.equal(outcome.rejected, 1, 'counted as one refused message, not 257 refused records');
});
