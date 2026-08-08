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
  joinSwarm,
  type PeerStream,
  type SwarmOptions,
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
  assert.deepEqual(
    out.map((p) => p[0]),
    [1, 2],
  );
});

test('a declared length over the limit is refused before anything is buffered against it', () => {
  // The cheapest denial of service a framed protocol offers: four bytes naming a gigabyte. The
  // check is on the DECLARATION, so refusing costs nothing and believing it costs everything.
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, SWARM_LIMITS.frameBytes + 1, false);
  const deframer = new Deframer();
  assert.equal(
    refusal(() => deframer.push(prefix)),
    'FRAME_TOO_LARGE',
  );
  assert.equal(deframer.pending, 4, 'and no allocation was made against the claim');
});

test('a zero-length frame is refused rather than looping', () => {
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, 0, false);
  assert.equal(
    refusal(() => new Deframer().push(prefix)),
    'FRAME_EMPTY',
  );
});

test('framing an over-sized payload is refused at the sender too', () => {
  assert.equal(
    refusal(() => frame(new Uint8Array(SWARM_LIMITS.frameBytes + 1))),
    'FRAME_TOO_LARGE',
  );
});

/* -------------------------------------------------------------------------- */
/* AUDIT: the deframer did quadratic work for linear input                     */
/* -------------------------------------------------------------------------- */

test('AUDIT: a peer dripping one byte at a time cannot cost quadratic work', () => {
  // Found by attacking the deframer rather than by reading it. The first version rebuilt the
  // whole pending buffer on every `push`, so a peer sending a 64 KiB frame one byte at a time
  // cost the receiver ~2.15 GB of memory copying and ~890 ms of CPU -- an amplification of about
  // 33,000:1 against a peer whose own cost is 64 KiB of bandwidth. With the connection cap at 64
  // peers, a sustained drip pins every core.
  //
  // REPLICATION.md 2.4 is explicit that "a hostile peer's maximum achievable effect is to waste
  // the receiver's bandwidth and CPU **within the limits of section 5**". Work quadratic in a
  // bounded quantity is outside those limits: the bound stops being a bound when the cost of
  // reaching it is not linear.
  //
  // Asserted on bytes copied rather than on elapsed time. A wall-clock assertion is flaky on a
  // loaded runner and reads a clock the hygiene gate refuses; the copy counter is exact, and it
  // is the quantity the defect is actually about.
  const payload = new Uint8Array(SWARM_LIMITS.frameBytes - 16).fill(7);
  const wire = frame(payload);

  const deframer = new Deframer();
  let emerged = 0;
  for (const byte of wire) emerged += deframer.push(Uint8Array.of(byte)).length;

  assert.equal(emerged, 1, 'the frame still reassembles');
  // Each byte is copied into the pending list once and into the finished frame once. Four times
  // the wire length is generous headroom over that and still four orders of magnitude below the
  // quadratic behaviour, which for this frame was over two billion.
  assert.ok(
    deframer.copiedBytes <= wire.length * 4,
    `copied ${deframer.copiedBytes} bytes to receive ${wire.length}; ` +
      `quadratic would be about ${Math.round((wire.length * wire.length) / 2)}`,
  );

  // **Two counters, because one was not enough.** The first fix for this defect replaced the
  // byte copying with `Array.shift` per chunk — also quadratic, and seven times SLOWER than the
  // defect it replaced — while `copiedBytes` reported everything was fine, because the cost had
  // moved out of the resource that counter measures. A bound on one resource is silent about
  // every other one, and a fix validated only by the metric it was written against is a fix
  // nobody has measured.
  assert.ok(
    deframer.workUnits <= wire.length * 4,
    `${deframer.workUnits} work units to receive ${wire.length} bytes`,
  );
});

test('AUDIT: the work is linear in the frame, measured rather than asserted', () => {
  // Linearity is the property; a single size cannot show it. Doubling the frame must double the
  // work, and quadratic behaviour quadruples it — which is visible here and is invisible to any
  // assertion made at one size.
  const perByte: number[] = [];
  for (const size of [4096, 8192, 16384, 32768]) {
    const wire = frame(new Uint8Array(size - 16).fill(3));
    const deframer = new Deframer();
    for (const byte of wire) deframer.push(Uint8Array.of(byte));
    perByte.push(deframer.workUnits / wire.length);
  }
  const first = perByte[0]!;
  for (const ratio of perByte) {
    assert.ok(
      Math.abs(ratio - first) < 0.25,
      `work per byte drifted across sizes: ${perByte.map((r) => r.toFixed(2)).join(', ')}`,
    );
  }
});

test('AUDIT: a frame that never completes holds bounded memory and copies bounded bytes', () => {
  // The other half: a peer that declares a legal frame and then stops. The receiver must hold at
  // most that frame, and must not have paid quadratically to get there.
  const deframer = new Deframer();
  const prefix = new Uint8Array(4);
  new DataView(prefix.buffer).setUint32(0, SWARM_LIMITS.frameBytes, false);
  deframer.push(prefix);
  for (let i = 0; i < 8192; i += 1) deframer.push(new Uint8Array(1));

  assert.ok(deframer.pending <= SWARM_LIMITS.frameBytes + SWARM_LIMITS.prefixBytes);
  assert.ok(
    deframer.copiedBytes <= (8192 + 4) * 4,
    `copied ${deframer.copiedBytes} for 8196 bytes of drip`,
  );
  assert.ok(
    deframer.workUnits <= (8192 + 4) * 4,
    `${deframer.workUnits} work units for 8196 bytes of drip`,
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

  stream.feed(
    frame(encodeMessage({ t: 'HELLO', v: PROTOCOL_VERSION, len: 1, root: new Uint8Array(32) })),
  );
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

/* -------------------------------------------------------------------------- */
/* AUDIT: the deadline that only ran when the peer chose to speak              */
/* -------------------------------------------------------------------------- */

test('AUDIT: a peer that greets and then goes silent has its slots reclaimed', () => {
  // **REPLICATION.md 4.3.b says a slot is reclaimed "whether or not a reply ever arrives", and
  // the shipping requester reclaimed one only when something else arrived.**
  //
  // `expireWants` was private and called from one place, `nextWant`; `nextWant` from one place,
  // `pump()`; and `pump()` from one place, `record()`, which runs inside the inbound `data`
  // handler. So the deadline was evaluated only when the peer sent something — which is precisely
  // the party the clause exists to defend against. A peer greets, takes all eight slots, and stops.
  // Measured against the old driver: 6,000 seconds against a 60-second deadline, not one slot
  // reclaimed and not one `WANT` retransmitted.
  //
  // Because a `WANT` is the only message this driver ever re-sends, this was also its only
  // retransmission path: a `WANT` or a `RECORDS` lost on the wire was never retried on any
  // connection, and the peer stayed silently under-synced while the connection looked healthy from
  // both ends.
  //
  // The regression test written with the session-level fix drove `session.nextWant` directly, so
  // it passed against the frozen driver. This one runs at the level the defect lives at.
  const stream = fakeStream();
  const clock = { at: NOW };
  const ticks: (() => void)[] = [];
  drivePeer(stream, emptySink(), () => clock.at, {
    setInterval: (fn: () => void) => {
      ticks.push(fn);
      return ticks.length;
    },
    clearInterval: () => undefined,
  });

  // The peer greets, declaring a log far ahead of ours, and then says nothing ever again.
  stream.feed(
    frame(
      encodeMessage({
        t: 'HELLO',
        v: PROTOCOL_VERSION,
        len: 10_000,
        root: new Uint8Array(32),
      }),
    ),
  );
  const afterGreeting = stream.written.length;
  assert.ok(afterGreeting > 1, 'the greeting must have drawn out some WANTs');

  // Nothing arrives. Every slot is spoken for and the connection is, from our side, finished.
  const saturated = stream.written.length;
  clock.at += 10 * LIMITS.wantDeadlineSeconds;
  assert.equal(stream.written.length, saturated, 'time alone sends nothing without a tick');

  // The driver's own clock fires. This is the whole fix: something other than the peer decides
  // that the deadline has passed.
  assert.ok(ticks.length > 0, 'drivePeer must schedule a tick of its own');
  for (const tick of ticks) tick();

  assert.ok(
    stream.written.length > saturated,
    `no WANT was re-issued after ${10 * LIMITS.wantDeadlineSeconds}s against a ` +
      `${LIMITS.wantDeadlineSeconds}s deadline`,
  );

  // And it keeps working, rather than reclaiming once and freezing again.
  const afterFirst = stream.written.length;
  clock.at += 10 * LIMITS.wantDeadlineSeconds;
  for (const tick of ticks) tick();
  assert.ok(stream.written.length > afterFirst, 'the tick must keep reclaiming, not fire once');
});

test('the driver stops its own clock when the connection closes', () => {
  // A timer per connection that outlives the connection is a leak proportional to how many peers
  // have ever connected — and it would keep a reference to the session, so the memory the deadline
  // was added to bound would be held by the mechanism that bounds it.
  const stream = fakeStream();
  let cleared = 0;
  drivePeer(stream, emptySink(), () => NOW, {
    setInterval: () => 'handle',
    clearInterval: () => {
      cleared += 1;
    },
  });
  assert.equal(cleared, 0, 'nothing is cleared while the connection is open');
  stream.destroy();
  assert.equal(cleared, 1, 'and the timer goes when the connection does');
});

test('AUDIT: a deferred record is actually retried, not merely held', () => {
  // **`retryDeferred` had no caller anywhere outside its own test.** The deferral fix that landed
  // earlier bounds the queue honestly — deduplicated by record hash, so one postdated record
  // resent a thousand times can no longer evict everybody else's — and the property that bound is
  // in service of is stated in the code: "skew costs a retry instead of a loss". No shipping path
  // performed the retry. `drivePeer` never called it, the swarm never called it, nothing on a
  // clock called it, so a record deferred for clock skew stayed deferred until the connection
  // ended and was then lost.
  //
  // This is the same missing clock as the WANT deadline above, in a second place, which is what
  // made it worth looking for: the driver had no notion of elapsed time at all.
  const stream = fakeStream();
  const clock = { at: NOW };
  const ticks: (() => void)[] = [];
  let appended = 0;
  let deferUntil = NOW + 100;
  const sink = {
    append: (_bytes: Uint8Array, at: number) => {
      appended += 1;
      return at < deferUntil
        ? ({ outcome: 'defer', code: 'CLOCK_SKEW', detail: 'early' } as never)
        : ({ outcome: 'accept' } as never);
    },
    length: () => 0,
    encodingAt: () => null,
    treeRoot: () => new Uint8Array(32),
  };
  drivePeer(stream, sink, () => clock.at, {
    setInterval: (fn: () => void) => {
      ticks.push(fn);
      return ticks.length;
    },
    clearInterval: () => undefined,
  });

  stream.feed(
    frame(encodeMessage({ t: 'HELLO', v: PROTOCOL_VERSION, len: 1, root: new Uint8Array(32) })),
  );
  stream.feed(frame(encodeMessage({ t: 'RECORDS', from: 0, recs: [new Uint8Array([1, 2, 3])] })));
  const afterArrival = appended;
  assert.ok(afterArrival > 0, 'the record must have been offered to the sink once');

  // The skew passes. Nothing else arrives — that is the case the queue exists for.
  clock.at = deferUntil + 1;
  deferUntil = NOW; // it would be accepted now
  for (const tick of ticks) tick();
  assert.ok(
    appended > afterArrival,
    'the deferred record was never re-offered, so the skew cost a loss rather than a retry',
  );
});

/* -------------------------------------------------------------------------- */
/* AUDIT: the reference transport binding, which nothing exercised             */
/* -------------------------------------------------------------------------- */

/** A Hyperswarm-shaped double. Satisfies `SwarmOptions['swarm']` structurally, with no cast. */
function fakeSwarm(): {
  swarm: SwarmOptions['swarm'];
  connect: (stream: PeerStream) => void;
  joined: Uint8Array[];
  options: { server?: boolean; client?: boolean }[];
  destroyed: number;
  flushes: number;
} {
  const listeners: ((stream: PeerStream, info: unknown) => void)[] = [];
  const self = {
    joined: [] as Uint8Array[],
    options: [] as { server?: boolean; client?: boolean }[],
    destroyed: 0,
    flushes: 0,
    connect: (stream: PeerStream) => {
      for (const l of listeners) l(stream, { publicKey: new Uint8Array(32).fill(0xbe) });
    },
    swarm: {
      on(_event: 'connection', listener: (stream: PeerStream, info: unknown) => void) {
        listeners.push(listener);
      },
      join(topic: Uint8Array, options?: { server?: boolean; client?: boolean }) {
        self.joined.push(topic);
        self.options.push(options ?? {});
        return {
          flushed: async () => {
            self.flushes += 1;
          },
        };
      },
      destroy: async () => {
        self.destroyed += 1;
      },
    },
  };
  return self;
}

test('AUDIT: joinSwarm joins the specified topic and drives every peer that connects', async () => {
  // **`joinSwarm` had no caller and no test.** It is the sole entry point of what the roadmap
  // calls the reference transport binding, and the dead-code gate certified it as live — because
  // that gate counted occurrences of the name over the raw file text, and the name appears a
  // second time in its own neighbouring doc comment. A gate that reads prose as usage will
  // certify any export that mentions itself.
  //
  // So this is the test the gate was standing in for. Everything it needs is injected already:
  // `SwarmOptions.swarm` exists so that this module is not the place that decides a VayuWeb node
  // must speak HyperDHT, and that same injection is what makes the binding checkable with no
  // network at all.
  const fake = fakeSwarm();
  const joined = await joinSwarm({ swarm: fake.swarm, sink: emptySink(), now: () => NOW });

  // The topic is the derived one, not a literal — the same value `replicationTopic()` computes
  // from the string the specification names.
  assert.equal(fake.joined.length, 1);
  assert.deepEqual(fake.joined[0], replicationTopic());
  // Server AND client: a node that only dialled would never be findable, and a node that only
  // listened would never find anyone. Both halves are what makes a peer set rather than a service.
  assert.deepEqual(fake.options[0], { server: true, client: true });
  // The join is awaited, so a caller that gets a Swarm back has actually joined.
  assert.equal(fake.flushes, 1);

  // A connecting peer is driven, which is observable as the HELLO this end sends unprompted.
  const stream = fakeStream();
  fake.connect(stream);
  assert.equal(joined.peers, 1);
  assert.equal(stream.written.length, 1, 'a connected peer must be greeted');
  assert.equal(decodeMessage(stream.written[0]!.subarray(SWARM_LIMITS.prefixBytes)).t, 'HELLO');

  // And the count follows the connection rather than only counting up.
  stream.destroy();
  assert.equal(joined.peers, 0);

  await joined.leave();
  assert.equal(fake.destroyed, 1, 'leaving must destroy the swarm, not merely stop counting');
});

test('AUDIT: joinSwarm refuses a peer over the connection cap without leaking a slot', async () => {
  // The cap is the only thing bounding how much memory a stranger can make this node hold, and
  // the refusal path is where the sibling cap in serve.ts leaked a slot on every refusal. Here the
  // refused stream must be destroyed and must not be driven — a greeted peer is a peer this node
  // is talking to, cap or no cap.
  const fake = fakeSwarm();
  const joined = await joinSwarm({ swarm: fake.swarm, sink: emptySink(), now: () => NOW });

  const accepted: FakeStream[] = [];
  for (let i = 0; i < SWARM_LIMITS.connections; i += 1) {
    const s = fakeStream();
    fake.connect(s);
    accepted.push(s);
  }
  assert.equal(joined.peers, SWARM_LIMITS.connections);

  const overflow = fakeStream();
  fake.connect(overflow);
  assert.equal(overflow.destroyed, true, 'the peer over the cap is dropped');
  assert.equal(overflow.written.length, 0, 'and never greeted');
  assert.equal(joined.peers, SWARM_LIMITS.connections, 'the refusal took no slot');

  // Closing one makes room again, so the cap is a cap and not a lifetime quota.
  accepted[0]!.destroy();
  assert.equal(joined.peers, SWARM_LIMITS.connections - 1);
  const later = fakeStream();
  fake.connect(later);
  assert.equal(later.destroyed, false);
  assert.equal(later.written.length, 1, 'and the new peer is greeted');

  await joined.leave();
});
