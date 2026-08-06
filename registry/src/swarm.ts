/**
 * The reference transport binding: Hyperswarm over HyperDHT.
 *
 * docs/spec/REPLICATION.md section 2. Everything protocol-shaped lives in `replicate.ts`, which
 * consumes and produces messages and knows nothing about sockets; this module carries them.
 *
 * ## 2.2 says this binding is not normative, and that is load-bearing
 *
 * "An implementation MAY use any transport, including a local socket, a serial line, or a courier
 * carrying a file." Article 4 forbids any function of the protocol requiring a single party's
 * availability, and a protocol defined in terms of one discovery network would make that
 * network's operators load-bearing. So this file is deliberately thin and deliberately
 * replaceable: it is one binding of a transport-agnostic state machine, not the way VayuWeb
 * works. A second binding should need nothing from `replicate.ts` that this one did not.
 *
 * ## 2.3 is the rule this module is most able to break
 *
 * "An implementation MUST NOT treat the transport's authentication, if any, as evidence about a
 * record." Hyperswarm hands over a Noise-encrypted stream with an authenticated remote public
 * key, and that key is exactly the kind of thing an implementer reaches for when they want to
 * skip work for a peer they have talked to before. Nothing here reads it. A record's authority is
 * its signature; the channel adds nothing, and an implementation that skips verification for a
 * "known" peer has removed the only check there is.
 *
 * ## Framing is this module's job
 *
 * Hyperswarm provides an ordered, reliable, encrypted **stream**. Section 2.1 asks for an ordered,
 * reliable, **framed** channel, and the gap between those two words is a length prefix. Getting it
 * wrong is not a cosmetic bug: a reader that trusts a declared length allocates whatever a peer
 * asks for, and a reader that does not resynchronise after a bad frame stays wrong forever.
 */

import { createHash } from 'node:crypto';

import {
  LIMITS,
  ReplicationError,
  ReplicationSession,
  decodeMessage,
  encodeMessage,
  type Message,
  type ReceiveOutcome,
  type ReplicationSink,
} from './replicate.ts';

/** The discovery topic, per REPLICATION.md 2.2. */
export const TOPIC_PREIMAGE = 'VayuWeb-Replication-v1';

/** Bounds this binding enforces on top of the protocol's own. */
export const SWARM_LIMITS = {
  /** Bytes buffered for one frame before the connection is dropped. Matches the message limit. */
  frameBytes: LIMITS.messageBytes,
  /** The length prefix, big-endian. Four bytes covers the message limit many times over. */
  prefixBytes: 4,
  /** Concurrent peer connections. Beyond this, new ones are closed rather than queued. */
  connections: 64,
} as const;

/**
 * `BLAKE2b-256("VayuWeb-Replication-v1")`.
 *
 * Computed rather than written down, so the topic cannot drift from the string the specification
 * names. A hard-coded digest is a second source of truth for a value one line of code derives.
 */
export function replicationTopic(): Uint8Array {
  return new Uint8Array(createHash('blake2b512').update(TOPIC_PREIMAGE).digest().subarray(0, 32));
}

/** Why a connection was dropped by the framing layer, before any message was decoded. */
export type FramingRejection = 'FRAME_TOO_LARGE' | 'FRAME_EMPTY';

export class FramingError extends Error {
  readonly code: FramingRejection;
  constructor(code: FramingRejection, message: string) {
    super(`${code}: ${message}`);
    this.name = 'FramingError';
    this.code = code;
  }
}

/** Length-prefix one message for the wire. */
export function frame(payload: Uint8Array): Uint8Array {
  if (payload.length > SWARM_LIMITS.frameBytes) {
    throw new FramingError(
      'FRAME_TOO_LARGE',
      `${payload.length} bytes is over the ${SWARM_LIMITS.frameBytes} frame limit`,
    );
  }
  const out = new Uint8Array(SWARM_LIMITS.prefixBytes + payload.length);
  new DataView(out.buffer).setUint32(0, payload.length, false);
  out.set(payload, SWARM_LIMITS.prefixBytes);
  return out;
}

/**
 * Incremental de-framer.
 *
 * Exported and free of any socket so that every refusal below is testable as data — the same
 * reason the replication session takes messages rather than a stream.
 *
 * **A declared length is a claim.** It is checked against the frame limit *before* anything is
 * buffered against it, because the alternative is that a four-byte prefix reserves however much
 * memory the sender felt like naming. That is the cheapest denial of service a framed protocol
 * offers, and it costs the attacker four bytes.
 */
export class Deframer {
  private buffer = new Uint8Array(0);

  /** Feed bytes; returns every complete payload they completed, in order. */
  push(chunk: Uint8Array): Uint8Array[] {
    const joined = new Uint8Array(this.buffer.length + chunk.length);
    joined.set(this.buffer, 0);
    joined.set(chunk, this.buffer.length);
    this.buffer = joined;

    const out: Uint8Array[] = [];
    for (;;) {
      if (this.buffer.length < SWARM_LIMITS.prefixBytes) break;
      const length = new DataView(
        this.buffer.buffer,
        this.buffer.byteOffset,
        this.buffer.byteLength,
      ).getUint32(0, false);

      // Checked before buffering, not after. There is no resynchronising from a bad length on a
      // stream protocol -- the next byte could be anything -- so the connection is finished.
      if (length > SWARM_LIMITS.frameBytes) {
        throw new FramingError(
          'FRAME_TOO_LARGE',
          `a peer declared a ${length}-byte frame, over the ${SWARM_LIMITS.frameBytes} limit`,
        );
      }
      if (length === 0) {
        throw new FramingError('FRAME_EMPTY', 'a zero-length frame carries no message');
      }
      if (this.buffer.length < SWARM_LIMITS.prefixBytes + length) break;

      out.push(this.buffer.slice(SWARM_LIMITS.prefixBytes, SWARM_LIMITS.prefixBytes + length));
      this.buffer = this.buffer.slice(SWARM_LIMITS.prefixBytes + length);
    }
    return out;
  }

  /** Bytes held awaiting the rest of a frame. Bounded by the frame limit plus the prefix. */
  get pending(): number {
    return this.buffer.length;
  }
}

/**
 * The minimum a stream must offer for this binding to drive it.
 *
 * One `on` signature rather than an overload set, and the reason is worth a line: overloads force
 * every implementation of this interface -- including a test double -- through a cast, and
 * `scripts/check-source-hygiene.py` refuses `as unknown as` because it silences exactly the
 * checks that catch a dropped field. An interface a caller cannot satisfy without an escape hatch
 * is an interface that has been written for one implementation.
 */
export interface PeerStream {
  write(bytes: Uint8Array): void;
  on(event: 'data' | 'error' | 'close', listener: (chunk: Uint8Array) => void): void;
  destroy(): void;
}

/** What one peer connection reported while it was open. */
export interface PeerOutcome {
  applied: number;
  rejected: number;
  deferred: number;
  duplicates: number;
  equivocations: number;
}

/**
 * Drive one peer connection.
 *
 * Returns the running totals, which the caller may watch. Exported separately from the swarm so
 * that a different transport -- a Unix socket, a test pipe, a file replayed from disk -- reuses
 * every line of it, which is what makes 2.2's "not normative" true rather than merely stated.
 */
export function drivePeer(
  stream: PeerStream,
  sink: ReplicationSink,
  now: () => number,
): PeerOutcome {
  const session = new ReplicationSession(sink);
  const deframer = new Deframer();
  const outcome: PeerOutcome = {
    applied: 0,
    rejected: 0,
    deferred: 0,
    duplicates: 0,
    equivocations: 0,
  };

  const send = (message: Message): void => {
    try {
      stream.write(frame(encodeMessage(message)));
    } catch {
      // A write that fails is a connection that is gone. There is nothing to recover and nothing
      // to report to a peer that is no longer listening.
      stream.destroy();
    }
  };

  /**
   * Ask for whatever this peer does not have yet.
   *
   * **The half a driver forgets.** The session answers questions and never asks them: `nextWant`
   * exists precisely so that the *transport* decides when to pull, since how aggressively to sync
   * is a resource decision and not a protocol one. A driver that only sends HELLO and replies is
   * a peer that can serve and can never catch up -- and two of them connect, greet each other,
   * and sit there permanently diverged while looking exactly like a working connection. That was
   * the first version of this function, and the convergence test is what found it.
   *
   * Called after every message, because `remoteLength` and the local length both move.
   */
  const pump = (): void => {
    if (!session.ready) return;
    for (;;) {
      const want = session.nextWant(sink.length());
      if (want === null) break;
      send(want);
    }
  };

  const record = (result: ReceiveOutcome): void => {
    outcome.applied += result.applied;
    outcome.rejected += result.rejected;
    outcome.deferred += result.deferred;
    outcome.duplicates += result.duplicates;
    outcome.equivocations += result.equivocations.length;
    for (const reply of result.replies) send(reply);
    pump();
  };

  send(session.open());

  stream.on('data', (chunk: Uint8Array) => {
    let payloads: Uint8Array[];
    try {
      payloads = deframer.push(chunk);
    } catch {
      // Framing is unrecoverable by construction; see Deframer.
      stream.destroy();
      return;
    }
    for (const payload of payloads) {
      let message: Message;
      try {
        message = decodeMessage(payload);
      } catch (error) {
        // A message this peer cannot read is NOT fatal to the connection. REPLICATION.md 3.2:
        // refusing to speak to a peer that knows a message you do not is how a protocol becomes
        // unextendable. Counted and dropped.
        if (error instanceof ReplicationError) {
          outcome.rejected += 1;
          continue;
        }
        stream.destroy();
        return;
      }
      try {
        record(session.receive(message, now()));
      } catch {
        stream.destroy();
        return;
      }
    }
  });

  stream.on('error', () => stream.destroy());
  return outcome;
}

/** A joined swarm. */
export interface Swarm {
  /** Peers currently connected. */
  readonly peers: number;
  leave(): Promise<void>;
}

/** What `joinSwarm` needs. `swarm` is a Hyperswarm instance, injected so tests can supply one. */
export interface SwarmOptions {
  readonly swarm: {
    on(event: 'connection', listener: (stream: PeerStream, info: unknown) => void): void;
    join(topic: Uint8Array, options?: { server?: boolean; client?: boolean }): { flushed(): Promise<void> };
    destroy(): Promise<void>;
  };
  readonly sink: ReplicationSink;
  readonly now: () => number;
}

/**
 * Join the replication topic and drive every peer that connects.
 *
 * The Hyperswarm instance is injected rather than constructed here. That is not test scaffolding:
 * it is what keeps this module from being the place that decides a VayuWeb node must speak
 * HyperDHT, which 2.2 forbids in terms.
 */
export async function joinSwarm(options: SwarmOptions): Promise<Swarm> {
  let peers = 0;

  options.swarm.on('connection', (stream: PeerStream) => {
    if (peers >= SWARM_LIMITS.connections) {
      stream.destroy();
      return;
    }
    peers += 1;
    stream.on('close', () => {
      peers -= 1;
    });
    // The remote's authenticated public key is available here and is deliberately not read.
    // REPLICATION.md 2.3: nothing about the channel is evidence about a record.
    drivePeer(stream, options.sink, options.now);
  });

  const discovery = options.swarm.join(replicationTopic(), { server: true, client: true });
  await discovery.flushed();

  return {
    get peers() {
      return peers;
    },
    leave: () => options.swarm.destroy(),
  };
}
