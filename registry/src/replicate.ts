/**
 * The replication protocol state machine: many machines, one registry state.
 *
 * docs/spec/REPLICATION.md is authoritative. Nothing here relaxes it, and where the two could
 * disagree the specification wins.
 *
 * Three properties carry the whole design, and each is a refusal rather than a feature.
 *
 * **Replication transports records and decides nothing.** Every record is verified locally, by
 * the same `verify()` a locally created record passes, against this peer's clock and this peer's
 * view of prior state. There is no trusted peer, no "already checked upstream" path, and no
 * shortcut for a peer we have talked to before. A record's authority is its signature; the
 * channel adds nothing to it.
 *
 * **Merging is set-based.** The resulting state is a function of the *set* of valid records
 * held — never of which peer sent one, in what order it arrived, or where it sat in anyone's log.
 * A state that depends on delivery order is a state whoever controls delivery can choose, and
 * that was a real defect here rather than a hypothetical one: the convergence rule decided
 * conflicts by local log position until Phase 2 asked what two peers do, at which point it became
 * a permanent namespace fork that any relay could trigger for free.
 *
 * **Nothing is allocated for what a peer merely asserts.** `HELLO.len` is a claim, not a
 * measurement. A peer announcing a log of 2^53 records costs this one the size of the message
 * and no more. Every limit in {@link LIMITS} exists because local verification (above) leaves
 * resource exhaustion as the only attack a hostile peer retains.
 *
 * ## What this module does not do
 *
 * No transport. The session consumes and produces messages; carrying them is somebody else's
 * job, and deliberately so — Article 4 forbids any function of the protocol requiring a single
 * party's availability, and a protocol written against one discovery network makes that
 * network's operators load-bearing. Hyperswarm is the intended first binding and is not
 * normative.
 *
 * No peer identity, reputation, membership or scoring. Those are the materials a governance
 * layer gets built from, and Article 39 says there is no governing body. A peer here is a source
 * of bytes that are checked.
 */

import { decode, encode, type CborMap, type CborValue } from './cbor.ts';
import { isEquivocation, type Candidate } from './converge.ts';
import { parseRecordBytes } from './record.ts';
import { recordHashFromBytes } from './domain.ts';
import type { Verdict } from './verify.ts';

/** Protocol version carried in HELLO. A peer MUST reject a major version it does not implement. */
export const PROTOCOL_VERSION = 1;

/**
 * Every bound the protocol enforces, in one place so a reviewer can see the whole budget.
 *
 * REPLICATION.md section 5 states each with its reasoning. They are collected here rather than
 * scattered as literals because a limit nobody can enumerate is a limit nobody audits.
 */
export const LIMITS = {
  /** Whole-message encoding. Holds a full RECORDS batch with framing and nothing more. */
  messageBytes: 65_536,
  /** How many records one WANT may ask for. A syncing peer sends many, not one large one. */
  wantCount: 256,
  /** How many records one RECORDS may carry. Matches wantCount so an honest reply is never split. */
  recordsPerBatch: 256,
  /** REGISTRY.md's record limit, checked before parsing rather than after. */
  recordBytes: 4_096,
  /** In-flight WANTs per connection, bounding memory held for requests. */
  outstandingWants: 8,
  /** Records held awaiting a clock-skew window. Bounded: an attacker allocates these by dating
   *  records into the near future. Oldest evicted first. */
  deferred: 1_024,
} as const;

export interface Hello {
  readonly t: 'HELLO';
  readonly v: number;
  readonly len: number;
  readonly root: Uint8Array;
}

export interface Want {
  readonly t: 'WANT';
  readonly from: number;
  readonly count: number;
}

export interface Records {
  readonly t: 'RECORDS';
  readonly from: number;
  readonly recs: readonly Uint8Array[];
}

export interface CheckpointMessage {
  readonly t: 'CHECKPOINT';
  readonly len: number;
  readonly treeRoot: Uint8Array;
  readonly indexRoot: Uint8Array;
  readonly liveNames: number;
}

export interface EquivocationMessage {
  readonly t: 'EQUIVOCATION';
  readonly a: Uint8Array;
  readonly b: Uint8Array;
}

export type Message = Hello | Want | Records | CheckpointMessage | EquivocationMessage;

export type ReplicationRejection =
  | 'TOO_LARGE'
  | 'NON_CANONICAL'
  | 'MALFORMED'
  | 'UNKNOWN_TYPE'
  | 'UNSUPPORTED_VERSION'
  | 'HELLO_EXPECTED'
  | 'HELLO_REPEATED'
  | 'LIMIT_EXCEEDED'
  | 'NOT_EQUIVOCATION';

export class ReplicationError extends Error {
  readonly code: ReplicationRejection;
  constructor(code: ReplicationRejection, message: string) {
    super(`${code}: ${message}`);
    this.name = 'ReplicationError';
    this.code = code;
  }
}

/**
 * What a session needs from the local registry.
 *
 * Narrow on purpose. A session that could reach the whole {@link import('./store.ts').Store}
 * could reach `writeLog`, and the point of the interface is that a remote peer's bytes can only
 * ever arrive through `append`, which verifies.
 */
export interface ReplicationSink {
  /** Verify and merge one record encoding. Returns the local verdict; never throws on rejection. */
  append(bytes: Uint8Array, now: number): Verdict;
  /** How many records this peer's own log holds. A measurement, never a claim. */
  length(): number;
  /** The encoding at an index of this peer's own log, or null. */
  encodingAt(index: number): Uint8Array | null;
  /** This peer's merkle tree root at its current length. */
  treeRoot(): Uint8Array;
}

/** What one received message did, reported rather than inferred. */
export interface ReceiveOutcome {
  readonly replies: readonly Message[];
  readonly applied: number;
  readonly rejected: number;
  readonly deferred: number;
  /** Records already held. Accepted, changed nothing, and deliberately not counted as progress. */
  readonly duplicates: number;
  /** Equivocation evidence this message produced or confirmed, for the caller to record. */
  readonly equivocations: readonly EquivocationMessage[];
}

const EMPTY: ReceiveOutcome = {
  replies: [],
  applied: 0,
  rejected: 0,
  deferred: 0,
  duplicates: 0,
  equivocations: [],
};

/* -------------------------------------------------------------------------- */
/* Encoding                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Encode a message as deterministic CBOR.
 *
 * Deterministic for the same reason records are: an encoding a peer can vary without changing the
 * content is an encoding two peers can disagree about while both being right.
 */
export function encodeMessage(message: Message): Uint8Array {
  const map: CborMap = new Map<string | Uint8Array, CborValue>();
  map.set('t', message.t);
  switch (message.t) {
    case 'HELLO':
      map.set('v', message.v);
      map.set('len', message.len);
      map.set('root', message.root);
      break;
    case 'WANT':
      map.set('from', message.from);
      map.set('count', message.count);
      break;
    case 'RECORDS':
      map.set('from', message.from);
      map.set('recs', [...message.recs]);
      break;
    case 'CHECKPOINT':
      map.set('len', message.len);
      map.set('treeRoot', message.treeRoot);
      map.set('indexRoot', message.indexRoot);
      map.set('liveNames', message.liveNames);
      break;
    case 'EQUIVOCATION':
      map.set('a', message.a);
      map.set('b', message.b);
      break;
  }
  const bytes = encode(map);
  if (bytes.length > LIMITS.messageBytes) {
    throw new ReplicationError(
      'TOO_LARGE',
      `message encodes to ${bytes.length} bytes, over the ${LIMITS.messageBytes} limit`,
    );
  }
  return bytes;
}

function uint(map: CborMap, key: string): number {
  const value = map.get(key);
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new ReplicationError('MALFORMED', `${key} must be an unsigned integer`);
  }
  return value;
}

function bstr(map: CborMap, key: string, length?: number): Uint8Array {
  const value = map.get(key);
  if (!(value instanceof Uint8Array)) {
    throw new ReplicationError('MALFORMED', `${key} must be a byte string`);
  }
  if (length !== undefined && value.length !== length) {
    throw new ReplicationError('MALFORMED', `${key} must be ${length} bytes, got ${value.length}`);
  }
  return value;
}

/**
 * Decode a message, enforcing size and shape before anything is believed.
 *
 * The size check runs before decoding rather than after: a decoder is the one piece of this that
 * a remote peer's bytes reach first, and asking it to chew through a megabyte to discover the
 * message was too big is the denial of service the limit exists to prevent.
 */
export function decodeMessage(bytes: Uint8Array): Message {
  if (bytes.length > LIMITS.messageBytes) {
    throw new ReplicationError(
      'TOO_LARGE',
      `message is ${bytes.length} bytes, over the ${LIMITS.messageBytes} limit`,
    );
  }

  let value: CborValue;
  try {
    value = decode(bytes);
  } catch (error) {
    throw new ReplicationError('NON_CANONICAL', `not deterministic CBOR: ${String(error)}`);
  }
  if (!(value instanceof Map)) throw new ReplicationError('MALFORMED', 'message is not a map');
  const map = value;

  const type = map.get('t');
  if (typeof type !== 'string') throw new ReplicationError('MALFORMED', 't must be text');

  switch (type) {
    case 'HELLO':
      return { t: 'HELLO', v: uint(map, 'v'), len: uint(map, 'len'), root: bstr(map, 'root', 32) };
    case 'WANT':
      return { t: 'WANT', from: uint(map, 'from'), count: uint(map, 'count') };
    case 'RECORDS': {
      const recs = map.get('recs');
      if (!Array.isArray(recs)) throw new ReplicationError('MALFORMED', 'recs must be an array');
      if (recs.length > LIMITS.recordsPerBatch) {
        throw new ReplicationError(
          'LIMIT_EXCEEDED',
          `batch of ${recs.length} exceeds the ${LIMITS.recordsPerBatch} limit`,
        );
      }
      const out: Uint8Array[] = [];
      for (const entry of recs) {
        if (!(entry instanceof Uint8Array)) {
          throw new ReplicationError('MALFORMED', 'recs must hold byte strings');
        }
        out.push(entry);
      }
      return { t: 'RECORDS', from: uint(map, 'from'), recs: out };
    }
    case 'CHECKPOINT':
      return {
        t: 'CHECKPOINT',
        len: uint(map, 'len'),
        treeRoot: bstr(map, 'treeRoot', 32),
        indexRoot: bstr(map, 'indexRoot', 32),
        liveNames: uint(map, 'liveNames'),
      };
    case 'EQUIVOCATION':
      return { t: 'EQUIVOCATION', a: bstr(map, 'a'), b: bstr(map, 'b') };
    default:
      throw new ReplicationError('UNKNOWN_TYPE', `unknown message type ${JSON.stringify(type)}`);
  }
}

/* -------------------------------------------------------------------------- */
/* Equivocation evidence                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Check equivocation evidence from its two encodings alone.
 *
 * Self-contained on purpose, and this is the property that makes the message worth forwarding:
 * a recipient verifies it without trusting the sender, without holding prior state, and without
 * having been online when it happened. A report that must be believed is a report that can be
 * faked.
 *
 * Note what this does NOT check: whether either record would be accepted by a verifier. An
 * equivocation is two signatures by one key over two futures for one name, and that is a fact
 * about the bytes whether or not either record is otherwise valid. Requiring validity would let
 * an equivocator escape the record by making both halves invalid in some unrelated way.
 */
export function verifyEquivocation(evidence: EquivocationMessage): boolean {
  if (evidence.a.length > LIMITS.recordBytes || evidence.b.length > LIMITS.recordBytes) {
    return false;
  }
  let left: Candidate;
  let right: Candidate;
  try {
    left = {
      record: parseRecordBytes(evidence.a),
      hash: recordHashFromBytes(evidence.a),
      logIndex: null,
      valid: true,
    };
    right = {
      record: parseRecordBytes(evidence.b),
      hash: recordHashFromBytes(evidence.b),
      logIndex: null,
      valid: true,
    };
  } catch {
    return false;
  }
  return isEquivocation(left, right);
}

/* -------------------------------------------------------------------------- */
/* The session                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * One replication conversation with one peer.
 *
 * Symmetric: there is no client and no server. An implementation that assigns those roles has
 * created an asymmetry the design does not have, and asymmetries are where privileged parties
 * come from.
 */
export class ReplicationSession {
  private readonly sink: ReplicationSink;
  private helloSent = false;
  private helloReceived = false;
  private remoteLength = 0;
  private outstanding = 0;
  private readonly deferredQueue: Array<{ bytes: Uint8Array; at: number }> = [];

  constructor(sink: ReplicationSink) {
    this.sink = sink;
  }

  /** True once the remote has introduced itself. */
  get ready(): boolean {
    return this.helloReceived;
  }

  /** The length the remote *claims*. Never allocated against — see LIMITS and REPLICATION.md 5.1. */
  get remoteClaimedLength(): number {
    return this.remoteLength;
  }

  /** How many records are held awaiting their clock-skew window. */
  get deferredCount(): number {
    return this.deferredQueue.length;
  }

  /** The opening HELLO. Sent exactly once, before anything else. */
  open(): Hello {
    if (this.helloSent) {
      throw new ReplicationError('HELLO_REPEATED', 'HELLO has already been sent');
    }
    this.helloSent = true;
    return {
      t: 'HELLO',
      v: PROTOCOL_VERSION,
      len: this.sink.length(),
      root: this.sink.treeRoot(),
    };
  }

  /**
   * Handle one message, returning what it did and what to send back.
   *
   * Never throws for anything a hostile peer controls. A protocol whose parser throws on hostile
   * input pushes the decision about whether that kills the connection out to a caller who has
   * less context, and callers reliably decide "close it" — which turns malformed input into a
   * denial of service against the peers who did nothing wrong.
   */
  receive(message: Message, now: number): ReceiveOutcome {
    if (!this.helloReceived && message.t !== 'HELLO') {
      // REPLICATION.md 3.4: nothing to want until the remote states what it has.
      return EMPTY;
    }

    switch (message.t) {
      case 'HELLO':
        return this.onHello(message);
      case 'WANT':
        return this.onWant(message);
      case 'RECORDS':
        return this.onRecords(message, now);
      case 'EQUIVOCATION':
        return this.onEquivocation(message);
      case 'CHECKPOINT':
        // A checkpoint is evidence for a light client to weigh, not an instruction to this
        // session. Comparing it against local state is checkpoint.ts's job and a caller's
        // decision; accepting it here would make a remote assertion part of our state.
        return EMPTY;
    }
  }

  private onHello(message: Hello): ReceiveOutcome {
    if (this.helloReceived) {
      // REPLICATION.md 3.3. A peer that may restate its length can rewind its own history
      // mid-session and invite us to reconcile against a moving target.
      return EMPTY;
    }
    if (message.v !== PROTOCOL_VERSION) return EMPTY;
    this.helloReceived = true;
    this.remoteLength = message.len;
    return EMPTY;
  }

  private onWant(message: Want): ReceiveOutcome {
    if (message.count === 0 || message.count > LIMITS.wantCount) return EMPTY;

    const recs: Uint8Array[] = [];
    const length = this.sink.length();
    for (let index = message.from; index < message.from + message.count; index += 1) {
      if (index >= length) break;
      const encoding = this.sink.encodingAt(index);
      if (encoding === null) break;
      recs.push(encoding);
    }
    if (recs.length === 0) {
      // REPLICATION.md 4.3: declining is not an error. Serving is voluntary and no peer owes
      // another bandwidth, so silence here must not be reported as a failure by either side.
      return EMPTY;
    }
    return { ...EMPTY, replies: [{ t: 'RECORDS', from: message.from, recs }] };
  }

  /**
   * Apply a batch, each record independently.
   *
   * "Independently" is the load-bearing word. A single malformed record in a batch of two hundred
   * is an attacker's cheapest denial of service if it discards the other hundred and ninety-nine,
   * so nothing here short-circuits and nothing propagates a throw.
   */
  private onRecords(message: Records, now: number): ReceiveOutcome {
    if (message.recs.length > LIMITS.recordsPerBatch) return { ...EMPTY, rejected: 1 };

    let applied = 0;
    let rejected = 0;
    let deferred = 0;
    let duplicates = 0;

    for (const encoding of message.recs) {
      if (encoding.length > LIMITS.recordBytes) {
        rejected += 1;
        continue;
      }
      let verdict: Verdict;
      try {
        verdict = this.sink.append(encoding, now);
      } catch {
        // A sink that throws is a local defect, but a remote peer must not be able to convert it
        // into a dropped batch. Counted as a rejection and the batch continues.
        rejected += 1;
        continue;
      }
      if (verdict.outcome === 'accept') {
        // A duplicate is accepted and changes nothing, so it is not progress. Counting it as
        // applied would let a peer resending one record forever look like a peer making
        // progress forever, which is a session that never ends for the cost of one record.
        if (verdict.duplicate === true) duplicates += 1;
        else applied += 1;
      } else if (verdict.outcome === 'defer') {
        this.holdDeferred(encoding, now);
        deferred += 1;
      } else rejected += 1;
    }

    if (this.outstanding > 0) this.outstanding -= 1;
    return { ...EMPTY, applied, rejected, deferred, duplicates };
  }

  /**
   * Hold a clock-skewed record for later, bounded, oldest evicted first.
   *
   * Deferral is memory an attacker allocates by dating records a few minutes into the future,
   * which costs them a proof-of-work each but costs us nothing to refuse. The bound is what makes
   * the refusal cheap.
   */
  private holdDeferred(bytes: Uint8Array, at: number): void {
    if (this.deferredQueue.length >= LIMITS.deferred) this.deferredQueue.shift();
    this.deferredQueue.push({ bytes, at });
  }

  /**
   * Retry held records whose skew window has passed.
   *
   * Returns how many were applied. A record that still defers stays held; one that now rejects is
   * dropped, because a record that has become invalid rather than merely early will not improve.
   */
  retryDeferred(now: number): number {
    if (this.deferredQueue.length === 0) return 0;
    const pending = this.deferredQueue.splice(0, this.deferredQueue.length);
    let applied = 0;
    for (const held of pending) {
      let verdict: Verdict;
      try {
        verdict = this.sink.append(held.bytes, now);
      } catch {
        continue;
      }
      if (verdict.outcome === 'accept') applied += 1;
      else if (verdict.outcome === 'defer') this.holdDeferred(held.bytes, held.at);
    }
    return applied;
  }

  private onEquivocation(message: EquivocationMessage): ReceiveOutcome {
    // REPLICATION.md 6.3: verify independently before recording or forwarding. A report taken on
    // trust is a way to get a name reported as compromised by anyone who can send a message.
    if (!verifyEquivocation(message)) return { ...EMPTY, rejected: 1 };
    return { ...EMPTY, equivocations: [message] };
  }

  /**
   * The next range to request, or null when there is nothing to ask for.
   *
   * Bounded by {@link LIMITS.wantCount} per request and by {@link LIMITS.outstandingWants} in
   * flight. `remoteLength` is a claim, so this only ever produces a request for the next bounded
   * window — a peer claiming 2^53 records gets asked for 256 of them, not 2^53.
   */
  nextWant(haveThrough: number): Want | null {
    if (!this.helloReceived) return null;
    if (this.outstanding >= LIMITS.outstandingWants) return null;
    if (haveThrough >= this.remoteLength) return null;
    const count = Math.min(LIMITS.wantCount, this.remoteLength - haveThrough);
    this.outstanding += 1;
    return { t: 'WANT', from: haveThrough, count };
  }
}
