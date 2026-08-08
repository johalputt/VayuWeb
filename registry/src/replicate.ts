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
import { recordHashFromBytes, signingInput } from './domain.ts';
import { verifyStrict } from './signature.ts';
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
  /**
   * Whole-message encoding.
   *
   * This said "holds a full RECORDS batch with framing and nothing more" and it was false by more
   * than 16x: fifteen maximum-size records fit, and 256 records at the SMALLEST encoding in
   * conformance/vectors.json is already over. `recordsPerBatch` is therefore a bound on array
   * iteration; this is the bound on volume, and `onWant` counts bytes against it.
   */
  messageBytes: 65_536,
  /** How many records one WANT may ask for. A syncing peer sends many, not one large one. */
  wantCount: 256,
  /**
   * How many records one RECORDS may carry.
   *
   * Matches `wantCount`, but NOT so that "an honest reply is never split" — that claim was
   * inverted. An honest reply to a full `WANT` is routinely split, because `messageBytes` binds
   * first and it binds on a byte count the requester has not seen.
   */
  recordsPerBatch: 256,
  /** REGISTRY.md's record limit, checked before parsing rather than after. */
  recordBytes: 4_096,
  /** In-flight WANTs per connection, bounding memory held for requests. */
  outstandingWants: 8,
  /**
   * How long a WANT may stay outstanding before its slot is reclaimed.
   *
   * Section 4.3 makes declining legal and silent, so a slot released only by a reply is a slot a
   * peer can keep by doing nothing. Sixty seconds is far longer than an honest reply takes and far
   * shorter than a connection lives, so it costs a healthy peer nothing and costs a silent one
   * every slot it is sitting on.
   */
  wantDeadlineSeconds: 60,
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
 * Bytes a `RECORDS` message spends on everything that is not a record.
 *
 * The map header, the `t` key and its value, the `from` key and a four-byte index, and the `recs`
 * key with the array header that grows as the array does. Sixty-four bytes is several times what
 * any of that costs, and the margin is the point: this bounds a reply the sender must be able to
 * encode, and one byte short is a dropped connection while one record fewer is a round trip.
 */
const RECORDS_ENVELOPE_BYTES = 64;

/** A byte string as a Set key. Hex rather than `join(',')` so the key length is fixed. */
const toHexKey = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

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
 * Is this record attributable to the key it names as owner, from its own bytes alone?
 *
 * The one signature check equivocation evidence needs. REPLICATION.md 6.2 puts it first in the
 * list of what a recipient checks, and everything downstream depends on it: equivocation is a
 * claim about *who signed*, so evidence carrying no signature by the accused is not weak
 * evidence, it is evidence of nothing.
 *
 * Which signature is the owner's depends on the operation, and both are recoverable from the
 * bytes:
 *
 * - A REGISTER is signed by the key it names. Every other non-TRANSFER operation must carry
 *   `ownerKey == prev.ownerKey` and is signed under the controlling key, which — outside a
 *   settlement window, where only TRANSFER is accepted at all — is that same key. So `sig`
 *   verifies under `ownerKey` for all five.
 * - A TRANSFER's `sig` is the *transferor's*, whose key is not in these bytes at all — that is
 *   the same self-containment gap that gives `VectorState.transferorKey` its reason to exist.
 *   The named owner's own signature is `coSig`, which the schema requires on TRANSFER and
 *   forbids everywhere else, and which verifies under `ownerKey`.
 */
function attributable(candidate: Candidate): boolean {
  const record = candidate.record;
  const signature = record.op === 'TRANSFER' ? record.coSig : record.sig;
  if (signature === null) return false;
  return verifyStrict(record.ownerKey, signingInput(record.map), signature);
}

/**
 * Check equivocation evidence from its two encodings alone.
 *
 * Self-contained on purpose, and this is the property that makes the message worth forwarding:
 * a recipient verifies it without trusting the sender, without holding prior state, and without
 * having been online when it happened. A report that must be believed is a report that can be
 * faked.
 *
 * Note what this does NOT check: whether either record would be **accepted** by a verifier.
 * Expiry, proof of work, chain position and lifecycle state are all reasons a record would be
 * refused, and requiring them here would hand an equivocator a one-line evasion — break your own
 * proof of work in both halves and no report of you can be verified.
 *
 * The signatures are the exception, and the distinction is worth stating because it was got
 * wrong here: a signature is not a validity condition, it is the thing that makes a record
 * *attributable*. Without checking them, an owner key — which is public, and appears in every
 * record its holder ever published — was enough to manufacture evidence against its holder. Mint
 * two records naming the victim as owner for one name at one `seq`, sign both with a key of your
 * own, and every peer receiving the pair recorded it and forwarded it on. That is precisely the
 * mechanism 6.4 refuses when it says a mechanism able to act on evidence is a mechanism able to
 * act on *manufactured* evidence.
 *
 * A limit that remains, stated rather than hidden: attribution is by `ownerKey`, so a transferor
 * signing two different TRANSFERs of one name at one `seq` to two different recipients is not
 * reported — the two records name different owners. Detecting that needs the transferor's key,
 * which is not in the bytes, and evidence that needs outside state is evidence that can be faked
 * by whoever supplies the state.
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
  if (!isEquivocation(left, right)) return false;
  return attributable(left) && attributable(right);
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
  /**
   * When each in-flight WANT was issued, in issue order.
   *
   * A list of instants rather than a counter, because a counter can only be decremented by
   * something happening and the whole defect was that nothing had to happen.
   */
  private outstanding: number[] = [];
  private readonly deferredQueue: Array<{ bytes: Uint8Array; at: number }> = [];
  /** Record hashes currently in {@link deferredQueue}, so a resend costs a peer nothing. */
  private readonly deferredKeys = new Set<string>();

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

    // Truncate to what a `RECORDS` can actually carry, counting BYTES rather than records.
    //
    // Counting only records was wrong for every log with more than a couple of hundred entries,
    // which is every real one. `wantCount` and `recordsPerBatch` are both 256, and 256 records do
    // not fit in a 65,536-byte message: fifteen maximum-size records fit, and 256 at the smallest
    // encoding in this project's own conformance vectors is already over. So the first `WANT` of
    // every cold sync produced a reply this peer could not encode, `send` in swarm.ts swallowed
    // the throw, and the connection was destroyed with the failure attributed to the peer.
    //
    // The budget below is deliberately conservative rather than exact. `RECORDS` carries `t` and
    // `from` beside the array, and a CBOR array's own header grows with its length, so a reply
    // built to the byte is a reply that fails on the header — and the cost of being wrong here is
    // a dropped connection, while the cost of sending one record fewer is one more round trip.
    const budget = LIMITS.messageBytes - RECORDS_ENVELOPE_BYTES;
    const recs: Uint8Array[] = [];
    let used = 0;
    const length = this.sink.length();
    for (let index = message.from; index < message.from + message.count; index += 1) {
      if (index >= length) break;
      const encoding = this.sink.encodingAt(index);
      if (encoding === null) break;
      // Each byte string costs its own CBOR header too, and at these sizes that header is at most
      // three bytes. Charged per record so the running total cannot drift under the real cost.
      const cost = encoding.length + 3;
      if (used + cost > budget && recs.length > 0) break;
      recs.push(encoding);
      used += cost;
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

    // A reply releases the OLDEST outstanding request. The protocol carries no request identifier
    // (REPLICATION.md section 3), so a reply cannot be matched to the `WANT` that prompted it, and
    // "oldest" is chosen because the oldest is the most likely to have been abandoned — releasing
    // it keeps the freshest requests alive.
    //
    // **The residual, stated because an earlier comment here claimed it away.** That comment said
    // releasing the oldest "cannot release the same slot twice". It can, and so can any other
    // choice: if a request's deadline expires and its reply then arrives late, `expireWants` has
    // already reclaimed one slot and this line reclaims a second — for one completed request.
    // Measured, that permits a ninth request against a budget of eight. The mutation that swapped
    // `shift` for `pop` survived precisely because the two are equivalent here, which is what
    // exposed the claim as false.
    //
    // It is bounded rather than closed, and closing it would need a request identifier the wire
    // format does not have: each overshoot costs the peer one late message, so the excess is at
    // most the number of late replies and never accumulates beyond them. `nextWant` re-expires on
    // every call, so the window closes as soon as the late replies stop.
    this.outstanding.shift();
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
    // Deduplicated by record hash, because the bound counts held encodings and the thing being
    // protected is CAPACITY. One postdated record resent 1,024 times used to fill the whole queue
    // with copies of itself and evict every genuine deferral from the front — the attacker
    // spending one record it already had, and the peer losing skew tolerance for everybody.
    //
    // 4.6's silent-drop rule does not cover this: it applies to records the peer "already holds",
    // and a deferred record is precisely one that is not held. The bound was doing exactly what it
    // said and protecting nothing, because a bound on entries only bounds capacity when the
    // entries are distinct.
    const key = toHexKey(recordHashFromBytes(bytes));
    if (this.deferredKeys.has(key)) return;
    if (this.deferredQueue.length >= LIMITS.deferred) {
      const evicted = this.deferredQueue.shift();
      if (evicted !== undefined)
        this.deferredKeys.delete(toHexKey(recordHashFromBytes(evicted.bytes)));
    }
    this.deferredKeys.add(key);
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
    this.deferredKeys.clear();
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
   *
   * **`now` is why this takes a clock at all.** Section 4.3 makes declining legal and silent, and
   * nothing obliges a peer to answer — correctly, since a duty that can be failed is a duty that
   * can be enforced. But the slot was only ever released by a reply arriving, so a peer that
   * greeted and then said nothing took all eight and kept them: `nextWant` returned null for the
   * rest of the connection while the peer broke no rule. The absence of a duty on one side has to
   * be paid for by a bound on the other, and this is that bound.
   */
  nextWant(haveThrough: number, now: number): Want | null {
    if (!this.helloReceived) return null;
    this.expireWants(now);
    if (this.outstanding.length >= LIMITS.outstandingWants) return null;
    if (haveThrough >= this.remoteLength) return null;
    const count = Math.min(LIMITS.wantCount, this.remoteLength - haveThrough);
    this.outstanding.push(now);
    return { t: 'WANT', from: haveThrough, count };
  }

  /**
   * Drop requests whose deadline has passed.
   *
   * Oldest first, because `outstanding` is append-only and therefore already in issue order, and
   * because the oldest is the one most likely to have been abandoned. The requester accuses
   * nobody and records nothing about the peer: 4.5 keeps a non-answer legal, so this is a local
   * decision to stop waiting, not a finding about anyone.
   */
  private expireWants(now: number): void {
    while (
      this.outstanding.length > 0 &&
      now - this.outstanding[0]! >= LIMITS.wantDeadlineSeconds
    ) {
      this.outstanding.shift();
    }
  }
}
