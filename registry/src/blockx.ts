/**
 * The block-exchange wire format: four messages, and the bounds on each.
 *
 * [docs/spec/VWIP-0005.md](../../docs/spec/VWIP-0005.md) sections 3 and 5 are authoritative.
 *
 * ## Why this exists before the session does
 *
 * VWIP-0005 is a Draft, and the roadmap's rule is that code written before the specification
 * settles is code that will be thrown away. This module is not an exception to that rule; it is
 * part of settling. VWIP-0000 makes test vectors mandatory for anything observable on the wire,
 * and a vector nobody generated is a hex string somebody typed — which this corpus has learned to
 * distrust, having found several of its own hand-written expectations to be wrong.
 *
 * So the line drawn here is between the **encoding**, which is what the specification fixes and
 * what two implementations must agree on byte for byte, and the **session** — connection state,
 * outstanding-request accounting, the budget across a logical fetch — which is behaviour a
 * specification constrains rather than defines. The encoding is here. The session is not, and
 * will not be until VWIP-0005 leaves Draft.
 *
 * ## What the refusals are for
 *
 * VWIP-0005 2.3 leaves resource exhaustion as the only attack a hostile peer retains, so every
 * bound in {@link BX_LIMITS} is load-bearing and every one of them is checked *at decode*, before
 * the structure it bounds is walked. A limit enforced after iterating the thing it limits is a
 * limit that has already been paid.
 *
 * The rule this module exists to keep is 3.5: a block travels **without** its identifier. The
 * receiver computes the identifier from the octets, which it must do in any case, so a declared
 * identifier alongside the bytes would be either redundant or a lie — and a field that can be a
 * lie is a field somebody eventually believes.
 */

import { decode, encode, type CborMap, type CborValue } from './cbor.ts';

/** The protocol version carried in `BHELLO.v`. VWIP-0005 3.3. */
export const BLOCK_EXCHANGE_VERSION = 1;

/**
 * The discovery topic preimage. VWIP-0005 2.2.
 *
 * The binding that uses it is explicitly non-normative — Article 4 forbids a protocol defined in
 * terms of one discovery network — but the string is fixed so that implementations which do use
 * the reference binding find each other rather than each other's near misses.
 */
export const BLOCK_EXCHANGE_TOPIC_PREIMAGE = 'VayuWeb-BlockExchange-v1';

/**
 * Every bound the wire format enforces, in one place so a reviewer can see the whole budget.
 *
 * VWIP-0005 section 5 states each with its reasoning. Collected here rather than scattered as
 * literals because a limit nobody can enumerate is a limit nobody audits — the same reason
 * `LIMITS` exists in the replication module.
 */
export const BX_LIMITS = {
  /** Whole-message encoding: one maximum block plus CBOR framing and nothing more. */
  messageBytes: 1_114_112,
  /**
   * Octets in one block. Four times the 262,144-byte chunk size, which leaves room for a
   * directory node at the maximum link count while refusing anything that could only be an
   * amplification attempt.
   */
  blockBytes: 1_048_576,
  /** Identifiers one `BWANT` may name. A syncing peer sends many, not one large one. */
  wantCids: 64,
  /**
   * Blocks one `BLOCKS` may carry.
   *
   * Matches `wantCids`, but NOT so that "an honest reply is never split" — that claim was
   * inverted, in this file and in VWIP-0005's own limits table, having already been found and
   * corrected in the sibling protocol. This bounds ARRAY ITERATION. `messageBytes` bounds volume
   * and binds first: at the 262,144-byte chunk size, four blocks fit and the fifth does not, so an
   * honest reply is split as the ordinary case. VWIP-0005 3.6.b, and `blocksReplyFor` below.
   */
  blocksPerMessage: 64,
  /** REGISTRY.md's `cid` entry bound, checked before decoding an identifier rather than after. */
  cidBytes: 64,
  /**
   * In-flight `BWANT`s per connection, bounding memory held for requests.
   *
   * Not enforced by this module — like `unrequestedBlocks` below it is session state, and this
   * module deliberately holds none. It is stated with the rest of the budget so the whole of it is
   * auditable in one place, and qualified because the identically-named limit in `replicate.ts`
   * IS enforced there: an unqualified copy read as though this one were too.
   */
  outstandingWants: 8,
  /** Unrequested blocks tolerated before a peer is spending the receiver's bandwidth on its own
   *  behalf. Not enforced by this module — it is session state — but stated with the rest of the
   *  budget so the whole of it is auditable in one place. */
  unrequestedBlocks: 16,
} as const;

export interface BlockHello {
  readonly t: 'BHELLO';
  readonly v: number;
  /** The largest block THIS peer will accept. A statement, never a request. VWIP-0005 3.4. */
  readonly max: number;
}

export interface BlockWant {
  readonly t: 'BWANT';
  readonly cids: readonly Uint8Array[];
}

export interface Blocks {
  readonly t: 'BLOCKS';
  /** Block octets, without identifiers. VWIP-0005 3.5. */
  readonly blks: readonly Uint8Array[];
}

export interface BlockDone {
  readonly t: 'BDONE';
  /** Requested identifiers not being answered. Carries no reason, by design. VWIP-0005 6.2. */
  readonly cids: readonly Uint8Array[];
}

export type BlockMessage = BlockHello | BlockWant | Blocks | BlockDone;

export type BlockExchangeRejection =
  | 'TOO_LARGE'
  | 'NON_CANONICAL'
  | 'MALFORMED'
  | 'UNKNOWN_TYPE'
  | 'LIMIT_EXCEEDED';

export class BlockExchangeError extends Error {
  readonly code: BlockExchangeRejection;

  constructor(code: BlockExchangeRejection, message: string) {
    super(message);
    this.name = 'BlockExchangeError';
    this.code = code;
  }
}

/* -------------------------------------------------------------------------- */
/* Encoding                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * VWIP-0005 3.6.a: an identifier list MUST NOT name the same identifier twice.
 *
 * Applied to `BDONE` as well as `BWANT`. 6.2 requires a lacking peer and a declining peer to emit
 * the identical message, and a repeat in a refusal is content a receiver can count — so the same
 * rule that makes a repeat an amplification demand in a request makes it a signal in an answer.
 */
function assertDistinct(cids: readonly Uint8Array[]): void {
  const seen = new Set<string>();
  for (const cid of cids) {
    const key = cid.join(',');
    if (seen.has(key)) {
      throw new BlockExchangeError('MALFORMED', 'an identifier is named twice; see 3.6.a');
    }
    seen.add(key);
  }
}

/**
 * Encode one message, refusing to emit anything a conforming receiver would reject.
 *
 * **It used to enforce one of the three sender-side prohibitions and claim all of them.** The size
 * bound was checked; 3.6.a (a `BWANT` MUST NOT name the same identifier twice) and 3.4.a (a peer
 * MUST NOT declare a `max` above the block limit) were not, so this function would emit sixty-four
 * copies of one identifier — a request for one block and a demand for sixty-four, which is the
 * attack 3.6.a was written to close — and a `BHELLO` declaring 2^53 - 1. The vector generator was
 * the proof: it built `blockx/bhello-absurd-max` by calling this function with a value the
 * specification forbids a peer to declare, and got no objection.
 *
 * The reasoning that put the size check here applies unchanged to the other two: the peer best
 * placed to notice is the one that built the message, and a sender that emits something the
 * receiver must refuse has produced a failure that looks like the receiver's fault.
 */
export function encodeBlockMessage(message: BlockMessage): Uint8Array {
  const map: CborMap = new Map<string | Uint8Array, CborValue>();
  map.set('t', message.t);
  switch (message.t) {
    case 'BHELLO':
      // 3.4.a. A declared maximum may only ever be LOWER than the protocol's — lowering it harms
      // nobody but the peer that declared it, while raising it would let a stranger raise the
      // receiver's own limit by asking.
      if (message.max > BX_LIMITS.blockBytes) {
        throw new BlockExchangeError(
          'LIMIT_EXCEEDED',
          `declared max ${message.max} is above the ${BX_LIMITS.blockBytes}-byte block limit`,
        );
      }
      map.set('v', message.v);
      map.set('max', message.max);
      break;
    case 'BWANT':
    case 'BDONE':
      assertDistinct(message.cids);
      map.set('cids', [...message.cids]);
      break;
    case 'BLOCKS':
      map.set('blks', [...message.blks]);
      break;
  }
  const bytes = encode(map);
  // Checked on the way out as well as the way in. A sender that emits something the receiver must
  // refuse has produced a failure that looks like the receiver's fault, and the peer best placed
  // to notice is the one that built the message.
  if (bytes.length > BX_LIMITS.messageBytes) {
    throw new BlockExchangeError(
      'TOO_LARGE',
      `message is ${bytes.length} bytes, over the ${BX_LIMITS.messageBytes} limit`,
    );
  }
  return bytes;
}

/**
 * Build the largest `BLOCKS` reply that actually encodes, and say how many blocks it took.
 *
 * VWIP-0005 3.6.b. This exists because the limits table read as a matched pair — `BWANT.cids` and
 * `BLOCKS.blks` are both 64 — and a responder that gathers 64 blocks has built a reply of up to
 * 64 MiB against a 1,114,112-byte message bound. The identical defect shipped in the sibling
 * protocol on the commonest request there is: the reply could not be encoded, the throw was
 * swallowed by the transport, and the connection died with the failure attributed to the peer.
 *
 * **It encodes to measure rather than estimating from a per-block size.** An estimate is where the
 * sibling fix's first attempt went wrong: CBOR's length prefixes change width at 24, 256 and 65,536
 * bytes, so a per-item constant is right almost everywhere and wrong in narrow bands — and "almost
 * everywhere" is exactly the shape of a bug that survives a test with one block size in it. The
 * cost is one encode per candidate prefix, which is bounded by 64 and paid once per reply.
 *
 * At least one block is always returned, even if that one block does not fit: a responder cannot
 * make progress by sending nothing, and a block over the message bound is a block this peer should
 * never have accepted in the first place. The caller gets the throw from `encodeBlockMessage` and
 * the error names the size, which is the honest failure.
 */
export function blocksReplyFor(blocks: readonly Uint8Array[]): {
  readonly take: number;
  readonly encoded: Uint8Array;
} {
  const room = Math.min(blocks.length, BX_LIMITS.blocksPerMessage);
  let best: { take: number; encoded: Uint8Array } | null = null;
  for (let take = 1; take <= room; take += 1) {
    let encoded: Uint8Array;
    try {
      encoded = encodeBlockMessage({ t: 'BLOCKS', blks: blocks.slice(0, take) });
    } catch {
      break;
    }
    best = { take, encoded };
  }
  if (best !== null) return best;
  // Nothing fit, which means the first block alone is over the bound. Encode it anyway so the
  // caller receives the specific refusal rather than an empty reply that says nothing.
  return { take: 1, encoded: encodeBlockMessage({ t: 'BLOCKS', blks: blocks.slice(0, 1) }) };
}

/**
 * Build the one `BDONE` that answers a `BWANT`, in the request's own order.
 *
 * VWIP-0005 6.2 requires a peer that lacks a block and a peer that declines to send one to emit
 * the identical message. The obligation is on the sender (6.2.a) because only the sender can
 * comply — and it is easy to discharge only the visible half of it.
 *
 * **What a receiver observes is content, count, order and timing.** Byte-identical messages leak
 * anyway if a peer sends one `BDONE` per identifier it lacks and one combined `BDONE` for the ones
 * it refuses, or if it lists the refused ones last. This function closes count and order by
 * construction: exactly one message, and the identifiers in the order the *requester* wrote them,
 * which is a permutation the peer did not choose and which therefore says nothing about what it
 * holds.
 *
 * Timing is left to the caller and stated rather than pretended away — 6.2.c requires the answer
 * to be decided in full before any of it is sent, which is a rule about control flow that no
 * function signature can enforce.
 */
export function blockDoneFor(want: BlockWant, unanswered: readonly Uint8Array[]): BlockDone {
  const key = (cid: Uint8Array): string => cid.join(',');
  const wanted = new Map(want.cids.map((cid, index) => [key(cid), index]));
  for (const cid of unanswered) {
    if (!wanted.has(key(cid))) {
      throw new BlockExchangeError(
        'MALFORMED',
        'a BDONE identifier is not in the request it answers',
      );
    }
  }
  // Sorted by the identifier's position in the REQUEST. Sorting by the bytes themselves would be
  // deterministic too, but it would be a permutation of the peer's choosing rather than of the
  // requester's, and the point is that no choice is being made.
  const seen = new Set(unanswered.map(key));
  return { t: 'BDONE', cids: want.cids.filter((cid) => seen.has(key(cid))) };
}

/* -------------------------------------------------------------------------- */
/* Decoding                                                                    */
/* -------------------------------------------------------------------------- */

function uint(map: CborMap, key: string): number {
  const value = map.get(key);
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new BlockExchangeError('MALFORMED', `${key} must be an unsigned integer`);
  }
  return value;
}

/**
 * A bounded array of byte strings, checked in the order that costs least.
 *
 * Length first, then each element — so an array of a million entries is refused having touched
 * none of them. Reversing those two is how a limit becomes an accounting of work already done.
 */
function bstrArray(map: CborMap, key: string, limit: number, each: number): Uint8Array[] {
  const value = map.get(key);
  if (!Array.isArray(value)) {
    throw new BlockExchangeError('MALFORMED', `${key} must be an array`);
  }
  if (value.length > limit) {
    throw new BlockExchangeError(
      'LIMIT_EXCEEDED',
      `${key} holds ${value.length} entries, over the ${limit} limit`,
    );
  }
  const out: Uint8Array[] = [];
  for (const entry of value) {
    if (!(entry instanceof Uint8Array)) {
      throw new BlockExchangeError('MALFORMED', `${key} must hold byte strings`);
    }
    if (entry.length > each) {
      throw new BlockExchangeError(
        'LIMIT_EXCEEDED',
        `an entry in ${key} is ${entry.length} bytes, over the ${each} limit`,
      );
    }
    out.push(entry);
  }
  return out;
}

/**
 * Decode one message.
 *
 * The whole-message bound is checked against the raw octets before any parsing, because a decoder
 * asked to parse an unbounded input has already lost — VWIP-0005 5.1's rule that nothing is
 * allocated on the basis of an asserted value starts here, with the assertion being the length of
 * the buffer itself.
 */
export function decodeBlockMessage(bytes: Uint8Array): BlockMessage {
  if (bytes.length > BX_LIMITS.messageBytes) {
    throw new BlockExchangeError(
      'TOO_LARGE',
      `message is ${bytes.length} bytes, over the ${BX_LIMITS.messageBytes} limit`,
    );
  }

  let value: CborValue;
  try {
    value = decode(bytes);
  } catch (error) {
    throw new BlockExchangeError('NON_CANONICAL', `not deterministic CBOR: ${String(error)}`);
  }
  if (!(value instanceof Map)) throw new BlockExchangeError('MALFORMED', 'message is not a map');
  const map = value;

  const type = map.get('t');
  if (typeof type !== 'string') throw new BlockExchangeError('MALFORMED', 't must be text');

  switch (type) {
    case 'BHELLO':
      // `max` is read and NOT acted upon here. VWIP-0005 5.1: a peer declaring 2^53 must cost the
      // receiver nothing beyond this message, so nothing downstream may size a buffer from it.
      return { t: 'BHELLO', v: uint(map, 'v'), max: uint(map, 'max') };
    case 'BWANT':
      return { t: 'BWANT', cids: bstrArray(map, 'cids', BX_LIMITS.wantCids, BX_LIMITS.cidBytes) };
    case 'BDONE':
      return { t: 'BDONE', cids: bstrArray(map, 'cids', BX_LIMITS.wantCids, BX_LIMITS.cidBytes) };
    case 'BLOCKS':
      return {
        t: 'BLOCKS',
        blks: bstrArray(map, 'blks', BX_LIMITS.blocksPerMessage, BX_LIMITS.blockBytes),
      };
    default:
      // Ignored rather than fatal, per VWIP-0005 3.2: refusing to speak to a peer that knows a
      // message you do not is how a protocol becomes unextendable. The caller drops the message;
      // the code distinguishes that from a reason to close the connection.
      throw new BlockExchangeError('UNKNOWN_TYPE', `unknown message type ${JSON.stringify(type)}`);
  }
}
