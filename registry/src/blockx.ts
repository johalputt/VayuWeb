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
  /** Blocks one `BLOCKS` may carry. Matches `wantCids` so an honest reply is never split. */
  blocksPerMessage: 64,
  /** REGISTRY.md's `cid` entry bound, checked before decoding an identifier rather than after. */
  cidBytes: 64,
  /** In-flight `BWANT`s per connection, bounding memory held for requests. */
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

/** Encode one message, refusing to emit anything a conforming receiver would reject. */
export function encodeBlockMessage(message: BlockMessage): Uint8Array {
  const map: CborMap = new Map<string | Uint8Array, CborValue>();
  map.set('t', message.t);
  switch (message.t) {
    case 'BHELLO':
      map.set('v', message.v);
      map.set('max', message.max);
      break;
    case 'BWANT':
    case 'BDONE':
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
