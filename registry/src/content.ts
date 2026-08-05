/**
 * Content addressing: turning a site's bytes into the CID a registry record points at.
 *
 * docs/spec/HOSTING.md, "Content addressing" and "The publish flow", are authoritative.
 *
 * ## Why these parameters and not the defaults
 *
 * Every value here is fixed by the specification rather than left to a library's defaults, and
 * the reason is interoperability of a specific and unforgiving kind: two publishers importing the
 * same directory MUST produce the same CID. A different chunk size, a different leaf codec or a
 * different directory sort order produces a different root hash for identical bytes, and the
 * failure is silent — both CIDs resolve, both sites work, and nobody notices the namespace has
 * two addresses for one site until someone tries to verify a third party's copy.
 *
 * So: fixed-size chunking rather than content-defined, because it is deterministic across
 * implementations; raw leaves, so a single-block file's CID is the hash of the file itself; and
 * sha2-256 rather than the BLAKE2b-256 used for registry record hashes.
 *
 * That last divergence looks like an inconsistency and is a deliberate one. Registry hashing is
 * internal to VayuWeb and free to pick the faster function. Content hashing has to interoperate
 * with the existing IPFS network, where sha2-256 is what other nodes and gateways expect — and a
 * VayuWeb site that no ordinary IPFS node can fetch would be a parallel web in a much lonelier
 * sense than intended.
 */

import { createHash } from 'node:crypto';

/** The fixed import parameters. HOSTING.md, "Content addressing". */
export const CID_PARAMETERS = {
  /** CIDv1. Version 0 is base58btc dag-pb only and cannot express a raw leaf. */
  version: 1,
  /** Fixed-size chunker, 256 KiB. Deterministic across implementations, unlike Rabin. */
  chunkBytes: 262_144,
  /** Maximum links per UnixFS node in the balanced DAG. */
  maxLinks: 174,
  /** Raw block codec: a leaf's CID is the hash of the leaf's bytes and nothing else. */
  codecRaw: 0x55,
  /** dag-pb, for directories and for files that need more than one block. */
  codecDagPb: 0x70,
  /** sha2-256, for interoperability with the IPFS network. */
  multihashSha2_256: 0x12,
  /** sha2-256 digest length in bytes. */
  digestBytes: 32,
} as const;

/** Multibase prefix for lowercase base32 without padding. */
export const MULTIBASE_BASE32 = 'b';

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

export class ContentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContentError';
  }
}

/**
 * RFC 4648 base32, lowercase, **without padding**.
 *
 * Written out rather than taken from a library because multibase base32 differs from the default
 * in two ways that are easy to get wrong and silent when wrong: the alphabet is lowercase, and
 * there is no `=` padding. A CID that round-trips through a padding-emitting encoder is a
 * different string for the same bytes, and string equality is how CIDs get compared.
 */
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** Decode lowercase unpadded base32, refusing anything outside the alphabet. */
export function base32Decode(text: string): Uint8Array {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const character of text) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index === -1) {
      throw new ContentError(`${JSON.stringify(character)} is not a base32 character`);
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

/** A decoded CID, in the only shape this specification admits. */
export interface Cid {
  readonly version: number;
  readonly codec: number;
  readonly digest: Uint8Array;
}

/**
 * Encode a CID to its text form.
 *
 * Bytes are `version || codec || multihash-code || digest-length || digest`, each as an unsigned
 * varint. Every value here is below 128, so each varint is one byte — but the varint rule is what
 * the format says, and an implementation that hard-codes single bytes will produce wrong output
 * the first time a value exceeds 127. The encoder below is written for the general case.
 */
export function encodeCid(cid: Cid): string {
  if (cid.digest.length !== CID_PARAMETERS.digestBytes) {
    throw new ContentError(
      `a sha2-256 digest is ${CID_PARAMETERS.digestBytes} bytes, got ${cid.digest.length}`,
    );
  }
  const header = [
    ...varint(cid.version),
    ...varint(cid.codec),
    ...varint(CID_PARAMETERS.multihashSha2_256),
    ...varint(cid.digest.length),
  ];
  const bytes = Uint8Array.from([...header, ...cid.digest]);
  return MULTIBASE_BASE32 + base32Encode(bytes);
}

/**
 * Decode a CID, refusing every form this specification does not use.
 *
 * Refusing rather than accommodating is the point. A CIDv0, a base58 CID, a BLAKE3 multihash or a
 * dag-json codec are all valid CIDs somewhere; accepting one here would mean a registry record
 * could point at content this resolver cannot address the way the specification says it must, and
 * "we accepted it and did something reasonable" is how two implementations stop agreeing.
 */
export function decodeCid(text: string): Cid {
  if (!text.startsWith(MULTIBASE_BASE32)) {
    throw new ContentError(
      `expected a ${MULTIBASE_BASE32}-prefixed base32 CID; CIDv0 and other multibases are not used`,
    );
  }
  const bytes = base32Decode(text.slice(1));
  let at = 0;
  const read = (): number => {
    const [value, size] = readVarint(bytes, at);
    at += size;
    return value;
  };

  const version = read();
  if (version !== CID_PARAMETERS.version) {
    throw new ContentError(`only CIDv1 is used, got v${version}`);
  }
  const codec = read();
  if (codec !== CID_PARAMETERS.codecRaw && codec !== CID_PARAMETERS.codecDagPb) {
    throw new ContentError(`codec 0x${codec.toString(16)} is not raw or dag-pb`);
  }
  const multihash = read();
  if (multihash !== CID_PARAMETERS.multihashSha2_256) {
    throw new ContentError(`only sha2-256 is used, got multihash code 0x${multihash.toString(16)}`);
  }
  const length = read();
  if (length !== CID_PARAMETERS.digestBytes) {
    throw new ContentError(
      `a sha2-256 digest is ${CID_PARAMETERS.digestBytes} bytes, got ${length}`,
    );
  }
  const digest = bytes.subarray(at);
  if (digest.length !== length) {
    throw new ContentError(`digest is ${digest.length} bytes, header declared ${length}`);
  }
  return { version, codec, digest };
}

/** Unsigned LEB128, as multiformats uses. */
function varint(value: number): number[] {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ContentError(`varint values are non-negative integers, got ${value}`);
  }
  const out: number[] = [];
  let remaining = value;
  while (remaining >= 0x80) {
    out.push((remaining & 0x7f) | 0x80);
    remaining = Math.floor(remaining / 128);
  }
  out.push(remaining);
  return out;
}

function readVarint(bytes: Uint8Array, at: number): [number, number] {
  let value = 0;
  let shift = 1;
  let index = at;
  for (;;) {
    if (index >= bytes.length) throw new ContentError('truncated varint');
    const byte = bytes[index]!;
    value += (byte & 0x7f) * shift;
    index += 1;
    if ((byte & 0x80) === 0) break;
    shift *= 128;
    // A varint long enough to exceed the safe integer range is malformed input, not a large
    // number: every field this decoder reads is a small constant.
    if (shift > Number.MAX_SAFE_INTEGER) throw new ContentError('varint is too long');
  }
  return [value, index - at];
}

/**
 * Split bytes into fixed-size chunks.
 *
 * The empty input produces exactly one empty chunk rather than none. A file of zero bytes is a
 * file, it has a CID, and returning no chunks would make it addressless — which is the kind of
 * edge case that only shows up when someone publishes a placeholder.
 */
export function chunk(bytes: Uint8Array, size: number = CID_PARAMETERS.chunkBytes): Uint8Array[] {
  if (size <= 0) throw new ContentError('chunk size must be positive');
  if (bytes.length === 0) return [new Uint8Array(0)];
  const out: Uint8Array[] = [];
  for (let at = 0; at < bytes.length; at += size) {
    out.push(bytes.subarray(at, Math.min(at + size, bytes.length)));
  }
  return out;
}

/** sha2-256, the content-side hash. */
export function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

/**
 * The CID of a raw leaf: the hash of the bytes, and nothing else.
 *
 * This is what "raw leaves" buys. A single-block file's CID is the sha2-256 of the file, so a
 * reader can verify it with a command-line hash tool and no VayuWeb software at all — which makes
 * the verification story explainable rather than merely true.
 */
export function rawLeafCid(bytes: Uint8Array): string {
  if (bytes.length > CID_PARAMETERS.chunkBytes) {
    throw new ContentError(
      `a raw leaf is at most ${CID_PARAMETERS.chunkBytes} bytes; ${bytes.length} needs a DAG`,
    );
  }
  return encodeCid({ version: 1, codec: CID_PARAMETERS.codecRaw, digest: sha256(bytes) });
}

/**
 * Whether a file fits in one raw leaf, and therefore needs no dag-pb wrapper at all.
 *
 * Exposed because the publish flow branches on it and the branch is worth naming: a site of small
 * files is entirely raw leaves plus directory nodes, which is the common case and the one whose
 * CIDs are independently checkable.
 */
export function fitsInOneLeaf(bytes: Uint8Array): boolean {
  return bytes.length <= CID_PARAMETERS.chunkBytes;
}
