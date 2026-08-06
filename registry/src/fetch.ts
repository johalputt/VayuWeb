/**
 * Verified traversal: turning a root CID and a bag of untrusted blocks into bytes.
 *
 * docs/spec/RESOLUTION.md steps 11 to 13, and clauses 12.1 to 12.3 in particular. This is the
 * mirror of {@link ./unixfs.ts}, and it is the more dangerous half: the encoder's input is the
 * publisher's own files, while everything here arrives from a peer that has no reason to be
 * honest.
 *
 * ## The three rules, and why each needed writing down
 *
 * **Verification is recursive.** Step 12 said "verify the bytes hash to the requested CID",
 * singular, which is exactly right for one block and silent about the other n − 1. A site root is
 * a directory whose links are CIDs; a file over one chunk is a node whose links are CIDs. Every
 * block is checked against the CID *that referred it* — the root against the CID in the record,
 * each child against the CID in its parent's link — and nothing in a block is acted on before
 * that block verifies. The property this buys is the whole of VayuWeb's transport authenticity
 * story, because there is no certificate authority to ask instead.
 *
 * **The bound is on the traversal, not on the output.** A dag-pb node may link to the same child
 * more than once. Thirty blocks, each linking twice to the next, describe over a billion leaves —
 * the content-addressed form of a billion-laughs attack, and the reason {@link FETCH_LIMITS}
 * counts blocks and depth rather than trusting the 256 MiB resource cap to catch it. The cap
 * would catch it, after doing the work. Bounding the output is the wrong end of the problem.
 *
 * **UnixFS metadata is content, not authority.** `filesize` and `blocksizes` are publisher-chosen
 * fields covered by the node's own hash, so a lie is self-consistent rather than detectable by
 * hashing: a node may declare 256 MiB and link to one byte, and it verifies perfectly. Nothing
 * here allocates on a declared size, and a file node whose declared sizes disagree with the bytes
 * that arrive is refused.
 *
 * ## What this module does not do
 *
 * No network. Blocks come from a {@link BlockSource} the caller supplies, exactly as records come
 * to the replication session from a caller rather than a socket. A traversal that could open its
 * own connections would be a traversal whose refusals are untestable without one.
 */

import { CID_PARAMETERS, decodeCid, encodeCid, sha256, type Cid } from './content.ts';
import { UNIXFS_TYPE } from './unixfs.ts';

/**
 * Every bound the traversal enforces, collected so a reviewer can see the whole budget at once —
 * the same reason `LIMITS` exists in the replication module.
 *
 * These are resolver policy rather than protocol constants: RESOLUTION.md 12.2 requires *a*
 * bound on blocks and depth without fixing either number, because the right value depends on what
 * the resolver is running on. They are stated here so that a change to one is a change to a named
 * thing rather than to a literal somewhere in a loop.
 */
export const FETCH_LIMITS = {
  /**
   * Blocks fetched for one request. Counts every fetch, including repeats of a CID already seen,
   * because repetition is the amplification vector rather than an optimisation opportunity.
   */
  blocks: 4_096,
  /** Link depth below the root. A site of ordinary shape is three or four. */
  depth: 32,
  /** RESOLUTION.md: a single resource is capped at 256 MiB. Applied as bytes accumulate. */
  resourceBytes: 256 * 1024 * 1024,
  /** The largest single block a conforming publisher produces is one 256 KiB chunk. */
  blockBytes: 1024 * 1024,
  /** Links in one node. A directory larger than this is a directory nobody meant to publish. */
  linksPerNode: 8_192,
} as const;

/** Why a traversal refused. Each maps to a numbered error in RESOLUTION.md's catalogue. */
export type FetchRejection =
  /** A block's bytes do not hash to the CID that referred it. RESOLUTION.md 1512. */
  | 'CONTENT_INTEGRITY'
  /** No block was offered for a CID the tree links to. RESOLUTION.md 1504. */
  | 'CONTENT_UNAVAILABLE'
  /** A traversal or size bound was exceeded. RESOLUTION.md 1413. */
  | 'RESPONSE_TOO_LARGE'
  /** A block is not decodable as the thing its CID's codec says it is. */
  | 'MALFORMED_BLOCK'
  /** The path names something the tree does not contain. RESOLUTION.md 1414. */
  | 'PATH_NOT_FOUND';

export class FetchError extends Error {
  readonly code: FetchRejection;
  constructor(code: FetchRejection, message: string) {
    super(`${code}: ${message}`);
    this.name = 'FetchError';
    this.code = code;
  }
}

/**
 * Where blocks come from.
 *
 * Deliberately narrow, and deliberately synchronous. A source returns candidate bytes for a CID
 * or null; it is never asked to say whether they are correct, and its answer is never believed.
 */
export interface BlockSource {
  get(cid: string): Uint8Array | null;
}

/* -------------------------------------------------------------------------- */
/* Protobuf decoding                                                           */
/* -------------------------------------------------------------------------- */

/** One decoded protobuf field: its number and its payload. */
interface Field {
  readonly number: number;
  readonly varint: number;
  readonly bytes: Uint8Array;
}

/**
 * Decode a varint, refusing the encodings a hostile encoder reaches for first.
 *
 * Ten bytes is the maximum for a 64-bit varint, and anything past 2^53 is refused rather than
 * silently rounded — a length field that arrives as a float is a length field that compares
 * strangely against a buffer's real size.
 */
function readVarint(bytes: Uint8Array, at: number): { value: number; next: number } {
  let result = 0;
  let shift = 1;
  let index = at;
  for (let read = 0; read < 10; read += 1) {
    if (index >= bytes.length) {
      throw new FetchError('MALFORMED_BLOCK', 'varint runs past the end of the block');
    }
    const byte = bytes[index]!;
    index += 1;
    result += (byte & 0x7f) * shift;
    if ((byte & 0x80) === 0) {
      if (!Number.isSafeInteger(result)) {
        throw new FetchError('MALFORMED_BLOCK', 'varint exceeds the safe integer range');
      }
      return { value: result, next: index };
    }
    shift *= 128;
  }
  throw new FetchError('MALFORMED_BLOCK', 'varint longer than ten bytes');
}

/** Decode a protobuf message into its fields, in wire order. */
function readFields(bytes: Uint8Array): Field[] {
  const fields: Field[] = [];
  let at = 0;
  while (at < bytes.length) {
    const key = readVarint(bytes, at);
    at = key.next;
    const number = Math.floor(key.value / 8);
    const wire = key.value % 8;
    if (number === 0) {
      throw new FetchError('MALFORMED_BLOCK', 'protobuf field number 0 is not valid');
    }
    if (wire === 0) {
      const value = readVarint(bytes, at);
      at = value.next;
      fields.push({ number, varint: value.value, bytes: new Uint8Array(0) });
      continue;
    }
    if (wire === 2) {
      const length = readVarint(bytes, at);
      at = length.next;
      if (at + length.value > bytes.length) {
        throw new FetchError('MALFORMED_BLOCK', 'length-delimited field runs past the end');
      }
      fields.push({ number, varint: 0, bytes: bytes.subarray(at, at + length.value) });
      at += length.value;
      continue;
    }
    // Groups and the fixed-width types. dag-pb and UnixFS use neither, and a block carrying one
    // is not a block a conforming publisher produced.
    throw new FetchError('MALFORMED_BLOCK', `unsupported protobuf wire type ${wire}`);
  }
  return fields;
}

/* -------------------------------------------------------------------------- */
/* dag-pb and UnixFS                                                           */
/* -------------------------------------------------------------------------- */

/** A link out of a dag-pb node, as it arrived. */
export interface DecodedLink {
  readonly cid: string;
  readonly name: string;
  readonly tsize: number;
}

/** A decoded dag-pb node: its links and its UnixFS payload, neither of them trusted yet. */
export interface DecodedNode {
  readonly links: readonly DecodedLink[];
  readonly type: number;
  /** Declared logical length for a file node. Publisher-chosen: never allocate on it. */
  readonly filesize: number;
  /** Declared per-chunk lengths for a file node, in order. Publisher-chosen. */
  readonly blocksizes: readonly number[];
}

/** Decode the `Hash` bytes of a PBLink into a CID string. */
function linkCid(hash: Uint8Array): string {
  const version = readVarint(hash, 0);
  const codec = readVarint(hash, version.next);
  const fn = readVarint(hash, codec.next);
  const length = readVarint(hash, fn.next);
  if (version.value !== 1) {
    throw new FetchError('MALFORMED_BLOCK', `link carries CID version ${version.value}, not 1`);
  }
  if (fn.value !== CID_PARAMETERS.multihashSha2_256) {
    throw new FetchError('MALFORMED_BLOCK', `link uses multihash ${fn.value}, not sha2-256`);
  }
  if (length.value !== 32 || length.next + 32 !== hash.length) {
    throw new FetchError('MALFORMED_BLOCK', 'link digest is not 32 bytes');
  }
  const cid: Cid = {
    version: 1,
    codec: codec.value,
    digest: hash.subarray(length.next),
  };
  return encodeCid(cid);
}

/**
 * Decode one dag-pb node.
 *
 * The encoder puts Links (field 2) on the wire before Data (field 1), against the
 * ascending-field-number habit; this reads whichever order arrives, because refusing a valid
 * encoding is a different bug from accepting an invalid one and only the second is a security
 * property. What is refused is a field this format does not define, which is how a block smuggles
 * bytes past a reader that skips what it does not recognise.
 */
export function decodeNode(bytes: Uint8Array): DecodedNode {
  const links: DecodedLink[] = [];
  let type = -1;
  let filesize = 0;
  const blocksizes: number[] = [];

  for (const field of readFields(bytes)) {
    if (field.number === 2) {
      if (links.length >= FETCH_LIMITS.linksPerNode) {
        throw new FetchError(
          'RESPONSE_TOO_LARGE',
          `a node may carry at most ${FETCH_LIMITS.linksPerNode} links`,
        );
      }
      links.push(decodeLink(field.bytes));
      continue;
    }
    if (field.number === 1) {
      for (const inner of readFields(field.bytes)) {
        if (inner.number === 1) type = inner.varint;
        else if (inner.number === 3) filesize = inner.varint;
        else if (inner.number === 4) blocksizes.push(inner.varint);
        // Fields 2 (Data), 5 (hashType), 6 (fanout), 7 (mode), 8 (mtime) exist in UnixFS and are
        // not produced by this project's importer. Ignored rather than refused: a reader that
        // rejects a field it merely does not use cannot read a tree built by any other tool,
        // and interoperating with the wider network is the point of using this format at all.
        continue;
      }
      continue;
    }
    throw new FetchError('MALFORMED_BLOCK', `dag-pb has no field ${field.number}`);
  }

  return { links, type, filesize, blocksizes };
}

function decodeLink(bytes: Uint8Array): DecodedLink {
  let cid: string | null = null;
  let name = '';
  let tsize = 0;
  for (const field of readFields(bytes)) {
    if (field.number === 1) cid = linkCid(field.bytes);
    else if (field.number === 2)
      name = new TextDecoder('utf-8', { fatal: false }).decode(field.bytes);
    else if (field.number === 3) tsize = field.varint;
    else throw new FetchError('MALFORMED_BLOCK', `PBLink has no field ${field.number}`);
  }
  if (cid === null) {
    throw new FetchError('MALFORMED_BLOCK', 'PBLink carries no Hash');
  }
  return { cid, name, tsize };
}

/* -------------------------------------------------------------------------- */
/* Verified traversal                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Decode a CID, turning any refusal into one of this module's codes.
 *
 * Every refusal that leaves this module must map to a numbered error in RESOLUTION.md's
 * catalogue, and `decodeCid` throws `ContentError` — a different type, which a caller catching
 * `FetchError` to build a numbered response would miss entirely. The block would then surface as
 * an internal error rather than as 1512, which tells an operator the resolver is broken when what
 * actually happened is that a peer sent rubbish. Found by a test that expected a code and got a
 * stack trace.
 */
function contentCid(cid: string): Cid {
  try {
    return decodeCid(cid);
  } catch (error) {
    throw new FetchError(
      'MALFORMED_BLOCK',
      `${cid} is not a CID this resolver can address content with: ${String(error)}`,
    );
  }
}

/** A traversal in progress. One per request, so the budget cannot leak between them.
 *
 * Exported because a caller assembling several paths from one tree needs to say whether they are
 * one request or several, and the answer changes what an attacker can spend.
 */
export class Budget {
  blocks = 0;
  bytes = 0;

  spendBlock(): void {
    this.blocks += 1;
    if (this.blocks > FETCH_LIMITS.blocks) {
      throw new FetchError(
        'RESPONSE_TOO_LARGE',
        `this request would fetch more than ${FETCH_LIMITS.blocks} blocks`,
      );
    }
  }

  spendBytes(count: number): void {
    this.bytes += count;
    if (this.bytes > FETCH_LIMITS.resourceBytes) {
      throw new FetchError(
        'RESPONSE_TOO_LARGE',
        `a single resource is capped at ${FETCH_LIMITS.resourceBytes} bytes`,
      );
    }
  }
}

/**
 * Fetch one block and verify it against the CID that referred it.
 *
 * The single most important function in this module, and the one a hurried implementation leaves
 * out: without it every peer is trusted to return whatever it likes for any CID, and the entire
 * authenticity story of the system collapses to "the peer said so".
 */
export function fetchVerified(
  source: BlockSource,
  cid: string,
  budget: Budget = new Budget(),
): Uint8Array {
  budget.spendBlock();
  const bytes = source.get(cid);
  if (bytes === null) {
    throw new FetchError('CONTENT_UNAVAILABLE', `no block offered for ${cid}`);
  }
  if (bytes.length > FETCH_LIMITS.blockBytes) {
    throw new FetchError(
      'RESPONSE_TOO_LARGE',
      `block for ${cid} is ${bytes.length} bytes, over the ${FETCH_LIMITS.blockBytes} limit`,
    );
  }
  const digest = sha256(bytes);
  const expected = contentCid(cid);
  if (expected.digest.length !== digest.length) {
    throw new FetchError('CONTENT_INTEGRITY', `${cid} does not name a sha2-256 digest`);
  }
  let same = 0;
  for (let i = 0; i < digest.length; i += 1) same |= digest[i]! ^ expected.digest[i]!;
  if (same !== 0) {
    throw new FetchError('CONTENT_INTEGRITY', `bytes offered for ${cid} hash to something else`);
  }
  return bytes;
}

/**
 * Assemble the file addressed by `cid`.
 *
 * A raw-codec CID is a leaf and its bytes are the file. A dag-pb CID is a node whose links are
 * the chunks in order, and whose declared `blocksizes` are checked against what actually arrives
 * rather than believed.
 */
export function fetchFile(
  source: BlockSource,
  cid: string,
  depth = 0,
  budget: Budget = new Budget(),
): Uint8Array {
  if (depth > FETCH_LIMITS.depth) {
    throw new FetchError(
      'RESPONSE_TOO_LARGE',
      `descended past ${FETCH_LIMITS.depth} levels; a DAG this deep is not a site`,
    );
  }
  const bytes = fetchVerified(source, cid, budget);
  const codec = contentCid(cid).codec;

  if (codec === CID_PARAMETERS.codecRaw) {
    budget.spendBytes(bytes.length);
    return bytes;
  }
  // No third case to guard. `contentCid` admits raw and dag-pb and nothing else, so a defensive
  // branch here would be unreachable — and an unreachable guard reads as load-bearing to the next
  // person, which is worse than its absence. The refusal for any other codec happens above.
  const node = decodeNode(bytes);
  if (node.type === UNIXFS_TYPE.directory) {
    throw new FetchError('PATH_NOT_FOUND', `${cid} is a directory, not a file`);
  }
  if (node.type !== UNIXFS_TYPE.file) {
    throw new FetchError('MALFORMED_BLOCK', `${cid} declares UnixFS type ${node.type}`);
  }
  if (node.blocksizes.length !== node.links.length) {
    // RESOLUTION.md 12.3: declared sizes are content. A node claiming a blocksizes list that does
    // not match its links is describing a file nobody can reconstruct the same way twice.
    throw new FetchError(
      'MALFORMED_BLOCK',
      `${cid} declares ${node.blocksizes.length} block sizes for ${node.links.length} links`,
    );
  }

  const parts: Uint8Array[] = [];
  let total = 0;
  for (let i = 0; i < node.links.length; i += 1) {
    const part = fetchFile(source, node.links[i]!.cid, depth + 1, budget);
    if (part.length !== node.blocksizes[i]) {
      throw new FetchError(
        'MALFORMED_BLOCK',
        `chunk ${i} of ${cid} declares ${node.blocksizes[i]} bytes and delivered ${part.length}`,
      );
    }
    parts.push(part);
    total += part.length;
  }
  if (total !== node.filesize) {
    throw new FetchError(
      'MALFORMED_BLOCK',
      `${cid} declares a filesize of ${node.filesize} and its chunks total ${total}`,
    );
  }

  // Allocated from what arrived, never from `filesize`. A node declaring 256 MiB and linking to
  // one byte verifies perfectly, and an implementation sizing a buffer from the declaration hands
  // an attacker a memory commitment for the price of one block.
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/**
 * Resolve a site-relative path against a directory root, returning the file's bytes.
 *
 * Path segments are matched against link names byte-for-byte. `.` and `..` are refused rather
 * than interpreted: a directory entry may legitimately be *named* `..` in dag-pb, and a resolver
 * that resolves it as a parent reference lets a published tree address a sibling of the site
 * root. Nothing in the format grants that, so nothing here implements it.
 */
export function fetchPath(source: BlockSource, root: string, path: string): Uint8Array {
  const budget = new Budget();
  const segments = path.split('/').filter((s) => s.length > 0);
  for (const segment of segments) {
    if (segment === '.' || segment === '..') {
      throw new FetchError('PATH_NOT_FOUND', `${JSON.stringify(segment)} is not a path segment`);
    }
  }

  let cid = root;
  for (const [index, segment] of segments.entries()) {
    if (index > FETCH_LIMITS.depth) {
      throw new FetchError('RESPONSE_TOO_LARGE', `path descends past ${FETCH_LIMITS.depth} levels`);
    }
    const bytes = fetchVerified(source, cid, budget);
    if (contentCid(cid).codec !== CID_PARAMETERS.codecDagPb) {
      throw new FetchError('PATH_NOT_FOUND', `${cid} is a file, and ${segment} descends into it`);
    }
    const node = decodeNode(bytes);
    if (node.type !== UNIXFS_TYPE.directory) {
      throw new FetchError('PATH_NOT_FOUND', `${cid} is not a directory`);
    }
    // First match wins, and a duplicate name is refused rather than shadowed. The encoder refuses
    // to produce one; a received tree carrying two entries called `index.html` is asking two
    // resolvers to disagree about which is the site, which is a fork with extra steps.
    const matches = node.links.filter((link) => link.name === segment);
    if (matches.length === 0) {
      throw new FetchError(
        'PATH_NOT_FOUND',
        `${cid} has no entry named ${JSON.stringify(segment)}`,
      );
    }
    if (matches.length > 1) {
      throw new FetchError(
        'MALFORMED_BLOCK',
        `${cid} carries ${matches.length} entries named ${JSON.stringify(segment)}`,
      );
    }
    cid = matches[0]!.cid;
  }

  return fetchFile(source, cid, segments.length, budget);
}

/** A block source over a list of blocks, for callers holding a whole tree already. */
export function blockSourceOf(blocks: readonly { cid: string; bytes: Uint8Array }[]): BlockSource {
  const byCid = new Map<string, Uint8Array>();
  for (const block of blocks) {
    if (!byCid.has(block.cid)) byCid.set(block.cid, block.bytes);
  }
  return { get: (cid) => byCid.get(cid) ?? null };
}
