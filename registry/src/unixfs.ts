/**
 * dag-pb and UnixFS: turning a directory tree into the root CID a registry record points at.
 *
 * docs/spec/HOSTING.md, "Content addressing", fixes the parameters. This module implements the
 * encoding those parameters describe, and it is the piece that makes {@link ./content.ts} into a
 * publish path rather than a hashing utility.
 *
 * ## Written against vectors, not against a reading of the format
 *
 * Every byte layout here was checked against blocks produced by the reference IPFS importer
 * before it was written, and the tests pin those blocks. That is not belt-and-braces: a first
 * attempt at this module, reasoning from a description of the format, put the UnixFS `Data` field
 * at protobuf field 2 and produced
 * `bafybeiepbj3744hbmji3sz5wqivcxj6au3jzfk54qfnki7ploa2gnsxxt4` for the empty directory, where
 * the network says `bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354`.
 *
 * That failure mode is the whole argument for the discipline. The wrong encoder was
 * self-consistent. It round-tripped. It hashed correctly. Every site it published would have had
 * a CID that resolved on the publisher's own machine and was invisible to every other node on the
 * network — and nothing in the publisher's own testing would ever have said so.
 *
 * ## The two rules a reader will get wrong
 *
 * **Links are serialised before Data.** `PBNode` numbers `Data` as field 1 and `Links` as field 2,
 * and dag-pb requires field 2 on the wire *first*. That violates the ascending-field-number habit
 * every protobuf encoder has, so a library's default output is wrong here and the error is one
 * byte's position.
 *
 * **A directory's links are sorted by name in raw byte order.** Two publishers importing the same
 * files in different order must produce the same CID, so the sort is part of the format rather
 * than a tidiness convention.
 */

import {
  CID_PARAMETERS,
  ContentError,
  chunk,
  decodeCid,
  encodeCid,
  rawLeafCid,
  sha256,
} from './content.ts';

/** UnixFS `Data.Type` values. Only the two a site needs are defined. */
export const UNIXFS_TYPE = {
  file: 2,
  directory: 1,
} as const;

/** One entry in a directory, or one chunk of a file. */
export interface Link {
  /** The child's CID, in text form. */
  readonly cid: string;
  /** Entry name. Empty for a file's chunk links, which are positional. */
  readonly name: string;
  /** Cumulative serialised size of the subtree this link points at. */
  readonly tsize: number;
}

/** An encoded block: its bytes and the CID that addresses them. */
export interface Block {
  readonly cid: string;
  readonly bytes: Uint8Array;
}

/** Protobuf unsigned varint. */
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

/** Tag byte(s) for a field: `(number << 3) | wireType`. */
function tag(field: number, wire: 0 | 2): number[] {
  return varint(field * 8 + wire);
}

function lengthDelimited(field: number, payload: readonly number[]): number[] {
  return [...tag(field, 2), ...varint(payload.length), ...payload];
}

function varintField(field: number, value: number): number[] {
  return [...tag(field, 0), ...varint(value)];
}

/**
 * The UnixFS `Data` message for a directory.
 *
 * Just `Type = Directory`. No size, no blocksizes — a directory's content is its links, which live
 * in the enclosing dag-pb node rather than here.
 */
export function unixfsDirectory(): number[] {
  return varintField(1, UNIXFS_TYPE.directory);
}

/**
 * The UnixFS `Data` message for a multi-chunk file.
 *
 * `filesize` is the logical length of the file. `blocksizes` repeats once per chunk, in order, so
 * a reader can seek to an offset without fetching every block first. Both are needed: the sum of
 * the block sizes equals the file size, but the reader has no way to know that until it has the
 * whole list, and a range request should not require the whole list.
 */
export function unixfsFile(chunkSizes: readonly number[]): number[] {
  const total = chunkSizes.reduce((sum, size) => sum + size, 0);
  const out = [...varintField(1, UNIXFS_TYPE.file), ...varintField(3, total)];
  for (const size of chunkSizes) out.push(...varintField(4, size));
  return out;
}

/** One `PBLink`: `Hash`, `Name`, `Tsize`, in that order. */
function pbLink(link: Link): number[] {
  const cid = decodeCid(link.cid);
  const hash = [
    ...varint(cid.version),
    ...varint(cid.codec),
    ...varint(CID_PARAMETERS.multihashSha2_256),
    ...varint(cid.digest.length),
    ...cid.digest,
  ];
  return [
    ...lengthDelimited(1, hash),
    ...lengthDelimited(2, Array.from(new TextEncoder().encode(link.name))),
    ...varintField(3, link.tsize),
  ];
}

/**
 * Encode a `PBNode`.
 *
 * **Links before Data**, which is the rule a reader will get wrong. `PBNode` numbers `Data` as
 * field 1 and `Links` as field 2, and dag-pb requires field 2 on the wire first — against the
 * ascending-field-number habit every protobuf encoder has. A node with the fields the other way
 * round hashes differently, so it is a different CID for identical content.
 */
export function encodePbNode(links: readonly Link[], data: readonly number[]): Uint8Array {
  const out: number[] = [];
  for (const link of links) out.push(...lengthDelimited(2, pbLink(link)));
  if (data.length > 0) out.push(...lengthDelimited(1, data));
  return Uint8Array.from(out);
}

/** Address an encoded dag-pb node. */
export function dagPbBlock(bytes: Uint8Array): Block {
  return {
    cid: encodeCid({ version: 1, codec: CID_PARAMETERS.codecDagPb, digest: sha256(bytes) }),
    bytes,
  };
}

/**
 * Build a directory node from its entries.
 *
 * Entries are sorted by name in **raw byte order**, so two publishers importing the same files in
 * different order produce the same CID. The sort is part of the format, not a tidiness
 * convention: without it, the root hash of a site would depend on the order a directory listing
 * happened to come back in, which differs between filesystems.
 */
export function directoryNode(entries: readonly Link[]): Block {
  const names = new Set<string>();
  for (const entry of entries) {
    if (entry.name.length === 0) {
      throw new ContentError('a directory entry must be named');
    }
    if (names.has(entry.name)) {
      throw new ContentError(`duplicate directory entry ${JSON.stringify(entry.name)}`);
    }
    names.add(entry.name);
  }
  const sorted = [...entries].sort((a, b) => compareBytewise(a.name, b.name));
  return dagPbBlock(encodePbNode(sorted, unixfsDirectory()));
}

/** Compare two names as raw bytes, which is not the same as JavaScript's default string order. */
function compareBytewise(a: string, b: string): number {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  const shared = Math.min(left.length, right.length);
  for (let i = 0; i < shared; i += 1) {
    if (left[i]! !== right[i]!) return left[i]! - right[i]!;
  }
  return left.length - right.length;
}

/**
 * Build every block for one file, returning the blocks and the CID that addresses it.
 *
 * A file that fits in one chunk is a **raw leaf and nothing more** — no dag-pb wrapper, no UnixFS
 * message. That is what HOSTING.md's raw-leaf choice buys: a small file's CID is the sha2-256 of
 * the file, checkable with an ordinary hash tool.
 *
 * A larger file becomes a dag-pb node whose links are the chunks in order, with empty names,
 * because chunk links are positional rather than named.
 */
export function fileBlocks(bytes: Uint8Array): { blocks: Block[]; cid: string; tsize: number } {
  const chunks = chunk(bytes);

  if (chunks.length === 1) {
    const leaf = chunks[0]!;
    const cid = rawLeafCid(leaf);
    return { blocks: [{ cid, bytes: leaf }], cid, tsize: leaf.length };
  }

  const blocks: Block[] = [];
  const links: Link[] = [];
  for (const piece of chunks) {
    const cid = rawLeafCid(piece);
    blocks.push({ cid, bytes: piece });
    links.push({ cid, name: '', tsize: piece.length });
  }

  const node = dagPbBlock(encodePbNode(links, unixfsFile(chunks.map((piece) => piece.length))));
  blocks.push(node);
  // Tsize is the cumulative serialised size of the subtree: this node plus every block under it.
  const tsize = node.bytes.length + links.reduce((sum, link) => sum + link.tsize, 0);
  return { blocks, cid: node.cid, tsize };
}

/** One file in a site, as the importer sees it. */
export interface SiteFile {
  /** Path relative to the site root, using `/` separators. */
  readonly path: string;
  readonly content: Uint8Array;
}

/**
 * Import a whole site, returning every block and the root CID.
 *
 * Directories are created from the paths rather than declared, and the whole tree is built
 * bottom-up so that each parent's links carry a `Tsize` its children have already determined.
 */
export function importSite(files: readonly SiteFile[]): { blocks: Block[]; root: string } {
  const blocks: Block[] = [];
  const tree = new Map<string, Link>();

  for (const file of files) {
    if (file.path.length === 0 || file.path.startsWith('/') || file.path.endsWith('/')) {
      throw new ContentError(`${JSON.stringify(file.path)} is not a site-relative path`);
    }
    if (file.path.split('/').some((part) => part === '' || part === '.' || part === '..')) {
      throw new ContentError(`${JSON.stringify(file.path)} contains an empty or relative segment`);
    }
    const built = fileBlocks(file.content);
    blocks.push(...built.blocks);
    tree.set(file.path, { cid: built.cid, name: file.path, tsize: built.tsize });
  }

  const root = buildDirectory('', tree, blocks);
  return { blocks, root: root.cid };
}

/** Build one directory level, recursing into subdirectories first. */
function buildDirectory(
  prefix: string,
  tree: ReadonlyMap<string, Link>,
  blocks: Block[],
): { cid: string; tsize: number } {
  const entries: Link[] = [];
  const subdirectories = new Set<string>();

  for (const [path, link] of tree) {
    if (prefix !== '' && !path.startsWith(`${prefix}/`)) continue;
    const relative = prefix === '' ? path : path.slice(prefix.length + 1);
    const slash = relative.indexOf('/');
    if (slash === -1) {
      entries.push({ ...link, name: relative });
    } else {
      subdirectories.add(relative.slice(0, slash));
    }
  }

  for (const name of subdirectories) {
    const child = buildDirectory(prefix === '' ? name : `${prefix}/${name}`, tree, blocks);
    entries.push({ cid: child.cid, name, tsize: child.tsize });
  }

  const node = directoryNode(entries);
  blocks.push(node);
  const tsize = node.bytes.length + entries.reduce((sum, entry) => sum + entry.tsize, 0);
  return { cid: node.cid, tsize };
}
