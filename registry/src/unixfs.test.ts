import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  directoryNode,
  encodePbNode,
  fileBlocks,
  importSite,
  unixfsDirectory,
  unixfsFile,
} from './unixfs.ts';
import { CID_PARAMETERS, ContentError } from './content.ts';

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

/* -------------------------------------------------------------------------- */
/* Vectors from the reference importer, not from a reading of the format       */
/* -------------------------------------------------------------------------- */
//
// Every value below was produced by the reference IPFS importer with this project's fixed
// parameters, before this module was written. They are what makes it checked against the network
// rather than against itself.
//
// The need is not hypothetical. A first attempt at this module, reasoning from a description of
// the format, put the UnixFS `Data` field at protobuf field 2 and produced
// `bafybeiepbj3744hbmji3sz5wqivcxj6au3jzfk54qfnki7ploa2gnsxxt4` for the empty directory. It was
// self-consistent, it round-tripped, it hashed correctly — and every site it published would have
// had a CID that resolved on the publisher's own machine and was invisible to every other node.

const EMPTY_DIRECTORY_CID = 'bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354';
const ONE_FILE_ROOT = 'bafybeiegxp4jcqwwry6cjdalgkpozbizynlfvo5krlvezukdaun5a4husi';
const TWO_FILE_ROOT = 'bafybeidyhgtyzk2tdvek6nmdcyxnv5law46pcjwdgbkj6spv6bovnjbesy';
const BIG_FILE_ROOT = 'bafybeiew3gz7lfge2uvtcdhd4kf37ya3zjpmxqcbxucsjl5x66glmrjhzi';
const BIG_FILE_NODE = 'bafybeihmxcvd4urq4sge4r5s3mtju5yaoz7urfh4hghul327uyaznjwyhq';
const NESTED_ROOT = 'bafybeicrzlnxeesybu4h7j7gx64po5k65kvq5iloqko6i4ph7tincovx2i';

test('the empty directory matches the network, byte for byte and CID for CID', () => {
  const node = directoryNode([]);
  assert.equal(hex(node.bytes), '0a020801');
  assert.equal(node.cid, EMPTY_DIRECTORY_CID);
});

test('a one-file site matches the reference importer', () => {
  const { root } = importSite([{ path: 'index.html', content: utf8('<h1>hi</h1>') }]);
  assert.equal(root, ONE_FILE_ROOT);
});

test('a two-file site matches, which pins the link ordering', () => {
  // `a.txt` sorts before `index.html`. Two publishers importing the same files in different order
  // must produce the same CID, so the sort is part of the format rather than a tidiness
  // convention — without it the root hash depends on the order a directory listing came back in.
  const forwards = importSite([
    { path: 'index.html', content: utf8('<h1>hi</h1>') },
    { path: 'a.txt', content: utf8('alpha') },
  ]);
  const backwards = importSite([
    { path: 'a.txt', content: utf8('alpha') },
    { path: 'index.html', content: utf8('<h1>hi</h1>') },
  ]);
  assert.equal(forwards.root, TWO_FILE_ROOT);
  assert.equal(backwards.root, TWO_FILE_ROOT, 'import order must not change the root');
});

test('a file needing two chunks matches, node bytes and all', () => {
  const big = new Uint8Array(CID_PARAMETERS.chunkBytes + 10).fill(7);
  const built = fileBlocks(big);
  assert.equal(built.cid, BIG_FILE_NODE);
  assert.equal(built.blocks.length, 3, 'two raw leaves and the file node');

  // The tail of the node is its UnixFS Data field, byte for byte as the reference importer emits
  // it: field 1, length 12, Type=File, filesize 262154, blocksizes [262144, 10].
  const node = built.blocks[2]!;
  assert.equal(hex(node.bytes).slice(-28), '0a0c0802188a801020808010200a');

  const { root } = importSite([{ path: 'big.bin', content: big }]);
  assert.equal(root, BIG_FILE_ROOT);
});

/* -------------------------------------------------------------------------- */
/* The two rules a reader will get wrong                                       */
/* -------------------------------------------------------------------------- */

test('Links are serialised before Data, against every protobuf habit', () => {
  // PBNode numbers Data as field 1 and Links as field 2, and dag-pb requires field 2 on the wire
  // FIRST. That is the opposite of the ascending-field-number order every protobuf encoder emits
  // by default, so a library's default output is wrong here and the error is one byte's position.
  // A node with the fields the other way round hashes differently, which is a different CID for
  // identical content.
  const bytes = encodePbNode(
    [{ cid: 'bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e', name: 'x', tsize: 11 }],
    unixfsDirectory(),
  );
  assert.equal(bytes[0], 0x12, 'the first tag byte is field 2, wire type 2 — Links');
  const dataTag = hex(bytes).indexOf('0a02' + '0801');
  assert.ok(dataTag > 0, 'Data appears after the links, not before');
});

test('a directory with no data field still carries its UnixFS message', () => {
  // An empty Data field would encode as nothing at all, and a directory node with no UnixFS
  // message is not a directory — it is an untyped node that a reader cannot interpret.
  assert.equal(hex(directoryNode([]).bytes), '0a020801');
});

test('the UnixFS file message carries filesize and every block size', () => {
  // Both are needed. The sum of the block sizes equals the file size, but a reader has no way to
  // know that until it holds the whole list, and a range request should not require the whole
  // list first.
  const message = unixfsFile([262_144, 10]);
  assert.deepEqual(message.slice(0, 2), [0x08, 0x02], 'Type = File');
  assert.deepEqual(
    message,
    [0x08, 0x02, 0x18, 0x8a, 0x80, 0x10, 0x20, 0x80, 0x80, 0x10, 0x20, 0x0a],
  );
});

/* -------------------------------------------------------------------------- */
/* Raw leaves, and what they buy                                               */
/* -------------------------------------------------------------------------- */

test('a small file is a raw leaf with no wrapper at all', () => {
  // The property HOSTING.md's raw-leaf choice exists to buy: a small file's CID is the sha2-256 of
  // the file, checkable with an ordinary hash tool and no VayuWeb software.
  const built = fileBlocks(utf8('hello world'));
  assert.equal(built.blocks.length, 1);
  assert.equal(built.cid, 'bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e');
  assert.equal(built.tsize, 11, 'a raw leaf’s tsize is its own length');
});

test('an empty file is addressable', () => {
  const built = fileBlocks(new Uint8Array(0));
  assert.equal(built.cid, 'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku');
  assert.equal(built.tsize, 0);
});

/* -------------------------------------------------------------------------- */
/* Nested directories, and paths that are not paths                            */
/* -------------------------------------------------------------------------- */

test('subdirectories are created from paths and the root is stable', () => {
  const first = importSite([
    { path: 'index.html', content: utf8('root') },
    { path: 'docs/index.html', content: utf8('docs') },
    { path: 'docs/deep/index.html', content: utf8('deep') },
  ]);
  const second = importSite([
    { path: 'docs/deep/index.html', content: utf8('deep') },
    { path: 'docs/index.html', content: utf8('docs') },
    { path: 'index.html', content: utf8('root') },
  ]);
  assert.equal(first.root, second.root, 'the tree is a function of its contents, not its order');
  // Pinned against the reference importer as well, because the recursion that builds intermediate
  // directories is the one part of this module no flat vector exercises — and a Tsize accumulated
  // wrongly one level down changes the root while every leaf stays correct.
  assert.equal(first.root, NESTED_ROOT);
});

test('a path that could escape the site is refused rather than normalised', () => {
  // Refusing rather than repairing, for the same reason names are: a publisher who wrote `..` did
  // not mean the directory above the site root, and guessing what they meant is how a build
  // pulls in a file nobody intended to publish.
  for (const path of ['', '/absolute', 'trailing/', 'a//b', '../escape', 'a/../b', './here']) {
    assert.throws(
      () => importSite([{ path, content: utf8('x') }]),
      ContentError,
      JSON.stringify(path),
    );
  }
});

test('a duplicate entry in one directory is refused', () => {
  assert.throws(
    () =>
      directoryNode([
        { cid: 'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku', name: 'a', tsize: 0 },
        { cid: 'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku', name: 'a', tsize: 0 },
      ]),
    /duplicate/,
  );
});
