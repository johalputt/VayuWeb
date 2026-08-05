import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  CID_PARAMETERS,
  ContentError,
  base32Decode,
  base32Encode,
  chunk,
  decodeCid,
  encodeCid,
  fitsInOneLeaf,
  rawLeafCid,
  sha256,
} from './content.ts';

/* -------------------------------------------------------------------------- */
/* Checked against the IPFS network, not only against itself                   */
/* -------------------------------------------------------------------------- */

test('the empty file and "hello world" produce the CIDs the IPFS ecosystem publishes', () => {
  // These two are widely published reference values. Pinning them is what makes this module
  // checked against the network it has to interoperate with, rather than merely self-consistent:
  // an implementation can be internally perfect, round-trip everything it produces, and still
  // address content nobody else can find.
  assert.equal(
    rawLeafCid(new Uint8Array(0)),
    'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku',
  );
  assert.equal(
    rawLeafCid(new TextEncoder().encode('hello world')),
    'bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e',
  );
});

test('a raw leaf CID is the sha2-256 of the file, verifiable with an ordinary hash tool', () => {
  // The property "raw leaves" exists to buy. A reader can check a single-block file with
  // `sha256sum` and no VayuWeb software, which makes the verification story explainable rather
  // than merely true.
  const bytes = new TextEncoder().encode('the quick brown fox');
  const decoded = decodeCid(rawLeafCid(bytes));
  assert.deepEqual(decoded.digest, sha256(bytes));
  assert.equal(decoded.codec, CID_PARAMETERS.codecRaw);
  assert.equal(decoded.version, 1);
});

test('the parameters match the ones HOSTING.md fixes', () => {
  // Two publishers importing the same directory must produce the same CID. A different chunk
  // size, leaf codec or hash gives a different root for identical bytes — and the failure is
  // silent, because both CIDs resolve and both sites work.
  const spec = readFileSync(new URL('../../docs/spec/HOSTING.md', import.meta.url), 'utf8');
  assert.match(spec, /Multihash\s+sha2-256/);
  assert.match(spec, /262144 bytes \(256 KiB\)/);
  assert.match(spec, /max 174 links per node/);
  assert.match(spec, /raw blocks \(codec 0x55\)/);
  assert.match(spec, /base32, lowercase \('b' prefix\)/);

  assert.equal(CID_PARAMETERS.chunkBytes, 262_144);
  assert.equal(CID_PARAMETERS.maxLinks, 174);
  assert.equal(CID_PARAMETERS.codecRaw, 0x55);
});

/* -------------------------------------------------------------------------- */
/* base32: lowercase, unpadded                                                 */
/* -------------------------------------------------------------------------- */

test('base32 is lowercase and unpadded, and round-trips at every length', () => {
  // Multibase base32 differs from the RFC 4648 default in two ways that are silent when wrong:
  // lowercase alphabet, no `=` padding. A CID through a padding-emitting encoder is a different
  // string for the same bytes, and string equality is how CIDs get compared.
  for (let length = 0; length < 40; length += 1) {
    const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + 11) & 0xff);
    const text = base32Encode(bytes);
    assert.equal(text, text.toLowerCase(), 'no uppercase');
    assert.equal(text.includes('='), false, 'no padding');
    assert.deepEqual(base32Decode(text), bytes, `round-trip at ${length}`);
  }
});

test('a character outside the alphabet is refused rather than skipped', () => {
  for (const bad of ['abc=', 'AB', 'ab1', 'ab0', 'ab8', 'ab9', 'a b']) {
    assert.throws(() => base32Decode(bad), ContentError, bad);
  }
});

/* -------------------------------------------------------------------------- */
/* The decoder refuses every form the specification does not use               */
/* -------------------------------------------------------------------------- */

test('a CID this specification does not use is refused, not accommodated', () => {
  // Refusing is the point. A CIDv0, a base58 CID or a BLAKE3 multihash are all valid CIDs
  // somewhere. Accepting one would mean a registry record could point at content this resolver
  // cannot address the way the specification says it must, and "we accepted it and did something
  // reasonable" is how two implementations stop agreeing.
  assert.throws(
    () => decodeCid('QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG'),
    /base32/,
    'CIDv0',
  );
  assert.throws(() => decodeCid('zdj7Wk'), /base32/, 'base58btc multibase');

  // CIDv1, dag-json codec (0x0129) — a legitimate CID, and not one used here.
  const dagJson = encodeCidRaw(1, 0x0129, sha256(new Uint8Array(0)));
  assert.throws(() => decodeCid(dagJson), /not raw or dag-pb/);

  // CIDv1, raw, but BLAKE3 (0x1e) instead of sha2-256.
  const blake3 =
    'b' + base32Encode(Uint8Array.from([0x01, 0x55, 0x1e, 0x20, ...new Uint8Array(32)]));
  assert.throws(() => decodeCid(blake3), /only sha2-256/);
});

test('a truncated or over-long digest is refused', () => {
  const short =
    'b' + base32Encode(Uint8Array.from([0x01, 0x55, 0x12, 0x20, ...new Uint8Array(31)]));
  assert.throws(() => decodeCid(short), ContentError);
  assert.throws(
    () => encodeCid({ version: 1, codec: 0x55, digest: new Uint8Array(31) }),
    /32 bytes/,
  );
});

test('a multi-byte codec encodes as a varint rather than one byte', () => {
  // Every value this specification uses is below 128, so every varint is one byte — which is
  // exactly why an implementation that hard-codes single bytes passes every test written from
  // the happy path and produces wrong output the first time a value exceeds 127.
  const text = encodeCidRaw(1, 0x0129, new Uint8Array(32).fill(7));
  const bytes = base32Decode(text.slice(1));
  assert.deepEqual(Array.from(bytes.subarray(0, 4)), [0x01, 0xa9, 0x02, 0x12]);
});

/* -------------------------------------------------------------------------- */
/* Chunking                                                                    */
/* -------------------------------------------------------------------------- */

test('chunking is fixed-size and deterministic', () => {
  const bytes = Uint8Array.from({ length: CID_PARAMETERS.chunkBytes * 2 + 17 }, (_, i) => i & 0xff);
  const chunks = chunk(bytes);
  assert.equal(chunks.length, 3);
  assert.equal(chunks[0]!.length, CID_PARAMETERS.chunkBytes);
  assert.equal(chunks[1]!.length, CID_PARAMETERS.chunkBytes);
  assert.equal(chunks[2]!.length, 17);
  assert.deepEqual(chunk(bytes), chunks, 'the same bytes chunk the same way every time');
});

test('an empty file is one empty chunk, not none', () => {
  // A file of zero bytes is a file, it has a CID, and returning no chunks would make it
  // addressless — the kind of edge case that only surfaces when someone publishes a placeholder.
  assert.equal(chunk(new Uint8Array(0)).length, 1);
  assert.equal(chunk(new Uint8Array(0))[0]!.length, 0);
  assert.equal(fitsInOneLeaf(new Uint8Array(0)), true);
});

test('a file larger than one chunk is refused as a raw leaf rather than silently truncated', () => {
  const big = new Uint8Array(CID_PARAMETERS.chunkBytes + 1);
  assert.equal(fitsInOneLeaf(big), false);
  assert.throws(() => rawLeafCid(big), /needs a DAG/);
});

/** Encode a CID with an arbitrary codec, for testing forms the public encoder refuses. */
function encodeCidRaw(version: number, codec: number, digest: Uint8Array): string {
  const varint = (value: number): number[] => {
    const out: number[] = [];
    let remaining = value;
    while (remaining >= 0x80) {
      out.push((remaining & 0x7f) | 0x80);
      remaining = Math.floor(remaining / 128);
    }
    out.push(remaining);
    return out;
  };
  return (
    'b' +
    base32Encode(Uint8Array.from([...varint(version), ...varint(codec), 0x12, 0x20, ...digest]))
  );
}
