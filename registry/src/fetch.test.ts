import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  FETCH_LIMITS,
  FetchError,
  Budget,
  blockSourceOf,
  decodeNode,
  fetchFile,
  fetchPath,
  fetchVerified,
  type BlockSource,
} from './fetch.ts';
import { importSite, fileBlocks, dagPbBlock, encodePbNode, unixfsFile } from './unixfs.ts';
import { CID_PARAMETERS, encodeCid, sha256, decodeCid } from './content.ts';

const text = (s: string): Uint8Array => new TextEncoder().encode(s);
const read = (b: Uint8Array): string => new TextDecoder().decode(b);

/** The error code a call refuses with, or 'accepted' if it does not refuse. */
function refusal(run: () => unknown): string {
  try {
    run();
    return 'accepted';
  } catch (error) {
    return error instanceof FetchError ? error.code : `threw:${String(error)}`;
  }
}

/* -------------------------------------------------------------------------- */
/* Round trip: what the importer produces, the traversal reads back            */
/* -------------------------------------------------------------------------- */

test('a site imported and fetched back yields the bytes that went in', () => {
  const files = [
    { path: 'index.html', content: text('<!doctype html><title>home</title>') },
    { path: 'about.html', content: text('<!doctype html><title>about</title>') },
    { path: 'assets/style.css', content: text('body{color:#fff}') },
    { path: 'assets/deep/nested/note.txt', content: text('four levels down') },
  ];
  const { blocks, root } = importSite(files);
  const source = blockSourceOf(blocks);

  for (const file of files) {
    assert.equal(read(fetchPath(source, root, file.path)), read(file.content));
  }
});

test('a multi-chunk file is reassembled in order', () => {
  // Two chunks and a bit, so the file is a dag-pb node with three links rather than a raw leaf —
  // the path that exercises blocksizes, filesize and the recursive descent all at once.
  const size = CID_PARAMETERS.chunkBytes * 2 + 1234;
  const content = new Uint8Array(size);
  for (let i = 0; i < size; i += 1) content[i] = (i * 7 + 3) & 0xff;

  const built = fileBlocks(content);
  assert.ok(built.blocks.length > 1, 'the fixture must actually chunk');
  assert.deepEqual(fetchFile(blockSourceOf(built.blocks), built.cid), content);
});

test('a single-chunk file is a raw leaf with no dag-pb wrapper', () => {
  const built = fileBlocks(text('small'));
  assert.equal(decodeCid(built.cid).codec, CID_PARAMETERS.codecRaw);
  assert.equal(read(fetchFile(blockSourceOf(built.blocks), built.cid)), 'small');
});

/* -------------------------------------------------------------------------- */
/* RESOLUTION.md 12.1 — verification is recursive                              */
/* -------------------------------------------------------------------------- */

test('12.1 a peer substituting bytes for the ROOT cid is refused', () => {
  const { root } = importSite([{ path: 'index.html', content: text('real') }]);
  const lying: BlockSource = { get: () => text('whatever I like') };
  assert.equal(refusal(() => fetchFile(lying, root)), 'CONTENT_INTEGRITY');
});

test('12.1 a peer substituting bytes for a CHILD is refused, which is the whole point', () => {
  // The attack the recursive rule exists for. Step 12 as written said "verify the bytes hash to
  // the requested CID" — an implementation reading that literally checks the root, gets a valid
  // directory node, and then trusts whatever arrives for the files it links to. Serving a
  // different index.html under a correct root is then free, and it is the one substitution a
  // reader would never notice: the URL, the name and the record are all genuine.
  const { blocks, root } = importSite([{ path: 'index.html', content: text('the real page') }]);
  const honest = blockSourceOf(blocks);
  const rootBytes = honest.get(root)!;

  const tampering: BlockSource = {
    get: (cid) => (cid === root ? rootBytes : text('<script>attacker</script>')),
  };
  assert.equal(refusal(() => fetchPath(tampering, root, 'index.html')), 'CONTENT_INTEGRITY');
});

test('12.1 substitution at DEPTH is refused too, not only one level down', () => {
  const { blocks, root } = importSite([
    { path: 'a/b/c/deep.txt', content: text('genuine') },
    { path: 'index.html', content: text('home') },
  ]);
  const honest = blockSourceOf(blocks);
  const deep = fetchPath(honest, root, 'a/b/c/deep.txt');
  assert.equal(read(deep), 'genuine');

  // Swap only the leaf. Every directory node on the way down is authentic.
  const leafCid = encodeCid({
    version: 1,
    codec: CID_PARAMETERS.codecRaw,
    digest: sha256(text('genuine')),
  });
  const swapped: BlockSource = {
    get: (cid) => (cid === leafCid ? text('forged!') : honest.get(cid)),
  };
  assert.equal(refusal(() => fetchPath(swapped, root, 'a/b/c/deep.txt')), 'CONTENT_INTEGRITY');
});

test('12.1 a block that is simply missing is distinguished from one that is wrong', () => {
  // Two different operational situations that a single "it failed" would conflate: nobody has the
  // block, versus somebody is lying about it. Only the second is an attack, and an operator who
  // cannot tell them apart cannot act on either.
  const { root } = importSite([{ path: 'index.html', content: text('x') }]);
  const empty: BlockSource = { get: () => null };
  assert.equal(refusal(() => fetchFile(empty, root)), 'CONTENT_UNAVAILABLE');
});

/* -------------------------------------------------------------------------- */
/* RESOLUTION.md 12.2 — the bound is on the traversal                          */
/* -------------------------------------------------------------------------- */

test('12.2 a DAG that links to the same child repeatedly cannot amplify without bound', () => {
  // The content-addressed billion laughs. Each node links twice to the one below it, so k nodes
  // describe 2^k leaves. Thirty levels is over a billion; the resolver must refuse on the block
  // budget rather than on the output size, because reaching the output size means having done the
  // work an attacker wanted done.
  const leaf = text('.');
  const leafCid = encodeCid({
    version: 1,
    codec: CID_PARAMETERS.codecRaw,
    digest: sha256(leaf),
  });

  const blocks = new Map<string, Uint8Array>([[leafCid, leaf]]);
  let childCid = leafCid;
  let childSize = leaf.length;
  for (let level = 0; level < 30; level += 1) {
    const links = [
      { cid: childCid, name: '', tsize: childSize },
      { cid: childCid, name: '', tsize: childSize },
    ];
    const node = dagPbBlock(encodePbNode(links, unixfsFile([childSize, childSize])));
    blocks.set(node.cid, node.bytes);
    childCid = node.cid;
    childSize = childSize * 2;
  }

  // The source counts, and gives up well above the budget. A test that relies on the traversal
  // stopping is a test that HANGS when the traversal stops stopping -- which is what happened
  // when the block budget was mutated out: the run did not fail, it expanded 2^30 leaves until
  // the harness killed it. A hang is a worse failure than an assertion, because CI reports it as
  // a timeout rather than as this defence being gone.
  let gets = 0;
  const ceiling = FETCH_LIMITS.blocks * 4;
  const source: BlockSource = {
    get: (cid) => {
      gets += 1;
      if (gets > ceiling) {
        throw new Error(
          `traversal fetched ${gets} blocks with a budget of ${FETCH_LIMITS.blocks}: ` +
            'the amplification bound is not being applied',
        );
      }
      return blocks.get(cid) ?? null;
    },
  };
  assert.equal(refusal(() => fetchFile(source, childCid)), 'RESPONSE_TOO_LARGE');
  assert.ok(gets <= FETCH_LIMITS.blocks + 1, `stopped after ${gets} fetches`);

  // And the refusal is on the BUDGET, not on having assembled 2^30 bytes: the whole DAG is 31
  // blocks, so an implementation that only checked output size would have to expand it first.
  assert.equal(blocks.size, 31);
});

test('12.2 the block budget counts repeats rather than deduplicating them', () => {
  // Deduplicating by CID is the optimisation an implementer reaches for, and it is exactly what
  // makes the amplification free again: the second visit to a shared subtree costs nothing to
  // count and everything to expand. The budget therefore counts fetches.
  const budget = new Budget();
  const built = fileBlocks(text('once'));
  const source = blockSourceOf(built.blocks);
  fetchVerified(source, built.cid, budget);
  fetchVerified(source, built.cid, budget);
  assert.equal(budget.blocks, 2, 'the same CID fetched twice is two blocks of budget');
});

test('12.2 a chain deeper than the depth limit is refused', () => {
  const budget = new Budget();
  const built = fileBlocks(text('deep'));
  assert.equal(
    refusal(() => fetchFile(blockSourceOf(built.blocks), built.cid, FETCH_LIMITS.depth + 1, budget)),
    'RESPONSE_TOO_LARGE',
  );
});

test('12.2 a node carrying more links than the cap is refused', () => {
  // `linksPerNode` had no test when it was written, which makes it a bound that could be deleted
  // with nothing to notice — the same defect as any other guard nothing exercises. A directory
  // this wide is not a directory anybody meant to publish; it is a way to make one block cost a
  // reader an unbounded amount of decoding.
  const leaf = leafOf('x');
  const links = Array.from({ length: FETCH_LIMITS.linksPerNode + 1 }, (_unused, i) => ({
    cid: leaf.cid,
    name: `f${i}`,
    tsize: 1,
  }));
  const bytes = encodePbNode(links, DIRECTORY_DATA);
  assert.equal(refusal(() => decodeNode(bytes)), 'RESPONSE_TOO_LARGE');

  // And one link under the cap still decodes, so the bound is a bound rather than a refusal of
  // anything large.
  const justUnder = encodePbNode(links.slice(0, FETCH_LIMITS.linksPerNode), DIRECTORY_DATA);
  assert.equal(decodeNode(justUnder).links.length, FETCH_LIMITS.linksPerNode);
});

test('12.2 the accumulated-bytes cap is applied, and is a real comparison', () => {
  // Tested on the Budget rather than end to end, and the reason is worth stating rather than
  // hiding: reaching 256 MiB through the traversal means allocating a quarter of a gigabyte in
  // CI to prove one arithmetic comparison. What matters is that the comparison exists, that it
  // is `>` rather than `>=` at the boundary, and that it is spent from the same budget the
  // traversal uses — `fetchFile` calls `spendBytes` for every raw leaf it returns.
  const budget = new Budget();
  budget.spendBytes(FETCH_LIMITS.resourceBytes);
  assert.equal(budget.bytes, FETCH_LIMITS.resourceBytes, 'exactly at the cap is not over it');

  let code = 'accepted';
  try {
    budget.spendBytes(1);
  } catch (error) {
    code = error instanceof FetchError ? error.code : `threw:${String(error)}`;
  }
  assert.equal(code, 'RESPONSE_TOO_LARGE');
});

test('12.2 an over-sized single block is refused before it is hashed into anything', () => {
  const big = new Uint8Array(FETCH_LIMITS.blockBytes + 1);
  const cid = encodeCid({ version: 1, codec: CID_PARAMETERS.codecRaw, digest: sha256(big) });
  const source: BlockSource = { get: () => big };
  assert.equal(refusal(() => fetchFile(source, cid)), 'RESPONSE_TOO_LARGE');
});

/* -------------------------------------------------------------------------- */
/* RESOLUTION.md 12.3 — declared metadata is content, not authority            */
/* -------------------------------------------------------------------------- */

test('12.3 a node declaring a filesize its chunks do not add up to is refused', () => {
  // The node hashes correctly. The lie is inside the bytes the CID commits to, so hashing cannot
  // detect it — only comparing the declaration against what arrives can. An implementation
  // trusting `filesize` to size a buffer hands an attacker a 256 MiB allocation for one block.
  //
  // ONE relationship is broken: blocksizes agrees with the chunk that arrives, and only filesize
  // lies. Anything else would let a different check take the credit for this one.
  const leaf = leafOf('four');
  const node = dagPbBlock(
    encodePbNode(
      [{ cid: leaf.cid, name: '', tsize: 4 }],
      hostileFileData([4], 268_435_456),
    ),
  );
  const source: BlockSource = {
    get: (cid) => (cid === node.cid ? node.bytes : cid === leaf.cid ? leaf.bytes : null),
  };
  assert.equal(refusal(() => fetchFile(source, node.cid)), 'MALFORMED_BLOCK');
});

test('12.3 a chunk whose length disagrees with its declared blocksize is refused', () => {
  // The first version of this test set filesize to 9 as well, so deleting the per-chunk check
  // still failed -- on the filesize total instead. It survived the mutation and proved nothing.
  // filesize now agrees with what ARRIVES (4), so the per-chunk comparison is the only check that
  // can fire.
  const leaf = leafOf('four');
  const node = dagPbBlock(
    encodePbNode([{ cid: leaf.cid, name: '', tsize: 4 }], hostileFileData([9], 4)),
  );
  const source: BlockSource = {
    get: (cid) => (cid === node.cid ? node.bytes : cid === leaf.cid ? leaf.bytes : null),
  };
  assert.equal(refusal(() => fetchFile(source, node.cid)), 'MALFORMED_BLOCK');
});

test('12.3 a blocksizes list that does not match the link count is refused', () => {
  // Two links, THREE declared sizes, and every other relationship intact: each arriving chunk
  // matches its declared blocksize, and filesize matches what the two chunks actually total. Only
  // the count is wrong, so only the count check can catch it.
  //
  // The first version used one link and two sizes with filesize derived from both, which the
  // filesize check caught -- so deleting the count check changed nothing and the test survived.
  const leaf = leafOf('four');
  const node = dagPbBlock(
    encodePbNode(
      [
        { cid: leaf.cid, name: '', tsize: 4 },
        { cid: leaf.cid, name: '', tsize: 4 },
      ],
      hostileFileData([4, 4, 4], 8),
    ),
  );
  const source: BlockSource = {
    get: (cid) => (cid === node.cid ? node.bytes : cid === leaf.cid ? leaf.bytes : null),
  };
  assert.equal(refusal(() => fetchFile(source, node.cid)), 'MALFORMED_BLOCK');
});

/* -------------------------------------------------------------------------- */
/* Path resolution                                                             */
/* -------------------------------------------------------------------------- */

test('a path segment named .. is refused rather than interpreted', () => {
  // dag-pb permits a link literally named `..`, and a resolver that treats it as a parent
  // reference lets a published tree address a sibling of the root it was served under. Nothing in
  // the format grants that, so the segment is refused instead of resolved either way.
  const { blocks, root } = importSite([{ path: 'index.html', content: text('home') }]);
  const source = blockSourceOf(blocks);
  assert.equal(refusal(() => fetchPath(source, root, '../secret')), 'PATH_NOT_FOUND');
  assert.equal(refusal(() => fetchPath(source, root, 'a/../index.html')), 'PATH_NOT_FOUND');
  assert.equal(refusal(() => fetchPath(source, root, './index.html')), 'PATH_NOT_FOUND');
});

test('a directory carrying two entries of one name is refused, not silently shadowed', () => {
  // The encoder refuses to produce one. A RECEIVED tree carrying two entries called index.html is
  // asking two resolvers to disagree about which is the site, which is a fork with extra steps —
  // and "first link wins" and "last link wins" are both defensible readings of a format that does
  // not say.
  //
  // The first version of this test built its directory `Data` as `[8]` — the field-1 tag with no
  // value after it. That is malformed protobuf, so the node was refused before the duplicate was
  // ever looked at, and deleting the duplicate check changed nothing. It passed, and it was
  // testing the varint decoder.
  const a = fileBlocks(text('page A'));
  const b = fileBlocks(text('page B'));
  const dir = dagPbBlock(
    encodePbNode(
      [
        { cid: a.cid, name: 'index.html', tsize: a.tsize },
        { cid: b.cid, name: 'index.html', tsize: b.tsize },
      ],
      DIRECTORY_DATA,
    ),
  );
  const source = blockSourceOf([...a.blocks, ...b.blocks, dir]);
  assert.equal(refusal(() => fetchPath(source, dir.cid, 'index.html')), 'MALFORMED_BLOCK');
});

test('descending into a file is a path error rather than a crash', () => {
  const { blocks, root } = importSite([{ path: 'index.html', content: text('home') }]);
  const source = blockSourceOf(blocks);
  assert.equal(refusal(() => fetchPath(source, root, 'index.html/more')), 'PATH_NOT_FOUND');
});

test('a name the directory does not carry is a path error', () => {
  const { blocks, root } = importSite([{ path: 'index.html', content: text('home') }]);
  assert.equal(refusal(() => fetchPath(blockSourceOf(blocks), root, 'nope.html')), 'PATH_NOT_FOUND');
});

test('fetching a directory as a file is refused', () => {
  const { blocks, root } = importSite([{ path: 'index.html', content: text('home') }]);
  assert.equal(refusal(() => fetchFile(blockSourceOf(blocks), root)), 'PATH_NOT_FOUND');
});

/* -------------------------------------------------------------------------- */
/* Malformed input                                                             */
/* -------------------------------------------------------------------------- */

test('malformed protobuf is refused with a code rather than an exception from the decoder', () => {
  const cases: [string, Uint8Array][] = [
    // Field 3 does not exist in dag-pb: how a block smuggles bytes past a reader that skips
    // what it does not recognise.
    ['unknown dag-pb field', Uint8Array.of(0x1a, 0x01, 0x00)],
    // A length that runs past the end of the block.
    ['length past the end', Uint8Array.of(0x12, 0x7f, 0x00)],
    // Wire type 5 (fixed32) — neither dag-pb nor UnixFS uses it.
    ['unsupported wire type', Uint8Array.of(0x15, 0x00, 0x00, 0x00, 0x00)],
    // A varint that never terminates.
    ['unterminated varint', Uint8Array.of(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)],
    // Field number 0.
    ['field number zero', Uint8Array.of(0x02, 0x00)],
  ];
  for (const [why, bytes] of cases) {
    assert.equal(refusal(() => decodeNode(bytes)), 'MALFORMED_BLOCK', why);
  }
});

test('an empty block decodes to a node with nothing in it rather than throwing', () => {
  // Not an error: the empty dag-pb node is a real, published CID with a well-known value. It is
  // simply not a file or a directory, so anything asking it to be one refuses further along.
  const node = decodeNode(new Uint8Array(0));
  assert.deepEqual(node.links, []);
  assert.equal(node.type, -1);
});

test('a CID naming a codec that is not content is refused', () => {
  const bytes = text('bytes');
  // dag-cbor (0x71) is a valid codec and is not something a site serves.
  const cid = encodeCid({ version: 1, codec: 0x71, digest: sha256(bytes) });
  const source: BlockSource = { get: () => bytes };
  assert.equal(refusal(() => fetchFile(source, cid)), 'MALFORMED_BLOCK');
});

/**
 * UnixFS file `Data` with `blocksizes` and `filesize` chosen independently.
 *
 * `unixfsFile` derives filesize from the block sizes, which is right for an honest publisher and
 * useless for testing a reader: every defence in the reader exists for a node whose declarations
 * do NOT agree, and a builder that keeps them consistent cannot construct one. Each test below
 * breaks exactly one relationship, so that removing one check cannot be caught by another.
 */
function hostileFileData(blocksizes: readonly number[], filesize: number): number[] {
  const varint = (value: number): number[] => {
    const out: number[] = [];
    let rest = value;
    while (rest >= 0x80) {
      out.push((rest & 0x7f) | 0x80);
      rest = Math.floor(rest / 128);
    }
    out.push(rest);
    return out;
  };
  const out = [0x08, 2, 0x18, ...varint(filesize)]; // Type = File, then filesize
  for (const size of blocksizes) out.push(0x20, ...varint(size)); // repeated blocksizes
  return out;
}

/** UnixFS `Data` for a directory: field 1 varint, Type = Directory. */
const DIRECTORY_DATA = [0x08, 0x01];

/** A raw leaf and its CID, for building hostile nodes by hand. */
function leafOf(body: string): { cid: string; bytes: Uint8Array } {
  const bytes = text(body);
  return {
    cid: encodeCid({ version: 1, codec: CID_PARAMETERS.codecRaw, digest: sha256(bytes) }),
    bytes,
  };
}
