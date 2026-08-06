import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  STORE_LIMITS,
  blockBytes,
  memorySource,
  prefetch,
  prepareStoreDirectory,
  publish,
  resolveValue,
  type AsyncBlocks,
  type CidCodec,
} from './blockstore.ts';
import { FetchError, fetchPath, fetchFile, blockSourceOf } from './fetch.ts';
import { importSite, fileBlocks, type Block } from './unixfs.ts';
import { CID_PARAMETERS, decodeCid, encodeCid, sha256 } from './content.ts';

const text = (s: string): Uint8Array => new TextEncoder().encode(s);
const read = (b: Uint8Array): string => new TextDecoder().decode(b);

const refusal = async (run: () => Promise<unknown>): Promise<string> => {
  try {
    await run();
    return 'accepted';
  } catch (error) {
    return error instanceof FetchError ? error.code : `threw:${String(error)}`;
  }
};

/**
 * A blockstore keyed by CID string, with the multiformats-shaped `parse` a Helia store expects.
 *
 * The real `CID.parse` returns an object; nothing in this module reads it, which is the point —
 * the CID string stays the identity throughout and the codec is a boundary adapter.
 */
function fakeStore(): AsyncBlocks & { codec: CidCodec; contents: Map<string, Uint8Array> } {
  const contents = new Map<string, Uint8Array>();
  return {
    contents,
    codec: { parse: (t: string) => t },
    // Returns an ASYNC GENERATOR, exactly as Helia's BlockStorage does, rather than the
    // `Promise<Uint8Array>` the first version of this fake returned. A double that is easier to
    // satisfy than the real thing is a double that certifies code the real thing rejects.
    get(cid: unknown) {
      const held = contents.get(String(cid));
      if (held === undefined) throw new Error(`not held: ${String(cid)}`);
      return (async function* () {
        yield held;
      })();
    },
    // A generator FUNCTION, as `blockstore-core` declares `put` — so the write happens only when
    // somebody drives it. The first version of this double did the write eagerly and returned a
    // generator afterwards, which meant a `publish` that never drove the generator still stored
    // every block and the mutation removing the drive survived. Three times now this double has
    // been more agreeable than the library it stands for; each time the double was the defect.
    *put(cid: unknown, block: Uint8Array) {
      contents.set(String(cid), block);
      yield cid;
    },
    async has(cid: unknown) {
      return contents.has(String(cid));
    },
  };
}

/* -------------------------------------------------------------------------- */
/* The four shapes a real blockstore returns                                   */
/* -------------------------------------------------------------------------- */

test('a blockstore result is reduced to bytes from any of the shapes libraries use', async () => {
  // This suite existed and passed entirely against a fake returning `Promise<Uint8Array>`, which
  // is what the interface said. The first run against a real Helia node failed inside `sha256`
  // with "data argument must be of type string or an instance of Buffer" — because
  // `blockstore-core` declares `*get(key, options)`, a synchronous await-or-value generator, and
  // Helia's `BlockStorage` wrapper returns an ASYNC generator over it. An `await` on either is a
  // no-op that hands back the generator.
  //
  // A fake that returns what the interface claims cannot find a wrong interface. All four shapes
  // are pinned here so the fake can never again be more agreeable than the library.
  const bytes = text('the block');

  assert.deepEqual(await blockBytes(bytes, 'plain'), bytes, 'a plain value');
  assert.deepEqual(await blockBytes(Promise.resolve(bytes), 'promise'), bytes, 'a promise');

  function* syncGen(): Generator<Uint8Array> {
    yield bytes;
  }
  assert.deepEqual(await blockBytes(syncGen(), 'sync generator'), bytes, 'a sync generator');

  async function* asyncGen(): AsyncGenerator<Uint8Array> {
    yield bytes;
  }
  assert.deepEqual(await blockBytes(asyncGen(), 'async generator'), bytes, 'an async generator');

  // A Uint8ArrayList-shaped result: flattened via subarray, which every such type provides.
  assert.deepEqual(
    await blockBytes({ subarray: () => bytes }, 'list'),
    bytes,
    'a byte-list wrapper',
  );
});

test('an async generator is not mistaken for a synchronous one', async () => {
  // The order of the two branches is the whole fix. An AsyncGenerator also has `next`, but its
  // `next()` answers a promise — so reading `.value` off it synchronously yields `undefined` and
  // the adapter reports "not bytes" for a store that is working perfectly. That was the second
  // failed attempt, after the first had already failed differently.
  const bytes = text('async only');
  async function* gen(): AsyncGenerator<Uint8Array> {
    yield bytes;
  }
  const resolved = await resolveValue(gen());
  assert.ok(resolved instanceof Uint8Array, `got ${Object.prototype.toString.call(resolved)}`);
});

test('something that is not bytes at all is refused with a code', async () => {
  assert.equal(
    await refusal(async () => blockBytes({ nothing: true }, 'bafyfake')),
    'MALFORMED_BLOCK',
  );
  assert.equal(await refusal(async () => blockBytes(undefined, 'bafyfake')), 'MALFORMED_BLOCK');
});

/* -------------------------------------------------------------------------- */
/* Publish, then fetch back through the verified traversal                     */
/* -------------------------------------------------------------------------- */

test('a site published into a store is fetched back through the traversal', async () => {
  const files = [
    { path: 'index.html', content: text('<!doctype html><title>home</title>') },
    { path: 'assets/deep/note.txt', content: text('nested') },
  ];
  const { blocks, root } = importSite(files);
  const store = fakeStore();

  assert.equal(await publish(store, store.codec, blocks), blocks.length);

  const held = await prefetch(store, store.codec, root, { blocks: 256 });
  const source = { get: (cid: string) => held.get(cid) ?? null };

  for (const file of files) {
    assert.equal(read(fetchPath(source, root, file.path)), read(file.content));
  }
});

test('a multi-chunk file survives the round trip through the store', async () => {
  const size = CID_PARAMETERS.chunkBytes * 2 + 99;
  const content = new Uint8Array(size);
  for (let i = 0; i < size; i += 1) content[i] = (i * 11 + 5) & 0xff;

  const built = fileBlocks(content);
  const store = fakeStore();
  await publish(store, store.codec, built.blocks);

  const held = await prefetch(store, store.codec, built.cid, { blocks: 256 });
  assert.deepEqual(fetchFile({ get: (cid) => held.get(cid) ?? null }, built.cid), content);
});

/* -------------------------------------------------------------------------- */
/* The store is not trusted, because it is a network                           */
/* -------------------------------------------------------------------------- */

test('a store returning the wrong bytes is refused, exactly as a hostile peer is', async () => {
  // The property that makes keeping `fetch.ts` in front of the library worth the extra code. A
  // blockstore is a cache in front of strangers; to this code a buggy library and a lying peer
  // are the same thing, and neither gets to decide what a CID means.
  const { blocks, root } = importSite([{ path: 'index.html', content: text('real') }]);
  const store = fakeStore();
  await publish(store, store.codec, blocks);

  const honest = store.get.bind(store);
  store.get = async (cid: unknown) => {
    const bytes = await honest(cid);
    // Corrupt exactly one block: a leaf, leaving every directory node authentic.
    return decodeCid(String(cid)).codec === CID_PARAMETERS.codecRaw ? text('forged!') : bytes;
  };

  assert.equal(
    await refusal(() => prefetch(store, store.codec, root, { blocks: 256 })),
    'CONTENT_INTEGRITY',
  );
});

test('a tree referencing more distinct blocks than the budget is refused', async () => {
  const { blocks, root } = importSite([
    { path: 'a.txt', content: text('a') },
    { path: 'b.txt', content: text('b') },
    { path: 'c.txt', content: text('c') },
  ]);
  const store = fakeStore();
  await publish(store, store.codec, blocks);
  assert.ok(blocks.length > 2, 'the fixture must exceed the budget below');

  assert.equal(
    await refusal(() => prefetch(store, store.codec, root, { blocks: 2 })),
    'RESPONSE_TOO_LARGE',
  );
});

test('a block that never arrives fails on a deadline rather than hanging', async () => {
  // A promise with no deadline is a request a peer can hold open forever while never quite
  // failing, which is how a 120-second total budget becomes unreachable.
  const built = fileBlocks(text('slow'));
  const store = fakeStore();
  await publish(store, store.codec, built.blocks);
  store.get = () => new Promise<Uint8Array>(() => undefined);

  // Raced against a much longer timer rather than measured with a clock. Two reasons: reading
  // `Date.now()` is ambient nondeterminism that `check-source-hygiene.py` refuses, and a bare
  // assertion on the code would HANG rather than fail if the deadline were removed — a hang
  // reports as a CI timeout instead of as a missing defence, which this repository has already
  // been bitten by once. The race turns "never gives up" into a named failure.
  const outcome = await Promise.race([
    refusal(() => prefetch(store, store.codec, built.cid, { blocks: 8, timeoutMs: 60 })),
    new Promise<string>((resolve) => setTimeout(() => resolve('HUNG'), 5_000)),
  ]);
  assert.equal(outcome, 'CONTENT_UNAVAILABLE', 'it gave up rather than waiting');
});

test('the default per-block deadline is finite and stated', () => {
  assert.ok(Number.isFinite(STORE_LIMITS.blockMs) && STORE_LIMITS.blockMs > 0);
  // RESOLUTION.md step 11's first-byte timeout. Pinned so the two cannot part company silently.
  assert.equal(STORE_LIMITS.blockMs, 15_000);
});

test('a shared subtree is pulled once and still traverses correctly', async () => {
  // Two files with identical content share a leaf CID. The prefetch counts distinct blocks, so
  // the sharing is a saving here — while the traversal's own budget still counts every visit,
  // because that is the one an attacker inflates.
  const same = text('identical bytes');
  const { blocks, root } = importSite([
    { path: 'one.txt', content: same },
    { path: 'two.txt', content: same },
  ]);
  const store = fakeStore();
  await publish(store, store.codec, blocks);

  let gets = 0;
  const honest = store.get.bind(store);
  store.get = async (cid: unknown) => {
    gets += 1;
    return honest(cid);
  };

  const held = await prefetch(store, store.codec, root, { blocks: 64 });
  const source = { get: (cid: string) => held.get(cid) ?? null };
  assert.equal(read(fetchPath(source, root, 'one.txt')), 'identical bytes');
  assert.equal(read(fetchPath(source, root, 'two.txt')), 'identical bytes');
  assert.equal(gets, held.size, 'each distinct block was pulled exactly once');
});

/* -------------------------------------------------------------------------- */
/* Small helpers                                                               */
/* -------------------------------------------------------------------------- */

test('memorySource answers for what it holds and null for what it does not', () => {
  const built = fileBlocks(text('held'));
  const source = memorySource(built.blocks);
  assert.deepEqual(source.get(built.cid), built.blocks[0]!.bytes);
  const absent = encodeCid({
    version: 1,
    codec: CID_PARAMETERS.codecRaw,
    digest: sha256(text('never stored')),
  });
  assert.equal(source.get(absent), null);
});

test('memorySource and blockSourceOf agree, so neither is a second opinion', () => {
  // Two functions that answer the same question in two modules is how two answers appear. They
  // are pinned against each other rather than left to look similar.
  const { blocks } = importSite([{ path: 'x.txt', content: text('x') }]);
  const a = memorySource(blocks);
  const b = blockSourceOf(blocks as readonly Block[]);
  for (const block of blocks) {
    assert.deepEqual(a.get(block.cid), b.get(block.cid), block.cid);
  }
});

test('the store directory is created private', () => {
  const path = prepareStoreDirectory(
    join(mkdtempSync(join(tmpdir(), 'vayuweb-blocks-')), 'blocks'),
  );
  const mode = statSync(path).mode & 0o777;
  assert.equal(mode, 0o700, 'a blockstore is not world-readable');
});
