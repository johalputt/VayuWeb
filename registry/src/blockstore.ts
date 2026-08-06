/**
 * Blocks on disk, and the network behind them.
 *
 * docs/spec/HOSTING.md. {@link ./unixfs.ts} turns a directory into blocks and {@link ./fetch.ts}
 * turns blocks back into bytes; this is the layer that keeps them somewhere and asks a peer for
 * the ones it does not have.
 *
 * ## The verified traversal stays in front of the network, not behind it
 *
 * This is the whole design constraint, and it is the one an integration is most likely to get
 * backwards. Helia will happily assemble a UnixFS tree itself, and using that would be shorter,
 * faster to write, and would move every check in `fetch.ts` out of the path — RESOLUTION.md 12.1
 * to 12.3 would then be enforced by somebody else's library, or not at all, and nothing in this
 * repository would say which.
 *
 * So the blockstore is exposed as a {@link BlockSource} and nothing more. Helia is asked for one
 * block at a time; `fetch.ts` decides what to ask for next, checks every block against the CID
 * that referred it, and bounds the traversal. A library that returns the wrong bytes is caught
 * here exactly as a hostile peer is, because to this code they are the same thing.
 *
 * ## What is honestly not covered
 *
 * Bitswap over a real network is not exercised by this repository's tests. A blockstore on disk
 * is, and so is the traversal in front of it; the part where a stranger on the internet declines
 * to send a block, or sends a different one, needs two machines. HOSTING.md's acceptance test
 * says so and this module does not pretend otherwise.
 */

import { mkdirSync } from 'node:fs';

import { FetchError, decodeNode, type BlockSource } from './fetch.ts';
import { CID_PARAMETERS, decodeCid, sha256 } from './content.ts';
import type { Block } from './unixfs.ts';

/**
 * The subset of a blockstore this module needs, stated as loosely as the real ones behave.
 *
 * `get` and `put` may return the value, a promise for it, or a **generator** — and that third
 * option is not hypothetical. `blockstore-core` declares `*get(key, options)`, an await-or-value
 * generator used for cancellation, and Helia's `BlockStorage` wrapper returns an async generator
 * in turn. An `await` on a generator is a no-op that yields the generator itself, so an interface
 * declaring `Promise<Uint8Array>` type-checks against the real library and hands the caller an
 * object that is not bytes.
 *
 * That is exactly what happened here: every test against a hand-written fake passed, and the
 * first run against a real Helia node failed inside `sha256` with "data argument must be of type
 * string or an instance of Buffer". A fake that returns what the interface *says* is a fake that
 * cannot find a wrong interface. {@link resolveValue} is the boundary, and it exists because this
 * was got wrong rather than because it was foreseen.
 */
export interface AsyncBlocks {
  get(cid: unknown, options?: unknown): unknown;
  put(cid: unknown, block: Uint8Array, options?: unknown): unknown;
  has(cid: unknown): unknown;
}

/** A generator used as an await-or-value trampoline, which is what these libraries return. */
type MaybeGenerator = { next(sent?: unknown): { value: unknown; done?: boolean } };

function isGenerator(value: unknown): value is MaybeGenerator {
  return typeof value === 'object' && value !== null && typeof (value as MaybeGenerator).next === 'function';
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as AsyncIterable<unknown>)[Symbol.asyncIterator] === 'function'
  );
}

function isThenable(value: unknown): value is Promise<unknown> {
  return typeof value === 'object' && value !== null && typeof (value as Promise<unknown>).then === 'function';
}

/**
 * Reduce whatever a blockstore returned to the bytes it stands for.
 *
 * Three shapes, because three shapes arrive: a value, a promise, or a generator that yields the
 * value and returns nothing. The last is the one that reads as working and is not — driving it
 * and taking the RETURN value gives `undefined`, because `blockstore-core` yields its result
 * rather than returning it.
 *
 * A `Uint8ArrayList`-shaped result is flattened via `subarray`, which every such type provides.
 * Nothing here trusts the bytes; they go straight to a hash comparison afterwards.
 */
export async function resolveValue(value: unknown, depth = 0): Promise<unknown> {
  if (depth > 4) throw new FetchError('MALFORMED_BLOCK', 'blockstore result nested too deeply');
  if (isThenable(value)) return resolveValue(await value, depth + 1);
  // Checked BEFORE the synchronous-generator branch: an AsyncGenerator also has `next`, but its
  // `next()` answers a promise, so treating it as a sync generator reads `undefined` out of a
  // pending object and reports "not bytes" for a store that is working perfectly. Helia's
  // `BlockStorage` returns exactly this, and getting the order wrong is how the second attempt
  // at this adapter failed after the first one had already failed differently.
  if (isAsyncIterable(value)) {
    let last: unknown;
    let seen = 0;
    for await (const item of value) {
      last = item;
      if ((seen += 1) > 64) break;
    }
    return resolveValue(last, depth + 1);
  }
  if (isGenerator(value)) {
    let last: unknown;
    for (let step = value.next(), guard = 0; guard < 64; guard += 1) {
      if (step.value !== undefined) last = step.value;
      if (step.done === true) break;
      step = value.next(await Promise.resolve(step.value));
    }
    return resolveValue(last, depth + 1);
  }
  return value;
}

/** Coerce a resolved blockstore result into real bytes, or refuse. */
export async function blockBytes(value: unknown, cid: string): Promise<Uint8Array> {
  const resolved = await resolveValue(value);
  if (resolved instanceof Uint8Array) return resolved;
  // A Uint8ArrayList and friends expose `subarray()`, which flattens.
  const list = resolved as { subarray?: () => unknown };
  if (typeof list?.subarray === 'function') {
    const flat = list.subarray();
    if (flat instanceof Uint8Array) return flat;
  }
  throw new FetchError(
    'MALFORMED_BLOCK',
    `the blockstore returned ${Object.prototype.toString.call(resolved)} for ${cid}, not bytes`,
  );
}

/** Turn a CID string into the multiformats-shaped object a Helia blockstore expects. */
export interface CidCodec {
  parse(text: string): unknown;
}

/** Bounds this layer applies on top of the traversal's own. */
export const STORE_LIMITS = {
  /**
   * How long one block may take to arrive, in milliseconds.
   *
   * RESOLUTION.md step 11 gives a 15 second first-byte timeout and a 120 second total budget. A
   * per-block deadline is the piece that makes the total reachable: without one, a peer that
   * sends a byte a minute holds the request open forever while never quite failing.
   */
  blockMs: 15_000,
} as const;

/**
 * A synchronous {@link BlockSource} over a bag of blocks already held.
 *
 * The traversal is synchronous because every refusal in it is a decision about bytes, and making
 * it async would put an await in front of each one for no benefit. Content that has to come from
 * the network is therefore fetched first and traversed second — see {@link prefetch}.
 */
export function memorySource(blocks: readonly Block[]): BlockSource {
  const byCid = new Map<string, Uint8Array>();
  for (const block of blocks) if (!byCid.has(block.cid)) byCid.set(block.cid, block.bytes);
  return { get: (cid) => byCid.get(cid) ?? null };
}

/**
 * Walk a tree from `root`, pulling every block it references into memory.
 *
 * **This does not verify anything, and must not be mistaken for the fetch.** It is a
 * breadth-first pull whose only job is to make the bytes locally available so the real traversal
 * can run synchronously over them. Every block it pulls is checked against its CID afterwards by
 * `fetch.ts`, which is the check that counts; a block that arrives wrong is collected here and
 * refused there.
 *
 * The one check it *does* make is the cheap one that makes the bound meaningful: a block whose
 * bytes do not hash to the CID that asked for it is not stored, so a peer cannot fill this map
 * with rubbish keyed by CIDs it does not own. That is not a substitute for the traversal's
 * verification — it is the same check, applied early, so the budget below counts real blocks.
 */
export async function prefetch(
  blocks: AsyncBlocks,
  codec: CidCodec,
  root: string,
  limits: { blocks: number; timeoutMs?: number },
): Promise<Map<string, Uint8Array>> {
  const held = new Map<string, Uint8Array>();
  const queue: string[] = [root];
  const seen = new Set<string>();

  while (queue.length > 0) {
    const cid = queue.shift()!;
    if (seen.has(cid)) continue;
    seen.add(cid);

    // Counted on DISTINCT blocks here, unlike the traversal's budget which counts every fetch.
    // The two answer different questions: this one bounds the network, that one bounds the work a
    // repeated link can cause, and conflating them would let one of the two attacks through.
    if (held.size >= limits.blocks) {
      throw new FetchError(
        'RESPONSE_TOO_LARGE',
        `this tree references more than ${limits.blocks} distinct blocks`,
      );
    }

    const bytes = await withDeadline(
      blockBytes(blocks.get(codec.parse(cid)), cid),
      limits.timeoutMs ?? STORE_LIMITS.blockMs,
      cid,
    );

    // The same check the traversal makes, applied here so the budget above counts real blocks
    // rather than whatever a peer chose to return.
    const digest = sha256(bytes);
    const expected = decodeCid(cid).digest;
    let same = digest.length === expected.length ? 0 : 1;
    for (let i = 0; i < digest.length && i < expected.length; i += 1) {
      same |= digest[i]! ^ expected[i]!;
    }
    if (same !== 0) {
      throw new FetchError('CONTENT_INTEGRITY', `bytes offered for ${cid} hash to something else`);
    }

    held.set(cid, bytes);
    for (const child of childrenOf(cid, bytes)) queue.push(child);
  }
  return held;
}

/** Reject rather than hang. A promise with no deadline is a request a peer can hold open. */
async function withDeadline<T>(promise: Promise<T>, ms: number, cid: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new FetchError('CONTENT_UNAVAILABLE', `no block for ${cid} within ${ms}ms`)),
          ms,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * The CIDs a block links to, or none.
 *
 * Decoding is delegated to `fetch.ts` so that this module has no second opinion about the format.
 * A parse failure yields no children rather than throwing: the block is still stored, and the
 * traversal refuses it properly with a code. Two places deciding what a malformed block means is
 * how two answers to one question appear.
 */
function childrenOf(cid: string, bytes: Uint8Array): string[] {
  if (decodeCid(cid).codec !== CID_PARAMETERS.codecDagPb) return [];
  try {
    return decodeNode(bytes).links.map((link) => link.cid);
  } catch {
    return [];
  }
}

/** Put every block of a published tree into the store. */
export async function publish(
  blocks: AsyncBlocks,
  codec: CidCodec,
  built: readonly Block[],
): Promise<number> {
  let written = 0;
  for (const block of built) {
    // Resolved for the same reason `get` is: `put` is also declared as a generator by
    // `blockstore-core`, and a `put` nobody drives is a block nobody stored.
    await resolveValue(blocks.put(codec.parse(block.cid), block.bytes));
    written += 1;
  }
  return written;
}

/** Create the directory a filesystem blockstore needs, with the mode a private store should have. */
export function prepareStoreDirectory(path: string): string {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}
