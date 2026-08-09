/**
 * RESOLUTION.md's caching and TTL policy, from the side that wants it wrong.
 *
 * The policy is short and every clause in it is load-bearing, which is why the implementation that
 * covered one of its five cacheable codes still looked finished: a cache that caches the common
 * case is a cache that works, right up to the request where the code it stored is not the code it
 * returns.
 *
 * Two things these tests are mostly about, neither of which is "does it cache":
 *
 * - **What must NOT be cached**, because every never-cache clause in the specification is there to
 *   stop a transient failure becoming a sticky one, and a resolver that caches generously looks
 *   faster in every benchmark and worse in every incident.
 * - **What must stop being cached the moment it stops being true**, because a positive hit skips
 *   the validity window at step 8, and a cache is only allowed to skip a check it has made
 *   unnecessary.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  CACHE_CEILINGS,
  CACHE_ENTRY_ALLOWANCE,
  CACHE_LIMITS,
  NEGATIVE_TTL_SECONDS,
  POSITIVE_TTL_SECONDS,
  ResolutionCache,
} from './cache.ts';
import { RESOLVE_ERRORS, resolveName, type ResolverPorts, type Outcome } from './resolve.ts';
import { parseRecord, type RegistryRecord } from './record.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH } from './pow.ts';
import type { CborMap, CborValue } from './cbor.ts';

const NOW = 1_782_518_400;
const TERM = 31_536_000;
/** REGISTRY.md's grace period: how long after `notAfter` a name is in GRACE rather than free. */
const GRACE = 2_592_000;

const pow = (): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['alg', POW_ALGORITHM],
    ['nonce', new Uint8Array(POW_NONCE_LENGTH).fill(7)],
    ['bits', 10],
  ]);

const entry = (type: string, value: CborValue): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['type', type],
    ['value', value],
  ]);

function rec(
  name: string,
  over: Record<string, CborValue> = {},
  entries: CborValue[] = [entry('cid', new Uint8Array(32).fill(0xcc))],
): RegistryRecord {
  const m = new Map<string | Uint8Array, CborValue>([
    ['version', 1],
    ['suite', 1],
    ['op', 'REGISTER'],
    ['name', name],
    ['tld', 'vayu'],
    ['ownerKey', new Uint8Array(32).fill(0x11)],
    ['seq', 0],
    ['notBefore', NOW],
    ['notAfter', NOW + TERM],
    ['records', entries],
    ['powProof', pow()],
    ['prevHash', new Uint8Array(32)],
    ['sig', new Uint8Array(64).fill(0xaa)],
  ]);
  for (const [k, v] of Object.entries(over)) m.set(k, v);
  return parseRecord(m);
}

/** A registry that counts how often it was asked, so a cache hit is provable rather than assumed. */
function countingPorts(records: Record<string, RegistryRecord>): ResolverPorts & {
  lookups: string[];
} {
  const lookups: string[] = [];
  return {
    lookups,
    lookup: (label, tld) => {
      lookups.push(`${label}.${tld}`);
      return records[`${label}.${tld}`] ?? null;
    },
    hasVerifiedHead: () => true,
  };
}

const code = (o: Outcome): string => (o.ok ? 'ok' : o.error);

/* -------------------------------------------------------------------------- */
/* The table, against the words in the specification                          */
/* -------------------------------------------------------------------------- */

test('every TTL the specification states is the TTL the table uses', () => {
  // Written out as literals rather than derived from the table, because a test that reads the
  // value it is checking is a test that agrees with any value. These numbers come from
  // RESOLUTION.md, "Caching and TTL policy", and nowhere else.
  assert.equal(NEGATIVE_TTL_SECONDS.NAME_NOT_FOUND, 30);
  assert.equal(NEGATIVE_TTL_SECONDS.NAME_EXPIRED, 60);
  assert.equal(NEGATIVE_TTL_SECONDS.NAME_QUARANTINED, 60);
  assert.equal(NEGATIVE_TTL_SECONDS.NAME_REVOKED, 60);
  assert.equal(NEGATIVE_TTL_SECONDS.CONTENT_UNAVAILABLE, 10);
  assert.equal(NEGATIVE_TTL_SECONDS.IPNS_UNRESOLVED, 10);
  assert.equal(POSITIVE_TTL_SECONDS, 300);
});

test('every code in the catalogue has a caching decision, and none is made by omission', () => {
  // The guard against the failure mode this table replaced. A code added to `RESOLVE_ERRORS`
  // without an entry here would previously have inherited whatever the lookup's default was —
  // policy decided by an absence. The type makes it a compile error; this makes it visible.
  for (const name of Object.keys(RESOLVE_ERRORS)) {
    assert.ok(
      name in NEGATIVE_TTL_SECONDS,
      `${name} has no caching decision — say what it means, do not let it default`,
    );
  }
  assert.equal(
    Object.keys(NEGATIVE_TTL_SECONDS).length,
    Object.keys(RESOLVE_ERRORS).length,
    'and the table names nothing the catalogue does not',
  );
});

test('a hit returns the code that was stored, not the one code the cache used to know', () => {
  // The bug the single-code cache was one line away from. It stored a boolean and answered
  // `NAME_NOT_FOUND`; the moment a second code became cacheable, every hit would have told the
  // reader that a name nobody has registered was the problem — for a name that is registered,
  // expired, quarantined or revoked. Four wrong answers, all of them confident.
  const cache = new ResolutionCache();
  cache.putNegative('expired.vayu', 'NAME_EXPIRED', NOW);
  cache.putNegative('held.vayu', 'NAME_QUARANTINED', NOW);
  cache.putNegative('gone.vayu', 'NAME_NOT_FOUND', NOW);

  assert.equal(cache.negative('expired.vayu', NOW + 1), 'NAME_EXPIRED');
  assert.equal(cache.negative('held.vayu', NOW + 1), 'NAME_QUARANTINED');
  assert.equal(cache.negative('gone.vayu', NOW + 1), 'NAME_NOT_FOUND');
});

test('each cacheable code expires at its own TTL and not at the shortest or the longest', () => {
  const cache = new ResolutionCache();
  const cases = [
    ['gone.vayu', 'NAME_NOT_FOUND', 30],
    ['expired.vayu', 'NAME_EXPIRED', 60],
    ['offline.vayu', 'CONTENT_UNAVAILABLE', 10],
  ] as const;
  for (const [key, error, ttl] of cases) {
    cache.putNegative(key, error, NOW);
    assert.equal(cache.negative(key, NOW + ttl - 1), error, `${error} must last ${ttl}s`);
    assert.equal(cache.negative(key, NOW + ttl), null, `${error} must not outlast ${ttl}s`);
  }
});

/* -------------------------------------------------------------------------- */
/* What must never be cached                                                  */
/* -------------------------------------------------------------------------- */

test('I make your resolver refuse a site permanently by feeding it one bad copy', () => {
  // The attack that makes `CONTENT_INTEGRITY`'s never-cache clause load-bearing. I get one
  // corrupted response through — a peer serving bytes that do not hash to the CID. If your
  // resolver caches that refusal, I have taken the site down for everyone behind your resolver for
  // the length of the TTL, at the cost of one bad block, and I can repeat it.
  //
  // The same reasoning covers `REGISTRY_UNAVAILABLE`: it is a fact about the resolver rather than
  // about the name, and it stops being true without any name changing.
  const cache = new ResolutionCache();
  assert.equal(cache.putNegative('atlas.vayu', 'CONTENT_INTEGRITY', NOW), false);
  assert.equal(cache.putNegative('atlas.vayu', 'REGISTRY_UNAVAILABLE', NOW), false);
  assert.equal(cache.negative('atlas.vayu', NOW), null, 'neither may become sticky');
  assert.equal(cache.negativeSize, 0, 'and neither may occupy an entry');
});

test('nothing the specification does not name gets cached because it looked cacheable', () => {
  const cache = new ResolutionCache();
  const uncacheable = Object.entries(NEGATIVE_TTL_SECONDS)
    .filter(([, ttl]) => ttl === null)
    .map(([name]) => name);
  assert.ok(uncacheable.length >= 12, 'most of the catalogue is not cacheable');
  for (const name of uncacheable) {
    assert.equal(
      cache.putNegative(`x-${name}.vayu`, name as keyof typeof NEGATIVE_TTL_SECONDS, NOW),
      false,
      `${name} has no TTL, so storing it would be inventing one`,
    );
  }
  assert.equal(cache.negativeSize, 0);
});

test('I fill your memory with names nobody will ever ask for twice', () => {
  const cache = new ResolutionCache({ negativeEntries: 8, positiveEntries: 4 });
  for (let i = 0; i < 1_000; i += 1) cache.putNegative(`name${i}.vayu`, 'NAME_NOT_FOUND', NOW);
  assert.equal(cache.negativeSize, 8);

  // The positive half is bounded for the same reason, even though filling it needs registered
  // names. "Expensive for an attacker" is a claim about today's namespace; a bound is not.
  for (let i = 0; i < 1_000; i += 1) cache.putPositive(`name${i}.vayu`, rec(`name${i}`), NOW);
  assert.equal(cache.positiveSize, 4);
  assert.ok(CACHE_LIMITS.positiveEntries > 0);
});

/* -------------------------------------------------------------------------- */
/* The positive cache, which skips a check and must earn the skip             */
/* -------------------------------------------------------------------------- */

test('I keep an expired name serving by getting it cached one second before it lapses', () => {
  // A positive hit goes to step 9, skipping the validity window at step 8 — so without the cap at
  // `notAfter` this is free: get the name resolved while it is live, and it keeps serving for the
  // rest of the TTL after its term ends. Step 8 says a resolver MUST NOT resolve an expired name
  // "even if the old `cid` is still held locally", and a cache is a local copy.
  const expiring = rec('atlas', { notAfter: NOW + 1 });
  const cache = new ResolutionCache();
  const ports = countingPorts({ 'atlas.vayu': expiring });

  assert.equal(code(resolveName('atlas.vayu', ports, NOW, cache)), 'ok');
  assert.equal(cache.positiveSize, 1, 'it was cached while live');

  // One second later the name is in grace. The TTL says 300 seconds; the term says otherwise.
  const after = resolveName('atlas.vayu', ports, NOW + 1, cache);
  assert.equal(code(after), 'NAME_EXPIRED', 'the cap at notAfter is what makes the skip safe');
});

test('a record already past its term is not cached at all, rather than cached uselessly', () => {
  // An entry that can never be served is memory an attacker allocates for free by asking about
  // names in grace.
  const cache = new ResolutionCache();
  const lapsedNow = rec('atlas', { notBefore: NOW - TERM, notAfter: NOW });
  const lapsedEarlier = rec('atlas', { notBefore: NOW - TERM, notAfter: NOW - 1 });
  assert.equal(cache.putPositive('atlas.vayu', lapsedNow, NOW), false);
  assert.equal(cache.putPositive('atlas.vayu', lapsedEarlier, NOW), false);
  assert.equal(cache.positiveSize, 0);
});

test('a cached answer says so, which nothing could say before', () => {
  // `resolvedFrom: 'cache'` was a declared value with no producer — the diagnostic header
  // RESOLUTION.md enumerates could only ever read `registry`, so an operator debugging a stale
  // answer had no way to see that it came from a cache.
  const cache = new ResolutionCache();
  const ports = countingPorts({ 'atlas.vayu': rec('atlas') });

  const first = resolveName('atlas.vayu', ports, NOW, cache);
  assert.equal(first.diagnostics.resolvedFrom, 'registry');

  const second = resolveName('atlas.vayu', ports, NOW + 1, cache);
  assert.equal(second.diagnostics.resolvedFrom, 'cache');
  assert.deepEqual(ports.lookups, ['atlas.vayu'], 'and the registry was asked exactly once');
});

test('a negative answer from the cache says so too', () => {
  const cache = new ResolutionCache();
  const ports = countingPorts({});
  assert.equal(code(resolveName('atlas.vayu', ports, NOW, cache)), 'NAME_NOT_FOUND');
  const again = resolveName('atlas.vayu', ports, NOW + 5, cache);
  assert.equal(code(again), 'NAME_NOT_FOUND');
  assert.equal(again.diagnostics.resolvedFrom, 'cache');
  assert.equal(ports.lookups.length, 1, 'the second request did not reach the registry');
});

test('a cached record is served for its own name and no other', () => {
  const cache = new ResolutionCache();
  const ports = countingPorts({ 'atlas.vayu': rec('atlas') });
  resolveName('atlas.vayu', ports, NOW, cache);
  assert.equal(code(resolveName('borealis.vayu', ports, NOW, cache)), 'NAME_NOT_FOUND');
});

/* -------------------------------------------------------------------------- */
/* Generation: the TTL is a bound, not a promise                              */
/* -------------------------------------------------------------------------- */

test('I revoke my compromised key and your resolver keeps serving me for five minutes', () => {
  // RESOLUTION.md accepts this in terms — "five minutes bounds how long a superseded owner key
  // stays usable" — and on a resolver whose registry is a local log it is five minutes bought for
  // nothing, because the lookup a positive entry saves is a map read. `REVOKE` exists to stop
  // content being served from a key its holder has declared compromised, and every record that
  // could supersede a cached one arrives by an append.
  const live = rec('atlas');
  const registry: Record<string, RegistryRecord> = { 'atlas.vayu': live };
  const ports = countingPorts(registry);
  const cache = new ResolutionCache();

  cache.setGeneration(1);
  assert.equal(code(resolveName('atlas.vayu', ports, NOW, cache)), 'ok');
  assert.equal(code(resolveName('atlas.vayu', ports, NOW + 1, cache)), 'ok');
  assert.equal(ports.lookups.length, 1, 'the second answer came from the cache');

  // The revocation lands in the log. One append, one generation.
  // A REVOKE carries no proof of work — REGISTRY.md requires `powProof` null on everything but
  // REGISTER and RENEW — and the parser enforces it, which is why this fixture says so.
  registry['atlas.vayu'] = rec('atlas', { op: 'REVOKE', seq: 1, powProof: null });
  cache.setGeneration(2);

  const after = resolveName('atlas.vayu', ports, NOW + 2, cache);
  assert.equal(code(after), 'NAME_REVOKED', 'on the next request, not five minutes later');
  assert.equal(after.diagnostics.resolvedFrom, 'registry');
});

test('a name I register is found on the next request, not thirty seconds later', () => {
  // The negative half of the same property. `NAME_NOT_FOUND` is cached for thirty seconds because
  // "a name may be registered at any moment" — and this resolver knows the moment.
  const registry: Record<string, RegistryRecord> = {};
  const ports = countingPorts(registry);
  const cache = new ResolutionCache();
  cache.setGeneration(7);
  assert.equal(code(resolveName('atlas.vayu', ports, NOW, cache)), 'NAME_NOT_FOUND');

  registry['atlas.vayu'] = rec('atlas');
  cache.setGeneration(8);
  assert.equal(code(resolveName('atlas.vayu', ports, NOW + 1, cache)), 'ok');
});

test('a generation that has not moved is not a reason to re-resolve anything', () => {
  // The other direction, because a cache that clears on every call is a cache that does nothing
  // while looking correct in every test above.
  const cache = new ResolutionCache();
  const ports = countingPorts({ 'atlas.vayu': rec('atlas') });
  for (let i = 0; i < 5; i += 1) {
    cache.setGeneration(3);
    assert.equal(code(resolveName('atlas.vayu', ports, NOW + i, cache)), 'ok');
  }
  assert.equal(ports.lookups.length, 1, 'one lookup for five requests at one generation');
});

test('without a generation the cache is exactly what the specification describes', () => {
  // An embedder with no registry to count still gets the TTLs, and nothing here depends on the
  // tightening being wired. That matters because the tightening is this implementation's, not the
  // protocol's, and a second implementation reading RESOLUTION.md must not be at a disadvantage.
  const cache = new ResolutionCache();
  const ports = countingPorts({ 'atlas.vayu': rec('atlas') });
  assert.equal(code(resolveName('atlas.vayu', ports, NOW, cache)), 'ok');
  assert.equal(code(resolveName('atlas.vayu', ports, NOW + POSITIVE_TTL_SECONDS - 1, cache)), 'ok');
  assert.equal(ports.lookups.length, 1);
  assert.equal(code(resolveName('atlas.vayu', ports, NOW + POSITIVE_TTL_SECONDS, cache)), 'ok');
  assert.equal(ports.lookups.length, 2, 'the positive TTL is 300 seconds and it is enforced');
});

/* -------------------------------------------------------------------------- */
/* Where the lookups happen, which is inside the algorithm                    */
/* -------------------------------------------------------------------------- */

test('an alias hop consults the cache for the name it lands on', () => {
  // Steps 5 and 6 sit between step 4 and step 7, and step 10 restarts at step 4 — so a chain
  // reaching a cached name must answer from the cache. With the lookups outside the algorithm,
  // where they used to be, only the name in the `Host` header was ever checked: a request for
  // `a.vayu` aliasing to a negatively cached `b.vayu` paid a full registry lookup that a direct
  // request for `b.vayu` would have skipped.
  const aliasing = rec('atlas', {}, [entry('alias', 'borealis.vayu')]);
  const ports = countingPorts({ 'atlas.vayu': aliasing });
  const cache = new ResolutionCache();

  assert.equal(code(resolveName('atlas.vayu', ports, NOW, cache)), 'NAME_NOT_FOUND');
  assert.deepEqual(ports.lookups, ['atlas.vayu', 'borealis.vayu']);

  // Second time round: `atlas.vayu` comes from the positive cache and `borealis.vayu` from the
  // negative one, so the registry is not asked at all.
  const again = resolveName('atlas.vayu', ports, NOW + 1, cache);
  assert.equal(code(again), 'NAME_NOT_FOUND');
  assert.equal(ports.lookups.length, 2, 'neither hop reached the registry the second time');
});

test('a name in quarantine is cached as quarantined, and answers that on the next request', () => {
  // The whole point of storing the code: this name is not missing, and telling its owner it is
  // sends them to register something they already hold and cannot re-register yet.
  const lapsed = rec('atlas', { notBefore: NOW - TERM - GRACE - 1, notAfter: NOW - GRACE - 1 });
  const ports = countingPorts({ 'atlas.vayu': lapsed });
  const cache = new ResolutionCache();

  assert.equal(code(resolveName('atlas.vayu', ports, NOW, cache)), 'NAME_QUARANTINED');
  const again = resolveName('atlas.vayu', ports, NOW + 30, cache);
  assert.equal(code(again), 'NAME_QUARANTINED', 'stored at 60s, so 30s later it is still held');
  assert.equal(again.diagnostics.resolvedFrom, 'cache');
  assert.equal(ports.lookups.length, 1);

  assert.equal(
    code(resolveName('atlas.vayu', ports, NOW + 60, cache)),
    'NAME_QUARANTINED',
    'and after the TTL the registry is asked again and says the same thing',
  );
  assert.equal(ports.lookups.length, 2);
});

test('a resolver with no verified head caches nothing, however often it is asked', () => {
  const ports: ResolverPorts = { lookup: () => null, hasVerifiedHead: () => false };
  const cache = new ResolutionCache();
  for (let i = 0; i < 50; i += 1) {
    assert.equal(code(resolveName(`name${i}.vayu`, ports, NOW, cache)), 'REGISTRY_UNAVAILABLE');
  }
  assert.equal(cache.negativeSize, 0, 'a fact about the resolver is not a fact about a name');
});

/* -------------------------------------------------------------------------- */
/* Flushing, and counting — added with GET /v1/cache/stats and DELETE /v1/cache */
/* -------------------------------------------------------------------------- */

test('a flush of everything leaves nothing, including the manifests', () => {
  // Found by a surviving mutation: the methods shipped with the endpoints and without tests.
  // `DELETE /v1/cache` is what an operator reaches for when they believe this resolver is wrong
  // about something, and a flush that quietly keeps a third of what it holds leaves them
  // believing it worked.
  const cache = new ResolutionCache();
  cache.putNegative('gone.vayu', 'NAME_NOT_FOUND', NOW);
  cache.putPositive('atlas.vayu', rec('atlas'), NOW);
  cache.rememberManifest('bafyroot', null);
  assert.equal(cache.negativeSize + cache.positiveSize + cache.manifestSize, 3);

  assert.equal(cache.clear(), 3, 'it reports what went, so a caller can say rather than assume');
  assert.equal(cache.negativeSize, 0);
  assert.equal(cache.positiveSize, 0);
  assert.equal(cache.manifestSize, 0, 'a flush that keeps the manifests is not a flush');
  assert.equal(cache.clear(), 0, 'and flushing an empty cache reports nothing rather than lying');
});

test('flushing one name takes that name and leaves the rest standing', () => {
  const cache = new ResolutionCache();
  cache.putNegative('gone.vayu', 'NAME_NOT_FOUND', NOW);
  cache.putPositive('atlas.vayu', rec('atlas'), NOW);
  cache.putPositive('borealis.vayu', rec('borealis'), NOW);
  cache.rememberManifest('bafyroot', null);

  assert.equal(cache.forget('atlas.vayu'), 1);
  assert.equal(cache.positive('atlas.vayu', NOW), null);
  assert.equal(
    cache.positive('borealis.vayu', NOW) !== null,
    true,
    'a neighbour is not collateral',
  );
  assert.equal(cache.negative('gone.vayu', NOW), 'NAME_NOT_FOUND');
  assert.equal(
    cache.manifestSize,
    1,
    'manifests are keyed by CID, so no fact about one name can make one wrong',
  );

  // Both halves of one name go together, because they are two answers about the same thing.
  cache.putNegative('atlas.vayu', 'NAME_EXPIRED', NOW);
  cache.putPositive('atlas.vayu', rec('atlas'), NOW);
  assert.equal(cache.forget('atlas.vayu'), 2);
  assert.equal(cache.forget('never-cached.vayu'), 0);
});

test('a miss is counted as a miss, which is the only way a hit rate means anything', () => {
  const cache = new ResolutionCache();
  assert.deepEqual(cache.counts, { hits: 0, misses: 0 });

  cache.positive('atlas.vayu', NOW);
  cache.negative('atlas.vayu', NOW);
  assert.deepEqual(cache.counts, { hits: 0, misses: 2 }, 'nothing held is two misses');

  cache.putPositive('atlas.vayu', rec('atlas'), NOW);
  cache.positive('atlas.vayu', NOW);
  assert.deepEqual(cache.counts, { hits: 1, misses: 2 });

  // An entry that has expired is a miss, not a hit: it was there and it was no use.
  cache.positive('atlas.vayu', NOW + POSITIVE_TTL_SECONDS);
  assert.deepEqual(cache.counts, { hits: 1, misses: 3 });
});

/* -------------------------------------------------------------------------- */
/* Resizing, which has to take effect on what is already held                  */
/* -------------------------------------------------------------------------- */

test('lowering a cache bound trims what is already held, rather than only future inserts', () => {
  // The defect this is written against: a resize that assigns a field and returns. `PATCH
  // /v1/config` would answer 200, an operator would believe they had capped memory, and the
  // entries already over the new bound would sit there until something happened to evict them.
  // A bound that only governs the next insert is not the bound the caller asked for.
  const cache = new ResolutionCache({ negativeEntries: 8 });
  for (let i = 0; i < 8; i += 1) cache.putNegative(`name${i}.vayu`, 'NAME_NOT_FOUND', NOW);
  assert.equal(cache.negativeSize, 8);

  cache.setLimits({ negativeEntries: 3 });
  assert.equal(cache.negativeSize, 3, 'the new bound applies to what is already there');
  // Oldest-first, the same order `evictFor` uses when making room for one key. A resize that
  // trimmed from the other end would contradict the eviction policy it shares a cache with.
  assert.equal(cache.negative('name0.vayu', NOW), null, 'the oldest went');
  assert.notEqual(cache.negative('name7.vayu', NOW), null, 'the newest stayed');
});

test('raising a bound admits more without inventing anything', () => {
  const cache = new ResolutionCache({ negativeEntries: 2 });
  for (let i = 0; i < 4; i += 1) cache.putNegative(`name${i}.vayu`, 'NAME_NOT_FOUND', NOW);
  assert.equal(cache.negativeSize, 2);
  cache.setLimits({ negativeEntries: 6 });
  assert.equal(cache.negativeSize, 2, 'raising a bound adds nothing');
  for (let i = 4; i < 8; i += 1) cache.putNegative(`name${i}.vayu`, 'NAME_NOT_FOUND', NOW);
  assert.equal(cache.negativeSize, 6, 'and the new headroom is real');
});

test('a bound that is not a usable size is refused rather than coerced', () => {
  // A cache with a limit of zero holds nothing and reports hits it cannot have; a fractional or
  // negative one is a caller who has misunderstood. Refused at the setter, because a Map does not
  // enforce anything and the wrong value would surface as behaviour nobody could explain.
  const cache = new ResolutionCache({});
  for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => cache.setLimits({ negativeEntries: bad }),
      /positive integer/i,
      String(bad),
    );
  }
  // An empty patch is not an error: it changes nothing, which is what it asked for.
  cache.setLimits({});
});

test('AUDIT: a bound cannot be raised past the memory the specification budgets for it', () => {
  // **Found on a live socket, not here.** `PATCH /v1/config {"cacheSizes":{"negativeEntries":1e9}}`
  // answered 200, and so did `999999999999999999999` — stored as `1e+21`, a number the cache cannot
  // count to. An authenticated caller, or anything that can reach the control socket, could set the
  // resolver's memory bound to a value that guarantees the process dies.
  //
  // LOCAL-SURFACE.md 3.4 is not vague about this. It budgets "record and negative caches, combined:
  // 64 MiB", and says why the number is in the document at all: "Changing one is a VWIP, because a
  // resolver that quietly raises a limit is a resolver whose denial-of-service surface differs from
  // the one this document describes." An endpoint that raises it at runtime is exactly that
  // resolver, and it shipped one commit after `CACHE_LIMITS`' own comment argued that "an unbounded
  // map whose size is an argument rather than a limit is the shape LOCAL-SURFACE.md 3.4 asks not to
  // exist". The setter handed back the argument the constant had taken away.
  const cache = new ResolutionCache({});

  for (const field of ['negativeEntries', 'positiveEntries', 'manifestEntries'] as const) {
    const ceiling = CACHE_CEILINGS[field];
    // At the ceiling is allowed: it is a limit, not a limit minus one.
    cache.setLimits({ [field]: ceiling });
    assert.equal(cache.limits[field], ceiling);
    assert.throws(() => cache.setLimits({ [field]: ceiling + 1 }), /ceiling/i, field);
    assert.throws(() => cache.setLimits({ [field]: 1e9 }), /ceiling/i, `${field} 1e9`);
    // The value that made this visible: an integer by `Number.isInteger` and not a countable one.
    assert.throws(() => cache.setLimits({ [field]: 1e21 }), /ceiling/i, `${field} 1e21`);
  }

  // And a refused patch changes nothing, which is the property the whole validate-then-apply
  // ordering exists for — a caller naming three sizes and getting one wrong keeps all three.
  const held = cache.limits;
  assert.throws(() => cache.setLimits({ negativeEntries: 8, positiveEntries: 1e9 }));
  assert.deepEqual(cache.limits, held, 'the good field must not land when a later one is refused');
});

test('AUDIT: the ceilings are derived from the budget rather than chosen beside it', () => {
  // The numbers above are only worth anything if they add up to the document's. LOCAL-SURFACE.md
  // 3.4 budgets 64 MiB for the record and negative caches COMBINED, so each half gets 32 MiB at a
  // stated per-entry allowance. Asserted rather than commented, because a ceiling raised later
  // without redoing the arithmetic is how a budget stops being one.
  const MiB = 1024 * 1024;
  assert.equal(
    CACHE_CEILINGS.negativeEntries * CACHE_ENTRY_ALLOWANCE.negative +
      CACHE_CEILINGS.positiveEntries * CACHE_ENTRY_ALLOWANCE.positive,
    64 * MiB,
    'record and negative caches, combined, at their ceilings, are exactly the budgeted 64 MiB',
  );
  // Manifests are in neither clause — RESOLUTION.md gives content its own 2 GiB LRU and a manifest
  // is not content — so their ceiling is a judgement of the same size, and stated as one.
  assert.equal(CACHE_CEILINGS.manifestEntries * CACHE_ENTRY_ALLOWANCE.manifest, 32 * MiB);

  // Every default must sit under its own ceiling, or the constructor ships a configuration the
  // setter would refuse.
  for (const field of ['negativeEntries', 'positiveEntries', 'manifestEntries'] as const) {
    assert.ok(CACHE_LIMITS[field] <= CACHE_CEILINGS[field], `${field} default exceeds its ceiling`);
  }
});
