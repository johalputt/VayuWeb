/**
 * The resolver's caches, and the policy that decides what may go in them.
 *
 * docs/spec/RESOLUTION.md, "Caching and TTL policy", is authoritative. It names a per-code table
 * and this file is that table plus the two bounded maps it governs — steps 5 and 6 of the
 * resolution algorithm, which is where the specification puts the lookups.
 *
 * ## What was here before
 *
 * One code, at one TTL, and a hit that answered `NAME_NOT_FOUND` whatever had been stored. Five
 * codes are cacheable at three different TTLs, so four of them were re-resolved every time — and
 * the moment a second code was cached the answer would have been the wrong code, since nothing
 * recorded which one it was. `resolvedFrom: 'cache'` was declared in `Diagnostics` and assigned
 * nowhere, because no positive cache existed at all.
 *
 * ## The table is total, and that is the point
 *
 * {@link NEGATIVE_TTL_SECONDS} names **every** error in the catalogue, with `null` for "not
 * cached". A partial table would let a code added later fall through to whatever the lookup's
 * default happened to be, which is a policy decision made by an absence. Typed as a total record,
 * adding an error code to `RESOLVE_ERRORS` fails to compile until this file says what caching it
 * means — the check runs at build time rather than in a test somebody has to remember to write.
 *
 * Anything the specification does not name is `null`. Caching an answer no clause authorises is
 * inventing policy, and the invented policy is always the permissive one.
 *
 * ## Generation, which makes the TTLs a bound rather than a promise
 *
 * A TTL says how long a wrong answer may persist. It does not have to be reached. This resolver's
 * registry is a **local log**, so it knows exactly when the thing a cached answer was derived from
 * has changed: the log grew. {@link ResolutionCache.setGeneration} takes any number that moves
 * when the registry does — `Store.length` is one — and drops every entry when it moves.
 *
 * That is not a micro-optimisation, it is the difference between two behaviours a reader would
 * describe differently. RESOLUTION.md accepts, in terms, that a 300-second record cache means
 * "five minutes bounds how long a superseded owner key stays usable". A key is superseded by a
 * record, a record arrives by an append, and an append moves the generation — so on a resolver
 * whose registry is local, a `REVOKE` takes effect on the next request rather than five minutes
 * later. Since the lookup a positive entry saves is a map read, the cache exists to bound
 * attacker-driven work, and paying for it in freshness would be paying for nothing.
 *
 * A caller that never sets a generation still gets exactly what the specification requires: the
 * TTLs. The tightening is additive, and it is wired in `serve.ts` rather than left as a method
 * with no caller.
 */

import type { RegistryRecord } from './record.ts';
import type { ResolveErrorName, SiteManifest } from './resolve.ts';

/**
 * How long a negative answer may be trusted, in seconds. `null` means it is never cached.
 *
 * Every entry is either a number RESOLUTION.md states or a `null` this comment justifies. The
 * three groups it names:
 *
 * - **30 seconds** for `NAME_NOT_FOUND`, short because a name may be registered at any moment.
 * - **60 seconds** for the states a name sits in rather than passes through.
 * - **10 seconds** for the two content failures, so a site coming back online recovers quickly.
 *
 * `LABEL_INVALID` and `TLD_UNKNOWN` are `null` for a reason worth restating: the grammar check is
 * cheaper than the cache lookup, so caching them buys nothing and hands a page an attacker-keyed
 * insert — which is why they are also decided before the cache is consulted at all.
 *
 * `REGISTRY_UNAVAILABLE` and `CONTENT_INTEGRITY` are `null` because the specification says never.
 * The first is a statement about this resolver rather than about the name, and would go on being
 * true to every caller for its whole TTL after it had stopped being true. The second is the one
 * refusal that must never become sticky: an answer that content failed its hash, cached, is a way
 * to make a site unreachable by feeding one bad copy through once.
 *
 * Everything else is `null` because RESOLUTION.md does not name it, and this file does not invent
 * policy. Two are worth a line each, because both look cacheable and are not: `ALIAS_LOOP` is a
 * fact about a *chain* and not about the name it is keyed under, so caching it would attach one
 * request's budget exhaustion to a name that may be perfectly resolvable by a shorter route; and
 * `NO_USABLE_RECORD` is a fact about a record that its owner can change with one `UPDATE`.
 */
export const NEGATIVE_TTL_SECONDS: Record<ResolveErrorName, number | null> = {
  NAME_NOT_FOUND: 30,
  NAME_EXPIRED: 60,
  NAME_QUARANTINED: 60,
  /**
   * 60 seconds, alongside the other two states a name rests in.
   *
   * RESOLUTION.md's caching table did not name it, because 1412 was added to the error catalogue
   * *after* that table was written — step 8 used to answer a revoked name with 1410. The omission
   * was a gap rather than a decision, and the clause now says so. A revoked name accepts no
   * further record from anyone until its term ends, which makes it the most stable negative answer
   * in the catalogue; 60 seconds is conservative for it and matches its neighbours.
   */
  NAME_REVOKED: 60,
  CONTENT_UNAVAILABLE: 10,
  IPNS_UNRESOLVED: 10,

  LABEL_INVALID: null,
  TLD_UNKNOWN: null,
  REGISTRY_UNAVAILABLE: null,
  CONTENT_INTEGRITY: null,
  REGISTRY_STALE: null,
  CONTENT_TIMEOUT: null,
  RESPONSE_TOO_LARGE: null,
  PATH_NOT_FOUND: null,
  NO_USABLE_RECORD: null,
  ALIAS_LOOP: null,
  BLOCKED_BY_POLICY: null,
  INTERNAL: null,
};

/** RESOLUTION.md: "Record cache, positive: 300 seconds, further capped at `notAfter`." */
export const POSITIVE_TTL_SECONDS = 300;

/**
 * Entry counts, bounded because the keys are attacker-chosen.
 *
 * The positive half is bounded too, and the reason is not symmetry. A positive entry needs a
 * registered name, which costs a proof of work — so the set is small and expensive to enlarge. But
 * "expensive for an attacker" is a statement about today's namespace, and an unbounded map whose
 * size is an argument rather than a limit is the shape LOCAL-SURFACE.md 3.4 asks not to exist.
 */
export const CACHE_LIMITS = {
  negativeEntries: 512,
  positiveEntries: 512,
  /**
   * Manifests held, keyed by content identifier.
   *
   * Small: a manifest is at most {@link import('./resolve.ts').MAX_MANIFEST_BYTES} and this bounds
   * the memory a stream of distinct names can make this resolver hold. It exists at all because
   * without it a directory request costs an extra block fetch **every time** rather than once per
   * site — the manifest has to be read before mapping, since a declared `index` outranks
   * `index.html` and there is no way to learn that after the fact.
   */
  manifestEntries: 256,
} as const;

interface NegativeEntry {
  readonly error: ResolveErrorName;
  readonly expires: number;
}

interface PositiveEntry {
  readonly record: RegistryRecord;
  readonly expires: number;
}

/**
 * Both halves of the resolver's cache, bounded and evicting.
 *
 * **Eviction is by insertion order, never LRU.** LRU lets an attacker pin their own entries by
 * touching them, and there is nothing here worth protecting from eviction: every entry is
 * reconstructible from a local lookup costing microseconds.
 */
export class ResolutionCache {
  private readonly negatives = new Map<string, NegativeEntry>();
  private readonly positives = new Map<string, PositiveEntry>();
  private readonly manifests = new Map<string, SiteManifest | null>();
  private readonly negativeLimit: number;
  private readonly positiveLimit: number;
  private readonly manifestLimit: number;
  private generation: number | null = null;

  /**
   * The TTL table, injectable so a test can prove the *policy* is consulted rather than
   * reimplemented. Not a configuration surface: `PATCH /v1/config` is where an operator adjusts
   * these, and that endpoint does not exist yet.
   *
   * Declared and assigned rather than written as a constructor parameter property, which
   * `tsc --noEmit` accepts and Node's `--experimental-strip-types` refuses — type-checking is not
   * running, and this project runs straight from source.
   */
  private readonly ttls: Record<ResolveErrorName, number | null>;

  constructor(
    limits: { negativeEntries?: number; positiveEntries?: number; manifestEntries?: number } = {},
    ttls: Record<ResolveErrorName, number | null> = NEGATIVE_TTL_SECONDS,
  ) {
    this.negativeLimit = limits.negativeEntries ?? CACHE_LIMITS.negativeEntries;
    this.positiveLimit = limits.positiveEntries ?? CACHE_LIMITS.positiveEntries;
    this.manifestLimit = limits.manifestEntries ?? CACHE_LIMITS.manifestEntries;
    this.ttls = ttls;
  }

  get negativeSize(): number {
    return this.negatives.size;
  }

  get positiveSize(): number {
    return this.positives.size;
  }

  get manifestSize(): number {
    return this.manifests.size;
  }

  /**
   * Tell the cache what the registry looks like now.
   *
   * Any number that moves when the registry does. When it moves, every entry goes: a negative
   * answer may have been made wrong by a registration, and a positive one by an `UPDATE`, a
   * `RENEW`, a `TRANSFER` or a `REVOKE` — all of which are appends. Dropping both halves rather
   * than reasoning about which names an append could have touched is the honest implementation:
   * working out that a particular append is irrelevant to a particular key costs a lookup, which
   * is the thing the entry was saving.
   *
   * The consequence, stated rather than discovered: on a peer actively syncing a busy log this
   * cache holds nothing. That is the correct outcome and not a regression — the answers it would
   * have held are the ones the incoming records are changing, and the lookup it is failing to save
   * is a map read.
   */
  setGeneration(generation: number): void {
    if (this.generation === generation) return;
    this.generation = generation;
    this.negatives.clear();
    this.positives.clear();
  }

  /** The cached error for this name, or null. Expired entries are dropped as they are found. */
  negative(key: string, now: number): ResolveErrorName | null {
    const entry = this.negatives.get(key);
    if (entry === undefined) return null;
    if (entry.expires <= now) {
      this.negatives.delete(key);
      return null;
    }
    return entry.error;
  }

  /**
   * Cache a negative answer, if the policy allows it. Returns whether it was stored.
   *
   * The return value is not decoration: a caller that assumed storage would have no way to tell a
   * never-cached code from a stored one, and the tests that prove `CONTENT_INTEGRITY` is not
   * sticky need to see the refusal rather than infer it from a later miss.
   */
  putNegative(key: string, error: ResolveErrorName, now: number): boolean {
    const ttl = this.ttls[error];
    if (ttl === null) return false;
    evictFor(this.negatives, key, this.negativeLimit);
    this.negatives.set(key, { error, expires: now + ttl });
    return true;
  }

  /** The cached record for this name, or null. */
  positive(key: string, now: number): RegistryRecord | null {
    const entry = this.positives.get(key);
    if (entry === undefined) return null;
    if (entry.expires <= now) {
      this.positives.delete(key);
      return null;
    }
    return entry.record;
  }

  /**
   * What a site's manifest says, or `undefined` if this CID has not been looked at.
   *
   * Three states, and the middle one is the point: `undefined` means "not read yet", `null` means
   * "read, and there is no usable manifest", and a value is a manifest. Collapsing the first two
   * would make a site without a manifest pay for a fetch on every request forever.
   */
  manifest(cid: string): SiteManifest | null | undefined {
    return this.manifests.get(cid);
  }

  /**
   * Remember what a CID's manifest says, with **no expiry**.
   *
   * RESOLUTION.md's caching section: "Content cache: immutable, keyed by CID, no expiry." A CID
   * addresses its bytes, so an entry keyed by one cannot go stale — which is also why
   * {@link setGeneration} does not clear these. A registry append changes which CID a *name*
   * resolves to; it cannot change what a CID contains, and dropping these on every append would
   * make a syncing peer re-fetch every manifest it holds for no reason at all.
   *
   * Bounded like everything else, because the keys are still chosen by whoever gets this resolver
   * to look at a name.
   */
  rememberManifest(cid: string, manifest: SiteManifest | null): void {
    evictFor(this.manifests, cid, this.manifestLimit);
    this.manifests.set(cid, manifest);
  }

  /**
   * Cache a live record. Returns whether it was stored.
   *
   * **Capped at `notAfter`, and that cap is the security property rather than a tidy detail.** A
   * positive hit sends the algorithm to step 9, skipping the validity window at step 8 — so an
   * entry outliving its record's term would serve an expired name, which step 8 forbids in terms
   * even when the content is still held locally. The cap makes the skip safe instead of fast.
   *
   * A record already at or past `notAfter` is not stored at all, rather than stored with a TTL in
   * the past: an entry that can never be served is memory an attacker allocates for free.
   */
  putPositive(key: string, record: RegistryRecord, now: number): boolean {
    const expires = Math.min(now + POSITIVE_TTL_SECONDS, record.notAfter);
    if (expires <= now) return false;
    evictFor(this.positives, key, this.positiveLimit);
    this.positives.set(key, { record, expires });
    return true;
  }
}

/** Make room for one key, evicting the oldest insertion when the map is at its bound. */
function evictFor<T>(map: Map<string, T>, key: string, limit: number): void {
  if (map.size < limit || map.has(key)) return;
  const oldest = map.keys().next();
  if (!oldest.done) map.delete(oldest.value);
}
