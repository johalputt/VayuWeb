/**
 * The resolution algorithm.
 *
 * docs/spec/RESOLUTION.md, "Resolution algorithm". Those steps are normative *and ordered*, and
 * the order is observable: two resolvers that check the same request in different orders return
 * different numbered errors for a request that is wrong in more than one way, and the error code
 * is part of what a user and a second implementation both see.
 *
 * ## What is here and what is not
 *
 * Steps 1 to 10 and 13 are decidable without a network: parsing, TLD classification, label
 * validation, cache consultation, the validity window, record selection, alias following and
 * path mapping. They are implemented here as pure functions of their inputs.
 *
 * Steps 7, 10, 11 and 12 need a registry, an IPNS resolver and an IPFS fetch. Those arrive
 * through {@link ResolverPorts} rather than being reached for, exactly as the verifier takes a
 * {@link RegistryView}. There is deliberately no default: a port that answered permissively
 * would make a caller that forgot to supply one appear to work while resolving nothing, and
 * that failure is invisible in a passing test.
 *
 * ## Diagnostics are recorded, not disclosed
 *
 * Every resolution returns a `diagnostics` object. Whether any of it reaches the requesting page
 * as `X-VayuWeb-*` headers is the caller's decision and is **off by default**: emitted
 * unconditionally those headers brand every response as VayuWeb, which lets any page that can
 * elicit a response learn the resolver is installed. RESOLUTION.md calls that the most
 * consequential fingerprint the resolver produces, and for a reader in a hostile jurisdiction
 * that single fact may be all an adversary needs. The type system keeps them apart: diagnostics
 * are a field on the outcome, never a header.
 */

import { isRatifiedTld, labelRejection, parseAlias } from './names.ts';
import { stateAt, lifecycleOf } from './lifecycle.ts';
import type { RegistryRecord, RecordEntry } from './record.ts';
import type { ResolutionCache } from './cache.ts';

/** Numbered errors, exactly as the catalogue in RESOLUTION.md defines them. */
export const RESOLVE_ERRORS = {
  LABEL_INVALID: { code: 1400, http: 400, message: 'That name is not a valid VayuWeb name.' },
  TLD_UNKNOWN: { code: 1403, http: 502, message: 'This resolver only handles VayuWeb names.' },
  NAME_NOT_FOUND: { code: 1404, http: 404, message: 'No one has registered this name.' },
  CONTENT_TIMEOUT: { code: 1408, http: 504, message: 'The site took too long to load.' },
  NAME_QUARANTINED: { code: 1409, http: 409, message: 'This name expired and is on hold.' },
  NAME_EXPIRED: { code: 1410, http: 410, message: "This name's registration has expired." },
  /**
   * Distinct from 1410, and the distinction is the point.
   *
   * `stateAt` reports a revoked name as GRACE for the remainder of its term, so this path used to
   * return 1410 — "This name's registration has expired". The registration has not expired: the
   * holder declared the key compromised. Saying "expired" tells the reader to renew, which is the
   * single action a revoked name must not invite, and it is the kind of user-facing claim this
   * project treats as a defect rather than as wording.
   */
  NAME_REVOKED: {
    code: 1412,
    http: 410,
    message:
      "This name's owner declared its key compromised. It cannot be renewed or re-registered " +
      'by anyone until its term ends.',
  },
  RESPONSE_TOO_LARGE: {
    code: 1413,
    http: 502,
    message: 'This file is larger than the resolver will load.',
  },
  PATH_NOT_FOUND: { code: 1414, http: 404, message: 'This page does not exist on this site.' },
  NO_USABLE_RECORD: { code: 1421, http: 502, message: 'This name points at nothing fetchable.' },
  BLOCKED_BY_POLICY: {
    code: 1451,
    http: 403,
    message: 'The resolver refused this request for safety reasons.',
  },
  INTERNAL: { code: 1500, http: 500, message: 'The resolver hit an internal error.' },
  REGISTRY_UNAVAILABLE: {
    code: 1502,
    http: 503,
    message: 'The resolver has not synchronised the registry yet.',
  },
  REGISTRY_STALE: {
    code: 1503,
    http: 503,
    message: 'The registry copy is too old to answer safely.',
  },
  CONTENT_UNAVAILABLE: {
    code: 1504,
    http: 504,
    message: "No one is currently sharing this site's files.",
  },
  IPNS_UNRESOLVED: {
    code: 1505,
    http: 504,
    message: "This site's pointer could not be resolved.",
  },
  ALIAS_LOOP: { code: 1508, http: 508, message: 'This name points in a circle.' },
  CONTENT_INTEGRITY: {
    code: 1512,
    http: 502,
    message: 'The content did not match its fingerprint and was discarded.',
  },
} as const;

export type ResolveErrorName = keyof typeof RESOLVE_ERRORS;

/** Alias budget, counted per original request. Matches REGISTRY.md's three-hop limit. */
export const ALIAS_BUDGET = 3;

/**
 * Content-source preference: the living pointer, then the snapshot, then the one that needs a
 * specific host online, then the one that costs another full resolution.
 *
 * ## Why `ipns` comes before `cid`, having once come after
 *
 * An earlier revision preferred `cid` first, reasoning that immutable content is verifiable
 * without a liveness assumption. That reasoning is sound and the conclusion was still wrong,
 * because it was drawn without reading what a publisher is told to do.
 *
 * HOSTING.md recommends carrying both entries: an `ipns` pointer for the living site and a `cid`
 * for "the last snapshot the owner is willing to have served if the pointer cannot be resolved",
 * so that "the registry record stays still while the site behind it changes, which is what an
 * author republishing weekly actually wants". With `cid` selected first and unconditionally, a
 * publisher following HOSTING and a resolver following RESOLUTION both conform — and every
 * reader is served the frozen snapshot forever, while the author publishes into a pointer nobody
 * consults. Silent, permanent, and invisible to the author, who resolves their own pointer.
 *
 * Preferring the pointer costs no verifiability. An IPNS record is signed by the same key that
 * controls the name, and what it yields is a CID, hash-verified exactly as an inline one is. What
 * it costs is a resolution step and a liveness dependency — the right price for showing a reader
 * what the author actually published. The snapshot then serves the purpose HOSTING always said
 * it had: the fallback for when the pointer cannot be resolved.
 */
/**
 * The content sources, in the order RESOLUTION.md selects them.
 *
 * **`peer` is deliberately absent.** It was third here, and step 12 — "verify the bytes hash to
 * the requested CID" — has no operand for a `peer` entry, so a resolver following the order
 * served whatever the dialled host returned, unhashed. The fallback rule made it attacker-
 * reachable rather than merely publisher-reachable: deny `ipns` and `cid` at the network layer,
 * which is cheap, and the resolver walks down to a source nothing can verify.
 *
 * A `peer` entry is a transport hint. It says where blocks might be found; the CID they are
 * checked against still comes from an `ipns` or `cid` entry, which is the shape VWIP-0005 gives
 * block exchange and the only shape in which asking a named host for content is safe.
 */
export const SOURCE_ORDER = ['ipns', 'cid', 'alias'] as const;
export type SourceType = (typeof SOURCE_ORDER)[number];

export interface ParsedHost {
  readonly label: string;
  readonly tld: string;
}

/**
 * What a resolution recorded about itself.
 *
 * **`stale` was here and is gone.** It was declared, initialised to `false`, and assigned by
 * nothing — the only reader OR'd it with the fallback count, so the header it fed was driven
 * entirely by that count and the field was dead weight.
 *
 * The rule it existed for is RESOLUTION.md's: "when the registry is unreachable the resolver MAY
 * serve a record up to 600 seconds past its TTL […] It MUST record the staleness". That is a MAY,
 * and it is not implemented — deliberately, because it would have no reachable caller here. This
 * resolver's registry is a local log opened once at startup, so "unreachable" is a state it cannot
 * enter mid-run: the length it derives its verified head from cannot fall. Building the path
 * anyway would be a mechanism with no way to run it, which is the defect this codebase keeps
 * finding rather than one to add on purpose.
 *
 * The other kind of staleness — a source fallback, which RESOLUTION.md says MUST mark the answer
 * stale — is implemented, is where `X-VayuWeb-Stale` comes from, and lives in {@link fallbacks}
 * where a reader can see what was abandoned rather than only that something was.
 */
export interface Diagnostics {
  readonly name: string;
  readonly seq: number | null;
  readonly source: SourceType | null;
  readonly resolvedFrom: 'cache' | 'registry' | null;
  /** Sources tried and abandoned, in order. Recorded even when headers are off. */
  readonly fallbacks: readonly SourceType[];
  readonly aliasHops: number;
}

export type Outcome =
  | {
      readonly ok: true;
      readonly entry: RecordEntry;
      readonly record: RegistryRecord;
      readonly diagnostics: Diagnostics;
    }
  | {
      readonly ok: false;
      readonly error: ResolveErrorName;
      readonly detail: string;
      readonly diagnostics: Diagnostics;
    };

/**
 * Everything the algorithm cannot decide by itself.
 *
 * No defaults, for the same reason `RegistryView` has none.
 */
export interface ResolverPorts {
  /** Step 7. Local index lookup; contacts no peer. Null when the name has no record. */
  lookup(label: string, tld: string): RegistryRecord | null;
  /** Step 7. False before the log has ever synchronised, giving 1502 rather than 1404. */
  hasVerifiedHead(): boolean;
}

/**
 * Step 1. Split a host into label and TLD.
 *
 * More than two dot-separated components is refused rather than interpreted: subdomains are
 * deferred, and silently treating `a.b.vayu` as a name under `.vayu` would resolve something
 * the registry never issued.
 */
export function parseHost(host: string): ParsedHost | null {
  const bare = host.replace(/:\d+$/, '').toLowerCase();
  const parts = bare.split('.');
  if (parts.length !== 2) return null;
  const [label, tld] = parts as [string, string];
  if (label.length === 0 || tld.length === 0) return null;
  return { label, tld };
}

const emptyDiagnostics = (name: string): Diagnostics => ({
  name,
  seq: null,
  source: null,
  resolvedFrom: null,
  fallbacks: [],
  aliasHops: 0,
});

const fail = (error: ResolveErrorName, detail: string, diagnostics: Diagnostics): Outcome => ({
  ok: false,
  error,
  detail,
  diagnostics,
});

/**
 * Step 9. Choose one content source from a record's entries.
 *
 * A `txt` entry is never a content source, and an entry whose type this version does not know
 * is never acted upon — REGISTRY.md requires unknown types to be stored and replicated
 * unchanged, which is not the same as being usable.
 */
export function selectSource(record: RegistryRecord): RecordEntry | null {
  return sourceCandidates(record)[0] ?? null;
}

/**
 * Every content source a record offers, in preference order.
 *
 * **`selectSource` returning one entry was the whole of the defect.** RESOLUTION.md says "if the
 * chosen entry fails, the resolver SHOULD fall back to the next" — and there was no next, because
 * nothing above this line could see one. A record carrying the arrangement HOSTING.md recommends
 * to publishers, an `ipns` pointer beside a `cid` snapshot, answered 502: the pointer was refused
 * and the snapshot supplied for exactly that case was never asked for.
 *
 * `alias` is deliberately NOT in this list even though it is in `SOURCE_ORDER`. Falling back to an
 * alias is not a second fetch, it is a second RESOLUTION — a new name, a new record, its own hop
 * budget and its own diagnostics — and step 9 already follows an alias when one is selected. What
 * this function returns is the set of candidates a content layer can be handed directly, which is
 * what a fallback loop over `fetch` needs and all it can honestly use. A resolver that wanted to
 * fall back from a dead pointer to an alias would re-enter `resolveName`, and that is a larger
 * change than the one the failing case required; it is stated here rather than left as a silent
 * omission from a list a reader would assume is complete.
 */
export function sourceCandidates(record: RegistryRecord): readonly RecordEntry[] {
  const fetchable: readonly SourceType[] = ['ipns', 'cid'];
  const candidates: RecordEntry[] = [];
  for (const type of SOURCE_ORDER) {
    const match = record.entries.find((e) => e.known && e.type === type);
    if (match === undefined) continue;
    if (!fetchable.includes(type)) {
      // An alias is a source, and it is the LAST one; reaching it means the fetchable sources are
      // exhausted. Returning it here would hand the content layer a name to fetch, which is not
      // something a content layer can do.
      if (candidates.length === 0) return [match];
      continue;
    }
    candidates.push(match);
  }
  return candidates;
}

/**
 * Steps 1 through 10: resolve a host to the content entry that should be fetched.
 *
 * Stops before the network. The caller performs steps 11 and 12 — fetch and integrity check —
 * and must not fall back across an integrity failure, which signals an attack rather than an
 * availability problem.
 */
export function resolveName(
  host: string,
  ports: ResolverPorts,
  now: number,
  cache?: ResolutionCache,
): Outcome {
  let diagnostics = emptyDiagnostics(host);
  const seen = new Set<string>();
  let current = host;

  for (let hop = 0; hop <= ALIAS_BUDGET; hop += 1) {
    diagnostics = { ...diagnostics, aliasHops: hop };

    // Step 1: parse.
    const parsed = parseHost(current);
    if (parsed === null) {
      return fail('LABEL_INVALID', `'${current}' is not label.tld`, diagnostics);
    }
    const { label, tld } = parsed;

    // Step 2 and 3: TLD classification. A non-VayuWeb TLD is refused here rather than handed to
    // the operating system, which is what makes the no-DNS-fallback rule enforceable instead of
    // aspirational.
    if (!isRatifiedTld(tld)) {
      return fail('TLD_UNKNOWN', `.${tld} is not a VayuWeb extension`, diagnostics);
    }

    // Step 4: label validation, before the network and before the cache, so malformed input
    // reaches neither.
    const problem = labelRejection(label);
    if (problem !== null) {
      return fail('LABEL_INVALID', `${label}: ${problem}`, diagnostics);
    }

    // A cycle among well-formed names. The budget below also bounds this, but detecting the
    // repeat names the failure accurately instead of reporting an exhausted budget.
    const key = `${label}.${tld}`;
    if (seen.has(key)) {
      return fail('ALIAS_LOOP', `${key} was already visited`, diagnostics);
    }
    seen.add(key);

    // Steps 5 and 6: the caches, in the order the specification puts them and INSIDE the loop, so
    // an alias hop consults them for the name it lands on. They sat outside `resolveName`
    // entirely before, which meant a chain ending at a negatively cached name paid for a full
    // registry lookup that a direct request for the same name would have skipped.
    const cached = cache?.positive(key, now) ?? null;
    if (cached === null) {
      const refused = cache?.negative(key, now) ?? null;
      if (refused !== null) {
        // Step 6: "return its stored error". The stored one — not a fixed code chosen because
        // only one was ever cached, which is what a single-code cache degrades into the moment a
        // second code joins it.
        return fail(refused, `${key} answered from the negative cache`, {
          ...diagnostics,
          resolvedFrom: 'cache',
        });
      }
    }

    /** Record a negative answer under the name it is a fact about, and refuse. */
    const refuse = (error: ResolveErrorName, detail: string): Outcome => {
      cache?.putNegative(key, error, now);
      return fail(error, detail, diagnostics);
    };

    let record: RegistryRecord;
    if (cached !== null) {
      // Step 5: "take its record bundle and go to step 9", which skips the validity window at
      // step 8. That skip is only safe because a positive entry's TTL is capped at `notAfter`;
      // see `putPositive`.
      record = cached;
      diagnostics = { ...diagnostics, seq: record.seq, resolvedFrom: 'cache' };
    } else {
      // Step 7: registry lookup, local only.
      if (!ports.hasVerifiedHead()) {
        // Not cached, whatever the table said — this is a statement about this resolver rather
        // than about the name, and it stops being true without any name changing.
        return fail('REGISTRY_UNAVAILABLE', 'no verified log head', diagnostics);
      }
      const looked = ports.lookup(label, tld);
      diagnostics = { ...diagnostics, resolvedFrom: 'registry' };
      if (looked === null) {
        return refuse('NAME_NOT_FOUND', `${key} is not registered`);
      }
      record = looked;
      diagnostics = { ...diagnostics, seq: record.seq };

      // Step 8: validity window. An expired name MUST NOT resolve even when its content is still
      // held locally — otherwise a lapsed registration keeps serving to whoever never re-queried.
      const state = stateAt(record, now);
      if (lifecycleOf(record).revoked && state !== 'FREE') {
        return refuse('NAME_REVOKED', `${key} was revoked at ${record.notBefore}`);
      }
      if (state === 'GRACE') {
        return refuse('NAME_EXPIRED', `${key} expired at ${record.notAfter}`);
      }
      if (state === 'QUARANTINE') {
        return refuse('NAME_QUARANTINED', `${key} is on hold`);
      }
      if (state !== 'LIVE') {
        return refuse('NAME_NOT_FOUND', `${key} is ${state.toLowerCase()}`);
      }

      // Step 14's "populate the caches", for the record half. Here rather than after the content
      // fetch, because this is where the record was established live and the content layer's
      // outcome says nothing about the registry.
      cache?.putPositive(key, record, now);
    }

    // Step 9: record selection.
    const entry = selectSource(record);
    if (entry === null) {
      return fail('NO_USABLE_RECORD', `${key} has no fetchable entry`, diagnostics);
    }

    // Step 10: an alias restarts the algorithm against the budget.
    if (entry.type === 'alias') {
      const target = parseAlias(entry.value as string);
      if (target === null) {
        return fail('NO_USABLE_RECORD', 'alias target is not a valid name', diagnostics);
      }
      diagnostics = { ...diagnostics, source: 'alias' };
      current = `${target.label}.${target.tld}`;
      continue;
    }

    return {
      ok: true,
      entry,
      record,
      diagnostics: { ...diagnostics, source: entry.type as SourceType },
    };
  }

  // The budget is counted per original request, so a chain of distinct names longer than three
  // hops exhausts it even though no name repeats.
  return fail('ALIAS_LOOP', `alias budget of ${ALIAS_BUDGET} hops exhausted`, diagnostics);
}

/**
 * The path of the site manifest inside a published tree.
 *
 * `.vayu` is the one dot-directory `siteFilesFor` publishes, and this is why.
 */
export const MANIFEST_PATH = '/.vayu/manifest.json';

/** Bytes of manifest this resolver will read. A publisher-controlled file needs a bound. */
export const MAX_MANIFEST_BYTES = 8_192;

/** Characters in a path a manifest may declare. Longer than any sane one and shorter than an attack. */
const MAX_DECLARED_PATH = 512;

/**
 * The three manifest fields that drive resolver behaviour, and nothing else.
 *
 * `title`, `description` and `generator` are descriptive — PUBLISHING.md section 2 says so in
 * terms — so they are not parsed here. A resolver that read them would be a resolver that could be
 * made to act on them later by somebody who found them already available.
 */
export interface SiteManifest {
  /** What `/` and a directory path resolve to, when declared. */
  readonly index: string | null;
  /** Served with 200 on no match, so a site's own router can handle the path. */
  readonly fallback: string | null;
  /** Served with 404 on no match, in preference to `fallback`. */
  readonly notFound: string | null;
}

/**
 * Read a site manifest, discarding anything that is not a usable declaration.
 *
 * ## Verified is not benign
 *
 * The manifest is inside the tree and covered by the root CID, so it is **authentic**: it is what
 * the publisher signed. That is the whole of what the hash proves. It says nothing about whether
 * the publisher is careless or hostile toward their own readers, and these fields become paths
 * this resolver fetches — so every one is validated as though it arrived from a stranger, because
 * in the case that matters it did.
 *
 * A declaration that is malformed, absolute, or contains `..` is **discarded rather than
 * reported**. RESOLUTION.md step 13: "a declared file that is not present in the verified tree is
 * discarded rather than reported, because the manifest declares intent and is never evidence about
 * the tree". A manifest with a bad `notFound` is a site that 404s ordinarily, not a site that
 * cannot be served — refusing the whole site over a typo in an optional field would make an
 * optional field a way to break a site.
 */
export function parseManifest(bytes: Uint8Array): SiteManifest | null {
  if (bytes.length === 0 || bytes.length > MAX_MANIFEST_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
  const map = parsed as Record<string, unknown>;
  // `version` is the one required field. A manifest declaring a version this resolver does not
  // know is ignored whole rather than read optimistically: a future version may give one of these
  // names a different meaning, and acting on it would be acting on a guess.
  if (map['version'] !== 1) return null;
  return {
    index: declaredPath(map['index']),
    fallback: declaredPath(map['fallback']),
    notFound: declaredPath(map['notFound']),
  };
}

/**
 * A path a manifest declares, or null.
 *
 * Relative, no traversal, bounded, non-empty. Rejected before normalising rather than after, for
 * the reason {@link mapPath} gives: a check that normalises first has produced path-traversal bugs
 * for thirty years. A leading `/` is refused rather than stripped — a manifest declaring an
 * absolute path means something this resolver would have to invent an interpretation for.
 */
function declaredPath(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  if (value.length === 0 || value.length > MAX_DECLARED_PATH) return null;
  if (value.startsWith('/') || value.includes('..')) return null;
  if (value.includes('\0') || value.includes('\n') || value.includes('\r')) return null;
  return value;
}

/**
 * Step 13. Map a request path onto a directory listing.
 *
 * Returns the entry to serve, or null for 1414 — an ordinary 404, the site's problem rather than
 * the network's.
 */
export function mapPath(path: string, listing: ReadonlySet<string>): string | null {
  // Reject traversal before normalising rather than after: a resolver that normalises first and
  // checks second is the shape that has produced path-traversal bugs for thirty years.
  if (path.includes('..')) return null;

  const clean = path.split('?')[0]!.split('#')[0]!;
  const trimmed = clean.startsWith('/') ? clean.slice(1) : clean;

  if (trimmed === '' || trimmed.endsWith('/')) {
    const index = `${trimmed}index.html`;
    return listing.has(index) ? index : null;
  }
  if (listing.has(trimmed)) return trimmed;

  // A directory named without its trailing slash still resolves to its index.
  const index = `${trimmed}/index.html`;
  return listing.has(index) ? index : null;
}
