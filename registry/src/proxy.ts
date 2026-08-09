/**
 * The browsing proxy: VayuWeb names in a browser nobody modified.
 *
 * docs/spec/LOCAL-SURFACE.md sections 2 to 4 and docs/spec/CONTENT-SECURITY.md are authoritative.
 *
 * ## Why this is a pure function
 *
 * {@link handleRequest} takes a request and returns a response. It binds nothing, reads no clock
 * of its own and performs no I/O. The socket is a shim around it.
 *
 * That is not tidiness. Every rule this module enforces is a rule about *what is refused*, and a
 * handler that can only be exercised by making a real TCP connection is a handler whose refusals
 * get tested for the happy path and assumed for the rest. The hostile cases here — a rebound
 * `Host`, a `CONNECT` to loopback, a name crafted for header injection — are cheap to write as
 * data and awkward to write as sockets, and the awkward ones are the ones that quietly never get
 * written.
 *
 * ## The three properties, each a refusal
 *
 * **The proxy is not an open relay.** It accepts exactly two request shapes, both requiring a
 * VayuWeb host, and refuses everything else before routing. This is the DNS-rebinding defence:
 * an attacker who rebinds a name they control to 127.0.0.1 still arrives carrying their own
 * `Host`, which is not a VayuWeb name. `CONNECT` is not implemented at all.
 *
 * **The proxy does not announce itself.** The diagnostic headers naming VayuWeb are off unless
 * explicitly enabled, and a refusal is not distinguishable from an ordinary connection failure.
 * For a reader in a hostile jurisdiction, "this person runs VayuWeb" may be the only fact an
 * adversary needs, so a header that brands every response is disclosure rather than diagnostics.
 *
 * **Nothing unbounded is reachable from a page.** The negative cache is bounded and evicting with
 * a finite TTL, and syntactically invalid names are not cached at all — the grammar check is
 * cheaper than the cache lookup, and caching them would let one hostile page fill memory with an
 * endless stream of names nobody will ever request twice.
 */

import { labelRejection, isRatifiedTld, MAX_TLD_LENGTH, MAX_LABEL_LENGTH } from './names.ts';
import {
  RESOLVE_ERRORS,
  resolveName,
  sourceCandidates,
  type ResolveErrorName,
  type ResolverPorts,
  type SourceType,
  MANIFEST_PATH,
  parseManifest,
  type SiteManifest,
} from './resolve.ts';
import { cidFromBytes, encodeCid } from './content.ts';
import { ResolutionCache } from './cache.ts';
import type { CborValue } from './cbor.ts';

/**
 * The default Content-Security-Policy, byte-identical to CONTENT-SECURITY.md section 2.
 *
 * Restated here because a header has to exist in code to be sent, and pinned by a test that reads
 * the canonical block out of the specification and compares. A second copy of a security policy is
 * a copy that drifts, and this one is wire-visible: a directive lost in transcription is a
 * relaxation nobody chose.
 */
export const DEFAULT_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; " +
  "media-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'none'; " +
  "child-src 'none'; frame-src 'none'; object-src 'none'; frame-ancestors 'none'; " +
  "form-action 'self'; base-uri 'none'; webrtc 'block'; require-trusted-types-for 'script'; " +
  "trusted-types 'none'";

/**
 * The Permissions-Policy deny list, from CONTENT-SECURITY.md section 3.
 *
 * Every feature carries the empty allowlist, denying it to the document and every nested
 * context. It is a literal enumeration rather than a description because "deny every powerful
 * feature" is not something an implementation can execute or a test can check.
 *
 * **This header was specified and never emitted.** The proxy sent the CSP and eight of the nine
 * other canonical values, so every feature this list closes was in fact permitted by the headers
 * a reader actually received. The test meant to catch it pinned the CSP *by naming its block*,
 * and a test that names the block it checks cannot notice a block nobody wrote a test for. The
 * replacement enumerates the canonical markers in the document instead.
 */
export const PERMISSIONS_POLICY =
  'accelerometer=(), ambient-light-sensor=(), attribution-reporting=(), autoplay=(), battery=(), bluetooth=(), browsing-topics=(), camera=(), clipboard-read=(), clipboard-write=(), compute-pressure=(), display-capture=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), identity-credentials-get=(), idle-detection=(), join-ad-interest-group=(), language-detector=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), otp-credentials=(), payment=(), picture-in-picture=(), private-state-token-issuance=(), private-state-token-redemption=(), publickey-credentials-create=(), publickey-credentials-get=(), run-ad-auction=(), screen-wake-lock=(), serial=(), shared-storage=(), shared-storage-select-url=(), speaker-selection=(), storage-access=(), summarizer=(), translator=(), usb=(), web-share=(), window-management=(), xr-spatial-tracking=()';
/** Accompanying response headers, from CONTENT-SECURITY.md section 3. */
export const SECURITY_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ['content-security-policy', DEFAULT_CSP],
  ['permissions-policy', PERMISSIONS_POLICY],
  ['referrer-policy', 'no-referrer'],
  ['x-content-type-options', 'nosniff'],
  ['x-frame-options', 'DENY'],
  ['x-dns-prefetch-control', 'off'],
  ['cache-control', 'no-store'],
  ['cross-origin-opener-policy', 'same-origin'],
  ['cross-origin-embedder-policy', 'require-corp'],
  ['cross-origin-resource-policy', 'same-origin'],
  ['origin-agent-cluster', '?1'],
];

/**
 * Headers this proxy MUST NEVER emit, on any response, on any listener.
 *
 * `access-control-allow-private-network` exists to let a public page reach a private service,
 * which is the exact thing this specification prevents; LOCAL-SURFACE.md 2.3 forbids it and
 * forbids making it configurable. The rest brand the response as VayuWeb.
 */
export const FORBIDDEN_RESPONSE_HEADERS: ReadonlySet<string> = new Set([
  'access-control-allow-private-network',
  'access-control-allow-origin',
  'server',
  'x-powered-by',
  'via',
]);

/** Diagnostic headers, off unless the control API turns them on. LOCAL-SURFACE.md 2.4. */
export const DIAGNOSTIC_HEADERS: readonly string[] = [
  'x-vayuweb-name',
  'x-vayuweb-seq',
  'x-vayuweb-cid',
  'x-vayuweb-source',
  'x-vayuweb-resolved-from',
  'x-vayuweb-stale',
  'x-vayuweb-fallbacks',
];

/**
 * Every bound a page can reach, with a concrete number. LOCAL-SURFACE.md 3.4.
 *
 * "Specified with concrete numbers and enforced" is the requirement, and the numbers are collected
 * here rather than scattered so a reviewer can see the whole budget at once.
 */
export const PROXY_LIMITS = {
  /** Longest acceptable host: 63-character label, a dot, a 12-character extension. */
  hostBytes: MAX_LABEL_LENGTH + 1 + MAX_TLD_LENGTH,
  /** Longest request target accepted before routing. */
  targetBytes: 2_048,
} as const;

// The cache's own bounds and TTLs live in `cache.ts` with the policy that reads them. They were
// here, as a single entry count and a single TTL, which is the shape a cache that could only ever
// hold one error code needs — and exactly the shape that made four other cacheable codes invisible.

/** What arrives. Header keys are lowercased by the caller; HTTP header names are case-insensitive. */
export interface ProxyRequest {
  readonly method: string;
  /** The request-target exactly as received: absolute-form or origin-form. */
  readonly target: string;
  readonly headers: ReadonlyMap<string, string>;
}

export interface ProxyResponse {
  readonly status: number;
  readonly headers: ReadonlyMap<string, string>;
  /**
   * The body as BYTES.
   *
   * It was a JS string, and that silently corrupted every image and every multi-byte character:
   * the content path widened the fetched octets to latin-1 and `writeHttp` narrowed them back
   * through UTF-8, so every byte above 0x7f became two. A 12-byte PNG prefix arrived as 17. The
   * comment beside the conversion asserted the opposite and was believed for exactly as long as
   * nobody served a non-ASCII byte.
   *
   * Bytes end to end removes the question rather than answering it. A refusal page is UTF-8 text
   * encoded once, here, where its encoding is obvious.
   */
  readonly body: Uint8Array;
}

export interface ProxyOptions {
  /** LOCAL-SURFACE.md 2.4: off by default, and only the control API may turn it on. */
  readonly diagnostics?: boolean;
  /**
   * RESOLUTION.md step 13: map the request path onto the resolved CID's tree.
   *
   * Supplied rather than imported, and synchronous, for the reason every port in this file is:
   * `handleRequest` stays a pure function of its inputs, so every refusal below is exercised as
   * data. The caller has already fetched and **verified** the tree — `fetch.ts` checks each block
   * against the CID that referred it — so what arrives here is bytes that hashed correctly, not
   * bytes a peer sent.
   *
   * Absent means no content layer is wired, and the proxy answers a bare 200 rather than
   * pretending: an empty body is a truthful "the name resolves and nothing here serves it".
   */
  readonly content?: ContentPort;
  /**
   * Step 10's pointer resolution, injected for the same reason the content layer is.
   *
   * Absent means this resolver cannot resolve a pointer, and the honest answer for an `ipns`
   * source is then 1505 `IPNS_UNRESOLVED` — "this site's pointer could not be resolved", which is
   * true — rather than 1421 `NO_USABLE_RECORD`, which says the name points at nothing fetchable
   * and is false about a perfectly good pointer. The distinction matters to the one person who
   * reads it: 1421 tells a publisher their record is wrong, and their record is fine.
   */
  readonly ipns?: IpnsPort;
}

/**
 * RESOLUTION.md step 10: "For `ipns`, resolve the pointer to a CID; on failure return 1505."
 *
 * An interface rather than an implementation, and not because implementing it is hard. Resolving
 * an IPNS name means the IPFS routing stack, and `security.yml` caps this package at 40 resolved
 * dependencies — installing Helia took it to 601 and the gate refused, as designed. So this is the
 * same shape Hyperswarm has in `swarm.ts`: a seam the protocol is defined against, with the
 * network binding outside it.
 *
 * Synchronous, like {@link ContentPort} and for the same reason: the fallback across sources is a
 * loop with an ordering the specification fixes, and an await inside it would let a caller
 * interleave sources the ordering exists to keep apart.
 */
export interface IpnsPort {
  /** The CID this pointer names, in the text form a content layer takes, or null. */
  resolve(pointer: string): string | null;
}

/** A response with nothing in it, shared so that no caller invents its own empty body. */
const EMPTY_BODY = new Uint8Array(0);

/** What the proxy needs to turn a resolved content source into a response body. */
/**
 * The cache key a content failure is stored under.
 *
 * Exported because it is read from two places now: the resolver stores a failure here, and the pin
 * path has to drop it when the reason for the failure goes away. Building the string twice would
 * be two spellings of one rule, and the two would disagree the first time either changed.
 *
 * A name key cannot collide with one of these — the label grammar admits no colon.
 */
export function contentCacheKey(type: string, value: string): string {
  return `content:${type}:${value}`;
}

export interface ContentPort {
  /**
   * Bytes for `path` under `source`, or a numbered failure.
   *
   * The path is the request target's path component, already bounded by `PROXY_LIMITS`. Returning
   * a code rather than throwing keeps the catalogue in one place: RESOLUTION.md's numbers are the
   * contract, and an exception escaping here would surface as a 500 that says nothing.
   */
  fetch(source: { type: string; value: string }, path: string): ContentResult;
}

export type ContentResult =
  | { readonly ok: true; readonly bytes: Uint8Array; readonly contentType: string }
  | { readonly ok: false; readonly error: ResolveErrorName };

/**
 * Render a resolved entry's value as the text an addressing layer takes.
 *
 * **This existed as `String(entry.value)` and was wrong for every binary entry type.** A `cid`
 * entry is a `bstr` (REGISTRY.md, entry table), so `String` produced `"1,112,32,180,…"` — the
 * comma-joined decimals of a typed array. That is a string, it is not empty, and it flows through
 * every type check on the way to a content port that can only ever fail to match it. The symptom
 * was a 502 on a name that resolved perfectly, with nothing wrong logged anywhere, because
 * nothing had gone wrong as far as any code on the path could tell.
 *
 * So the conversion is explicit, per type, and returns null rather than guessing. `String()` on a
 * value whose shape you have not checked is not a conversion; it is a promise that there will
 * always be *some* string, which is exactly the property that keeps a mismatch from surfacing.
 */
export function sourceValueOf(entry: { type: string; value: CborValue }): string | null {
  const value = entry.value;
  switch (entry.type) {
    case 'cid':
      // Rendered base32, as REGISTRY.md renders a `cid` outside CBOR. `cidFromBytes` refuses a
      // CIDv0, a foreign codec or a short digest, so a record carrying one addresses nothing
      // here instead of addressing something approximate.
      if (!(value instanceof Uint8Array)) return null;
      try {
        return encodeCid(cidFromBytes(value));
      } catch {
        return null;
      }
    case 'ipns':
    case 'alias':
      return typeof value === 'string' ? value : null;
    case 'peer':
      if (!(value instanceof Uint8Array)) return null;
      return Array.from(value, (b) => b.toString(16).padStart(2, '0')).join('');
    default:
      return null;
  }
}

/**
 * Extract the host from a request, or null if the shape is not one of the two accepted.
 *
 * LOCAL-SURFACE.md 2.1. Absolute-form takes its host from the target and *ignores* the `Host`
 * header; origin-form takes it from `Host`. Preferring the target where both exist matters,
 * because a request carrying `http://a.vayu/` with `Host: b.vayu` is a request two implementations
 * would route differently, and a proxy that consults whichever is more convenient is a proxy an
 * attacker can aim.
 */
export function requestHost(request: ProxyRequest): string | null {
  if (request.target.length > PROXY_LIMITS.targetBytes) return null;

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(request.target)) {
    // Absolute-form. Only http is accepted: an https target would promise a transport guarantee
    // this proxy does not provide, and accepting it would let a page believe it had one.
    if (!/^http:\/\//i.test(request.target)) return null;
    const rest = request.target.slice('http://'.length);
    const end = rest.search(/[/?#]/);
    const authority = end === -1 ? rest : rest.slice(0, end);
    // Userinfo is refused rather than stripped. `http://a.vayu@evil.example/` is a host-confusion
    // primitive, and every reading of it that is not "refuse" has been an exploit somewhere.
    if (authority.includes('@')) return null;
    return authority;
  }

  if (!request.target.startsWith('/')) return null;
  return request.headers.get('host') ?? null;
}

/**
 * Split a host into a validated `(label, tld)`, or null.
 *
 * LOCAL-SURFACE.md 3.1: the label is validated against the NAMES.md grammar **before** it is
 * echoed, cached, logged, used to construct a header, or sent anywhere. A hostile name is the
 * injection vector for response splitting, and the ordering is the whole defence — so this
 * function is the only way a host becomes a name in this module, and it refuses rather than
 * repairs.
 *
 * LOCAL-SURFACE.md 3.2: the result is the cache key. Never the raw `Host`, because two spellings
 * of one name occupying two entries is a cache-poisoning primitive.
 */
export function normaliseHost(host: string): { label: string; tld: string } | null {
  if (host.length === 0 || host.length > PROXY_LIMITS.hostBytes) return null;
  // A port, an IP literal, userinfo or a bracketed IPv6 address is refused outright. Each is a way
  // of naming something that is not a VayuWeb name, and this proxy routes nothing else.
  if (host.includes(':') || host.includes('@') || host.includes('[')) return null;

  let value = host.normalize('NFC').toLowerCase();
  if (value.endsWith('.')) value = value.slice(0, -1);

  const dot = value.lastIndexOf('.');
  if (dot <= 0 || dot === value.length - 1) return null;
  const label = value.slice(0, dot);
  const tld = value.slice(dot + 1);
  if (label.includes('.')) return null;

  if (labelRejection(label) !== null) return null;
  if (!isRatifiedTld(tld)) return null;
  return { label, tld };
}

export function refusal(error: ResolveErrorName): ProxyResponse {
  const spec = RESOLVE_ERRORS[error];
  const headers = new Map<string, string>(SECURITY_HEADERS);
  headers.set('content-type', 'text/plain; charset=utf-8');
  // LOCAL-SURFACE.md 2.4: "a refusal MUST NOT be distinguishable from an ordinary connection
  // failure in a way that confirms VayuWeb is running." So the body carries no product name, no
  // numeric VayuWeb code and no name the caller supplied — echoing the request back is both the
  // fingerprint and the injection vector. The code stays available to the control API, which is
  // where a diagnosis belongs, because that surface is not reachable from a page.
  return { status: spec.http, headers, body: EMPTY_BODY };
}

/**
 * The path component of a request target, absolute-form or origin-form.
 *
 * Query and fragment are dropped rather than passed on: a VayuWeb tree has no query semantics,
 * and forwarding one would invite a resolver to grow them.
 */
export function pathOf(target: string): string {
  const withoutScheme = target.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '');
  const path = (withoutScheme.split(/[?#]/)[0] ?? '').trim();
  return path.length === 0 ? '/' : path;
}

/**
 * Handle one request.
 *
 * Ordered so that the cheapest and most decisive refusals run first, and so that nothing derived
 * from the request is used before it has been validated.
 */
export function handleRequest(
  request: ProxyRequest,
  ports: ResolverPorts,
  cache: ResolutionCache,
  now: number,
  options: ProxyOptions = {},
): ProxyResponse {
  // LOCAL-SURFACE.md 2.2. CONNECT is not implemented, so there is no destination policy to get
  // wrong: a proxy that will CONNECT anywhere is an open relay and an SSRF pivot into the
  // reader's own network, and the safest implementation of a dangerous verb is none.
  //
  // Named explicitly even though the shape rule below already refuses an authority-form target
  // and the method allowlist already refuses the verb. Two defences cover it and this is a third;
  // it earns its place by making the refusal legible to a reader looking for it, which a rule
  // that only happens to be implied by two other rules does not.
  if (request.method === 'CONNECT') return refusal('BLOCKED_BY_POLICY');
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return refusal('BLOCKED_BY_POLICY');
  }

  const host = requestHost(request);
  if (host === null) return refusal('BLOCKED_BY_POLICY');

  const name = normaliseHost(host);
  if (name === null) {
    // Not cached, at all. LOCAL-SURFACE.md 3.3: the grammar check is cheaper than the cache
    // lookup, so caching a syntactically invalid name buys nothing and hands a page an
    // attacker-keyed insert.
    return refusal('LABEL_INVALID');
  }

  const key = `${name.label}.${name.tld}`;

  // The cache checks are steps 5 and 6 of the algorithm, so they happen inside it. They used to
  // happen here instead, which put them outside the alias loop and hard-wired the one code this
  // surface knew how to store — a hit answered `NAME_NOT_FOUND` whatever had been cached, and
  // nothing but `NAME_NOT_FOUND` was ever cached, so the two bugs concealed each other.
  const outcome = resolveName(key, ports, now, cache);
  if (!outcome.ok) return refusal(outcome.error);

  const headers = new Map<string, string>(SECURITY_HEADERS);
  headers.set('content-type', 'text/plain; charset=utf-8');

  // RESOLUTION.md step 13. Only attempted when a content layer is wired; otherwise the answer
  // stays a bare 200, which is the truthful "this name resolves and nothing here serves it"
  // rather than a pretend page. What arrives from the port has already been VERIFIED --
  // `fetch.ts` checks every block against the CID that referred it -- so these are bytes that
  // hashed correctly, not bytes a peer sent.
  //
  // **The fallback across sources lives here, and used to not exist anywhere.** RESOLUTION.md:
  // "If the chosen entry fails, the resolver SHOULD fall back to the next, MUST record the
  // fallback in the control API's per-request diagnostics, and MUST mark the answer stale." One
  // source was tried and that was the end of it, so a record carrying the arrangement HOSTING.md
  // recommends — an `ipns` pointer beside a `cid` snapshot — answered 502 while the snapshot the
  // publisher supplied for exactly that case went unasked. `Diagnostics.fallbacks` was declared
  // and always empty.
  let body: Uint8Array = EMPTY_BODY;
  let source: SourceType | null = outcome.diagnostics.source;
  /**
   * The identifier actually served, for `X-VayuWeb-CID`.
   *
   * That header is enumerated in RESOLUTION.md and was emitted nowhere — declared in
   * `DIAGNOSTIC_HEADERS` and set by no line of code. The only test over the list asserted the
   * headers are ABSENT by default, which is true of a header that does not exist, so the list
   * could name anything and stay green.
   *
   * It carries the source's rendered value rather than the record's first entry, because after a
   * fallback those are different things and the useful one is what the reader received.
   */
  let servedCid: string | null = null;
  /**
   * The status a successful answer carries, which is not always 200.
   *
   * Step 13 serves a declared `notFound` document **with HTTP 404**: the site's own page, and the
   * status a search engine, a link checker and a browser's history all need. Serving it with 200
   * would make every broken deep link look like a page, which is the thing a `notFound` document
   * exists to avoid rather than to cause.
   */
  let status = 200;
  const fallbacks: SourceType[] = [];
  if (options.content !== undefined) {
    const candidates = sourceCandidates(outcome.record);
    let failure: ResolveErrorName = 'NO_USABLE_RECORD';
    let served = false;
    for (const candidate of candidates) {
      const type = candidate.type as SourceType;
      const value = sourceValueOf(candidate);
      if (value === null) {
        // A malformed entry is this source failing, not the request failing. The next source is
        // exactly what a publisher supplied a second entry for.
        failure = 'NO_USABLE_RECORD';
        fallbacks.push(type);
        continue;
      }

      // **Content failures are keyed by the content, not by the name**, and the reason is a defect
      // in the algorithm's own ordering rather than a preference. Step 5 takes a positive record
      // from the cache and jumps to step 9, which SKIPS step 6 — so a `CONTENT_UNAVAILABLE` stored
      // under `atlas.vayu` is unreachable for exactly as long as `atlas.vayu`'s record is cached,
      // which is every request after the first. The two shortest TTLs in RESOLUTION.md's table
      // would have been a writer with no reader.
      //
      // Keyed by the source it is a fact about, it is reachable and it is also more nearly true:
      // a CID nobody is serving is not being served to any name that points at it, and two names
      // sharing a snapshot share the answer. A name key cannot collide with one of these — the
      // label grammar admits no colon.
      const contentKey = contentCacheKey(type, value);
      const known = cache.negative(contentKey, now);
      if (known !== null) {
        // No fetch at all. This is the whole of what caching a content failure buys: a site being
        // offline costs one attempt per TTL rather than one attempt per reader.
        failure = known;
        fallbacks.push(type);
        continue;
      }

      // **Step 10, which had no implementation and left 1505 with no producer.** `SOURCE_ORDER`
      // puts `ipns` FIRST — HOSTING.md tells publishers to carry a pointer for the living site and
      // a `cid` for the snapshot to serve when the pointer cannot be resolved — so the entry the
      // specification prefers was the one nothing could act on. A record carrying only a pointer
      // answered 1421 `NO_USABLE_RECORD`, which tells its publisher the record is wrong.
      //
      // After this step there is only a CID, which is what step 11 fetches. A content layer
      // therefore never needs to know what a pointer is.
      let addressed = value;
      if (type === 'ipns') {
        const resolved = options.ipns?.resolve(value) ?? null;
        if (resolved === null) {
          failure = 'IPNS_UNRESOLVED';
          cache.putNegative(contentKey, failure, now);
          fallbacks.push(type);
          continue;
        }
        addressed = resolved;
      }

      const fetched = serveStep13(options.content, addressed, pathOf(request.target), cache);
      if (fetched.ok) {
        status = fetched.status;
        headers.set('content-type', fetched.contentType);
        // Handed on unchanged. There is no encoding step here any more, which is the point: the
        // two that used to exist did not agree with each other.
        body = fetched.bytes;
        // The ORIGINAL type, because `X-VayuWeb-Source` enumerates `cid`, `ipns`, `peer` and a
        // reader asking which kind of entry served them is asking about the record, not about
        // what step 10 turned it into.
        source = type;
        // The CID actually addressed, which after a pointer resolution is not in the record at
        // all. It was `type === 'cid' ? value : null`, so an ipns-served page carried an empty
        // `X-VayuWeb-CID` — the one header that would tell an operator which snapshot a live
        // pointer had landed on.
        servedCid = addressed;
        served = true;
        break;
      }
      // **The one MUST NOT, and the one whose absence is exploitable.** Bad bytes mean somebody
      // is lying, not that a host is down. A resolver that falls back on an integrity failure
      // hands an attacker a downgrade: corrupt the source the publisher prefers, and the resolver
      // walks itself to whichever source the attacker can better influence.
      if (fetched.error === 'CONTENT_INTEGRITY') return refusal('CONTENT_INTEGRITY');
      // Ten seconds, and only for the codes the table names — `CONTENT_INTEGRITY` never reaches
      // here, and would be refused by the table if it did. That refusal is the one that matters
      // most: an integrity failure cached against a CID is a way to make a site unreachable to
      // everyone behind this resolver by getting one bad copy through once.
      cache.putNegative(contentKey, fetched.error, now);
      failure = fetched.error;
      fallbacks.push(type);
    }
    if (!served) return refusal(failure);
  }

  if (options.diagnostics === true) {
    // Only reachable once the control API has turned them on. Values come from the *validated*
    // name and the resolver's own diagnostics, never from the request, so there is nothing here
    // an attacker chose the bytes of.
    headers.set('x-vayuweb-name', key);
    headers.set('x-vayuweb-seq', String(outcome.diagnostics.seq ?? ''));
    headers.set('x-vayuweb-cid', servedCid ?? '');
    headers.set('x-vayuweb-source', source ?? '');
    headers.set('x-vayuweb-resolved-from', outcome.diagnostics.resolvedFrom ?? '');
    // Stale when a source was abandoned, which is the MUST the specification attaches to falling
    // back: the answer is not the one the publisher would rather have served. It used to be
    // `diagnostics.stale || fallbacks.length > 0`, and the first half was a field nothing ever
    // set — so the expression read as though two conditions fed this header when one did.
    headers.set('x-vayuweb-stale', fallbacks.length > 0 ? '1' : '0');
    headers.set('x-vayuweb-fallbacks', fallbacks.join(','));
  }

  return { status, headers, body };
}

/**
 * RESOLUTION.md step 13, including the half that consulted no manifest.
 *
 * ## What was missing, and what it cost
 *
 * PUBLISHING.md 2.3 is a **SHALL** — "on no path match the resolver SHALL serve `notFound` with
 * HTTP 404 if present; otherwise, if `fallback` is declared, serve it with HTTP 200 so the site's
 * own router can handle the path" — and it names its own symptom in the sentence before: "a site
 * with client-side routing 404s on every deep link unless a fallback exists". Nothing in the
 * shipping resolver read `.vayu/manifest.json` at all. `mapPath` implements the non-manifest half
 * and had no caller; the CLI's content port reimplemented a subset of it inline, which is how the
 * manifest half went missing without anything looking wrong.
 *
 * ## The manifest is fetched at most once, and only when it is needed
 *
 * A file request that hits costs nothing extra — the common case is untouched. A directory request
 * needs it up front, because a declared `index` takes precedence over `index.html` and there is no
 * way to know that after the fact. A miss needs it to look for `notFound` and `fallback`.
 *
 * The manifest is remembered per CID with no expiry, which is the first slice of the content cache
 * RESOLUTION.md's caching section describes — "immutable, keyed by CID, no expiry". A CID addresses
 * its bytes, so the entry cannot go stale, and the cost is therefore one extra block fetch per
 * SITE rather than per request. Stated rather than left for a reader to measure.
 */
export function serveStep13(
  content: ContentPort,
  cid: string,
  path: string,
  cache: ResolutionCache,
):
  | (ContentResult & { readonly ok: true; readonly status: number })
  | { ok: false; error: ResolveErrorName } {
  const fetchPath = (at: string): ContentResult => content.fetch({ type: 'cid', value: cid }, at);

  const site = (): SiteManifest | null => {
    const known = cache.manifest(cid);
    if (known !== undefined) return known;
    const got = fetchPath(MANIFEST_PATH);
    const parsed = got.ok ? parseManifest(got.bytes) : null;
    // Remembered whether or not there was one: "this site has no manifest" is exactly as reusable
    // a fact as its contents, and is the more common one.
    cache.rememberManifest(cid, parsed);
    return parsed;
  };

  // A declared `index` wins over `index.html`, which is what "resolving `/` and directory paths to
  // the manifest's `index` when one is declared and to `index.html` otherwise" says. If the
  // declared file is not in the tree the request carries on to the ordinary mapping, because a
  // manifest declares intent and is never evidence about the tree.
  //
  // **The whole mapping happens here and not in the content layer**, which is a change from how
  // this worked. The CLI's port did its own directory-to-`index.html` mapping, so step 13 was
  // implemented in two places — a resolver that knew about `mapPath` and a port that knew about
  // `index.html` — and the manifest, which belongs to neither, ended up in nothing. A port that is
  // asked for an exact path cannot lose half a rule it was never given.
  const directory = path === '/' || path.endsWith('/');
  if (directory) {
    const declared = site()?.index ?? null;
    if (declared !== null) {
      const attempt = fetchPath(`${path}${declared}`);
      if (attempt.ok) return { ...attempt, status: 200 };
      // **Only a missing path is a reason to try another path.** A source that is unavailable, or
      // whose bytes failed their hash, is not going to answer a different path any better — and on
      // an integrity failure, asking again is the downgrade RESOLUTION.md forbids at the source
      // level, applied one level down. Every attempt after the first is bandwidth spent proving
      // something already known.
      if (attempt.error !== 'PATH_NOT_FOUND') return attempt;
    }
    const fallbackIndex = fetchPath(`${path}index.html`);
    if (fallbackIndex.ok) return { ...fallbackIndex, status: 200 };
    if (fallbackIndex.error !== 'PATH_NOT_FOUND') return fallbackIndex;
    // A directory that has no index is not the same as a path that is missing, but the tree is the
    // only thing that can say so — ask for the path as given before giving up on it.
  }

  const direct = fetchPath(path);
  if (direct.ok) return { ...direct, status: 200 };
  // A directory named without its trailing slash still resolves to its index — `mapPath`'s rule,
  // applied where the tree can actually be asked.
  if (!directory && direct.error === 'PATH_NOT_FOUND') {
    const nested = fetchPath(`${path}/index.html`);
    if (nested.ok) return { ...nested, status: 200 };
  }
  // Only a missing PATH is a reason to look at the manifest. A source that is unavailable, a
  // pointer that will not resolve or bytes that failed their hash are not "this path is not in the
  // tree", and answering any of them with the site's 404 page would tell a reader the site is fine
  // and their link is wrong.
  if (direct.error !== 'PATH_NOT_FOUND') return direct;

  const declared = site();
  if (declared !== null) {
    if (declared.notFound !== null) {
      const attempt = fetchPath(`/${declared.notFound}`);
      // Served with 404, which is the point of it being a separate field from `fallback`.
      if (attempt.ok) return { ...attempt, status: 404 };
    }
    if (declared.fallback !== null) {
      const attempt = fetchPath(`/${declared.fallback}`);
      if (attempt.ok) return { ...attempt, status: 200 };
    }
  }
  return direct;
}
