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
  type ResolveErrorName,
  type ResolverPorts,
} from './resolve.ts';
import { cidFromBytes, encodeCid } from './content.ts';
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
  /** Negative cache entries. Bounded because the keys are attacker-chosen. */
  negativeEntries: 512,
  /** How long a negative answer is trusted, in seconds. Finite for the same reason. */
  negativeTtlSeconds: 30,
} as const;

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
  readonly body: string;
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
}

/** What the proxy needs to turn a resolved content source into a response body. */
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
 * A bounded, evicting negative cache with a finite TTL.
 *
 * Both properties are load-bearing and both were specification defects before: caching negative
 * answers "for process lifetime" gave a page an unbounded, attacker-fillable, never-evicted map.
 * Insertion order eviction rather than LRU, deliberately — LRU lets an attacker pin their own
 * entries by touching them, and there is nothing here worth protecting from eviction.
 */
export class NegativeCache {
  private readonly entries = new Map<string, number>();
  private readonly limit: number;
  private readonly ttl: number;

  constructor(
    limit: number = PROXY_LIMITS.negativeEntries,
    ttl: number = PROXY_LIMITS.negativeTtlSeconds,
  ) {
    this.limit = limit;
    this.ttl = ttl;
  }

  get size(): number {
    return this.entries.size;
  }

  has(key: string, now: number): boolean {
    const expires = this.entries.get(key);
    if (expires === undefined) return false;
    if (expires <= now) {
      this.entries.delete(key);
      return false;
    }
    return true;
  }

  put(key: string, now: number): void {
    if (this.entries.size >= this.limit && !this.entries.has(key)) {
      const oldest = this.entries.keys().next();
      if (!oldest.done) this.entries.delete(oldest.value);
    }
    this.entries.set(key, now + this.ttl);
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

function refusal(error: ResolveErrorName): ProxyResponse {
  const spec = RESOLVE_ERRORS[error];
  const headers = new Map<string, string>(SECURITY_HEADERS);
  headers.set('content-type', 'text/plain; charset=utf-8');
  // LOCAL-SURFACE.md 2.4: "a refusal MUST NOT be distinguishable from an ordinary connection
  // failure in a way that confirms VayuWeb is running." So the body carries no product name, no
  // numeric VayuWeb code and no name the caller supplied — echoing the request back is both the
  // fingerprint and the injection vector. The code stays available to the control API, which is
  // where a diagnosis belongs, because that surface is not reachable from a page.
  return { status: spec.http, headers, body: '' };
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
  cache: NegativeCache,
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
  if (cache.has(key, now)) return refusal('NAME_NOT_FOUND');

  const outcome = resolveName(key, ports, now);
  if (!outcome.ok) {
    if (outcome.error === 'NAME_NOT_FOUND') cache.put(key, now);
    return refusal(outcome.error);
  }

  const headers = new Map<string, string>(SECURITY_HEADERS);
  headers.set('content-type', 'text/plain; charset=utf-8');

  // RESOLUTION.md step 13. Only attempted when a content layer is wired; otherwise the answer
  // stays a bare 200, which is the truthful "this name resolves and nothing here serves it"
  // rather than a pretend page. What arrives from the port has already been VERIFIED --
  // `fetch.ts` checks every block against the CID that referred it -- so these are bytes that
  // hashed correctly, not bytes a peer sent.
  let body = '';
  if (options.content !== undefined) {
    const value = sourceValueOf(outcome.entry);
    if (value === null) return refusal('NO_USABLE_RECORD');
    const fetched = options.content.fetch(
      { type: outcome.entry.type, value },
      pathOf(request.target),
    );
    if (!fetched.ok) return refusal(fetched.error);
    headers.set('content-type', fetched.contentType);
    // Latin-1 rather than UTF-8: the body is a byte string all the way to the socket, and
    // decoding it as text would corrupt every image and every multi-byte character before the
    // serialiser could write it back out.
    body = Buffer.from(fetched.bytes).toString('binary');
  }

  if (options.diagnostics === true) {
    // Only reachable once the control API has turned them on. Values come from the *validated*
    // name and the resolver's own diagnostics, never from the request, so there is nothing here
    // an attacker chose the bytes of.
    headers.set('x-vayuweb-name', key);
    headers.set('x-vayuweb-seq', String(outcome.diagnostics.seq ?? ''));
    headers.set('x-vayuweb-source', outcome.diagnostics.source ?? '');
    headers.set('x-vayuweb-resolved-from', outcome.diagnostics.resolvedFrom ?? '');
    headers.set('x-vayuweb-stale', outcome.diagnostics.stale ? '1' : '0');
  }

  return { status: 200, headers, body };
}
