# VayuWeb Resolution Specification

This document specifies how a VayuWeb name is turned into bytes in a browser: the
local HTTP proxy, the control API, the ordered resolution algorithm, caching,
privacy obligations, the origin and security model, and the error catalogue.

The key words MUST, MUST NOT, SHALL, SHOULD, SHOULD NOT and MAY are to be
interpreted as described in RFC 2119.

Nothing described here has been implemented. This is a design under review.

## Scope and conformance

A conforming resolver replicates the VayuWeb registry log and serves reads from
its local Hyperbee index (see [REGISTRY.md](REGISTRY.md)), validates labels
against [NAMES.md](NAMES.md), fetches content over IPFS/IPNS as described in
[HOSTING.md](HOSTING.md), and exposes the two loopback listeners defined below.

This document owns the resolution path only. Record semantics, signature rules
and log verification belong to the registry specification.

## Components

A resolver SHALL expose exactly two listeners, and **only one of them is a
network listener**:

```text
127.0.0.1:7654         HTTP proxy    browser-facing, unauthenticated
<runtime-dir>/vayuweb.sock  control API   tooling-facing, bearer-token authenticated
```

The proxy MUST bind `127.0.0.1` (and `[::1]` where available). A resolver MUST
NOT bind `0.0.0.0`, `::`, a LAN address or a tunnel interface, and MUST refuse
to start if configuration requests one. There is no "share my resolver" mode: a
resolver answering for other hosts becomes an unauthenticated proxy and a
query-log collector, precisely the shape VayuWeb exists to avoid.

The control API is served over a **Unix domain socket (or a named pipe on
Windows)** with mode `0600`, in a directory owned by the user with mode `0700`.
It MUST NOT listen on TCP, on any address, including loopback — not even opt-in,
not even for development.

That single decision deletes DNS rebinding, CSRF, `Upgrade` reach and
browser port-scanning against the privileged surface permanently, because a
browser cannot address a Unix domain socket by any means. The full reasoning and
the hardening rules for the proxy that must remain on TCP are specified in
[LOCAL-SURFACE.md](LOCAL-SURFACE.md), which is normative.

## Resolution algorithm

The following steps are normative and ordered. The trigger is a browser request
for `http://example.vayu/` arriving at the proxy.

1. **Parse.** Take host and path from the absolute-form request URI or the
   `Host` header. Split the host into label and TLD at the last dot. Reject a
   host with more than two dot-separated components (subdomains are deferred;
   see the limitations section).
2. **TLD classification.** If the TLD is a member of the Namespace Annex — the
   1,270 ratified extensions enumerated in
   [NAMESPACE-CATALOGUE.md](NAMESPACE-CATALOGUE.md), incorporated into
   Constitution Article 35.1 by reference — continue at step 4; otherwise go to
   step 3. The set is not restated here. An earlier revision of this step
   hard-coded eleven strings inline, which made a resolver's namespace a copy
   able to drift from the Annex and from every other document that also restated
   it. The restatements did drift, by a factor of a hundred, and each
   implementer conformed to whichever one they happened to read.
3. **Non-VayuWeb host.** In the default `vayu-only` mode the proxy MUST return
   error 1403 `TLD_UNKNOWN`. In `passthrough` mode it MAY forward the request
   to the operating system's networking stack. In neither mode is a VayuWeb TLD
   eligible for step 3; that is what makes the no-DNS-fallback rule enforceable
   rather than aspirational.
4. **Label validation.** Normalise the label to NFC, lowercase, and check it
   against the grammar in [NAMES.md](NAMES.md). On failure return 1400
   `LABEL_INVALID`. Validating first keeps malformed input out of the network
   and the cache.
5. **Positive cache check.** Look up `(label, tld)`. If a fresh entry exists,
   take its record bundle and go to step 9.
6. **Negative cache check.** If a fresh negative entry exists, return its
   stored error without consulting the registry.
7. **Registry lookup.** Query the local Hyperbee index for the highest-`seq`
   record. The lookup is local and contacts no peer. If the log has never
   synchronised (no verified head), return 1502 `REGISTRY_UNAVAILABLE`.
8. **Validity window.** Compare now against `notBefore` and `notAfter`. An
   unexpired record proceeds; a record in grace or quarantine returns 1410
   `NAME_EXPIRED` or 1409 `NAME_QUARANTINED`; no record returns 1404
   `NAME_NOT_FOUND`. A resolver MUST NOT resolve an expired name even if the
   old `cid` is still held locally.
9. **Record selection.** Choose one content source from the record's `records`
   set using the ordering below. If none is usable, return 1421
   `NO_USABLE_RECORD`.
10. **Pointer resolution.** For `ipns`, resolve the pointer to a CID; on
    failure return 1505 `IPNS_UNRESOLVED`. For `alias`, restart at step 4 with
    the target against an alias budget of **3 hops**, counted per original
    request and matching [REGISTRY.md](REGISTRY.md); exhaustion returns 1508
    `ALIAS_LOOP`.
11. **Content fetch.** Fetch the CID over IPFS, preferring locally pinned
    blocks, then connected peers, then the DHT. No provider within the 15
    second first-byte timeout returns 1504 `CONTENT_UNAVAILABLE`; exceeding the
    120 second total budget returns 1408 `CONTENT_TIMEOUT`.
12. **Integrity check.** Verify the bytes hash to the requested CID. A mismatch
    MUST return 1512 `CONTENT_INTEGRITY` and MUST NOT reach the browser; if
    detected mid-stream the connection is aborted. This check is the whole of
    VayuWeb's transport authenticity story — there is no certificate authority to
    consult.
13. **Path mapping.** Treat the CID as a directory root and map the request
    path onto it, resolving `/` and directory paths to the manifest's `index`
    when one is declared and to `index.html` otherwise. On no match, consult
    `.vayu/manifest.json` from the **verified** tree: serve `notFound` with 404
    if declared, else serve `fallback` with 200 if declared so the site's own
    router can handle the path, else return 1414 `PATH_NOT_FOUND` — an ordinary
    404, the site's problem rather than the network's. The manifest's schema is
    in [PUBLISHING.md](PUBLISHING.md) section 2; a declared file that is not
    present in the verified tree is discarded rather than reported, because the
    manifest declares intent and is never evidence about the tree.

    An earlier revision of this step consulted no manifest at all, which left
    PUBLISHING.md 2.3's `SHALL` with no counterpart in the document that says
    what a resolver does: a publisher declaring `notFound` got an ordinary 404,
    and every site with client-side routing 404'd on every deep link.
14. **Response.** Emit the bytes with the security headers below and a
    `Content-Type` from the file extension. Emit the diagnostic `X-VayuWeb-*`
    headers **if and only if they have been enabled through the control API**;
    they are off by default, and the reason is in the caching section below —
    emitted unconditionally they brand every response as VayuWeb, which is the
    most consequential fingerprint the resolver can produce. Populate the
    caches. Return.

Steps 7 through 12 are the only slow ones. A resolver SHOULD report per-step
timings through the control API, never in the served response.

## Record selection

With several content entries present the resolver SHALL select in this order:
`ipns`, `cid`, `peer`, `alias`. A `txt` entry is never a content source. A
`peer` entry is the only option whose availability depends on one specific host
being online, so it ranks below both content-addressed forms; `alias` is last
because it costs another full resolution.

If the chosen entry fails, the resolver **SHOULD** fall back to the next, MUST
record the fallback in the control API's per-request diagnostics, and MUST mark
the answer stale. It MUST NOT fall back across a `CONTENT_INTEGRITY` failure,
which signals an attack rather than an availability problem. Disclosure to the
page through the `X-VayuWeb-*` headers happens only when those have been
enabled, since they are off by default — recording is mandatory, disclosing is
not.

### Why the pointer is preferred over the snapshot

An earlier revision of this section selected `cid` first, unconditionally, on
the reasoning that immutable content is verifiable without any liveness
assumption. That reasoning is sound. The conclusion was still wrong, because it
was drawn without reading what [HOSTING.md](HOSTING.md) tells a publisher to do.

HOSTING.md recommends carrying **both**: an `ipns` entry for the living site and
a `cid` for "the last snapshot the owner is willing to have served if the
pointer cannot be resolved", so that "the registry record stays still while the
site behind it changes, which is what an author republishing weekly actually
wants". Under the old order a publisher following HOSTING and a resolver
following this document would **both conform**, and every reader would be served
the frozen snapshot forever while the author published into a pointer nobody
consulted.

Three things made it worse than an ordinary bug. It is **silent** — no error, no
staleness signal. It is **permanent** — nothing later revisits the choice. And
it is **invisible to the author**, who resolves their own pointer and sees a
current site. Only readers see the frozen one.

The fallback rule contributed: it was `MAY`, so a conforming resolver need never
fall back at all, and the entry that never fails is precisely the pinned
snapshot. It is now `SHOULD`, and a fallback answer MUST be marked stale. Not
`MUST`, because forcing a resolver to serve older content whenever a pointer is
momentarily unreachable hands a network-level attacker a downgrade primitive —
but the snapshot is owner-signed, so serving it is a staleness problem rather
than an authenticity one, and refusing to serve anything is worse.

Preferring the pointer costs no verifiability. An IPNS record is signed by the
same key that controls the name, and what it yields is a CID, hash-verified
exactly as an inline one is. What it costs is a resolution step and a liveness
dependency, which is the right price for showing a reader what the author
actually published.

## The local HTTP proxy

The proxy on `127.0.0.1:7654` speaks HTTP/1.1 forward-proxy semantics:
absolute-form request URIs, plus `CONNECT` in `passthrough` mode only. It
accepts plaintext HTTP. There is no CA-issued certificate for `example.vayu`
and there cannot be one; confidentiality on that hop comes from the hop being
loopback, and authenticity from content addressing.

The proxy MUST refuse any request whose target host is `localhost`, an address
in `127.0.0.0/8`, `::1`, a link-local address, or one of the resolver's own
listeners. That is what stops a VayuWeb page reaching the control API through the
proxy it is already talking to. The proxy MUST NOT accept proxy credentials,
MUST NOT emit `X-Forwarded-For`, and MUST NOT add any header identifying the
user, the install or the resolver version.

A single resource is capped at 256 MiB, beyond which the resolver returns 1413
`RESPONSE_TOO_LARGE`; whole-CID verification would otherwise turn an unbounded
resource into an unbounded memory commitment.

## The control API

**The control API is not a TCP listener.** It MUST be served over a Unix domain
socket (POSIX) or a named pipe (Windows), mode `0600`, owned by the invoking
user, in a directory owned by that user with mode `0700`. It MUST NOT listen on
TCP on any address, including loopback.
[LOCAL-SURFACE.md](LOCAL-SURFACE.md) section 1 is normative and carries the
reasoning; a build offering a TCP control listener is non-conformant, including
opt-in and including "for development", because a development affordance is an
attack surface that ships.

An earlier revision of this section specified `127.0.0.1:7653` and is recorded
here rather than quietly replaced. The change landed in `LOCAL-SURFACE.md` and
nowhere else, so the corpus told an implementer to build a TCP listener in one
document and forbade it in another — and the one that said "127.0.0.1:7653" was
the one with the endpoint table, so it was the one an implementer would work
from. `scripts/check-listeners.py` now fails if any document reattaches a TCP
address to the control API.

The API is JSON over HTTP carried on that socket. Every endpoint MUST
require an `Authorization: Bearer <token>` header. The token is 32 bytes from
the OS CSPRNG, base64url-encoded, generated at first run, stored in the
resolver's config directory with mode `0600`, and compared in constant time. A
resolver MUST NOT start with a default, empty or derivable token, and MUST
regenerate it if the file is missing.

Endpoints:

```text
GET    /v1/status            version, mode, uptime, listeners
GET    /v1/health            liveness; 200 or 503
GET    /v1/log/head          verified registry head: length, root hash
GET    /v1/peers             peer count and swarm state
POST   /v1/resolve           {name} -> selected record and source
GET    /v1/records/{name}    current record
GET    /v1/cache/stats       entries, hit rate, bytes
DELETE /v1/cache             flush all caches
DELETE /v1/cache/{name}      flush one name
GET    /v1/pins              locally pinned CIDs
POST   /v1/pin               {cid} -> pin
DELETE /v1/pin/{cid}         unpin
GET    /v1/config            effective configuration
PATCH  /v1/config            mode, timeouts, cache sizes
POST   /v1/token/rotate      issue a new bearer token
```

The API MUST reject any request carrying an `Origin` header, MUST require the
custom header `X-VayuWeb-Control: 1`, MUST reject `Upgrade` or
`Connection: Upgrade` with 400, and MUST NOT set `Access-Control-Allow-Origin`
for any origin, ever.

These are kept, and the honest reason has changed. They were originally the
*primary* defence: a custom header forces a CORS preflight the API answers with
a denial, so no browser page could reach the endpoints even if it learned the
port. On a Unix socket that defence is redundant, because a browser cannot
address the socket at all — there is no `fetch`, form, `img`, WebSocket or
`XMLHttpRequest` that names one. They remain mandatory as defence in depth
against the one failure they still cover: an operator or a future refactor
putting an HTTP proxy, a socket-activation shim or a container port-forward in
front of the socket. Belt and braces cost nothing here; the braces are the
socket.

Signed registry writes (register, update, transfer, release) are not part of
this surface; see [REGISTRY.md](REGISTRY.md). They are performed by the client
application, which holds the keys.

## Browser integration

Options are ranked. A resolver SHALL support option 1 and SHOULD support
option 2.

1. **PAC file, preferred.** The resolver serves a proxy auto-configuration
   script routing only the VayuWeb TLD set to `127.0.0.1:7654` and returning
   `DIRECT` for everything else. Recommended because it keeps clearnet traffic
   outside the resolver, works in every major browser with no install, and
   yields the correct origin per name automatically.
2. **System or browser proxy setting.** Point the browser at `127.0.0.1:7654`
   for all HTTP traffic and run `passthrough` mode. Simpler, but it routes
   clearnet browsing through the resolver process — a larger trust and failure
   surface.
3. **Optional extension.** An extension MAY add address-bar completion, a
   name-status indicator and one-click pinning.

A browser extension MUST NOT be required to browse VayuWeb. Requiring one would
put an extension store — an entity that can review, reject, remove or silently
update the code — between users and a protocol whose premise is the absence of
such an entity. The extension MUST be a convenience layer over the same proxy
and control API, with no capability unavailable without it.

## Caching and TTL policy

The resolver keeps three caches with these defaults, all adjustable through
`PATCH /v1/config`:

- **Record cache**, positive: 300 seconds, further capped at `notAfter`. Five
  minutes bounds how long a superseded owner key stays usable, and the lookup
  it saves is a local B-tree read costing microseconds.
- **IPNS pointer cache**: `min(record validity, 120 seconds)`. This is the
  mutable path, and a publisher updating a site expects it live in about two
  minutes.
- **Content cache**: immutable, keyed by CID, no expiry. Bounded by a 2 GiB
  LRU cap and a 30-day idle eviction age.

Negative caching:

- `NAME_NOT_FOUND`: 30 seconds — short, because a name may be registered at any
  moment and the log replicates continuously.
- `NAME_EXPIRED`, `NAME_QUARANTINED`: 60 seconds.
- `LABEL_INVALID`, `TLD_UNKNOWN`: **not cached at all.** Both are decided by a
  grammar check that is cheaper than a cache lookup, and caching them for the
  process lifetime — as an earlier draft of this document specified — creates an
  unbounded, attacker-fillable, never-evicted structure that one hostile page
  can use to exhaust memory. Every other negative entry lives in a bounded
  evicting cache with a maximum entry count and a finite TTL; see
  [LOCAL-SURFACE.md](LOCAL-SURFACE.md) section 3.3.
- `CONTENT_UNAVAILABLE`, `IPNS_UNRESOLVED`: 10 seconds, so a site coming back
  online recovers quickly.
- `REGISTRY_UNAVAILABLE`, `CONTENT_INTEGRITY`: never cached.

When the registry is unreachable the resolver MAY serve a record up to 600
seconds past its TTL and MUST NOT serve past `notAfter`. It MUST record the
staleness in the control API's per-request diagnostics, and MUST send
`X-VayuWeb-Stale: 1` only when the diagnostic headers are enabled — that header
is one of them, and is off by default for the reason given below.

Diagnostic headers — `X-VayuWeb-Name`, `X-VayuWeb-Seq`, `X-VayuWeb-CID`, `X-VayuWeb-Source`
(`cid`, `ipns`, `peer`), `X-VayuWeb-Resolved-From` (`cache`, `registry`) and
`X-VayuWeb-Stale` — MUST be **off by default** and enabled only through the control
API.

Emitted unconditionally they brand every response as VayuWeb, which is the most
consequential fingerprint the resolver produces: it lets any page that can
elicit a response determine that VayuWeb is installed. For a reader in a hostile
jurisdiction that single fact may be all an adversary needs. Diagnostics that
disclose the tool's presence are disclosure, not diagnostics. See
[LOCAL-SURFACE.md](LOCAL-SURFACE.md) section 2.4.

## Privacy requirements

- The resolver MUST NOT log queries by default. Logging is opt-in, reset to off
  after every upgrade, capped by a retention in hours, and written only to a
  local file. There is no remote log target and configuration MUST NOT accept
  one.
- The resolver MUST NOT send telemetry, analytics, crash reports or update
  pings to any host. Update checks, if offered, MUST be manual.
- The resolver MUST NOT contact the clearnet DNS resolver for any host in the
  VayuWeb TLD set, in any mode, for any reason, including when the name does not
  exist. Enforcement is structural: step 2 classifies the TLD before a network
  path is chosen, step 3 is unreachable for VayuWeb TLDs, and the negative answer
  is produced locally as error 1404 rather than by falling through. A leaked
  lookup would tell a DNS operator exactly which VayuWeb names a user visits — the
  most valuable metadata in the system.
- The resolver MUST NOT prefetch, speculatively resolve, or warm caches from
  names the user has not requested.

Stated plainly as a limitation: swarm participation reveals to peers that an
address runs VayuWeb, and content requests reveal to the serving peer which CIDs
are fetched. VayuWeb removes the DNS observer; it does not make browsing
anonymous. See [THREAT-MODEL.md](../THREAT-MODEL.md).

## Origin and security model

Because the proxy answers absolute-form requests, the browser derives the
origin from the request URL. `http://example.vayu` and `http://other.vayu` are
therefore distinct origins with separate cookie jars, storage and permissions,
requiring nothing of the resolver beyond not rewriting hosts. The resolver MUST
NOT serve one name's content under another name's host.

The proxy SHALL inject the strict content-security profile on every HTML
response, replacing any policy the site supplied. That profile — the
Content-Security-Policy, the ten accompanying response headers, the request
headers the resolver must never emit, the response headers it must strip, and
the markup it must neutralise — is specified normatively in
[CONTENT-SECURITY.md](CONTENT-SECURITY.md) and is **not restated here**. It is
defined in exactly one place so that it cannot drift; `scripts/check-headers.py`
enforces that, and CI fails on divergence.

The shape of it: `default-src 'none'` with every resource type enumerated
explicitly, so a directive nobody remembered to add fails closed. Every source
is `'self'`, so a page loads only bytes from its own verified CID. Clearnet
subresources are refused because each one reintroduces a DNS lookup, a
certificate authority, and a third party learning the visitor's address and
which VayuWeb page they are reading — three things the protocol exists to remove.
There is no `'unsafe-inline'`, for styles or anything else, and no CSP
reporting endpoint, because a report endpoint is an outbound channel that fires
precisely when something unexpected happens.

Four channels are not closable by CSP at all — WebRTC, top-level navigation,
timing side channels, and a compromised endpoint. CONTENT-SECURITY.md section 4
names each and specifies what closes it instead; the resolver MUST implement
those controls, and the client MUST warn where it cannot.

A site MAY request one of the two per-site relaxations defined in
CONTENT-SECURITY.md section 1.3 (WebAssembly, or a named Trusted Types policy).
Each is scoped to that site alone and MUST be surfaced to the reader. No flag,
control-API setting or configuration file widens the policy to clearnet, or
applies a relaxation globally; those refusals are not tunable.

HSTS is never sent: VayuWeb names are served over plaintext loopback HTTP, and an
HSTS entry would poison the browser's state for that host permanently.

## Error catalogue

A failure is returned as an HTML page carrying the numeric code, and as a JSON
object on the control API.

The code is carried in an `X-VayuWeb-Error` header **only when the diagnostic
headers are enabled**. It is subject to the same default-off rule as the rest of
the `X-VayuWeb-*` family and for the same reason: a header emitted on every
failure brands the response as VayuWeb to any page that can provoke one, and a
failure is the easiest response to provoke. With diagnostics off, the code
appears in the HTML body — which the requesting page cannot read cross-origin —
and on the control API, which is where a diagnostic belongs.

| Code | Name | HTTP | User-facing message |
| --- | --- | --- | --- |
| 1400 | LABEL_INVALID | 400 | That name is not a valid VayuWeb name. |
| 1403 | TLD_UNKNOWN | 502 | This resolver only handles VayuWeb names. |
| 1404 | NAME_NOT_FOUND | 404 | No one has registered this name. |
| 1408 | CONTENT_TIMEOUT | 504 | The site took too long to load. |
| 1409 | NAME_QUARANTINED | 409 | This name expired and is on hold. |
| 1410 | NAME_EXPIRED | 410 | This name's registration has expired. |
| 1413 | RESPONSE_TOO_LARGE | 502 | This file is larger than the resolver will load. |
| 1414 | PATH_NOT_FOUND | 404 | This page does not exist on this site. |
| 1421 | NO_USABLE_RECORD | 502 | This name points at nothing fetchable. |
| 1451 | BLOCKED_BY_POLICY | 403 | The resolver refused this request for safety reasons. |
| 1500 | INTERNAL | 500 | The resolver hit an internal error. |
| 1502 | REGISTRY_UNAVAILABLE | 503 | The resolver has not synchronised the registry yet. |
| 1503 | REGISTRY_STALE | 503 | The registry copy is too old to answer safely. |
| 1504 | CONTENT_UNAVAILABLE | 504 | No one is currently sharing this site's files. |
| 1505 | IPNS_UNRESOLVED | 504 | This site's pointer could not be resolved. |
| 1508 | ALIAS_LOOP | 508 | This name points in a circle. |
| 1512 | CONTENT_INTEGRITY | 502 | The content did not match its fingerprint and was discarded. |
| 1401 | CONTROL_AUTH_REQUIRED | 401 | This request needs the resolver's control token. |
| 1406 | CONTROL_FORBIDDEN_ORIGIN | 403 | Web pages may not use the control API. |

Error pages MUST be generated locally, MUST NOT load any subresource, and MUST
NOT offer a search box or suggestion list — anything that would send the failed
name onward.

## Known limitations

Subdomains are not resolvable at launch; a record addresses one name. Wildcard
and delegated subdomain semantics are deferred to a VWIP.

There is no transport encryption beyond the loopback boundary, so a local
process running as the same user can observe traffic — an accepted trade
against requiring a certificate authority.

Availability is only as good as the set of peers pinning a site. A name can
resolve correctly and still return 1504 indefinitely; the protocol offers no
remedy beyond volunteers.

Status: Draft — not yet implemented. This describes the intended behaviour of a
resolver that has not been written; every number is open to revision through
the VWIP process.

See also: [REGISTRY.md](REGISTRY.md), [NAMES.md](NAMES.md),
[HOSTING.md](HOSTING.md), [THREAT-MODEL.md](../THREAT-MODEL.md).
