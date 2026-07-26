# VayuWeb Local Attack Surface Specification

The resolver runs on the reader's own machine and listens for connections. That makes it
reachable by every page in every tab, including hostile clearnet pages the reader never
associated with VayuWeb. This document specifies how those listeners are hardened.

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

**Status:** Draft — not yet implemented. Proposed formally by [VWIP-0001](VWIP-0001.md).

## 1. The control API is not a TCP listener

**The control API MUST be served over a Unix domain socket (POSIX) or a named pipe (Windows),
with mode `0600` and owned by the invoking user. It MUST NOT listen on TCP, on any address,
including loopback.**

This is the single highest-value hardening decision in the whole design, and it is worth stating
as a rule rather than a preference, because "loopback is safe" is a belief that has cost many
projects dearly.

A browser cannot address a Unix domain socket. No `fetch`, no form, no `img` tag, no WebSocket, no
`XMLHttpRequest` can reach one. Moving the privileged surface off TCP therefore deletes, in one
change and permanently:

- **DNS rebinding** against the control API — the attacker's page cannot open the socket at all.
- **CSRF**, including the simple-request forms that bypass preflight.
- **WebSocket `Upgrade` reach** into the privileged port.
- **Browser port-scanning** of the privileged surface.

Each of those would otherwise require its own defence, each defence would need to be correct
forever, and each would be one refactor away from regressing. A socket a browser cannot name needs
none of them.

The cost is a small change to the client and CLI transport. That is an excellent trade and it MUST
NOT be reversed for convenience. A build that offers a TCP control listener — even opt-in, even
"for development" — is non-conformant, because a development affordance is an attack surface that
ships.

1.1 The socket path MUST be in a directory owned by the user with mode `0700`.

1.2 Authentication is still required. Defence in depth: the bearer token specified in
[RESOLUTION.md](RESOLUTION.md) remains mandatory on every endpoint, compared in constant time over
fixed-length decoded bytes. A socket permission is a control that a misconfigured umask can
weaken; a token is not.

1.3 The control API MUST reject any request carrying `Upgrade` or `Connection: Upgrade` with 400.
It offers no WebSocket endpoint, so the rejection is unconditional and needs no analysis.

1.4 `GET /v1/config` MUST redact the token and every secret-bearing path. `GET /v1/status` MUST
NOT disclose a build version to an unauthenticated caller — a version string is a fingerprint and
a vulnerability-matching aid.

## 2. The browsing proxy

The proxy on `127.0.0.1:7654` must remain a TCP listener, because a browser has to reach it. It is
therefore hardened directly.

### 2.1 Request shape

The proxy MUST accept only two request shapes and reject everything else:

- **absolute-form** request URIs whose host is a VayuWeb-TLD host, or
- **origin-form** requests whose `Host` header is a VayuWeb-TLD host.

Any other `Host` — an IP literal, `localhost`, `127.0.0.1`, a clearnet name, an empty value, or a
value with a port — MUST be rejected before routing. This is the DNS-rebinding defence: an
attacker who rebinds a hostname they control to `127.0.0.1` still arrives carrying their own
`Host`, which is not a VayuWeb name, and is refused.

### 2.2 `CONNECT`

The proxy SHOULD NOT implement `CONNECT` at all. Where it is implemented for compatibility, it
MUST refuse every destination that is not a VayuWeb name, and MUST refuse loopback, link-local,
multicast and RFC 1918 destinations unconditionally. A proxy that will `CONNECT` anywhere is an
open relay and an SSRF pivot into the reader's own network.

### 2.3 Private Network Access

The resolver MUST NOT emit `Access-Control-Allow-Private-Network` on any response, on any
listener, and MUST NOT be configurable to. That header exists to let a public page reach a private
service, which is the exact thing this specification is preventing.

### 2.4 Identifying headers

The `X-VayuWeb-Name`, `X-VayuWeb-Seq`, `X-VayuWeb-CID`, `X-VayuWeb-Source`, `X-VayuWeb-Resolved-From` and
`X-VayuWeb-Stale` diagnostic headers MUST be **off by default**, available only when explicitly
enabled through the control API.

As specified previously they brand every response as VayuWeb, which is the most consequential
fingerprint the system emits: it lets any page that can elicit a response determine that VayuWeb is
installed. For a reader in a hostile jurisdiction, "this person runs VayuWeb" may be the only fact an
adversary needs. Diagnostics that reveal the tool's presence are not diagnostics, they are
disclosure.

The same reasoning applies to error bodies: a refusal MUST NOT be distinguishable from an ordinary
connection failure in a way that confirms VayuWeb is running.

## 3. Naming and cache integrity

### 3.1 Validate before anything else

The label MUST be validated against the [NAMES.md](NAMES.md) grammar **before** it is echoed,
cached, logged, used to construct any header, or sent to the network. A hostile name is the
injection vector for response splitting and header injection, and ordering is the whole defence.

### 3.2 Cache keying

The cache key MUST be the post-normalisation `(label, tld)` tuple — never the raw `Host`. The
resolver normalises to NFC, lowercases, strips a trailing dot and any port, and **rejects** rather
than repairs anything that does not then match the grammar. Keying on the raw `Host` allows two
spellings of one name to occupy two entries, which is a cache-poisoning primitive.

### 3.3 Negative caching must be bounded

Caching `LABEL_INVALID` and `TLD_UNKNOWN` "for process lifetime" is a specification defect: the
entries are attacker-fillable, unbounded and never evicted, so one hostile page can exhaust
memory by requesting an endless stream of invalid names.

Negative cache entries MUST be held in a bounded, evicting structure with a documented maximum
entry count and a finite TTL. Syntactically invalid names SHOULD NOT be cached at all — the
grammar check is cheaper than the cache lookup.

### 3.4 Resource limits

Per-page and per-origin concurrency caps, a bounded in-flight request count, and a total memory
ceiling for caches MUST all be specified with concrete numbers and enforced. An unbounded resource
is a denial-of-service primitive available to any page.

## 4. Cross-name subresources

Where `allow_cross_name_subresources` is offered at all it MUST be off by default, and when set it
MUST widen only `img-src`, `font-src` and `media-src`.

It MUST NOT widen `script-src`, `connect-src`, `frame-src`, `object-src` or `worker-src`. Widening
`script-src` across names creates a cross-name supply chain: one compromised name executes code in
the context of every name that references it — the precise failure mode that has made third-party
scripts the most reliable attack path on the clearnet.

## 5. What remains open

**5.1 Port-scanning and service detection.** A page can time `connect()` against `127.0.0.1:7654`
and distinguish a listening port from a closed one. This happens below the HTTP layer, so no
response header, `Host` check or bind rule reaches it. Moving the control API to a Unix socket
removes the *privileged* surface from this exposure, but the browsing proxy must remain reachable
and therefore remains detectable.

*Partial mitigation:* a randomised proxy port chosen at install time and written to the client's
configuration raises the cost of a blind scan. It does not eliminate detection, and the
specification MUST NOT claim it does.

**5.2 Token theft by a same-user local process.** Any process running as the reader can read a
`0600` file owned by that reader. This is an operating-system boundary, not one VayuWeb can enforce.
Mitigated by keeping the token in the platform keystore where one is available, and by
regenerating it per run in Private Mode.

**5.3 Swap and memory disclosure.** Covered in [PRIVACY.md](PRIVACY.md) section 6.

## 6. Conformance

1. The control API is not reachable over TCP on any address. A connection attempt to any port
   finds no control listener.
2. `fetch` from a page to the control socket fails at the transport layer, not at authentication.
3. A request to the proxy bearing a non-VayuWeb `Host` is rejected before routing.
4. `Access-Control-Allow-Private-Network` never appears on any response.
5. `X-VayuWeb-*` headers are absent unless explicitly enabled.
6. An endless stream of invalid names does not grow resident memory without bound.
7. Two spellings of one name produce one cache entry.
8. A request with `Upgrade` to the control API returns 400.

## See also

- [Resolution specification](RESOLUTION.md) — the listeners this document hardens
- [Content security specification](CONTENT-SECURITY.md) — the page-facing profile
- [Privacy and zero-trail specification](PRIVACY.md) — what is written to disk
- [Threat model](../THREAT-MODEL.md)
