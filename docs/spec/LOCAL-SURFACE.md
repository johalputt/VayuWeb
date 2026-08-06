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

#### 2.1.1 `passthrough` mode, and why it is a carve-out rather than an exception

[RESOLUTION.md](RESOLUTION.md) step 3 defines a `passthrough` mode in which a non-VayuWeb host
"MAY be forwarded to the operating system's networking stack", and its browser-integration option
2 requires it: a browser pointed at the proxy for **all** HTTP traffic cannot reach the clearnet
otherwise. This document said nothing about it, and the word did not appear here at all — so an
implementer reading this section alone built a proxy that cannot do option 2, and one reading
RESOLUTION.md alone built an open relay. Both conformed.

Where `passthrough` is implemented, all of the following are normative:

- It MUST be **off by default**. `vayu-only` is the default mode, and a resolver that forwards
  clearnet traffic without being asked has enlarged its own trust surface silently.
- It MUST be unavailable in **Private Mode**, without exception and without a setting.
  [CONTENT-SECURITY.md](CONTENT-SECURITY.md) 5.2 closes top-level navigation exfiltration
  *precisely by refusing* the forwarded request with `1403 EGRESS_REFUSED`; a passthrough that
  honoured it would reopen the one channel full-proxy configuration exists to close.
- It MUST refuse loopback, link-local, multicast and RFC 1918 destinations **unconditionally**,
  exactly as `CONNECT` must in 2.2. Forwarding to the reader's own network is an SSRF pivot
  whether the verb is `GET` or `CONNECT`, and the rebinding defence above is not weakened by
  passthrough for the same reason: a rebound host is still not a VayuWeb name, so it is forwarded
  outward rather than routed internally, and the internal-address refusal is what stops it
  arriving anywhere sensitive.
- A VayuWeb TLD MUST NOT be eligible for it in either mode. That is what makes the
  no-DNS-fallback rule enforceable rather than aspirational, and RESOLUTION.md step 3 says so.

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
resolver normalises to NFC, lowercases, strips a trailing dot, and **rejects** rather than repairs
anything that does not then match the grammar.

It does **not** strip a port. This clause said "strips a trailing dot and any port", against 2.1
above, which lists "a value with a port" among the `Host` values that "MUST be rejected before
routing" — one document telling an implementer to repair the exact value the other tells them to
refuse. 2.1 wins: it is the DNS-rebinding rule, and repairing a malformed authority is how a
request that should have been refused acquires a cache entry instead. Keying on the raw `Host` allows two
spellings of one name to occupy two entries, which is a cache-poisoning primitive.

### 3.3 Negative caching must be bounded

Caching `LABEL_INVALID` and `TLD_UNKNOWN` "for process lifetime" is a specification defect: the
entries are attacker-fillable, unbounded and never evicted, so one hostile page can exhaust
memory by requesting an endless stream of invalid names.

Negative cache entries MUST be held in a bounded, evicting structure with a finite TTL and a
maximum of **4,096 entries**, evicted least-recently-used. Syntactically invalid names SHOULD NOT
be cached at all — the grammar check is cheaper than the cache lookup, which is what makes the
attacker-fillable half of this surface close to empty in practice.

An earlier revision required "a documented maximum entry count" and documented none, here or
anywhere else in the corpus. A `MUST` with no value is not a weaker requirement than one with a
number; it is an untestable one, and Article 44.6's standard is that a competent implementer can
build from the specifications alone.

### 3.4 Resource limits

An unbounded resource is a denial-of-service primitive available to any page, so each of these is
a concrete number rather than an instruction to pick one:

| Limit | Value | Why this number |
| --- | --- | --- |
| Concurrent requests per origin | **6** | What browsers already impose on HTTP/1.1, so it constrains the proxy without constraining the page beyond what the engine does anyway |
| In-flight requests per page | **32** | Above any ordinary page's simultaneous subresource fan-out, below the point where one tab can starve another |
| In-flight requests per process | **256** | A ceiling on the whole resolver, so many tabs cannot compose into the exhaustion one tab is prevented from causing |
| Record and negative caches, combined | **64 MiB** | Both hold small entries and neither is content; the content cache has its own 2 GiB LRU in [RESOLUTION.md](RESOLUTION.md) |

These are engineering judgements, not derivations, and are stated as such: each is defensible and
none is the only defensible value. Changing one is a VWIP, because a resolver that quietly raises
a limit is a resolver whose denial-of-service surface differs from the one this document
describes.

The previous revision of this section required all four "specified with concrete numbers" and
specified none of them. That is the more common failure of the two: a document can require a
number of its implementers in language strong enough to sound like it has supplied one.

## 4. Cross-name subresources

**There is no cross-name subresource allowance, and this document does not offer one.**

An earlier revision specified the behaviour of an `allow_cross_name_subresources` setting —
off by default, widening only `img-src`, `font-src` and `media-src`. It is withdrawn.
[CONTENT-SECURITY.md](CONTENT-SECURITY.md) 2.3 closes the list of relaxations, and this is not on
it; the same document's section 1 names "a cross-name subresource allowance" **first** among the
widenings that "instantly revalue every unfixable fingerprinting vector from harmless to
critical". Specifying how a forbidden setting would behave is how a forbidden setting acquires an
implementation.

It escaped notice for a structural reason worth recording: `scripts/check-headers.py` compares
**fenced canonical blocks**, and this section quoted none, so the one gate that holds the profile
together never saw it. The rule it violated is the one `PUBLISHING.md` violated with inline
hashes — a relaxation not in 2.3's table does not exist, whichever document proposes it — and
both were found the same week by reading the two documents together rather than either alone.

The reasoning is kept, because it is the argument any future proposal has to answer. Widening
`script-src` across names creates a cross-name supply chain: one compromised name executes code in
the context of every name that references it — the precise failure mode that has made third-party
scripts the most reliable attack path on the clearnet. A proposal that widened only `img-src`,
`font-src` and `media-src` would still have to answer the fingerprinting argument in
CONTENT-SECURITY.md section 1, which is about the *existence* of a cross-name fetch rather than
about which directive permits it.

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
3. A request to the proxy bearing a non-VayuWeb `Host` is rejected before routing in the default
   `vayu-only` mode, and in Private Mode under every mode setting.
3.a Under `passthrough`, the same request is forwarded outward and a loopback, link-local,
   multicast or RFC 1918 destination is still refused. Both halves, because a test that only
   asserted the refusal would fail every resolver implementing browser-integration option 2, and
   one that only asserted the forwarding would pass an open relay.
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
