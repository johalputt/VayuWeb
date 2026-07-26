# The `webx://` URI Scheme

WebX names are addressed with their own scheme, not with `http://` or `https://`.

```text
webx://example.webx/about/
webx://ankush.vayu/
webx://archive.libre/2026/notes.html#top
```

This document specifies the syntax, the origin model, how the scheme is handled, its deliberate
security properties, and the compatibility mapping for browsers that do not know it.

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

**Status:** Draft — not yet implemented. Proposed formally by [WXIP-0001](WXIP-0001.md).

## 1. Why a scheme of its own

`https://` carries a specific promise: a certificate authority vouched for the identity of the
host, and the transport is encrypted end to end. WebX makes a **different** promise — content is
addressed by hash and verified byte by byte against a signed registry record, with no certificate
authority anywhere. Neither promise implies the other.

Reusing `https://` would misrepresent both. A reader seeing `https://` reasonably infers a CA
chain that does not exist. A reader seeing `http://` reasonably infers unauthenticated plaintext,
when in fact the content is cryptographically verified more strongly than TLS verifies most
sites. Both readings are wrong, and a security indicator that lies is worse than none.

`webx://` says what is true: this name resolved through the WebX registry, and these bytes matched
their CID.

The scheme also does structural work. It makes WebX links unambiguous in clearnet pages, it lets a
browser or operating system route them without guessing, and it prevents a WebX name from ever
being confused with a DNS name in a log, a bookmark, or a person's memory.

## 2. Syntax

```text
webx-URI = "webx://" label "." tld [ "/" path ] [ "?" query ] [ "#" fragment ]

label    = 1*63( %x61-7A / %x30-39 / "-" )   ; a-z 0-9 -
tld      = 2*12( %x61-7A )                   ; a-z
```

2.1 The authority is exactly `label "." tld`. It MUST match the grammar in
[NAMES.md](NAMES.md): 1–63 characters, no leading or trailing `-`, lowercase ASCII only.

2.2 A `webx://` URI MUST NOT contain a **port**. There is no port to connect to; resolution is not
a socket operation. A URI carrying one MUST be rejected, not ignored.

2.3 A `webx://` URI MUST NOT contain **userinfo** (`user:password@`). This is not a stylistic
rule: `webx://trusted.webx@evil.webx/` is the oldest phishing construction on the web, and the
scheme forbids it at the parser rather than mitigating it in a UI.

2.4 The authority MUST NOT be an IP literal, `localhost`, or anything other than a WebX name.

2.5 Uppercase in the authority MUST be rejected rather than case-folded. Silent normalisation
means two different strings display differently and resolve identically, which is a confusion
surface; an error is honest. Percent-encoding in the authority MUST likewise be rejected.

2.6 Non-ASCII and punycode authorities MUST be rejected in v1. Internationalised labels and their
homograph defences are deferred to a future WXIP, and until that WXIP exists the safe behaviour is
refusal, not a best guess. See [NAMES.md](NAMES.md).

2.7 The path, query and fragment follow RFC 3986. An empty path is equivalent to `/`.

2.8 There is no `webxs://`. There is exactly one scheme, because a second one would invite the
question of which is safer, and the answer would have to be "neither, they are the same".

## 3. Origin model

3.1 The origin of a `webx://` URI is the tuple `("webx", label "." tld)`. There is no port
component.

3.2 Every name is a separate origin. `webx://a.webx` and `webx://b.webx` share nothing: no
storage, no cookies, no permissions, no scripting access. `webx://a.webx` and `webx://a.vayu` are
also distinct — the TLD is part of the authority, and there is no relationship between names that
merely share a label.

3.3 There is no concept of a subdomain in v1, therefore no cross-subdomain relaxation, no
document.domain, and no cookie domain scoping to get wrong.

3.4 A `webx://` document MUST NOT be able to script, frame, or read any `http://` or `https://`
document, and the reverse MUST also hold.

## 4. Security properties

### 4.1 `webx://` is deliberately NOT a trustworthy scheme

A handler implementation MUST NOT register `webx://` as a *potentially trustworthy* or *secure
context* scheme.

This looks like a downgrade and is the opposite. Marking the scheme trustworthy would, in one
step, re-enable:

- **Service worker registration** — the largest persistence and background-exfiltration surface in
  the platform, currently unavailable for free.
- `navigator.mediaDevices`, `queryLocalFonts`, `getScreenDetails`, WebUSB, WebHID, Web Serial,
  Web Bluetooth, geolocation, storage-access — every one of them secure-context gated today.

WebX gains nothing in return. The headers that require a secure context — `Clear-Site-Data`,
COOP, COEP, `Origin-Agent-Cluster` — are either unnecessary here (everything is same-origin
already) or actively unwanted (COEP's cross-origin isolation would grant `SharedArrayBuffer` and
high-resolution timers, sharpening timing attacks). Storage clearing is achieved instead by an
ephemeral profile directory, which works regardless of context. See
[CONTENT-SECURITY.md](CONTENT-SECURITY.md) section 1 and [PRIVACY.md](PRIVACY.md).

The trade is therefore: give up four headers that buy nothing, keep an entire API surface closed.
That is not a compromise, it is the better side of the deal — and it is written down here because
it will look like an oversight to a future maintainer, who will be tempted to "fix" it.

### 4.2 Opaque origins in the client webview

Where the handler is the WebX client's own webview, the implementation SHOULD go further and give
each document an **opaque origin** with all persistent storage disabled, so that
`localStorage`, `IndexedDB` and Cache Storage are unavailable rather than merely partitioned.
Private Mode MUST do this.

### 4.3 No transport promise

The scheme asserts registry resolution and content verification. It asserts **nothing** about
who can observe the connection. `webx://` is not an anonymity indicator, and a client MUST NOT
present it as one — that is what Private Mode is for, and it is signalled separately.

### 4.4 Display rules

A client displaying a `webx://` URI MUST show the full authority without truncation or elision of
the TLD, and MUST NOT render it in a way that mimics a clearnet security indicator — no padlock,
no "Secure" label. The correct indicator answers a different question: *was this content verified
against its CID?* Clients SHOULD show that, and MUST show it as distinct from anything a browser
displays for TLS.

## 5. Handling

Three paths, in descending order of strength.

### 5.1 Native, in the WebX client (preferred)

The desktop client registers `webx://` as a custom protocol handled in-process by its own webview.
This is the strongest configuration and the only one in which every control in
[CONTENT-SECURITY.md](CONTENT-SECURITY.md) is enforceable: the client controls scheme
registration, WebRTC availability, storage, window size, timezone and the absence of extensions.

### 5.2 Third-party browser with the WebX extension

The extension intercepts `webx://` navigations and routes them to the local resolver. Weaker than
5.1: the browser's own telemetry, omnibox behaviour, WebRTC stack and other extensions are outside
WebX's control, and the client MUST say so plainly rather than imply otherwise.

### 5.3 Compatibility mapping, no extension

For a browser that knows neither the scheme nor the extension, the resolver exposes each name over
the loopback proxy:

```text
webx://example.webx/about/   ->   http://example.webx/about/   (via the proxy)
```

The mapping is mechanical: the authority and path are preserved exactly, and only the scheme
changes. This exists so that WebX is usable without installing anything, which
Constitution Article 4 requires — a system that needs a specific client is a system with a
chokepoint.

It is explicitly the **weakest** configuration, and clients MUST label it as compatibility mode.
The `webx://` form remains canonical: links, documentation, sharing and display all use it, and
the `http://` form is an implementation detail of a browser that cannot do better.

### 5.4 Operating-system registration

A client MAY register as the OS handler for `webx://`. If it does, it MUST NOT register handlers
for any other scheme, and MUST NOT alter the system's handling of `http://` or `https://`.

## 6. Links from the clearnet

A clearnet page may link to `webx://example.webx/`. For a reader without a handler the link
simply fails, which is correct behaviour and not something to work around: a fallback that
silently redirects to a clearnet mirror would defeat the purpose of the link.

Publishers wanting a graceful path SHOULD write the link as `webx://` and place any explanatory
text beside it. A resolver MUST NOT operate a public gateway that renders WebX content on the
clearnet: such a gateway is a chokepoint, an observer of every reader who uses it, and a
single point of legal pressure — the three things this protocol exists to remove.

## 7. Conformance

1. Every URI in section 2 that MUST be rejected is rejected with a distinct error, not
   normalised, not ignored: port, userinfo, IP literal, uppercase, percent-encoded authority,
   non-ASCII, punycode.
2. `webx://a.webx` and `webx://a.vayu` do not share storage, permissions or scripting access.
3. `serviceWorker.register()` rejects on a `webx://` document.
4. A `webx://` document cannot script or read an `http://` or `https://` document, and vice versa.
5. The compatibility mapping in 5.3 preserves authority and path byte for byte.
6. No security indicator resembling a TLS padlock is shown for a `webx://` document.

## See also

- [Naming and TLD policy](NAMES.md) — the label grammar this scheme embeds
- [Resolution specification](RESOLUTION.md) — what happens after a URI is parsed
- [Content security specification](CONTENT-SECURITY.md) — the profile applied to the result
- [Privacy and zero-trail specification](PRIVACY.md) — Private Mode and the ephemeral profile
- [The WebX Constitution](../../constitution/CONSTITUTION.md) — Articles 4, 12, 14
