# VayuWeb Privacy and Zero-Trail Specification

What VayuWeb writes down, what it sends, and what can be reconstructed afterwards.

The goal of this document is stated precisely rather than as a slogan:

> **Everything within VayuWeb's control is closed completely.** Zero requests to any party other
> than the VayuWeb network. Zero logs. Zero telemetry. Not "minimised", not "configurable off by
> default" — absent, and structurally impossible to add back without amending the Constitution.
>
> **One qualification, here rather than in a footnote.** "Zero durable trail on disk" holds where
> the platform provides a memory-backed location for the ephemeral browser profile. macOS and
> Windows provide none by default, so there the profile is written and deleted rather than never
> written, and the client must say so. Section 9 explains why that is weaker; section 11 records
> it as a limit. A summary that stated the stronger property and left the weaker one to be
> discovered further down would be the exact failure Article 21 names.
>
> **Two things are outside VayuWeb's control**, and are named here rather than buried: the network
> path, which Private Mode closes by routing through an anonymising transport, and the reader's
> own device, which no software anywhere can protect once an adversary holds it unlocked.

That distinction is the whole document. Anything a naming and hosting protocol can close is
closed absolutely; anything it cannot is stated plainly, and where a composition closes it, the
composition is specified rather than left to the reader.

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

**Status:** Draft — not yet implemented. Proposed formally by [VWIP-0001](VWIP-0001.md).

## 1. The adversary

This specification is written against a **forensic adversary**: someone who obtains the reader's
machine afterwards and tries to reconstruct what was read, and a **network adversary**: someone
who observes the reader's traffic in real time.

Designing against "afterwards" is what makes this strict. A control that merely prevents live
observation still leaves a machine that answers the question under examination.

## 2. Modes

VayuWeb has exactly two modes. There is no third, no partial, and no per-feature toggle, because a
matrix of privacy settings is a matrix of ways to be wrong.

| | **Standard** | **Private** |
|---|---|---|
| Third-party requests **originated by the resolver** | None | None |
| Third-party requests **the browser may still make** | **Possible.** The browser is not contained: top-level navigation, WebRTC, omnibox lookups and extensions are outside the resolver's reach. | **Contained in the client's own webview; narrowed otherwise.** See the note below — this cell said "Contained" unconditionally, and one of the two permitted configurations does not deliver it. |
| Query logging | None | None |
| Telemetry | None | None |
| Egress transport | Direct to the VayuWeb network | Anonymising transport, mandatory |

**Why that cell is qualified.** It read "**Contained**, because full-proxy configuration and the
client's own webview are mandatory", and both halves of the reason were wrong in the same
direction.

[CONTENT-SECURITY.md](CONTENT-SECURITY.md) 5.5 requires "the client's own webview **or** a locked
browser profile with telemetry, suggestions and extensions disabled" — the webview is one of two
permitted configurations, not mandatory. And 5.1 states that WebRTC "uses raw UDP and ignores the
HTTP proxy entirely, so full-proxy mode does not contain it either", and calls it "the most
serious residual in the browser layer".

So of the two reasons this cell gave, full-proxy does not close WebRTC at all, and the webview —
which does, by compiling it out — is not mandatory. Under a locked third-party profile the
strongest available statement is that the resolver cannot enforce it and the client MUST warn
plainly, which is what 5.1 already says.

This is the same defect as the "Nothing durable" claim corrected in section 4, and it is worth
noticing that it is the same *shape*: a summary cell asserting the property of the strongest
configuration, in a document whose own section 11 exists to list what it does not claim.
| Durable local state | Registry log and content cache on disk | **Memory only where the platform provides a memory-backed location** (Linux `tmpfs`). On macOS and Windows, which provide none by default, the profile is written to a temporary directory and destroyed on exit — and the client MUST report that, because written-then-deleted is a weaker property than never-written. See section 9. |
| Behaviour if transport unavailable | n/a | **Refuses to start** |
| Browser requirement | Proxy configured for VayuWeb names | **Full-proxy configuration required** |

Standard Mode is private against everyone except an observer of the reader's own network link.
Private Mode closes that too, at the cost of speed and of a cold start on every launch.

The mode is selected by `VAYU_MODE=standard|private` and is fixed for the life of the process. It
MUST NOT be switchable at runtime: a process that has already written to disk in Standard Mode
cannot become a Private Mode process by changing a variable, and pretending otherwise would be the
worst kind of false assurance.

## 3. Egress control

### 3.1 The single choke point

Every outbound byte — registry replication, peer discovery, content fetch, and any future
subsystem — MUST pass through **one** guarded transport constructor. No component may open a
socket by any other means.

```text
egress.Dial(purpose, addr)      // the only way out
  ├─ mode == private?
  │    ├─ transport healthy?  ──no──►  REFUSE. Do not fall back. Do not queue.
  │    └─ yes ─► dial through the anonymising transport
  └─ mode == standard ─► dial directly, subject to 3.2
```

A single choke point is a design requirement, not a style preference. The recurring failure in
systems like this is not a broken guard — it is a **new call site that never called the guard**,
added a year later by someone who did not know it existed. One function, and a build-time check
that no other code in the tree constructs a socket, converts that from a vigilance problem into a
compile error.

### 3.2 Destination policy

The browsing proxy MUST refuse any destination that is not part of the VayuWeb network. This is what
closes the top-level-navigation exfiltration channel described in
[CONTENT-SECURITY.md](CONTENT-SECURITY.md) section 4.2: a page that navigates to a clearnet URL
produces a request the resolver sees, and refuses with error `1403 EGRESS_REFUSED`.

In Private Mode this is absolute. In Standard Mode a resolver MAY be configured to pass clearnet
navigation through to the system's normal handling, and if it is, it MUST tell the reader at the
moment of the first such navigation, once per site, that they are leaving VayuWeb.

### 3.3 Fail closed, always

If the anonymising transport is unavailable in Private Mode, the resolver **refuses to start**, or
if already running, **stops serving**. It MUST NOT:

- fall back to a direct connection,
- queue requests until the transport returns,
- offer the reader a "continue anyway" option,
- or degrade to Standard Mode.

A fallback is a leak that fires exactly when the protection was most needed, and a prompt is a
leak with a consent form attached. This behaviour is not configurable, and a build that makes it
configurable is non-conformant.

## 4. What VayuWeb writes to disk

Every file the resolver may create, and the rule governing it. Anything not on this list MUST NOT
be written.

| Artefact | Standard Mode | Private Mode |
|---|---|---|
| Registry log (Hypercore) | On disk. Contains public registry data only — it is the same data every peer holds, so it reveals participation, never reading. | Memory only |
| Hyperbee index | On disk, derived, rebuildable | Memory only |
| Content cache | On disk, **encrypted at rest** with a key held in the OS keychain | Memory only |
| Pin set | On disk. This is a deliberate, reader-chosen record of what they keep alive. | Memory only |
| Control-API bearer token | On disk, mode `0600` | Memory only, regenerated per run |
| Resolver configuration | On disk, mode `0600`, contains no history | Memory only |
| **Query log** | **Never written, in either mode** | **Never written** |
| **Access log** | **Never written** | **Never written** |
| **Crash dump / core file** | **Disabled by the process at startup** | **Disabled** |
| **Telemetry, analytics, update ping** | **Does not exist** | **Does not exist** |
| IPFS blockstore | On disk, in the same encrypted store as the content cache — it holds the blocks of everything fetched, so it is a reading record and MUST be treated as one | Memory only |
| IPFS datastore / pin set | On disk. Reader-chosen; see the pin-set row above. | Memory only |
| IPNS record cache | On disk, encrypted | Memory only |
| libp2p peerstore | On disk. Reveals who was talked to, not what was read. | Memory only |
| libp2p PeerID keypair | On disk, mode `0600` | **Regenerated every launch**, so sessions cannot be linked by PeerID |

Four properties of this table are normative and testable:

1. **The registry log reveals participation, not reading.** It is the public, replicated state.
   Holding it says you run VayuWeb; it does not say what you looked up.
2. **The content cache is encrypted at rest.** It is the one artefact that does record what was
   fetched, so it is never plaintext on disk in either mode.
3. **There is no logging subsystem.** Not "logging defaults to off" — no code path that writes a
   resolution to durable storage exists. A verbosity flag affects stderr for the current process
   and nothing else.
4. **Crash dumps are disabled by the process itself** at startup, not left to the operating
   system's configuration, because a core file contains keys and recently fetched content.

## 5. Browser-side traces

The browser writes its own record of what the reader did, and the resolver's headers are the only
influence it has over that.

**`Clear-Site-Data` is ignored on insecure origins, and VayuWeb origins are insecure by deliberate
design** — see [CONTENT-SECURITY.md](CONTENT-SECURITY.md) section 1 and
[URI-SCHEME.md](URI-SCHEME.md) section 4.1. Any design that reaches for it to clear storage is
reaching for nothing. This specification therefore does not use it, and an implementer who adds
it should understand they have added a no-op.

| Trace | Control |
|---|---|
| HTTP cache | `Cache-Control: no-store` on every response |
| Back/forward cache | Suppressed by `no-store` |
| Service-worker registration | **Structurally impossible.** Service workers require a secure context, and `worker-src 'none'` denies it a second time. |
| `localStorage`, `IndexedDB`, Cache API | Origin-scoped by construction. Cleared by destroying the **ephemeral profile directory**, not by any header. |
| Cookies | The resolver strips every `Set-Cookie`; VayuWeb pages cannot set one |
| `sessionStorage` | Survives reload and tab duplication within a session; gone with the profile |
| `window.name` | **Survives cross-name navigation**, because COOP is inert on an insecure origin. A live cross-name correlation channel; the client MUST clear it on navigation between names where it controls the webview. |
| Browser history and session restore | **Not controllable by any header.** |
| Download history, thumbnails, recently-used | **Not controllable.** OS and browser artefacts. |

Because no header can clear browser storage here, Private Mode achieves it structurally:

**Private Mode MUST use an ephemeral browser profile directory**, created per session and
destroyed on exit. It covers the traces a header never could — history, session restore and the
visited-link database included.

**Where the platform provides a memory-backed location, the client MUST use it.** On Linux that
is normally a `tmpfs` such as `/dev/shm`, or an `XDG_RUNTIME_DIR` mounted on one; the client MUST
verify the filesystem type rather than infer it from the path.

**Where the platform provides none, the client MUST say so.** macOS and Windows provide none by
default. In that case the client:

1. MUST create the profile in a per-session directory under the platform's temporary location,
   and destroy it on exit;
2. MUST report, in the same place it reports its mode, that **the profile was written to disk and
   deleted rather than never written**; and
3. MUST NOT describe that session as leaving nothing durable behind.

The reporting duty is the substantive part, and it exists because this document's own words
foreclose the comfortable reading: filesystem metadata "can outlive a deleted file. Private Mode
avoids creating the file at all, which is the only reliable defence." A conditional clause cannot
deliver that on a platform with no memory-backed location, so on two of the three desktop
platforms the strongest available behaviour is *written then deleted* — a weaker property, and
Article 21's duty of honest claiming requires it to be named where the claim is made rather than
left for a reader to infer.

An earlier revision said only "in a memory-backed location where the platform provides one",
imposing no fallback and no reporting duty, while section 2's mode table stated Private Mode's
durable local state as "**Memory only. Nothing durable.**" without qualification. Section 6's
`mlock` mitigation is platform-conditional in exactly the same way and already carries "MUST
attempt and MUST report when it fails"; this clause now follows the shape the document had
already found for itself.

Where the reader insists on a third-party browser, the client MUST require a private-browsing
window, MUST detect and refuse to proceed where detection is possible, and MUST warn plainly where
it is not.

## 6. Traces VayuWeb cannot remove

Named so that nobody discovers them by being arrested.

- **Swap and hibernation images.** Keys and content in memory may be written to swap by the
  operating system. Mitigated by locking sensitive pages where the platform allows it
  (`mlock`/`VirtualLock`), which the implementation MUST attempt and MUST report when it fails.
  Full-disk encryption is the real answer and is outside VayuWeb.
- **Filesystem metadata.** Access times, journal entries and free-space remnants can outlive a
  deleted file. Private Mode avoids creating the file at all, which is the only reliable defence.
- **The IPFS repository and provider records.** Announcing that you hold a CID is how content
  addressing works; it is visible to the network by design.
- **OS-level artefacts.** Recently-used lists, shell history, screenshots, accessibility caches.
- **A compromised device.** Complete and irreducible.

## 7. Memory hygiene

Secret material — Ed25519 private keys, the content-cache key, the control-API token — MUST be:

1. Allocated in locked pages where the platform permits.
2. Zeroised immediately after use, by a means the compiler cannot elide.
3. Never placed in a garbage-collected string, an environment variable, a command-line argument,
   or an error message.
4. Never written to disk except in the platform keystore, per Constitution Article 6.

An error message that includes a key is a disclosure. The implementation MUST carry a test that
formats every error type with secret material present and asserts none of it appears in the output.

## 8. The prohibition on telemetry

There is no telemetry, no analytics, no crash reporting, no update check that carries an
identifier, and no "anonymous usage statistics".

This is not a default. Constitution Article 14 makes privacy of resolution a right, and Article 9
entrenches the core against amendment. A future maintainer who wishes to add telemetry must first
amend an entrenched constitutional provision, which Article 58 does not permit. The mechanism is
therefore not "we promise not to" but "the process required to do it does not exist".

An update check, if one is ever added, MUST be off by default, MUST carry no identifier, version
string or platform, and MUST be refused entirely in Private Mode.

## 9. Panic and shred

The client SHOULD provide a single action that, in one step:

1. Stops serving and closes all connections.
2. Zeroises all in-memory secrets.
3. Deletes the content cache and its key from the keychain.
4. Destroys the ephemeral browser profile directory, which is what actually clears browser-side
   state here — `Clear-Site-Data` would be a no-op on an insecure origin (section 5).

It MUST NOT claim to delete the registry log, which is public replicated state, nor to remove
traces the operating system holds. A panic button that overstates its reach is worse than none,
because it is trusted at the moment when being wrong costs the most.

## 10. Conformance

Each of these is an executable test in the conformance suite, and each asserts on **observed
behaviour**, not on configuration:

1. **The zero-egress test.** Resolve one name and load one page under a socket monitor. Assert the
   observed connection set contains only VayuWeb network peers. Any other socket fails the build.
   This is the test Constitution Article 14 requires and Article 44.8 places alongside the wire
   vectors.
2. **The fail-closed test.** Start in Private Mode, kill the anonymising transport, assert the
   resolver stops and that no direct connection is attempted.
3. **The no-trail test.** Run a Private Mode session under a filesystem monitor.

   On a platform with a memory-backed location, assert zero durable writes outside the process's
   own memory. On a platform without one — macOS and Windows by default — assert that the only
   durable writes are inside the per-session profile directory, that the directory is destroyed
   on exit, **and that the client reported the weaker guarantee**. The second form is not a
   relaxation of the first: it tests a different claim, because it is a different claim, and a
   test that passed on both platforms by asserting the weaker property everywhere would have made
   the stronger one unmeasured.
4. **The uniform-request test.** Two installs on different machines fetch the same page; assert
   byte-identical outbound request headers.
5. **The no-secrets-in-errors test.** Format every error type with secrets present; assert none
   appear.
6. **The single-choke-point test.** A build-time check that no code outside `egress` constructs a
   socket.
7. **The no-logging test.** Grep the built binary's write paths; assert no resolution data reaches
   durable storage under any verbosity setting.

## 11. What this specification does not claim

Required by Constitution Article 21, the Duty of Honest Claiming, and repeated here because this
is the document most likely to be quoted out of context:

- It does not claim anonymity against an adversary who controls the reader's device.
- **It does not claim Private Mode leaves nothing durable on every platform.** Where the platform
  provides no memory-backed location — macOS and Windows by default — the ephemeral profile is
  written to disk and deleted rather than never written, and section 9 of this document says why
  that is weaker: filesystem metadata can outlive a deleted file. The client must report it; this
  specification will not imply otherwise by omission.
- It does not claim that Standard Mode hides VayuWeb use from the reader's network provider.
- It does not claim the registry log can be made private. It is public replicated state.
- It does not claim that content, once fetched by others, can be recalled.
- It does not claim the browser's own history can be erased by any header the resolver sends.
- It does not claim Standard Mode contains the browser, and it does not claim Private Mode fully
  contains it either. Private Mode narrows it — full-proxy configuration, and either the client's
  own webview or a locked profile. Only the webview closes WebRTC, by compiling it out;
  `CONTENT-SECURITY.md` 5.1 records that WebRTC ignores the HTTP proxy entirely, so under a
  locked third-party profile it remains the most serious residual in the browser layer and the
  client MUST say so.
- It does not claim `Cache-Control: no-store` removes every browser-side artefact. It removes the
  HTTP disk cache; the media cache, favicon database and thumbnail store are separate, and are
  closed only by the ephemeral profile.
- It does not claim uniform enforcement across engines. `webrtc 'block'` is Chromium-only and
  Trusted Types is not implemented everywhere; section 5 of
  [CONTENT-SECURITY.md](CONTENT-SECURITY.md) carries the per-directive position.

Every other control in this document is stated with its scope and its residual. Where a control
is engine-conditional or mode-conditional, that condition is named in the clause itself rather
than left to a reader to infer — which is what Constitution Article 21 requires, and what makes
the difference between a specification and a brochure.

## See also

- [Content security specification](CONTENT-SECURITY.md) — the browser-layer profile
- [Resolution specification](RESOLUTION.md) — the proxy and its privacy obligations
- [Threat model](../THREAT-MODEL.md) — T12, T13 and T14 in particular
- [The VayuWeb Constitution](../../constitution/CONSTITUTION.md) — Articles 13, 14, 19, 24
