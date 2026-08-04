# VayuWeb Architecture

VayuWeb is a peer-to-peer naming and hosting protocol: a parallel web with no ICANN, no
certificate authority, no hosting company and no privileged operator. This document describes
the component-level design — what the pieces are, how they talk, what each is allowed to
trust, and what each is forbidden to do.

Nothing described here is running. There is no network, no registered name and no release.
Every "SHALL" below is an obligation on an implementation that does not yet exist.

## System Shape

VayuWeb is four layers and two surfaces.

The layers are identity, registry, discovery and content, strictly ordered: identity signs
registry entries, the registry replicates over discovery, and registry entries point into
content. No layer may reach back up. The content layer never authenticates anything and the
discovery layer never decides what is true. The surfaces are the resolver proxy and the
desktop client; everything a user or a browser touches goes through one of those two.

## Layer 1 — Identity

An identity is an Ed25519 keypair. There are no accounts, no usernames and no registration
authority. The public key IS the owner; possession of the secret key IS the proof of
ownership.

Every state-changing operation — register, update, transfer, release — is a signed message
appended to the registry log. The signature covers the canonical serialisation of the record
including `prevHash` and `seq`, so a signature cannot be lifted from one record and replayed
against another.

Key rotation is a transfer to a new key by the current key. There is no recovery path: a lost
secret key means the name expires at `notAfter` and returns to the pool through the normal
grace and quarantine sequence. VayuWeb trades recoverability for the absence of an authority that
could seize a name. Social recovery (threshold co-signers named in the record) is a candidate
for a future VWIP and is NOT part of the launch design.

## Layer 2 — Registry

The registry is an append-only, signed Hypercore log with a Hyperbee B-tree index built over
it. The log is the truth; the index is a derived, rebuildable convenience.

Each peer replicates the log in full and verifies it independently; a peer that has not
verified a record MUST NOT answer queries about it. Full replication is what makes "no
privileged writer" possible and is also the design's main scaling constraint. The normative
record format is in [docs/spec/REGISTRY.md](spec/REGISTRY.md).

A record carries `name`, `tld`, `ownerKey`, `seq`, `notBefore`, `notAfter`, `records`,
`powProof`, `prevHash` and `sig`. Implementations SHALL cap a record at 4 KiB and the
`records` set at 32 entries, because at 4 KiB one million names averaging four updates each is
roughly 16 GiB of log — still within reach of a volunteer peer. Exceeding that budget requires
a VWIP, not a silent relaxation.

The per-name chain is enforced by `seq` and `prevHash`: `seq` MUST be exactly one greater than
the previous accepted record for that name, and `prevHash` MUST equal that record's hash. The
history of a name is therefore a verifiable chain inside the global log, so no update can be
skipped or reordered unnoticed.

## Layer 3 — Discovery

Peers find each other with Hyperswarm over HyperDHT. The registry log's discovery key is the
swarm topic; joining it is how a peer announces that it carries the registry.

Discovery is deliberately dumb: it answers "who else is here" and nothing more. A peer
returned by the DHT has zero authority, since everything it sends is verified before it is
believed. A hostile DHT can waste a peer's time and observe its interest in VayuWeb, but cannot
make it accept a false record. See [docs/THREAT-MODEL.md](THREAT-MODEL.md).

## Layer 4 — Content

Sites are stored in IPFS via Helia and addressed by CID. Mutable sites use IPNS: the registry
record's `ipns` entry names the pointer, and the `cid` entry optionally pins an exact
immutable snapshot.

Pinning is the owner's job. The owner's node pins the site, and any volunteer MAY pin it too.
There is no obligatory pinning service, no built-in payment and no default provider. The
consequence, stated plainly: if the owner's node is offline and nobody else pinned the
content, the name resolves correctly and the site does not load. VayuWeb guarantees name
resolution, not availability. See [docs/spec/HOSTING.md](spec/HOSTING.md).

## Surface 1 — Resolver Proxy

A small local daemon that any browser can be pointed at. It listens on loopback only:
`127.0.0.1:7654` for the HTTP proxy and `127.0.0.1:7653` for the control API. Two ports, not
one, so that the control API can be firewalled or disabled without disabling resolution.

The proxy holds the verified registry index in memory, so a `.vayu` lookup is a local B-tree
read — no network round trip and no query leaves the machine. An optional browser extension
may register the VayuWeb TLDs directly so users need not set a system proxy; the extension is a
convenience, never a separate source of truth.

## Surface 2 — Desktop Client

A Tauri 2.x application for people who will never run a daemon by hand. It supervises the
resolver, holds the key handling UI, runs the proof-of-work for registration and renewal, and
publishes a folder as a site. It is a front end over the libraries the CLI uses and has no
private capability.

## Repository Layout

| Path | Contents |
| --- | --- |
| `registry/` | Record schema, canonical serialisation, signature and chain verification, Hypercore/Hyperbee wiring, Hyperswarm replication, proof-of-work verification. |
| `proxy/` | Local resolver: HTTP proxy on 7654, control API on 7653, Helia fetch, response caching, browser extension source. |
| `client/` | Tauri 2.x desktop application: UI, keychain-backed key management, proof-of-work worker, site publishing. |
| `scripts/` | Build, reproducible-release and test-network scripts. No production logic. |
| `docs/` | This file and its siblings, including `docs/spec/` for the normative specifications. |
| `constitution/` | The Constitution and the VWIP process documents. Governance text, not code. |

Code in `registry/`, `proxy/` and `client/` is MIT licensed. The Constitution and specifications are
dedicated to the public domain.

## Data Flow — Register a Name

1. The client checks the label against the grammar in [docs/spec/NAMES.md](spec/NAMES.md) and
   confirms the TLD is one of the eleven launch TLDs.
2. The client queries the local verified index for `name.tld`. Absent, or expired past grace
   and quarantine, means the name is a free candidate.
3. The client generates or loads an Ed25519 keypair; the secret key goes to the OS keychain.
4. The client computes the Argon2id proof-of-work at the difficulty derived from the label
   length and that TLD's registration rate over the trailing 30 days.
5. The client assembles the record with `seq = 0`, `prevHash` set to the all-zero hash,
   `notBefore = now`, `notAfter = notBefore + 31536000`, and signs it.
6. The record is appended to the local log and replicated to connected peers.
7. Each receiving peer verifies independently and either accepts or drops. There is no
   acknowledgement channel back to the sender.
8. A registration is settled once the record is in the peer's own verified log. Swarm-wide
   convergence is expected in seconds and is NOT guaranteed by any deadline.

```text
client ──sign──> record{seq=0, pow, sig}
   │
   ├─ append ──> local Hypercore log ──> Hyperbee index
   │
   └─ replicate ──> Hyperswarm ──> peer ──> verify(grammar, sig, pow, chain, freshness)
                                             │
                                     accept ─┴─ drop
```

Concurrent first registrations resolve by first-valid-signature-wins: peers converge on the
earliest valid record they observed, tie-broken by the lexicographically smaller record hash
so that all peers reach the same answer without a coordinator.

## Data Flow — Publish a Site

1. The user selects a directory in the client, or points the CLI at one.
2. Helia imports the directory and produces a root CID.
3. The client pins the CID locally and serves it to the swarm.
4. The client publishes an IPNS record for the site key pointing at that CID.
5. The client builds a registry update: `seq` incremented by one, `prevHash` set to the hash
   of the current record, `records` carrying the `ipns` name and optionally the pinned `cid`.
6. The update is signed, appended and replicated exactly as in registration. A renewal has the
   same shape with `notAfter` extended and a fresh proof-of-work.

```text
site dir ──Helia import──> CID ──pin──> local blockstore
                            │
                            └──IPNS publish──> /ipns/<site key>
                                                     │
owner key ──sign──> record{seq=n+1, records:{ipns, cid}} ──> log ──> peers
```

## Data Flow — Resolve a Name

1. The browser sends `GET http://example.vayu/` to the proxy on 127.0.0.1:7654.
2. The proxy splits the host into label and TLD and rejects anything failing the grammar
   before any lookup.
3. The proxy reads `name.tld` from the local verified Hyperbee index. No network request is
   made for this step.
4. If absent, expired, or inside grace or quarantine, the proxy returns a VayuWeb status page
   with a 404 or 410. It MUST NOT fall back to DNS or any clearnet resolver.
5. The proxy resolves the `ipns` entry to a CID and fetches through Helia. An `alias` entry is
   followed to another VayuWeb name, at most three hops, to bound loops.
6. Content is streamed back. The proxy caches the IPNS-to-CID mapping for 300 seconds — cheap
   page loads, updates visible within five minutes — and caches immutable CID content by
   content hash with no expiry.

```text
browser ──> 127.0.0.1:7654 ──> grammar check ──> local Hyperbee (no network)
                                                        │
                                          record ───────┤
                                                        │
                                             ipns ──> Helia ──> CID ──> bytes ──> browser
```

Status pages and the control API surface are normative in
[docs/spec/RESOLUTION.md](spec/RESOLUTION.md).

## Trust Boundaries

Before accepting a record, a peer MUST verify all of the following and MUST drop the record if
any check fails: the label matches the grammar and is NFC-normalised lowercase ASCII; the TLD
is recognised; `sig` verifies against `ownerKey` over the canonical serialisation; `seq` is
exactly one greater than the previous accepted record for that name; `prevHash` matches that
record's hash; for `seq = 0` the name is free; `notAfter` minus `notBefore` equals 31536000;
`notBefore` is not more than 300 seconds ahead of local time, a tolerance sized to absorb
ordinary clock drift without allowing meaningful post-dating; `powProof` meets the required
difficulty; the record is within the size and entry caps. A peer trusts no other peer's
verdict, ever. There is no "trusted peer" flag and adding one would be a Constitution
violation.

The proxy trusts exactly one thing: its own verified local index. It does not trust the
browser, the DHT, or the peer it fetched content from. Fetched content is validated against
the CID before being served, so a lying content peer is detected rather than believed.

The browser trusts the proxy on loopback, which is the weakest link in the chain: anything
with local user privileges can bind or hijack that port. VayuWeb does not solve local compromise
and does not pretend to. The control API on 7653 SHALL require a token generated at first run
and stored with user-only permissions, which raises the bar without eliminating the risk.

## State on Disk

A node keeps four things: the Hypercore log and its Hyperbee index, the Helia blockstore for
pinned content, a peer cache, and configuration. All four are replicated, public, or trivially
rebuildable, and none is sensitive.

The Ed25519 secret key is the exception. It SHALL live in the OS keychain — Keychain on macOS,
DPAPI-backed credential storage on Windows, Secret Service on Linux — and MUST NOT appear in
the replicated log, in a plaintext config file, in logs, or in any file the client backs up
automatically. Where no Secret Service is available, the fallback SHALL be a file encrypted
with a key derived by Argon2id from a user passphrase at 256 MiB of memory, three iterations,
one lane, so that an offline dictionary attack on a stolen file is expensive rather than
convenient.

Query logs are not written by default. If a user turns on debug logging, the resolver SHALL
say so in its startup output, because a silent query log is a deanonymisation tool.

## Bootstrap and Cold Start

A brand-new node knows nothing and must reach the DHT somehow. That first contact is the most
centralising point in the design and is treated as such.

A fresh node joins HyperDHT using its bootstrap list, joins the registry topic, replicates the
log, verifies it, and builds its index. From then on it uses its own peer cache — up to 512
addresses, refreshed every 15 minutes, a few hundred kilobytes that comfortably survives large
parts of the network going away — and consults bootstrap nodes only when the cache fails
entirely.

The design keeps bootstrap plural and swappable by rule. A release SHALL ship at least six
bootstrap entries operated by at least three mutually independent parties, as plain
configuration a user can replace wholesale without rebuilding. A node SHALL prefer its cache
and SHALL NOT contact a bootstrap node when the cache yields a working peer. Two nodes on one
LAN SHOULD find each other by local discovery and skip bootstrap entirely.

The limitation is real: a user who accepts the shipped list on first run trusts those
operators for reachability at that moment. They cannot forge records, but they can observe
that a new node appeared and can refuse to introduce it. VayuWeb reduces this to a first-run
window and makes it replaceable; it does not eliminate it.

## Versioning and Wire Compatibility

The swarm topic derives from a protocol string carrying a major version, `vayuweb/1`. A breaking
change means a new topic and a new network, deliberately, so incompatible peers never
half-talk to each other.

Records carry a `version` field. Peers MUST accept records at their own major version, MUST
ignore unknown fields rather than rejecting the record, and MUST NOT re-serialise a record
they did not author — canonical bytes are preserved verbatim so signatures stay verifiable
across implementations with different field sets. Unknown `records` entry types are stored and
replicated but not acted upon. The major version changes only by a ratified VWIP, per
[docs/GOVERNANCE.md](GOVERNANCE.md); no implementation, including the reference one, may ship
a wire change ahead of ratification.

## What Each Component Must NOT Do

The resolver MUST NOT fetch from the clearnet on a VayuWeb lookup. Not as a fallback, not for a
"did you mean", not for telemetry. A failed VayuWeb resolution is an error page; leaking the name
to DNS would hand every lookup to the infrastructure VayuWeb exists to route around. It MUST NOT
log queries by default and MUST NOT contact any author-operated service.

The client MUST NOT embed a default pinning service. Not a preferred one, not a free tier, not
a partner: the moment a default exists, most sites depend on one company and the hosting layer
has quietly recentralised. The client MAY let a user add an endpoint they chose themselves,
with no suggestion shipped in the binary. It MUST NOT export the secret key in plaintext; an
export SHALL be passphrase-encrypted or SHALL NOT exist.

The registry MUST NOT have a privileged writer: no admin key, no seizure path, no emergency
override, no allowlist of blessed peers. It answers exactly two questions — is the signature
valid, and is the name free — and MUST NOT adjudicate trademark, impersonation or ownership
disputes. Any patch introducing a special-cased key violates
[constitution/CONSTITUTION.md](../constitution/CONSTITUTION.md) regardless of intent.

## Known Gaps

Full replication bounds the design at roughly a million names on ordinary hardware; beyond
that, light-client proofs are needed and no scheme is specified. IDN support is deferred:
launch is ASCII-only, and a homograph policy MUST arrive as a VWIP before any non-ASCII label
is accepted. Availability is not guaranteed, only resolution.

## Status

Status: Draft — not yet implemented. This document describes the pre-implementation design and
will be revised as the `docs/spec/` documents are ratified.

## See also

- [docs/spec/REGISTRY.md](spec/REGISTRY.md)
- [docs/spec/RESOLUTION.md](spec/RESOLUTION.md)
- [docs/THREAT-MODEL.md](THREAT-MODEL.md)
- [constitution/CONSTITUTION.md](../constitution/CONSTITUTION.md)
