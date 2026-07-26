<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/webx-logo-dark-512.png">
    <source media="(prefers-color-scheme: light)" srcset="assets/webx-logo-512.png">
    <img src="assets/webx-logo-512.png" alt="WebX" width="300">
  </picture>
</p>

<h1 align="center">WebX</h1>

<p align="center"><strong>Decentralised. Parallel. Web.</strong></p>

<p align="center">
  A peer-to-peer naming and hosting protocol —<br>
  a parallel web with no registrar, no certificate authority, and no landlord.
</p>

---

## Coming soon

**WebX is not built yet, and this repository does not pretend otherwise.**

What exists today is the part that has to come first: the **Constitution**, the
**specifications**, and the **threat model**. There is no binary to download, no network to
join, and no name to register. Everything in this repository describes a system that is being
designed in the open, before a line of it is written.

That order is deliberate. A naming system inherits whatever politics it was built with, and
retrofitting governance onto shipped infrastructure has never once worked. So the rules come
first, in public, where they can be attacked while changing them is still cheap.

| | |
|---|---|
| **Status** | Specification and charter — pre-implementation |
| **Code** | None yet. The `registry/`, `proxy/` and `client/` directories are placeholders |
| **Charter** | [The WebX Constitution](constitution/CONSTITUTION.md) — ratified, in force |
| **Licence** | MIT for code · public domain for the Constitution text |
| **Home** | Long-term development moves to **Radicle**; GitHub is a temporary public mirror |

If you are here to read one thing, read the [Constitution](constitution/CONSTITUTION.md).
If you are here to break something, read the [Threat Model](docs/THREAT-MODEL.md) and tell us
what we missed.

---

## Why

Two chokepoints decide whether anything on the web stays reachable: **who resolves your name**
and **who serves your bytes**. Both have consolidated into a handful of companies operating
under a handful of jurisdictions. A registrar can suspend a domain. A resolver can refuse to
answer. A certificate authority can revoke. A host can deplatform. A content network can
decide your traffic is not worth the trouble. Any one of them ends a site; in practice the
same few organisations hold all five levers at once.

WebX answers by removing the levers rather than negotiating with whoever holds them. Names live
in a signed, append-only log that every participant replicates and can verify independently.
Content lives on IPFS, pinned by the people who care whether it survives. Resolution happens
on your own machine. There is no root zone, no privileged writer, no treasury, and no token.

WebX is not a replacement for the existing web and does not try to be. It is a *parallel* one —
running alongside, reachable from the same browser, owned by nobody.

---

## Core design

- **An elastic namespace — 409 extensions at launch, and no ceiling.** Creating a top-level
  domain on the clearnet cost USD 185,000 in the 2012 application round, plus roughly USD 25,000
  a year, in a window that opens about once a decade. Here it costs a ratified proposal and some
  CPU, so the namespace can be as broad as the people using it want. See the
  [catalogue](docs/spec/NAMESPACE-CATALOGUE.md) — from `.folio` and `.zine` to `.dissent`,
  `.allodial`, `.ghazal` and `.chai`. Every extension is equal; there is no premium tier and
  nothing is sold.

- **Peer-to-peer registry.** A Hypercore append-only log with a Hyperbee index over it. Every
  record is signed; every peer holds the whole history and verifies it without trusting anyone.

- **IPFS hosting.** Sites are content-addressed and published through IPNS, pinned by their
  owner and by anyone who volunteers. No mandatory pinning service.

- **Its own scheme.** WebX names are addressed `webx://example.webx/`, never `http://` or
  `https://`. Those schemes carry a promise about certificate authorities that WebX does not
  make; WebX makes a different and stronger one — content verified byte for byte against its
  hash. A security indicator that lies is worse than none.

- **Local resolution.** A small proxy on loopback makes WebX names work in any browser. The
  optional extension is a convenience, never a requirement. A WebX lookup never falls through to
  clearnet DNS, and queries are never logged.

- **Secure by subtraction, not by guarding.** There is no server, so the categories that account
  for most website compromises simply do not exist: no SQL injection, no remote code execution at
  the origin, no dependency treadmill, no stolen hosting credentials, no certificate mis-issuance.
  What remains — the reader's browser — is held under a deny-by-default profile
  (`default-src 'none'`, no inline anything, no reporting endpoint), with the privileged control
  API on a Unix socket a browser cannot address.

- **No money, anywhere.** A name costs seconds of CPU. Hosting costs your own disk. There is no
  token, no treasury and no protocol fee, and the Constitution entrenches all three prohibitions
  against amendment — so unlike a pricing promise, this one cannot be revised by whoever is
  running things in ten years.

- **Nobody learns what you looked up.** Resolution happens against your local replica of the
  registry, so a lookup never leaves your machine. A clearnet DNS query tells a resolver operator
  every name you visit; a WebX lookup tells nobody anything. It is the cheapest privacy in the
  design, because it comes from not sending the query at all.

- **Cryptographic ownership.** Ed25519 keypairs. Registration, update, transfer and release are
  signed operations. The registry answers exactly two questions — *is this signature valid*
  and *is this name free* — and refuses to be a trademark court.

- **Memory-hard proof-of-work.** Registration and renewal cost seconds of CPU for one name and
  grow superlinearly for ten thousand. It prices squatting without a payment rail, a token, or
  a treasury that could be captured.

- **Community governance.** New TLDs and protocol changes move through the
  [WXIP process](docs/spec/WXIP-0000.md) and are ratified by peers under the
  [Constitution](constitution/CONSTITUTION.md).

---

## Architecture

| Layer | Technology | Purpose |
|---|---|---|
| Identity | Ed25519 | Ownership and signatures |
| Registry | Hypercore + Hyperbee | Signed, append-only, replicated name records |
| Discovery | Hyperswarm / HyperDHT | Finding other peers |
| Content | IPFS (Helia) + IPNS | Immutable storage and mutable pointers |
| Resolution | Local proxy (loopback) | Makes WebX names work in an ordinary browser |
| Client | Tauri 2.x | Desktop application for people who do not use terminals |
| Governance | Constitution + WXIP | How the rules change, and what can never change |

Full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Repository layout

```text
WebX/
├── constitution/       # The WebX Constitution — the founding charter
├── docs/               # Specifications, threat model, governance, roadmap
│   └── spec/           # Normative protocol specifications and WXIP-0000
├── registry/           # Hypercore + Hyperbee registry        (not yet implemented)
├── proxy/              # Local resolution proxy                (not yet implemented)
├── client/             # Tauri desktop application             (not yet implemented)
├── scripts/            # Build, release and asset tooling
└── assets/             # Brand artwork
```

---

## Documentation

| Document | What it covers |
|---|---|
| [**Position**](docs/POSITION.md) | **What WebX is and is not** — the parallel-web frame, and the four commitments: secure, future-proof, cheap, easy |
| [Constitution](constitution/CONSTITUTION.md) | The founding charter: rights, governance, entrenchment, the right to fork |
| [Whitepaper](docs/WHITEPAPER.md) | The problem, the design, and what WebX deliberately is not |
| [Architecture](docs/ARCHITECTURE.md) | Components, data flow, trust boundaries |
| [Threat Model](docs/THREAT-MODEL.md) | Adversaries, attacks, mitigations, residual risk |
| [Governance](docs/GOVERNANCE.md) | How decisions are actually made |
| [Longevity review](docs/LONGEVITY.md) | What breaks before 2126, and what was done about it |
| [Roadmap](docs/ROADMAP.md) | Phases, acceptance tests, and what would make us rethink |
| [FAQ](docs/FAQ.md) | Short answers, including the unwelcome ones |
| [Glossary](docs/GLOSSARY.md) | Every term used across the specifications |

**Specifications:**
[Registry](docs/spec/REGISTRY.md) ·
[Names & TLDs](docs/spec/NAMES.md) ·
[`webx://` scheme](docs/spec/URI-SCHEME.md) ·
[Resolution](docs/spec/RESOLUTION.md) ·
[Hosting](docs/spec/HOSTING.md) ·
[Proof-of-Work](docs/spec/PROOF-OF-WORK.md) ·
[Publishing](docs/spec/PUBLISHING.md) ·
[Cost model](docs/spec/COST.md) ·
[Namespace](docs/spec/NAMESPACE.md) ·
[Attestation](docs/spec/ATTESTATION.md) ·
[Catalogue](docs/spec/NAMESPACE-CATALOGUE.md) ·
[Services & the Vayu suite](docs/SERVICES.md)

**Security and privacy:**
[Content security](docs/spec/CONTENT-SECURITY.md) ·
[Privacy & zero-trail](docs/spec/PRIVACY.md) ·
[Local attack surface](docs/spec/LOCAL-SURFACE.md) ·
[Crypto agility & post-quantum](docs/spec/CRYPTO-AGILITY.md)

**Process:**
[WXIP-0000](docs/spec/WXIP-0000.md) ·
[WXIP-0001](docs/spec/WXIP-0001.md)

---

## What WebX does not promise

A charter that overclaims dies the first time reality tests it, so these are stated up front
and repeated in the specifications:

- **WebX is a parallel web, not a hidden one.** It does not make you anonymous, and that is a
  design decision rather than a shortfall — see [POSITION.md](docs/POSITION.md). WebX removes the
  chokepoints that let someone switch your site off; it does not hide your traffic from your
  network provider. An optional anonymity layer is deferred until there is a population large
  enough for an anonymity set to mean anything. Use Tor when hiding is what you need.
- **WebX does not guarantee availability.** Content lives while at least one peer pins it. If
  everybody stops pinning, it is gone.
- **WebX cannot forget.** The registry is an append-only log. You can withdraw a pointer and
  unpin your copy; you cannot compel other peers to discard bytes they already hold.
- **WebX does not stop a state from blocking traffic** at the network layer, seizing a device,
  or compelling a person.
- **A lost key is a lost name.** There is no support desk, because a support desk that can
  restore your name is a support desk that can take it.

---

## Development principles

1. No single point of failure.
2. No central authority can censor names or content.
3. Ordinary people must be able to use it without technical knowledge.
4. Code and governance stay open and independently verifiable.
5. Prefer lightweight, battle-tested peer-to-peer technology over novelty.
6. Say what the system cannot do, as loudly as what it can.

---

## Contributing

At this stage, **specification review is worth more than code**. Reading the Constitution
adversarially and finding the clause that a bad actor could drive a truck through is the single
most valuable contribution anyone can make right now.

Start with [CONTRIBUTING.md](CONTRIBUTING.md), then the
[Constitution](constitution/CONSTITUTION.md) and [WXIP-0000](docs/spec/WXIP-0000.md).
Security issues go through [SECURITY.md](SECURITY.md), not the public issue tracker.

---

## Licence

Code is [MIT](LICENSE).

The Constitution text is dedicated to the public domain, deliberately: any fork must be able to
carry the charter with it. A licence on a constitution is a leash on a fork, and the right to
fork is the last check that survives when every other one has failed.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/webx-mark-dark-256.png">
    <source media="(prefers-color-scheme: light)" srcset="assets/webx-mark-256.png">
    <img src="assets/webx-mark-256.png" alt="" width="72">
  </picture>
</p>

<p align="center"><em>WebX is the peer-owned root of the free internet.</em></p>
