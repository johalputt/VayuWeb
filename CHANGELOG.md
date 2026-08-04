# Changelog

All notable changes to VayuWeb are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

VayuWeb is pre-implementation. Until the first release there is no version number to assign, so
changes accumulate under `[Unreleased]`. Versioning begins with the first tagged release of
the registry core; the scheme will be set by a VWIP before then, not improvised at tag time.

## [Unreleased]

### Added

- **The VayuWeb Constitution** (`constitution/CONSTITUTION.md`) — the founding charter: the
  Preamble, an operative Bill of Rights, the registry and naming law, the governance
  machinery, the entrenchment and amendment rules, the right to fork, and the succession and
  continuity provisions.
- **Specification set** (`docs/spec/`) — the registry record format and operation set, the
  naming and TLD policy, the resolution algorithm and resolver requirements, the hosting and
  publishing flow, the proof-of-work construction, and VWIP-0000 defining the improvement
  proposal process itself.
- **Design documents** (`docs/`) — the whitepaper, the architecture, the threat model, the
  governance guide, the roadmap, the glossary and the FAQ.
- **Project policies** — `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and `SECURITY.md`.
- **Brand assets** (`assets/`) — the VayuWeb mark, wordmark and lockup in light and dark
  variants, generated from the source artwork by `scripts/build-assets.py`.
- Repository scaffolding: licence, changelog, editor and lint configuration, issue and pull
  request templates, and a documentation lint workflow.

- **Strict content-security and zero-trail profile** (`docs/spec/CONTENT-SECURITY.md`,
  `docs/spec/PRIVACY.md`), proposed formally as VWIP-0001. A deny-by-default
  Content-Security-Policy (`default-src 'none'`, no inline script or style, no `data:` images,
  `worker-src 'none'`, `webrtc 'block'`, Trusted Types required), a Permissions-Policy denying
  every named powerful feature, request-header uniformity across installs, response-header
  stripping, markup neutralisation for the speculative-loading channels CSP does not cover, and
  an explicit section on the channels no header can close.
- **Private Mode** — all egress through an anonymising transport behind a single guarded choke
  point, memory-only state, and a hard refusal to start rather than fall back if the transport is
  unavailable.
- **The `vayu://` URI scheme** (`docs/spec/URI-SCHEME.md`). VayuWeb names get their own scheme
  rather than borrowing `http://` or `https://`, and it is deliberately not registered as a
  trustworthy scheme — doing so would re-enable service workers and the whole secure-context API
  surface, which is currently closed for free.
- **Local attack surface hardening** (`docs/spec/LOCAL-SURFACE.md`). The control API moves off
  TCP onto a Unix domain socket, which a browser cannot address, deleting DNS rebinding, CSRF,
  `Upgrade` reach and port-scanning of the privileged surface in one change. Also: `Host`
  validation on the proxy, diagnostic headers off by default so a page cannot detect that VayuWeb is
  installed, bounded negative caching, and cross-name subresource widening restricted to media
  types only.
- **Cryptographic agility and post-quantum migration** (`docs/spec/CRYPTO-AGILITY.md`). No
  primitive is named in the protocol, only versioned suites; every signed object carries its
  suite; suites move forward only; verifiers support every historical suite forever; migration
  runs through a hybrid so it is safe even if the target is later found weak.
- **Longevity review** (`docs/LONGEVITY.md`) — substrate independence, time handling, format
  evolution, log growth, dependency discipline, and six recorded predictions so that being wrong
  later is visible rather than deniable.
- `scripts/check-headers.py` and a CI job asserting the canonical security header values are
  quoted identically everywhere they appear.
- **VWIP-0002** (`docs/spec/VWIP-0002.md`) — proposes amending Article 16.2 to permit a
  reciprocal licence for the reference implementation, so that a well-capitalised operator
  cannot run a closed, improved derivative as a hosted service and publish none of it. The
  amendment is drafted to permit rather than require, names no specific licence, tightens the
  specification requirement to public-domain-equivalent terms, and makes unrestricted forking
  a condition of any qualifying licence. Ratification could not relicense existing code —
  see below.
- `LICENSES/` — the canonical CC0-1.0 and MIT texts, so the terms in force are readable in the
  repository rather than at a URL that may not resolve in 2126.
- **Developer Certificate of Origin 1.1** for contributions (`CONTRIBUTING.md`), signed off per
  commit as the Linux kernel does.

### Changed

- **`LICENSE` restructured into the two layers the project actually has**: CC0-1.0 for the
  charter, the specifications and the brand artwork; MIT for code. This is what Article 16.2
  requires, and the file now says so, cites the clause, and records the argument against it
  rather than acting on it unilaterally.
- **No Contributor Licence Agreement, stated as a permanent commitment** in both `LICENSE` and
  `CONTRIBUTING.md`. Copyright stays distributed across every contributor, so relicensing the
  corpus would require the agreement of all of them and becomes impossible almost immediately.
  That impossibility is the protection: it is why the Linux kernel cannot be relicensed, and it
  is the licensing counterpart of the entrenched clauses in Article 9. It also binds the author
  — a governance process able to relicense the whole corpus by vote would be the capture vector,
  not the remedy.

### Fixed

- **A single `RENEW` could buy an unbounded term for one proof of work.** Found by attacking the
  verification rules while implementing them. `RENEW` derives its expiry from `notBefore`, and
  the renewal-window check is a lower bound only; the clock checks sat inside the `REGISTER`
  branch, so nothing bounded `notBefore` from above. A renewal naming a term start a century
  ahead received a term ending a century and a year ahead, at the cost of one proof — defeating
  the property `RENEW` exists to create, that holding a large portfolio is a recurring annual
  cost rather than a one-off. `clock_check` now applies to every operation. Postdating is
  **deferred, not rejected**, so a verifier with a slow clock does not permanently disagree with
  its peers about a valid record.
- **Three namespace and prefix defects in the specifications**, each found by implementing the
  text rather than reading it: the domain-separation prefixes were documented as 23 and 21 bytes
  and are 26 and 24; `.p2p` violated the letters-only label ABNF, which now admits digits after
  the first character; and the launch-extension list contained `.vayu` twice, so eight documents
  described twelve extensions where eleven exist. `scripts/check-counts.py` now derives such
  counts from the document that defines them, and refuses a duplicated entry outright.
- **The accompanying-header count** was given as twelve in three documents; section 3 of
  `CONTENT-SECURITY.md` defines ten.

### Notes

- The registry core is under implementation in `registry/`: deterministic CBOR, domain
  separation, strict Ed25519, the label grammar and ratified TLD set, record schema validation
  and the verification state machine. `proxy/` and `client/` remain placeholders.
- Proof-of-work verification is defined as an interface (`RegistryView.powVerified`) with no
  default implementation. A permissive default would make every caller that forgot to supply one
  accept unproven records silently, which a passing test suite cannot show.
- Long-term development will move to Radicle; this GitHub repository is a public mirror.
