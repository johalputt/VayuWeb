# Changelog

All notable changes to WebX are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

WebX is pre-implementation. Until the first release there is no version number to assign, so
changes accumulate under `[Unreleased]`. Versioning begins with the first tagged release of
the registry core; the scheme will be set by a WXIP before then, not improvised at tag time.

## [Unreleased]

### Added

- **The WebX Constitution** (`constitution/CONSTITUTION.md`) — the founding charter: the
  Preamble, an operative Bill of Rights, the registry and naming law, the governance
  machinery, the entrenchment and amendment rules, the right to fork, and the succession and
  continuity provisions.
- **Specification set** (`docs/spec/`) — the registry record format and operation set, the
  naming and TLD policy, the resolution algorithm and resolver requirements, the hosting and
  publishing flow, the proof-of-work construction, and WXIP-0000 defining the improvement
  proposal process itself.
- **Design documents** (`docs/`) — the whitepaper, the architecture, the threat model, the
  governance guide, the roadmap, the glossary and the FAQ.
- **Project policies** — `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and `SECURITY.md`.
- **Brand assets** (`assets/`) — the WebX mark, wordmark and lockup in light and dark
  variants, generated from the source artwork by `scripts/build-assets.py`.
- Repository scaffolding: licence, changelog, editor and lint configuration, issue and pull
  request templates, and a documentation lint workflow.

- **Strict content-security and zero-trail profile** (`docs/spec/CONTENT-SECURITY.md`,
  `docs/spec/PRIVACY.md`), proposed formally as WXIP-0001. A deny-by-default
  Content-Security-Policy (`default-src 'none'`, no inline script or style, no `data:` images,
  `worker-src 'none'`, `webrtc 'block'`, Trusted Types required), a Permissions-Policy denying
  every named powerful feature, request-header uniformity across installs, response-header
  stripping, markup neutralisation for the speculative-loading channels CSP does not cover, and
  an explicit section on the channels no header can close.
- **Private Mode** — all egress through an anonymising transport behind a single guarded choke
  point, memory-only state, and a hard refusal to start rather than fall back if the transport is
  unavailable.
- **The `webx://` URI scheme** (`docs/spec/URI-SCHEME.md`). WebX names get their own scheme
  rather than borrowing `http://` or `https://`, and it is deliberately not registered as a
  trustworthy scheme — doing so would re-enable service workers and the whole secure-context API
  surface, which is currently closed for free.
- **Local attack surface hardening** (`docs/spec/LOCAL-SURFACE.md`). The control API moves off
  TCP onto a Unix domain socket, which a browser cannot address, deleting DNS rebinding, CSRF,
  `Upgrade` reach and port-scanning of the privileged surface in one change. Also: `Host`
  validation on the proxy, diagnostic headers off by default so a page cannot detect that WebX is
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

### Notes

- No protocol code exists yet. The `registry/`, `proxy/` and `client/` directories are
  placeholders describing what will be built there.
- Long-term development will move to Radicle; this GitHub repository is a public mirror.
