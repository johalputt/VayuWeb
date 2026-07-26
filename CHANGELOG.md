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

### Notes

- No protocol code exists yet. The `registry/`, `proxy/` and `client/` directories are
  placeholders describing what will be built there.
- Long-term development will move to Radicle; this GitHub repository is a public mirror.
