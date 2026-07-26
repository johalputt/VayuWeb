# WebX Longevity Review

The Constitution is written for a hundred years. This document asks the engineering question that
follows: **what in the technical design will break long before then, and what has been done about
it?**

It is deliberately pessimistic. Every dependency named here is expected to die, every constant is
expected to be wrong eventually, and the design is judged by how gracefully it survives being
wrong rather than by how right it looks today.

**Status:** Draft against the pre-implementation design.

## 0. The test

A design is future-proof to the extent that a change of substrate, primitive, format or
maintainer can happen **without invalidating a single existing name**. Names are the asset. Code
is replaceable, the network is replaceable, the organisation is replaceable — but a person's name
must survive all of it, or WebX has recreated the thing it exists to replace.

Every section below is measured against that one test.

## 1. Cryptography

The existential one, specified separately and in full in
[spec/CRYPTO-AGILITY.md](spec/CRYPTO-AGILITY.md).

Summary: no primitive is named in the protocol, only *suites*; every signed object carries its
suite identifier; suites move forward only; verifiers must support every historical suite forever;
migration runs through a hybrid so it is safe even if the target is later found weak; and
checkpoints are anchored so a future break cannot retroactively make all history deniable.

**Verdict:** structurally addressed. This is the one thing that could not have been retrofitted —
a record format without a suite field can never migrate — and it is present from record zero.

## 2. Substrate

Hypercore, Hyperbee, Hyperswarm, HyperDHT, IPFS and Helia are all young. Assume at least one does
not survive the century; assume all of them might not.

**What protects the design:** the specification defines the registry's *semantics* — a signed,
append-only, independently verifiable sequence of records with a deterministic convergence rule —
not its implementation. The substrate sits behind an interface.

**What a substrate migration must preserve**, and these are requirements, not aspirations:

1. Every historical record verifies unchanged. The signing input is defined over canonical CBOR
   and a domain-separation prefix, neither of which mentions the transport.
2. No name is re-registered. A migration that asks every holder to act is a migration that loses
   every inactive holder.
3. Sequence numbers and `prevHash` chains carry over intact.
4. The convergence rule produces identical outcomes on the migrated history.

**Weak point, stated honestly:** IPFS content addressing is more deeply assumed than the registry
substrate is. CIDs appear in records, so a move away from IPFS means either translating CIDs or
carrying a compatibility layer indefinitely. Multihash gives hash agility but not
content-addressing-scheme agility. This is the least future-proof part of the current design and
should be a standing agenda item.

## 3. Time

A century-scale system must be explicit about time, because every naive choice here fails inside
the design lifetime.

| Concern | Rule |
|---|---|
| Representation | Signed 64-bit seconds since the Unix epoch. Not 32-bit — 32-bit signed time ends in 2038, which is *inside* the first fifth of the design lifetime. |
| Scale | UTC. Leap seconds are tolerated by never using timestamps for ordering. |
| Ordering | **Never** by wall-clock timestamp. Ordering is by log position and per-name `seq`. Two records with identical timestamps are ordered deterministically by the convergence rule, never by clock comparison. |
| Validity | `notBefore` and `notAfter` are wall-clock, and therefore advisory against a lying clock. A peer with a wrong clock reaches wrong conclusions about expiry; this is unavoidable without a trusted time source, which would be a chokepoint. |
| Durations | One year is 31,536,000 seconds. Fixed, not calendar-derived, so leap years, timezone databases and calendar reform cannot change it. |
| Skew | A defined tolerance for future-dated records, beyond which they are rejected rather than queued. |

**Weak point:** expiry depends on wall-clock time, and a sufficiently isolated node can be lied to
about the date. The mitigation is that expiry is not a transfer of ownership to anyone — it
returns a name to the pool after grace and quarantine — so a clock lie delays or accelerates a
lapse rather than handing a name to an attacker.

## 4. Format evolution

4.1 Records use **deterministic CBOR** with a version tag. Determinism is required because the
bytes get signed; a format with two valid encodings of one value is a format with two valid
signatures and one interoperability failure.

4.2 The unknown-field rule MUST be **reject, not ignore**, for anything inside the signed
envelope. "Must-ignore" is right for extensible documents and wrong for signed ones: silently
ignoring a field means two implementations can disagree about what a signature covers, which is
how signature schemes get broken in practice rather than in theory.

4.3 New fields therefore arrive with a version increment and an activation epoch, per
Constitution Article 47, so every peer knows to expect them before any peer emits them.

4.4 Capability negotiation lets old and new peers coexist during a transition. A peer that cannot
parse a version does not guess.

## 5. Growth

A century of append-only log is a lot of log.

**What exists:** checkpointing and compaction are specified in [spec/REGISTRY.md](spec/REGISTRY.md)
so a light client can verify current state without replaying all history.

**What is unresolved, and should be said plainly:** nobody knows the constant factor. If full
verification of a hundred-year log cannot run on ordinary consumer hardware in 2126, then most
people will rely on somebody else's verified view — and a de facto root returns through the back
door, defeating the entire design. This is listed in [ROADMAP.md](ROADMAP.md) as one of the
findings that would make the project stop and rethink, and it is the one most likely to actually
occur.

The honest position: the design has a mechanism (checkpoints) but not yet a proof that the
mechanism is sufficient at scale. That proof is Phase 2 work.

## 6. Dependencies

| Dependency | Risk | Discipline |
|---|---|---|
| Hypercore / Hyperswarm | Small ecosystem | Behind the registry interface (section 2) |
| IPFS / Helia | Governance and funding volatility | Behind the content interface; CID coupling is the weak point |
| Tauri | Young framework | Client only. The protocol has no opinion about the UI toolkit, and a rewrite loses no names. |
| Radicle | Young, and the intended permanent home | Development home only. Losing it costs the project a workflow, not a namespace. |
| JavaScript runtimes | Churn | Reference implementation only, and per Constitution Article 44.4 the reference implementation is explicitly not normative |
| Browser engines | Consolidation | Genuine and irreducible; mitigated by belt-and-braces headers so one engine's gap is not a hole |

**The rule:** no dependency may become load-bearing for *names*. A dependency may be load-bearing
for convenience, for speed, or for the current implementation — never for whether a person still
holds what they registered.

## 7. Documents

Specifications outlive the people who wrote them only if they can be read without external
context.

- Every specification is self-contained: no normative requirement lives behind an external link.
- External links are illustrative only, because link rot over a century is total.
- Cross-references are relative paths inside the repository, verified by
  `scripts/check-links.py` in CI, so a reorganisation cannot silently break the corpus.
- The canonical security header values live in exactly one file, enforced by
  `scripts/check-headers.py`, so quotations cannot drift apart over decades of editing.
- The Constitution text is public domain, so a fork carries the charter intact rather than
  reconstructing it from memory.

## 8. Governance

Covered by the Constitution and not repeated here. The provisions that carry the century are
Article 28 (duties bind the text and the software, not any body, so the system keeps working when
nobody is watching), Article 49 (anti-ossification duties), Article 55 (succession and founder
sunset), Article 56 (dormancy, caretaker mode and revival by strangers) and Article 58 (the
decennial review).

The decennial review is the mechanism most relevant to this document: every ten years, the design
assumptions above get re-examined on a schedule rather than when someone happens to notice.

## 9. What we would bet against

Predictions recorded now so that being wrong later is visible rather than deniable:

1. **Ed25519 will not be the signing scheme in 2126.** Suite migration will happen at least once,
   probably twice.
2. **At least one named substrate dependency will be unmaintained within twenty years.**
3. **The 63-character ASCII label limit will be regretted.** Internationalised names are deferred,
   not refused, and the homograph problem will not have got easier.
4. **Proof-of-work difficulty will need retuning more often than expected**, because the
   hardware-cost assumption behind memory-hardness is the least stable assumption in the design.
5. **Someone will propose a treasury**, sincerely and for good reasons, roughly every five years.
6. **The convenience-driven centralisation in threat T8 will happen at least partially**, and the
   concentration metrics will be the only reason anyone notices.

## 10. What this review does not claim

- It does not claim the design will last a century. It claims the design can *change* without
  losing names, which is the only property that makes a century plausible.
- It does not claim the growth problem in section 5 is solved. It is identified and unsolved.
- It does not claim the IPFS coupling in section 2 is adequately abstracted. It is not.
- It does not claim these six predictions are the right six.

## See also

- [Cryptographic agility and post-quantum migration](spec/CRYPTO-AGILITY.md)
- [Registry specification](spec/REGISTRY.md)
- [Roadmap](ROADMAP.md) — what would make us stop and rethink
- [The WebX Constitution](../constitution/CONSTITUTION.md) — Articles 28, 47, 49, 55, 56, 58
