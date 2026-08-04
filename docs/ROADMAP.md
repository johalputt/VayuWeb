# VayuWeb Roadmap

**Nothing here is implemented, and no date is promised.**

This roadmap is organised by phase, not by calendar. Dates on a volunteer protocol project are a
form of dishonesty: they are set by wishful thinking, missed, and then quietly deleted. Phases
are honest instead, because each one carries an **acceptance test** — a condition an outsider can
check without asking anyone whether the phase is done.

Phases are ordered by dependency. A later phase may start early where it does not depend on an
earlier one, but it cannot *finish* early.

## Phase 0 — Charter and specification

**Goal:** settle the rules before writing code that would make them expensive to change.

| Item | State |
|---|---|
| The VayuWeb Constitution — six Titles, sixty Articles | Complete |
| Registry specification | Complete (draft) |
| Naming and TLD policy | Complete (draft) |
| Resolution specification | Complete (draft) |
| Hosting and publishing specification | Complete (draft) |
| Proof-of-work specification | Complete (draft) |
| VWIP-0000, the improvement process | Complete |
| Threat model | Complete (draft) |
| Whitepaper, architecture, governance guide, glossary, FAQ | Complete (draft) |
| Independent adversarial review of the above | **Open — this is the current work** |
| Test vectors for every wire-visible rule | Partial — [`conformance/vectors.json`](../conformance/vectors.json) pins the registry record rules, including a vector for every rejection code; replication, convergence and resolution have none |

**Done when:** a competent implementer can read the specifications alone — without access to any
source code and without asking a question — and produce a client that would interoperate. That
property is required by Constitution Article 44.6, and it is not satisfied today.

Implementing the registry against these specifications has so far found eight defects in them,
each recorded in `CHANGELOG.md`: two that would have made proof-of-work free or unnecessary, one
that let an expired holder reclaim a name during quarantine, one that let a single renewal buy an
unbounded term, one false justification in the index keyspace layout, one difficulty ceiling that
the schedule cannot reach, one name able to alias itself, and one keyspace codec that did not
enforce the grammar its own design rests on. Every one was invisible to reading and obvious to
implementing, which is the argument for treating the vector set as part of the specification
rather than as test scaffolding.

## Phase 1 — Registry core

**Goal:** the signed, append-only name registry, working on one machine.

Hypercore log with a Hyperbee index over it; the record schema; deterministic CBOR canonical
serialisation with domain separation; Ed25519 sign and verify; Argon2id proof-of-work generation
and verification; the six operations (`REGISTER`, `UPDATE`, `RENEW`, `TRANSFER`, `RELEASE`,
`REVOKE`) with their validation ordering; the lifecycle state machine including grace and
quarantine.

**Depends on:** Phase 0.

**Done when:** a command-line tool can register a name into a local log, resolve it back, reject
every malformed and replayed record in the test-vector set, and a second tool written from the
specification agrees on every vector.

## Phase 2 — Peer replication

**Goal:** many machines, one registry state.

Hyperswarm and HyperDHT discovery; replication and verification of received records; the
convergence rule for conflicting first-registrations with its deterministic tie-break;
equivocation detection; snapshot and checkpoint format so a light client can verify without
replaying all history.

**Partly done.** The convergence rule and equivocation detection are implemented and tested in
`registry/src/converge.ts` — they are pure logic and needed no network. Discovery, replication,
and the snapshot/checkpoint format remain, and they are the parts that cannot be finished
without peers to test against.

**Depends on:** Phase 1.

**Done when:** independent peers, started in any order and partitioned deliberately during the
test, converge on identical registry state and identical conflict outcomes across the
conformance suite.

## Phase 3 — Resolution proxy

**Goal:** VayuWeb names work in a browser nobody modified.

The loopback HTTP proxy on `127.0.0.1:7654`; the token-authenticated control API on
`127.0.0.1:7653`; the resolution algorithm with its cache and TTL policy including negative
caching; per-name origin isolation and the default Content-Security-Policy; the numbered error
catalogue.

**Depends on:** Phase 2.

**Done when:** an unmodified browser, pointed at the proxy, renders a VayuWeb page end to end — and
the outbound-connection conformance test of Constitution Article 14 passes, showing that a
single-name lookup produces no clearnet DNS query and no phone-home.

## Phase 4 — Hosting

**Goal:** publishing a site, and keeping it alive.

Helia integration; the publish flow (build the tree, add to IPFS, obtain the CID, sign the IPNS
record, write the pointer into the registry); pin-set management with honest reporting of what is
and is not being kept alive; unpublishing and its documented limits.

**Depends on:** Phase 3.

**Done when:** a site published on one machine is fetched and rendered by a second machine that
was never told where it came from, and the publishing client can state accurately how many peers
currently hold the content.

## Phase 5 — Desktop client

**Goal:** the whole system, for people who will never open a terminal.

Tauri 2.x application; identity generation with the secret key placed in the operating system
keychain and never written to a config file or the log; register, renew, transfer and release;
publish; browse; pin management; opt-in succession key designation.

**Depends on:** Phase 4.

**Done when:** someone who has never used a command line completes the full flow — install,
create an identity, register a name, publish a page, and open it in their own browser — without
assistance and without reading the specifications.

## Phase 6 — Radicle migration and independent implementations

**Goal:** remove the project's own dependency on a centralised host, and prove the specifications
are finished.

Migration of development to Radicle, with GitHub retained as a read-only mirror; reproducible
builds and multi-party release signing per Constitution Article 51; the first published
implementation-diversity report.

**Depends on:** Phase 1 onward, running in parallel from Phase 3.

**Done when:** a second implementation, written by parties with no common employer or funder,
interoperates fully with the first across the conformance suite. This is the only real proof that
a specification is complete, and Constitution Article 44.2 makes it a precondition of any
Standards Track VWIP reaching Final.

## Phase 7 — Convenience layers

**Goal:** make it easier, without making anything mandatory.

Browser extension; mobile companion; improved discovery and search that does not become an index
anyone must ask permission from.

**Depends on:** Phase 5.

**Built last on purpose.** A convenience shipped early becomes a requirement, and a requirement
becomes a chokepoint. The extension must never be necessary to use VayuWeb; if it becomes so, that
is a defect against Constitution Article 4.

**Done when:** every convenience layer can be removed and the system still works completely.

## How to help right now

Honestly: not with code. There is no code to write against yet, and code written before the
specification settles is code that will be thrown away.

What is worth doing today, in descending order of value:

1. **Attack the Constitution.** Find the clause a determined bad actor could drive a truck
   through. Find the entrenched Article that the amendment machinery can actually reach. Find the
   mechanism that stops working when the volunteers get bored.
2. **Attack the threat model.** Add an adversary, a vector, or a residual risk it understates.
3. **Break a specification.** Find the ambiguity two implementers would resolve differently — the
   place where the text is not sufficient to build a conformant client.
4. **Challenge a number.** Every threshold and duration was chosen and justified. If a
   justification is weak, say so; that is a legitimate VWIP.
5. **Find an overclaim.** Any sentence that makes VayuWeb sound more private, more available or more
   censorship-resistant than the design supports is a bug, and a serious one.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how, and [spec/VWIP-0000.md](spec/VWIP-0000.md) for
the process.

## What would make us stop and rethink

Listed in advance, so that changing our minds later looks like integrity rather than improvisation:

- **Proof-of-work does not price squatting.** If modelling shows that the cost curve fails to
  deter bulk registration at plausible hardware budgets — or that it prices ordinary users out on
  a phone — the anti-squatting design is wrong and needs replacing, not tuning.
- **The convergence rule produces outcomes users experience as arbitrary confiscation** often
  enough to matter. Deterministic is not the same as acceptable.
- **Independent verification is too expensive.** If full-history verification cannot run on
  ordinary consumer hardware, most people will use somebody else's verified view, and a de facto
  root returns through the back door.
- **Bootstrap or pinning concentration proves unavoidable.** If the concentration metrics of
  Article 53 show a de facto centre forming despite plural, swappable defaults, then the
  no-chokepoint invariant is aspirational rather than real, and the honest response is to say so
  publicly, not to restate the principle.
- **Nobody writes the second implementation.** If, after a serious effort, no independent party
  will implement the protocol, then it is a single-vendor system regardless of its licence, and
  Article 44.3 already says such a design must not advance.

## See also

- [The VayuWeb Constitution](../constitution/CONSTITUTION.md)
- [Whitepaper](WHITEPAPER.md)
- [Threat model](THREAT-MODEL.md)
- [VWIP-0000](spec/VWIP-0000.md)
