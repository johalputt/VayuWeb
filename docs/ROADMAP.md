# VayuWeb Roadmap

**No date is promised, and no phase past 0 is finished.**

This line said "nothing here is implemented" until the day that stopped being true, and then for
a while after — a stale claim at the top of the file whose whole subject is what is and is not
done. Phases 1 to 4 are variously started or mostly built, each says so in its own words, and
every one of them is held open by an acceptance test that a single machine in a sandbox cannot
honestly pass. Understating progress is not the safe direction: it is as wrong as overstating it,
and it teaches a reader to discount the rest of the page.

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
| Independent adversarial review of the above | **Findings all dispositioned; the review itself is not finished.** The 2026-08-04 audit raised 66 surviving findings and every one now carries an outcome in [AUDIT-FINDINGS.md](AUDIT-FINDINGS.md) — fixed, escalated to an amendment, or verified stale. That is one audit, by seven agents, on one corpus. It is not the *independent* review this row asks for, and it cannot be: Article 44.6's standard is a competent implementer reading the specifications alone, and the same party that wrote them cannot supply that reader |
| Test vectors for every wire-visible rule | **Six suites**, in [`conformance/vectors.json`](../conformance/vectors.json): record verification (a vector for every rejection code), convergence, resolution, replication, equivocation and proof-of-work derivation. The last five pin what implementations must *agree* about rather than what one accepts — which is where a fork lives, and where every consensus-critical defect found here so far has been |

**Done when:** a competent implementer can read the specifications alone — without access to any
source code and without asking a question — and produce a client that would interoperate. That
property is required by Constitution Article 44.6, and it is not satisfied today.

**What the audit changed, and what it did not.** It closed every defect anyone found and it
raised the floor a great deal: **six conflicts** are now held open deliberately rather than
unnoticed, and the checkers refuse the classes of drift that produced most of the rest. It
did not establish the done-when condition, and no self-administered review can. The strongest
honest statement is the negative one: an implementer reading these documents today will not hit
the sixty-six things that were found, which is a different claim from will not hit anything.

The audit's own lesson is worth carrying into Phases 2 to 5. **Fourteen of the eighteen HIGH
findings were invisible to reading any single document and obvious with two open at once** — a
specification against the charter, a specification against its sibling, or the charter against
itself. Every checker this project had before the audit compared prose to a list, or a number to
its source. Nothing compared two documents to each other, and that is where the defects were.

Implementing the registry against these specifications has so far found eight defects in them,
each recorded in `CHANGELOG.md`: two that would have made proof-of-work free or unnecessary, one
that let an expired holder reclaim a name during quarantine, one that let a single renewal buy an
unbounded term, one false justification in the index keyspace layout, one difficulty ceiling that
the schedule cannot reach, one name able to alias itself, and one keyspace codec that did not
enforce the grammar its own design rests on. Every one was invisible to reading and obvious to
implementing, which is the argument for treating the vector set as part of the specification
rather than as test scaffolding.

**Six conflicts are held open rather than decided**, and they are held open for the same reason
each time: both sides are Articles of the Constitution, so Article 3.7 cannot rank them and
Article 58 reserves the choice to an amendment. `scripts/check-charter-consistency.py` prints all
six on every run and fails if one is closed by editing a single side.

Three are **quantities** — the registration term, the renewal window and the post-expiry interval
each have three disagreeing sources. One is a **term**: "epoch" is an interval under Article 2.5
and an instant under Article 11.5. Two are **memberships**: `RENEW` is normative in Articles 11.6,
11.8 and 31.1 and absent from Article 29.4's closed record set, so a peer obeying 29.4 literally
must refuse every renewal; and `TLD-CREATE` is a record type in 29.4 while Article 35.6 vests
extension creation in a ratified proposal.

Held open is not deferred. Each is printed, each is guarded, and the specification says which side
it implements and why — because a subordinate document that quietly does the sensible thing
against a clause of the charter is indistinguishable, to a second implementer, from one that
overlooked the clause.

## Phase 1 — Registry core

**Goal:** the signed, append-only name registry, working on one machine.

Hypercore log with a Hyperbee index over it; the record schema; deterministic CBOR canonical
serialisation with domain separation; Ed25519 sign and verify; Argon2id proof-of-work generation
and verification; the six operations (`REGISTER`, `UPDATE`, `RENEW`, `TRANSFER`, `RELINQUISH`,
`REVOKE`) with their validation ordering; the lifecycle state machine including grace and
quarantine.

**The proof-of-work arithmetic is now a contract, and writing it found a way to fork.** The
difficulty schedule was covered by unit tests alone, so the `pow` suite was written to expose it
to a second implementation — and the exercise turned up that `PROOF-OF-WORK.md` specifies its
rate term as `floor(log2(n / 512))` without saying that `log2` is implementation-approximated in
every language a client is likely to be written in. One ulp at an exact doubling is one bit of
difficulty, which is one peer rejecting a record another accepted, permanently. Nothing has
diverged — this implementation agrees across the whole reachable range, now established by a
test that walks it — but nothing in the document required that, which is the defect. It now gives
the integer formulation, and the vectors pin every boundary for everyone else.

Writing that suite also produced the sharper lesson of the two. Its first version computed
`expect: baseBits(labelLength)` — the answer obtained by calling the function under test — and
four of five deliberate mutations to `pow.ts` survived it, because breaking the implementation
moved the expectation with it. It is the same failure as the hand-written coverage list and the
CSP test that pinned its block by name: **a check derived from the thing it checks proves
nothing, and reads exactly like one that does.**

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

**Equivocation detection had no conformance vector, and writing one found the defect.** It was
covered by unit tests alone — implemented, exercised, and measured against nothing but itself.
Building the contract meant asking what a *second* implementation would do with a pair of
records, and the answer was that this one recorded and forwarded evidence nobody had signed. An owner key is public, so two records naming a victim as owner for one name at one `seq`,
signed by the attacker, were verified and passed on by every peer that received them: 6.4's
manufactured evidence, arriving by the front door of the mechanism that refuses it.

The fix is a signature check, deliberately not a validity check — `REPLICATION.md` 6.2.1 to
6.2.4, and the `equivocation` suite in `conformance/vectors.json`. The pattern is by now the
familiar one: the gap was invisible from inside the implementation and obvious the moment the
question became "what would somebody else's code do with these bytes".

**Mostly done.** The protocol is specified in [spec/REPLICATION.md](spec/REPLICATION.md) and
implemented as a transport-agnostic state machine in `registry/src/replicate.ts`, exercised
against paired peers with real stores and real proofs of work: order independence over every
permutation of a record set, partition-and-heal convergence, hostile batches, and the message
limits. The convergence rule, equivocation detection and the checkpoint format were already
there. The **reference transport binding** is now in `registry/src/swarm.ts` — the discovery
topic, the length-prefix framing that section 2.1 asks for and a stream does not provide, and a
driver that carries messages without ever reading the channel's authenticated remote key. Two
peers driven over a pipe converge on identical state, each having verified locally.

**Running it against peers on other machines is what remains**, and it is the part a sandbox
cannot honestly claim: the acceptance test asks for independent peers, started in any order and
deliberately partitioned, and a pipe between two objects in one process is not that however
carefully it is wired.

Writing the binding produced the phase's third consensus-shaped defect, and the same way as the
first two. The first driver sent `HELLO`, answered what it was asked, and never called
`nextWant` — so it could serve and could never catch up. Two of them complete a handshake, report
no error, and sit permanently diverged while looking exactly like a working connection. A unit
test on one driver cannot see it; the question "what do two of these do" found it immediately.

Two defects surfaced the moment the work asked what *two* peers do, and both had passed a feature
review and their own unit tests:

- The convergence rule decided conflicts by the peer's own log position, which is arrival order.
  Two peers handed the same pair in opposite orders kept different owners, permanently, and any
  relay could choose which — for free, with nothing detectable sent.
- The rule was then found to be **called by nothing**. It was specified, implemented and tested
  while the merge path did first-arrival-wins, so fixing the rule alone would have changed no
  behaviour at all. `Store.append` now runs it.

Both are recorded in the changelog and in `THREAT-MODEL.md` T6a. The lesson is the one this
project keeps relearning: a green unit test proves the unit, and a single machine has only one
arrival order to test with.

**Depends on:** Phase 1.

**Done when:** independent peers, started in any order and partitioned deliberately during the
test, converge on identical registry state and identical conflict outcomes across the
conformance suite.

## Phase 3 — Resolution proxy

**Goal:** VayuWeb names work in a browser nobody modified.

The loopback HTTP proxy on `127.0.0.1:7654`; the token-authenticated control API on
a Unix domain socket; the resolution algorithm with its cache and TTL policy including negative
caching; per-name origin isolation and the default Content-Security-Policy; the numbered error
catalogue.

**The `Permissions-Policy` header was specified and never emitted**, found in the audit's final
pass: the proxy sent the CSP and eight of the nine other canonical values, so every powerful
feature `CONTENT-SECURITY.md` enumerates as denied was in fact permitted. Fixed, and the test now
enumerates the canonical markers in the document rather than naming the one block it checks. It
is the sharpest example of this phase's own risk — the surfaces here are the ones a document can
describe correctly while nothing emits them.

**The specification described publishing in byte-exact detail and fetching as if a CID addressed
one resource.** Step 12 said "verify the bytes hash to the requested CID" — right for one block,
silent about the other n − 1 — so an implementer following it verifies the root, gets an authentic
directory node, and then believes whatever arrives for the files it points at. Substituting an
`index.html` under a genuine root was free, and it is the one substitution a reader could never
notice: the name, the record and the root are all real. Clauses 12.1 to 12.3 now state that
verification is recursive, that the traversal is bounded rather than only its output, and that
declared UnixFS metadata is content rather than authority. The pattern is the phase's own: the
half of the design that consumes untrusted input was the half nobody had written down.

**Mostly done, and now runnable.** The resolution algorithm — steps 1 to 10 and 13, the
record-selection order, alias following with its hop budget, and the numbered error catalogue —
is in `registry/src/resolve.ts`. The **browsing proxy** is in `registry/src/proxy.ts` and the
**control API** in `registry/src/control.ts`, both still pure request handlers so that every
refusal is exercised as data rather than assumed behind a socket; `registry/src/serve.ts` binds
them, and `vayuweb-registry serve` starts both. A browser pointed at the proxy gets a numbered
answer with the full header set on it, including on refusals — which is where a header set is
most often forgotten. **Verified traversal** is in `registry/src/fetch.ts`: block-by-block verification against the referring CID, a bound on blocks
and depth rather than on assembled bytes, and refusal of a node whose declared sizes disagree with
what arrives. **The block-exchange transport and the browser integration remain**, and so does the
Article 14 outbound-connection test, which needs a real browser and a real network to mean
anything.

The two surfaces are deliberately of different kinds. The proxy is TCP because a browser must
reach it; the control API is a Unix domain socket because a browser must never reach it, and
`assertSocketAddress` throws on a TCP address rather than leaving that to a sentence in a
document — the sentence already existed, in `LOCAL-SURFACE.md` section 1, and five documents went
on specifying `127.0.0.1:7653` anyway.

Three test inadequacies were found and fixed during the work, all the same shape: an assertion of
`status !== 200` passed while the defence under test was deleted, because the request then failed
for an unrelated reason. Asserting the *exact* refusal code is what made them able to fail. One
guard turned out to be genuinely redundant on re-mutation, and its comment now says so rather
than implying it is load-bearing.

**Depends on:** Phase 2.

**Done when:** an unmodified browser, pointed at the proxy, renders a VayuWeb page end to end — and
the outbound-connection conformance test of Constitution Article 14 passes, showing that a
single-name lookup produces no clearnet DNS query and no phone-home.

## Phase 4 — Hosting

**Goal:** publishing a site, and keeping it alive.

Helia integration; the publish flow (build the tree, add to IPFS, obtain the CID, sign the IPNS
record, write the pointer into the registry); pin-set management with honest reporting of what is
and is not being kept alive; unpublishing and its documented limits.

**Started.** `registry/src/content.ts` implements the fixed import parameters — CIDv1, lowercase
unpadded base32, sha2-256, 256 KiB fixed chunks, raw leaves — and its tests pin the **published
IPFS reference CIDs** for the empty file and `hello world`, so the module is checked against the
network it must interoperate with rather than only against itself. An implementation can be
internally perfect, round-trip everything it produces, and still address content nobody else can
find; only an external vector catches that.

`registry/src/unixfs.ts` completes the tree-to-root-CID path: dag-pb nodes, UnixFS directory and
file messages, raw-leaf files, multi-chunk file nodes, and recursive directory building. Six
vectors from the reference importer are pinned, including a nested tree.

The refusal to guess at this was justified within the hour. Written from a *description* of the
format, the first encoder put the UnixFS `Data` field at protobuf field 2 and produced a
confidently wrong CID for the empty directory. It was self-consistent, it round-tripped, and every
site it published would have resolved on the publisher's own machine and been invisible to every
other node.

`registry/src/pins.ts` covers availability reporting and unpublishing. It is written to refuse to
overstate: silence is reported as silence rather than as absence, a self-pin is never counted as
redundancy, and there is no total, percentage or uptime field for an interface to bind to —
Article 23 forbids the figure, so the number does not exist. Article 19's limits on unpublishing
are held as a list rather than as prose, so a user interface has to render them or deliberately
drop them.

**What remains.** Helia integration and the block-exchange path, and the end-to-end acceptance
test — which needs two machines and a network, and which this repository cannot honestly claim
from a sandbox.

Starting the phase surfaced two settled-spec contradictions and one gap, all recorded in the
changelog: the resolver preferred the frozen snapshot over the living pointer, so a conforming
publisher and a conforming resolver together froze every site; `.vayu/manifest.json` had two
disjoint normative schemas and a third document that ignored it; and step 5 said "sign an IPNS
record" without saying which bytes are signed, which Article 44.6 makes a defect rather than an
omission.

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

This section said "not with code — there is no code to write against yet" for as long as that was
true, and it stopped being true without anybody editing it. There is now a registry, a
replication state machine, a resolver, a browsing proxy, a control API, the content-addressing
and UnixFS encoders, and six conformance suites. A contributor reading the old sentence would
have been told the opposite of the situation, which is the same defect as any other stale claim
in this corpus — it just happened to be in the paragraph telling people what to do about it.

The reasoning behind it still holds where it applies: **code written before the specification
settles is code that will be thrown away**, and every phase from 2 onward is still marked
"mostly done" rather than done for that reason. So the ranking below is unchanged, and it is
unchanged deliberately. Attacking a document is still worth more than writing a module, because
every defect this project has found in its own implementation was a defect in a document first.

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
6. **Run the conformance vectors against your own code.**
   [`conformance/vectors.json`](../conformance/vectors.json) is readable without any of this
   repository, and a disagreement is worth reporting whichever of us is wrong — the third
   possibility, that the specification let two people read it differently, is the most valuable
   of the three and the reason the file exists.

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
