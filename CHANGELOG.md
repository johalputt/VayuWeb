# Changelog

All notable changes to VayuWeb are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Versions follow the scheme set by [VWIP-0003](docs/spec/VWIP-0003.md), which keeps the
**protocol version** carried in every record separate from the **implementation version** on the
software. Before 1.0.0 the public interface is explicitly unstable and a minor release may break
it.

## [Unreleased]

### Fixed — the resolver could not serve a page, and nothing said so

Phase 3's acceptance criterion is a browser nobody modified rendering a VayuWeb name. Running it
returned **502** for a name that resolved perfectly. Three defects sat in a row on the path from a
typed CID to a rendered page, and not one of them produced an error message.

- **`--cid` was accepted and silently discarded.** `entriesFrom` never read the flag, so the tool
  could register a name and could never point one at content, and it answered
  `accepted REGISTER … 329 bytes` for a record with no entries in it. `cid` and `ipns` are the two
  entry types `RESOLUTION.md`'s source order puts *first*, so this was not a gap at the edge of
  the surface but a hole through the middle of it. Every unrecognised flag is now refused by name,
  with the nearest known flag suggested — a tool that drops what you typed and then reports
  success is a tool that lies about what it did.

- **A `cid` entry is binary, and the CLI stored text.** `REGISTRY.md` types the entry `bstr` —
  "Binary CIDv1, 1-64 bytes; rendered base32 in JSON" — so the `bafy…` string is the *rendering*
  and the bytes are the value. The binary form had no encoder anywhere in the codebase, which is
  part of why it was easy to miss. `content.ts` grows `cidBytes` and `cidFromBytes` as the pair
  the record format actually needs, and the flag is decoded before the proof-of-work solve rather
  than rejected by the parser after it: a mistyped CID used to cost a full solve to find out about.

- **`String(entry.value)` on a byte string.** The proxy handed the content layer
  `String(outcome.entry.value)`, which for a `Uint8Array` produces `"1,112,18,32,180,…"` — the
  comma-joined decimals of the array. It is a string, it is non-empty, and it satisfies every type
  check between there and a content port that can then only ever fail to match it. Replaced with
  `sourceValueOf`, which converts per entry type and returns null rather than guessing. Same
  lesson as the stale-lockfile one earlier: the dangerous conversion is the one that always
  produces *something*.

`resolve` now prints a `cid` in base32 as well, so what it shows can be compared by eye with what
was typed; it was printing hex.

### Added

- **`registry/scripts/acceptance-browser.mjs`** — Phase 3's acceptance criterion, executable. It
  publishes a two-file site, registers a name against the root CID the importer actually produced,
  starts the resolver, drives stock Chromium through it with no extension and no flag beyond
  `--proxy-server`, then checks that the page renders, that the *stylesheet* renders too (a
  resolver that serves `index.html` and nothing else still passes a text assertion), that the CSP
  arrives intact, that a non-VayuWeb name is refused rather than handed to the OS resolver, and
  that the resolver opened no outbound connection.

  It is not a CI job and not a dependency: Playwright's tree would take `registry/` past the
  forty-package supply-chain ceiling, and that ceiling exists to notice exactly this kind of
  change. It **refuses rather than skips** when it cannot run, because a harness that reports
  success on a machine with no browser converts an unrun check into a green one.

- The Prettier job covers `scripts/**/*.mjs` as well as `.ts`. A glob naming only the extensions
  that existed when it was written stops covering the tree the moment a file arrives in another
  one.

- **A sampled DNS check on the browser tree**, because Phase 3's acceptance criterion has two
  halves and only one was being measured. "No phone-home" was: the resolver holds no non-loopback
  socket. "No clearnet DNS query" was not — it was inferred from Chromium's documented behaviour
  under `--proxy-server`. The browser's process tree is now polled for port-53 sockets throughout
  the navigation, and the sampler was mutation-tested by launching Chromium with `--no-proxy-server`
  at a clearnet name: it reports `8.8.8.8:53` there and nothing in the acceptance run.

  Its limits are written into the function rather than left implied. Sampling narrows the window
  on a short-lived UDP socket without closing it, and a resolver reached over a Unix socket
  carries no port and would not appear at all. The load-bearing evidence for that half stays the
  refusal check: a clearnet name fails while a VayuWeb name renders, which no configuration that
  quietly resolved names could produce.

### Added — VWIP-0005, the block-exchange protocol

VayuWeb could name a site and could not fetch one from anybody else. The publish path and the
verify path were both built and joined by nothing, so a site was readable only on the machine that
imported it — which is a parallel web with one reader, and the reason Phase 4's acceptance test
was not merely unpassed but unattemptable.

**The proposal, not the code, is the deliverable.** Phase 4's own rule is that code written before
the specification settles is code that will be thrown away, so this is the settling: four messages
(`BHELLO`, `BWANT`, `BLOCKS`, `BDONE`) over the transport contract replication already uses, with
all twelve sections VWIP-0000 makes mandatory.

**It is deliberately smaller than bitswap, and the omissions are the substance.**

- **No advertisement of what a peer holds.** A request discloses interest and that is
  unavoidable — you cannot ask for a block without naming it. Answering an inventory query is
  avoidable, and in a hostile jurisdiction "this machine holds that site" may be the only fact an
  adversary needs.
- **No reason on a refusal.** A peer that lacks a block and one that declines to send it emit the
  identical message. A distinguishable refusal is an oracle for enumerating what a machine hosts —
  the advertisement rule defeated by a side channel.
- **No ledger, no debt ratio, no reputation.** REPLICATION.md 1.4 already refuses a peer
  reputation score and the reason generalises: a score is a standing, a standing can be denied, and
  a mechanism that can deny standing is worth capturing. This admits free-riding, which is stated
  as an accepted cost rather than hidden.
- **No cancellation.** Telling a peer the block arrived elsewhere discloses the requester's other
  connections.

The clause most likely to be got backwards is written out: after a block fails verification, asking
a **different peer for the same identifier** is permitted and expected. That is not the fallback
RESOLUTION.md forbids — the identifier and the verification are unchanged and only the counterparty
differs — and a protocol where one hostile peer can make a site permanently unfetchable would hand
every hostile peer a veto.

The capture analysis names the honest weakness rather than arguing round it: peers must find each
other, and the realistic outcome is that one discovery network becomes the one everybody uses while
the specification's non-normative escape hatch goes unexercised. No text in the proposal fixes
that.

**`registry/src/blockx.ts` is the wire format and nothing else** — encode, decode, and the bounds
of section 5, because the vectors are mandatory and a vector nobody generated is a hex string
somebody typed. An earlier draft of the proposal carried exactly such a hand-typed hex block as an
illustration; it looked like evidence and was worth less than nothing. The `blockExchange` suite is
generated, and a test compares the committed artifact against a fresh generation.

One vector is published as a **recipe** rather than as bytes: a block one octet over the megabyte
limit is 2.1 MB of hex zeros in the artifact, of which every byte after the first carries no
information. The vectors file went from 159 KB to 2.25 MB before this was noticed. A runner builds
the buffer from the stated length and tests exactly what one reading two million zeros would.

### Fixed — two entries of one type were a fork, and the vector set could not express it

Uniqueness is imposed on exactly one entry type: `alias` is at most one and must not coexist with
anything. `cid`, `ipns`, `peer` and `txt` may each appear up to thirty-two times in one signed
record.

RESOLUTION.md's selection rule orders the **types** — "ipns, cid, alias" — and said nothing about
which entry wins when a record carries two of the chosen one. `selectSource` takes the first in
record order. An implementer taking the last, or the shortest, or sorting by value would be equally
conformant and would fetch **different content from the same signed record**.

No attacker is involved, which is what makes it the dangerous kind: the owner signed both entries,
two readers see two different sites, and neither has any way to notice. Deterministic CBOR fixes
the array's order on the wire, so *first in record order* was always well defined — it simply had
never been written down.

**And the conformance suite could not have caught it.** A `ResolutionVector`'s expectation carried
only the source *type*, so "which of the two `cid` entries" had no expressible answer: the record
would have been green in every implementation regardless of which one it picked. A vector set that
cannot state a disagreement cannot catch it. `expect.value` now names the selected entry where the
type is not enough, the runner compares it, and two vectors pin the rule — the second with the
entries reversed, so the first cannot pass against an implementation that merely happened to prefer
those bytes.

### Fixed — one postdated record could evict every other deferred record

The deferral queue holds records that arrived slightly ahead of this peer's clock, so skew costs a
retry instead of a loss. Its bound counted **held encodings, not distinct records**, and
`holdDeferred` pushed unconditionally — nothing deduplicated.

So one postdated record, resent 1,024 times, filled the whole queue with copies of itself and
evicted every genuine deferral from the front. Measured before the fix: **1,024 slots occupied by
one record.** The attacker spends one record it already holds; the peer loses clock-skew tolerance
for every peer it is talking to. 4.6's silent-drop rule does not reach it — that covers records a
peer "already holds", and a deferred record is precisely one that is not held.

**The bound was doing exactly what it said and protecting nothing.** A bound on entries bounds
capacity only when the entries are distinct, which is now REPLICATION.md **5.4**.

**Then a mutation survived again, and again it was the interesting part.** Forgetting to drop the
evicted entry's key from the dedup set failed no test. It leaks twice over: the key set grows
without bound — the very thing the queue's limit exists to prevent, reintroduced beside it — and a
record evicted once can never be deferred again, so a transient skew becomes a permanent refusal.

Writing the test for it found a defect in the *test*, not the code. `deferredCount` cannot see this
at all: once the queue is at its bound the count is at its bound whatever happens next, because a
re-held record evicts another. The first version asserted on the count and failed against correct
code. What distinguishes a leak from a re-hold is *which* records are in the queue, so the sink is
now the probe — it accepts exactly one record on retry and `retryDeferred` reports whether that
record was there to be retried.

Three more mutations, all now failing: dedup removed, the key set never cleared on retry (a
transient skew becoming permanent), and the evicted key left behind.

### Fixed — two clauses written today that closed the example instead of the property

Both are in VWIP-0005, both were added in this session's audit, and both are the same mistake:
fixing the case that prompted the finding rather than the thing the clause was protecting.

**3.6.a stopped at the message boundary.** It said a `BWANT` MUST NOT name the same identifier
twice — closing the sixty-four-copies-in-one-array attack that was found. Section 5 permits
**eight outstanding `BWANT`s per connection**, and nothing forbade a second one naming an
identifier already outstanding in the first, so the same attack ran again across eight messages.
Eight times rather than sixty-four, and equally free. Now scoped to the connection.

**6.2 constrained one of four observables.** It required the identical *message*, and 6.2.a had
deliberately moved the duty onto the sender because only the sender can comply. But what a
receiver sees is content, **count**, **order** and **timing** — and each is enough alone. A peer
that emits one `BDONE` per identifier it lacks and one combined `BDONE` for the ones it refuses
has sent byte-identical messages and answered the question anyway. So has one that lists the
refused identifiers last.

New **6.2.c** requires exactly one `BDONE` per `BWANT`, the identifiers in the **request's** order,
and the answer decided in full before any of it is sent. The ordering rule matters more than it
looks: sorting by the identifier bytes would also be deterministic, and would be a permutation of
the *peer's* choosing — **deterministic is not the same as uninformative.** Request order is a
permutation the requester chose, so it carries nothing.

`blockDoneFor` closes count and order by construction and refuses an identifier that was not in the
request. Timing is a rule about control flow that no signature can enforce, and 6.2.c says so
rather than implying otherwise.

Also: a `SPEC_FLAT` helper, after three assertions in this file failed because a normative phrase
happened to **wrap across a line** — the rule present and correct, the test reporting it missing. A
test that fails on the reflow of a paragraph trains people to edit the test, which is how a real
regression eventually gets waved through.

### Fixed — a silent peer could freeze a sync forever, and the fix exposed a second defect

**The same hole VWIP-0005 4.5.a closes for block exchange, still open in the older protocol that
actually ships.** Three clauses combine, each individually right:

- section 5 bounds in-flight `WANT`s at eight, so memory is bounded;
- 4.3 makes declining both legal and *silent* — "**Declining is not an error condition**" — because
  serving is voluntary and Article 28 states duties without a custodian precisely so nobody can be
  said to have failed one;
- and nothing required a requester ever to give up.

`this.outstanding` was decremented in exactly one place: `onRecords`. A peer that greeted and then
answered nothing took all eight slots and kept them for the life of the connection, while breaking
no rule at all. From the outside it is indistinguishable from a slow honest peer, which is what
makes it cheap to do and hard to see. `nextWant` now takes a clock and reclaims a slot whose
deadline has passed; **4.3.b** requires it.

**Then the mutation run found a second defect, by surviving.** Swapping `shift()` for `pop()` in
the reply path failed nothing — and the project's rule is to distrust that. Chasing it showed the
inadequate thing was the comment beside the line, which claimed releasing the oldest slot "cannot
release the same slot twice". It can, and so can any other choice.

No message carries a request identifier, so a reply cannot be matched to its own `WANT`. If a
deadline elapses and the reply then arrives, the deadline has already reclaimed one slot and the
reply reclaims a second — for one completed request. Measured: **nine issuable against a budget of
eight.**

It is bounded rather than closed, and closing it would need a request identifier the wire format
does not have. So the residual is now *stated* in both the code and REPLICATION.md rather than
claimed away, and a test pins the bound: N late replies permit at most N extra, and the window
closes as soon as they stop. A mutation that makes the overshoot unbounded fails it; the
`shift`/`pop` mutation still survives, which is now the documented correct answer rather than a
gap.

The lesson is the one the rule exists for. A surviving mutation is not a fix that needs no test —
it is a question that has not been answered yet, and this one was hiding a false claim in a
comment nobody would have re-derived.

### Fixed — COST.md promised a mechanism VWIP-0005 forbids, and hid a risk in a table cell

**A contradiction created by this session's own work, which makes it the more instructive kind.**
COST.md 3.3 described peers trading storage tit-for-tat, in the tradition of the classic swarm
protocols, under the heading "Redundancy is earned, not bought". VWIP-0005 6.3 — written today —
says *"No ledger, no debt ratio, no reputation. A peer's history MUST NOT affect whether it is
served."* Tit-for-tat **is** a history-based debt ratio. Adding a normative refusal to one document
silently falsified a sentence in another, and nothing compared them.

It was also the **only** reciprocity mechanism anywhere in the corpus, so the paragraph promised
something no specification defined. 6.3 stands, and the honest replacement is weaker than what it
replaces: redundancy is **neither earned nor bought**. A peer holds what it chooses to hold, and
contributing capacity buys no claim on anyone else's disk.

**And the cost table's renewal row answered a different question than its own heading.** The row
is headed *Renewal risk*. The clearnet cell stated a risk — "Lapse, chargeback, or registrar policy
loses the name" — and the VayuWeb cell stated a *mechanism*: "Renewal is a signature plus fresh
proof-of-work". A reader comparing the columns concludes VayuWeb has no renewal risk.

It has one, and it is the same one. `lifecycle.ts` is unambiguous: LIVE → GRACE (30 days,
owner-only renewal) → QUARANTINE (30 days, nobody) → **FREE, open pool**. Forget to renew and the
name is gone after sixty days, exactly as on the clearnet. What VayuWeb removes is two of the three
causes — chargeback and registrar policy — not the lapse.

A comparison table is the densest form a claim takes, and a cell that answers beside its own row
heading is the easiest place in a document to overstate something without writing a false sentence.

Three mutations, all caught — including withdrawing 6.3 itself, which fails the test rather than
satisfying it, so a future decision to permit reciprocity has to be made deliberately instead of
by deletion.

### Added — Article 21.4 is now enforced, and it was being broken in seven places

Constitution Article 21.4 is a **MUST NOT**: "anonymous", "untraceable", "uncensorable",
"permanent", "unstoppable", "cannot be taken down", "your data is safe forever", "100% private",
and 21.4.i, "any unqualified absolute of the same kind". Nothing had ever checked it.

Seven violations were live, including **POSITION.md's own thesis pull-quote** — the sentence set
apart at the top of the document and followed by "Everything below follows from that sentence" —
and two in the FAQ's answer to "So what does VayuWeb actually protect?".

Article 21.5 supplies the test and also explains why careful authors kept missing them:

> The test is what the words assert to a reader who has read nothing else, not what the author
> intended and **not what a longer passage elsewhere qualifies.**

Every violation sat within a few paragraphs of an honest caveat. The author had the caveat in
mind; a reader arriving at the pull-quote does not.

What changed, in each case narrowing the claim to what the design actually delivers:

- **POSITION.md** — the thesis now says there is nobody to petition to take it away, which is what
  the design removes: the *addressable party*. It does not remove a state's ability to seize a
  device, compel a key, or block the network.
- **FAQ.md and README.md** — "nobody learns what you looked up … a VayuWeb lookup tells nobody
  anything" is now about the *lookup*, with the rest said plainly: fetching the content afterwards
  contacts peers, and that traffic reveals which site is being read.
- **WHITEPAPER.md** — "No step in that path contacts a party that could refuse" was contradicted
  by the path's own step 5 in the same diagram, where IPFS peers and volunteer pins can each
  decline. And "impossible to rewrite that history quietly" became detection-with-a-witness, which
  is what a Merkle log actually buys.

`scripts/check-absolute-claims.py` reads the forbidden list **out of the Constitution** rather than
restating it, so amending 21.4 changes the check in the same commit. It runs in `ci.yml` and in
the release preconditions. Eleven checkers now.

**Two things it deliberately does not do, because the first version did them badly.** It does not
scan single words: "permanent" and "anonymous" produced fifty-nine hits and every one was innocent
— "a permanent archive", "it does *not* make you anonymous", a heading reading "**Untraceable
publishing.**" introducing the paragraph saying VayuWeb does not provide it. A regex cannot tell an
assertion from a denial, and a checker with sixty false positives is one somebody switches off,
taking the seven real findings with it. And its denial guard stops at the previous sentence
boundary: a first version looked back a flat sixty characters and **silently swallowed the
POSITION.md thesis**, because "VayuWeb is *not* a place to hide" sits in the sentence before. A
guard that hides the most prominent violation in the corpus while the count still reads like a
result is worse than no guard. Both were caught by mutation.

### Fixed — two publisher-controlled values that nothing constrained

Both are the same shape, and it is not a missing idea in either case. It is a rule already written
down in this corpus, never applied to a third place that needed it.

**A Trusted Types policy name spliced into a security header.** `PUBLISHING.md` 2.2 declares
`csp.trustedTypes: "<policy-name>"`, taken from the site's own `.vayu/manifest.json`, and points
at `CONTENT-SECURITY.md` 2.3 as authoritative. What 2.3 said was one prose row — "Per-site named
Trusted Types policy, same scoping and disclosure" — with no character set, no length and no
forbidden values. `<policy-name>` appeared **exactly once in the entire corpus**.

So the publisher decided what text landed in the header. `*` yields `trusted-types *`, which is
unrestricted policy creation rather than one named policy — a materially larger widening than the
table authorises, obtained without a VWIP. A `;` appends arbitrary directives. A CR or LF splits
the response header outright. Each defeats "No configuration file … may apply either relaxation
globally, and that refusal is not tunable" three paragraphs above, and each is invisible to the
reader-facing disclosure, which announces a named policy whatever the name actually did.

New **2.3.1** pins the value to the CSP `tt-policy-name` production, forbids `*` and
`'allow-duplicates'`, requires validation **before the header is constructed**, and requires a
failing manifest to be served under the canonical `trusted-types 'none'` — refused, not repaired.

**A blind SSRF oracle over every reader's LAN.** `ATTESTATION.md` 3.2 verifies an attestation by
fetching `https://<subject>/.well-known/vayu-attest.json`, and `subject` comes out of the registry
record — chosen by whoever registered the name. Section 4 constrained it in no way at all: no
grammar, no IP-literal refusal, no length, no redirect rule, no bound on the fetched document.

Register any name, publish `subject: "169.254.169.254"`, and every reader's client issues that
request from inside the reader's own network — on first view and again on 4.2's thirty-day
re-verification schedule, without the reader doing anything. The response never reaches the
attacker, but **section 5 makes displaying attestation state mandatory**, so success, failure and
staleness become a rendered oracle. 4.4 disables only *DNS* verification in Private Mode, so the
https path was live in both.

New **4.6** routes verification through the guarded transport, refuses loopback, link-local,
multicast and RFC 1918 destinations unconditionally, constrains `subject` to a DNS name with no IP
literal validated before a URL is built *or displayed*, forbids following redirects, and bounds
the document at 8 KiB.

The rule 4.6 states was already written for the resolver's other two outbound verbs —
`LOCAL-SURFACE.md` 2.1.1 and 2.2, "unconditionally", reasoning that forwarding to the reader's own
network is an SSRF pivot whatever the verb is. Attestation added a third and nobody extended it.

### Fixed — the reserved suite limits did not follow their own stated derivation

`REGISTRY.md` gives the rule and then tells the reader not to check it: the reserved record limits
are "suite 1's non-signature content plus that suite's own key and signature material, rounded to a
whole number of KiB", followed by **"They are not extra room."**

They were extra room. Suite 1's non-signature content is 4,096 − 96 = 4,000 bytes, so suite 4 needs
4,000 + 32 + 7,856 = 11,888 → 12 KiB. It carried **16,384 — 4,096 bytes of slack, more than an
entire suite-1 record.** Suites 2 and 3 carried 2,048 each.

This is the **pre-decode bound on untrusted input**, so the slack is not cosmetic: on the day the
break-glass suite activates, every verifier would parse a third more attacker-supplied bytes per
record than the derivation justifies, forever, with no VWIP having decided it. Corrected to
10,240 / 10,240 / 12,288 in `suites.ts`, `CRYPTO-AGILITY.md` and `REGISTRY.md`, with a test that
recomputes each limit from the rule rather than asserting the number. The old test only checked
that each reserved limit exceeded 4,096, so nothing derived them at all.

**And correcting them made an adjacent claim wrong**, which is the part worth keeping.
"Sizing the outer bound to the largest reserved suite would hand an attacker **four** times the
parsing work" was 16,384 / 4,096 — true of the inflated limit, stale the instant it changed. It is
three, and a second test derives that factor from the suite table too. A number stated beside a
number that changed is the one nobody rechecks.

The pairing is the lesson rather than the arithmetic: **"They are not extra room" was the only
sentence in the passage a reviewer would take on trust, and it was the false one.**

### Fixed — `peer` was a content source nothing could verify

**The substitution that clause 12.1 exists to close, reachable through the front door of the
selection rule.**

`RESOLUTION.md` ranked `peer` third in the content-source order with no condition on it. Step 11
fetches *the CID* and step 12 verifies *the bytes hash to the requested CID* — for a `peer` entry
there is no CID, so step 12 had no operand and the bytes' only authority was the assertion of the
host that sent them. An implementer building a resolver from the document resolvers are built from
dials the key in the record and serves whatever comes back, unhashed. `registry/src/resolve.ts`
shipped `SOURCE_ORDER = ['ipns', 'cid', 'peer', 'alias']` to match.

It was **attacker-reachable, not merely publisher-reachable**. The fallback rule walks the
resolver down the list when an entry "fails", so denying `ipns` and `cid` at the network layer —
cheap — silently downgraded the reader from content-addressed verification to host trust, on a
name whose record, owner and signature were all genuine. That is precisely the substitution "a
reader could never notice".

One sentence in the corpus did refuse it, and the way it failed is the lesson.
`CONTENT-SECURITY.md` section 6 item 10 said a `peer` record "is refused as a content source
unless it can be **snapshot-verified**" — a rule sitting in a list of conformance *tests* in
another document, turning on a term that appeared **exactly once in the entire repository** and
was defined nowhere. A rule stated only as a test of an undefined term is not a rule an
implementer can follow.

A `peer` entry is now a **transport hint**: a host that may be asked for blocks, whose CID still
comes from an `ipns` or `cid` entry and which are verified recursively under 12.1 to 12.3. That is
exactly the shape [VWIP-0005](docs/spec/VWIP-0005.md) gives block exchange, and the only shape in
which asking a named host for content is safe. A record carrying only a `peer` entry now returns
1421.

### Fixed — two documents said "Nothing described here has been implemented"

`RESOLUTION.md` said it while eight modules under `registry/src` cite it as what they implement and
an unmodified browser renders pages through it. `HOSTING.md` said it too, five modules deep — and
**that is the same document whose Status section was corrected earlier in this same session**,
three hundred lines below the sentence that was left standing.

`scripts/check-status-claims.py` exists for exactly this sentence and missed both, on one
adjective: its pattern was `nothing (?:here )?…implemented`, and the text read "Nothing
**described** here has been implemented". Widened, and it caught both immediately.

This is the second time this session that a checker was right until the phrasing moved. The
earlier one counted "any top-level array" as a vector suite; this one matched one exact wording of
a sentence nobody writes twice the same way. Both were mutation-tested by narrowing them back:
each then misses the very defect it had just found.

### Fixed — a ratio the previous fix got wrong, in the paragraph about getting ratios wrong

`REGISTRY.md` said a two-epoch activation floor was "a quarter of the floor … four times sooner
than the charter permits". Two epochs is 5,184,000 seconds and the charter's floor is 15,552,000,
so it is a **third**, and **three** times sooner.

Two things make this worth more than the correction. It was **introduced by the fix** for the
original 60-versus-180 drift finding, so it was new text that no pass had recomputed. And it sits
in the paragraph whose entire purpose is recording honestly how far a subordinate document had
drifted from the charter — the worst possible place for an unchecked figure, since a reader
auditing the severity of the withdrawn rule is handed one inflated by a third. It had already
propagated to `VWIP-0002.md` and to this file before anybody divided.

Corrected in all three, and the ratio is now **derived** by `scripts/check-counts.py` from the two
constants REGISTRY.md states itself, rather than asserted. The deriver reads both numbers out of
the document instead of carrying its own copies — a checker holding the values it checks is a
second source that drifts alongside the first.

Found by a corpus-wide sweep for the defect classes the VWIP-0005 audit turned up.

### Fixed — the first WANT of every cold sync could not be sent

**A real bug, not a documentation defect, and it sat behind a sentence nobody recomputed.**

`REPLICATION.md`'s limits table said the 65,536-byte message bound "holds a full `RECORDS` batch
with framing overhead and nothing more". It does not. Only **fifteen** maximum-size records fit,
and 256 records at 258 bytes — the smallest encoding in this project's own conformance vectors —
is 66,048 bytes and already over.

That false justification reached the code exactly where it would do the most damage.
`nextWant` asks for `wantCount` (256) whenever a peer is that far behind, which is every peer
starting from nothing. `onWant` then gathered up to 256 encodings **with no size accounting at
all** and returned them. `encodeMessage` refused the result — measured on an ordinary log at
COST.md's own 300 bytes per record: 77,593 bytes against a 65,536 limit.

The throw was then swallowed by `send` in `swarm.ts`, whose `catch` destroys the stream under the
comment *"A write that fails is a connection that is gone."* It was not gone. Our own encoder
refused our own message, and the connection was dropped with the failure attributed to the peer —
a silent stall on the first message of every cold sync that looks exactly like a broken network.

Nothing caught it because every existing test syncs a handful of records, where 256 never arises
and the sizes fit.

- `onWant` now counts **bytes** against the message bound, with a stated envelope margin.
- `REPLICATION.md` gains **4.3.a**: a responder MUST truncate to fit, counting bytes rather than
  records, and MUST NOT emit a message it cannot encode.
- The adjacent promise that "an honest reply is never split for a reason the requester cannot
  predict" was **inverted** — the split is unavoidable at scale and falls on a byte total the
  requester has not seen. Corrected, with the consequence spelled out: a requester MUST NOT read a
  short reply as evidence the responder holds no more.

**The margin survived its first mutation, which meant the test was wrong.** Removing
`RECORDS_ENVELOPE_BYTES` changed nothing, because 300-byte records stop the greedy loop well short
of the boundary. Ninety-one record sizes between 200 and 4,096 bytes *do* land in that band. A
single size is a sample and the bug is a boundary, so the test now sweeps a thousand sizes and
asserts every reply encodes; the mutation fails against it. Four mutations in total, all failing
their intended test: the budget removed, the margin removed, truncation to one record (which the
progress test catches), and the specification clause weakened to SHOULD.

### Fixed — the conformance artifact could not be used without this repository

`docs/ROADMAP.md` tells contributors that `conformance/vectors.json` "is readable without any of
this repository". That is the artifact's whole reason to exist — it is a contract for a second
implementation, and a contract whose terms are defined in the other party's source code is not one.
The claim went stale the same day, and the defect was this session's own doing.

- **The `construct` recipe was undocumented.** A reader outside this repository met
  `{"kind":"blocks-of-zeros","count":1,"bytes":1048577}` with no `message` beside it and nothing
  anywhere saying what to build. The vector was not wrong; it was unusable, which for a conformance
  artifact is the same thing. The notes now define the recipe format and every kind, close the
  list, and say that a runner meeting an unknown kind must fail rather than skip — a skipped vector
  reports as a passing one.

- **`generatedFor` still named one document for seven suites.** It said `docs/spec/REGISTRY.md`
  while the file carried vectors for six other specifications. Now a list.

Worth naming separately: **every other test in `vectors.test.ts` imports the generator and the
decoder**, so all of them prove the implementation agrees with *itself*. The new one reads nothing
but the file, which is the only way to test the property the roadmap actually claims.

### Fixed — a checker that was right until the shape changed

Making `generatedFor` a list immediately failed `scripts/check-counts.py`: it counted "any
non-empty top-level array" as a suite, so a metadata list read as an eighth one and two accurate
sentences were sent to the failure list. A heuristic that is right until the shape changes reports
the shape change as a documentation defect.

A suite is now an array **of vectors**, and a vector is an object with a `name`. The same loose
rule had been copied into the new test, and is fixed there too — it asserted `>= 7` and would have
sat quietly at eight.

### Changed — two documents that had gone stale by being true

- **`HOSTING.md` said "No publishing tool exists, no site has been published."** Both were true
  when written and neither survived running the acceptance harness once. Corrected, with the two
  things that *are* still missing named specifically — no standalone publish command, and no
  block-exchange path — rather than folded into a general disclaimer.

  `scripts/check-status-claims.py` did not catch it and was deliberately not extended to.
  The check is whole-document: it fires when a cited document claims no implementation exists.
  HOSTING.md must stay free to say truthfully that the block-exchange path is unwritten, so
  widening the patterns would make a true sentence unwriteable. Per-clause staleness is caught by
  running the system, not by reading it.

- **`ROADMAP.md`'s preamble said every phase is held open by a test a sandbox cannot pass.**
  Phase 3's now passes here. The remaining four are still genuinely out of reach and are listed
  individually, which is more useful than the blanket claim and no longer understates the work —
  the same error the paragraph itself warns about, pointing the other way.

### Adversarial review

Attacked: the new content path end to end, and the acceptance harness itself.

- **The harness's own Article 14 check was measuring the wrong thing, twice.** The first version
  declared a `dnsAttempts` array and a saved `dns.lookup`, used neither, and passed — dead code
  shaped exactly like a check. Replacing it with a read of `/proc/<pid>/net/tcp` then reported
  *fourteen* outbound connections for a resolver that had opened none, because that file is per
  network **namespace**, not per process. The measurement is now a join against the process's own
  socket inodes from `/proc/<pid>/fd`, and it was mutation-tested against a process holding one
  deliberate non-loopback connection: it reports that one and stays empty for the resolver.

- **Eight mutations, each re-breaking exactly one thing.** `sourceValueOf` back to
  `String(value)`; `entriesFrom` dropping `--cid` again; `cidValue` storing the text;
  `assertKnownFlags` made a no-op; the entry build moved back inside the solver skeleton;
  `cidFromBytes` losing its trailing-digest bound; `cidFromBytes` accepting any codec; `resolve`
  rendering hex again. All eight failed the intended test.

- Found **SOUND** under attack: the negative cache bounds, the `CONNECT` refusal, the
  diagnostic-header disclosure default, and the closed content-type list — a sniffed type would
  undo the `nosniff` header from the other side.

- **Two more of this session's own tests were dead checks, and both were caught by mutation
  rather than by review.** The first built an array of getters to prove a length bound runs before
  the loop it bounds, and never fed it to the decoder, so the counter was trivially empty and the
  assertion passed against any implementation. Replaced with an ordering test that makes the two
  orderings return *different codes* — 65 entries whose first element is not a byte string — plus
  a control at 64 that must reach the element check, without which the assertion would also pass
  against a decoder that refused everything.

  The second is worse, because it came with a confident comment about how equality assertions are
  the ones that pass for the wrong reason. It compared the two published `BDONE` vectors byte for
  byte — two identical calls to the same encoder. A mutation adding a `why: "absent"` field to
  `BDONE`, which is the direct defeat of the rule the test exists for, sailed straight through it,
  because the field was added to both. The property is not that two equal things are equal; it is
  that the message type has **nowhere to put the difference**. The assertion is now structural:
  `BDONE`'s encoding carries exactly `t` and `cids`, and any new key is a channel for state the
  specification says must not be observable.

- **Seven mutations against the wire format**, all failing their intended test: the length bound
  moved after the element loop; `UNKNOWN_TYPE` collapsed into `MALFORMED`; the per-entry byte
  bound loosened; the whole-message bound moved after the parse; a reason field added to `BDONE`;
  the encoder's own output check removed; and a limit raised in code but not in the specification.

- **A test of mine asserted an unreachable case.** It claimed a negative `BHELLO.max` is rejected
  as malformed. The CBOR profile has no negative integers in it, so there is no encoding of one for
  a peer to send — a stronger guarantee than the one asserted, and a test describing an unreachable
  case is a test that passes whatever the code does. Now asserted at the profile level, with the
  decoder's own guard kept and labelled as unreachable-until-the-profile-widens.

#### Then the same treatment applied to VWIP-0005, which found seven more

The roadmap ranks attacking a document above writing a module, on the evidence that every defect
found in this implementation was a defect in a document first. A new normative document had just
been added, so it was attacked. Each finding was written as a failing test against the
specification's text before the text was changed, and each fix was mutation-tested by reverting
the clause.

- **The amplification figure in the security section has been wrong twice, in the same
  direction.** It first said the limits "cap one message's leverage at 64 megabytes of response for
  a few kilobytes of request" — 64 blocks at 1 MiB each. But 64 MiB does not fit in a
  1,114,112-byte message, so that reply cannot exist: the bounds interact and the binding one is
  the message size, which makes `BLOCKS.blks` a bound on array iteration rather than on volume.
  Wrong by 64×.

  The correction was **272×**, and it was wrong too, for a worse reason: it divided the largest
  reply by the *largest* request. Amplification is max(response) over **min**(request) — dividing
  by the biggest possible request yields the smallest ratio, which is the opposite of a cap, two
  sentences after the section opens "a small request names a large response". The real figure is
  **19,784×**: a minimal `BWANT` naming one 36-byte identifier encodes to 53 bytes, and the largest
  honest reply to it is 1,048,597. Wrong by another 73×, written by the pass that was fixing the
  first error, and the test written alongside it enshrined the same mistake — so the number carried
  a green check it had not earned.

  Both flattered the protocol, which makes this the class worth naming rather than the instance: an
  implementation sizing per-connection egress budgets from 272× would set them two orders of
  magnitude too loose. The divisor is now the *measured* encoding of the minimal request rather
  than a product of two limits, and the published figure is recomputed from the codec on every run.

- **`BHELLO.max` could raise a receiver's own limit.** 3.4 said only that a peer MUST NOT send a
  block larger than the remote's declared maximum. Read alone that makes the *advertisement* the
  governing bound, so an implementer accepts a ten-megabyte block from a peer that declared ten
  megabytes — a stranger raising the receiver's limit by asking it to. 3.4.a now caps a declared
  maximum at the protocol's and makes the protocol bound win regardless.

- **The identical-refusal rule was written as a duty on the receiver**, who cannot obey it.
  "A receiver MUST NOT attempt to distinguish them by timing" is unenforceable: nothing stops a
  receiver measuring, and a rule only the honest follow is not a rule. The duty is now on the
  sender, who can. And `BDONE` moves from SHOULD to MUST for the same reason — if answering were
  optional then *whether* a peer answers is itself the signal, and an optional message is a
  channel.

- **Two rules combined into a free deadlock.** Eight outstanding requests per connection, no
  liveness obligation on a peer (deliberately), and no requirement that a requester ever gives up.
  A peer that greets and then says nothing takes every slot permanently while breaking no rule.
  4.5.a requires the requester to bound its own wait: the absence of a duty on one side has to be
  paid for by a bound on the other.

- **A `BWANT` could name one identifier sixty-four times** — a request for one block and a demand
  for sixty-four, passing every limit in section 5. Refused by 3.6.a.

- **"No cancellation" was presented as a free win.** It is a trade: a requester that obtained a
  block elsewhere still receives the copy it no longer needs. The cost is now stated, with why it
  is accepted — the wasted transfer is bounded and paid by the requester, while the disclosure
  would be unbounded in time and paid by somebody who never chose it.

- **An overclaim, which is the finding this project treats most seriously.** The
  impossibility analysis said it is impossible to know what a peer holds without it choosing to
  tell you. Falsifying that takes one request: name an identifier, see whether the block arrives.
  A peer that holds it and serves it has answered, and serving is what the protocol is *for* —
  6.1 and 6.2 make a refusal indistinguishable and can do nothing about a success. So an adversary
  who knows a site's root can determine whether a given peer hosts it, at the cost of one transfer.
  What those sections actually close is the **cheap** oracle: bulk enumeration, and probing without
  paying for the transfer. That is real and worthwhile and much smaller than what was claimed. The
  correction is recorded in the document rather than quietly edited.

- Four conformance tests added for the new clauses (7.8 to 7.11), including the one that pins the
  hard case: a peer holding none of the requested blocks and a peer holding all of them but serving
  none must produce the same sequence of messages.

- **`git checkout` on a specification file destroyed all six fixes mid-audit** — the third time in
  this project that restoring from the index rather than from an explicit backup has thrown work
  away. Recovered from the backup taken before the mutation run. The rule that was already written
  down after the second time is the right one and was not followed: mutation cleanup copies from an
  explicit backup, never from the index.

## [0.2.1] — 2026-08-06

**The release 0.2.0 was supposed to be.** `v0.2.0`'s tag exists on the remote and produced no
release: the workflow pushed the tag, then GitHub answered HTTP 422 because the notes were the
entire changelog section — about 200 KB against a 125,000-character ceiling. A tagged commit with
no release is the worst of the three possible outcomes, because from the tag list it looks
finished.

That commit also does not pass its own CI, which is the reason this is a new version rather than
a release page retrofitted onto the old tag. Four workflows were failing on it and all four were
this session's doing: 601 npm dependencies against a supply-chain ceiling of 40, a Prettier job
never run locally, a `Cargo.lock` not regenerated after the version bump, and the notes length
above. Shipping a release page for a commit known to fail its gates would be the decision nobody
would defend out loud.

`v0.2.0` is left in place rather than deleted. It is real history, it is what the tag says, and
rewriting it would be a lie of a different shape.

### Fixed — four CI failures, all of this session's making

- **601 dependencies against a ceiling of 40.** Installing Helia and Hyperswarm took `registry/`
  from 5 resolved packages to 601, and `security.yml`'s supply-chain gate refused it — a gate
  whose own comment says it should "fire on a change of kind rather than on ordinary maintenance".
  It fired exactly as designed, and it was right on the merits rather than merely procedurally:
  neither library was ever imported, because `blockstore.ts` takes the store as an interface and
  `swarm.ts` takes the swarm injected, both deliberately so that neither module decides what a
  VayuWeb node must run. They were installed only to verify against the real thing. Removed;
  `registry/` is back to 5 packages. A protocol whose Article 4 forbids making any operator
  load-bearing should not quietly make six hundred package maintainers load-bearing instead — a
  point `ARCHITECTURE.md` had made about the Node ecosystem earlier the same day.

- **Prettier is a CI job and had never been run here.** Nine files.

- **`cargo test --locked` failed** because `Cargo.toml` was bumped to 0.2.0 and `Cargo.lock` was
  not, so the lockfile could not be used unchanged. Checking whether npm had the same problem
  found that it did and had simply not complained: `package-lock.json` carried 0.2.0 against a
  package.json saying 0.2.1, and `npm ci` accepted it. Cargo refuses the mismatch and npm ships
  it, which makes the npm one the more dangerous of the two — a stale lockfile that nothing
  reports is a stale lockfile that reaches a user.

- **Release notes are truncated at 100,000 characters** with a link to the file, and both the tag
  and the release steps are now idempotent, so a re-run after a partial failure converges rather
  than dying on the tag it just created.

**The claim that needed correcting.** "All gates green" was said after running the ten
`scripts/check-*.py` checkers. The repository has five workflows; that was part of one. The
difference was invisible from inside the sandbox because nothing here runs them, and checking
took a single API call that had not been made.

**And one documentation correction.** The Helia adapter *was* verified against a real node — that
run is what discovered every declared shape in its interface was wrong — and it is **not
reproducible from a clean checkout** now the library is gone. The shapes it taught survive as
tests, which is the part that matters, and `blockstore.ts` says so in its own header.

### Adversarial review

Carried forward from 0.2.0 below, which this release does not add code to: the two
denial-of-service findings, what was attacked and found sound, and what the pass did not cover.
The changes in this version are a dependency removal, a formatter run, a lockfile regeneration
and a workflow fix — none of which adds attack surface, and the first of which removes 596
packages' worth of it.

## [0.2.0] — 2026-08-06

**Protocol version 1**, unchanged, and VWIP-0003 2.5 asks for that to be said plainly along with
what moved underneath it.

**The accepted RECORD set is unchanged.** Nothing in this release alters which registry records a
peer accepts: the schema, the signature rules, the proof-of-work verification and the lifecycle
are all as they were, and every one of the 72 record vectors produces the same verdict.

**The accepted EVIDENCE set narrowed, and the content rules are new.** `verifyEquivocation` now
refuses a report whose two records are not attributable to the key they accuse, so a peer running
0.1.0 will record forged evidence that a peer running this release discards — a difference in
behaviour with no difference in protocol version, which 2.5 names as the combination most likely
to surprise. `RESOLUTION.md` gains clauses 12.1 to 12.3, which are new normative rules rather than
changed ones: they cover ground the document was silent about.

Pre-`1.0.0`, so the public interface is explicitly unstable and this MINOR release changes it —
VWIP-0003 2.2, stated here rather than left to be discovered.

### Adversarial review

Run against everything under this heading and everything it touched, before the version was
bumped rather than after — `docs/ROADMAP.md` and `CHANGELOG.md`'s own rule that the audit gates
the release. The question asked was not "does this do what it says" but "what would I do to this
if I wanted it to fail". Two defects were found, both in code written the same day, and both were
denial of service rather than a wrong answer — which is itself the lesson, because every test
written that day asked what the code *returns*.

**The connection cap leaked a slot on every refusal.** `serve.ts` incremented its counter and
returned before registering the handler that gives the slot back, so an attacker who could cause
as many refusals as the cap allows killed the browsing proxy permanently: no crash, no log entry,
just a resolver answering 503 to its own user forever. Reproducing it through real sockets did not
work — the client's `connect` event fires before the server's `connection` handler for later
sockets, so concurrent dials never reliably put three connections in flight. That failure is why
`ConnectionCounter` now exists as a separate class: accounting is policy, policy belongs where it
can be exercised as data, and a defect only reproducible by racing the operating system is a
defect with no regression test. Four mutations fail, including the original defect restored
exactly, and a double-close that would otherwise mint capacity.

**The deframer did quadratic work for linear input.** A peer dripping a 64 KiB frame one byte at
a time cost the receiver about 2.15 GB of memory copying and 890 ms of CPU, for 64 KiB of its own
bandwidth — roughly 33,000:1, and with the connection cap at 64 peers a sustained drip pins every
core. `REPLICATION.md` 2.4 promises that a hostile peer's effect stays "within the limits of
section 5"; work quadratic in a bounded quantity is outside them, because a bound stops being a
bound when the cost of reaching it is not linear.

**The first fix was seven times slower than the defect, and the metric said it was fine.**
Replacing the per-push buffer rebuild with a chunk list moved the cost into `Array.shift`, which
is linear in the array's length, so sixty-five thousand one-byte chunks were quadratic all over
again — 6,692 ms against the original 891 ms. `copiedBytes`, the counter written specifically to
bound this defect, reported no change, because the cost had moved out of the resource it
measures. **A bound on one resource is silent about every other one, and a fix validated only by
the metric it was written against is a fix nobody has measured.** The class now carries a second
counter, the work is 2.00 units per byte at every frame size tested, and both quadratic
implementations — the original and the bad fix — fail as mutations.

**Attacked and found sound**, recorded because a clean result is only evidence if it says what
was tried. Response splitting through the proxy: three shapes of CRLF in the `Host` header and one
in the request target, all refused with 400 before serialisation, because the head parser splits
on CRLF and the host grammar admits neither. Frame-length inflation: a declared length is checked
before anything is buffered against it, so a four-byte prefix naming a gigabyte costs nothing.
Slow-loris on the browsing proxy: bounded by the head size limit and the head timeout, both
tested. Transport authentication used as evidence about a record: `swarm.ts` never reads the
remote public key and a test greps the source to keep it that way. Private keys reaching disk on a
keyring-less machine: refused by construction, and the test makes the fallback closure `panic!`
so a regression says why.

**What this pass did not cover, stated rather than implied.** It attacked the code added under
this heading. It did not re-attack the specification corpus — that was the 2026-08-04 audit, whose
findings are dispositioned in `docs/AUDIT-FINDINGS.md` — and it is not the independent review
Article 44.6 asks for, which the same party that wrote the code cannot supply. Bitswap against a
hostile peer on a real network, and the browser integration, are unattacked because they are
unbuilt.

### Added — the client's secret handling, in Rust, where the rule cannot be relaxed

- **`client/` is a Rust crate and `client/src/secrets.rs` is its point.** PRIVACY.md 7.4 says a
  private key on a platform without a keystore is *"a refusal, not a downgrade"*. As prose that is
  a rule somebody implements correctly and relaxes six months later because the build fails on a
  machine with no keyring. As a type it does not compile: `Sensitivity::KeystoreOnly` has no path
  to the file fallback, and the test that proves it makes the fallback closure `panic!` so a
  regression says why rather than merely failing.

- **A keystore that refuses is not a keystore that is absent.** Collapsing the two would turn
  every transient keyring failure into a private key on disk — the forbidden downgrade arriving
  through an error path rather than through a decision. `available()` and `set()` are separate
  questions and both are tested.

- **The disclosure is attached to the value.** "The client MUST report that the weaker guarantee
  applies" implemented as "the caller should probably mention it" is how a requirement becomes a
  comment, so `Placement::FileFallback` carries the sentence a user is owed.

- **A `Secret` never prints itself**, in `Debug` or `Display`, which satisfies 7.3's "never placed
  in […] an error message" without asking every future caller to remember; and `Secret::take`
  zeroises the caller's buffer, because a constructor that leaves the original lying around has
  moved the problem rather than solved it.

- **Gated in CI with no GUI libraries installed**, deliberately: a security rule that can only be
  checked by launching a window is a security rule nobody checks. `cargo test --locked`,
  `cargo fmt --check` and `cargo clippy -D warnings`.

### Added — blocks on disk, with the verified traversal still in front of the network

- **Helia is not a dependency, and that is the design working rather than a compromise.** Nothing
  imports it: the store arrives as an interface and the CID codec as another, exactly as
  `swarm.ts` takes its swarm injected. Installing Helia and Hyperswarm took `registry/` from **5
  resolved packages to 601**, and `security.yml`'s supply-chain gate refused it at a ceiling of
  40 — a gate whose own comment says it should "fire on a change of kind rather than on ordinary
  maintenance". It fired exactly as designed, and it was right: for a project whose Article 4
  forbids making any party load-bearing, 601 packages is 596 more parties who can reach a user's
  resolver. The libraries are gone; the interfaces they taught are what remains.

- **`registry/src/blockstore.ts` keeps `fetch.ts` in the path, which is the whole design
  constraint.** Helia will assemble a UnixFS tree itself, and using that would be shorter, faster
  to write, and would move every check in RESOLUTION.md 12.1 to 12.3 into somebody else's library
  — or out of the path entirely, with nothing in this repository saying which. So the blockstore
  is exposed as a `BlockSource` and nothing more. To this code a buggy library and a lying peer
  are the same thing, and a test corrupts a single leaf to prove it.

- **Four shapes, and the interface was wrong about all of them.** `AsyncBlocks` declared
  `Promise<Uint8Array>` because that is what a blockstore obviously returns. `blockstore-core`
  declares `*get(key, options)` — a synchronous await-or-value generator — and Helia's
  `BlockStorage` wrapper returns an **async** generator over it. An `await` on either is a no-op
  that hands back the generator. The whole suite passed against a fake returning what the
  interface claimed, and the first run against a real Helia node failed inside `sha256` with
  "data argument must be of type string or an instance of Buffer".

  **A fake that returns what the interface says cannot find a wrong interface.** The double now
  returns an async generator from `get` and is a generator *function* for `put`, matching the
  library rather than the assumption; all four shapes are pinned by name.

- **The async branch must be checked before the synchronous one**, and that was a second failure
  after the first was fixed: an `AsyncGenerator` also has `next`, but its `next()` answers a
  promise, so reading `.value` synchronously yields `undefined` and the adapter reports "not
  bytes" for a store that is working perfectly.

- **A per-block deadline, because a promise with no deadline is a request a peer holds open.**
  RESOLUTION.md step 11's 120-second total budget is unreachable without one — a peer sending a
  byte a minute never quite fails. The test races the refusal against a longer timer rather than
  measuring elapsed time, because a bare assertion would *hang* if the deadline were removed, and
  a hang reports as a CI timeout instead of as a missing defence.

- **The prefetch budget counts distinct blocks; the traversal's counts every visit.** They answer
  different questions — one bounds the network, the other bounds the work a repeated link can
  cause — and conflating them would let one of the two attacks through.

### Added — the reference transport binding, and a driver that could only ever answer

- **`registry/src/swarm.ts` carries the messages `replicate.ts` produces.** Discovery on
  `BLAKE2b-256("VayuWeb-Replication-v1")`, computed rather than written down so the topic cannot
  drift from the string the specification names. The Hyperswarm instance is injected rather than
  constructed, which is not test scaffolding: REPLICATION.md 2.2 says this binding is **not
  normative**, and a module that decided a VayuWeb node must speak HyperDHT would be the thing
  Article 4 forbids, arriving through a dependency.

- **Framing is the gap between "ordered stream" and "framed channel".** Hyperswarm delivers the
  first; section 2.1 asks for the second, and the difference is a length prefix. A declared length
  is checked against the limit *before* anything is buffered against it — four bytes naming a
  gigabyte is the cheapest denial of service a framed protocol offers. A bad frame drops the
  connection, because a stream cannot resynchronise; a bad *message* does not, because
  REPLICATION.md 3.2 says refusing to speak to a peer that knows a message you do not is how a
  protocol becomes unextendable.

- **The remote public key is never read, and a test enforces it against the source.** Hyperswarm
  hands over an authenticated remote key, and it is exactly what an implementer reaches for when
  they want to skip work for a peer they have seen before. REPLICATION.md 2.3 forbids treating
  the channel as evidence about a record: a record's authority is its signature, and skipping
  verification for a "known" peer removes the only check there is.

- **The first driver could serve and could never catch up.** It sent `HELLO`, answered what it
  was asked, and never called `nextWant` — so two such peers connect, complete a handshake,
  report no error, and sit there permanently diverged while looking exactly like a working
  connection. The session answers questions and deliberately does not ask them, because how
  aggressively to pull is a resource decision rather than a protocol one, and the transport is
  where that decision belongs. Found by the convergence test rather than by reading, and now
  pinned by its own test so it cannot return quietly.

### Added — the resolver runs: sockets under the pure handlers

- **`registry/src/serve.ts` binds what `proxy.ts` and `control.ts` only described.** The split is
  kept: every policy decision stays in the pure handlers, so a refusal is still exercised as data.
  What lives in the new file is the part that cannot be a pure function — listening, reading a
  head, writing a response, and the file mode on a socket. `vayuweb-registry serve` starts both.

- **The HTTP head parser is deliberately strict**, because every leniency in one is a
  request-smuggling primitive waiting for a second parser to disagree with it. Obsolete line
  folding, duplicate headers, non-token header names and anything but HTTP/1.0 or 1.1 are refused
  rather than resolved: first-wins and last-wins are both defensible readings of a duplicate
  header, which is exactly why picking one is the wrong move. No request body is read on either
  surface, because nothing in either API takes one and a body reader is an unbounded allocation
  controlled by whoever opened the connection.

- **The control socket is `0600` inside a `0700` directory, and both halves are asserted.** A
  socket anyone on the machine can connect to is a control API anyone on the machine has; a
  `0600` socket in a world-writable directory is one anybody can replace. `assertSocketAddress`
  runs before the bind, so a TCP address is a thrown error rather than a listening port.

- **A control token that could never authenticate is now refused at bind.** A token that does not
  decode to 32 bytes can never match, so the resolver would bind an API nobody can reach and say
  nothing — every request answering 401 exactly as a wrong guess would. Found by writing the
  tests with a 64-character token that decodes to 48 bytes and having nothing to distinguish a
  bad token from bad code. The token is generated per run and printed once, never written to
  disk: a token in a config file is a token in a backup, a screenshot and a support ticket.

- **Two of the project's own gates caught this work**, which is the first time they have caught
  something written after them. `check-listeners.py` refused a comment that merely *mentioned*
  the retired control port — the number is not written anywhere here, including as a test
  fixture, so it cannot be reintroduced by copying a line that looked authoritative.
  `check-source-hygiene.py` refused a default clock reaching for `Date.now()`; the proxy's `now`
  is required rather than defaulted, and the real clock exists only at the process boundary.

- **Three test inadequacies, found by mutation and by the tests failing honestly.** The control
  tests put the token in the marker header instead of `Authorization`, so every request 403'd and
  the disclosure test passed while asserting nothing — a 403 body trivially contains no secret.
  The directory-mode test let the resolver create a fresh directory, so it was testing `mkdir`
  rather than the tightening, and passed with the `chmod` deleted; it now starts from a
  deliberately world-writable directory. And the line-folding guard turned out to be **genuinely
  redundant** — a folded line is already refused for having no colon or a non-token name — so its
  comment says so rather than implying it is load-bearing.

### Fixed — the deadcode gate, in four ways, none of them visible by reading it

- **`export { X }` was never examined.** The pattern matched `export function`, `export const`
  and their siblings; a bare re-export statement is none of those, so a whole syntactic form went
  unchecked. A gate that silently declines to look at something is worse than one that looks and
  is wrong, because nothing in its output says so.

- **A hit could come from anywhere.** The search was for the bare word across the corpus, so any
  symbol sharing a name with something used elsewhere was permanently invisible — an
  `export const sha256Helper` counted as used because `sha256` appears in another module. The
  evidence now has to be a dependency: a consuming file must name the symbol *and* import from
  the module that defines it.

- **A re-export could justify itself.** With both of those fixed, the case that started this
  still passed. A re-export names its symbol twice in the defining file — once to import it, once
  to export it — so the "used elsewhere in this file" rule was satisfied by the re-export
  statement. That rule is right for an internal helper and exactly wrong here.

- **There was no floor.** Narrowing the export pattern so `function`, `const`, `interface` and
  `type` were ignored dropped the corpus from 305 matches to 18 and still printed OK. A gate that
  has stopped matching is indistinguishable from one with nothing to report unless it says how
  much it looked at.

  Fixing the first three immediately surfaced a real finding: `store.ts` re-exported
  `GRACE_SECONDS` and `QUARANTINE_SECONDS`, which every consumer imports from `lifecycle.ts`
  instead. The re-export and the import feeding it were both inert and had been invisible
  throughout. Two exports in `fetch.ts` — a protobuf field written and never read, and a
  `ContentError` re-export that contradicted the module's own contract that no other error type
  escapes it — were found the same way and removed.

  Two of the mutations used to check this were themselves badly chosen, and both times the probe
  was at fault rather than the fix: relaxing a restriction cannot fail a clean tree, and a name
  the defining file already imports is covered by the same-file rule before the dependency rule
  is reached. The discipline says distrust a mutation that does not fail; it does not say the
  code is guilty.

### Added — verified traversal, and the half of fetching the specification never described

- **`RESOLUTION.md` specified fetching as though a CID addressed one resource.** Step 12 said
  "verify the bytes hash to the requested CID" — exactly right for one block, and silent about the
  other n − 1. A site root is a directory whose links are CIDs and a file over one chunk is a node
  whose links are CIDs, so an implementer following step 12 literally verifies the root, gets an
  authentic directory node, and then believes whatever arrives for the files it points at.
  Substituting an `index.html` under a genuine root is then free, and it is the one substitution a
  reader could never notice: the name, the record and the root are all real. Article 44.6 makes
  that a defect in the document, not an omission a careful reader is expected to repair.

  New clauses 12.1 to 12.3 state the three rules the old text left out — verification is
  recursive; the traversal is bounded rather than only the output; declared UnixFS metadata is
  content rather than authority.

- **`registry/src/fetch.ts` implements them.** Every block is checked against the CID *that
  referred it*, and nothing in a block is acted on before that block verifies. The bound is on
  blocks and depth, not on assembled bytes, because a dag-pb node may link to the same child twice
  — thirty blocks describe over a billion leaves, and a resolver that catches that on the 256 MiB
  resource cap catches it only after doing the work an attacker wanted done. `filesize` and
  `blocksizes` are publisher-chosen fields covered by the node's own hash, so a lie there is
  self-consistent rather than detectable by hashing; nothing allocates on a declared size, and a
  node whose declarations disagree with what arrives is refused.

- **Every refusal maps to a numbered error, which needed fixing once.** `decodeCid` throws
  `ContentError`, a type a caller catching `FetchError` would miss entirely — so a CID naming a
  codec that is not content surfaced as an internal error rather than as a refusal, telling an
  operator the resolver was broken when a peer had sent rubbish. Found by a test that expected a
  code and got a stack trace.

- **Three of the new tests were passing for unrelated reasons, and mutation found all three.**
  The per-chunk size check and the blocksizes-count check were both being caught by the
  *filesize* check instead, because the fixtures broke more than one relationship at a time;
  each now breaks exactly one. The duplicate-directory-entry test built its UnixFS `Data` as a
  field tag with no value after it, so the node was refused as malformed protobuf before the
  duplicate was ever looked at — it passed while testing the varint decoder.

- **Two of the five traversal bounds had no test when they were written.** `linksPerNode` and the
  accumulated-bytes cap could each have been deleted with nothing to notice, which is the same
  defect as any other guard nothing exercises — found by listing the limits and asking which the
  tests mention. Both are covered now, the byte cap on its `Budget` rather than end to end,
  because reaching 256 MiB through the traversal means allocating a quarter of a gigabyte in CI
  to prove one comparison. Fourteen mutations of `fetch.ts` now fail, including an off-by-one at
  the byte-cap boundary.

- **One test could hang CI rather than fail it.** Removing the block budget did not make the
  amplification test fail; it made it expand 2^30 leaves until the harness killed the run. A hang
  reports as a timeout rather than as a missing defence, so the block source now counts its own
  calls and gives up loudly above the budget.

### Changed — the implementation language is not fixed by the protocol

- **`ARCHITECTURE.md` gains "Implementation Language".** Everything a second implementation must
  match is language-neutral by construction — CBOR, Ed25519, Argon2id, BLAKE2b-256, dag-pb,
  base32 — and the conformance vectors are hex and JSON for the same reason. The reference
  implementation is TypeScript because the reference *transport binding* is; Hypercore, Hyperbee,
  Hyperswarm and HyperDHT have no mature equivalent elsewhere, and that dependency is now stated
  rather than absorbed. A substrate only one ecosystem implements is a substrate whose ecosystem
  is load-bearing, which is the concentration Article 4 refuses, arriving through the toolchain.

  Rust is recorded as a first-class choice and the expected one for the desktop client (Tauri is
  already a Rust backend), the resolver and proxy (long-running processes whose entire input is
  bytes from strangers), and the proof-of-work worker. With two limits stated plainly: a component
  in another language passes the same conformance suites or it is not the same component, and a
  second language written by the same hands is not progress toward Phase 6, which asks for parties
  with no common employer or funder.

### Fixed — eleven documents saying the project has no implementation

- **Nobody wrote a false sentence; a true one went stale, in eleven places at once.**
  `ROADMAP.md` opened with "Nothing here is implemented" and told contributors "not with code —
  there is no code to write against yet". `CONTRIBUTING.md`, the file a newcomer opens to decide
  what to do, said "there is no implementation yet". `README.md`'s repository tree annotated
  `registry/` as not yet implemented. Eight specifications carried "Status: Draft — not yet
  implemented", `REGISTRY.md` among them — against sixteen modules that cite it by name as the
  thing they implement.

  Understating progress is not the safe direction. It is as wrong as overstating it, and it
  teaches a reader to discount everything else on the page — which is expensive in a corpus whose
  method rests on its documents being trustworthy about their own state. Each now says what is
  true: which parts are built, which are not, and that no phase past 0 has met its acceptance
  test. The reasoning the old sentences carried is kept where it still applies — code written
  before the specification settles is code that will be thrown away, and attacking a document is
  still worth more than writing a module.

- **`scripts/check-status-claims.py` makes the class mechanical.** Two rules, both deriving their
  evidence from the source rather than from a hand-written map, because a map is another
  restatement and restatements are what go stale. A specification may not claim to be
  unimplemented while a non-test module under `registry/src` cites it; a project-scope document
  may not claim the project has no implementation while any module exists at all. Adding the code
  is what fails the check — nobody has to remember the script is there.

- **Two of the guard's own defects were found by mutating it, and both were structural.** The
  first version could not see `README.md`, `CONTRIBUTING.md` or `ROADMAP.md` at all: nothing
  implements a README, so the citation rule had no evidence to work from, and reverting
  CONTRIBUTING.md's stale sentence passed cleanly. Hence the second rule. The second version
  treated a triple-backtick fence as one enormous inline-code span and swallowed its contents, so
  `README.md`'s directory tree could assert anything it liked; a fence in this corpus holds
  pseudocode, wire formats and directory listings, every one an assertion rather than a
  quotation. Eight mutations now fail, including emptying `registry/src` — a guard whose evidence
  has vanished must say so rather than pass.

### Fixed — equivocation evidence nobody had to sign

- **Any owner key was enough to manufacture equivocation evidence against its holder.**
  `verifyEquivocation` checked that two records named one `name.tld`, at one `seq`, with one
  `ownerKey`, and that their hashes differed — everything the report claims except *who signed
  it*. An owner key is public; it appears in every record its holder ever published. So the
  attack was: take a victim's key, mint two records naming it as owner for one name at one `seq`,
  sign both with a key of your own, and send the pair. Every peer receiving it verified it,
  recorded it, and forwarded it on. Nothing in the pair was the victim's but their public key.

  `REPLICATION.md` 6.2 already listed signatures first among what a recipient checks, and 6.4
  already named the consequence of skipping them — "a mechanism able to strip a name on evidence
  is a mechanism able to strip a name on *manufactured* evidence". The gap was between the
  document and the code, and the unit test covering the area stated the exact threat in a comment
  ("a report taken on trust is a way to get any name reported as compromised by anyone who can
  send a message") while exercising only a duplicate and two bytes of garbage.

  The fix is a signature check and deliberately **not** a validity check. Expiry, proof of work,
  chain position and lifecycle state are reasons a record would be *refused*, and requiring them
  would hand an equivocator a one-line evasion: break your own proof of work in both halves and
  no report of you can be verified. A signature is different in kind — it is the only thing that
  makes a record attributable, and equivocation is a claim about who signed. Both are now written
  into the specification rather than left as an implementation opinion (6.2.1 and 6.2.4).

- **`TRANSFER` is attributed by its countersignature, not its signature.** A `TRANSFER`'s `sig`
  is the *transferor's*, and the transferor's key is not in those bytes at all — the same
  self-containment gap that gives `VectorState.transferorKey` its reason to exist. The named
  owner's own signature is `coSig`, which the schema requires on `TRANSFER` and forbids
  everywhere else. An implementation reading `sig` for every operation would refuse every report
  involving a transfer, silently, and precisely in the window Article 33.4 leaves a name in flux.
  Written down as a table in 6.2.2 so it is not a thing each implementer has to rediscover.

- **One limit is now stated rather than left to be discovered.** Attribution is by `ownerKey`, so
  a transferor signing two different `TRANSFER`s of one name at one `seq` to two *different*
  recipients is not reported: the records name different owners. Detecting it needs the
  transferor's key, which is not in the evidence, and evidence that needs outside state is
  evidence that can be faked by whoever supplies the state. `REPLICATION.md` 6.2.3.

### Added — the `pow` conformance suite, and a `log2` that two peers can disagree about

- **`PROOF-OF-WORK.md` now requires the rate term to be computed exactly.** Its pseudocode says
  `floor(log2(n / 512))`, and `log2` is an implementation-approximated function in ECMAScript, C,
  Python and Go alike — a result one ulp below an integer at an exact doubling floors to one
  less. That is a one-bit difficulty disagreement between two peers that each believe they
  conform: one rejects a record the other accepted, permanently, on a record that is otherwise
  entirely valid and cost 64 MiB per attempt to produce. Every other quantity in that section is
  quantised specifically so two peers agree on `n`; a transcendental at the last step gave it
  away for nothing. The document now states the integer formulation (count the doublings) and the
  vectors pin every boundary. This implementation agrees across the whole reachable range, which
  is now established by a test walking it rather than assumed.

- **`pow` vectors in `conformance/vectors.json`** — 40 of them, and not one Argon2id evaluation.
  The split is the point: Argon2id is a standard with published vectors of its own, while the
  base table, the rate term, the trailing window, the salt preimage and the leading-zero-bit test
  are local to this protocol and are therefore what two implementations diverge on. Passing the
  suite does not demonstrate a correct Argon2id and does not claim to.

- **Four of five mutations survived the first version of that suite, which is why it was
  rewritten.** It computed `expect: baseBits(labelLength)` — calling the function under test — so
  breaking the implementation moved the expectation with it. Every expectation is now a literal
  transcribed from `PROOF-OF-WORK.md`, the salt excepted because it is a digest, and the runner
  reads the committed artifact rather than regenerating. All six mutations fail against the
  rewrite. A vector whose expected value comes from the implementation is a snapshot of what that
  implementation does, which is the opposite of a specification — and it is the same shape as the
  hand-written coverage list and the CSP test that pinned its block by name.

### Added — the equivocation conformance suite, and what building it found

- **`equivocation` vectors in `conformance/vectors.json`** — eleven pairs of record encodings and
  the one boolean each must produce, per `REPLICATION.md` 6.2: two records, no state, no clock,
  no prior view. Equivocation had been covered by unit tests alone, and writing the contract is
  what surfaced the forgery above. That is the pattern this project keeps
  producing: the defect was invisible from inside the implementation and obvious the moment the
  question became "what would somebody else's code do with these bytes".

  Both answers are pinned, not only the refusals, and a test enforces it — a suite made entirely
  of forgeries passes against an implementation that never reports anything, and under-reporting
  here is silent.

- **The artifact comparison now covers all five suites.** The record suite had been compared
  against a fresh generation since the beginning; `convergence`, `resolution` and `replication`
  were only checked for existence, so a generator change could have moved their bytes without the
  diff appearing in the committed file — which is the entire purpose of committing it.

- **`scripts/check-counts.py` derives the suite count.** Two documents were left asserting "four
  suites" while the file carried five. The vector *count* was already derived; the *suite* count
  was not, and the two go stale for different reasons — one drifts when the generator changes,
  the other the moment somebody adds a suite. Conformance items 8.5 and 8.6 in `REPLICATION.md`
  now name the vectors that pin them.

### Fixed — the last three findings: a clock that could stop, and a revocation that said "expired"

- **The epoch counter could stall forever, justified by a paragraph naming that exact failure.**
  A boundary required **both** fourteen days of `notBefore` time *and* a checkpoint computed since
  the last one. Checkpoints came every 10,000 entries and nowhere else, so a quiet log produced no
  checkpoint, no boundary, and a frozen epoch — while the rationale two paragraphs down says log
  progress alone "would stall the epoch counter whenever registration activity dropped, which
  over a century is a near certainty". The condition being justified caused the failure the
  justification warns about. It would also have breached Article 2.5's fourteen-day ceiling: an
  epoch that cannot end is longer than any bound. A boundary now triggers a checkpoint, which
  keeps what condition 2 is for — the epoch anchored to log state a peer verifies rather than a
  clock it is told about — at a cost of 32 bytes on an idle log.

- **A revoked name told the reader its registration had expired.** `RESOLUTION.md` step 8 said to
  compare `now` against `notAfter` directly, which is right for four operations and wrong for
  two. A `RELINQUISH` sets `notAfter == notBefore` and skips grace, so the comparison reports
  `NAME_EXPIRED` through quarantine. A `REVOKE` keeps `prev.notAfter`, so it reports the name
  **live for the remainder of its term** — a resolver following the step literally serves content
  from a key its holder has declared compromised, the one outcome `REVOKE` exists to prevent.

  The implementation computed the state correctly and never served one, so this was not a hole.
  What it returned was 1410, *"This name's registration has expired"* — false, since the
  registration has not expired, and it sends the reader to renew, which is the single action a
  revoked name must not invite. Now 1412 `NAME_REVOKED`, with a message that says what happened,
  and step 8 defers to the lifecycle rules rather than restating a comparison that only works for
  some operations.

- **`LOCAL-SURFACE.md` told an implementer to repair the value it also told them to refuse.**
  §2.1 rejects a `Host` "with a port" as part of the DNS-rebinding defence; §3.2 said the resolver
  "strips a trailing dot and any port". §2.1 wins: repairing a malformed authority is how a
  request that should have been refused acquires a cache entry instead.

  **The first version of the revocation test passed against the deleted fix.** It asserted the
  1412 constant and the specification's table and never resolved a revoked name — so removing the
  branch that returns it changed nothing. A test that checks a value exists is not a test that the
  value is ever produced. Rewritten to resolve one, twice, including deep into what would
  otherwise be the live term. Five mutations now fail.

  **Every finding in `docs/AUDIT-FINDINGS.md` now carries an outcome.**

### Fixed — the entire `Permissions-Policy` header was specified and never sent

- **The proxy emitted the CSP and eight of the nine other canonical values.** `Permissions-Policy`
  — the whole 44-token deny list, every powerful feature `CONTENT-SECURITY.md` enumerates as
  closed — was **never sent at all**. Camera, microphone, geolocation, serial, HID, USB, the
  Privacy Sandbox surface: each documented as denied, each permitted by the headers a reader
  actually received. Conformance item 1 requires "the three canonical values in sections 2 and 3
  emitted byte-identically on every response", and one of the three was absent.

  **The test that should have caught it was the reason it survived.** It pinned the CSP by
  *naming its block* — `spec.split('<!-- canonical:content-security-policy -->')` — and a test
  that names the block it checks cannot notice a block nobody wrote a test for. The replacement
  enumerates the `<!-- canonical:… -->` markers in the document and asserts each one is emitted
  and byte-identical. Mutation-tested three ways: dropping the header, dropping one token from
  its value, and adding a fourth canonical block to the specification. All three refused.

  This is the second time in this audit a check has been the reason a gap persisted rather than
  the thing that closed it — the first was the vector-coverage list, hand-written and therefore
  blind to the six codes nobody typed. Both had the same shape: an expectation enumerated by hand
  where it could have been derived from the source.

- **`clipboard-read` and `clipboard-write` were reported as impossible.**
  `CONTENT-SECURITY.md` said "**no Permissions-Policy token exists** for notifications, push,
  clipboard, …". Both clipboard tokens are in the W3C permissions-policy registry. The document
  reported an omission as an impossibility, which is the one way its own floor rule can fail
  silently: "a feature not named here SHOULD be denied" only produces an action if someone
  believes there is a token to deny it with. Both are now in the header — a clipboard read is a
  page reading whatever the reader last copied, which on a machine where somebody handles keys is
  not a small thing.

- **`PRIVACY.md` contradicted itself about where a secret lives.** §7: secret material is "Never
  written to disk except in the platform keystore", with no fallback clause. §4's inventory:
  control-API bearer token, "On disk, mode `0600`". One document, two rules, and the table
  described the fallback as though it were the rule.

  Resolved the way the same document already resolved it for Private Mode's ephemeral profile:
  the fallback is normative, limited to the control-API token alone, and the client MUST report
  that the weaker guarantee applies. A private key or the content-cache key on a platform without
  a keystore is a refusal, not a downgrade. Worth noting that this recurred *in the same file*
  after that lesson, which is the argument for the guard rather than for the correction.

### Fixed — a record type the registry does not carry, and the log anchor nothing carries

- **`ATTESTATION.md` described "an ordinary registry record type, `attest`".** Two readings, both
  unimplementable. As an **operation** it is outside Article 29.4's closed set and outside
  `REGISTRY.md`'s six, so a conformant peer rejects it `UNKNOWN_OP`. As a **`records` entry type**
  it is outside `REGISTRY.md`'s five, and that document's rule is explicit — "Unknown `type`
  values are stored and replicated unchanged but MUST NOT be acted upon" — so an attestation would
  propagate and no resolver could display it, which is the entire mechanism.

  The ambiguity was itself the defect: "record type" is the phrase Article 29.4 uses for
  operations, so an implementer could not tell which layer it was at. `ATTESTATION.md` now states
  the entry reading, that neither layer carries it, and that adding it is a Standards Track VWIP
  against `REGISTRY.md` — the same refusal applied to `PUBLISHING.md`'s inline digests and
  `LOCAL-SURFACE.md`'s cross-name allowance this month, and the third instance of one document
  quietly extending another's closed set.

  A new test refuses **any** specification naming an operation or entry type the registry does
  not carry. The existing guard compares `OPERATIONS` against the charter, which catches the
  implementation drifting; it does not catch a document proposing something nobody implements,
  and that is the direction all three of those findings went.

- **Articles 29.5.d and 31.1 require a log anchor in every record. No field carries one.** 31.1
  binds the proof of work to three things — name, ownership key, and "a recent log anchor" — and
  the schema delivers two.

  **The gap is measured rather than asserted, and it is smaller in one direction than it looks.**
  The salt derives from the record's canonical bytes, which include `notBefore`, and the clock
  rules pin that to roughly a day — so generic precomputation is bounded to a 24-hour window, not
  open-ended. That is a real advantage at a namespace opening and negligible afterwards. What is
  absent entirely is binding to log *state*: a proof valid on one linearisation is valid on any
  other, including a partition, which is exactly the "replay resistance without any clock shared
  between peers" 29.5.d asks for — and the clock-bounded `notBefore` is the shared-clock
  dependency that Article was avoiding.

  Recorded in both documents an implementer would look in, with the three questions a VWIP has to
  settle: what the anchor is, what "recent" means, and how a peer with no history validates one it
  cannot recompute. That last is why this is a design task and not a field addition — an anchor a
  newcomer must take on trust is the privileged authority the checkpoint's unsigned-ness refuses.

- **Ten UNRATED findings dispositioned**; five remain. UNRATED meant the recheck assigned no
  severity, not that the severity was low, and this pair is the evidence: one was a third instance
  of a pattern already fixed twice at HIGH, and the other is the largest remaining gap in the
  record format.

### Fixed — the last four MEDIUM findings, and a `MUST` that supplied no value

- **`privacy-contained-webview-vs-locked-profile`.** `PRIVACY.md`'s mode table said Private
  Mode's browser is "**Contained**, because full-proxy configuration and the client's own webview
  are mandatory". Both stated reasons fail. `CONTENT-SECURITY.md` 5.5 makes it "the client's own
  webview **or** a locked browser profile" — one of two configurations, not mandatory — and 5.1
  says WebRTC "uses raw UDP and ignores the HTTP proxy entirely, so full-proxy mode does not
  contain it either", calling it the most serious residual in the browser layer. So full-proxy
  does not close WebRTC at all, and the thing that does is optional.

  Now: contained in the client's own webview, narrowed otherwise, with the reason written out.
  Same shape as the "Nothing durable" claim corrected earlier — a summary cell asserting the
  strongest configuration's property, in a document whose section 11 exists to list what it does
  not claim.

- **`local-surface-3.3-3.4-unspecified-bounds`.** §3.3 required "a documented maximum entry
  count" and §3.4 required concurrency caps, an in-flight bound and a memory ceiling "specified
  with concrete numbers and enforced". **None of the five numbers existed**, here or anywhere in
  the corpus. A `MUST` with no value is not a weaker requirement than one with a number; it is an
  untestable one, and Article 44.6's standard is that a competent implementer can build from the
  specifications alone.

  Supplied: 4,096 negative-cache entries LRU; 6 concurrent requests per origin; 32 in-flight per
  page; 256 per process; 64 MiB for the record and negative caches combined. Each with its
  reasoning, and each stated as an engineering judgement rather than a derivation — defensible,
  not uniquely so. It is the more common of the two failures: a document can require a number of
  its implementers in language strong enough to sound like it has supplied one.

- **`local-surface-cross-name-subresources-vs-content-security`.** §4 specified how an
  `allow_cross_name_subresources` setting would behave. `CONTENT-SECURITY.md` 2.3 closes the list
  of relaxations and does not contain it, and that document's section 1 names "a cross-name
  subresource allowance" **first** among the widenings that "instantly revalue every unfixable
  fingerprinting vector from harmless to critical". Specifying how a forbidden setting behaves is
  how a forbidden setting acquires an implementation.

  Withdrawn, with the argument kept for whoever proposes it properly. It escaped notice for a
  structural reason worth recording: `check-headers.py` compares **fenced canonical blocks**, and
  this section quoted none, so the gate that holds the profile together never saw it. Identical
  in rule and in month to `PUBLISHING.md`'s inline hashes — and both were found by reading two
  documents together rather than either alone.

- **`resolution-md-cross-reference-and-count`** was already fixed by the residual-channel sweep.

  **Every HIGH, MEDIUM and LOW finding now carries an outcome.** Fifteen UNRATED remain, and
  UNRATED means the recheck did not assign a severity rather than that the severity is low —
  several are of the same class as findings that turned out to be HIGH.

### Fixed — a signed checkpoint, and a proxy mode one document did not know existed

- **Three documents signed a checkpoint that `REGISTRY.md` and the code deliberately leave
  unsigned.** `REGISTRY.md`: a checkpoint "is not an authority and carries no signature that
  would make it one" — anyone derives it from the same log, so trusting one *is* recomputing it,
  and a signature would turn it into an attestation peers could be asked to accept instead.

  `CRYPTO-AGILITY.md` 6.1 was the sharpest: it required the checkpoint "signed under the
  then-current suite" **two sentences after** arguing that anchoring must rest on hashes rather
  than signatures "since hashes survive quantum adversaries". Signing it would have made the
  anti-repudiation mechanism rest on the primitive it exists to outlive. Corrected there and in
  `PROOF-OF-WORK.md`; a paired statement forbids all three spellings, one of which slipped a
  length-bounded pattern that had looked generous.

- **`RESOLUTION.md` defined a `passthrough` mode `LOCAL-SURFACE.md` did not know existed.**
  RESOLUTION step 3 lets a non-VayuWeb host be forwarded to the OS networking stack, and its
  browser-integration option 2 *requires* it — a browser pointed at the proxy for all HTTP
  traffic cannot reach the clearnet otherwise. `LOCAL-SURFACE.md` requires every non-VayuWeb
  `Host` rejected before routing, makes it conformance item 3, and the word "passthrough" did not
  appear in it at all.

  An implementer reading one built a proxy that cannot do option 2; one reading the other built
  an **open relay and SSRF pivot** into the reader's own network. Both conformed. That is the
  shape this audit keeps producing, and it is why the fix is a carve-out with teeth rather than a
  cross-reference: `LOCAL-SURFACE.md` 2.1.1 now states the mode and four normative constraints —
  off by default, **never** available in Private Mode (5.2 closes top-level navigation
  exfiltration *by refusing* the forwarded request, so an honouring passthrough reopens the one
  channel full-proxy exists to close), loopback and RFC 1918 refused unconditionally as with
  `CONNECT`, and no VayuWeb TLD eligible in either mode.

  Conformance item 3 is split in two, and both halves are load-bearing: a test asserting only the
  refusal fails every resolver implementing option 2, and one asserting only the forwarding
  passes an open relay.

- **The paired-statement mechanism gained a purely positive form**, since this rule has a
  statement that must be present and no withdrawn form to forbid — with a guard refusing any
  rule that has neither, because that one would check nothing while looking like a check.

### Fixed — every LOW finding: three claims that were arithmetically or logically wrong

- **`pow-64x-ratio`.** `PROOF-OF-WORK.md` and `pow.ts` both said "a two-character name costs 64
  times a fifteen-character name". A fifteen-character label is on 5 bits and a two-character one
  on 10, so the ratio is 2⁵ = **32**. Sixty-four is the gap to the sixteen-and-above branch — two
  correct numbers from the same table, paired wrongly, overstating the anti-hoarding property
  twofold at exactly the length where the schedule stops changing. Both corrected to sixteen, and
  a test derives the ratio from `baseBits` rather than trusting either restatement, because the
  restatements are what disagreed.

- **`arch-resolution-ttl-status-contradiction`.** `ARCHITECTURE.md` gave the IPNS-to-CID cache
  300 seconds — "updates visible within five minutes" — against `RESOLUTION.md`'s
  `min(record validity, 120 seconds)` and "a publisher updating a site expects it live in about
  two minutes". Same cache, two defaults, two rationales arguing for opposite numbers. Not a
  mislabelled reference to the record cache either, which is separately 300 in the same list. An
  overview that invents a figure the specification already sets is the overview's defect;
  `ARCHITECTURE.md` now defers, and a paired statement holds it.

- **`uri-scheme-conformance-2-identical-uris`**, also filed as
  `uri-scheme-s7-origin-isolation-self-comparison`. Conformance item 2 read "`vayu://a.vayu` and
  `vayu://a.vayu` do not share storage, permissions or scripting access" — the same URI on both
  sides, requiring a name to be cross-origin with **itself**, which is the opposite of the origin
  model in 3.1. Not a test nobody ran: a test nobody could pass. It now names both pairs, one
  differing by label and one by TLD, because the origin tuple has two components and testing one
  leaves the other unmeasured — and a test asserts exactly that, so a future edit cannot quietly
  drop a component.

  **Every LOW finding is now closed.** Six MEDIUM and fifteen UNRATED remain.

### Added — dispositions for the MEDIUM and LOW findings, and the count that caught me out

- **Twenty more findings now carry an outcome**, alongside the eighteen HIGH ones. Ten fixed,
  five stale, and — worth knowing before anyone budgets the rest —
  `registry-worked-example-powproof` appears **four times** at two severities, and
  `docs/spec/PROOF-OF-WORK.md:135,118` is the `VWIP-0000` missing-sections finding filed under a
  file-and-line heading. The list is shorter than it looks, and a heading that names a location
  rather than a defect is worth re-reading before being counted as separate work.

- **The remainder is six MEDIUM, five LOW and fifteen UNRATED — and the first draft of that
  sentence said eight.** A number asserted from memory, in the file that exists to stop numbers
  being asserted from memory, in a session spent fixing exactly that. Counting it took two lines.

  It is now derived, which required reaching past a deliberate exclusion: `AUDIT-FINDINGS.md` is
  in `EVIDENCE_FILES` and skipped by every rule that walks the corpus, because it quotes defects
  verbatim and a check for a defect fails on the document reporting it. That exclusion stands.
  But a count of the file's own disposition rows is not a quoted defect, so it is read directly —
  and that is the **only** thing permitted to reach into an evidence file, because a second one
  would mean the exclusion had stopped meaning anything.

  Mutation-tested four ways: staling the number, deleting a disposition row, removing the sentence
  entirely, and the control. All refused — including the removal, since a count that can be
  deleted to make the check pass is not a check.

### Fixed — a reserved label that no reservation was withholding

- **`NAMES.md` listed `_vayu` among the reserved labels; `registry/src/names.ts` did not.** The
  gap was not a hole — `_` is not in the label grammar, so `_vayu` can never be a label under any
  policy — and that is precisely why it was worth correcting rather than silently adding to the
  set.

  Listing an ungrammatical string among the reserved labels implies the reservation is what
  withholds it, and therefore that a VWIP releasing the class would make it available. It would
  not. The section's own next paragraph says "Reserved labels are not permanently unregistrable.
  A VWIP MAY release a class of them", so a reader deciding what such a VWIP could release would
  have got this one wrong. A string the grammar already excludes is excluded by the grammar, and
  saying so twice makes the weaker statement look like the operative one.

  `NAMES.md` now states that every label in the table is grammatical, and why that is the property
  that makes the list mean anything: each one would be registrable if the reservation were lifted,
  so lifting it is a real decision.

- **A test parses the table out of the document and compares it with the enforced set**, so
  neither can gain or lose a label without the other — and asserts that every member is refused
  as `RESERVED_LABEL` rather than by some other rule, which is the assertion that would have
  caught `_vayu` on the day it was added. Mutation-tested three ways: dropping a label from the
  code, adding one to the table only, and putting `_vayu` back. All three refused.

### Fixed — the document defining the completeness bar was the one never measured against it

- **`VWIP-0000` is `Status: Final` and was missing five of its own mandatory sections.**
  Centralisation analysis, Migration and rollback, Activation epoch, Expiry of transitional
  mechanisms and Test vectors — required by its own section 3 of every proposal that advances
  beyond Draft, and absent from the document that requires them. Its section 3.2 says an analysis
  identifying no dependent party "SHOULD be treated by reviewers as an unfinished analysis rather
  than a clean result"; an absent one is worse.

  All five written, and written as arguments rather than as placeholders, because 3.1 makes
  "none" unacceptable and says why: the explanation is the reviewable artefact, and writing it is
  where authors discover there was a consequence after all. Two examples of that happening here —
  the editor panel is a real centralisation dependency and is named as the only one; and the
  drafting window of section 2.4.b is the one transitional mechanism, self-extinguishing rather
  than dated, because a date would either strand the corpus or outlive the anchor and leave a
  live bypass of Article 58.

- **`scripts/check-vwips.py`** does what section 3 describes and nobody performed: "An editor
  checks their presence, never their merit." It reads the mandatory-sections table out of
  `VWIP-0000` rather than restating it, applies the two conditional rows by `Category` and `Type`,
  and **reports** incomplete Drafts rather than skipping them — `VWIP-0002` still needs Migration
  and rollback, which is permitted at Draft and would otherwise surface on the day somebody tried
  to advance it. Mutation-tested three ways; all refused.

- **`check-workflows.py` now fails if any checker is not run by a workflow.** A checker nothing
  invokes is a file that looks like a gate and is not one — and writing `check-vwips.py` and
  nearly forgetting the CI step, in the same hour, is why the rule exists rather than a
  hypothetical. `scripts/README.md` documents all nine and what each refuses; the listener check
  promptly failed that README for naming the superseded port, which is the rule working.

### Fixed — CI cancelled a run on `main`, which its own comment says never happens

- **`cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}` is inert.** GitHub evaluates an
  expression in that field to a **string**, and every non-empty string is truthy — so
  `"false"` cancels. Four workflows carried it, each above a comment reading "Never cancel on
  main, where a run's result is a record rather than a preview".

  It was not caught by reading, because the line says what it means to do. It was caught by
  looking at what happened: CI run 31068869289, on `main`, cancelled **one second** after the next
  push started, having recorded no jobs at all. Six main runs this session, one of them silently
  discarded, and the commit it was verifying went unverified until a later commit re-covered it.

  The working form puts the discriminator in the group rather than the flag —
  `github.sha` for main gives each commit a group of its own, so nothing can supersede it, while
  branch runs keep sharing a group per ref. `check-workflows.py` now refuses any expression in
  `cancel-in-progress`, since the whole class fails the same way. Mutation-tested by restoring the
  old expression and by writing a different one; both refused.

  Two things about this are worth stating rather than fixing quietly. It is the same defect the
  audit kept finding one layer out — a control that is declared, reads correctly, and does not do
  what its comment says — and it was found by checking the artifact rather than the configuration,
  which is the only method that has worked on this class all week.

### Fixed — cross-references and counts that were right when written and never moved

- **`RESOLUTION.md` was the third document to undercount the residual channels**, and it was
  wrong three ways in one paragraph: "Four channels are not closable by CSP at all", a pointer to
  `CONTENT-SECURITY.md` **section 4** where the channels are in section 5, and "specifies what
  closes it instead" for all of them. The paired-statement guard added an hour earlier matched
  only the plural "them", so the singular spelling here survived it — the rule now takes both,
  and `RESOLUTION.md` is in its file list.

- **`VWIP-0001` claimed "Twelve executable tests"** against `CONTENT-SECURITY.md` section 6 (ten)
  and `PRIVACY.md` section 10 (seven) — seventeen. A proposal that undercounts its own acceptance
  criteria is claiming a smaller bar than it set. It also pointed twice at "section 1.3" for the
  per-site relaxations, which are in section 2.3.

  Both counts are now derived: `check-counts.py` sums the numbered items in the two conformance
  sections, and takes the residual-channel count from the numbered subsections. Mutation-tested
  by staling each claim and by adding an eleventh conformance test; all refused.

  These are the low-severity end of the same defect the whole audit turned up — a number or a
  reference that was correct at the moment it was typed, in a document that then moved underneath
  it. The fix is never the correction; it is deriving the value so the next move is caught.

### Fixed — a security document that undercounted what it cannot close

- **`VWIP-0001` summarised the residual channels as "the four channels CSP cannot close and
  specifying what closes them instead".** `CONTENT-SECURITY.md` section 5 lists **eight**, and the
  remedy clause is false for six of them. 5.7 says "Not closable, and not claimed"; 5.8 says
  "Complete and irreducible"; and 5.1, 5.4, 5.5 and 5.6 are narrowed by a control that works in
  the client's own webview and cannot be enforced in a third-party browser, where the honest
  answer is a plain warning.

  `CONTENT-SECURITY.md`'s own opening carried the same clause three lines above a section that
  opens *"A security document that lists only its wins is a marketing document."* Undercounting
  what a security profile cannot close is the opposite of a disclosure, and it is the failure that
  section names.

  Both corrected: the count is stated, and each channel is sorted into closed by a shipped
  control, narrowed where the client owns the browser, or neither.

- **Two guards, because the first alone left a hole and a mutation found it.** `check-counts.py`
  derives the number from the numbered subsections, so a ninth channel or a stale summary fails.
  But a count rule only fires against a claim it can *parse* — delete the number and nothing is
  checked at all, which is exactly what reverting the intro to the old wording did: it passed the
  count check untouched. A paired statement now forbids the old clause outright. Mutation-tested
  four ways; all four refused.

### Fixed — the test that guaranteed vector coverage was the reason coverage was incomplete

- **`conformance/README.md` claimed "at least one vector for every rejection code the verifier can
  return — a test fails if a code is added without one".** The test enforcing it compared the
  artifact against a **hand-written** list of codes, so it passed by asking only about the
  twenty-two somebody had remembered to type. Six genuinely returnable codes were missing from
  the list and from the artifact together: `NOT_A_MAP`, `MISSING_FIELD`, `BAD_FIELD_TYPE`,
  `TOO_MANY_RECORDS`, `MISSING_POW` and `TOO_LARGE`.

  A hand-written expectation cannot detect the thing it forgot. That is the whole defect, and it
  is the same shape as the audit's other findings one layer down: the check compared an artifact
  to a restatement instead of to its source.

  The list is now derived from the rejection codes, which meant making them a runtime value —
  `RECORD_REJECTIONS` and `VERIFY_ONLY_REJECTIONS` as `const` arrays with the types derived from
  them, the pattern `OPERATIONS` already used — because a TypeScript union is erased and cannot
  be enumerated. Six vectors added; the artifact holds 72.

- **Exemptions are named and expire.** `SUITE_DOWNGRADE` has no wire vector and cannot: a vector
  states its predecessor as bytes, and `CRYPTO-AGILITY.md` 4.2 makes a record naming an inactive
  suite unparseable. It is unit-tested against a constructed predecessor. A second assertion
  fails if an exempted code *acquires* a vector, so the excuse cannot outlive its reason.

- **Two claims in that README were also wrong.** It said the file does not cover replication,
  convergence or resolution; all three have had their own suites for some time. And it did not
  mention **equivocation detection**, which is implemented, unit-tested, and has no vector — so a
  second implementation is not measured on it. Now stated as the one uncovered area.

  Mutation-tested four ways: adding a rejection code with no vector, deleting one of the six new
  vectors, exempting a code that has one, and staling the README's count. All four refused — the
  last by `check-counts.py`, which now derives that number from the artifact, because a count
  written beside a generated file is a count that drifts the next time the file is generated.

### Fixed — a URI parser that could not address a founding extension

- **`URI-SCHEME.md`'s `tld` production was `2*12( %x61-7A )` — letters only.** `NAMES.md` is the
  normative specification for what a name may contain and gives `%x61-7A *11( %x61-7A / %x30-39 )`
  — a letter, then letters or digits. Those are not a stricter and a looser spelling of one rule,
  they are two rules, and the difference is `.p2p`, an extension Constitution Article 35.1 names
  in its own text. A parser built from `URI-SCHEME.md` rejects `vayu://site.p2p` while a resolver
  built from `NAMES.md` resolves it: two conforming implementations, one of which cannot address
  a founding extension.

  Corrected, with `NAMES.md` named as authoritative for both productions and the ABNF reproduced
  rather than restated. `check-counts.py` now pairs the two spellings; mutation-tested by
  reverting each document in turn, both refused.

### Fixed — three conformance items written against a namespace that no longer exists

- **`NAMESPACE.md` section 7 would now fail against the Annex it is meant to guard.** All three
  are recorded rather than quietly replaced, because each was true of an earlier design.

  **"No implementation hard-codes an extension list; the valid set is derived from the log."**
  Section 2.3 of the same document carried this, was found to require the opposite of what is
  implementable — the record format has no TLD-creation operation, so the log carries nothing to
  derive the set from, and Article 35.6 vests creation in a ratified proposal rather than in a
  record anyone can append — and was corrected. The conformance section was not touched in that
  change. Article 2.31 settles it: membership is decided offline against the copy the verifier
  holds, never fetched and never derived from the log. **The second half-fix inside one document
  found this week**, which is why the paired-statement guard exists.

  **"A two-character extension proposal is rejected."** The Annex ratifies **60** two-letter
  extensions, and VWIP-0004's collision review turns on that number — 35 of the 60 share a string
  with an ISO 3166-1 code. A conformance item rejecting all sixty contradicts the namespace three
  sections above it.

  **"A proposal duplicating a well-known ICANN gTLD is rejected."** Five ratified entries share a
  string with a widely known ICANN generic — `.blog`, `.news`, `.forum`, `.wiki`, `.app` — each
  carried deliberately, each with its reason in VWIP-0004's collision review.

  Two guards, because they catch different things. `check-counts.py` derives the two-letter count
  from the Annex, so a document stating the wrong number fails; and a paired statement forbids the
  rejection sentence outright, because a count rule catches a wrong *number* and says nothing
  about a sentence that refuses all sixty. The first mutation proved that: reinstating the
  rejection rule passed the count check untouched. Both now refuse it.

### Fixed — a ballot the charter forbids, withdrawn in one document and left standing in its sibling

- **`NAMESPACE.md` still ratified extensions by "a two-thirds majority over a 30-day voting
  period".** `NAMES.md` had carried the same rule, found it contradicted Article 43.1 — consensus
  is the absence of unaddressed substantive technical objection and is expressly *not* a head
  count, with 43.5.4 listing "a vote count" among the things that do not constitute it — and
  withdrew it, recording why. The document that actually names the extensions was not touched in
  that change, so the ballot survived there. Corrected, with the withdrawal recorded in the same
  form: Article 35.6's ninety days are an objection window, not a voting period.

- **The half-fix is now the thing being guarded, not the ballot.** Each document read as settled
  on its own; the defect was only visible with both open, which is the same shape as every other
  cross-document finding this audit has turned up. `check-counts.py` gains a **paired statement**
  mechanism: a phrase that must be present in every listed document and whose withdrawn form must
  be absent from all of them.

  Both halves are needed, and neither alone would have caught this. Requiring only the presence
  lets the old rule sit two paragraphs below the new one — which is exactly how a document ends
  up asserting both. Requiring only the absence lets a document drop the subject entirely and
  look compliant by saying nothing. The absent-check runs against text with quoted and bolded
  spans removed, so a paragraph recording what was withdrawn — which has to quote it — is not
  itself a violation.

  Mutation-tested four ways: reinstating the vote in `NAMESPACE.md` alone, and deleting the
  settled sentence from each document in turn. All four refused.

### Fixed — the specification's only complete record was one the specification rejects

- **`REGISTRY.md`'s Worked Example carried the pre-hardening proof-of-work shape.**
  `{alg: "argon2id", m: 262144, t: 3, p: 1, salt: …, nonce: <integer>, bits: 22}` — the exact form
  the schema section three paragraphs above forbids in terms ("exactly three keys"; "A verifier
  MUST reject a `powProof` carrying `m`, `t`, `p` or `salt`"), and which the reference
  implementation refuses three separate ways. `bits: 22` also exceeded the schedule's ceiling of
  18, overstating the cost budget roughly fourfold.

  The provenance is a missed edit, not a disagreement: the commit that removed those dials
  rewrote the schema paragraph, said "REGISTRY.md is corrected to match PROOF-OF-WORK.md", and
  touched nothing else — leaving the only complete record in the corpus modelling the shape the
  same commit had just called an attack.

  **The consequence was sharper than a stale paragraph.** `conformance/vectors.json` publishes
  `schema/pow-carrying-cost-parameters`, which requires an implementation to *reject* exactly
  that shape. So the artifact that measures a second implementation demanded refusing the only
  record the specification models — in a project whose Phase 6 acceptance is an independent
  implementation built from the specification alone.

- **A test now parses the example out of the document** and runs it through the verifier's schema
  rules. Signatures are not checked, since the example's `sig` is illustrative and cannot verify;
  everything structural is, which is where the defect was. Mutation-tested three ways: restoring
  the old `powProof`, raising `bits` past the schedule ceiling, and deleting the `suite` field the
  agility work had just added. All three refused.

  An example nobody parses is prose, and this one had been prose for two commits.

### Fixed — a subordinate document added a third relaxation to a security profile it does not own

- **`PUBLISHING.md` section 2.1 let the resolver append per-site `'sha256-…'` expressions to
  `style-src` and `script-src`.** `CONTENT-SECURITY.md` is the single source of truth for the
  browser-security profile and its section 2.3 enumerates the relaxations: two, with
  `None. Move to a stylesheet in the same CID.` against inline style and script. `RESOLUTION.md`
  and `VWIP-0001` both say two, and VWIP-0001's rights-impact analysis states in terms that
  "sites using inline styles, inline scripts, `data:` images or WASM must change to be rendered".
  One document said three, and it is not the one that owns the profile.

  It came with two sharper conflicts. `PUBLISHING.md` said "the reader-facing security indicator
  MUST NOT change", against 2.3's unconditional "visible to the reader" and conformance item 6 —
  so the relaxation was not merely extra, it was undisclosed. And the section immediately after
  it was titled "The two remaining relaxations", so the document had already outgrown its own
  framing.

  Withdrawn from `PUBLISHING.md`, along with the manifest `inline` field, publish step 3,
  `doctor --fix`'s declare-instead-of-move behaviour and two conformance items that tested it.
  **The argument is kept in full**, because a rejected design that leaves no trace gets
  reproposed every eighteen months by someone who cannot find out why it was rejected — and it
  was a good argument: the tree is verified against its CID before a byte is served, so a
  hash-pinned inline script permits exactly the bytes the holder signed and an injected one still
  fails. What a VWIP would have to answer is written down with it.

- **`CONTENT-SECURITY.md` contradicted itself, which is why this could happen.** Conformance item
  1 required the canonical values "emitted byte-identically on every response", while 2.3 permits
  two per-site widenings — so the authoritative document simultaneously forbade and permitted a
  policy that differs per site. An implementer reading only item 1 concludes the relaxations
  cannot be emitted; one reading only 2.3 concludes the policy may vary freely, which is the door
  `PUBLISHING.md` walked through. Item 1 now says what it can mean: byte-identical absent an
  enumerated 2.3 relaxation, and any deviation is exactly one of those and nothing else.

- **The count drifted three ways and is now derived.** `PUBLISHING.md` said "the two remaining
  relaxations" while defining a third above it; `CONTENT-SECURITY.md` said two; `RESOLUTION.md`
  said "one of the two per-site relaxations" while pointing at a document that had grown to
  three. `check-counts.py` derives the number from the 2.3 table's granting rows, so a document
  stating a different one fails rather than waiting for a reader who happens to hold both files
  open. Mutation-tested by making `RESOLUTION.md` say three, and by adding a row to the table
  without updating the prose; both refused.

### Fixed — the agility mechanism had no field to read

- **`CRYPTO-AGILITY.md` is fully specified and was entirely unimplementable.** Its section 1:
  "No primitive is named in the protocol. Only suites are, and every signed object carries the
  identifier of the suite that produced it." The record schema had no `suite` field at all, so
  4.2 (reject an unknown suite), 4.3 (the suite inside the signing input), 5.1 (suites move
  forward only) and conformance items 2, 3, 6 and 7 each tested a field that did not exist —
  while the schema pinned `ownerKey` to 32 bytes and `sig` to 64, which the same document calls
  defective in terms.

  It matters more than an ordinary gap because that document says why: **"a record format
  without a suite identifier is a record format that can never migrate."** Every other
  future-proofing decision here can be made later. This one could not.

- **`suite` is now a required field**, and the four rules that depend on it exist:
  - Unknown or **reserved** suites are rejected `UNKNOWN_SUITE`. Reserved counts as unknown —
    3.1 makes "reserved" mean the format can carry it and no record may use it, so accepting one
    would admit a signature scheme nothing can verify.
  - The signing input carries `uint8(suite)` after the separator, per 4.3. Belt and braces, since
    `suite` is also inside the signed CBOR; kept because the cost is one byte and the failure —
    a cross-suite replay during the one migration this protocol gets — is unrecoverable. A record
    with no suite now throws rather than silently producing the pre-agility input.
  - `suite >= prev.suite`, or `SUITE_DOWNGRADE`. Without it, migrating a name to a stronger suite
    buys nothing: whoever broke suite 1 still holds a key that verifies under it.
  - Key and signature lengths come from the suite table, never a constant.

- **Size limits are per suite**, per 3.2, and the check runs **twice**. `suite` is a field inside
  the record, so no per-suite limit can be consulted until the bytes are decoded — and decoding
  unbounded input is the denial-of-service the outer bound prevents. The outer bound is therefore
  the maximum over *active* suites, and the suite's own limit is applied after parsing. Bounding
  the outer check by the largest *reserved* suite would hand an attacker four times the parsing
  work per record for suites no key can sign with.

- **Two documents asserted the field existed.** `CRYPTO-AGILITY.md`'s own "See also" described
  `REGISTRY.md` as "the record format that carries `suite`", and `LONGEVITY.md` recorded as a
  verdict that it "is present from record zero". Both corrected; the longevity entry keeps the
  false claim visible and says what it was, because a review asserting a property of a document
  it had not checked is the failure mode that review can least afford.

- **Two more disagreements surfaced while wiring it up.** The suite table gave suite 1's hash as
  SHA-256, against `REGISTRY.md`'s BLAKE2b-256, the conformance vectors and every implementation
  — the specification that defines record bytes wins, so the table was the error. And 4.3's code
  block showed a different prefix literal with no `0x00` separator, which would have produced
  signatures `REGISTRY.md`'s verifier rejects; the requirement was always the *structure*, and
  the literal belongs to the document that defines the bytes.

- **`keys.ts` baked a 32-byte key into the Hyperbee keyspace**, found by the new static rule
  rather than by the audit. Renamed to `OWNER_KEY_FIELD_BYTES` and documented: it is a property
  of the keyspace layout rather than of the signature scheme, a suite-3 key does not fit, and the
  fix at migration is a re-specified `o` keyspace and an index rebuild — affordable exactly
  because `REGISTRY.md` makes the index derived state with no authority. Deferred, in writing,
  rather than overlooked.

  **Three vectors, and two rules that cannot have one.** `suite/unknown`,
  `suite/reserved-is-not-active` and `suite/zero` are on the wire. A downgrade vector cannot
  exist yet: a vector states its predecessor as bytes, and 4.2 makes any record naming an
  inactive suite unparseable, so the suite-3 predecessor is not a record a conforming peer can
  hold. It is unit-tested against a constructed predecessor instead, and the absence is written
  into the vector file — an absent vector nobody wrote down reads exactly like a covered rule.

  **Two of the first eight mutations survived, and the tests were wrong again.** Hard-coding
  32/64 back, and deleting the per-suite size check, both left every test passing — because with
  one active suite the per-suite limit *equals* the global one and the suite's lengths *equal*
  Ed25519's. Behavioural tests cannot reach either. `check-source-hygiene.py` gains a `REQUIRED`
  mechanism for call sites nothing else can hold, plus a rule forbidding `PUBLIC_KEY_LENGTH` and
  `SIGNATURE_LENGTH` outside their suite module — which is the "static check" CRYPTO-AGILITY.md
  conformance item 1 asks for by name. Re-mutated: both refused, along with reverting `keys.ts`.

### Fixed — `RELEASE` was an operation the charter closed the set against

- **Article 29.4 does not list record types, it closes the list.** "There SHALL be no
  administrative record type, no operator record type, no reserved opcode and no side channel. A
  record bearing an unrecognised type MUST be rejected rather than ignored." So an operation name
  outside that set is not a spelling preference — it is a record every conformant peer is
  required to refuse, which is total non-interoperation on a core operation.

  `RELEASE` was such a name. It appears nowhere in the Constitution: Article 19.2 says
  "relinquish the name" and 29.4 names the record `RELINQUISH`. Article 3.7 voids the
  specification to the extent of the conflict, so the specification was the defective party.
  Renamed throughout — schema, pseudocode, lifecycle, vectors, CLI, `NAMES.md`. A test now reads
  Article 29.4 out of the charter and asserts that every implemented operation is a name it
  closed the set to. Mutation-tested by reverting the rename and by adding an `ADMIN` opcode;
  both refused.

- **`REGISTRY.md` now states the whole operation set against 29.4's eleven**, with the Article
  that mandates each of the five it does not implement: `DELEGATE` (34.2), `KEY-ROTATE` (34.1),
  `TOMBSTONE` (19.2/19.3/19.4, with a conformance test at 19.9), `TLD-FREEZE` (35.9) and
  `TLD-RETIRE` (35.10). Leaving that gap implicit is what let the settlement-delay work land with
  a protection it could only half deliver — Article 33.4 vests the power to revoke a pending
  transfer in an Article 34 recovery path that `DELEGATE` and pre-declared succession material
  would carry, and neither exists. The gap is now sized rather than gestured at.

### Escalated — two names the charter both requires and excludes

- **`RENEW` is normative in Articles 11.6, 11.8 and 31.1 and absent from 29.4's closed set.** A
  peer obeying 29.4 literally must refuse every renewal. Article 11 is entrenched under Article
  9, so 29.4 is the erroneous clause — but it is also the higher-precedence instrument as
  written, and adding a type to it is an amendment under Article 58. The specification implements
  `RENEW`, because the alternative is a registry in which no name can ever be renewed. **Recorded
  rather than silent**, which is the whole point: a specification that quietly does the sensible
  thing against a clause of the charter is indistinguishable, to a second implementer, from one
  that overlooked the clause.

- **`TLD-CREATE` is the same contradiction pointing the other way.** 29.4 makes it a record, so
  an extension would come into being by someone appending one; Article 35.6 vests creation in a
  ratified Naming-category VWIP. If a record creates a TLD the ratification is decorative, and if
  ratification creates it the record type has nothing to do. `NAMESPACE.md` inherited this once
  already — it required deriving the valid set "from the registry log" when the log carries
  nothing to derive it from — and was corrected there; the charter is where it originated.

  `check-charter-consistency.py` gains a third kind of tracked item for **membership**: a name one
  clause excludes and another depends on, or includes and another forbids. It is deliberately not
  a decision, for the same reason as the epoch entry — both sides are Articles, and Article 3.7
  ranks the Constitution above the specifications rather than above itself. Mutation-tested five
  ways: adding `RENEW` to 29.4, dropping `TLD-CREATE` from it, deleting Article 11.8's dependency,
  rewriting 35.6 so a record does create a TLD, and removing the word "closed" from 29.4. All
  five refused; an unmutated corpus passes.

### Fixed — a transfer took effect the instant it was signed, and the charter forbids that

- **Article 33.4 mandates a fourteen-day settlement delay. Nothing implemented one.** "A TRANSFER
  record SHALL take effect only after a mandatory settlement delay of fourteen days, during which
  any recovery path configured by the transferor under Article 34 MAY revoke it by signed
  record." `REGISTRY.md` said "Effect: ownership moves and the term is unchanged" and the code
  agreed: the moment the record was accepted, the incoming key was the ownership key. A lower
  instrument contradicting the charter on a wire-visible rule is void under Article 3.7, and
  three other documents — `THREAT-MODEL.md`, `GLOSSARY.md`, `FAQ.md` — already presented the
  delay to readers as an existing protection, which made it a false claim as well as a gap.

  A TRANSFER is now accepted at once and takes effect `1,209,600` seconds after its own
  `notBefore`. Throughout that window the transferor still controls the name and the recipient
  can do nothing with it.

- **Only a further TRANSFER is accepted while one is settling**, and this is the part that is
  not tidiness. The chain rules force a non-TRANSFER successor to carry
  `ownerKey == prev.ownerKey`, which for a pending transfer is the *recipient's* key. One
  accepted `UPDATE` would leave a predecessor whose `op` is no longer TRANSFER and whose
  `ownerKey` is the recipient's — completing the handover early, silently, by an operation with
  nothing to do with ownership. Found by attacking the first version of the fix.

- **Cancellation needed no new record type.** Article 29.4's set is closed and contains no
  "cancel". The transferor signs a TRANSFER naming their own key and countersigns it themselves;
  it satisfies the differing-key rule because the key it names differs from the pending
  recipient's.

- **The delay is measured from the record, never from the verifier's clock.** Article 29.6
  requires a record to be verifiable offline from the record and the chain alone. Under a
  clock-driven test one record gets different verdicts on two peers whose clocks differ, and the
  same record flips verdict as a clock crosses the settlement instant — a log accepted on Tuesday
  fails to replay on Wednesday.

- **A transfer must fit inside the term it transfers.** Signed with ten days left it settles four
  days after the name has expired, and the name is frozen for the whole window because `RENEW` is
  refused during settlement like everything else.

  Seven vectors, `settlement/*`, pin all of it, including both sides of the boundary instant.
  Without them an implementation that hands the name over on acceptance passes the whole suite —
  `authority/valid-transfer` measures that the record is accepted and says nothing about when it
  takes effect, which is exactly how this shipped.

  **Two of the first eight mutations survived, and both times the test was wrong rather than the
  fix.** Making settlement clock-driven passed, because the test compared the same bytes at two
  distant instants and `BACKDATED` is checked long before authority is — it never reached the
  code it was aiming at. Deleting the guard on `predecessorFrom` passed, because nothing asserted
  the guard existed. Rewritten: the clock test now places the settlement instant inside the
  narrow gap the clock rules allow between `now` and `notBefore`, in both directions. Re-mutated,
  both fail. A ninth mutation covers the store's own copy of the rule — the index computes the
  controlling key a second time, and a disagreement there means a log that will not replay.

### Fixed — two normative documents specified two different transfers

- **`NAMES.md` specified a two-record `offer`/`accept` handover; `REGISTRY.md` specified one
  `TRANSFER` with a countersignature.** Both documents declare themselves normative, and
  `NAMES.md` says in terms "Transfer is a two-signature handover. It is never a single
  operation." They are not two encodings of one flow — they are different state machines.
  `NAMES.md` assigned the `seq` increment to `accept`, added a 14-day offer expiry and an
  offer-hash back-reference, and required a record naming a recipient key, while `REGISTRY.md`'s
  schema has no field for either and its chain rules force `ownerKey == prev.ownerKey` for every
  operation but TRANSFER. A second implementer building from `NAMES.md` would emit `offer` and
  get `UNKNOWN_OP` — the reference code already pins that even a case variant is refused.

  **The charter decides it, and against `NAMES.md` on three separate grounds.** Article 29.4's
  record set is closed and names none of `offer`, `accept` or `revoke`. Article 33.2 forbids the
  protocol to provide an "offer channel" by name and adds "No such faculty is within the closed
  record set of Article 29.4". Article 34.1 gives transfer effect by signature from the incumbent
  ownership key. `NAMES.md` §Transfer is rewritten to the single-record form.

- **The `revoke` collision was the sharp end.** `NAMES.md` already used lowercase names for
  registry operations elsewhere — "appending a signed release" for `RELEASE` — so a reader had
  direct precedent for mapping its `revoke` onto `REVOKE`, which freezes a name for the rest of
  its term plus quarantine, with no recovery key and no appeal. Someone trying to call a transfer
  off could have destroyed the name instead.

### Escalated — the renewal window and the post-expiry interval, tracked rather than decided

- **The term was already recorded as unresolved; the two durations that hang off it were only
  described.** The earlier escalation named the grace disagreement in prose and stopped there, so
  `check-charter-consistency.py` was guarding one of three quantities while the other two could
  still be closed by a one-line edit. Prose in a changelog is not a guard. Both are now tracked
  the same way the term is.

  **Renewal window.** Article 11.6 imposes none — a `RENEW` is valid "at any moment while the
  name is held". Article 32.3 opens it twelve months before expiry. `REGISTRY.md` opens it sixty
  days before, and the code enforces that. A factor of twenty-four between the outer two, and the
  disagreement bites in both directions: an implementation following the charter accepts a record
  the specification refuses, and one following the specification refuses a record Article 11.6
  expressly permits.

  **Post-expiry interval reserved to the incumbent.** Article 11.8 reserves ninety days and
  requires every other key's `REGISTER` to be refused throughout. Article 32.3 makes it one
  hundred and eighty. `REGISTRY.md` gives thirty days of grace and then thirty of quarantine — so
  the incumbent loses the name on day 31 and a stranger may take it on day 61, both inside the
  interval Article 11.8 reserves to the holder alone. The worked case is a day-45 `RENEW`: valid
  under the charter, rejected `EXPIRED` by the specification.

  **Not fixed, deliberately, and for a sharper reason than last time.** Article 11.14 names
  Article 32 as **Article 11's own machinery**, so this is not a subordinate document overriding
  a superior one — it is an entrenched Article and its implementing Article stating different
  numbers, which Article 3.7 cannot rank because both sit inside the Constitution. Any fix
  reconciles three regimes, not two, and the thirty-day figure is `GRACE_SECONDS` in the code and
  is restated across five more documents, so aligning it is a coordinated change downstream of an
  amendment rather than instead of one.

  The check gains a way to read a duration stated as a *condition* rather than a number — Article
  11.6's window is the whole of tenure — with the phrase spelled out in a table so that editing
  the clause breaks the match instead of silently changing the value. Mutation-tested five ways:
  aligning the specification's grace up to Article 11.8, aligning Article 32.3's grace down to it,
  aligning the specification's window out to Article 32.3, narrowing Article 32.3's window to the
  specification, and deleting Article 11.6's any-moment clause. All five refused; an unmutated
  corpus passes.

  `REGISTRY.md` now carries the three-way table where an implementer reads the lifecycle rules,
  rather than leaving the contradiction discoverable only by reading two Articles side by side —
  which is how it survived this long.

### Fixed — two documents specified a query log the charter forbids outright

- **`RESOLUTION.md` and `ARCHITECTURE.md` both described an opt-in query log.** RESOLUTION.md:
  logging is "opt-in, reset to off after every upgrade, capped by a retention in hours, and
  written only to a local file". ARCHITECTURE.md: query logs "are not written by default", and the
  resolver announces it at startup if a user turns debug logging on.

  `PRIVACY.md` section 4 says "never written, in either mode" and explicitly rejects the
  logging-defaults-to-off framing. Constitution Article 14.1 and 14.2 forbid logging a lookup to
  durable storage; 14.7 makes it a conformance test that fails on any durable file containing a
  resolved name; Article 9.8 entrenches it. **A local file with an hours-long retention is durable
  storage**, and Article 14.5's optional-diagnostic carve-out does not license it, because that
  carve-out requires the diagnostic to be per-session rather than persistent.

  Every qualifier in the old text was a mitigation, and a mitigation is the wrong shape: a log a
  user can enable is a log a user can be persuaded, tricked or compelled to enable, and announcing
  it at startup does not make the file less durable. Both corrected. The two that were wrong are
  the two an implementer building a resolver actually reads.

### Fixed — "Nothing durable" was true on one desktop platform of three

- **Private Mode's headline claim was unconditional; its normative clause was not.** The mode
  table stated durable local state as "**Memory only. Nothing durable.**", and the goal at the top
  of the document promised "Zero durable trail on disk". The clause that implements it required an
  ephemeral profile "in a memory-backed location **where the platform provides one**" — and macOS
  and Windows provide none by default, so on two of the three desktop platforms the profile is
  written to disk and deleted.

  `PRIVACY.md` itself forecloses the comfortable reading: filesystem metadata "can outlive a
  deleted file. Private Mode avoids creating the file at all, which is the only reliable defence."
  So written-then-deleted is a genuinely weaker property, and stating the stronger one unqualified
  is what Article 21's duty of honest claiming exists to forbid — the Article being entrenched
  under 9.12.

  The clause now names the fallback normatively, requires the client to **report** that the weaker
  guarantee applies, and forbids describing such a session as leaving nothing durable behind. The
  mode table, the goal statement, the no-trail conformance test and section 11's limits all carry
  it. Section 6's `mlock` mitigation is platform-conditional in exactly the same way and already
  carried "MUST attempt and MUST report when it fails"; this clause now follows the shape the
  document had already found for itself.

  The conformance test is deliberately **two** assertions rather than one relaxed one: a test that
  passed on both platforms by asserting the weaker property everywhere would have left the
  stronger property unmeasured on the platform that can actually deliver it.

### Fixed — the specification overrode the charter twice on activation timing

- **`REGISTRY.md` set the epoch at 30 days where Article 2.5 caps it at 14.** The Article is
  unambiguous — "Epoch length MUST NOT be shorter than one day nor longer than fourteen days" —
  so this was a subordinate document plainly overriding the charter, and Article 3.7 voids it.
  Corrected to `1,209,600` seconds. Fourteen rather than some lower figure because every reason
  for wanting a long epoch pushes at the bound rather than away from it.

- **`REGISTRY.md` set the activation floor at "two epochs — roughly sixty days".** Articles 20.3,
  20.11, 35.7 and 47.6 each set it at 180 days, **every one of them stated in seconds**, so this
  was not even a unit confusion: a change scheduled by the specification would have activated four
  times sooner than the charter permits.

- **`VWIP-0002` had already inherited it.** Its activation clause said "at least two epochs beyond
  the epoch in which this proposal reaches Accepted, per Article 47.3 and the epoch definition in
  REGISTRY.md" — faithfully following a subordinate document that was itself wrong, and so
  scheduling its own activation at a third of the constitutional floor. It now states the floor
  directly rather than inheriting it through a reference, which is the general lesson: a
  cross-reference to a document that can be wrong is a way to be wrong without looking wrong.

### Escalated — the charter defines "epoch" as two different kinds of thing

- **Article 2.5 makes an Epoch an interval; Article 11.5 makes it an instant.** 2.5: "the
  protocol's unit of ordered time: a fixed, deterministic interval", bounded at one to fourteen
  days. 11.5: "Every epoch in this Constitution is an integer count of SI seconds elapsed since
  1970-01-01T00:00:00Z". Usage follows 11.5 throughout — 11.6 speaks of "the epoch of the latest
  REGISTER or RENEW record", 11.7 compares an epoch to "the receiving party's own clock", 20.2 to
  "records created at or after that epoch".

  **Not fixed, deliberately.** Precedence cannot resolve it: Article 3.7 ranks the Constitution
  above the specifications and *both clauses are inside the Constitution*. Article 3.21 points at
  11.5 as the text in conflict without curing it. Choosing between an interval and an instant for
  a term Article 20.11 makes the subject of a conformance test is an amendment under Article 58 —
  and this specification has just been corrected twice for overriding the charter by accident,
  which is not a good moment to do it deliberately.

  `check-charter-consistency.py` gains a second kind of tracked item for terms whose disagreement
  is about the *kind* of thing named rather than about a number. It proves both definitions are
  still present and still incompatible; it does not compare them, because an interval and an
  instant cannot be compared and a number that looked like a resolution would be worse than none.
  Mutation-tested by editing one definition away: refused.

  Article 2.5's pointer to "the Annex" also resolves to nothing — no primitives Annex exists.
  That absence is why `REGISTRY.md` filled the gap in the first place, and why it filled it
  outside the stated bound.

### Fixed — `wpad.vayu` was registrable, in code that claimed to prevent it

- **The reserved-label set was never implemented.** `NAMES.md` withholds twelve named labels in
  every extension and says a registration naming one "is invalid and MUST be rejected by every
  peer, not merely ignored; an invalid operation never becomes an ownership fact".
  `registry/src/names.ts` implemented the length classes and stopped. Its own header claimed the
  module covers "label grammar, **reserved labels** and the ratified TLD set".

  So `wpad.vayu`, `pac.vayu`, `proxy.vayu`, `control.vayu`, `api.vayu` and `vayu.vayu` were all
  registrable here.

  **Two harms, and the second is the larger.** `wpad` is Web Proxy Auto-Discovery: a browser
  configured to find its proxy automatically fetches `wpad.<domain>/wpad.dat` and runs the
  JavaScript it finds there to decide where every request goes — a proxy-hijack vector with its own
  CVE history, and the reason `NAMES.md` says "a name that a browser might fetch as configuration
  MUST NOT be registrable by a stranger". `pac` is the same attack under the configuration file's
  own name. But no attacker is needed for the second harm: an implementation written from the
  specification refuses all twelve as `BAD_LABEL`, this one accepted them, and two peers holding
  different ownership facts for one name is the fork Article 44.6 exists to prevent.

- Fixed at the single validation point both the verifier and the proxy already use, so there is
  no second list to drift. **A conformance vector per reserved label** now exists — without them a
  second implementation was not measured on the rule either, which is part of how this survived.
  A proxy test pins the browser-facing refusal specifically, because that is where a `wpad` fetch
  actually arrives.

- `_vayu` is named in the specification's table and deliberately absent from the set: underscore is
  not in the label character set, so the grammar refuses it before reservation is consulted, and a
  second check for a string the first cannot admit is a check that only looks like coverage.

### Added — three conformance suites for the rules where forks actually live

- **`conformance/vectors.json` gains `convergence`, `resolution` and `replication`** alongside the
  existing record suite, closing Phase 0's last open item. The record suite pins what a verifier
  *accepts*. These pin what independent implementations must **agree about afterwards**, which is a
  different property and the one that matters for Article 44.6.

  The distinction is not academic here. **Every consensus-critical defect this project has found
  was invisible to record verification** and visible only to the question "what would a second
  implementation do": the convergence rule decided conflicts by local arrival order, so two peers
  kept different owners forever; that rule was then found to be called by nothing; and the
  resolver preferred the frozen snapshot over the living pointer, so a conforming publisher and a
  conforming resolver together froze every site. Record vectors passed throughout all three.

- **The convergence suite carries each pair twice, mirrored.** An implementation that decides by
  argument position, by arrival, or by its own log index gives one answer to the pair and a
  different answer to its mirror — which is exactly the fork that shipped. Vectors carry
  `logIndex: null` deliberately: a vector cannot express a local log position, and the whole point
  of the contract is that no implementation needs one.

- Resolution vectors pin the pointer-before-snapshot order, that `txt` is never a source, that
  subdomains are refused rather than guessed at, and that an unsynchronised resolver answers
  `REGISTRY_UNAVAILABLE` rather than `NAME_NOT_FOUND` — because a resolver that has never
  synchronised does not know the name is absent, and saying so would be inventing a fact from its
  own ignorance.

- All three suites mutation-tested against the real defects: restoring the frozen-publisher order,
  making convergence decide by argument position, and having an unsynchronised resolver claim a
  name is absent. Each is caught.

- A first draft of the resolution vectors passed the **text** form of a CID where REGISTRY.md
  types the entry value as a byte string, and was refused as `BAD_RECORD_ENTRY`. Recorded because
  it is the vectors doing their job on their own author: the text form belongs in a URL bar, not
  in a record.

### Added — pin sets, availability reporting, and unpublishing

- **`registry/src/pins.ts`** implements HOSTING.md's availability section and Constitution
  Articles 19, 21 and 23. Almost everything in it exists to stop a **true number being reported in
  a way that means something false**, which is an unusual job for a module and is the point.

  Three ways a correct count lies, each closed by construction rather than by careful wording:

  - **Silence is not absence.** A peer that did not answer is not a peer that lacks the content,
    and a client cannot distinguish "no peer holds this" from "no peer told me". The report carries
    how many peers were *asked* alongside how many answered, and the zero case says "No peer
    answered out of 40 asked. That is not the same as nobody holding it."
  - **Your own pin is not redundancy.** "1 peer holds this site" reads as reassurance and means
    nothing when that peer is you — and self-pinning-only is the most common self-inflicted failure
    in content-addressed publishing, because from the publisher's own machine the site always
    loads. Self pins cannot be summed in by accident, because there is no total to sum them into.
  - **A snapshot is not a forecast.** There is no `total`, `percentage`, `durability` or `uptime`
    field, so a dashboard cannot bind to one. Article 23 forbids the figure and HOSTING.md says any
    document quoting an uptime number is wrong; the defence is that the number does not exist.

  A peer answering twice counts once, so apparent redundancy cannot be manufactured by repetition,
  and more answers than peers asked is **refused** rather than reported — a wrong denominator
  presented with the authority of a measurement is worse than no report.

- **Unpublishing is enumerated as data, not prose.** Article 19.1 opens by saying it is "stated
  with deliberate precision, because unpublishing is where charters lie", and 19.6 requires the
  limits to be stated plainly *everywhere*. `UNPUBLISH_EFFECTS` holds the six acts Article 19.2
  guarantees and the four things 19.6 says cannot be guaranteed, as lists — so an interface has to
  render them or deliberately drop them, rather than simply never having had them. A test asserts
  that no string in the module claims erasure, per 19.7.

- Four mutation tests, one per honesty guarantee: counting self as a peer, rendering silence as
  absence, reintroducing a `total` field, and moving the tombstone cache bound off the charter's
  3600 seconds. Each is caught by exactly its own test.

### Added — dag-pb and UnixFS, so a tree becomes a root CID

- **`registry/src/unixfs.ts`** completes the publish path: a directory tree now has a root CID. It
  implements dag-pb node encoding, UnixFS directory and file messages, raw-leaf files, multi-chunk
  file nodes, and recursive directory building.

- **It was written against vectors, not against a reading of the format, and the first attempt was
  wrong.** Reasoning from a description of dag-pb, the initial encoder put the UnixFS `Data` field
  at protobuf field 2 and produced `bafybeiepbj3744hbmji3sz5wqivcxj6au3jzfk54qfnki7ploa2gnsxxt4`
  for the empty directory. The network says
  `bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354`.

  That wrong encoder was **self-consistent**. It round-tripped. It hashed correctly. Every site it
  published would have had a CID that resolved on the publisher's own machine and was invisible to
  every other node on the network — and nothing in the publisher's own testing would ever have said
  so. This is the case the previous entry declined to guess at, and the guess would have been
  wrong.

- **The two rules a reader gets wrong**, both now encoded and both mutation-tested. `PBNode`
  numbers `Data` as field 1 and `Links` as field 2, and dag-pb requires field 2 on the wire
  **first** — against the ascending-field-number order every protobuf encoder emits by default. And
  a directory's links are sorted by name in **raw byte order**, so two publishers importing the
  same files in different order produce the same root; without it the root hash depends on the
  order a filesystem happened to list a directory in.

- **Six vectors from the reference importer are pinned**: the empty directory's exact bytes, a
  one-file site, a two-file site, a two-chunk file's node bytes and CID, and a **nested tree**. The
  nested one earns its place — mutation-testing showed that a `Tsize` accumulated wrongly one
  level down changes the root while every leaf stays correct, and no flat vector catches it.

- **No new dependencies.** The reference libraries were installed in a scratch directory to
  generate vectors and are not in `registry/package.json`. The implementation is independent; only
  the expected values come from the ecosystem, which is the direction that makes them evidence.

### Added — Phase 4: content addressing

- **`registry/src/content.ts`** implements the fixed import parameters HOSTING.md sets: CIDv1,
  lowercase unpadded base32, sha2-256, 256 KiB fixed-size chunks, raw leaves. Every value is
  pinned by the specification rather than left to a library default, because two publishers
  importing the same directory must produce the same CID — and when they do not, **both CIDs
  resolve and both sites work**, so nothing surfaces until someone tries to verify a third
  party's copy.

- **It is checked against the IPFS network, not only against itself.** The tests pin the published
  reference CIDs for the empty file and `hello world`
  (`bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku` and
  `bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e`). An implementation can be
  internally perfect, round-trip everything it produces, and still address content nobody else can
  find; only an external vector catches that.

- **The decoder refuses every form the specification does not use** — CIDv0, base58 multibase, a
  dag-json codec, a BLAKE3 multihash — rather than accommodating them. Accepting one would mean a
  registry record could point at content this resolver cannot address the way the specification
  says it must, and "we accepted it and did something reasonable" is how two implementations stop
  agreeing. The varint encoder handles multi-byte values even though every value in use is below
  128, because a hard-coded single byte passes every happy-path test and fails the first time a
  codec exceeds 127.

### Fixed — the specification said "sign an IPNS record" without saying what gets signed

- **HOSTING.md step 5 could not be built against.** It required a publisher to "sign an IPNS
  record binding the site key to `/ipfs/<root CID>`" with a stated validity and sequence rule, and
  said nothing about which bytes are signed. Article 44.6 requires the specification set to be
  sufficient to build a conformant client without reading any implementation's source, and a
  signature scheme is the sharpest test of that: two implementers who guess differently produce
  records neither can verify, and the failure presents as "the name does not resolve" with nothing
  to point at.

  Now pinned to **IPNS Record V2**, with the signature input, the CBOR field set and the scheme
  written out. VayuWeb defines nothing of its own here, and the reason is the same one that fixed
  sha2-256 for content hashing: a record ordinary IPFS nodes cannot validate is a record the DHT
  will not usefully carry.

  Three rules are VayuWeb's own, each closing a way a record could be honest and still wrong: a
  V1-only record is rejected, because accepting both schemes means accepting the weaker one; a
  record whose sequence is not strictly greater is rejected, because equal-sequence records with
  different values are the site key equivocating and no non-arbitrary choice exists; and a
  publisher must never reuse a sequence, because the 168-hour validity leaves a superseded record
  servable for a week.

### Fixed — a conforming publisher and a conforming resolver froze every site

- **`SOURCE_ORDER` selected `cid` before `ipns`, so nobody ever saw an update.** `HOSTING.md`
  recommends carrying both entries: an `ipns` pointer for the living site and a `cid` for "the
  last snapshot the owner is willing to have served if the pointer cannot be resolved", so that
  "the registry record stays still while the site behind it changes, which is what an author
  republishing weekly actually wants". `RESOLUTION.md` said the resolver **SHALL** select `cid`
  first, unconditionally, with both present.

  Both documents were normative. A publisher following one and a resolver following the other
  **both conformed**, and every reader was served the frozen first snapshot forever while the
  author published into a pointer nobody consulted.

  Three things make this worse than an ordinary bug. It is **silent** — no error, no staleness
  signal. It is **permanent** — nothing later revisits the choice. And it is **invisible to the
  author**, who resolves their own pointer and sees a current site; only readers see the frozen
  one. The escape hatch made it worse rather than better: fallback was `MAY`, so a conforming
  resolver need never fall back at all, and the entry that never fails is precisely the pinned
  snapshot.

  The order is now `ipns`, `cid`, `peer`, `alias`. Preferring the pointer costs no verifiability:
  an IPNS record is signed by the same key that controls the name, and what it yields is a CID,
  hash-verified exactly as an inline one is. Fallback is now `SHOULD` and a fallback answer must
  be marked stale — not `MUST`, because forcing older content whenever a pointer is momentarily
  unreachable hands a network attacker a downgrade primitive, and the honest note is that the
  snapshot is owner-signed, so serving it is a staleness problem rather than an authenticity one.

  Written as a failing test in the reader's terms, mutation-tested by restoring the old order.
  `WHITEPAPER.md` carried the order in a diagram and is corrected too.

- **`.vayu/manifest.json` had two disjoint normative schemas and a third document that ignored
  it.** `HOSTING.md` defined `title`/`description`/`entry`/`generator` and called the manifest
  advisory; `PUBLISHING.md` defined `version`/`index`/`fallback`/`notFound`/`inline`/`csp` and
  gave it a `SHALL`. `entry` and `index` were two names for one field. `RESOLUTION.md` step 13
  consulted no manifest at all, so PUBLISHING's `SHALL` about deep links had no counterpart in the
  document describing what a resolver does — every site with client-side routing 404'd on every
  deep link, exactly as the spec's own text says it would without a fallback.

  One normative home now: `PUBLISHING.md` section 2, with the descriptive fields merged in.
  `HOSTING.md` defers to it. `RESOLUTION.md` step 13 consults it.

  The authority question is settled rather than split. **The manifest is authoritative about
  routing** — which file answers `/`, what to serve on no match — because those are decisions the
  owner is entitled to make about their own site, and the manifest is inside the CID-verified
  tree, signed by the same key. **It is never evidence about the tree**: a resolver takes no
  digest, no file's existence and no content property from it. PUBLISHING 2.1 already said this
  for digests — "the manifest declares intent; it does not confer permission" — and that rule is
  now general.

  `HOSTING.md` also required an `index.html` in every addressable subdirectory, justified by
  saying a resolver "has nothing to fall back on". That was true of that document and false of the
  specification set, since PUBLISHING 2.3 defines the fallback. Relaxed to `SHOULD`.

### Added — Phase 3: the browsing proxy and the control API

- **`registry/src/proxy.ts`** implements LOCAL-SURFACE.md sections 2 to 4 as a pure request
  handler. It binds nothing and does no I/O, and that is not tidiness: every rule here is a rule
  about *what is refused*, and a handler reachable only through a real TCP connection is one whose
  refusals get tested for the happy path and assumed for the rest. A rebound `Host`, a `CONNECT`
  to loopback, a name crafted for header injection — all cheap to write as data, all awkward to
  write as sockets, and the awkward ones are the ones that quietly never get written.

  Three properties, each a refusal. **Not an open relay**: exactly two request shapes, both
  requiring a VayuWeb host, everything else refused before routing — which is the DNS-rebinding
  defence, since an attacker who rebinds their name to 127.0.0.1 still arrives carrying their own
  `Host`. **Does not announce itself**: the headers naming VayuWeb are off unless the control API
  turns them on, and a refusal body echoes nothing, because "this person runs VayuWeb" may be the
  only fact an adversary in a hostile jurisdiction needs. **Nothing unbounded is reachable from a
  page**: the negative cache is bounded, evicting and TTL'd, invalid names are not cached at all,
  and eviction is insertion-order rather than LRU so an attacker cannot pin their own entries.

- **`registry/src/control.ts`** implements the privileged surface. `assertSocketAddress` throws on
  a TCP address rather than leaving the rule to prose — the prose already existed and five
  documents ignored it. The browser-shaped refusals (`Origin` present, custom header absent,
  `Upgrade`) run **before** the token comparison, so a page that somehow reached the socket is
  turned away without its guess ever being timed. Config redaction keys on the *name* by
  substring, so an unforeseen `apiToken` or `sessionSecret` is redacted by default: the failure
  mode of over-redaction is an operator looking elsewhere, and of under-redaction is the token in
  a log.

- **The CSP is pinned to the specification, not copied from it.** A test reads the canonical block
  out of `CONTENT-SECURITY.md` and compares byte for byte. A second copy of a security policy is a
  copy that drifts, and a directive lost in transcription is a relaxation nobody chose.

- **35 tests, and three of them were inadequate when first written.** All the same shape:
  `assert.notEqual(status, 200)` passed with the defence under test deleted, because the request
  then failed for an unrelated reason — the name simply did not resolve. A test satisfied by *any*
  failure cannot tell you which defence is standing. Rewritten to assert the exact refusal code,
  then re-mutated.

  One further result worth recording rather than hiding: on re-mutation the explicit `CONNECT`
  refusal turned out to be genuinely redundant — the request-shape rule and the method allowlist
  each already cover it. It is kept for legibility and its comment now says it is a third defence
  rather than implying it is the one holding.

### Fixed — the corpus specified a listener the security model forbids

- **Five documents put the control API on `127.0.0.1:7653`. `LOCAL-SURFACE.md` section 1 forbids
  a TCP control listener on any address, including loopback, and calls a build that offers one —
  even opt-in, even "for development" — non-conformant.**

  The socket decision is the strongest single piece of hardening in the design, and the reasoning
  is that a browser *cannot address a Unix domain socket*: no `fetch`, form, `img`, WebSocket or
  `XMLHttpRequest` can name one. That deletes DNS rebinding, CSRF, WebSocket `Upgrade` reach and
  browser port-scanning against the privileged surface outright, rather than requiring a correct
  defence against each one forever.

  It landed in `LOCAL-SURFACE.md` and nowhere else. `RESOLUTION.md` — which carries the endpoint
  table an implementer would actually build from — still said "The control API on
  `127.0.0.1:7653` is JSON over HTTP", and `ARCHITECTURE.md` attached a normative **SHALL** to the
  forbidden transport. A competent implementer reading top-to-bottom would have built the listener
  the security model exists to prevent.

  Corrected in `RESOLUTION.md`, `ARCHITECTURE.md`, `WHITEPAPER.md`, `GLOSSARY.md`, `ROADMAP.md`
  and `NAMES.md`. The `Origin`-rejection and custom-header rules are kept but re-justified: they
  were the *primary* defence when the surface was TCP, and on a socket they are defence in depth
  against an operator or refactor putting a proxy, a socket-activation shim or a container
  port-forward in front of it.

- **A new gate, `scripts/check-listeners.py`, and a CI job — 25 jobs now.** It is deliberately
  three exact string rules rather than something cleverer, and the reason is worth recording.

  The first version tried prose analysis: find each control-API mention, look for an address
  nearby, and infer from the surrounding words whether the sentence was specifying the binding or
  retiring it. It was mutation-tested three times and survived none of them cleanly. Proximity
  cannot separate "specifies" from "retires" when a document contains both in one paragraph —
  which every corrected document now does, because correcting them meant writing down what they
  used to say. Each patch made it worse in the usual way: the escape hatch that stopped the false
  positive also opened the door for the mutation.

  So the shape changed rather than the thresholds. The rules now are: the retired port may appear
  only in files whose job is recording history; four named documents must state that the control
  API is a Unix socket; and no loopback binding other than the proxy's may appear anywhere. All
  three mutation-tested and caught. The docstring states what the check does **not** prove.

### Added — Phase 2: the replication protocol

- **[REPLICATION.md](docs/spec/REPLICATION.md)** specifies how many machines reach one registry
  state without a coordinator: five messages, a symmetric exchange with no client and no server,
  and an explicit budget of limits. It is written against *any* ordered reliable channel.
  Hyperswarm over HyperDHT is named as the intended first binding and marked non-normative,
  because a protocol defined in terms of one discovery network makes that network's operators
  load-bearing, which is what Article 4 forbids.

- **`registry/src/replicate.ts`** implements the state machine, transport-free. Three refusals
  carry it: replication transports records and decides nothing, so every record is verified
  locally by the same `verify()` a local record passes; merging is set-based, so state never
  depends on who sent what when; and nothing is allocated for what a peer merely asserts, so a
  peer claiming a log of 2^53 records costs the receiver one bounded request.

- **28 tests against paired peers with real stores and real proofs of work**, structured as the
  conformance properties of REPLICATION.md section 8 rather than as unit coverage: order
  independence over *every* permutation of a record set, partition-and-heal convergence, a race
  between strangers delivered in opposite orders to each peer, hostile batches where one
  malformed record must not discard the other hundred and ninety-nine, and every limit.

- **No peer identity, reputation, membership or scoring**, and the omission is deliberate rather
  than pending. Those are the materials a governance layer gets built from, and Article 39 says
  there is no governing body.

### Fixed — the convergence rule was called by nothing

- **The rule was specified, implemented, unit-tested and unreachable.** `resolveConflict` and
  `voidedChain` had no caller outside their own test file. The merge path did first-arrival-wins,
  so the effective rule was the delivery-order fork the rule exists to prevent — and fixing the
  rule alone, as the entry below does, would have changed no behaviour whatsoever.

  This is the sharpest instance yet of the failure this project keeps finding: the deadcode gate
  did not catch it, because the functions *are* exercised — by tests. A test can keep a wrong
  answer looking alive indefinitely.

  `Store.append` now runs it, and the order of work is the security-relevant part. Judging a
  conflict properly means verifying the newcomer's Argon2id proof at 64 MiB, so doing that for
  every claim aimed at a held name would make spamming popular names a way to burn the network's
  memory bandwidth at the cost of sending bytes. The digest is therefore compared first: a
  newcomer with the larger digest cannot win under the rule, so there is nothing to learn from
  verifying it. An attacker must grind their digest below the incumbent's before a peer spends
  anything, at a full proof of work per attempt.

  Both halves are pinned by tests that assert the rejection *code*, which is what makes them able
  to fail: a claim carrying a broken proof is rejected as `NAME_TAKEN` when it cannot win (so the
  expensive path was never reached) and on the proof itself when it could (so the cheap path is
  not a way in). The first mutation of this was caught only incidentally by an unrelated store
  test — inadequate, so the targeted tests were written and the mutation re-run.

- **Wiring the rule in without a concurrency bound would have made every name stealable.** Found
  by attacking the merge path immediately after writing it, and independently flagged in the same
  session by an existing store test that the change had regressed — the failure was a real alarm,
  not a stale expectation.

  Nothing in the digest rule mentions time, so "first valid signature wins" decays into "lowest
  digest ever produced wins". No race is needed: wait until a name is established, grind
  registrations until one has a lower digest, submit it. The grinding is *cheap*, which is the
  part that makes it serious — an incumbent digest is uniform over 256 bits, so beating a given
  one takes about **two attempts on average**. Roughly half of every name in the registry would
  have been available for a couple of proofs of work, with nothing anywhere recording that
  anything had gone wrong.

  Two rules now decide whether a conflict is a partition at all, both computed from record fields
  so every peer answers identically:

  - **A late claim is not a concurrent claim.** A conflicting `REGISTER` whose `notBefore` exceeds
    the incumbent's by more than `MAX_BACKDATE_SECONDS` is refused outright — not weighed, not
    compared. The window is taken rather than invented: it is already the protocol's answer to how
    far apart two records can be and still both be arrivable now. Deciding by `notBefore` does not
    reintroduce the delivery-order fork, because `notBefore` is carried in the record, identical
    on every peer, and bounded against the receiver's clock.
  - **Equivocation is not a race.** A conflicting `REGISTER` signed by the incumbent's own key is
    refused. That is one party rewriting their own history, or a compromised key; the name belongs
    to that key either way, and resolving it by digest would let an owner replace their own
    registration at will while silently applying the evidence Article 38 wants surfaced.

  `THREAT-MODEL.md` gains T6b. Both rules are pinned by tests asserting the rejection code and
  mutation-tested by removing each guard.

- `Verdict` gains `voided`, so a caller learns which chain a merge destroyed rather than
  discovering it later. REGISTRY.md requires a client to surface that: somebody registered a name,
  saw it succeed, and lost it through no fault of their own, and a UI that quietly refreshes is
  lying about what happened.

- `Verdict` gains `duplicate`, because "accepted" and "accepted and changed something" are
  different facts and replication needs the difference. A peer resending one record forever would
  otherwise report progress on every batch, which a syncing loop reads as a reason to keep going —
  one record, an unbounded session.

### Fixed — convergence decided by arrival order, which is a permanent namespace fork

- **The convergence rule let any relay choose who owns a contested name.** Rule 2 awarded a
  conflict to "the earlier position in the linearised order", and the implementation evaluated
  that against **the peer's own log** — which is arrival order, chosen by whoever relays.

  The attack costs nothing and sends nothing detectable. Two strangers register the same free
  name across a partition; both records are valid. A relay delivers A to peer one before B, and B
  to peer two before A. Both peers now hold and have linearised both, so rule 2 fires on each,
  and they award the name to different keys — both correctly, against the evidence each holds.
  Nothing later revisits it: the loser's chain is void on one peer and live on the other,
  permanently, and every subsequent `UPDATE` deepens the split. Ownership of any contested name
  was a function of network position.

  **The charter's own entrenched canons decide this, so it is an interpretation and not an
  implementer's choice.** Article 3.12 forbids inferring a power from silence, which rules out
  reading in the coordinator a globally agreed order would need — and Articles 4 and 9.2 forbid
  that coordinator outright anyway. Article 3.13 then decides between what remains: the reading
  leaving fewer parties able to compel the operation prevails. Local arrival order lets every
  relay compel an outcome; the record digest lets nobody, because it is a pure function of bytes
  both peers already hold. So Article 30.3's "where log order does not separate them" is the
  operative branch for every conflict, and the digest decides. That is also the only reading
  under which 30.3's own closing sentence — "two honest implementations therefore always agree" —
  is true, and an interpretation that falsifies the clause it interprets is the wrong one.

  Fixed by deleting the ordering rule outright. `EARLIER_IN_LOG` is gone from `ConflictRule`, so
  an implementation cannot report an ordering verdict without changing the type, and the removal
  is documented in the union rather than left as an absence someone helpfully restores. Written
  as a failing test first, in the attacker's voice, and mutation-tested by reinstating the rule —
  both tests fail. `THREAT-MODEL.md` gains T6a.

  **Why it survived until now:** it passed a feature review and its own unit tests, because those
  tests supplied log positions consistent with a single order. A single-machine test has only one
  order to supply. The defect is only visible from the question Phase 2 forces — *what do two
  peers do* — which is the same lesson as every other real defect found in this project: test the
  artifact, not the transport.

### Changed — the launch namespace is 1,270 extensions, by amendment

- **[VWIP-0004](docs/spec/VWIP-0004.md) amends Constitution Article 35.1.** The initial top-level
  domains are now the **1,270 extensions of the Namespace Annex** — the 1,267 catalogue entries
  plus `.p2p`, `.news` and `.blog`, which the charter named but the catalogue omitted. Eleven are
  still named in the Article's own text so the founding set survives loss of the Annex, and
  35.1.c says in terms that this confers no rank.

  This reverses the resolution recorded further down this file, and the reversal is the point.
  Deferring to the charter is right for resolving *ambiguity*; it is not right for laundering an
  arbitrary number into a decision nobody made. Nothing in the corpus argued for eleven — no
  analysis, no threat it mitigated, no cost it avoided. The catalogue was 1,267 entries with a
  stated purpose each, in 34 categories, against published admission rules. The corpus held a
  considered enumeration and an unconsidered one, and the unconsidered one had won on where it
  sat rather than on what it said.

  Where the charter is unclear, an implementer must not decide. Where the charter is clear and
  wrong, an implementer must not decide *either* — which is why this is an amendment carrying
  full replacement text, a rights-impact analysis, a capture analysis and an Objection Register,
  and not an edit to a specification.

- **The collision review Article 35.6 requires was run over all 1,270 entries**, mechanically,
  and its uncomfortable results are published rather than summarised. **35 of the 60 two-letter
  extensions share a string with a legacy ccTLD** (`.io`, `.me`, `.co`, `.in` and 31 others), and
  five entries echo a well-known ICANN generic. They are ratified anyway, with the reasoning
  stated: the collision is of strings, not of resolution, since a VayuWeb name never reaches a DNS
  resolver. The review also states what it does **not** prove — the generic-collision figure is a
  floor, checked against a hand-maintained list rather than the ~1,200-entry ICANN root zone.

- **Articles 2.30 and 2.31 are added.** 2.30 defines the Namespace Annex as an instrument
  distinct from the primitives Annex, and disapplies 2.27 to it: the primitives Annex must be
  replaceable without an amendment or the charter dies with SHA-2, and the Namespace Annex must
  not be, because an editable list of valid extensions is a mechanism for deciding whose Name
  resolves. 2.31 requires a Node to decide TLD validity **offline**, from the copy it holds — a
  namespace that arrives over the network is a namespace someone can withhold.

- **The ratified set is generated, not written.** `scripts/generate-namespace.py` parses the
  Annex into `registry/src/namespace.generated.ts`, validating every entry against the TLD
  grammar, rejecting duplicates, and requiring the per-section counts to sum to the stated total
  and every charter-named extension to be present. CI runs it with `--check`, so editing either
  side alone fails the build; a test reads the Annex back independently. Both detections were
  mutation-tested by drifting the generated file one entry, and both named the entry.

- **`NAMES.md` specified a ratification procedure the charter forbids.** It required "a two-thirds
  supermajority of ballots cast" over 30 days with "a quorum of 25 percent of eligible signing
  keys". Article 43.1 defines consensus as the absence of unaddressed substantive technical
  objection and 43.5.4 lists a vote count among the things that are *not* consensus — and a
  franchise of "signing keys active in the trailing 90 days" is one anyone can mint keys to
  enlarge, which is the Sybil problem Article 40 answers by refusing to count identities at all.
  Replaced with the actual Article 35.6 path, and the old text recorded rather than deleted.

- **`NAMES.md`'s TLD retirement was a revocation with a calendar in front of it.** It specified a
  24-month sunset after which unclaimed names were lost. Article 35.9 permits exactly one action
  against a TLD with live names — FREEZE, under which every existing name keeps resolving
  *indefinitely* — and 35.10 makes retirement reachable only when no live names remain or every
  holder has migrated by their own signed action over at least five years. Every clause of the
  old text read as protective; the aggregate took a name from a key by the passage of time.

- **The anti-drift check inverted, because the old one would have stopped checking anything.**
  `check-counts.py` used to require every inline extension list to match the ratified set
  exactly. With 1,270 extensions no document can restate the set, so that rule would have passed
  on every file forever while still looking like a gate. It now enforces what VWIP-0004 section
  4.2 requires — documents *reference* the Annex, they do not repeat it — with the threshold set
  from the corpus rather than picked, and mutation-tested by reintroducing a restatement.

- **`VWIP-0000` declared neither of the two things it already relied on.** Line 159 referenced a
  "Constitutional Amendment" review duration and Article 35.6 requires a "Naming-category VWIP",
  while the header block declared only three types and seven categories. Neither existed, so a
  correctly headed Naming or amendment proposal could not be written at all. Both are now
  declared, with their durations, their extra mandatory sections, and — for amendments — the rule
  that one reaching an entrenched Article 9 clause is inadmissible at the completeness check
  rather than merely unlikely to pass.

### Added

- **CI grows from 14 jobs to 24** — 23 declared across five workflows, one of which is a
  two-version Node matrix — via a new `quality.yml` and additions to the existing
  workflows. Every new gate exists because the thing it forbids would disable a check that has
  already caught a real defect here:
  - **formatting** (Prettier, pinned) — an unformatted diff hides the change under the reflow.
  - **source hygiene** — no `as any` or `as unknown as`, no `@ts-ignore`, no `test.only`, no
    `console` from library code, no `Date.now`/`Math.random`, no unresolved TODO markers. The
    cast rules matter because a cast is exactly what hid the dropped nonce that typecheck caught;
    `test.only` matters because it turns a green run into a lie. Exceptions use an explicit
    `hygiene:allow <reason>` comment, so every waiver states why, next to the code it excuses.
  - **no unused exports** — the `deadcode-gate.sh` equivalent. 193 exports checked; an export is
    a promise to a caller, and one nobody makes still has to be kept working.
  - **reproducible build** — Article 51 requires it for releases. Weakest useful form (same
    machine, same moment) and it still catches an embedded timestamp, path or iteration order.
  - **conformance vectors are current** — moved out of the release workflow so it runs on every
    commit; a stale artifact means second implementations are checked against bytes this one no
    longer produces.
  - **workflow security** — every workflow must declare `permissions`, third-party actions must
    be pinned to a commit SHA rather than a movable tag, `pull_request_target` is refused, and
    no secret beyond the automatic token may be used. CI runs with more authority than any
    reader has, and it runs on every push with nobody watching.
- **A determinism fuzz suite** (`registry/src/fuzz.test.ts`), seeded so a failure is replayable
  rather than merely reported. It pins the property `record_hash` depends on: no two byte
  strings decode to one value. Every single-byte mutation of a random encoding must either be
  rejected outright or re-encode to something different — a mutation that decoded *and*
  round-tripped to the original bytes would be a second encoding of one value, which is the
  malleability the convergence tie-break cannot survive. Also fuzzed: arbitrary byte strings
  never decode to something that fails to re-encode identically, incremental merkle appends
  match a rebuild at random lengths, every leaf proves inclusion and no leaf proves another, and
  timestamp byte order equals numeric order.
- **The log's merkle tree and the checkpoint format** (`registry/src/merkle.ts`,
  `registry/src/checkpoint.ts`), closing an Article 44.6 gap rather than working around it.
  `REGISTRY.md` named `treeRoot` and required "Hypercore inclusion proofs" without ever stating
  the tree's construction, so the value was **uncomputable from these specifications alone** —
  precisely the property the charter requires an implementer to have. The construction is now
  normative in `REGISTRY.md`: leaf, parent and root hashing with their domain-separation bytes,
  byte size bound into every node, flat-tree indices, and combination by leaf span rather than
  byte size so the tree's shape cannot depend on the data.

  Inclusion proofs are implemented and adversarially tested: a proof does not verify against a
  different root, for data it was not made for, with any sibling tampered, with a sibling's side
  flipped, or with a substituted peak — that last one because verification checks the
  reconstructed peak against the claimed one rather than only the final root, and checking the
  root alone would let a proof point at a different peak supplied in the same list.

  Checkpoints carry no signature, deliberately: a signed checkpoint would be an attestation
  peers could be asked to trust rather than recompute, which is the privileged authority the
  charter forbids. Comparison distinguishes real divergence (same length, different history)
  from ordinary progress (different lengths) and from an indexer bug (same history, different
  derived state) — collapsing the third into the first would send someone hunting the log for a
  defect that is not in it.

  Freshness is handled by being honest about it in the types. No inclusion proof shows that the
  length a peer handed over is current, so `LightClientAnswer` carries `observedAt`,
  `peersAgreeing` and a `freshnessUnproven: true` that cannot be omitted, and the trusted length
  is the greatest **corroborated** one — taking the greatest claimed would let a single lying
  peer set it. It fails toward staleness rather than trust, because a stale answer is wrong
  about *when* and a forged one is wrong about *what*.
- **The resolution algorithm** (`registry/src/resolve.ts`) — Phase 3's core, as pure logic.
  Steps 1 to 10 and 13 of `RESOLUTION.md` are decidable without a network and are implemented
  here; the registry lookup, IPNS resolution and content fetch arrive through a `ResolverPorts`
  interface with no default, for the same reason `RegistryView` has none.

  The check *order* is the load-bearing part and is tested directly: the steps are normative and
  ordered, so two resolvers checking in different orders return different numbered errors for a
  request that is wrong in more than one way — and that number is what the user sees and what a
  second implementation is measured against. TLD classification precedes label validation;
  label validation precedes any registry lookup, so malformed input reaches neither the network
  nor the cache; and "the log has never synchronised" (1502) beats "the name is not there"
  (1404), because those are different answers.

  Also pinned: an expired name does not resolve *even though its content is usually still held
  locally*, which is the entire point of the rule; unknown entry types are stored but never
  acted upon; the alias budget is three hops counted per original request, and a two-name cycle
  — invisible from either record alone — is detected rather than chased; and path mapping
  refuses traversal *before* normalising rather than after, which is the ordering that has
  produced traversal bugs for thirty years.

  Diagnostics are a field on the outcome, never a header. Recording them is mandatory;
  disclosing them to the requesting page is the caller's decision and off by default. Keeping
  the two apart in the type system is what makes that default enforceable rather than
  aspirational.
- **Convergence and equivocation detection** (`registry/src/converge.ts`) — the consensus-critical
  half of Phase 2, which is pure logic and needs no network. Two peers on either side of a
  partition can each accept a valid first registration of the same free name; both did the work,
  both are signed, neither is wrong. Every peer must independently reach the same answer without
  asking anyone, because a rule that needs a coordinator is a rule that *has* one.

  The three rules apply in order: sole valid candidate, then strictly earlier in the linearised
  order, then smaller `record_hash` as a big-endian unsigned integer. Three details are load-
  bearing and each is pinned by a test. Rule 2 is skipped entirely unless **every** candidate has
  a linearised position — a peer that has not linearised both cannot know the order agrees
  everywhere, and guessing from arrival order is precisely how two peers reach different answers
  about the same pair. Rule 2 requires *strictly* earlier, so a tie falls through rather than
  being broken arbitrarily. And the result is independent of the order candidates arrive in,
  which is the property that makes it convergence rather than a race.

  The loser is returned explicitly along with its transitively voided chain, not merely dropped.
  REGISTRY.md requires a client to surface that rather than hide it behind a silent refresh:
  someone registered a name, watched it succeed, and lost it through no fault of their own, and
  a UI that quietly updates is lying about what happened. A caller that wants to ignore it has
  to do so deliberately.

  Equivocation — one owner signing two different records at the same `seq` — is detected and
  distinguished from an honest partition conflict between two different owners. It is not
  punished: there is no penalty mechanism in the protocol, and inventing one here would be
  inventing consensus. The evidence is what the function returns.

### Fixed

- **The duplicated `.vayu` originated in the charter, and the first fix never reached it.**
  Article 35.1 of `constitution/CONSTITUTION.md` — the constitutional definition of the
  namespace — listed `.vayu` twice, and `docs/spec/RESOLUTION.md` step 2 inherited it. The
  earlier round corrected the eight documents that stated a *number* and left the two that
  merely listed the extensions, so the charter and `NAMES.md` disagreed about what the namespace
  contains. Removing a repeated entry is editorial and changes no TLD: the set of distinct
  extensions was eleven before and is eleven now. Inventing a twelfth would have been
  substantive; deleting a duplicate is not.
- **`RESOLUTION.md` required the resolver to emit the fingerprint it forbids.** The document
  states that the `X-VayuWeb-*` diagnostic headers "MUST be **off by default**", and explains
  why in unusually direct terms: emitted unconditionally they brand every response as VayuWeb,
  which "lets any page that can elicit a response determine that VayuWeb is installed", and
  "for a reader in a hostile jurisdiction that single fact may be all an adversary needs".

  Four other normative statements in the same document contradicted it. Step 14 of the
  resolution algorithm — a section headed "the following steps are normative and ordered" —
  said to emit the diagnostic headers with every response. Record selection said the resolver
  "MUST record the fallback in the diagnostic headers". The stale-serving rule said it "MUST
  mark it `X-VayuWeb-Stale: 1`". The error catalogue said every failure carries its code in an
  `X-VayuWeb-Error` header — on the response easiest for a hostile page to provoke.

  An implementer following the numbered algorithm would therefore produce exactly the
  disclosure the document elsewhere calls the most consequential fingerprint the resolver can
  make, and would believe they had conformed, because they had. All four now defer to the
  default-off rule: recording a diagnostic stays mandatory, disclosing it to the page does not.
- **`scripts/check-counts.py` guarded the count but not the list**, which is precisely why the
  defect survived in the two places that never say "eleven". It now also validates every
  *enumeration* of the extensions against the ratified set in `NAMES.md`, failing on a repeat or
  an omission, and fails loudly if it matches no enumeration at all. Mutation-tested by
  reintroducing the duplicate into the charter, `RESOLUTION.md` and `FAQ.md` in turn; each is
  caught.

### Fixed — the namespace, where the charter *is* self-consistent

- **The namespace was defined twice, a hundredfold apart.** `REGISTRY.md` restricted `tld` to the
  founding set and the verifier enforced it; `NAMES.md` called `NAMESPACE-CATALOGUE.md` the
  "launch catalogue" of **1,267 extensions**, and the catalogue said the same. An implementer
  reading one built a different namespace from one reading the other, and each conformed to what
  they read.

  The charter did not contradict itself here, so the specifications were corrected to match it:
  the founding set was ratified, the 1,267 became **candidates** a verifier MUST reject, and the
  catalogue was reframed rather than deleted.

  **This resolution was superseded within the same release cycle, and it was the wrong one.** See
  the namespace entry above: deferring to the charter is correct for resolving ambiguity, not for
  laundering an arbitrary number into a decision nobody made. The count in the charter had no
  analysis behind it anywhere in the corpus. VWIP-0004 settled it at the level where a namespace
  decision belongs, by amendment. The entry is left here rather than rewritten because a
  changelog that quietly deletes the answer it gave last week is not a record.

- **`NAMESPACE.md` 2.3 required the opposite of what is implementable.** It said an
  implementation "MUST NOT hard-code the extension list" and that the valid set is "derived from
  the registry log". The record format has no TLD-creation operation, so the log carries nothing
  to derive the set from, and Article 35.6 vests creation in a ratified proposal rather than in a
  record anyone can append. It now requires the ratified set to be enforced and updated only by a
  Naming VWIP.

- **`README.md` carried stale claims**: a 69-test badge against 267 tests, "three
  consensus-critical defects" against a list that has grown well past three, a Phase 1 roadmap
  badge, and a code summary describing "a handful of registry primitives". Corrected, and the
  defect sentence no longer states a count it would have to keep updating.

### Escalated — needs an amendment, not an implementer

- **The Constitution contradicts itself on the registration term, and the implementation matches
  neither.** Article 11.6 sets tenure at 126,230,400 seconds (1461 days, about four years) and
  Article 11.13 turns that exact number into a conformance test. Article 32.2 — which Article
  11.14 names as **Article 11's own machinery** — says "The term SHALL be five years"
  (157,680,000 s). `REGISTRY.md` requires exactly 31,536,000 s, one year, and this code enforces
  it. Three documents, three values, and Article 11 is entrenched under Article 9.

  Grace disagrees the same way: Article 11.8 gives a 90-day redemption in which only the
  incumbent may renew; Article 32.3 gives a 180-day grace and opens the renewal window twelve
  months before expiry; `REGISTRY.md` gives 30 days of grace plus 30 of quarantine.

  **Not fixed here, deliberately.** No value can be chosen without overriding a clause that
  endorses another, and every other duration in the design — difficulty, the renewal window,
  grace, redemption — is expressed relative to the term. An implementer picking one by commit is
  precisely the capture Article 9's entrenchment exists to prevent.

  `scripts/check-charter-consistency.py` now records the conflict and prints it on every run. It
  fails if the conflict *changes shape* — including if someone closes it by editing one side —
  so the disagreement cannot be resolved except deliberately, and cannot be forgotten. Mutation-
  tested by editing the specification to match Article 11.6; the check refuses it.

  This is also why it went unnoticed: every check this project had compared prose to a list, or
  a number to its defining source. Nothing compared two Articles to each other.

- **The Constitution has never been anchored, so it has not commenced.** Article 1.7 requires
  exactly one canonical text, "byte-exact, content-addressed and signed", whose digest any reader
  can recompute offline. Article 1.9 requires that digest to be carried "in every published
  distribution of the specification" until a registry exists. **No digest is published anywhere
  in this repository.** Article 60.3 makes commencement conditional on publication of the
  anchored canonical text together with the first conformance suite and the first VWIP archive —
  the latter two exist, the anchor does not.

  The consequence is larger than a missing file, and it cuts both ways. The charter is not yet in
  force, which is exactly the state Articles 1.13–1.15 describe ("VayuWeb is specified here, not
  shipped") — and it is the state VWIP-0004 relies on to amend Article 35.1 without Article 58's
  twelve-month machinery, which is stated openly in that proposal rather than assumed quietly.
  It also means the README badge reading `charter: ratified` overstates the position under
  Article 21's duty of honest claiming.

  **Not fixed here.** Anchoring is a signing operation over a text that is still being amended,
  and doing it mid-amendment would anchor a document about to change. It is the last step before
  the first release, not a step to take while VWIP-0004 is in Draft. Recorded now because after
  the anchor is published this defect becomes unfixable in the cheap way: every subsequent change
  to charter text costs twelve months, two readings and double ratification.

### Adversarial review — second pass

A deeper pass than the one that gated 0.1.0, over surfaces the first did not reach: the CBOR
decoder's malformed-input handling, the label and alias grammar, the index keyspace codec, and
hex input on the command line. Recorded here whether or not it found anything, because a clean
result is only evidence if someone says what was tried.

**Attacked and found sound.** The deterministic CBOR decoder refuses negative integers, floats,
tags, invalid UTF-8, duplicate map keys, unsorted map keys, truncated input and empty input,
each with its own rejection code. Timestamps round-trip to 2^53-1 and refuse anything outside
it. Inverted ranges are refused rather than silently returning nothing. Decoding a key from the
wrong keyspace is refused. A TLD that is a prefix of another does not collide with its range
scan. Odd-length and non-hex input to the hex decoder is refused rather than truncated.

**Found and fixed:**

- **A name could alias itself.** `atlas.vayu` carrying `alias: atlas.vayu` was accepted.
  REGISTRY.md bounds resolution at three hops and requires a resolver to fail on a cycle, so a
  conforming resolver survives it — but the trivial self-loop is exactly the case a resolver
  written from the prose is most likely to mishandle, and it is the only cycle decidable from a
  single record. Refusing it at parse means no implementation has to be correct about it. This
  does **not** remove the need for cycle detection: `a → b → a` spans two records and is
  invisible from either, so the hop limit remains the real defence.
- **The index keyspace codec did not enforce the grammar its design depends on.** The `0x00`
  separator scheme is sound only because `tld` and `label` are drawn from `[a-z0-9-]`, and the
  codec checked only for the separator byte itself. It therefore relied on every caller having
  validated its input — and the index is precisely where a wrong key returns another owner's
  record rather than raising. It now enforces the grammar directly.

Both are modest, and that is the honest summary of this pass: it found less than the one before
it, which is what a second look at the same code should be expected to do.

## [0.1.0] — 2026-08-04

First tagged release. The registry core, working on one machine: record format, verification,
proof-of-work, the name lifecycle, a local log and a command-line tool. **No network** — peer
replication is Phase 2 — and nothing here should be run in front of a hostile party yet.

Versioned under [VWIP-0003](docs/spec/VWIP-0003.md). This release speaks **protocol version 1**.
Per that proposal it is not a reference implementation and must not be described as one: no
second implementation exists to check it against, so where this code and the specifications
disagree, the specifications win.

### Adversarial review

Run before this version was bumped, as VWIP-0003 section 3.1(3) requires. Recorded here
because a clean result is only evidence if someone says what was attacked.

**Attacked and found nothing:** CBOR nesting depth (already bounded at 32 in both encode and
decode, so a 4096-byte record of nested arrays cannot exhaust the stack); the duplicate-arrival
path; revocation stickiness across a post-quarantine re-registration; equivocation at the same
`seq`; signature and countersignature authority under every operation; the `--at` flag as a way
to forge a term (it cannot: a postdated record is deferred by every peer's own clock, and a
backdated one is refused).

**Found and fixed, in this release:**

- **A linear-cost amplification in the difficulty window.** Difficulty depends on the trailing
  thirty days of registrations in a TLD, and verifying one record consulted that twice by
  scanning every entry in the log — making a full replay O(N²). That is not merely slow: adding
  a record costs an attacker one proof of work, linear in what they spend, while the replay cost
  imposed on every peer that ever joins grows quadratically. `REGISTRY.md` offers no relief,
  since the log is never truncated and "a peer that has never verified the history and wants full
  assurance MUST pay the full cost once". Quadratic replay prices newcomers out of verifying, and
  a registry only newcomers-who-trust-someone can join is a different thing from the one
  specified. Now a per-TLD sorted index with two binary searches, and the duplicate check is a
  set rather than a scan.
- **A stray NUL byte in `store.ts`**, which had become the index-key separator by accident. It
  was collision-free and worked, but it made the file read as binary to `grep` and was nobody's
  intent. Replaced with a space, which is unambiguous because the label grammar admits only
  `[a-z0-9-]`.

The first fix is the one worth reading twice, because its first mutation test **failed to
fail**: reverting the sorted insertion to a plain append left all 189 tests green. The
out-of-order test had used two records with the same `notBefore`, so the array was sorted either
way and the property was never exercised. The test was rewritten to invert the order genuinely,
and the mutation then failed as it should. A test that passes against the broken version proves
nothing, and this one had to be caught by trying.

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

- **A command-line tool** (`registry/bin/vayuweb-registry.ts`) completing Phase 1's acceptance
  test: register a name into a local log, resolve it back, and reject every malformed and
  replayed record in the vector set. `keygen`, `register`, `update`, `renew`, `transfer`,
  `release`, `revoke`, `resolve`, `list`, `difficulty`, `verify` and `vectors`. `--at` pins the
  clock so any result is reproducible, and deferral is a distinct exit code rather than a soft
  rejection. It touches no network, and says so.
- **A local append-only log and index** (`registry/src/store.ts`). Length-prefixed deterministic
  CBOR, with the index rebuilt by replay and **every entry re-verified on load** rather than
  trusted for being on disk — a file an attacker can append to is not a file whose contents are
  known-good. Explicitly not Hypercore: no merkle tree, so entries are not self-authenticating
  and a light client cannot verify without replaying. Phase 2 replaces the storage beneath these
  interfaces without changing the rules above them.
- **VWIP-0003, the version scheme**, which `CHANGELOG.md` required before the first tag. Two
  independent numbers — the protocol version in every record, and the implementation version on
  the software — with a change to any verification rule classed as MAJOR even when the API is
  untouched, because a peer that accepts a different record set is a different implementation
  whatever its API looks like. It also forbids the term "reference implementation" until a
  second one exists, and forbids claiming conformance for areas with no test vectors.
- **Conformance vectors** (`conformance/vectors.json`, with a README describing the format).
  Forty cases pinning the registry record rules: each is a record's exact bytes, the registry
  state to verify it against, the instant to verify it at, and the verdict every conforming
  implementation must return. The rejection **code** is part of the contract rather than just
  accept-or-reject, which is what makes check order observable between implementations; `defer`
  is carried as a third verdict, since an implementation that rejects a clock-skewed record
  instead will disagree permanently with honest peers about a valid one. A test fails if a
  rejection code is added without a vector, and another compares the committed artifact against
  a fresh generation so an encoding change appears as a reviewable diff. Proof-of-work
  verification is injected rather than evaluated in these vectors, and the README says so
  plainly: passing them does not demonstrate a correct proof-of-work implementation.

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

- **The record schema let a registrant choose their own proof-of-work cost and salt.**
  `REGISTRY.md` listed `m`, `t`, `p` and `salt` as fields of `powProof`, while
  `PROOF-OF-WORK.md` specified the parameters as protocol constants and the salt as derived
  from the record. Two normative documents disagreeing about a wire format is a fork on its
  own; here the two readings also differ in whether the mechanism works at all. Cost parameters
  in the record mean `m = 8` KiB verifies happily, because the verifier evaluates whatever
  function the record names. A salt in the record is worse: the salt is what binds a proof to
  one record, so a carried salt makes one ground `(salt, nonce)` pair reusable on every record
  its author ever signs — a single proof of work buying unlimited names. `powProof` is now the
  three-field triple `{alg, nonce, bits}`, a proof carrying any of the four removed fields is
  rejected rather than ignored, and the salt is derived from the record's canonical bytes.
- **Expiry was stated as a chain rule but missing from the verification pseudocode.** The prose
  requires a predecessor "still inside its term or grace period"; the pseudocode carried only
  `revoked()`. Implemented literally, a holder whose grace had lapsed could still sign an
  `UPDATE` or a `TRANSFER` while the name sat in quarantine — reclaiming it ahead of everyone
  waiting the window out, when quarantine exists so that nobody may take the name during it.
  The check is now in the pseudocode and in the verifier, drawn where the per-operation
  preconditions draw it: `RENEW` may act in grace, the other four need a live predecessor.
- **The index keyspace justified itself with a false claim.** `REGISTRY.md` said key components
  "contain no `0x00` (guaranteed by the label grammar and by fixed-width integers)". True of
  `tld` and `label`; false of the two it names as guaranteed. A `u64be` timestamp in this
  century begins with four zero bytes, so *every* key in the expiry and rate keyspaces carries
  embedded separators, and a random Ed25519 owner key carries one about 12% of the time. The
  layout is unambiguous — a fixed-width component needs no delimiter — but an implementer who
  believed the sentence and split keys on `0x00` would parse three of the four keyspaces
  wrongly, and silently: a truncated owner key returns another owner's names rather than
  raising. Decoding is now specified as positional, and the codec pins it against keys chosen
  to contain zero bytes.
- **The documented 20-bit difficulty ceiling is unreachable.** `base` tops out at 10 and the
  rate term at 8, so the schedule cannot return more than 18 bits. The spec described twenty
  bits — "roughly a million evaluations, hours of CPU" — as the worst case a registrant should
  budget for; the real worst case is about 262,144 evaluations. The text now says so, and a
  test pins the true bound so a schedule change that makes 20 reachable is deliberate.
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

- **What this release does not do.** There is no network: no discovery, no replication, no
  convergence, no equivocation detection, no checkpoints and no light clients. The log is a local
  file rather than a Hypercore, so entries are not self-authenticating and nothing can be
  verified without replaying everything. `proxy/` and `client/` remain placeholders. Replication,
  convergence and resolution have no conformance vectors either, and per VWIP-0003 section 4.3 no
  claim of conformance is made for them.
- Phase 6 of the roadmap — a second implementation by parties with no common employer or funder
  — cannot be delivered from inside this repository and is not claimed as progressing.
- Proof-of-work verification is defined as an interface (`RegistryView.powVerified`) with no
  default implementation. A permissive default would make every caller that forgot to supply one
  accept unproven records silently, which a passing test suite cannot show.
- Long-term development will move to Radicle; this GitHub repository is a public mirror.
