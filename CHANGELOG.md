# Changelog

All notable changes to VayuWeb are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Versions follow the scheme set by [VWIP-0003](docs/spec/VWIP-0003.md), which keeps the
**protocol version** carried in every record separate from the **implementation version** on the
software. Before 1.0.0 the public interface is explicitly unstable and a minor release may break
it.

## [Unreleased]

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
