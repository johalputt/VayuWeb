# Changelog

All notable changes to VayuWeb are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Versions follow the scheme set by [VWIP-0003](docs/spec/VWIP-0003.md), which keeps the
**protocol version** carried in every record separate from the **implementation version** on the
software. Before 1.0.0 the public interface is explicitly unstable and a minor release may break
it.

## [Unreleased]

### Added

- **CI grows from 14 jobs to 23**, across a new `quality.yml` and additions to the existing
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
