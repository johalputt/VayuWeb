# Adversarial audit findings — 2026-08-04

Raw output of a corpus-wide adversarial audit: seven auditors over the specification set, the
charter and the implementation, each finding independently rechecked by a separate agent whose
instruction was to **refute** it.

130 candidates were raised. 31 were refuted and are not listed. 67 survived and are below. 32
could not be rechecked before the run hit a limit and are **not** listed either — absence from
this file is not evidence of soundness.

This is the raw record, kept verbatim because a finding nobody wrote down gets rediscovered
later at greater cost. What has actually been acted on lives in `CHANGELOG.md`; this file is
evidence, not a changelog.

Severity is the rechecker's corrected value, not the finder's claim. Bodies are fenced verbatim
so that quoted paths and snippets are not re-interpreted as markup, **and they are never edited
after the fact** — a finding that says "not fixed" is describing the corpus on 2026-08-04, not
today. Read the disposition below for current state.

## Disposition — every HIGH finding

Added because the status of these was re-derived from scratch three separate times, each costing
a full re-read of the corpus, and twice the answer was "already fixed, the finding text is
stale". A finding with no recorded outcome is a finding somebody re-investigates.

Four outcomes are used, and the distinction between the last two matters:

- **Fixed** — the defect is gone and a test or a checker refuses its return.
- **Escalated** — real, and not an implementer's to decide. Both sides are Articles of the
  Constitution, so Article 3.7 cannot rank them and Article 58 reserves the choice to an
  amendment. `scripts/check-charter-consistency.py` prints each on every run and fails if one is
  closed by editing a single side. Escalated is not deferred: the conflict is held open
  deliberately and visibly.
- **Stale** — the defect was real when written and had already been fixed before this file was
  triaged. Recorded rather than deleted, so the next reader does not re-derive it.

| # | Finding | Outcome |
| --- | --- | --- |
| 1 | `registry-worked-example-powproof` | **Fixed.** Example rewritten; a test parses it out of the document |
| 2 | `namespace-tld-set-contradiction` | **Fixed.** RESOLUTION.md defers to the Namespace Annex; `check-counts.py` derives the number |
| 3 | `local-surface-vs-resolution-control-api-tcp` | **Fixed.** `assertSocketAddress` throws on TCP; `check-listeners.py` holds the corpus |
| 4 | `privacy-query-log-contradiction` | **Fixed.** Both documents corrected to PRIVACY.md's "never written, in either mode" |
| 5 | `privacy-private-mode-ephemeral-profile` | **Fixed.** The platform fallback is normative and must be reported |
| 6 | `crypto-agility-registry-suite-mismatch` | **Fixed.** `suite` field, per-suite sizes, downgrade rule, three vectors |
| 7 | `manifest-schema-conflict` | **Stale.** HOSTING.md defers to PUBLISHING.md; RESOLUTION.md step 13 consults the manifest |
| 8 | `hosting-ipns-cid-selection-conflict` | **Stale.** `SOURCE_ORDER` is `ipns, cid, peer, alias`, with the reasoning in `resolve.ts` |
| 9 | `publishing-inline-hash-vs-content-security` | **Fixed.** The third relaxation is withdrawn; the argument for it is kept |
| 10 | `registration-term-conflict` | **Escalated.** Art 11.6 vs 32.2 vs REGISTRY.md — three terms |
| 11 | `art-29.4-vs-registry-op-set` | **Fixed** for `RELINQUISH` and the stated gap; **escalated** for `RENEW` and `TLD-CREATE` |
| 12 | `epoch-three-definitions` | **Escalated.** Art 2.5 an interval, Art 11.5 an instant |
| 13 | `constitution-vs-registry-renewal-grace-windows` | **Escalated.** Renewal window and post-expiry interval, three sources each |
| 14 | `art-33-4-settlement-delay-absent-from-specs` | **Fixed.** Fourteen-day settlement implemented, with seven vectors |
| 15 | `names-registry-transfer-op-mismatch` | **Fixed.** NAMES.md rewritten to the single-record `TRANSFER` |
| 16 | `names-namespace-tld-ratification-vote-vs-constitution` | **Fixed.** The ballot is gone from both documents, and `check-counts.py` pairs them |
| 17 | `vwip-0000-missing-naming-and-constitutional-amendment-categories` | **Fixed.** Both declared; VWIP-0004 uses them |
| 18 | `names-reserved-labels-unimplemented` | **Fixed.** `RESERVED_LABELS` enforced, one vector per label |

## Disposition — MEDIUM and LOW, as far as triaged

| Finding | Outcome |
| --- | --- |
| `conformance-vector-coverage-claim` | **Fixed.** The coverage list is derived from the rejection codes; six vectors added |
| `registry-fully-released-undefined` | **Fixed.** `fully_released` defined per operation, pinned against `lifecycle.ts` |
| `csp-four-channels-vs-eight` | **Fixed** in all three documents; the count is derived and the overstatement forbidden |
| `content-security-4.1-uniform-headers` | **Fixed** with it — conformance item 1 no longer contradicts 2.3 |
| `csp-test1-vs-relaxations` | **Fixed** with the same change |
| `csp-injection-scope-html-vs-every-response` | **Fixed** with the same change |
| `uri-scheme-tld-grammar-excludes-p2p` | **Fixed.** `URI-SCHEME.md` takes `NAMES.md`'s production; the two are paired |
| `letters-only-tld-grammar-uri-scheme-catalogue` | **Fixed** with it |
| `namespace-two-char-conformance-contradiction` | **Fixed.** Three `NAMESPACE.md` §7 items rewritten; two guards |
| `registry-eleven-tlds-vs-1267-catalogue` | **Stale.** `REGISTRY.md` defers to the Annex |
| `tld-set-specified-three-ways` | **Stale.** One `RATIFIED_TLDS` reference, resolved against the Annex |
| `check-counts-tld-enumeration-anchor` | **Stale.** The matcher was rewritten to find chains structurally, with no anchors |
| `docs-spec-nomatch-path-divergence` | **Stale.** `RESOLUTION.md` step 13 serves `notFound` then `fallback` |
| `registry-verify-check-order-too-large-vs-non-canonical` | **Stale.** The size bound runs before decoding, as it must |
| `implementation-omits-named-reserved-labels` | **Fixed.** `_vayu` was ungrammatical, not reserved; the two sets are compared by a test |
| `VWIP-0000-final-missing-sections` | **Fixed.** Five sections written; `check-vwips.py` reads the table from the document |
| `docs/spec/PROOF-OF-WORK.md:135,118` | **Fixed** with it — the same missing-sections finding under a filename |
| `vwip0001-test-count` (LOW) | **Fixed.** Seventeen, derived from the two conformance sections |
| `docs-spec-cross-reference-section-numbers` (LOW) | **Fixed** for the four found; not swept exhaustively |
| `registry-worked-example-powproof` (MEDIUM ×3) | **Fixed** — the same finding as HIGH #1, raised four times |
| `pow-64x-ratio` (LOW) | **Fixed.** 64× is the gap to a *sixteen*-character label; fifteen is 32× |
| `arch-resolution-ttl-status-contradiction` (LOW) | **Fixed.** `ARCHITECTURE.md` defers the three cache lifetimes to `RESOLUTION.md` |
| `uri-scheme-conformance-2-identical-uris` (LOW) | **Fixed.** The item compared a name with itself; both origin components now tested |
| `uri-scheme-s7-origin-isolation-self-comparison` (LOW) | **Fixed** with it — the same finding under a second name |
| `resolution-cs-section-1-3` (LOW) | **Stale.** Corrected to section 2.3 with the other cross-references |
| `pow-registry-signed-checkpoint` | **Fixed.** Checkpoints are unsigned in all three documents; a paired statement holds it |
| `resolution-passthrough-vs-local-surface` | **Fixed.** `LOCAL-SURFACE.md` 2.1.1 carves the mode out with four constraints |
| `privacy-contained-webview-vs-locked-profile` | **Fixed.** Private Mode narrows the browser; only the webview closes WebRTC |
| `local-surface-cross-name-subresources-vs-content-security` | **Fixed.** The allowance is withdrawn; 2.3's list is closed |
| `local-surface-3.3-3.4-unspecified-bounds` | **Fixed.** Four concrete limits and a negative-cache bound, stated as judgements |
| `resolution-md-cross-reference-and-count` | **Stale.** Corrected with the residual-channel sweep |

## Disposition — UNRATED

UNRATED means the recheck did not assign a severity, **not** that the severity is low. One of
these turned out to be the largest remaining gap in the record format.

| Finding | Outcome |
| --- | --- |
| `attestation-registry-record-type-conflict` | **Fixed.** `attest` is an entry, not an operation, and `REGISTRY.md` carries neither yet; a test refuses any document naming a type the registry lacks |
| `pow-log-anchor-missing` | **Acknowledged, with the gap measured.** Articles 29.5.d and 31.1 require a log anchor and no field carries one. Closing it is a VWIP; what the salt delivers instead, and the three questions a VWIP must settle, are written into both documents |
| `names-reserved-labels-unenforced` | **Fixed** with the HIGH finding of the same name |
| `names-reserved-labels-vs-art-10-8` | **Fixed** with it |
| `names-transfer-vs-registry-transfer` | **Fixed** with `names-registry-transfer-op-mismatch` |
| `resolution-control-api-tcp-vs-unix-socket` | **Stale.** `check-listeners.py` holds four documents and the code |
| `resolution-control-api-tcp-7653` | **Stale** with it |
| `registry-epoch-activation-interval` | **Stale.** Corrected to the 180-day constitutional floor |
| `names-tld-retire-24mo-vs-const-35.10` | **Stale.** The 24-month sunset was withdrawn, with the reason recorded |
| `names-tld-sunset-vs-registry-register-renew` | **Stale** with it |

| `privacy-md-secret-storage-contradiction` | **Fixed.** The keystore fallback is normative, reported, and limited to the control-API token |
| `content-security-md-s3-clipboard-permissions-policy` | **Fixed.** `clipboard-read` and `clipboard-write` exist and are now denied — and the proxy was emitting no `Permissions-Policy` at all |

| `registry-epochs-checkpoint-conjunction` | **Fixed.** A boundary now triggers a checkpoint, so silence cannot stop the epoch counter |
| `resolution-step8-release-revoke-lifecycle` | **Fixed.** Step 8 defers to the lifecycle rules, and a revoked name returns 1412 rather than "expired" |
| `resolution-step1-vs-local-surface-host-normalisation` | **Fixed.** A `Host` with a port is rejected, never repaired |

**Every finding in this file now carries an outcome.** Sixty-six headings, of which several are
the same defect filed more than once; the disposition tables above say which.

**Every HIGH, MEDIUM and LOW finding now carries an outcome.** The count of untriaged MEDIUM
findings is worth stating rather than implying: zero MEDIUM, and none at LOW either. **Fifteen
UNRATED remain**, and UNRATED means the recheck did not assign a severity rather than that the
severity is low — several are of the same class as findings that turned out to be HIGH. That is a statement about this file rather than about the
corpus — several are certainly stale in the way the entries above turned out to be, and finding
out costs a re-read each time. Whoever works them should extend these tables rather than
repeating the survey.

Two patterns are worth carrying into that work. **Duplicates**: `registry-worked-example-powproof`
appears four times at two severities, so the list is shorter than it looks. And **the same defect
under two names**: `docs/spec/PROOF-OF-WORK.md:135,118` is the VWIP-0000 missing-sections finding
filed under a file-and-line heading, which is why headings that name a location rather than a
defect are worth re-reading before being counted as separate work.

**The lesson the HIGH set carries, stated once.** Fourteen of the eighteen were invisible to
reading any one document and obvious with two open at the same time — a specification against
the charter, a specification against its sibling, or the charter against itself. Every checker
this project had before the audit compared prose to a list or a number to its source. The four
that now exist for cross-document agreement — `check-charter-consistency.py`'s quantities, terms
and memberships, and `check-counts.py`'s paired statements — exist because that class of defect
has no other way of being caught.

## registry-worked-example-powproof — HIGH

```text
Could not refute; every limb verified at HEAD. REGISTRY.md:526-534 (claim cited 487-495 — stale
offset only, commit 99d6355 inserted the merkle section above it) carries powProof
{alg:"argon2id", m:262144, t:3, p:1, salt:"XaGvK-1McJRNX-agVfElbQ", nonce:41827366, bits:22},
with no caveat — REGISTRY.md:509 introduces it plainly as "A registration of atlas.vayu as
JSON", not as a counter-example. REGISTRY.md:80-83 requires "exactly three keys" (alg =
argon2id-v19-m65536-t2-p1, nonce bstr 16 bytes, bits) and :85 states "A verifier MUST reject a
powProof carrying m, t, p or salt" — both cited lines exact. record.ts rejects the example three
ways: :174 alg !== POW_ALGORITHM ('argon2id-v19-m65536-t2-p1', pow.ts:34) -> BAD_POW_SHAPE;
:179-183 forbidden m/t/p/salt -> BAD_POW_SHAPE; :187 bytesField(map,'nonce',16) rejects the
integer nonce (as BAD_FIELD_TYPE, not BAD_POW_SHAPE — trivial label difference in the claim).
PROOF-OF-WORK.md:133-135 says the schedule's max is 18 bits; example claims 22. Provenance
confirms a missed edit rather than intent: git show a240435 ("remove the dials that made it
free") rewrote REGISTRY.md:80-85 from the old {alg,m,t,p,salt,nonce,bits} prose to the three-key
form and says "REGISTRY.md is corrected to match PROOF-OF-WORK.md", but its diff touches only
that paragraph. The Worked Example is a literal survival of the pre-fix schema the same commit
declared an attack. Not fixed: nothing in CHANGELOG [Unreleased] addresses it, and no CI gate
parses the example (only a comment reference at registry/src/domain.test.ts:21). Consequence is
if anything understated: conformance/vectors.json:173-175 publishes vector schema/pow-carrying-
cost-parameters, rule "REGISTRY.md: powProof is {alg, nonce, bits}", expect reject — so the
artifact measuring independent implementations requires rejecting exactly the shape the spec's
only complete record models, in a project whose Phase 6 acceptance is an unrelated second
implementation built from the spec. Severity corrected to high rather than critical: the
security property is intact (both code and normative prose enforce the safe form, so no verifier
is weakened), and failures are loud — the first vector run fails rather than passing silently.
Weakest limb is bits:22 — pow.ts:174-193 documents "over-payment is valid and harmless" and
record.ts:191 permits 1-256, so 22 is not a rejection cause; it is a value the schedule cannot
return, overstating the cost budget ~4x, the same overstatement a240435 corrected in PROOF-OF-
WORK.md while leaving it standing in the example.
```

## namespace-tld-set-contradiction — HIGH

```text
Every quotation checks out verbatim. RESOLUTION.md:58-60 hard-codes eleven TLD strings inside a
section headed "normative and ordered", with step 3 returning 1403 TLD_UNKNOWN for anything
else. REGISTRY.md:49 says "One of the eleven launch TLDs; any other is rejected" and
REGISTRY.md:256 rejects UNKNOWN_TLD on membership of RATIFIED_TLDS — a symbol that appears
exactly once in REGISTRY.md and is defined nowhere in the spec set. NAMESPACE.md:39 (2.3) and
§7.1 are RFC-2119 normative and a numbered conformance clause: MUST NOT hard-code, set derived
from the log. NAMES.md:192 and NAMESPACE-CATALOGUE.md:3 state 1,267. Three findings beyond the
claim as filed. (1) The log-derived rule is unimplementable from these documents: REGISTRY.md's
op enum is closed (REGISTER/UPDATE/RENEW/TRANSFER/RELEASE/REVOKE) and verify() rejects
UNKNOWN_OP, so no record can bring an extension into being — a mechanism gap, not a wording
clash. (2) The code and CI enforce the framing NAMESPACE.md:9 says it supersedes:
registry/src/names.ts:31 freezes the eleven ("this constant is wire-visible"),
registry/src/names.test.ts:22 asserts the set is exactly eleven, registry/src/record.ts:293
rejects UNKNOWN_TLD, and scripts/check-counts.py fails the build on any markdown enumeration
omitting one of the eleven. (3) I compared the two sets programmatically: only 8 of the 11
ratified TLDs appear in the 1,267-entry catalogue; .blog, .news and .p2p are absent from it
entirely (they are the ICANN gTLD echoes NAMESPACE.md 5.2 forbids). So 1,259 catalogued
extensions are unregistrable and 3 registrable ones are uncatalogued. Correction to the claim:
the example shop.art is wrong — neither .art nor .shop is in the catalogue (5.2 excludes ICANN
gTLD echoes). Correct instances are atlas.ai (NAMESPACE-CATALOGUE.md:52) or me.cv (:64),
catalogued yet rejected UNKNOWN_TLD / 1403. The claim's secondary points hold: TLD creation and
the 12-month retirement alias tail both require a client update under a hard-coded step-2 list,
contradicting NAMESPACE.md 2.3's "without an update"; and a log-derived set cannot be consulted
at step 2 when step 7 is where an unsynchronised log is detected (1502). Not already fixed: the
CHANGELOG namespace entries concern a duplicated .vayu and a twelve-vs-eleven count, the
opposite direction; [Unreleased] contains nothing on this. check-counts.py's "(\w+) at launch"
pattern captures the word "extensions" from README:107's "1,267 extensions at launch" and
discards it as non-numeric, so the gate built for exactly this drift is blind to it. Not a
roadmap-deferred feature either: ROADMAP Phase 0 is the current phase and its open item is
precisely the adversarial spec review, with the acceptance test being that an implementer
reading the specs alone can build an interoperating client — which this defeats. Severity high
rather than critical: nothing is deployed, no user harm today, and the reference implementation
is internally self-consistent; but the project's own commit b59963a calls a differing ratified
set a fork, and this is a contradiction between two normative documents plus a conformance
clause.
```

## local-surface-vs-resolution-control-api-tcp — HIGH

```text
Verified line by line; I could not refute it. WHAT I CHECKED -
/workspace/vayuweb/docs/spec/LOCAL-SURFACE.md:12-38 — §1 is exactly as quoted: "The control API
MUST be served over a Unix domain socket (POSIX) or a named pipe (Windows), with mode 0600 ...
It MUST NOT listen on TCP, on any address, including loopback", and line 36 "A build that offers
a TCP control listener — even opt-in, even 'for development' — is non-conformant". §6
conformance test 1 is "The control API is not reachable over TCP on any address. A connection
attempt to any port finds no control listener." -
/workspace/vayuweb/docs/spec/RESOLUTION.md:26-47 (Components) agrees with LOCAL-SURFACE: the
listener table lists `<runtime-dir>/vayuweb.sock` for the control API, states "only one of them
is a network listener", repeats the MUST NOT-on-TCP rule verbatim, and declares LOCAL-SURFACE.md
normative. - /workspace/vayuweb/docs/spec/RESOLUTION.md:151-185 ("The control API") was NOT
updated with it: line 153 "The control API on `127.0.0.1:7653` is JSON over HTTP", and line
180-184 specifies Origin-rejection plus the `X-VayuWeb-Control: 1` custom-header/preflight
defence "so no browser page ... can reach these endpoints even if it learns the port" — a
defence that is meaningless without a port. So RESOLUTION.md contradicts itself internally, ~120
lines apart, and the stale half is the half that enumerates the endpoints an implementer would
build from. CORROBORATION THAT IT IS STALENESS, NOT A DELIBERATE SPLIT - `git log` shows LOCAL-
SURFACE.md has been touched once since it was added (8647baf, an unrelated CLA wording fix),
while RESOLUTION.md has had three edits; the Components section carries the socket rule and the
control-API section does not, i.e. the update landed in one place only. - ARCHITECTURE.md:84
goes further than a stale port number and states an incompatible rationale: "`127.0.0.1:7654`
for the HTTP proxy and `127.0.0.1:7653` for the control API. Two ports, not one, so that the
control API can be firewalled or disabled without disabling resolution." ARCHITECTURE.md:104 and
:208 repeat it; GLOSSARY.md:47, WHITEPAPER.md:144 and :163 (the ASCII diagram), ROADMAP.md:85
(Phase 3's definition of done) and NAMES.md:77 (the rationale for reserving `control`/`api`) all
still carry 7653. - Nothing in RESOLUTION.md marks the control-API section as superseded; the
only pointer is the normativity sentence at line 47, three pages earlier. REFUTATIONS I TRIED
AND REJECTED - "Already fixed": no. CHANGELOG.md `[Unreleased]` covers CI gates, the merkle
tree/checkpoints, the fuzz suite and `registry/src/resolve.ts`; no entry touches the local
surface. `grep` for `7653` and `vayuweb.sock` across the source tree returns nothing — `proxy/`
and `client/` contain only README.md. - "Not yet built, so out of scope": partially true and it
is why I lowered severity, but it does not refute the finding. ROADMAP.md Phase 3 is explicitly
unbuilt, and the roadmap's own position is that the specification settles before code ("code
written before the specification settles is code that will be thrown away"). A normative self-
contradiction is therefore a defect in the current deliverable, not a premature one — and it is
the same class as commit 047d969, "RESOLUTION.md required the resolver to emit the fingerprint
it forbids", which was fixed as a real defect on exactly this basis. - "Style/wording": no. Two
RFC 2119 MUST-level statements about the same listener are mutually exclusive; an implementer
reading top-to-bottom hits the endpoint list, builds `127.0.0.1:7653`, and fails LOCAL-SURFACE
conformance test 1. SEVERITY — corrected down to high The claimed consequence
(rebinding/CSRF/Upgrade/port-scan exposure returning) is the right consequence but is not live:
no control API exists in the tree, so nothing is exploitable today. Two things also cap it below
critical — RESOLUTION.md states the correct rule in its own Components section and explicitly
cedes normativity to LOCAL-SURFACE.md, so a careful reader can resolve the conflict; and LOCAL-
SURFACE.md is marked "Draft — not yet implemented". High rather than critical, and the fix is
documentation-only: rewrite RESOLUTION.md's control-API section to address `<runtime-
dir>/vayuweb.sock` (keeping the bearer token and the Upgrade rejection, dropping or re-framing
the Origin/preflight paragraph, which is dead reasoning on a socket), then sweep the 7653
references in ARCHITECTURE.md (including the "two ports" rationale at :84), GLOSSARY.md:47,
WHITEPAPER.md:144/:163, ROADMAP.md:85 and NAMES.md:77.
```

## privacy-query-log-contradiction — HIGH

```text
Confirmed; every quotation is accurate and no reading reconciles them. PRIVACY.md:118 (§4 table)
and :134-135 state a query log is "Never written, in either mode" and that there is no logging
subsystem — explicitly rejecting "logging defaults to off" — with §10 test 7 asserting no
resolution data reaches durable storage under any verbosity setting; §2's mode table likewise
lists "Query logging | None | None". RESOLUTION.md:263-266, under its normative "Privacy
requirements" heading with RFC 2119 keywords declared at line 7, says logging is opt-in, "capped
by a retention in hours, and written only to a local file" — durable storage, not per-process
stderr. ARCHITECTURE.md:225 repeats the same posture and its preamble makes every SHALL an
implementation obligation. CONSTITUTION.md 14.1/14.2 forbid logging a lookup to durable storage
outright and 14.7's mandatory test fails on any durable file containing a resolved name; Article
14 is entrenched under Article 9. Refutations attempted and failed: (1) Article 14.5's optional-
diagnostic carve-out requires the diagnostic be per-session rather than persistent, so an hours-
long retention file is not licensed by it; (2) no supersession exists — PRIVACY.md:278 still
cites RESOLUTION.md as carrying "the proxy and its privacy obligations", and VWIP-0001, which
adopts PRIVACY.md as normative, lists nine substantive changes, none removing the opt-in log;
(3) not fixed — git log and CHANGELOG contain no change touching query logging (commit 047d969
fixed a different RESOLUTION.md privacy defect, the diagnostic headers), and the tree is clean;
(4) not a "not-yet-built" exemption — the spec text is the Phase 0 deliverable and an
adversarial spec review is the named open Phase 0 item. Severity corrected from the implied
critical framing to high: no resolver code exists yet (registry/src/resolve.ts has no logging
path), so this is a normative contradiction against an entrenched Article rather than a live
leak. Fix is a one-line strike at RESOLUTION.md:263 pointing at PRIVACY.md §4, plus the same at
ARCHITECTURE.md:225.
```

## privacy-private-mode-ephemeral-profile — HIGH

```text
Could not refute; verified in full. PRIVACY.md:46 states Private Mode's durable local state as
unconditional ("Memory only. Nothing durable."), and the same table (line 42) shows the authors
scope rows to the resolver when they mean to — it separates resolver-originated requests from
browser-originated ones and says Private Mode's browser is "Contained, because full-proxy
configuration and the client's own webview are mandatory". So the webview's profile directory is
inside VayuWeb's control; the "that row only covers the resolver" defence fails on the table's
own text. The only normative clause (165-166) qualifies the profile as memory-backed "where the
platform provides one" — macOS and Windows provide none by default, so the profile (which line
168 says covers history, session restore and the visited-link database) is written to disk and
deleted. PRIVACY.md:183 forecloses the "written then deleted is fine" reading in the document's
own words: filesystem metadata "can outlive a deleted file. Private Mode avoids creating the
file at all, which is the only reliable defence" — a claim the conditional clause cannot deliver
there. Conformance test 3 (line 240) asserts zero durable writes under a filesystem monitor
while §10's preamble demands observed behaviour and test 1 loads a page, so it either fails or
is silently narrowed to the resolver process. §11 does not disclaim this, and line 270-273
requires conditional controls to name their condition where the claim is made. The spec
elsewhere shows the correct shape and does not follow it here: §6's mlock mitigation is likewise
platform-conditional but carries "MUST attempt and MUST report when it fails"; line 165 imposes
no fallback and no reporting duty. Blast radius beyond the cited section: CONTENT-
SECURITY.md:88, CONTENT-SECURITY.md:214, URI-SCHEME.md:107 and VWIP-0001.md:209 all rely on the
ephemeral profile with no residual stated; grep shows "memory-backed" appears exactly once in
the repo. Not already fixed — CHANGELOG.md has no entry on the profile directory (line 260 only
restates "memory-only state") and the last commit touching PRIVACY.md was unrelated. Not out-of-
scope-by-roadmap: Phase 0 (current) is exactly the adversarial spec review, client/ is
unimplemented, and the spec text is the artefact. Severity high rather than critical: no
implementation exists so no reader is exposed today, but it is the headline claim of the privacy
spec, replicated unqualified across three specs plus a VWIP, it breaks a conformance test on two
of three desktop platforms, and it violates the constitutionally entrenched Duty of Honest
Claiming (Article 21). Fix is a clause: name the fallback location normatively, require a report
when no memory-backed location exists, and add the residual to §6 and §11.
```

## crypto-agility-registry-suite-mismatch — HIGH

```text
Verified directly. REGISTRY.md contains zero occurrences of "suite" anywhere in the file; its
Record Schema table (lines 45-58) is exhaustive and has no suite field, while pinning ownerKey
to "32 bytes | Ed25519 public key" (:50) and sig to "64 bytes | Ed25519 signature" (:57) —
exactly what CRYPTO-AGILITY.md section 1, section 3.2 and conformance item 7 call defective.
Signing inputs differ as quoted (REGISTRY.md:112 "VayuWeb-Registry-Record-v1" || 0x00 ||
det_cbor(core) vs CRYPTO-AGILITY.md:94 "vayuweb-record-v1" || uint8(suite) ||
canonical_cbor(...)), and the suite byte has no source field to read. Size limits conflict:
REGISTRY.md:135 flat "at most 4096 bytes" vs CRYPTO-AGILITY.md:73 "MUST therefore be expressed
per suite, not as one global constant". CRYPTO-AGILITY.md:215 describes REGISTRY.md as "the
record format that carries suite", which is false, and docs/LONGEVITY.md:33 states as a verdict
that the suite field "is present from record zero", which is false — a published claim defect of
the kind the repo's own audit rule targets. Not already fixed: CHANGELOG.md records eight spec
defects found during implementation, none of them this. Not exempted as unbuilt: ROADMAP.md
Phase 0 is the current phase, its open item is the independent adversarial spec review, and its
acceptance is Article 44.6 (specs alone suffice to build an interoperating client).
Implementation confirms REGISTRY is the one being followed: registry/src/domain.ts:28
RECORD_SIGNING_PREFIX = 'VayuWeb-Registry-Record-v1', and conformance/vectors.json has no suite.
Severity corrected from the claimed critical to high: the stated consequence "no signature
verifies for the other" is overstated, because CRYPTO-AGILITY.md defines no record schema and
REGISTRY.md is the specific, vector-backed authority for record bytes, so no real interop break
exists today. The genuine defect is that the agility mechanism is unimplementable as specified
(4.2, 5.1 and conformance items 2, 3, 6, 7 have no field to read), the record schema hard-codes
the primitive the agility spec forbids, and two documents assert a record-format property that
does not exist — in a docs-only, pre-implementation repo where it is fixable by editing the
schema, but which the document itself identifies as the one property that cannot be retrofitted
after launch.
```

## manifest-schema-conflict — HIGH

```text
Could not refute; the quotes are verbatim and the conflict is worse than claimed.
HOSTING.md:44-47 normatively defines .vayu/manifest.json as carrying
title/description/entry(default index.html)/generator and declares it "advisory", with "A
resolver MUST render a site that has none, and MUST NOT trust the manifest over the actual
tree"; HOSTING.md:31 says the package format has "no manifest requirement". PUBLISHING.md:47-66
normatively defines the same path with a disjoint schema — version, index, fallback, notFound,
inline.{style,script}, csp.{wasm,trustedTypes} — and title/description/entry/generator appear
nowhere in PUBLISHING.md. `entry` and `index` are two names for one field in one file.
PUBLISHING then gives the manifest force HOSTING denies it: PUBLISHING.md:98 declares
csp.wasm/csp.trustedTypes as manifest-declared "genuine widenings" of the CSP, and
PUBLISHING.md:104-106 is a SHALL ("the resolver SHALL serve notFound with HTTP 404 if present;
otherwise, if fallback is declared, serve it with HTTP 200"). Neither has a tree-side
equivalent, so "advisory" cannot hold. Third document confirms the split: RESOLUTION.md:98-101
step 13 (Path mapping) resolves directories to index.html and returns 1414 PATH_NOT_FOUND on no
match, consulting no manifest at all — no entry, index, fallback or notFound; and
HOSTING.md:35-37 justifies its per-directory index.html requirement by saying a resolver "has
nothing to fall back on", the exact capability PUBLISHING 2.3 mandates. Three specs, three
incompatible accounts. One narrowing of the claim: PUBLISHING 2.1's inline-digest rule is NOT in
conflict — it explicitly says digests "MUST be computed by the resolver from the verified
content, never taken on trust from the manifest… The manifest declares intent; it does not
confer permission", which agrees with HOSTING's "MUST NOT trust the manifest over the actual
tree". The authority conflict is real for notFound/fallback/wasm/trustedTypes only. Not already
fixed: grep -rn manifest across the repo finds no manifest handling in registry/, proxy/,
client/ or conformance/, and CHANGELOG [Unreleased] lists eight implementation-found spec
defects, none of them this. Not out of roadmap scope — ROADMAP Phase 0 is the current phase and
its acceptance test (Constitution Art. 44.6) is that an implementer can build an interoperating
client from the specs alone, which two disjoint normative schemas for one wire-visible file
defeat. Severity set to high rather than critical because nothing is implemented yet (no running
system is currently wrong) and the CSP-widening path is guarded by 2.1's recompute-from-
verified-content rule, so the cost is interoperability and spec-integrity, not an exploitable
hole.
```

## hosting-ipns-cid-selection-conflict — HIGH

```text
I tried to refute this and could not. Verified quotes are accurate and in force: -
/workspace/vayuweb/docs/spec/HOSTING.md:132-135 — "A record MAY carry both. The recommended
pattern is an `ipns` entry for the living site and a `cid` entry for the last snapshot the owner
is willing to have served if the pointer cannot be resolved. Resolver preference order is
specified in RESOLUTION.md and is not restated here." The paragraph immediately above
(HOSTING.md:126-130) states the `ipns` rationale as "the registry record stays still while the
site behind it changes, which is what an author republishing weekly actually wants" — so under
this pattern the `cid` entry is by design the frozen older snapshot, not a per-publish refresh.
- /workspace/vayuweb/docs/spec/RESOLUTION.md:116-118 — "the resolver SHALL select in this order:
`cid`, `ipns`, `peer`, `alias`." SHALL, unconditional, with both entries present. -
/workspace/vayuweb/docs/spec/RESOLUTION.md:123 — the escape hatch is weaker than the claim even
assumes: "If the chosen entry fails, the resolver **MAY** fall back to the next". So a
conforming resolver need never fall back at all, and the owner-pinned snapshot is precisely the
entry that does not fail (HOSTING's whole availability section is about keeping that pin alive).
- Implemented as claimed: /workspace/vayuweb/registry/src/resolve.ts:94 `SOURCE_ORDER =
['cid','ipns','peer','alias']`, `selectSource` at resolve.ts:170-181 returns the first match
with no record-level override, and registry/src/resolve.test.ts:147-173 pins `cid` as the winner
when both are present. Checks that could have refuted it, and why they don't: - No override
anywhere else. REGISTRY.md:69-77 defines the entry types and constrains only `alias`
coexistence; nothing marks an entry primary or fallback, and nothing requires the `cid` entry to
be re-appended on each IPNS republish. - The HOSTING publish flow (steps 7-8) does append a
registry update per publication, which is the only reading that would keep `cid` fresh — but it
contradicts HOSTING's own stated reason for having an `ipns` entry at all, and would make the
`ipns` entry dead weight rather than "what an author republishing weekly actually wants". - Two
other places assume the opposite of the normative order, which strengthens rather than excuses
it: docs/ARCHITECTURE.md:172 describes resolve step 5 as "The proxy resolves the `ipns` entry to
a CID and fetches through Helia", and RESOLUTION.md:221-223 sizes the IPNS pointer cache at
"min(record validity, 120 seconds) — This is the mutable path, and a publisher updating a site
expects it live in about two minutes", a cache that is never consulted for any record following
HOSTING's recommendation. - Not already fixed: CHANGELOG.md `[Unreleased]` covers resolve.ts,
merkle/checkpoint and the `X-VayuWeb-*` default-off contradiction (CHANGELOG.md:132-148) but
says nothing about record selection order or the HOSTING pattern. - Not out of roadmap scope:
this is a settled-spec self-contradiction, exactly the class Phase 0's adversarial spec review
exists to catch, and identical in kind to the header contradiction already fixed as a defect. It
is not a style preference — both statements are normative (SHALL) and an implementer following
them faithfully produces a site that never updates. Severity: high, not critical. Nothing is
deployed (HOSTING.md:10 and its Status section: "Nothing described here has been implemented"),
so there is no live breakage; but the defect is silent and permanent in effect — a conforming
publisher and a conforming resolver both behave "correctly" while readers see frozen content
forever, and the wrong order is already frozen into code and a passing test. Fix is a spec
decision (either invert the order when both are present, drop the both-entries recommendation,
or add an explicit per-record preference), so it should be settled before more code depends on
SOURCE_ORDER.
```

## publishing-inline-hash-vs-content-security — HIGH

```text
Confirmed by reading both files in full. PUBLISHING.md:80-81 normatively permits the resolver to
append 'sha256-…' expressions to style-src and script-src, and builds it out with a manifest
`inline` field, publish step 3, doctor --fix ("declaring their digests in the manifest"), and
conformance items 3-4 in PUBLISHING §6. CONTENT-SECURITY.md declares itself the single source of
truth (lines 8-11) and contains ZERO mention of hashes/digests/manifest — grep for
"sha256|digest|manifest|doctor|publish" returns only unrelated hits (`manifest-src`). Its §2.3
table (161-162) gives inline style and inline script the relaxation "None. Move to a … in the
same CID." The two cannot both be satisfied: conformance 1 (line 320) demands the canonical
policy be emitted byte-identically on every response, which a per-site appended hash breaks;
conversely PUBLISHING conformance 6 demands a site passing `vayu doctor` be served without a
policy violation, which fails under byte-identical `script-src 'self'` for a manifest-declared
inline script. An extra conflict the claim did not cite strengthens it: CONTENT-SECURITY §2.3
and conformance 6 require every relaxation to be "visible to the reader"/"surfaced in the UI",
while PUBLISHING:90-91 says "The reader-facing security indicator MUST NOT change." The
relaxation count is three-way inconsistent: PUBLISHING:96 "the two remaining relaxations" (=3),
CONTENT-SECURITY:157 "the two relaxations", RESOLUTION.md:317 "one of the two per-site
relaxations". Not refutable on the standard grounds: CHANGELOG [Unreleased] is
registry/merkle/CI work and does not touch this; no code implements either spec (both "Draft —
not yet implemented"); and it is squarely in scope, since ROADMAP.md:28 makes the independent
adversarial spec review the current open Phase 0 item, whose done-condition is that an
implementer can read the specs alone and interoperate. One correction to the claim:
scripts/check-headers.py would NOT catch this. It only compares fenced blocks with a `<!--
canonical:… -->` sentinel against other fenced blocks beginning with the same header name;
PUBLISHING §2.1 is unfenced prose, so CI is silent on the divergence. The claim's premise about
the single source of truth holds, but "fails check-headers.py" overstates what the script does.
Severity lowered to high rather than critical: real normative contradiction with a concrete
interop consequence between two independent implementations, but nothing is implemented, so
there is no live user-facing breakage.
```

## registration-term-conflict — HIGH

```text
Every quotation checks out verbatim. CONSTITUTION.md:888 (Art. 11.6) sets tenure at 126,230,400
s (~4 years) and 11.13 (line 931) turns that exact number into a conformance test; 11.14
entrenches Article 11 under Article 9 and names Article 32 as its machinery.
CONSTITUTION.md:2008 (Art. 32.2) says "The term SHALL be five years", with a rationale paragraph
arguing specifically for five — same subject as Art. 11, so it is a direct contradiction, not
two different quantities. REGISTRY.md:154/178/272/298/338 and NAMES.md:85 set 31,536,000 s as an
exact equality with a BAD_TERM rejection. Refutation attempts all failed. (1) Art. 3.7
precedence (Constitution > VWIPs > Annexes > conformance suite > implementation docs) resolves
charter-vs-spec only by making the specs void to the extent of the conflict — which confirms the
shipped specs/code are non-conformant rather than excusing them — and it cannot resolve 11.6 vs
32.2, both in the same instrument at the same tier. The document's only stated tie-breaks are
heading-vs-clause and Preamble-vs-Article (lines 76-84); there is no intra-constitutional
conflict rule. (2) Not already fixed: registry/src/verify.ts:31-32 hard-codes TERM_SECONDS =
31_536_000 ("exactly one year. Not 'about' a year"), cli.ts mints records with it, and
conformance/vectors.json:253 publishes it as a vector. No CHANGELOG entry mentions tenure
length, and docs/ROADMAP.md:35-42 lists the eight spec defects found so far — this is not one of
them. (3) Not out-of-scope-by-roadmap: Phase 0 is the current phase and its open item is
precisely the adversarial spec review. Two corrections, both making the finding broader than
claimed rather than narrower: the divergence also covers the lapse machinery (Art. 11.8/11.10 =
90-day redemption + 90-day warning; Art. 32.3 = 12-month window + 180-day grace;
REGISTRY.md/NAMES.md = 60-day window, 30-day grace, 30-day quarantine), and the fork mechanism
is mis-stated — two spec-derived implementations would agree on 31,536,000; the disagreement is
charter-vs-spec, and concretely today the published vectors cannot satisfy Art. 11.13 as
written. Severity corrected to high rather than critical: nothing is deployed, no name has ever
been registered, and there is no security or availability consequence. But it blocks the stated
Phase 0 exit criterion (an implementer must interoperate from the specs alone, Art. 44.6), it
sits inside an entrenched Article, and resolving it requires amending either 11.6 or 32.2 before
any implementation can be called conformant.
```

## art-29.4-vs-registry-op-set — HIGH

```text
Verified in-file, not refutable. CONSTITUTION.md:1882-1885 declares a closed set of eleven
record types and requires unrecognised types to be REJECTED; REGISTRY.md:47 plus its Operations
section (RENEW at :172, RELEASE at :195) and the verifier pseudocode at :254 define a different
closed set of six. Overlap is only four (REGISTER, UPDATE, TRANSFER, REVOKE). Grep across all
.md confirms DELEGATE, KEY-ROTATE, RELINQUISH, TOMBSTONE, TLD-CREATE, TLD-FREEZE and TLD-RETIRE
appear ONLY in CONSTITUTION.md and have no wire schema anywhere in docs/spec/, while Arts. 19.3
("Conformant clients MUST implement tombstone honouring"), 34.2 (DELEGATE record), 35.9 (TLD-
FREEZE) and 35.10 (TLD-RETIRE) mandate them. The conflict is not resolvable by reading further.
Art. 3.7 sets precedence "this Constitution; Final VWIPs; ... implementation documentation" and
voids the lower instrument to the extent of the conflict, so the spec loses; Arts. 44.5/44.6
make spec insufficiency itself a defect. It is not already fixed: no CHANGELOG entry mentions
Art. 29.4, "closed set" or the op-set divergence, and no errata/reconciliation doc exists. It is
not a roadmap "not yet built" item either — the divergence has already propagated into shipped
artifacts: registry/src/record.ts:27 OPERATIONS lists the six and :286 raises UNKNOWN_OP,
conformance/vectors.json pins RENEW/RELEASE vectors (lines 538/569/617/632), and ROADMAP.md:50
endorses "the six operations". Worse than filed in one respect: the charter contradicts itself.
Arts. 11.6 and 11.8 (lines 888-903) name RENEW records as normative ("the latest REGISTER or
RENEW record"; "the only record a conformant implementation MAY accept ... is a RENEW") and Art.
31.1 requires a renewal record to carry proof-of-work, yet 29.4 omits RENEW from the closed set.
So 29.4 is the erroneous clause, but it is the highest-precedence instrument as written.
Corrections to the claim: it says "five of which" and then lists six, and it omits RELINQUISH
from the charter-only set. RELEASE/RELINQUISH are plausibly one operation under two names
(REGISTRY.md:195 semantics match Art. 19.2's "relinquish the name"), so that half is a naming
reconciliation rather than a missing capability. Severity corrected from critical to high:
nothing is deployed (ROADMAP.md:3 "Nothing here is implemented"), so the "total non-
interoperation" consequence is prospective, and an implementer reading Arts. 11.6/11.8/31.1
would infer 29.4's list is stale rather than genuinely reject RENEW. But the contradiction is
unambiguous, normatively binding under Art. 3.7, already baked into code and vectors, and
directly defeats Phase 0's stated completion condition (Art. 44.6 sufficiency), so it must be
settled by VWIP before any tag.
```

## epoch-three-definitions — HIGH

```text
Could not refute; every quote checks out verbatim. CONSTITUTION.md:206-209 (Art 2.5) defines
Epoch as a fixed interval of 1-14 days whose length is recorded in the Annex and which MUST NOT
be adjustable at run time. CONSTITUTION.md:881-882 (Art 11.5) defines "every epoch in this
Constitution" as an integer count of SI seconds since 1970-01-01T00:00:00Z — an instant, not an
interval — and the scope is deliberate, since the following sentence is explicitly narrowed to
"this Title" while this one is not. Usage confirms the timestamp sense throughout (11.6 "epoch
of the latest REGISTER or RENEW record", 11.7 "exceeds the receiving party's own clock", 20.2
"records created at or after that epoch"). REGISTRY.md:461-468 self-declares as the definition
of the constitutional term and sets it at >=2,592,000 s (30 days) AND at least one checkpoint:
30 days breaches the 14-day MUST NOT, and the conjunction makes the length variable, breaching
"fixed". REGISTRY.md:484-486 additionally sets a "two epochs / roughly sixty days minimum"
activation floor against the Constitution's 15,552,000 s (180 day) floor at Art 20.3, 20.11,
47.6 and 35.7. The standard escapes do not work. Art 3.7 precedence voids REGISTRY.md where it
conflicts, but cannot resolve 2.5 against 11.5, both inside the highest instrument; Art 3.21
("terms defined in Article 2 keep their defined meaning") points toward 11.5 being the
conflicting text rather than curing it. A capital-E/lowercase convention does not save it: the
load-bearing term appears as "Activation Epoch" at 2.5 and 9.11 and "activation epoch" at 20.3,
20.11, 42.4.j, 47.6 and 35.7 for the same concept, and docs/GLOSSARY.md:10 adds a fourth framing
("A point strictly in the future"). No file matching *annex* exists anywhere in the repo, so Art
2.5's pointer to the recorded epoch length resolves to nothing — which is why REGISTRY.md filled
the gap and did so outside the stated bound. Not already fixed: CHANGELOG.md contains zero
occurrences of "epoch". Not an unbuilt-feature complaint: docs/ROADMAP.md marks Phase 0 as
current with "Independent adversarial review — Open — this is the current work", so settling
this term is exactly the current phase. The harm is already in-tree: docs/spec/VWIP-0002.md:212
schedules its own activation "At least two epochs beyond the epoch in which this proposal
reaches Accepted, per Article 47.3 and the epoch definition in REGISTRY.md", with no reference
to the 180-day constitutional floor. Art 2.1's own standard ("decidable rather than arguable")
is directly engaged because the Art 20.11 conformance test depends on this term. Two corrections
to the claim, neither fatal. First, Art 20.3 states its bound in seconds, so the 180-day
duration is not itself ambiguous; what is ambiguous is the TYPE of the value a VWIP states and
an implementation compares (Unix timestamp under 11.5 vs log-derived ordinal under
2.5/REGISTRY.md), compounded by the contradictory 60-day floor. Second, the PROOF-OF-WORK.md:106
leg is the weakest: "1-hour difficulty epochs" is qualified in-line and mirrored in
registry/src/pow.ts:53 as a local EPOCH_SECONDS constant, so it reads as a namespace collision
rather than a rival definition of the constitutional term. The finding stands on Art 2.5 vs Art
11.5 vs REGISTRY.md alone. Severity corrected to high rather than critical: nothing is deployed,
no user is affected now, and no registry epoch counter is implemented (grep for epoch in
registry/src, client, proxy, conformance returns only proof-of-work difficulty windows). But the
defect sits in entrenched constitutional text that a cut release would make expensive to amend,
and it is already propagating into VWIP-0002.
```

## constitution-vs-registry-renewal-grace-windows — HIGH

```text
Every quoted line is present and says what the claim says it says, and the conflict is real and
systemic. Verified in /workspace/vayuweb/constitution/CONSTITUTION.md: - 11.6 (line 888): tenure
= 126,230,400 s (1461 d, ~4 years) from the latest REGISTER/RENEW epoch; "A RENEW MAY be signed
at any moment while the name is held". - 11.8 (line 901): for 7,776,000 s (90 d) after tenure
ends, the only acceptable record is a RENEW by the incumbent; REGISTER from other keys MUST be
refused for that whole interval. - 11.10 (line 911) reinforces the same shape: clients must warn
from 90 d before lapse through the redemption interval. - 32.2/32.3 (lines 2008, 2013): term
SHALL be five years; renewal window opens twelve months before expiry and stays open through
expiry plus 180 days. Verified in /workspace/vayuweb/docs/spec/REGISTRY.md: - :154/:272 term is
exactly 31,536,000 s (1 year). - :175 and :297 renewal window is `notBefore >= prev.notAfter -
5184000` (60 d). - :287 `if rec.op == RENEW: if now >= prev.notAfter + 2592000: reject EXPIRED`
(30 d grace). - :148 a name is free again at `notAfter` + 30 d grace + 30 d quarantine. And
/workspace/vayuweb/docs/spec/NAMES.md:85 ("term is 1 year, 31,536,000 seconds") and :127-129
(REGISTERED state: "Renewal is refused" until 60 d before expiry). Both claimed consequences
check out mechanically. Day-45-after-expiry RENEW: `now >= prev.notAfter + 2592000` is true, so
REGISTRY.md rejects EXPIRED, while 11.8 reserves days 0-90 to that key. Worse than the claim
states: at day 61 (grace 30 + quarantine 30) REGISTRY.md:148 makes the name registrable by any
key, which 11.8 forbids outright until day 90. Renewal 100 days early: `notBefore` is pinned to
approximately `now` by the clock check at REGISTRY.md:270-271 and the "Term bounds and the
clock" section, so `notBefore >= prev.notAfter - 5184000` fails and the record is refused, which
11.6 expressly permits. Precedence makes this a defect rather than a variation: CONSTITUTION.md
3.7 ranks "this Constitution; Final VWIPs; published Annexes; the published conformance suite;
implementation documentation", and a lower instrument conflicting with a higher one "is void to
the extent of the conflict". No VWIP amends the tenure numbers (0001 CSP, 0002 licensing, 0003
versioning). Nothing in CHANGELOG.md fixes it; the 1-year/30-d/30-d model is also baked into the
code (registry/src/lifecycle.ts GRACE_SECONDS = 2_592_000, QUARANTINE_SECONDS, TERM) and
repeated in docs/FAQ.md:63, docs/GLOSSARY.md:131, docs/spec/PROOF-OF-WORK.md:240 and CRYPTO-
AGILITY.md:138, so it is not a stray line. The repo already treats exactly this class of finding
as a real defect — CHANGELOG.md:124-153 records "the duplicated .vayu originated in the charter,
and the first fix never reached it", where the charter and NAMES.md disagreed about the
namespace. Two corrections to the claim as stated. First, its Article 11.13 argument is wrong:
11.13's prongs are unauthorised key change, a lapse instant not computable offline, and tenure
extended past epoch + 126,230,400 s. The spec's 1-year lapse instant is fully offline-computable
and never exceeds that bound, so 11.13 is not violated and does not establish that "the two
grace regimes cannot coexist" — 3.7 precedence does that on its own. Likewise the entrenchment
appeal is weaker than presented: 9.7 entrenches the substance "no revocation save by neutral
mechanical Lapse", not the specific 1461-day and 90-day figures, so amending 11.6/11.8 is
arguably available under 9.19 rather than barred. Second, the charter is independently
inconsistent with itself: 11.14 names Article 32 as Article 11's own machinery, yet 32.2/32.3
state five years, a twelve-month window and 180 days against 11.6/11.8's four years, any-moment
renewal and 90 days. Any fix has to reconcile three regimes, not two. Severity high, not
critical: nothing is deployed (the Constitution header and NAMES.md both state no name has ever
been registered, ROADMAP.md Phase 0 is the current phase), so no holder can lose a name today.
It is high rather than medium because it is the exact failure Article 44.6 forbids — two
independent implementers, one reading the charter and one reading REGISTRY.md, produce non-
interoperating lapse rules on a wire-visible, name-loss-bearing rule — and settling these
numbers is Phase 0's stated job.
```

## art-33-4-settlement-delay-absent-from-specs — HIGH

```text
Verified all three citations verbatim. CONSTITUTION.md:2059 (33.4) mandates a fourteen-day
settlement delay before a TRANSFER takes effect, revocable in that window by an Article 34
recovery path; 33.5 requires the trade-off be stated wherever the delay is documented.
REGISTRY.md §TRANSFER (185-192) lists preconditions (live prev, differing ownerKey, coSig,
notAfter equality, null powProof) and states "Effect: ownership moves and the term is unchanged"
— no delay, no pending state, no reversal. NAMES.md §Transfer (152-172) confirms the 14 days is
the OFFER's expiry before acceptance, and that "On acceptance, ownerKey becomes the recipient's
key" immediately; the only revoke is the owner voiding an unaccepted offer. Grepped
settlement|delay|revers|recover|pending across both specs: no settlement mechanism exists. It is
stronger than omission — REGISTRY.md:215 states "There is no recovery key and no appeal", and
the spec record set (REGISTER/UPDATE/RENEW/TRANSFER/RELEASE/REVOKE) drops the DELEGATE and KEY-
ROTATE types Art 29.4 names, so the Article 34 recovery path 33.4 depends on has no wire form
either. Refutation attempts failed: not fixed (no settlement/Article 33 hit in CHANGELOG.md,
nothing under [Unreleased]); not unbuilt-future-work (ROADMAP Phase 0 marks both specs "Complete
(draft)" and names independent adversarial spec review as the current open item, and the same
class of defect — Art 35.1's duplicate .vayu inherited by RESOLUTION.md — is already logged as
real at CHANGELOG:125); not resolved by precedence (Art 3.7 ranks the Constitution highest and
makes a conflicting lower instrument void to the extent of the conflict, so the specs are the
defective party); not editorial, because THREAT-MODEL.md:54-55 relies on the delay as the T1
key-compromise mitigation and GLOSSARY.md:191, FAQ.md:106 and NAMESPACE.md:62 present it to
readers as an existing protection. Severity high rather than critical: nothing is deployed and
no live user is exposed, but it is a consensus-visible normative contradiction (two
implementations built from charter vs spec disagree on when ownership moves) and a user-facing
security claim no conformant client can honour. Fix note: REGISTRY.md and NAMES.md also disagree
with each other on transfer's shape (single TRANSFER record with coSig vs two-operation
offer/accept), which must be settled before 33.4 can be encoded.
```

## names-registry-transfer-op-mismatch — HIGH

```text
Tried to refute it and could not. What I verified in /workspace/vayuweb: 1. Both documents are
self-declared normative. NAMES.md:3 "This document is the normative specification for VayuWeb
names: ... how ownership is handed between keys". REGISTRY.md:3 specifies "the record format,
the signed bytes, the six operations". So this is not a normative-vs-explanatory mismatch. 2.
The quoted evidence is accurate. NAMES.md:156-188 (§Transfer) says verbatim "Transfer is a two-
signature handover. It is never a single operation.", then "1. The current owner appends an
`offer` operation naming the recipient's Ed25519 public key. The offer carries its own expiry:
exactly 14 days from the offer's `notBefore`.", "2. The recipient appends an `accept` operation,
signed by the offered key, referencing the offer by its hash. On acceptance, `ownerKey` becomes
the recipient's key, `seq` increments", and NAMES.md:179 "The owner MAY append a `revoke`
operation at any time before acceptance." REGISTRY.md:47 closes the op set to
REGISTER/UPDATE/RENEW/TRANSFER/RELEASE/REVOKE, and REGISTRY.md:185-193 defines TRANSFER as one
record: incoming ownerKey, `coSig` verifying under it, notAfter == prev.notAfter, powProof null.
REGISTRY.md:254 rejects anything else with UNKNOWN_OP, and registry/src/record.ts:27 + :286
implement exactly that closed set, so lowercase `offer`/`accept`/`revoke` would be rejected as
UNKNOWN_OP — the claimed consequence is literally what the reference code does
(record.test.ts:87 already pins that even a case variant, `register`, is UNKNOWN_OP). 3. The
deferral clause does not rescue it. NAMES.md:10-13 says record format and log semantics live in
REGISTRY.md and "This document does not restate them" — but §Transfer does restate them, and
restates them differently: it assigns the seq increment to `accept`, adds a 14-day offer expiry
and an offer-hash back-reference, and requires a record that names a recipient key while
REGISTRY.md's chain rules (REGISTRY.md:141) force `ownerKey == prev.ownerKey` for every op
except TRANSFER. REGISTRY.md's schema has no field for an offer hash or an offer expiry, so the
two flows cannot be reconciled by encoding — they are different state machines. 4. The `revoke`
collision is real and the hazard is not hypothetical. NAMES.md already uses lowercase names for
REGISTRY log ops elsewhere — NAMES.md:146 "appending a signed release" and the lifecycle
diagram's "release (signed by owner)" both mean REGISTRY.md's RELEASE — so a reader has direct
precedent for mapping NAMES.md `revoke` onto REGISTRY.md REVOKE, which per REGISTRY.md:204-213
freezes the name for the rest of its term plus 30 days quarantine with no recovery key and no
appeal. 5. Not already fixed and not out of scope. `offer`/`accept` appear nowhere else in the
repo (grep over docs/, registry/src, conformance/vectors.json); CHANGELOG.md [Unreleased] does
not mention it; git log on the two spec files shows no transfer reconciliation. Nothing in
constitution/ or the VWIPs establishes a precedence rule that would let REGISTRY.md silently
override NAMES.md — VWIP-0003:115 says the specifications, not the code, are authoritative,
which makes an unresolved contradiction between two specs worse rather than better. And it is
squarely inside the current phase: ROADMAP Phase 0's open items are the adversarial spec review
and test vectors for every wire-visible rule, expressly before code. One correction of the
claim's wording, which does not affect the substance: "a countersignature field that NAMES.md
never mentions" is slightly off — NAMES.md:169 does say "If the recipient never countersigns",
so the concept appears; what is absent is any mapping of it onto a single-record `coSig` rather
than a separate `accept` record. Severity: high, not critical. Nothing is deployed and no name
has ever been registered (both documents say so explicitly), and the reference implementation
plus conformance/vectors.json consistently follow REGISTRY.md, so there is no divergent code
today. It is a normative contradiction on a core operation that a second implementer building
from NAMES.md would get wrong, with a name collision whose worst case is an unrecoverable frozen
name — exactly the class of defect Phase 0 exists to remove before code is written. Files:
/workspace/vayuweb/docs/spec/NAMES.md lines 156-188; /workspace/vayuweb/docs/spec/REGISTRY.md
lines 47, 58, 141, 185-193, 204-213, 254; /workspace/vayuweb/registry/src/record.ts lines 27 and
286.
```

## names-namespace-tld-ratification-vote-vs-constitution — HIGH

```text
Could not refute; every quoted line checks out in context. VERIFIED: (1) NAMES.md:236-244 and
NAMESPACE.md:95-97 are quoted accurately. (2) grep -niE 'two-thirds|supermajority|ballot' over
constitution/CONSTITUTION.md returns ZERO hits; 'quorum' appears only in unrelated senses (9.21,
20.6, 56.1 "No quorum is required for the network to keep working"). So NAMES.md:240-242's
"These figures are restated here for readability only: [CONSTITUTION.md] is the normative source
for eligibility, ballot format, quorum and threshold" is a false citation - the Constitution
contains none of those four things for a Naming VWIP, and applying "governs where the two
differ" literally deletes the spec's own rule and leaves no procedure for creating a TLD at all.
(3) The Constitution's actual mechanism is Art. 42.1/42.5 lifecycle durations plus rough
consensus called by an editor (GOVERNANCE.md:38-65), with 39.3, 40.10 ("Any tally is advisory
only") and 43.1 ("does not mean ... a headcount, a majority") - a binding two-thirds-of-ballots-
cast requirement is the opposite of that, not a restatement. (4) Art. 40.1-40.4 defines standing
as four constituencies with demonstrated-participation criteria and 40.2 requires concurrent
support across all four; "eligible signing keys ... active in the log during the trailing 90
days" is a key count matching none of them, and 40.7 excludes weight from "account count ... or
any quantity a single party can inflate at will". (5) Aggravating and not in the original claim:
Art. 9.14 ENTRENCHES Article 39 by substance and 39.6 forbids "the informal recreation of a
governing body under another name" - constituting an electorate with a quorum and a binding
threshold sits squarely there. (6) Also not in the claim: the two specs disagree with each other
- NAMES.md has the 25% quorum but no dormancy period, NAMESPACE.md has the 180-day dormancy but
no quorum. (7) Art. 35.6's ninety-day public objection window appears in neither spec (grep
confirmed). NOT REFUTABLE BY THE USUAL ROUTES: no CHANGELOG entry addresses ratification
thresholds and recent commits are RESOLUTION/REGISTRY/merkle work, so it is not already fixed;
ROADMAP.md:28 lists "Independent adversarial review of the above - Open - this is the current
work" and Phase 0's exit test is that an implementer can build from the specs alone, so this is
in scope rather than an unbuilt feature; it is a normative contradiction with a ratified, partly
entrenched charter, not a wording preference. ONE OVERSTATEMENT IN THE CLAIM, CORRECTED: the
Constitution is not threshold-free in general - Art. 45.2 sets 60%/60%/20-party/180-day
deployment thresholds and Art. 58.1.d sets 75% concurrent per-constituency support for
amendments. Neither is a per-ballot tally weighted by signing key, so the substance stands, but
"the Constitution defines no threshold" is too flat. SEVERITY CORRECTED TO HIGH (not critical):
registry/src/names.ts freezes RATIFIED_TLDS at the eleven founding extensions with a test
pinning the set, and no ballot logic exists anywhere in registry/src or conformance/, so there
is no exploitable runtime path today. The defect is normative: an entrenched-Article conflict, a
false cross-reference, and an unimplementable rule on the surface GOVERNANCE.md itself calls the
most capturable in the system.
```

## vwip-0000-missing-naming-and-constitutional-amendment-categories — HIGH

```text
Verified, and I could not refute it. What I checked: 1.
`/workspace/vayuweb/docs/spec/VWIP-0000.md` lines 63-64 (header block) and line 92 (§2.4)
enumerate exactly `Type: Standards Track | Process | Informational` and `Category: Core |
Registry | Resolution | Hosting | Client | Interoperability | Security`. Neither `Naming` nor
`Constitutional Amendment` appears anywhere in the header format or §2. A full grep of VWIP-0000
for "Naming" returns only line 329 (a See-also link to NAMES.md), and for "Amendment" only line
159. 2. Line 159 of the same file prices `Review — Core, Registry, Security, Constitutional
Amendment | 180 days`. So VWIP-0000 is internally inconsistent on its own terms: its lifecycle
table sets a duration for a category its own header block and §2.4 cannot express. That kills
the "the omission is deliberate" defence. 3. `/workspace/vayuweb/constitution/CONSTITUTION.md`
confirms the quotes verbatim: 41.3 at line 2439-2440, 35.6 at line 2146 ("A new TLD comes into
being only by a ratified Naming-category VWIP"), 42.5 at line 2526 (180 days for "Core,
Registry, Security and Constitutional Amendment categories"), 58.1 at line 3280 ("Amendment
proceeds only by a Constitutional Amendment VWIP") with 58.1.b 12-month deliberation / two
readings 6 months apart, 58.1.d 75 percent concurrent supermajority in each of four
constituencies, 58.1.e double ratification. `docs/spec/NAMESPACE.md:94` independently relies on
the missing category: "A new extension requires a ratified Naming-category VWIP, per
Constitution Article 35.6". 4. `/workspace/vayuweb/docs/spec/VWIP-0002.md` lines 8-9 are `Type:
Process` / `Category: --`, and line 18 says the proposal "would amend that clause" of Article
16.2. Article 16 sits at CONSTITUTION.md:1107, inside Title II (line 765) — so this is an
amendment to a Title II Article. I read VWIP-0002 end to end (233 lines): it cites "Articles 9,
16, 17, 44, 47" and never mentions Article 58, 58.1, readings, deliberation period,
supermajority or double ratification. Its "Activation epoch" section reasons only from Article
47.3. So the consequence the claim states — the 58.1 machinery is not engaged by its declared
type — is borne out by the document itself, not inferred. 5. Not already fixed: CHANGELOG.md
`[Unreleased]` has no entry touching VWIP categories (the only VWIP-0000 mention is line 243,
its original publication). Not a roadmap "not yet built" item either — Phase 0's open work is
precisely the adversarial spec review, so a spec-internal contradiction is in scope rather than
premature. Severity corrected down from the implied critical to **high**. Two things temper it,
neither of which refutes it: VWIP-0000's own abstract states "where this document and the
Constitution diverge, the Constitution governs and this document is defective", so 41.3/58.1
still bind by operation of the charter and no amendment could lawfully pass on a 90-day track;
and VWIP-0002 is `Status: Draft`, so nothing has been wrongly ratified. What remains is real —
the process document that Article 41.1 makes the exclusive route for normative change cannot
express the two instruments the charter most depends on, and a live in-repo proposal is mis-
typed in exactly the way that gap invites. One correction to the claim's framing, which
strengthens rather than weakens it: 41.3's list is not a pure category axis — it includes
`Process` and `Informational`, which VWIP-0000 models as Types with `Category: --`. So
VWIP-0000's two-axis split is a reasonable refinement of 41.3, and the defect is specifically
the two dropped values, not the restructuring. I also found adjacent drift worth fixing in the
same pass: 41.3 says `Interop` where VWIP-0000 §2.4 says `Interoperability`, and VWIP-0000 adds
`Resolution`, `Hosting` and `Client`, which 41.3 does not list at all.
```

## names-reserved-labels-unimplemented — HIGH

```text
Could not refute; every cited element verified. NAMES.md:57 makes "MUST NOT be a reserved label"
a normative label constraint alongside the NFC and xx-- rules (both of which ARE implemented in
labelRejection), and NAMES.md:65-67 requires every peer to reject such a registration. The table
at NAMES.md:71-77 withholds the 1-char class, the 2-char class, www, localhost, example,
invalid, test, vayu, control, api, resolver, proxy, pac, wpad, _vayu.
registry/src/names.ts:82-108 implements only EMPTY, TOO_LONG, BAD_CHARACTER, LEADING_HYPHEN,
TRAILING_HYPHEN, RESERVED_IDN_SHAPE, then `if (label.length <= 2) return 'RESERVED_LABEL'` and
`return null`. Executed the built module: all twelve alphanumeric reserved labels return
labelRejection === null and nameRejection(l,'vayu') === null; only _vayu is refused,
incidentally as BAD_CHARACTER because underscore fails the grammar. Refutation attempts, all
failed: (1) Not enforced elsewhere — labelRejection is the sole validation used by the record
parser (record.ts:289, fail('BAD_LABEL')) and the resolver (resolve.ts:218, step 4); grep -rn
RESERVED_LABEL over registry/src hits only names.ts:59/105 and the test; grep -i reserved over
REGISTRY.md and RESOLUTION.md returns nothing, so no other spec relocates the check. (2) Not
deliberately deferred — names.ts:1-7 states the module covers "Label grammar, reserved labels
and the ratified TLD set" and that "Nothing here relaxes it… a peer that accepts a name others
reject has forked the namespace"; its header lists two NAMES.md defects found while writing it
and this is not among them. (3) Not already fixed — no mention of reserved labels anywhere in
CHANGELOG.md; [Unreleased] covers CI, fuzz, merkle/checkpoint, resolution. (4) Not an unbuilt
roadmap feature — Phase 1 registry core including validation ordering is implemented and already
emits BAD_LABEL; names.test.ts:88-102 exhaustively proves the two-character class is
unregistrable while never testing a single named label, so the omission is inside built, tested
code. (5) conformance/vectors.json contains no reserved-label vector, so a second implementation
is not measured on this either. Consequence confirmed as stated: wpad.vayu, pac.vayu,
proxy.vayu, api.vayu, control.vayu and vayu.vayu are registrable here and BAD_LABEL on an
implementation written from NAMES.md — two peers holding different ownership facts for the same
name, which is the namespace fork Constitution Article 44.6 and the Phase 0 acceptance test
exist to prevent, on the exact label set NAMES.md:77 withholds as a proxy-hijack vector.
Severity high rather than critical: no VayuWeb name has ever been registered (NAMES.md:8), there
is no live network, and the fix is a frozen reserved set plus a conformance vector per label.
But it is a divergence in a wire-visible rule inside code that documents itself as implementing
that rule.
```

## registry-eleven-tlds-vs-1267-catalogue — MEDIUM

```text
Every quoted line checks out verbatim. REGISTRY.md:49 and :256 do restrict `tld` to the eleven;
NAMES.md:192 does describe a 1,267-extension "launch catalogue" inside the section headed `##
Launch TLDs`; NAMESPACE-CATALOGUE.md has exactly 1267 `| `.x`` rows and a `## Founding
extensions` section labelled `*7 extensions*`; `grep` for `.p2p`, `.news`, `.blog` in the
catalogue returns nothing (`.libre` is present at line 394 but under a different category, so
the founding section omits four of eleven); registry/src/names.ts:33-45 freezes the eleven. I
ran `python3 scripts/check-counts.py` — it passes, and its `check_tld_enumerations` only matches
runs bounded by `.vayu`…`.blog`, which the catalogue never contains, so the claim that the check
cannot see this is correct. I found the mechanism the claim did not name, and it makes the
finding sharper rather than weaker. scripts/build-catalogue.py generates the catalogue and its
FOUNDING list holds only 8 entries, with the comment "Two of the original twelve are absent on
purpose: .news and .blog are live ICANN generic domains". `.p2p` is in FOUNDING but is then
silently discarded by `ok = re.compile(r"^[a-z]{2,12}$")` — letters only. That regex is a
residual of the already-shipped fix recorded in CHANGELOG ("`.p2p` violated the letters-only
label ABNF, which now admits digits after the first character"): NAMES.md's ABNF at line 44 was
widened, the generator was not. So two of the eleven ratified TLDs are excluded deliberately
because they violate NAMESPACE.md 5.2 ("An extension MUST NOT duplicate a well-known ICANN
generic top-level domain"), and a third is excluded by a stale grammar. Nothing in the repo
grandfathers the founding set out of 5.2, and the same two TLDs sit in Constitution Article 35.1
as "the initial top-level domains". That is an unresolved normative conflict, not a wording
preference, and it is squarely Phase 0 work — the roadmap's done-condition is that an
implementer reading the specs alone can interoperate. I could NOT confirm the claimed
consequence, and I am correcting the severity for it. The disjoint-namespace/log-replay fork
requires an implementer to build RATIFIED_TLDS from the catalogue, but NAMESPACE-CATALOGUE.md:26
states "Status: Draft — not yet implemented. No extension is registrable until the protocol
exists and each has completed the 180-day dormancy period required by Article 35." Every
normative source agrees on the eleven: Constitution 35.1, NAMES.md's own bullet list in the same
section, ARCHITECTURE.md:116, GLOSSARY, FAQ, WHITEPAPER, and conformance/vectors.json's
`schema/unratified-tld` vector. REGISTRY.md:49 also does not defer to NAMES.md on the `tld` row
(only the `name` row cites it), so the claim's framing of REGISTRY.md "deferring to the
catalogue" is not supported. Nobody derives a registrable set from a document that says nothing
in it is registrable — so no wire-level fork. What survives: (1) two ratified TLDs violate the
project's own stated collision policy and the generator refuses to emit them, with no document
resolving which side is right; (2) `.p2p` is missing from the catalogue through a stale regex
the prior ABNF fix never reached; (3) "1,267 extensions at launch" in README.md:104 and
NAMES.md:192 contradicts both the verifier and the catalogue's own status line; (4) check-
counts.py, written precisely to stop this class of drift, does not read the catalogue. Medium,
not high/critical.
```

## registry-fully-released-undefined — MEDIUM

```text
I tried to refute this and could not. Every quoted line is verbatim and in context. VERIFIED AS
QUOTED: - /workspace/vayuweb/docs/spec/REGISTRY.md:147-148 — the REGISTER precondition is the
ONLY place the document defines "free", and it states a literal sum: "past its `notAfter` plus
30 days of grace plus 30 days of quarantine." - REGISTRY.md:200-202 (RELEASE) — "expires at
once, enters the 30-day quarantine, then returns to the open pool. Grace is skipped". A RELEASE
record sets `notAfter == notBefore` (line 197), so its `notAfter` IS the release instant;
applying the line-148 formula to it yields release+60d, the paragraph yields release+30d. -
REGISTRY.md:209-211 (REVOKE) — `notAfter == prev.notAfter` (line 206) and the name is free at
`notAfter`+30d, not +60d. Same 30-day gap. - REGISTRY.md:271 — `fully_released(prev)` is the
sole normative arbiter in the pseudocode, and `grep -n "fully_released" docs/spec/REGISTRY.md`
returns exactly one hit. It is defined nowhere in the document, so an implementer sent to the
prose lands back on line 148. - NAMES.md:141-148 and the state diagram at :90-121 confirm
release goes straight to QUARANTINE (30 days), i.e. they agree with the RELEASE paragraph and
disagree with line 148. - registry/src/lifecycle.ts:60-68 (RELEASE → `at + QUARANTINE_SECONDS`),
:74-81 (REVOKE → `notAfter + QUARANTINE_SECONDS`), :84-89 (everything else → `graceUntil +
QUARANTINE_SECONDS`) — the implementation picks the 30-day reading for both special ops, pinned
by lifecycle.test.ts:107-109 and :148-150. REFUTATION ATTEMPTS THAT FAILED: - No reconciling
clause exists elsewhere. REGISTRY.md carries dedicated "Expiry is a precondition, not a
consequence" (:311-330) and "Term bounds and the clock" (:332-357) sections that fix two
neighbouring ambiguities of exactly this kind — and neither touches the free-instant. Nothing in
the doc says NAMES.md is normative for it (NAMES.md:150-154 points the other way). - Not already
fixed: no CHANGELOG entry addresses it. The `[Unreleased]` and 0.1.0 sections record eight other
spec defects, several structurally identical ("REGISTRY.md named `treeRoot` … uncomputable from
these specifications alone"; "one that let an expired holder reclaim a name during quarantine").
- Not out of scope. docs/ROADMAP.md:28-33 makes Phase 0 the current phase, with "Independent
adversarial review of the above — **Open — this is the current work**" and "Done when: a
competent implementer can read the specifications alone … and produce a client that would
interoperate … it is not satisfied today." This finding is that deliverable, not a future
feature. - Not style. Two normative statements give different instants for the same wire-visible
decision (accept vs `reject NAME_TAKEN`), and the pseudocode delegates to an undefined
predicate. ONE THING THAT MAKES IT WORSE THAN CLAIMED: the conformance suite cannot catch it.
conformance/vectors.json supplies `fullyReleased` as an INPUT boolean to the verifier
(registry/src/vectors.test.ts:27 `fullyReleased: () => vector.state.fullyReleased`;
conformance/README.md:33 glosses it as "finished grace and quarantine", repeating the 60-day
framing). The vector named `register/after-quarantine-the-name-is-free-again`
(vectors.json:284-285) restates the line-148 formula as its rule but only exercises the
ordinary-expiry path. So the artifact a second implementation is measured against parameterises
the disputed instant away — the disagreement would surface only against a live peer. CONSEQUENCE
CHECKS OUT, WITH A NUANCE: the two readings differ on any REGISTER landing in a 30-day band
(release+30d…+60d, or revoke `notAfter`+30d…+60d). The strict peer rejects NAME_TAKEN, the
lenient peer accepts; the conflicting pair is two REGISTERs at seq 0, and Convergence rule 1
(:236, "if exactly one is valid, that one wins") is evaluated per-peer, so it returns different
winners rather than repairing the split. It does not self-heal at day 60 either, since re-
evaluating the record then trips `notBefore < now - 86400` → BACKDATED (:267). SEVERITY —
medium, not higher. It is a real normative contradiction on a consensus-critical rule, but: only
one implementation exists (VWIP-0003/0.1.0 states the specs win where they disagree), nothing is
broken in the field today; the whole rest of the corpus (RELEASE/REVOKE rationale paragraphs,
NAMES.md state machine, docs/GLOSSARY.md:157, docs/FAQ.md:64-65, and the code) points at the
30-day reading, so a careful implementer probably lands right; and the fix is small — define
`fully_released()` normatively in REGISTRY.md and reword line 148 to "past the end of its
quarantine, computed per operation" rather than a fixed 60-day sum. Worth a vector for the
released and revoked cases so the conformance set stops handing the answer to the harness.
```

## conformance-vector-coverage-claim — MEDIUM

```text
CONFIRMED — I could not refute it, and the mutation test proves the enforcement claim is false.
What I verified (all paths absolute): 1. The claim's quote is accurate.
/workspace/vayuweb/conformance/README.md:76-78 reads "The set covers … including at least one
vector for every rejection code the verifier can return — a test fails if a code is added
without one." Reading the whole README (88 lines) gives no qualifier that narrows "every
rejection code": the only stated exclusions (lines 80-82) are replication, convergence,
equivocation and resolution — areas, not codes. 2. The gap is exactly the six codes named. I
extracted the union members programmatically from `RecordRejection`
(/workspace/vayuweb/registry/src/record.ts:55-74) plus `VerifyRejection`
(/workspace/vayuweb/registry/src/verify.ts:44-54) = 28 codes, and diffed against both the hand-
written `mustCover` list and the committed artifact: union − mustCover = union − vectors.json =
['BAD_FIELD_TYPE','MISSING_FIELD','MISSING_POW','NOT_A_MAP','TOO_LARGE','TOO_MANY_RECORDS'].
vectors.json holds 40 vectors covering 22 reject codes + accept + defer; mustCover − vectors =
empty, so the test passes precisely because it only asks about the 22 codes someone remembered
to type. 3. All six are genuinely returnable by `verify()`, so "the verifier can return" is not
being read too broadly: verify.ts:144 returns TOO_LARGE directly, :150 NOT_A_MAP, :249
MISSING_POW (the RENEW branch), and :159 (`if (error instanceof RecordError) return
reject(error.code, …)`) propagates MISSING_FIELD (record.ts:131,139,146,309,340), BAD_FIELD_TYPE
(:132-149,310) and TOO_MANY_RECORDS (:313). 4. Not already fixed, and no compensating mechanism
exists. I grepped registry/src and the workflows for any type-level or generated exhaustiveness
link (`satisfies`, `assertNever`, an exported code array, a CI grep) — there is none;
`mustCover` at vectors.test.ts:95-118 is an untyped string literal array. CHANGELOG.md
`[Unreleased]` does not mention the gap; it repeats the same overstatement ("A test fails if a
rejection code is added without a vector", ~line 318), and docs/ROADMAP.md:29 repeats it a third
time ("including a vector for every rejection code"). 5. Mutation test (the decisive step). I
added `| 'BRAND_NEW_CODE'` to `VerifyRejection`, ran `node --experimental-strip-types --test
src/vectors.test.ts` and `npx tsc --noEmit`: 5/5 tests pass, typecheck clean. So the
README/CHANGELOG/ROADMAP sentence "a test fails if a code is added without one" is demonstrably
false. I then restored verify.ts from a backup; `git status --porcelain` is empty. 6. The
consequence is as stated. TOO_LARGE and TOO_MANY_RECORDS are in REGISTRY.md's normative verify()
pseudocode (confirmed at docs/spec/REGISTRY.md — `if len(bytes) > 4096: reject TOO_LARGE` and
`if len(rec.records) > 32: reject TOO_MANY_RECORDS`), and the artifact is explicitly the thing a
second implementation is measured against ("another implementation is tested against the
committed file, not against this code", vectors.test.ts:65-67). A second implementation can
return any code it likes for a 4097-byte record or a 33-entry record and still pass the suite —
the exact drift the README's own "the rejection code is part of the contract" section (lines
38-41) says the vectors exist to prevent. VWIP-0003 also forbids claiming conformance for areas
with no test vectors, which is the rule this sentence quietly steps over. Severity correction:
medium, not high. Two mitigations bound the damage — this implementation's own behaviour is
correct and unit-tested for all six codes (record.test.ts:77,106-108,120,143,204 and
verify.test.ts:498), so nothing is broken at runtime; and the defect is confined to the interop
artifact plus a doc claim. But it is not editorial: the sentence is precisely what an
independent implementer would rely on to conclude the set is complete, the test carries a name
asserting a property it does not check, and the same false claim appears in three committed
documents. Minimal fix: derive `mustCover` from an exported const tuple of the union (e.g.
`export const VERIFY_REJECTIONS = [...] as const` with `type VerifyRejection = typeof
VERIFY_REJECTIONS[number]`) so a new code cannot compile without appearing in the list, then add
the six missing vectors — or, failing that, weaken the three prose claims to name the excluded
codes explicitly.
```

## registry-verify-check-order-too-large-vs-non-canonical — MEDIUM

```text
I tried to refute this and could not. Every quoted line is accurate and nothing elsewhere
reverses it. VERIFIED VERBATIM - docs/spec/REGISTRY.md:251-252 are exactly as quoted: `if bytes
!= det_cbor(rec): reject NON_CANONICAL` then `if len(bytes) > 4096: reject TOO_LARGE`. -
registry/src/verify.ts:142-144 does the size check first (`if (bytes.length > MAX_RECORD_BYTES)
return reject('TOO_LARGE', …)`), with the decode + `bytesEqual(encode(decoded), bytes)`
canonical re-check at 148-161. - registry/src/verify.ts:4-6 does claim the opposite: "That
section's pseudocode is normative down to the order of its checks, and this module follows it in
order deliberately: a record with two defects must produce the same rejection code on every
implementation". REFUTATION ATTEMPTS THAT FAILED - Other spec sections do not reorder it.
REGISTRY.md:134-136 ("Common preconditions, checked before any operation-specific rule:
deterministic CBOR encoding; at most 4096 bytes; …") lists the two in the same order as the
pseudocode. The "Size Limits" section (REGISTRY.md:498-503) says a verifier MUST reject rather
than truncate, but says nothing about ordering. No errata, no divergence note anywhere in docs/
or the module. - Not already fixed. `CHANGELOG.md` `[Unreleased]` is large and detailed but
contains no entry for this; `grep TOO_LARGE CHANGELOG.md` is empty. - Not a style preference.
This project treats check order as a normative wire-visible contract in at least four places:
conformance/README.md:39-43; verify.ts:4-6; REGISTRY.md:320-322 ("an implementation that relies
on it returns the wrong rejection code, which is itself wire-visible"); and the CHANGELOG's
resolve.ts entry ("The check *order* is the load-bearing part and is tested directly"). - Not an
unbuilt feature. Roadmap Phase 0 is explicitly about the spec being implementable from prose
alone (Article 44.6) and already logs eight spec defects found by implementing — this is the
same class. CONFIRMED BY EXECUTION Ran an indefinite-length CBOR map padded to 5,007 bytes
through `verify()` with a stub `RegistryView`: result
`{"outcome":"reject","code":"TOO_LARGE","detail":"5007 bytes exceeds 4096"}`. A verifier written
from REGISTRY.md alone returns NON_CANONICAL for the same bytes. THE INVISIBILITY CLAIM ALSO
HOLDS, AND IS WORSE THAN STATED registry/src/vectors.test.ts:88-121 `mustCover` omits TOO_LARGE.
It also omits NOT_A_MAP, MISSING_FIELD, BAD_FIELD_TYPE, TOO_MANY_RECORDS and MISSING_POW, all of
which are reachable members of `RecordRejection` (registry/src/record.ts:55-73). So
conformance/README.md's claim of "at least one vector for every rejection code the verifier can
return — a test fails if a code is added without one" is false as written, and no vector can
catch this pair. ONE THING THE FINDING GETS SLIGHTLY WRONG, WHICH CHANGES THE FIX NOT THE
VERDICT The implementation's order is very likely the correct one and the spec is the side that
is wrong. The pseudocode's signature is `verify(rec, bytes, state)` — `rec` is already decoded
on entry, so its ordering presupposes a decode that happens outside the pseudocode.
verify.ts:130-136 deliberately takes bytes only (a parsed record handed in may not correspond to
the bytes its hash was taken over), which forces the decode inside `verify`, and decoding an
unbounded attacker-supplied buffer before any size check is a denial-of-service surface.
registry/src/verify.test.ts:496-499 pins this intent by name: "a record above the size cap is
refused before it is decoded". `parseRecordBytes` (record.ts:388-392) uses the same size-then-
canonical order. So the remedy is almost certainly to swap REGISTRY.md:251-252 and add a
sentence saying why, plus correct the verify.ts:4-6 claim and add a TOO_LARGE vector — not to
reorder the code. SEVERITY The claim implies something higher; medium is right. It is a genuine
normative divergence in a value the project has made part of its interop contract, it is
accompanied by a module-header comment asserting the opposite of what the module does, and it is
uncatchable by the suite built to catch it. But both paths reject, no invalid record is
accepted, there is no security consequence, and it only fires for records that are both
oversized and non-canonical.
```

## pow-registry-signed-checkpoint — MEDIUM

```text
Could not refute; verified in the clean working tree at commit 99dfe25. VERIFIED QUOTES: PROOF-
OF-WORK.md:187-189 says a peer "MAY trust its own signed local checkpoint ... as described in
[REGISTRY.md](REGISTRY.md)". REGISTRY.md:401-404 defines the checkpoint as {logLength, treeRoot,
indexRoot, liveNames} and states it "carries no signature that would make it one". Both quotes
are exact and current. NOT FIXED: registry/src/checkpoint.ts defines `interface Checkpoint` with
exactly those four fields — no signature, no key — and its header comment restates REGISTRY's
no-signature rule. CHANGELOG.md:59 states the position deliberately ("Checkpoints carry no
signature, deliberately: a signed checkpoint would be an attestation peers could be asked to
trust rather than recompute, which is the privileged authority the charter forbids"). No
CHANGELOG entry fixes the PROOF-OF-WORK.md line; grep shows line 188 is the only place in that
file where "signed" attaches to a checkpoint, and nothing anywhere in the repo defines signing
of a local checkpoint. WIDER THAN CLAIMED: docs/spec/CRYPTO-AGILITY.md:160-161 is normative and
contradicts REGISTRY directly — "6.1 The registry SHALL publish periodic checkpoints: a hash of
the log state at a given length, signed under the then-current suite." So two SHALL-level
statements disagree on whether a checkpoint is signed, and PROOF-OF-WORK.md sits on the CRYPTO-
AGILITY side while citing REGISTRY as its source. That rules out reading "signed" as loose
prose. IN SCOPE: docs/ROADMAP.md marks Phase 0 as the current work with "Independent adversarial
review — Open" and a done-condition of Constitution Article 44.6 (implementer reads the specs
alone, asks nothing, interoperates). A normative contradiction across two specs is exactly that
gate failing, not an unbuilt feature. SEVERITY CORRECTED DOWN to medium — the claim's stated
failure mechanism is wrong. compareCheckpoints() in registry/src/checkpoint.ts compares field-
wise (logLength, then treeRoot, then indexRoot), not byte-for-byte over a serialised struct, so
an added signature field would NOT break the 32-byte treeRoot divergence check the claim calls
the checkpoint's "only stated purpose". The genuine harm is the one the CHANGELOG names — an
implementer following PROOF-OF-WORK.md (backed by CRYPTO-AGILITY 6.1) ships a checkpoint peers
can be asked to trust rather than recompute, the privileged attestation the charter forbids —
plus Article 44.6 undecidability. Documentation-level defect in draft specs; no code is wrong
and no running system is affected. FIX SPANS THREE FILES: drop "signed" at PROOF-OF-WORK.md:188
(a peer trusting its own already-verified prefix needs no signature), and reconcile CRYPTO-
AGILITY.md 6.1 with REGISTRY.md, most likely by naming the externally-anchored artifact as an
object distinct from the unsigned comparison checkpoint.
```

## resolution-passthrough-vs-local-surface — MEDIUM

```text
Verified all citations verbatim. RESOLUTION.md:61-65 defines passthrough mode ("MAY forward the
request to the operating system's networking stack"), :134-135 permits CONNECT in passthrough
only, and :192-203 says a resolver SHOULD support browser-integration option 2, which requires
passthrough for all HTTP traffic. RESOLUTION.md:46-47 declares LOCAL-SURFACE.md normative
precisely for "the hardening rules for the proxy that must remain on TCP" — i.e. the sections in
conflict. LOCAL-SURFACE.md:61-69 requires every non-VayuWeb Host (explicitly including "a
clearnet name") to be rejected before routing, :73-76 requires CONNECT to refuse every non-
VayuWeb destination, and conformance item 3 at :164 makes it a test. The string "passthrough"
does not appear anywhere in LOCAL-SURFACE.md, so there is no mode carve-out. Attempted
refutation via other documents and it went the other way: PRIVACY.md §3.2 (:82-90) states the
same destination rule but WITH the exception ("In Private Mode this is absolute. In Standard
Mode a resolver MAY be configured to pass clearnet navigation through"), and VWIP-0001.md:198
lists "Standard Mode clearnet passthrough (PRIVACY.md 3.2)" as a permanent, disclosed, non-
default option. So the exception is intended policy present in two other normative docs and
simply absent from LOCAL-SURFACE — confirming the contradiction and identifying the out-of-sync
text. Not already fixed: CHANGELOG [Unreleased] covers CI gates, fuzz suite, merkle/checkpoints
only; recent spec commits (047d969, 99d6355) address unrelated issues. Not excusable as unbuilt:
proxy/ is README-only, but ROADMAP Phase 0 is the current phase, its open item is the
adversarial spec review, and its exit bar is an implementer working from the specs alone — which
this defeats. One correction to the claim's framing: RESOLUTION.md:140-142 already forbids
localhost, 127.0.0.0/8, ::1, link-local and the resolver's own listeners in ANY mode, and
forbids proxy credentials and X-Forwarded-For, so the "SSRF pivot into loopback / open relay"
consequence is mostly already closed; the genuine residue is RFC 1918 (LAN) destinations and
clearnet CONNECT, which only LOCAL-SURFACE covers. The undiluted consequence is
interoperability: option 2 is a SHOULD in one normative document and a conformance failure in
the other, with no precedence statement anywhere, so two conforming resolvers diverge under
identical browser configuration. Severity medium rather than high: nothing is implemented, no
reader is exposed, and the intended resolution is already written down in PRIVACY.md §3.2 — the
fix is scoping LOCAL-SURFACE §2.1/§2.2/§6.3 by mode (plus carrying the RFC 1918 refusal into
RESOLUTION's passthrough paragraph), or deleting passthrough and option 2.
```

## registry-worked-example-powproof — MEDIUM

```text
Verified and could not refute. REGISTRY.md:507-537 is the only worked record example in the
entire spec set (sole occurrence of "ownerKey"/"op": "REGISTER" under docs/), and its powProof
is {alg: "argon2id", m, t, p, salt, nonce: 41827366 (integer), bits: 22}. Every quoted counter-
rule checks out verbatim: REGISTRY.md:80-82 requires exactly {alg, nonce, bits} with alg =
argon2id-v19-m65536-t2-p1 and nonce a 16-byte bstr; REGISTRY.md:85 says a verifier MUST reject a
powProof carrying m, t, p or salt; PROOF-OF-WORK.md:47/61-62/133-134 confirm the identifier, the
16-byte nonce and the 18-bit real bound. The implementation sides with the schema, not the
example: registry/src/pow.ts:34 pins POW_ALGORITHM to the long identifier, POW_NONCE_LENGTH=16,
and verifyPow returns POW_BAD_ALGORITHM for alg "argon2id" — registry/src/pow.test.ts:164
asserts that exact rejection, and conformance/vectors.json ships "schema/pow-carrying-cost-
parameters" as a REJECT vector whose CBOR is precisely the example's shape, while its accept
vectors use the long identifier and a 0x50 (16-byte) nonce. Root cause: commit a240435 rewrote
REGISTRY.md:80-95 plus the code and logged it at CHANGELOG.md:339-350, but never touched the
Worked Example 420 lines further down, so the example still shows the pre-fix schema. Not
already fixed, not a wording preference, not out-of-scope roadmap work (Phase 0 spec-settling is
the current phase, and the charter requires the spec to be implementable from the documents
alone). One correction to the claim: bits: 22 is NOT a rejection cause — pow.ts:174-175 states
over-payment is valid and harmless (claimed only has to meet or exceed the recomputed
requirement) and record.ts:191 rejects only bits === 0 or > 256, so 22 is merely inconsistent
with the schedule's stated 18-bit ceiling, not something every verifier rejects. The three
genuinely rejecting defects are the short algorithm identifier, the four forbidden keys, and the
integer-typed nonce. Severity corrected to medium rather than high: it is a real self-
contradiction between normative text and the example an implementer copies first, but the
contradicting MUST sits in the same file, the shipped conformance vectors are correct and
machine-readable, and the document is explicitly Status: Draft — not yet implemented. Fix is to
regenerate the example's powProof from the conformance vector.
```

## letters-only-tld-grammar-uri-scheme-catalogue — MEDIUM

```text
Tried to refute it four ways (misquote, covered elsewhere, already fixed, not-yet-built) and it
survives all four. What I verified: 1. Quotes are exact. `docs/spec/URI-SCHEME.md:44` is
literally `tld = 2*12( %x61-7A ) ; a-z` — letters only, no digits — and §2.1 three lines below
says "The authority is exactly `label "." tld`. It MUST match the grammar in
[NAMES.md](NAMES.md)". `docs/spec/NAMES.md:44` is `tld = %x61-7A *11( %x61-7A / %x30-39 ) ;
letter, then letters/digits`. So URI-SCHEME.md contradicts the document it defers to, in its own
normative section. 2. Already-fixed check makes it worse, not better. `CHANGELOG.md:384` records
the fix — "`.p2p` violated the letters-only label ABNF, which now admits digits after the first
character" — and `registry/src/names.ts:12-18` documents the same correction. The widening was
applied to NAMES.md and to the code only; the identical stale ABNF was left in URI-SCHEME.md and
the identical stale regex was left in the generator. This is a half-landed fix, not an unfixed
one. 3. The catalogue omission is real and worse than claimed. `scripts/build-catalogue.py:49`
is `ok = re.compile(r"^[a-z]{2,12}$")`; `p2p` is in `FOUNDING` at line 132 but fails that regex
at line 148, so it is appended to `rejected` and dropped. Confirmed against the committed
artifact: `grep p2p docs/spec/NAMESPACE-CATALOGUE.md` returns **nothing at all** — `.p2p` is
absent from the entire 1267-entry catalogue, and NAMESPACE-CATALOGUE.md:31-33 reads "## Founding
extensions / *7 extensions*". Constitution Article 35.1 (`constitution/CONSTITUTION.md:2124`)
names `.p2p` among the eleven initial TLDs, `NAMES.md:208` says eleven, `RESOLUTION.md:58` lists
it in the launch set the proxy must classify, and `registry/src/names.ts` freezes it in
`RATIFIED_TLDS`. A charter-ratified TLD is missing from the published launch catalogue. The
generator's comment at line 128 ("Two of the original twelve are absent on purpose: .news and
.blog … and .webx went with the rename") also fails to account for `.libre`, which is absent
from `FOUNDING` and surfaces only in an unrelated generated category at NAMESPACE-
CATALOGUE.md:394 with a different description. 4. No existing gate catches it. I ran `python3
scripts/check-counts.py`: it exits 0, derives "11 launch TLDs" from NAMES.md and checks 3
enumerations, none of which is the catalogue's founding section. `.github/workflows/` has no
build-catalogue regeneration job. The generator prints only a `Counter` of rejection reasons and
exits 0, so the drop is silent — the "absent" in the claim is accurate. 5. Not-yet-built defence
fails. The roadmap's current phase is Phase 0, whose open items are the adversarial spec review
and test vectors for wire-visible rules — a normative-grammar contradiction is precisely that
phase's deliverable, not deferred work. Corrections to the claim, which is why I lowered
severity from what its framing implies: - The *code* is correct. `registry/src/names.ts:123-126`
implements `isWellShapedTld` as letter-then-`[a-z0-9]*`, and `nameRejection` validates by
`RATIFIED_TLDS` membership, so the registry accepts `node.p2p` today. `conformance/vectors.json`
contains no `p2p` vector, so no published conformance bytes are wrong. Nothing shipped is
broken. - The "client refuses to open a valid name" consequence is prospective, not observed:
URI-SCHEME.md is marked "Status: Draft — not yet implemented", and `proxy/` and `client/` are
placeholders per the CHANGELOG's own "what this release does not do" note. The concrete damage
today is a spec a second implementer would build wrong from, plus a published artifact
contradicting the charter. - The low-end point is real but the weakest part. NAMES.md's ABNF
admits a 1-character TLD while NAMESPACE.md:112 ("An extension MUST be **two to twelve
characters**"), URI-SCHEME.md:44 and `names.ts:124` (`tld.length < 2`) all require 2. Three of
four sources say two, so NAMES.md's ABNF is the outlier and a normative prose MUST already
covers it — editorial-grade looseness, not an interop hazard on its own. Severity medium: two
normative documents state mutually exclusive grammars for the same production, one of them while
explicitly claiming to match the other, and a generated spec artifact silently omits a ratified
namespace — in a repo whose stated bar is that an implementer can build from the specifications
alone. Not high: no live behaviour is wrong, the implementation already has it right, and the
fix is three lines (URI-SCHEME.md:44 ABNF, build-catalogue.py:49 regex, and the stale line-128
comment) plus a count assertion in check-counts.py covering the catalogue's founding section.
```

## resolution-md-cross-reference-and-count — MEDIUM

```text
I tried to refute this and could not — every quoted string is verbatim and every cited section
number is wrong. VERIFIED, line by line: - /workspace/vayuweb/docs/spec/RESOLUTION.md:311-314
reads exactly "Four channels are not closable by CSP at all — WebRTC, top-level navigation,
timing side channels, and a compromised endpoint. CONTENT-SECURITY.md section 4 names each and
specifies what closes it instead; the resolver MUST implement those controls". -
/workspace/vayuweb/docs/spec/CONTENT-SECURITY.md heading map (grep of all ATX headings): §4 at
line 220 is "Header and markup hygiene at the proxy" (4.1 request headers not emitted, 4.2
response headers stripped, 4.3 markup neutralised). The residuals are §5 at line 261, "What no
header can close", with eight entries 5.1–5.8 (WebRTC, top-level navigation, the PAC file,
fingerprinting, the browser's own behaviour, network-layer correlation, same-origin timing,
compromised endpoint). So the pointer is wrong and the count is four of eight. -
RESOLUTION.md:316-317 cites "CONTENT-SECURITY.md section 1.3" for the two relaxations. §1 (line
46, "The insecure-context reality") has no subsections at all; the two relaxations are §2.3 at
line 157. PUBLISHING.md:100 cites the same content correctly as "section 2.3", which settles
which one is out of step. The same wrong "section 1.3" also appears twice in VWIP-0001.md (lines
98 and 129) — the defect is wider than the reported area. - PRIVACY.md:84 (the finding said 83;
the sentence starts on 83, the citation is on 84) cites "section 4.2" for the top-level-
navigation channel, which is §5.2. CONTENT-SECURITY.md's own §2.2 (line 152) refers to that same
channel as "section 5.2", so the document is internally consistent and PRIVACY.md is the one
that drifted. MECHANISM CHECK (does the misdirection actually orphan anything): RESOLUTION.md's
preceding paragraph (296-299) incorporates CONTENT-SECURITY.md by an explicit enumeration — "the
Content-Security-Policy, the ten accompanying response headers, the request headers the resolver
must never emit, the response headers it must strip, and the markup it must neutralise" — i.e.
§§2, 3, 4.1, 4.2, 4.3. §5 is not in that list. The only hook RESOLUTION.md has into §5 is the
sentence at 312, and it points back into §4, which was already incorporated. So §5.3's PAC rules
("MUST NOT call dnsResolve, isResolvable, isInNet or myIpAddress") and §5.6's atomic whole-DAG
fetch are genuinely unreachable from RESOLUTION.md, and RESOLUTION.md:191-198 makes the PAC file
the mandatory ("SHALL support option 1") browser integration without restating those rules
anywhere — grep confirms `dnsResolve` appears exactly once in the whole tree, at CONTENT-
SECURITY.md:283. Also inaccurate in the same sentence: "specifies what closes it instead" is
false for two of the four it names — §5.7 says "Not closable, and not claimed" and §5.8 says
"Complete and irreducible". NOT ALREADY FIXED / NOT GUARDED: nothing in CHANGELOG.md's
[Unreleased] touches cross-references or renumbering; git log shows no renumbering commit.
scripts/check-links.py validates file links only and explicitly skips anchors, so prose "section
N" references are unchecked. scripts/check-counts.py has only two rules (launch TLDs,
accompanying response headers) — neither covers residual channels. The project already treats
exactly this class of defect as real: commit 9ee6cc2 "correct six inherited count claims, and
derive counts from their source in CI". SEVERITY CORRECTED DOWN, from the claimed consequence.
The claim overstates the practical blast radius: CONTENT-SECURITY.md §6 turns both allegedly-
skipped items into build gates in its own document — test 8 "The PAC file contains none of the
forbidden functions (static check)" and test 10 "The whole-DAG snapshot is fetched and verified
before any path is served" — and §5's MUSTs are normative where they stand. An implementer
working from CONTENT-SECURITY.md end to end cannot ship a dnsResolve PAC file and pass
conformance. What is actually broken is that three normative pointers send a reader to the wrong
section (a real section, so the error is silent rather than dangling) and one states a count
that is half its source. For a project whose Phase 0 bar is that the specs be implementable from
the documents alone, that is a genuine medium — not the critical/high a "PAC file leaks DNS"
framing implies. Fix is four one-line edits: RESOLUTION.md:312 section 4 → 5 (and "Four" →
"Eight", or reword to "four of the eight"), RESOLUTION.md:317 and VWIP-0001.md:98,129 section
1.3 → 2.3, PRIVACY.md:84 section 4.2 → 5.2 — plus, in this repo's own idiom, a check-links.py
rule that resolves "section N" prose references against the target document's headings so it
cannot recur.
```

## csp-injection-scope-html-vs-every-response — MEDIUM

```text
Verified and survives. CONTENT-SECURITY.md:93-95 says the resolver SHALL inject the CSP "on
every response it serves" and explicitly adds "It is injected on non-HTML responses too, so that
a worker or worklet script inherits it" — a deliberate clause with its own rationale, not
incidental phrasing. CONTENT-SECURITY.md:320 (conformance test 1) asserts the canonical values
are "emitted byte-identically on every response", and section 6 states these are executable
tests on observed behaviour. RESOLUTION.md:292 narrows this to a normative SHALL "on every HTML
response", and RESOLUTION.md:296-299 immediately claims the profile "is not restated here…
defined in exactly one place so that it cannot drift; scripts/check-headers.py enforces that". I
searched the whole spec tree: the word "inject" appears exactly twice (those two sentences), and
nothing in RESOLUTION.md restores non-HTML scope — its only other subresource mentions are :304
(clearnet subresources refused) and :360 (error pages). I read scripts/check-headers.py end to
end: it extracts canonical:<name> sentinels and fenced blocks, normalises whitespace and
compares header VALUES only; it has no representation of injection scope, so the cited guard
genuinely cannot catch this. proxy/ and client/ contain only README.md, so there is no
implementation to have fixed it, and CHANGELOG.md has no entry for it. There is a direct
precedent that this class is treated as a real defect in this repo: a prior "Fixed" entry where
four normative statements in RESOLUTION.md contradicted a rule owned elsewhere ("RESOLUTION.md
required the resolver to emit the fingerprint it forbids"), remedied by making them defer.
Refutations attempted and rejected: it is not shorthand (it is a SHALL in a normative security
section); no other passage widens it; the delta is wire-visible so it is not stylistic. Severity
corrected down to medium: the security impact is narrower than claimed, because worker-src
'none' already forbids workers entirely (2.3 lists Web Workers as broken with no relaxation) and
2.1a concedes engines differ on whether worker-src or script-src governs worklets while noting
both are 'self' or stricter "so the ambiguity cannot open a hole". The genuine harm is
interoperability plus a false single-source-of-truth claim: two conforming resolvers emit
different bytes for the same .js/.css/.svg, and a RESOLUTION-conformant build fails CONTENT-
SECURITY conformance test 1 — exactly the wire-visible-rule class Phase 0 exists to settle.
Docs-only, one-word fix.
```

## privacy-contained-webview-vs-locked-profile — MEDIUM

```text
Verified all quoted lines verbatim. PRIVACY.md:42 claims Private Mode's browser is "Contained,
because full-proxy configuration and the client's own webview are mandatory (section 2.1)", and
PRIVACY.md:262 repeats it in §11. CONTENT-SECURITY.md:300 (§5.5) makes the webview optional —
"the client's own webview OR a locked browser profile" — and CONTENT-SECURITY.md:269-271 (§5.1)
says WebRTC IP disclosure "cannot be enforced" for a third-party browser and is "the most
serious residual in the browser layer". §5.1 additionally states WebRTC "uses raw UDP and
ignores the HTTP proxy entirely, so full-proxy mode does not contain it either", so of the two
reasons PRIVACY.md gives for "Contained", only the webview covers WebRTC — and that is exactly
the one CONTENT-SECURITY makes optional. PRIVACY.md contradicts itself internally too: lines
165-172 sit inside the Private Mode paragraph (ephemeral profile MUST) and provide for "the
reader insists on a third-party browser". Two points the claim understates. (1) I grepped every
.md in the tree: no normative clause anywhere makes the client's own webview mandatory. URI-
SCHEME.md:116 says SHOULD; CONTENT-SECURITY.md:137 says only "strongest in" the webview;
VWIP-0001.md:93 calls WebRTC "a documented residual for third-party browsers rather than a
solved problem". PRIVACY.md's own "Browser requirement" row for Private Mode lists only "Full-
proxy configuration required" and omits the webview. The containment claim rests on a mandate
that does not exist. (2) The dangling pointer is confirmed — PRIVACY.md headings run 1, 2, 3,
3.1; §2 has no subsections, so "(section 2.1)" has no referent and the reader sent to find the
mandate finds nothing. Refutations attempted and failed: §11's engine-uniformity hedge does not
rescue it, because §11's own closing paragraph requires that "where a control is engine-
conditional or mode-conditional, that condition is named in the clause itself rather than left
to a reader to infer" — the mode-table cell violates that standard. Not already fixed: CHANGELOG
has no entry on this wording (lines 256/260 are unrelated historical text). Not out-of-scope:
ROADMAP Phase 2's goal is "VayuWeb names work in a browser nobody modified" and CONTENT-
SECURITY.md:326 defines a conformance test across Firefox, Chromium and WebKit, so third-party
browsers are a supported configuration. Severity lowered to medium: this is a specification-
level normative conflict with no implementation yet (registry core only, Phase 0), and CONTENT-
SECURITY §5.1/§5.5 and PRIVACY §5 independently oblige a conformant client to warn plainly in
the third-party-browser case, so a reader would be warned rather than silently exposed. The
defect is a real unconditional security claim that holds in only one of two permitted
configurations, plus a broken cross-reference — worth fixing before Phase 0 closes, but not high
or critical.
```

## local-surface-cross-name-subresources-vs-content-security — MEDIUM

```text
Verified against the files; I tried to refute it and could not, though the framing is overstated
on two points. What checks out: - /workspace/vayuweb/docs/spec/CONTENT-SECURITY.md:8 does
declare itself "the **single source of truth**" for the CSP, and scripts/check-headers.py only
enforces byte-identity of *fenced canonical blocks* — LOCAL-SURFACE §4 quotes no fenced header,
so it escapes that gate entirely. - CONTENT-SECURITY.md:34 names "a cross-name subresource
allowance" as the first item in the list of relaxations that "instantly revalues every unfixable
fingerprinting vector from harmless to critical", and closes with "That is why the refusals in
this document are not tunable." - CONTENT-SECURITY.md:157 §2.3 is titled "What this breaks, and
the two relaxations"; the table's only relaxations are per-site `vayu-wasm` and a per-site
Trusted Types policy. Line 168-170: "Every relaxation is **per-site, never global**, and
**visible to the reader**… No configuration file, control-API setting or command-line flag may
apply either relaxation globally, and that refusal is not tunable." Canonical CSP at line 100
pins `img-src 'self'; font-src 'self'; media-src 'self'`, and conformance test 1 (line 320)
requires the canonical values "emitted byte-identically on every response". -
/workspace/vayuweb/docs/spec/LOCAL-SURFACE.md:130-138 is a whole section, "## 4. Cross-name
subresources", whose normative content is "Where `allow_cross_name_subresources` is offered at
all it MUST be off by default, and when set it MUST widen only `img-src`, `font-src` and `media-
src`" plus a MUST NOT list for script/connect/frame/object/worker. It says nothing about per-
site scoping or reader disclosure, and it is not in that document's own §6 conformance list. So
the two specs disagree on whether the setting may exist at all: one refuses it as untunable, the
other supplies a permission-shaped floor for it. That is exactly the failure mode check-
headers.py's own docstring names — "two implementers read two different policies and both
believe they are conformant". - Not already fixed: `allow_cross_name_subresources` appears
exactly once in the whole repo (grep), the text has never been touched since import (`git log
-S` returns only the initial spec commit), and CHANGELOG `[Unreleased]` has no entry for it. Not
"not yet built" either — docs/ROADMAP.md:28 lists "Independent adversarial review of the above"
as **the current work**, and CHANGELOG records prior spec-vs-spec defects fixed the same way
(e.g. 047d969 "RESOLUTION.md required the resolver to emit the fingerprint it forbids"). The
specification *is* the Phase 0 deliverable, so a contradiction inside it is a defect, not a
style preference. Where the claim overstates, and why I lowered severity from what the "live
cross-name request channel" framing implies: - LOCAL-SURFACE does not "specify a global
configuration setting". The clause is conditional — "Where … is offered at all" — and it never
mandates that the setting exist, never says global, and never names a config file. The defect is
silence on scope plus a permissive framing, not an affirmative global switch. - "An implementer
ships a global switch" is not reachable for a *conformant* build: CONTENT-SECURITY owns the CSP,
refuses the allowance outright, and its conformance test 1 fails any response whose CSP is not
byte-identical to the canonical line — so a widened img-src/font-src/media-src fails the suite
regardless of which document the implementer read. No code exists yet (no CSP emitter anywhere
in registry/, client/, proxy/). So: a real, unrepaired normative contradiction between two draft
specs in a security-critical area, caught by no existing gate, in the exact review phase meant
to catch it — but bounded by an authoritative document that already refuses it and a conformance
test that would fail the build. Medium, not high/critical. Fix is a one-paragraph edit: restate
LOCAL-SURFACE §4 as "MUST NOT be offered — see CONTENT-SECURITY.md §0 and §2.3", keeping the
cross-name supply-chain rationale as the explanation rather than as conditions of use.
```

## csp-test1-vs-relaxations — MEDIUM

```text
Verified all cited text verbatim. CONTENT-SECURITY.md:320 test 1 requires the three canonical
values (the three canonical:* sentinel-fenced blocks) to be "emitted byte-identically on every
response" with no carve-out anywhere in section 6; section 2's injection sentence is likewise
unqualified. Lines 163-164 confirmed: the per-site vayu-wasm relaxation adds 'wasm-unsafe-eval'
to script-src, and a named Trusted Types policy is by definition incompatible with the canonical
trusted-types 'none' (section 2.1 line 124 states "No policy may be created"). LOCAL-
SURFACE.md:132-133 confirmed. VWIP-0001.md:130 confirmed leaning on test 1 as the interop
anchor. Not already fixed: client/ and proxy/ contain only README.md, grep for Content-Security-
Policy across client/proxy/registry returns nothing, CHANGELOG [Unreleased] has no related
entry, and scripts/check-headers.py only enforces that quotations of the canonical block match
across documents, so CI cannot catch this. Not out-of-scope-by-roadmap: ROADMAP Phase 0 is
current and its open items are the adversarial spec review and test vectors for wire-visible
rules, so a spec-text defect is exactly the in-phase deliverable. Two corrections. (1) The
claimed consequence is overstated: test 6 in the same list ("Every relaxation in 2.3 is per-site
and surfaced in the UI") makes the relaxation feature unambiguously mandatory, so an implementer
reading all ten tests cannot land on "no relaxations exist" — the real failure is a conformance
test that cannot pass on a conformant build, not a genuine fork where each side has normative
backing. (2) The LOCAL-SURFACE half is stronger than the claim states and is a contradiction of
substance rather than wording: CONTENT-SECURITY section 0 names "a cross-name subresource
allowance" as the archetype of the relaxation that revalues every fingerprinting vector and
concludes "the refusals in this document are not tunable"; section 2.3 enumerates exactly two
relaxations and forbids any "configuration file, control-API setting or command-line flag" from
applying them globally; LOCAL-SURFACE section 4 nonetheless offers a third widening as an
install-scoped configuration setting (allow_cross_name_subresources) with no counterpart in 2.3.
Severity medium rather than high/critical: no code exists to be wrong, the test-1 half is a one-
clause fix, and test 6 forecloses the worst misreading. Incidental: VWIP-0001 cites "CONTENT-
SECURITY.md section 1.3" for the per-site relaxations, which live in 2.3 — a separate trivial
stale cross-reference.
```

## local-surface-3.3-3.4-unspecified-bounds — MEDIUM

```text
Verified the quotes exactly: LOCAL-SURFACE.md:120-122 (§3.3) requires "a documented maximum
entry count and a finite TTL"; :126-128 (§3.4) requires per-page/per-origin concurrency caps, a
bounded in-flight count and a total cache memory ceiling "specified with concrete numbers".
RESOLUTION.md:216-241 supplies TTLs (300 s positive, 120 s IPNS, 30/60/10 s negative) and a 2
GiB content-cache LRU + 30-day idle eviction, and at :236-238 points back to LOCAL-SURFACE §3.3
for the entry count. Grepped docs/, conformance/, client/, proxy/, registry/ for concurren|in-
flight|per-origin|max_entries|entry count|memory ceiling: the only hits are the LOCAL-SURFACE
lines themselves. No maximum entry count, no concurrency cap and no in-flight bound exist
anywhere in the set. CHANGELOG [Unreleased] does not address it; client/ and proxy/ contain only
README.md so it is not fixed in code. ROADMAP Phase 0 is the current phase, its open item is
literally the independent adversarial spec review, and its Done-when is Article 44.6
implementability-from-documents-alone, explicitly "not satisfied today" — so this is in-scope,
not an unbuilt feature, and there is CHANGELOG precedent (the merkle tree was specified for
exactly this reason). Corrections to the claim, which is partly overstated: (1) the circularity
is real only for §3.3's entry count — §3.4 is not circular, RESOLUTION.md never defers to it,
those numbers are simply missing. (2) "The bounds are the defence against the memory-exhaustion
primitive §3.3 exists to close" is wrong: the primary defence IS specified — RESOLUTION.md:233
makes LABEL_INVALID/TLD_UNKNOWN "not cached at all", removing the arbitrary-garbage fill; what
remains is fillable only with grammar-valid known-TLD names and is bounded in time at 30 s. (3)
These are local resource policies, not wire-visible rules, so different caps do not break
interoperation — the consequence is robustness variance and an uncheckable MUST, not a
resolution divergence. (4) A memory ceiling is partly covered (2 GiB content LRU, 256 MiB per
resource); the record and negative caches are the uncovered part. Severity medium rather than
high/critical: the sharpest primitive is already closed, remaining negative entries have finite
TTLs, and no code implements this surface yet (Phase 3 proxy unbuilt), so nothing is broken for
users.
```

## csp-four-channels-vs-eight — MEDIUM

```text
Confirmed against the files; could not refute. RESOLUTION.md:311-314 reads verbatim as quoted:
"Four channels are not closable by CSP at all — WebRTC, top-level navigation, timing side
channels, and a compromised endpoint. CONTENT-SECURITY.md section 4 names each and specifies
what closes it instead; the resolver MUST implement those controls". CONTENT-SECURITY.md:261-314
is "## 5. What no header can close" and enumerates eight: 5.1 WebRTC, 5.2 top-level navigation,
5.3 the PAC file, 5.4 fingerprinting, 5.5 the browser's own behaviour, 5.6 network-layer
correlation, 5.7 same-origin timing, 5.8 a compromised endpoint. Section 4 is header
hygiene/markup neutralisation, so the pointer is wrong as well as the count. VWIP-0001.md:24
repeats "the four channels CSP cannot close" (line 44's "nine channels ... quiet about four" is
defensible — it describes the provisional profile being replaced — but the abstract describes
the adopted document). The omitted controls are genuinely absent from RESOLUTION.md: grep for
DAG/snapshot in RESOLUTION.md returns nothing, so 5.6's whole-DAG-snapshot rule (numbered
conformance test 10 in CONTENT-SECURITY §6) exists only in CONTENT-SECURITY.md; and
RESOLUTION.md's PAC text at line 195 specifies only routing/DIRECT, not 5.3's "MUST NOT call
dnsResolve/isResolvable/isInNet/myIpAddress" (conformance test 8). Two of the four that
RESOLUTION does list have no control at all — 5.7 "Not closable, and not claimed" and 5.8
"Complete and irreducible" — so the MUST is attached to a set of which half is unimplementable.
Not already fixed: nothing in CHANGELOG.md [Unreleased]; git log on the three files shows only
047d969 / 9ee6cc2 / ae3af05 / 8647baf, none of which is this. Not caught by CI: scripts/check-
headers.py compares only fenced canonical header blocks, and scripts/check-counts.py has rules
only for launch TLDs and accompanying response headers — I ran it, exit 0, "13 counted claim(s)
agree". Refutations attempted and rejected: (a) "prose, not normative" — the sentence carries a
MUST, and the repo's own doctrine (check-counts.py docstring, commit 9ee6cc2 "correct six
inherited count claims") treats a counted claim disagreeing with its defining source as exactly
this class of defect; (b) "RESOLUTION defers to CONTENT-SECURITY" — the paragraph immediately
above states the profile is "not restated here ... defined in exactly one place so that it
cannot drift", so a wrong restatement two paragraphs later is the drift that sentence forbids;
(c) "unbuilt feature" — ROADMAP Phase 0's open work is the adversarial spec review, so spec text
is in scope. Severity corrected down to medium: the claimed consequence overstates the harm. An
implementer cannot stop at four and believe the profile complete — RESOLUTION points to CONTENT-
SECURITY.md as normative, VWIP-0001 adopts it in full, and the conformance suite including tests
8 and 10 lives in CONTENT-SECURITY §6, so anyone chasing conformance meets 5.3 and 5.6 there.
What is real is a normative MUST bound to a miscounted enumeration plus a broken section cross-
reference, in a project whose acceptance criterion is a second implementation built from the
specs alone. Fix is one sentence: drop the enumeration, cite section 5, attach the MUST to the
section.
```

## content-security-4.1-uniform-headers — MEDIUM

```text
Could not refute. Evidence verified verbatim: CONTENT-SECURITY.md:226 states the property "Every
install emits a byte-identical outbound request header set", and :228-235 supply only a denylist
("Never forwarded or generated: …" ending in a catch-all for "install identifier, resolver
version, build hash or platform string") plus two pinned constants (User-Agent, Accept-
Language). Repo-wide grep across docs/, constitution/, proxy/, client/, conformance/ returns
ZERO hits for Accept-Encoding, Sec-Fetch, Priority or header ordering — no other section rescues
it, and §0's "Uniform beats random" paragraph (:41-44) names only UA, window size, TZ and
Accept-Language. The catch-all does not reach Accept-Encoding (br/zstd varies by build), Sec-
Fetch-Site/Mode/Dest/User (Chromium/Firefox emit, WebKit does not), Priority, or header order,
none of which is an identifier/version/build-hash/platform string. The denylist reading is load-
bearing rather than pedantic: RESOLUTION.md:132-145 makes the resolver an HTTP/1.1 forward proxy
with a passthrough mode, and §4.1's own wording is "Never FORWARDED or generated", so an
implementer passes the browser's header set through minus the listed names and satisfies every
enumerated MUST NOT while emitting a per-build fingerprint. Test divergence also confirmed:
CONTENT-SECURITY.md:330 (unscoped) vs PRIVACY.md:242-243 ("fetch the same page") vs
VWIP-0001.md:211 (unscoped); scripts/check-headers.py only enforces byte-identity inside <!--
canonical:… --> fenced blocks (CSP/Permissions-Policy/Referrer-Policy at :98,:174,:199), so CI
does not catch it. Not already fixed — CHANGELOG.md [Unreleased] has no §4.1 entry, and proxy/
and client/ contain only README.md, so no implementation contradicts the spec. Not out of scope
— ROADMAP.md Phase 0 is the current phase with the adversarial spec review and wire-visible test
vectors open, and its done-criterion is that an implementer can build a conforming client from
the specs alone (Article 44.6); the document itself warns that policy drift means "two
implementers read two different policies and both believe they conform". Severity set to medium,
not high: it is a real normative gap in the flagship privacy property, but the spec is Draft, no
code exists, nothing is broken for users, and it was found in the phase designed to find it.
Fix: replace the denylist with an exhaustive ordered emitted-header allowlist (ideally inside a
canonical: sentinel so check-headers.py enforces it), and scope test 5 to "fetch the same page"
to match PRIVACY.md:242 — as written it is unimplementable because Host differs between
arbitrary requests. Files: /workspace/vayuweb/docs/spec/CONTENT-SECURITY.md,
/workspace/vayuweb/docs/spec/PRIVACY.md, /workspace/vayuweb/docs/spec/VWIP-0001.md,
/workspace/vayuweb/scripts/check-headers.py.
```

## registry-worked-example-powproof — MEDIUM

```text
Confirmed by reading the files. REGISTRY.md:80-85 requires powProof to be exactly {alg, nonce,
bits} with alg = "argon2id-v19-m65536-t2-p1" and nonce a 16-byte bstr, and states a verifier
MUST reject a powProof carrying m, t, p or salt. The Worked Example at REGISTRY.md:526-534
(claim cited 487-495; line numbers drifted, content verbatim) carries all four forbidden fields
plus alg "argon2id" and an integer nonce 41827366. It is introduced with no caveat at line 509.
PROOF-OF-WORK.md:47 and :61-62 say what the claim says. Additional divergence the claim missed:
"bits": 22 exceeds both the min(20,...) ceiling at PROOF-OF-WORK.md:113 and the 18-bit reachable
maximum stated at :133-137. Not already fixed: CHANGELOG.md:339-350 documents the removal of
m/t/p/salt, but the edit reached the field table and prose only, leaving the example in its pre-
fix shape. Code is correct and unaffected: registry/src/pow.ts pins POW_ALGORITHM,
POW_NONCE_LENGTH=16, MAX_DIFFICULTY_BITS=20, and pow.test.ts:164,315 assert alg "argon2id" is
rejected. Strongest confirmation: conformance/vectors.json publishes schema/pow-carrying-cost-
parameters and schema/pow-carrying-salt as MUST-REJECT vectors built on the same atlas record
with the correct alg string and a 16-byte nonce, so the spec's only worked example is field-for-
field a record the project's own conformance suite requires implementations to refuse. Guard
claim verified: registry/src/domain.test.ts:21 is the only reference to the worked example
outside dist/, and it uses ['powProof', null], so CI never reads the example's powProof.
Severity corrected to medium rather than higher: this is a documentation-only defect in a
document marked "Status: Draft - not yet implemented", the contradicting normative rule is in
the same file, and both the implementation and the conformance vectors are correct - but it is
above low because a worked example is what implementers copy first and this one is a published
must-reject, which is precisely the Phase 0 failure mode.
```

## docs-spec-nomatch-path-divergence — MEDIUM

```text
Verified all three quotes are accurate at the cited lines. RESOLUTION.md declares "This document
owns the resolution path only" and heads its algorithm "The following steps are normative and
ordered"; step 13 (lines 99-102) returns 1414 PATH_NOT_FOUND on no match. Grepping RESOLUTION.md
for "manifest", "notFound" and "fallback" returns zero content hits — the document has no step
that reads the manifest at all. PUBLISHING.md 2.3 (104-106) nonetheless imposes a normative
resolver obligation to serve notFound (404) or fallback (200) from manifest fields declared at
PUBLISHING.md:56-57. Two normative documents therefore give a conforming resolver different
wire-visible answers (status code and body) for GET /app/route. Reinforcing evidence:
HOSTING.md:44-47 describes the manifest as carrying title/description/entry/generator — a field
set completely disjoint from PUBLISHING.md's version/index/fallback/notFound/inline/csp — and
calls it "advisory", which conflicts with PUBLISHING's SHALL. HOSTING's rationale "has nothing
to fall back on" is indeed falsified by PUBLISHING's fallback field. Not fixed:
registry/src/resolve.ts mapPath (lines 290-307) implements RESOLUTION step 13 exactly, with no
notFound/fallback handling, and the error table (line 49) has only PATH_NOT_FOUND; CHANGELOG
[Unreleased] says nothing about deep links, 404 handling or the manifest schema. Not out of
scope: ROADMAP Phase 0 is the current phase and its open items are the adversarial spec review
and test vectors for every wire-visible rule, so a normative contradiction on a served response
is exactly the work in flight, and it is the kind of gap Phase 6's independent-implementation
test exists to expose. WHERE THE CLAIM OVERREACHES: it is two conflicting documents, not three.
HOSTING.md:34-36 states a publisher requirement (subdirectories MUST contain index.html) with a
rationale clause; it specifies no resolver response for an unmatched path. And PUBLISHING's two
outcomes are ordered relative to each other, not in conflict. So "three conforming resolvers,
three answers" is inflated to "one contradiction between two normative documents, plus a false
rationale in a third". Severity corrected to medium: real and wire-visible, but nothing is
deployed, the feature is opt-in and unusable today, RESOLUTION and the implementation agree with
each other, and the fix is a one-paragraph reconciliation (move deep-link fallback into
RESOLUTION step 13, or drop PUBLISHING 2.3's resolver obligation) plus correcting HOSTING's
manifest field list and its "nothing to fall back on" clause.
```

## uri-scheme-tld-grammar-excludes-p2p — MEDIUM

```text
Verified and survives. docs/spec/URI-SCHEME.md:44 still reads `tld = 2*12( %x61-7A ) ; a-z`,
while docs/spec/NAMES.md:44 reads `tld = %x61-7A *11( %x61-7A / %x30-39 )`. `.p2p` is a ratified
launch TLD (NAMES.md:214, RESOLUTION.md:57-58 step 2, and frozen in registry/src/names.ts
RATIFIED_TLDS), and it contains a digit, so it is unrepresentable under URI-SCHEME.md's own
production. registry/src/names.ts:11-17 and CHANGELOG.md:384 both record this exact letters-only
production as a defect that was corrected "there rather than worked around here" — a grep for
`2*12` across the repo shows the correction reached NAMES.md only; the stale copy in URI-
SCHEME.md was missed. Same for the minimum: NAMES.md permits a 1-character TLD, URI-SCHEME.md
requires 2. Refutation attempts that failed: (1) URI-SCHEME.md 2.1 says the authority "MUST
match the grammar in NAMES.md", but that is an additional constraint, not an override — I
grepped URI-SCHEME.md for authoritative/normative/prevail/conflict and there is no clause making
NAMES.md win a conflict, so the two MUSTs intersect and the intersection still excludes `p2p`.
Note the asymmetry with the sibling `label = 1*63(...)` production, which is broader than
NAMES.md and therefore legitimately narrowed by 2.1; the tld production is narrower and cannot
be widened back. (2) Not already fixed — [Unreleased] in CHANGELOG.md does not touch URI-
SCHEME.md. (3) Not merely editorial — the project itself classified the identical text in
NAMES.md as a defect, and Phase 0 (the current phase) is precisely about settling the spec and
writing test vectors for wire-visible rules. Severity corrected down to medium: the consequence
is latent rather than live. client/ and proxy/ are README-only placeholders, so no URI parser
exists yet, and REGISTRY.md validates a TLD by set membership rather than by re-deriving the
grammar. The one-character-TLD half is accurate but purely theoretical — no ratified TLD is one
character and minting one requires a VWIP. Fix is one line: align URI-SCHEME.md:44 with
NAMES.md:44, or drop the local production and cite NAMES.md as sole source.
```

## check-counts-tld-enumeration-anchor — MEDIUM

```text
Confirmed, and reproduced. scripts/check-counts.py:149 is verbatim as quoted:
re.finditer(r"\.vayu[,`\s].{0,400}?\.blog", text, re.S). Both anchors are themselves members of
truth_set, so the two extensions whose omission matters most are exactly the two the matcher
cannot detect as missing; only interior omissions are visible. Instrumented the loop over the
real repo: exactly three enumerations match, all the same canonical-order list
(constitution/CONSTITUTION.md:2124, docs/FAQ.md:58, docs/spec/RESOLUTION.md:58). Script prints
"checked 3 extension enumeration(s)" and exits 0. Mutation-tested three omission classes on a
copy of the repo at docs/FAQ.md:58: dropping interior `.news` is CAUGHT ("extension list omits
news", exit 1); dropping trailing `.blog` PASSES (checked 2, exit 0); dropping leading `.vayu`
PASSES (checked 2, exit 0). The `if listed == 0` loud-failure guard at line 228 does not help —
it fires only when every enumeration repo-wide stops matching, so losing one drops the count 3
to 2 with no diagnostic. The cited live instance is real: docs/spec/NAMESPACE-CATALOGUE.md:31-43
is a section literally headed "## Founding extensions", labelled "*7 extensions*", listing .dao
.decent .free .indie .open .sov .vayu — alphabetised, so .vayu is last with no .blog following,
hence never matched. It omits .p2p, .libre, .news, .blog against docs/spec/NAMES.md:213-223's
ratified eleven. Stronger than claimed: .p2p, .news and .blog appear nowhere in the 1,542-line
catalogue at all (.libre only at line 394, in a different section). The guard reports OK on it
today. Refutations attempted and failed: (a) not already fixed — CHANGELOG.md:149-153 is the
entry that introduced this code, and its mutation test only reintroduced the DUPLICATE .vayu
into three files, a repeat that preserves both anchors, so omission-of-an-anchor was never
exercised; (b) not out of scope or unbuilt — the script runs in .github/workflows/ci.yml:73 and
release.yml:141; (c) not style — the CHANGELOG makes a behavioural claim ("failing on a repeat
or an omission… fails loudly if it matches no enumeration at all") that the code does not honour
for a whole omission class, with an in-repo document exercising it. Severity medium rather than
high: it is a documentation-lint guard, not shipped protocol code or a security control, and the
underlying inconsistency is readable by a human. Not low/editorial either: this is a spec-first
project in the phase where the normative text is being settled, the script's own comments name
"a check quietly stops checking while still reporting success" as the exact failure it exists to
prevent, and it is currently doing that on a real file. Fix: anchor on any ratified extension (a
contiguous run of >=3 members of truth_set) instead of the two endpoints, or detect a self-
identifying founding-extensions block ("## Founding extensions" / "*N extensions*") and validate
it against truth_set and the derived count of 11.
```

## tld-set-specified-three-ways — MEDIUM

```text
Partly refuted, partly confirmed; severity corrected down. REFUTED: (a) The eleven TLDs are
consistent, not contradictory, across CONSTITUTION.md Art. 35.1, NAMES.md:208-218,
RESOLUTION.md:58, REGISTRY.md:49/:256 and registry/src/names.ts:31 (RATIFIED_TLDS, exactly 11).
registry/src/names.test.ts:23-50 pins the set by value and size AND re-parses NAMES.md's
founding list to assert equality; scripts/check-counts.py derives the set from NAMES.md and
fails any inline enumeration that omits an entry (ran it: passes, 13 claims). (b) The claimed
consequence — "a record with tld: 'shop' is valid under NAMES.md/NAMESPACE-CATALOGUE.md" — is
false. NAMESPACE-CATALOGUE.md:27 states "Status: Draft — not yet implemented. No extension is
registrable until the protocol exists and each has completed the 180-day dormancy period
required by Article 35", and NAMESPACE.md 4.1 requires a ratified Naming VWIP per extension. The
catalogue is an unratified menu; no implementer derives registrability from it. So there is no
"namespace fork decided by which document you read". CONFIRMED (two defects): (1) NAMESPACE-
CATALOGUE.md:31-43 heads a section "## Founding extensions / *7 extensions*" and lists 7, while
the charter fixes 11. grep over the whole 1,538-line file confirms .p2p, .news and .blog appear
nowhere in it. This is worse than a miscount: NAMESPACE.md 5.2 ("An extension MUST NOT duplicate
a well-known ICANN generic top-level domain") would itself forbid .news and .blog, which Art.
35.1 mandates — a charter-vs-spec conflict. .p2p is not an ICANN gTLD, so 5.2 does not explain
its absence. The repo's own guard misses it: check-counts.py only matches three-or-more
consecutive extensions on one line, and the catalogue is one per table row, so the founding-7
table evades the very check written to stop this drift. (2) NAMESPACE.md:39 ("An implementation
MUST NOT hard-code the extension list. The set of valid extensions is derived from the registry
log") and NAMES.md:200 ("no implementation hard-codes the list") are flatly contradicted by
REGISTRY.md:256 and by registry/src/names.ts, which hard-codes the set and freezes it with a
test asserting an edit must fail. The mechanism 2.3 describes has no carrier: REGISTRY.md:47
fixes op to six values, none TLD-creating, and Art. 35.6 creates TLDs by ratified VWIP — out-of-
band governance, not log content. 2.3 is therefore unimplementable as written and directs an
implementer to build something REGISTRY.md rejects. Not already fixed: CHANGELOG records earlier
namespace fixes (duplicate .vayu, "twelve" vs eleven, ABNF widened for .p2p) but nothing
touching the catalogue's founding section or NAMESPACE.md 2.3. Not out-of-scope: ROADMAP Phase 0
lists "Independent adversarial review of the above — Open, this is the current work", with the
done-condition "a competent implementer can read the specifications alone... and produce a
client that would interoperate" — exactly what these two contradictions defeat. Severity medium,
not critical/high: no wire behaviour is at risk today (five sources plus two tests agree on the
eleven, and no code implements a log-derived set), so the impact is implementer confusion in
normative text rather than a live namespace split.
```

## registry-worked-example-powproof — MEDIUM

```text
Could not refute. Verified in /workspace/vayuweb/docs/spec/REGISTRY.md: lines 80-85 state
powProof is exactly {alg, nonce, bits} with alg = "argon2id-v19-m65536-t2-p1" and nonce a
16-byte bstr, and that "A verifier MUST reject a powProof carrying m, t, p or salt". The worked
example (actually at REGISTRY.md:526-534, NOT 487-495 as the claim cites — citation off by ~39
lines, but the quoted JSON is verbatim correct) still carries alg "argon2id", m 262144, t 3, p
1, salt "XaGvK-1McJRNX-agVfElbQ", nonce 41827366 (a JSON integer, not the base64url bstr the
example's own preamble promises), bits 22. PROOF-OF-WORK.md:47-49 fixes the identifier and
m=65536/t=2/p=1, and line 61 repeats the three-field triple with a 16-byte nonce, so m:262144
and t:3 contradict the constants too. Refutation attempts all failed: (1) Not already fixed —
CHANGELOG.md:339-350 records this exact fix landing in the table, the code and the vectors, but
the example was never updated, which is precisely the claim's framing. (2) Code agrees with the
table, not the example: registry/src/record.ts:173-187 rejects any alg != POW_ALGORITHM with
BAD_POW_SHAPE and reads nonce via bytesField(map,'nonce',POW_NONCE_LENGTH);
registry/src/vectors.ts:87-88,269 emits the correct shape. So a record built from the example
fails the shipped verifier. (3) Not a roadmap-gap — the verifier, PoW and conformance vectors
are implemented. (4) Not style — two normative statements in one document describe incompatible
wire shapes, and no caveat marks the example as historical. Severity corrected to medium rather
than higher: the impact is documentation-only, conformance vectors are the authoritative wire
reference and are correct, and a record built from the example is rejected rather than silently
accepted, so it fails safe. Separately noted out of scope: REGISTRY.md:292 pseudocode "if rec.op
!= RENEW and rec.powProof != null: reject UNEXPECTED_POW" would also reject the powProof
REGISTER requires.
```

## namespace-two-char-conformance-contradiction — MEDIUM

```text
Verified in HEAD at /workspace/vayuweb, both halves stand. (1) NAMESPACE.md:112 (§5.1) states
"An extension MUST be two to twelve characters. Two-letter extensions are permitted", with four
paragraphs explicitly withdrawing the earlier three-character floor. NAMESPACE.md:163 (§7
conformance item 2) in the same document states "A two-character extension proposal is
rejected." No other section reconciles them: §4 is the proposal path §5.1 governs, and the
permissive reading is what the rest of the corpus depends on — NAMESPACE-CATALOGUE.md:45 carries
a "## Two letters — *60 extensions*" section and NAMES.md:192 states the launch catalogue holds
1,267 extensions "including 60 two-letter extensions". So 60 catalogued extensions fail the
conformance list in the document that defines them. git log -S shows both lines entered in the
same commit (8647baf); CHANGELOG.md's [Unreleased] does not mention it, so it is neither an
already-fixed fossil nor pending. The implementation sides with §5.1: registry/src/names.ts:124
isWellShapedTld rejects only tld.length < 2, so it accepts two-character TLDs and would fail
conformance item 2 as written. (2) NAMES.md:44 ABNF `tld = %x61-7A *11( %x61-7A / %x30-39 )`
admits a 1-character TLD (letter, zero more), which NAMESPACE.md:112's two-character floor
forbids. The three constraints NAMES.md:47-57 marks as normative-but-not-in-the-ABNF all concern
labels, not the TLD, so nothing restores the floor. The cause is documented in the code itself:
registry/src/names.ts:11-18 records that the ABNF was widened from `2*12( %x61-7A )` to admit
digits for `.p2p`; the `2*` lower bound was lost in that rewrite. registry/src/names.test.ts:136
pins `!isWellShapedTld('a')`, i.e. the test encodes NAMESPACE.md's bound rather than the ABNF,
confirming the documents disagree and the code chose one. Not refutable as wording preference:
§7 is a conformance list, the most normative part of the document, and it inverts the rule
stated 51 lines above it. Not a not-yet-built feature: the rule is wire-visible and already
implemented and tested. Severity corrected to medium. Nothing is broken at runtime — the code
consistently implements the intended (permissive) reading — but this is a spec-first repo whose
Phase 0 open item is test vectors for every wire-visible rule and whose Phase 6 acceptance is an
independent implementation built from these documents alone. A second implementer following §7
item 2 literally would reject 60 catalogued extensions, which is a namespace fork — the exact
failure registry/src/names.ts's header comment warns about. The residual one-character ABNF gap
alone would be low; it rides along on the same edit. Fix is two lines: change §7 item 2 to "A
one-character extension proposal is rejected" (or drop it), and restore the lower bound in the
ABNF as `tld = %x61-7A 1*11( %x61-7A / %x30-39 )`.
```

## VWIP-0000-final-missing-sections — MEDIUM

```text
VERIFIED (core of the finding survives): 1. docs/spec/VWIP-0000.md line 7 does read `Status:
Final` (Type: Process, Created 2026-07-26). 2. Its `##` headings are exactly: Abstract,
Motivation, Specification, Security considerations, Privacy considerations, Rights-impact
analysis, Impossibility-and-capture analysis, Backwards compatibility, See also. No
Centralisation analysis, no Migration and rollback, no Activation epoch, no Expiry of
transitional mechanisms. 3. CONSTITUTION.md 42.4 (~2515-2524) is unconditional — "A VWIP MUST
NOT advance beyond Draft unless it contains all of the following sections" — and 42.4.h/i/j/k
are exactly those four. VWIP-0000's own §3 table (VWIP-0000.md:95-116) restates all four as
mandatory, so the document fails the list it itself publishes. 4. Corroborating, not
theoretical: VWIP-0001 and VWIP-0003 (both Draft) each carry the full set including
Centralisation analysis, Migration and rollback, Activation epoch, Expiry of transitional
mechanisms, Test vectors. Only the Final one lacks them. (VWIP-0002 also lacks Migration and
rollback — a separate, smaller instance of the same drift.) 5. No exemption exists. I read
Articles 41, 42, 44, 47, 20.3, 55.5 and 60 in full. Art. 60.5 lists transitional provisions
"exhaustively" (a–f: editorial panel, primitives Annex, key rotation, genesis record,
conformance suite, founding steward) and 60.6 says every transitional provision "SHALL be listed
in this Article and nowhere else". VWIP-0000-as-Final-at-publication is not among them, so it
cannot be defended as a listed bootstrap. Art. 42.7 also bites: no state transition is recorded
for VWIP-0000 anywhere, and "an unrecorded transition has not occurred". 6. Art. 44.1 ("No VWIP
SHALL reach Final without running code") is unqualified, while VWIP-0000 §6.1 narrows it to "No
*Standards Track* VWIP". VWIP-0000's Abstract concedes the tiebreak ("where this document and
the Constitution diverge, the Constitution governs and this document is defective") —
acknowledging the conflict, not curing it. Art. 20.3/47.6 (epoch strictly 180 days in the future
at Final) has no stated epoch here at all. 7. Not already fixed, not out-of-phase: CHANGELOG.md
has no entry on it; no CI job checks VWIP section sets (scripts/*.py and .github/workflows/*.yml
contain no VWIP-section lint); docs/ROADMAP.md:25 marks "VWIP-0000, the improvement process |
Complete". This is Phase 0 spec-settling work, the current phase. REFUTED (why the severity
drops): A. "Its own body contradicts its header status" is wrong. Line 27's `**Status:** Draft
against the pre-implementation design.` is repo-wide boilerplate, not a lifecycle declaration —
the same or near-identical line appears in 18 files (docs/GLOSSARY.md, FAQ.md, POSITION.md,
GOVERNANCE.md, SERVICES.md, LONGEVITY.md, THREAT-MODEL.md, spec/COST.md; "Draft — not yet
implemented" in PRIVACY.md, URI-SCHEME.md, PUBLISHING.md, CRYPTO-AGILITY.md, ATTESTATION.md,
LOCAL-SURFACE.md, CONTENT-SECURITY.md, NAMESPACE.md, NAMESPACE-CATALOGUE.md). Its own second
clause disambiguates: "The process is in force from publication; the protocol it governs has not
been built yet" — about the unbuilt protocol, not the VWIP's lifecycle state. Reusing the word
"Status:" inside a VWIP is an editorial collision at most. B. "Every downstream VWIP inherits an
ambiguous status" is unsupported. The only references are two "See also" bullets
(VWIP-0001.md:222, VWIP-0002.md:229) and three ordinary section citations in VWIP-0003 (:131,
:157, :225). None asserts or depends on VWIP-0000 being Final; all three are themselves Draft,
so nothing has been decided under the disputed authority. C. The Art. 8.4 "ultra vires" framing
overreaches. 8.4 concerns signature authority not being sufficient for validity; nothing here
has been executed against anyone — no records, no registrations, no retroactive effect. There is
also a defensible (though unstated) reading that VWIP-0000 is not a "change" under 41.1 but a
restatement of Title V, in force by 60.3/60.4 with the Constitution. The real defect is that the
repo never says so. SEVERITY corrected to medium: a real, precisely-locatable self-inconsistency
in the governing document set of a repo whose only current deliverable is documents, and the
first thing a hostile reviewer will lead with — but with no runtime or wire consequence, nothing
ratified under it, and a document-edit fix: either change the header to a bootstrap-appropriate
label (or Draft) and add the four sections, or add an explicit self-repealing transitional
provision under Art. 60.5 (60.6 forbids stating it anywhere else). A CI check asserting the 42.4
section set for every non-Draft VWIP would pin it.
```

## docs/spec/PROOF-OF-WORK.md:135,118 — MEDIUM

```text
Tried to refute this and could not; both arithmetic errors are real and are checkable against
the document's own stated figures. 1) /workspace/vayuweb/docs/spec/PROOF-OF-WORK.md:133-135
reads exactly as quoted: max reachable D is "**18 bits** — roughly 262,144 expected evaluations,
on the order of tens of minutes of CPU at 70 ms each." 2^18 = 262,144 is right; 262,144 x 0.070
s = 18,350 s = 5.10 hours, not tens of minutes. The 70 ms basis is not in doubt: the same file's
other worked figures all check out at 70 ms single-core (:154 4096 x 0.07 = 286.7 ~= "287 s";
:164 32 x 0.07 = 2.24 ~= "2.2 s"; :170 512 x 0.07 = 35.8 ~= "36 s"), so the file is internally
consistent everywhere except this sentence. The multi-core escape does not hold either: the
wording is "of CPU", the reference is defined at :143-145 as 70 ms "on one core", and the
normative parameters at :44-50 set parallelism p = 1 with :56 stating that choice makes a single
evaluation's cost independent of core count. 5.1 CPU-hours is 5.1 CPU-hours however it is
scheduled. 2) :118 reads "the schedule makes a two-character name cost 64 times a fifteen-
character name" against the schedule at :98-103 where L <= 2 gives base = 10 and L <= 15 gives
base = 5. 2^10 / 2^5 = 32, not 64. 64 is the ratio against a *sixteen*-character name (base =
4). This is confirmed by the implementation: registry/src/pow.ts:63-64 carries the same wrong
sentence in its doc comment, while registry/src/pow.test.ts:201-202 asserts `2 ** baseBits(2) /
2 ** baseBits(16) === 64` — i.e. the test that looks like it pins the claim actually pins a
different comparison (length 16, not 15), so it cannot catch the prose error. Either the number
should be 32 or the length should be "sixteen-character"; as written the two disagree. 3) The
supporting point at :227 also checks out — "The ceiling of twenty bits caps how far the network
can push back" survives in Limits, directly contradicting :133 "The ceiling does not currently
bind" / "Twenty bits is not reachable". Not already fixed: CHANGELOG.md:368-372 under
[Unreleased] documents the *previous* round's fix ("The documented 20-bit difficulty ceiling is
unreachable" — old text said "roughly a million evaluations, hours of CPU"), which is the edit
that produced the current sentence. Nothing in [Unreleased] or elsewhere corrects "tens of
minutes" or the 64x figure. Ironically the superseded wording ("hours of CPU") was closer to the
truth for 18 bits than its replacement. Severity corrected down to medium, not high/critical.
The 70 ms cost is explicitly flagged non-normative at :143-145 ("illustrative and is NOT
normative; only the parameters and `required_bits` are normative"), so no wire-visible rule,
verification outcome or interop behaviour is affected, and a second implementation built from
the normative pseudocode is unharmed. The real damage is calibration and trust: docs/COST.md
§2.1 requires the difficulty function be calibrated against low-end mobile hardware and warns
that a flow which appears to hang gets abandoned, and constitution Art. 7.5 targets one hour of
median-device work (cap 24 hours) — so the true worst case of ~5 CPU-hours already overshoots
the constitutional *target* while the prose tells a registrant to budget tens of minutes.
Compounding it: the 64x error is duplicated into shipped source comments (pow.ts, and the stale
dist/ copies), and the test that appears to pin it does not.
```

## implementation-omits-named-reserved-labels — MEDIUM

```text
VERIFIED — the core claim survives, but one piece of its supporting evidence is wrong and the
severity is overstated. What I checked: - /workspace/vayuweb/registry/src/names.ts:82-108.
`labelRejection` is the whole label validator, and its only reserved check is line 105 `if
(label.length <= 2) return 'RESERVED_LABEL';`. There is no table of named reserved labels in the
module. The file header (lines 4-7) does say "docs/spec/NAMES.md is authoritative. Nothing here
relaxes it, and where the specification and this module could disagree the specification wins" —
and lines 9-20 list two NAMES.md defects the author found and corrected in the spec, so the
module documents its divergences where it has them. It documents nothing about dropping the
named-label table. - /workspace/vayuweb/docs/spec/NAMES.md:63-77. The reserved table has seven
rows: the two length classes plus `www`, `localhost`, `example`/`invalid`/`test`, `vayu`, and
`control`/`api`/`resolver`/`proxy`/`pac`/`wpad`/`_vayu`. Line 65-67 is normative and quoted
accurately: "MUST be rejected by every peer, not merely ignored; an invalid operation never
becomes an ownership fact." - Executed the built module (registry/dist/src/names.js):
`nameRejection(l,'vayu')` returns `null` for www, localhost, example, invalid, test, vayu,
control, api, resolver, proxy, pac and wpad. Only `_vayu` is rejected, and incidentally —
`BAD_CHARACTER`, because `_` is outside the grammar, not because it is reserved. - The gap is
wire-visible, not confined to a helper: registry/src/record.ts:289 calls `labelRejection(name)`
and maps a non-null result to the `BAD_LABEL` rejection code, so a REGISTER record for
`wpad.vayu` passes schema validation. resolve.ts:218 and cli.ts:110 share the same validator.
Grep for `wpad`/`www`/`localhost` across registry/src, client, proxy and conformance returns
nothing outside node_modules, so no other layer re-adds the check. - conformance/vectors.json
has no reserved-label vector at all (no `RESERVED_LABEL` outcome, no named label), so a second
implementation would not be measured on this either way. - CHANGELOG.md `[Unreleased]` does not
mention it; not already fixed. Corrections to the finding as written: - The port sub-claim is
FALSE as stated. NAMES.md:77 places the control surface on `127.0.0.1:7653`; RESOLUTION.md:153
says "The control API on `127.0.0.1:7653` is JSON over HTTP" — the same port.
RESOLUTION.md:28/134 puts `7654` on the browsing *proxy*, a different listener, so there is no
contradiction between those two documents. The only real part is that LOCAL-SURFACE.md §1
(marked "Draft — not yet implemented", proposed by VWIP-0001) moves the control API off TCP
entirely, which makes NAMES.md's rationale stale — a stale justification in a table cell, not a
second defect. - Severity should be medium, not critical/high. The "state fork" consequence is
currently hypothetical: NAMES.md:6-8 states no part of the system is implemented and no name has
ever been registered; ROADMAP.md:13-35 has Phase 0 (spec settling and adversarial review) as the
current work and Phase 1 registry core still open; there is no network, no second
implementation, and no conformance vector covering it. And the claim is right that the fix is
not simply "add the table": Constitution Article 10.8 (constitution/CONSTITUTION.md:820) forbids
withholding "a string, a pattern or a length class from registration for later allocation",
which would make the table unconstitutional — and, note, makes names.ts:105's own length-class
reservation unconstitutional too, so the module is not cleanly on either side. What remains a
genuine defect: a module that asserts in its own header that nothing in it relaxes NAMES.md
silently relaxes twelve normative MUSTs, undocumented, in the code path that produces a wire-
visible rejection code. Whichever way the Article 10.8 conflict is settled, the current state —
code and spec disagreeing with no note anywhere — is the thing to fix.
```

## names-reserved-labels-unenforced — UNRATED

```text
I could not refute the core of this. Every substantive quote is accurate and the behaviour
reproduces. WHAT I VERIFIED 1. The spec quotes are correct.
`/workspace/vayuweb/docs/spec/NAMES.md:64-66` says reserved labels are "withheld in every TLD…
MUST be rejected by every peer, not merely ignored; an invalid operation never becomes an
ownership fact." The table at :70-79 lists `www`, `localhost`, `example`/`invalid`/`test`,
`vayu`, and `control`/`api`/`resolver`/`proxy`/`pac`/`wpad`/`_vayu` with the wpad proxy-hijack
rationale quoted verbatim. NAMES.md:204 says "Each extension has its own reserved-label set (the
common set above, plus anything its charter adds)", and :233 requires a new-TLD VWIP to specify
"its additional reserved labels" — so the rule is genuinely per-TLD. Critically, NAMES.md:57
makes this part of label validity, not a separate layer: constraint 3 under "Label grammar" is
"The label MUST NOT be a reserved label for that TLD (see below)." 2. The implementation gap is
real. `/workspace/vayuweb/registry/src/names.ts:82-108` — `labelRejection()` checks EMPTY,
TOO_LONG, BAD_CHARACTER, LEADING_HYPHEN, TRAILING_HYPHEN, RESERVED_IDN_SHAPE, then `if
(label.length <= 2) return 'RESERVED_LABEL'` (line 105) and returns null. There is no reserved-
word list anywhere in the repo: grepping `wpad|localhost|'www'|reserved` across `registry/`,
`client/`, `proxy/`, `conformance/` and `scripts/` returns only the one/two-char check, the IDN-
shape check, and test assertions for those two. `nameRejection(label, tld)` (line 141) receives
the TLD but uses it only for `isWellShapedTld`/`isRatifiedTld`, then delegates to
`labelRejection(label)` — the TLD is discarded before any reserved check could use it. 3.
Executed it. Against the built module, `nameRejection(x,'vayu')` returns `null` for `wpad`,
`localhost`, `www`, `vayu`, `pac`, `api`, `resolver`, `proxy`, `control`, `example`, `invalid`,
`test`. Only `_vayu` is refused, and incidentally — `BAD_CHARACTER`, because `_` is not in
`[a-z0-9-]`, not because it is reserved. 4. It is not caught at a higher layer. The only callers
of label validation are `record.ts:289` (`labelRejection(name)`, no TLD), `resolve.ts:218`
(same), and `cli.ts:110` (`assertValidName`). `verify.ts` performs no name check of its own. I
ran `parseRecord()` on a `wpad`/`vayu` REGISTER map and it passed the label gate, failing later
at `MISSING_POW` — the label was accepted. 5. Not deferred, not fixed. `registry/README.md`
lists "Label grammar and ratified TLD set (`src/names.ts`) | Implemented, tested", and this
shipped in the released 0.1.0 (`be2c2ab`). `CHANGELOG.md` contains zero occurrences of
"reserved". So this is not a roadmap-not-yet-built item — it is a normative MUST partially
implemented in a module marked complete. CORROBORATION I FOUND INDEPENDENTLY
`conformance/vectors.json` holds 40 vectors, two of them BAD_LABEL (`schema/uppercase-label`,
`schema/leading-hyphen`). There is no reserved-label vector at all — not even for the one/two-
character class that *is* implemented. Since ROADMAP Phase 0 makes the vector set the
interoperability contract, the reserved rule is unpinned in the only wire-visible artifact a
second implementer would test against. And `names.ts`'s own header states the consequence: "a
peer that accepts a name others reject has forked the namespace, which is indistinguishable from
a bug until someone loses a name over it." WHERE THE CLAIM IS OVERSTATED — two corrections (a)
The `1-63 bytes` point does not stand. NAMES.md's own Label grammar section says "A label is 1
to 63 characters" and its ABNF admits 1- and 2-character labels; reserved-ness is layered on as
constraint 3, not folded into the range. REGISTRY.md:48 says "1-63 bytes from `[a-z0-9-]`, per
docs/spec/NAMES.md" — it cites and matches NAMES.md rather than contradicting it. This is not an
independent defect and should be dropped. (b) "No rejection code for one" is half wrong.
REGISTRY.md:255 has `BAD_LABEL`, and `grammar_ok` is never defined in REGISTRY.md — it delegates
to NAMES.md, where reserved-ness sits inside the Label grammar section. An implementer enforcing
the table would naturally report BAD_LABEL, so the two peers would not disagree about error
strings. The substantive half is correct and is the real spec defect: `grammar_ok(rec.name)`
takes one argument and never receives `rec.tld`, so a per-TLD reserved set — which NAMES.md:204
and :233 explicitly require every extension to have — is structurally inexpressible in the
pseudocode as written. SEVERITY: high, not critical. The consequence the claim leads with (a
live proxy-auto-config hijack) is not reachable today: Phase 2 has not started, there is no
network, `registry/README.md` says "There is no network yet", and NAMES.md:8 states "no VayuWeb
name has ever been registered." Nothing can be squatted. What is real and serious is a consensus
rule: two conforming implementations disagree about whether `www.vayu`, `wpad.vayu` and
`vayu.vayu` are registrable, which is a namespace fork — disagreement about ownership facts,
exactly as the claim says and as names.ts's own comment predicts. That it ships in a released
version, in a module advertised as implementing this specification, with no conformance vector
to catch it, is what keeps it above medium. FIX SHAPE: add the common reserved set plus a per-
TLD extension hook to names.ts; thread `tld` through `labelRejection`/`record.ts`/`resolve.ts`;
change REGISTRY.md:255 to `grammar_ok(rec.name, rec.tld)`; add reserved-label conformance
vectors (including one for the one/two-char class, which is missing today even though the code
enforces it).
```

## names-transfer-vs-registry-transfer — UNRATED

```text
VERIFIED — quotes are accurate and nothing in the repo reconciles them. What I checked: 1.
`/workspace/vayuweb/docs/spec/NAMES.md:156-186` — the Transfer section reads exactly as quoted.
L158 "Transfer is a two-signature handover. It is never a single operation."; L160-162 an
`offer` operation with "exactly 14 days from the offer's `notBefore`"; L163-165 an `accept`
operation "signed by the offered key, referencing the offer by its hash", on which "`seq`
increments"; L177-178 offer supersession; L179 a lowercase `revoke` "at any time before
acceptance"; L180 "An `accept` MUST be rejected if the name is in GRACE". These are normative
(MUST/MAY), not narrative, and NAMES.md:5 puts "how ownership is handed between keys" inside its
own declared scope. 2. `/workspace/vayuweb/docs/spec/REGISTRY.md` — L47 closes `op` at six
values; L254 `if rec.op not in OPS: reject UNKNOWN_OP`; L185-193 makes TRANSFER a single record
whose `coSig` is "present and verifying against `ownerKey` over the same signing input", with
`notAfter == prev.notAfter` and immediate effect; L295-302 repeats it in the switch. There is no
offer hash field, no offer-expiry field, and no pending-offer state anywhere in the record
schema (L40-58), the index keyspace, or the verification pseudocode. Grepping the whole repo for
`offer`/`accept` returns no other spec occurrence — no reconciling section exists. 3. The two
flows are structurally incompatible, not two descriptions of one thing. REGISTRY.md's chain
rules (L138-141) require `seq == prev.seq + 1` on every non-REGISTER record, so NAMES.md's offer
— a record that appends but does not increment `seq`, with acceptance incrementing it later —
cannot be expressed at all. 4. Not already fixed. `registry/src/record.ts:27` ships `OPERATIONS
= ['REGISTER','UPDATE','RENEW','TRANSFER','RELEASE','REVOKE']` and `record.ts:286` fails
`UNKNOWN_OP` for anything else; `record.ts:358-361` and `verify.ts:266` implement the single-
record coSig transfer. `CHANGELOG.md` `[Unreleased]` and the last 15 commits mention no NAMES.md
transfer fix. `conformance/vectors.json` has no offer/accept vectors. 5. Not rescued by a higher
document — the opposite. Constitution Article 29.4 (L1882) makes the record types "a closed set"
that contains TRANSFER and neither offer nor accept, and requires an unrecognised type "MUST be
rejected rather than ignored". Article 33.2 (L2051-2053) explicitly refuses an "offer channel"
as a faculty within that closed set. The 14 days in NAMES.md also does not match Article 33.4
(L2059), which is a post-TRANSFER settlement delay, not an offer expiry — so NAMES.md is a third
variant, not an elaboration of the Constitution. 6. The `revoke` collision at NAMES.md:179 is
real and destructive: REGISTRY.md:203-215 makes REVOKE freeze the name for the rest of its term
plus 30 days quarantine, with "no recovery key and no appeal". An implementer mapping NAMES.md's
offer-cancellation onto the only spelled operation with that name destroys the name. Not
refutable as "not yet built": both files are normative Phase 0 deliverables marked "Complete
(draft)" in `docs/ROADMAP.md:20-21`, the registry core implementing REGISTRY.md's six ops is
already shipped, and ROADMAP.md:31-33 sets Phase 0's exit as "a competent implementer can read
the specifications alone… and produce a client that would interoperate" — which this
contradiction directly defeats. Severity: high, not critical. Nothing is deployed, no VayuWeb
name has ever been registered, the implemented path enforces the safer of the two (coSig, per
REGISTRY.md), and NAMES.md:10-13 defers record format and log semantics to REGISTRY.md, so a
careful implementer will hit the six-op table before shipping. What makes it high rather than
medium is that NAMES.md claims transfer in its own scope, states it in RFC 2119 terms, invents
registry state (open-offer tracking, offer supersession, a 14-day offer clock) that exists in no
schema or index, and reuses `revoke` for a non-destructive act that the spelled operation makes
permanent.
```

## names-tld-sunset-vs-registry-register-renew — UNRATED

```text
Verified against the files; the core survives, but one of the three claimed consequences is
wrong and the severity was overstated. WHAT I CONFIRMED (every citation is accurate, verbatim):
- /workspace/vayuweb/docs/spec/NAMES.md:260-263 — successor label "is reserved for that name's
`ownerKey` for the full 24 months, claimable by a signed registration with no proof-of-work." -
REGISTRY.md:55 (`powProof` REQUIRED for REGISTER), :147 (REGISTER precondition "`powProof`
present"), :275 (`if not pow_ok(...): reject BAD_POW`, unconditional inside the REGISTER
branch). There is no sunset/successor exemption anywhere in REGISTRY.md — I grepped the whole
repo for retire/sunset/successor and REGISTRY.md never mentions any of them. PROOF-OF-
WORK.md:95-114 makes it worse: `required_bits` bottoms out at `base = 4`, so difficulty can
never be 0 either. A "signed registration with no proof-of-work" is unrepresentable at schema
level, at verify() level, and at difficulty level. - The reservation has no rule anywhere.
verify() takes the successor label as FREE, and first-valid-signature-wins with no dispute
process (Constitution Art. 36) means a watcher who registers `label.successorTLD` the second the
VWIP ratifies simply owns it. The claim's phrasing "no representation in any of the four index
keyspaces" is slightly loose — the fact is *derivable* (keyspace `n` gives `label.retiringTLD`
-> current record -> ownerKey), so a rule could be written — but no such rule exists, which is
the point that matters. - NAMES.md:264-266 (renewal invalid without an `alias`) vs
REGISTRY.md:76-77 (alias must not coexist with another entry) and :296-299 (RENEW requires
powProof, window, notAfter, pow_ok — no alias). Confirmed in the shipped code too:
registry/src/record.ts:321 rejects alias+peer as BAD_RECORD_ENTRY, and
registry/src/verify.ts:245-262 has no alias requirement and no MISSING_ALIAS code. WHAT I
REFUTED — the stranding consequence: "a holder who does renew during the sunset must drop every
peer/ipns/cid entry ... taking their site down" is wrong. That is the design working, not a
strand: NAMES.md:266 says "Resolvers MUST follow the alias", RESOLUTION.md:86-87 restarts
resolution at the alias target within a 3-hop budget, and resolve.ts:260-266 implements it. A
holder who has claimed the successor name keeps serving; the retiring name becomes a pointer,
which is exactly what "a name is either a pointer or a destination" intends. Only a holder who
has not yet claimed the successor sees a dangling alias, and that is a sequencing choice, not a
spec defect. Also overstated: "A retirement VWIP cannot be executed." The PoW prong is a promise
the spec cannot keep, not a blocker — a holder can claim the successor with an ordinary proof
(4-18 bits). The blocker is the reservation, not the PoW. WHAT NOBODY MENTIONED, AND IT CHANGES
THE FIX: the retirement section also collides with the Constitution, which NAMES.md:240-243
itself makes the governing source. constitution/CONSTITUTION.md:2157 (35.8) "there SHALL be no
reserved-name list, no sunrise period and no pre-allocation to anyone"; :822 (10.8) "Reserved
names are forbidden. No implementation, no VWIP and no amendment SHALL withhold a string ... for
later allocation"; :2165 (35.10) TLD-RETIRE requires no live names or a migration path "open for
not less than five years", against NAMES.md's 24 months; :2161 (35.9) and :827 (10.9) require
names in a closed TLD to keep resolving/renewing "indefinitely" and "on their original terms",
against NAMES.md:269-272 "Holders who never claim their successor name lose it at month 24." So
the repair is not "add reservation machinery to REGISTRY.md" — that machinery is prohibited. The
section needs rewriting toward TLD-FREEZE (35.9), which the registry can already express. NOT
already fixed, NOT out of scope: CHANGELOG's [Unreleased] covers merkle/checkpoint, resolution,
convergence — nothing here. docs/ROADMAP.md:28 makes "Independent adversarial review" the
current open Phase 0 item and :31-33 sets the done-criterion as an implementer producing an
interoperating client from the specs alone (Art. 44.6), which is precisely what this
contradiction defeats. SEVERITY: medium, not critical/high. Everything is Draft and pre-
implementation (both docs carry "Status: Draft — not yet implemented"), no TLD can be retired
before Phase 0 closes, the alias-strand consequence is wrong, and the PoW prong is a broken
promise rather than a hard block. What earns medium is the reservation: a MUST-level, wire-
visible guarantee to holders that no verifier in the spec can enforce, in a system with no
appeal — and the fact that the obvious repair is itself unconstitutional.
```

## registry-epochs-checkpoint-conjunction — UNRATED

```text
SURVIVES, but with two of its three consequences refuted and severity corrected down to medium.
VERIFIED (quotes accurate, line numbers drifted ~39 lines): -
/workspace/vayuweb/docs/spec/REGISTRY.md:465-470 — "An epoch boundary is crossed when **both**
of the following hold: 1. at least 2,592,000 seconds (30 days) ... and 2. at least one
checkpoint has been computed since that boundary." (claim cited 426-431) - REGISTRY.md:472-476 —
"Requiring both conditions is deliberate. Time alone would let a peer with a wrong or hostile
clock disagree ... Log progress alone would stall the epoch counter whenever registration
activity dropped ... Taking the median notBefore of a thousand records makes a single lying
clock irrelevant" (claim cited 433-436) - REGISTRY.md:401 — "Every 10,000 entries a node SHALL
compute a checkpoint" (claim cited 401, correct) - REGISTRY.md:483-486 — "MUST be at least two
epochs beyond the epoch in which the VWIP reached Accepted — roughly sixty days minimum ...
Article 47.3 forbids a silent breaking change; this is the interval that makes the prohibition
operable." (claim cited 445-447) - PROOF-OF-WORK.md:111 `if n < 512: rate = 0` (claim cited
110); REGISTRY.md:545 "roughly a million names" (claim cited 506). THE LOGIC HOLDS. The
rationale paragraph names two failure modes of the two conjuncts and then rescues only one of
them: the third sentence (median notBefore) answers the clock hazard of condition 1; nothing
answers the stall of condition 2, and a conjunction is at least as restrictive as either
conjunct, so requiring both preserves that stall rather than removing it. I looked for an escape
and found none. REGISTRY.md:401 is the only checkpoint trigger in the corpus, and the
deterministic reading is forced by REGISTRY.md:482 ("derived from the log, identically by every
peer") — a discretionary checkpoint would make the epoch number peer-dependent. The code agrees:
registry/src/checkpoint.ts `isCheckpointLength()` returns true only at `logLength % 10_000 ===
0`. REGISTRY.md:18 fixes "one record per entry", so 10,000 entries means 10,000 name operations,
not log blocks. SCALE CHECK CONFIRMS THE MAGNITUDE. There are eleven launch TLDs
(REGISTRY.md:49, NAMES.md:208, PROOF-OF-WORK.md:241). At the PoW schedule's own threshold where
difficulty has not yet begun to rise (512 registrations per TLD per 30 days), the entire
namespace produces 5,632 entries per 30 days — roughly half of one checkpoint. So a registry
operating at a level the PoW spec treats as unremarkable cannot cross an epoch boundary in 30
days. The bootstrap case is sharper: at genesis the log holds zero checkpoints, so Epoch 0
cannot end before the 10,000th entry ever appended, with no bound on when that arrives.
CORROBORATION (separate from the claim, but it shows the section is unsettled): Constitution
Art. 2.5 requires an Epoch to be "a fixed, deterministic interval", "MUST NOT be shorter than
one day nor longer than fourteen days", and "MUST NOT be settable, adjustable or announced by
any party at run time". REGISTRY.md's epoch is >=30 days and activity-variable, which conflicts
with a document that Art. 3.7 ranks above the spec. Art. 47.6 also sets a 180-day floor that
REGISTRY.md's 60 days does not reach. REFUTED SUB-CLAIMS — the finding is narrower than stated:
1. "The 'roughly sixty days minimum' is false for any registry below 10,000 entries per 30
days." Wrong. It is stated as a floor, and condition 1 guarantees every epoch is at least 30
days, so two epochs is always at least 60 days. A slow checkpoint clock makes the real interval
longer, never shorter, so the floor holds. The defect is that the gloss is presented as a
realistic planning figure with no upper bound stated — an understatement, not a falsehood. 2.
"Condition 1 is undefined for the first 1,000 entries, so peers cannot agree on when Epoch 0
ends." Moot, and self-refuting given condition 2: no boundary can be crossed until logLength
reaches 10,000, at which point at least 1,000 accepted records exist, so the median-of-1,000
window is always populated at any instant the boundary test can pass. This sub-claim adds
nothing. 3. "The epoch counter freezes and every Standards Track VWIP never activates." Over-
strong. Only a registry with permanently zero growth freezes forever; otherwise the advance is
unbounded-but-finite. The accurate statement is that epoch advance is gated on cumulative
registration volume with no time-based floor, so activation dates are unpredictable and can
exceed the stated 60 days by an arbitrary factor — most acutely at launch, which is when the
protocol most needs to ship changes. VWIP-0002:212 does schedule itself "at least two epochs
beyond" this definition, so a live proposal is exposed to it. NOT ALREADY FIXED: no CHANGELOG.md
entry mentions epochs (grep -i epoch on CHANGELOG returns nothing), and no epoch counter exists
in code — every `epoch` hit in registry/src is PoW's unrelated 1-hour difficulty window
(pow.ts:53-54). "Not yet built" is not a defence here: REGISTRY.md is Draft, but the Epochs
section is normative MUST text and settling the spec is the current Phase 0 deliverable.
SEVERITY: medium, not high/critical. It is a real defect in a governance-critical mechanism,
verified in the text rather than inferred, but nothing is implemented against it, the failure
direction is delay rather than a security break, and the claim's headline consequences (a false
60-day figure, an undefined Epoch 0) do not hold. The fix is small and belongs in the same
section: add a time-based checkpoint trigger, or replace condition 2 with a log-length floor
that is reachable at launch scale, and reconcile the epoch length with Constitution Art. 2.5's
1-to-14-day bound and Art. 47.6's 180-day floor.
```

## pow-64x-ratio — LOW

```text
Confirmed, could not refute. PROOF-OF-WORK.md:98-104 gives base=10 for L<=2 and base=5 for the
branch containing L=15 (base=4 only starts at L=16); PROOF-OF-WORK.md:85 defines expected work
as 2^D. So the two-character vs fifteen-character gap is five bits = 32x, not the 64x asserted
at PROOF-OF-WORK.md:117-118 and repeated verbatim in registry/src/pow.ts:63-65 (and in the
generated typings registry/dist/src/pow.d.ts:50). The rate term is added identically to both
labels (pow.ts:83-90) and the min(20,...) ceiling never binds (the doc pins the real max at 18
bits, lines 133-139), so no later section rescues the number. The decisive evidence that this is
an error rather than a reading dispute is the repo's own test at
registry/src/pow.test.ts:200-202, which asserts 2**baseBits(2) / 2**baseBits(16) === 64 — the
64x figure is correct for a SIXTEEN-character label, and the prose misattributes it to a
fifteen-character one. Not already fixed: CHANGELOG.md [Unreleased] has no such entry and git
log on both files shows no correction. SEVERITY LOWERED to low: the error lives only in
narrative prose and a docstring — the normative pseudocode, baseBits, requiredBits, tests and
conformance vectors are all correct, so there is no behavioural, wire-visible or interop
consequence. It is further blunted by NAMES.md:72 and names.test.ts:101, which withhold every
two-character label from registration pending an allocation VWIP, so the overstated deterrent
applies to a length nobody can currently register. Fix is one word (fifteen -> sixteen) or
restating as 32x, in PROOF-OF-WORK.md:118, registry/src/pow.ts:64, and the regenerated dist
typings.
```

## resolution-control-api-tcp-vs-unix-socket — UNRATED

```text
I tried to refute this and could not. Every quotation is accurate and the contradiction is
intra-document and normative. VERIFIED IN SOURCE (/workspace/vayuweb/docs/spec/RESOLUTION.md): -
L24-30 "A resolver SHALL expose exactly two listeners, and **only one of them is a network
listener**", with the table row `<runtime-dir>/vayuweb.sock control API`. - L38-41 "The control
API is served over a **Unix domain socket (or a named pipe on Windows)** ... It MUST NOT listen
on TCP, on any address, including loopback — not even opt-in, not even for development." - L47
declares LOCAL-SURFACE.md normative. - L153, section "## The control API": "The control API on
`127.0.0.1:7653` is JSON over HTTP." Quoted exactly. `127.0.0.1:7653` is a TCP loopback address,
so this section directly instantiates the thing L40 forbids on any address including loopback. -
L180-184 compounds it: the CORS-preflight rationale "so no browser page ... can reach these
endpoints even if it learns the port" is a defence that only has meaning for a TCP port, and it
is offered as the reason the surface is safe — i.e. the document argues the TCP design is
adequately defended in the same file where it says TCP is forbidden. - LOCAL-SURFACE.md L14-16
and its §6 conformance items 1 and 2 (L161-163) read exactly as quoted, so an implementer
following RESOLUTION.md's "The control API" section fails a documented conformance item.
REFUTATIONS I TESTED AND REJECTED: 1. Already fixed? No. `git blame` puts L24-47 and L153 in the
same boundary commit (8647baf) — this is not a half-applied migration, both readings have
coexisted since the file was written. CHANGELOG `[Unreleased]` → Fixed contains an entry for a
structurally identical defect in the same file (commit 047d969, "RESOLUTION.md required the
resolver to emit the fingerprint it forbids" — four normative statements contradicting the
default-off rule) and that pass did not touch the control-API transport text. Nothing in
`[Unreleased]` or `[0.1.0]` addresses it. 2. Reconciled elsewhere? No. There is no text anywhere
saying which statement wins, no "the port is retained as an identifier only", no deprecation
note. Grep for `vayuweb.sock` / "Unix domain socket" returns only RESOLUTION.md L29/38/45,
LOCAL-SURFACE.md L14/22 and CHANGELOG L268 — the socket rule is never restated in the "The
control API" section that an implementer would actually build from. 3. Style/wording rather than
defect? No. Both statements are normative in a document whose own preamble invokes RFC 2119, and
they specify the wire-visible transport of a listener — exactly the class of thing ROADMAP Phase
0 says must settle before code, and exactly the class the project's own CHANGELOG treats as a
fix ("Two normative documents disagreeing about a wire format is a fork on its own"). 4. Caught
by a gate? No. `scripts/check-headers.py` and `check-counts.py` cover canonical header values
and TLD enumerations; nothing in `scripts/` or `.github/workflows/` references 7653/7654 or the
socket, so no CI job detects the divergence. ONE CORRECTION TO THE CLAIM'S FRAMING: the "echoes"
it cites are non-normative design prose, not additional normative conflicts — but they do
confirm the TCP reading has propagated, and ARCHITECTURE.md L84 is worse than an echo, since it
supplies an affirmative rationale for the forbidden design ("Two ports, not one, so that the
control API can be firewalled or disabled without disabling resolution"), and L208 restates it
with SHALL. WHITEPAPER.md L163 draws it into the architecture diagram. SEVERITY: high, not
critical. The consequence is real and correctly described, but it is prospective, not live:
RESOLUTION.md L10 says "Nothing described here has been implemented", ROADMAP Phase 3 records
"The proxy, the control API and the browser integration remain", and `proxy/` is a placeholder —
so no vulnerable listener exists today and nothing is exploitable now. The correct rule is also
stated three times against the wrong one's once, which gives a careful implementer a fighting
chance. What keeps it at high rather than medium is that it is a normative self-contradiction
about the transport of the privileged surface, in the section titled "The control API" that an
implementer builds from, on the decision LOCAL-SURFACE.md L18 calls "the single highest-value
hardening decision in the whole design" — and the project's stated Phase 0 discipline is that
this must be settled before any code is written. FIX: rewrite RESOLUTION.md L153 to name the
socket path rather than `127.0.0.1:7653`, and rework L180-184 so the `Origin`/`X-VayuWeb-
Control` rules read as defence-in-depth rather than as the primary browser defence (the "even if
it learns the port" rationale is false once the surface is off TCP). ARCHITECTURE.md
L84/L104/L208, WHITEPAPER.md L143-144/L163, GLOSSARY.md L47, ROADMAP.md L85 and the NAMES.md L77
rationale need the same correction, and a `check-*.py` gate asserting no document places the
control API on a TCP address would stop it recurring — the same remedy pattern already used for
the TLD-count defect.
```

## resolution-step8-release-revoke-lifecycle — UNRATED

```text
VERIFIED — the finding survives, but two of its stated consequences are wrong and the severity
is lower than the framing implies. What I checked, and what is true: 1. The quoted text is
accurate. RESOLUTION.md:77-79 does say "Compare now against `notBefore` and `notAfter`. An
unexpired record proceeds; a record in grace or quarantine returns 1410 `NAME_EXPIRED` or 1409
`NAME_QUARANTINED`". NAMES.md:136 does define GRACE purely as `notAfter <= now < notAfter + 30
days`. REGISTRY.md:195-202 (RELEASE) does say "Grace is skipped" with `notAfter == notBefore`,
and REGISTRY.md:204-211 (REVOKE) does say "stops resolving at once" with `notAfter ==
prev.notAfter` and empty `records`. 2. The two timestamps genuinely are insufficient. A RELEASE
record has `notAfter == notBefore`, so NAMES.md's own GRACE formula puts it in GRACE for 30 days
(→1410/410) while REGISTRY.md and NAMES.md:150-152 prose put it in QUARANTINE for 30 days
(→1409/409). A REVOKE record has `notBefore <= now < notAfter`, so step 8 read literally says
"unexpired record proceeds" — it reaches step 9, `records` is empty by precondition, and 1421
NO_USABLE_RECORD is exactly what falls out. The claim's derivation is correct. 3. The reference
implementation confirms the two fields are not enough: `registry/src/lifecycle.ts`
`lifecycleOf()` branches on `record.op` — RELEASE sets `graceUntil = notAfter` (grace
collapsed), REVOKE sets `liveUntil = notBefore` and `graceUntil = notAfter`.
`registry/src/resolve.ts:243-251` then maps `stateAt()`, not raw timestamps, to the error. So
the shipped resolver is correct; the spec text an outside implementer must work from is not.
Article 44.6 / ROADMAP Phase 0's "done when" is precisely "read the specifications alone… and
produce a client that would interoperate", and Phase 0's open item is the adversarial spec
review, so this is in scope, not a not-yet-built feature. 4. Nothing pins it.
`conformance/vectors.json` has 40 vectors, all record-acceptance; `lifecycle/release-expires-
immediately` and `authority/revoked-name-accepts-nothing` test verifier verdicts, not resolve
codes. ROADMAP states outright that "resolution" has no vectors. CHANGELOG has no entry fixing
RESOLUTION.md step 8. `revoke`/revocation appears nowhere in RESOLUTION.md and no catalogue row
(RESOLUTION.md:340-358) names it; NAMES.md's only "revoke" (line 179) is the unrelated transfer-
offer revoke, so its Lifecycle section has no REVOKE state at all. Corrections to the claim as
written: - "different negative-cache TTL" is FALSE. RESOLUTION.md:231 assigns `NAME_EXPIRED` and
`NAME_QUARANTINED` the same 60 seconds. The divergence is the numbered code and the HTTP status
(409 vs 410) only. - "surfaces as 1421" is what the spec text yields, but it is not what the
reference implementation does — resolve.ts returns 1410 NAME_EXPIRED for a revoked name (via the
GRACE mapping). So no code is broken today; the defect is that the wire-visible value is
unspecified, and a second implementer following RESOLUTION.md literally would return 1421 while
this one returns 1410. - No security consequence: under every reading a released or revoked name
serves no content (`records` is empty by precondition), so the worst case is a wrong error code
and a misleading message, not revoked content being served. Severity: medium, not high/critical
— a spec-only interop gap on error codes, in a document explicitly marked Draft/unimplemented,
with the reference implementation already behaving correctly. The fix is small and belongs in
RESOLUTION.md: make step 8 consult the lifecycle state as defined by `op` (citing lifecycleOf's
rules) rather than the two timestamps, and add a catalogue row for a revoked name (or state
explicitly that revocation maps to 1410).
```

## resolution-step1-vs-local-surface-host-normalisation — UNRATED

```text
SURVIVES, but the severity framing is overstated. I could not refute it; I found corroborating
evidence the claim did not cite. What I verified in the text (all quotes are accurate,
verbatim): - /workspace/vayuweb/docs/spec/LOCAL-SURFACE.md:66-69 (§2.1) — "Any other `Host` — an
IP literal, `localhost`, `127.0.0.1`, a clearnet name, an empty value, or a value with a port —
MUST be rejected before routing." - LOCAL-SURFACE.md:109-112 (§3.2) — "The resolver normalises
to NFC, lowercases, strips a trailing dot and any port, and **rejects** rather than repairs
anything that does not then match the grammar." The "does not THEN match" ordering makes this
repair-then-check, i.e. normalise-and-accept, which is the opposite of §2.1 for the port case.
It is not reconcilable as belt-and-braces: if §2.1 rejects first, the port-strip in §3.2 is
unreachable, yet it is written as part of the live normalisation pipeline. -
/workspace/vayuweb/docs/spec/RESOLUTION.md:54-57 (step 1) — "Split the host into label and TLD
at the last dot. Reject a host with more than two dot-separated components". No trailing dot, no
port, and no numbered code. Step 1 is the ONLY rejecting step in the ordered normative list that
names no code — steps 3, 4, 7, 8, 9, 10, 11, 12 and 13 all cite one (1403, 1400, 1502,
1410/1409/1404, 1421, 1505/1508, 1504/1408, 1512, 1414). - Under step 1 as literally written,
`example.vayu.` splits into three dot-separated components and is rejected; §3.2 would strip the
dot, match the grammar and serve it. And `example.vayu:8080` split "at the last dot" yields tld
`vayu:8080`, which is not in the launch set, so step 1 yields 1403 TLD_UNKNOWN — a THIRD
outcome, distinct from both §2.1 (reject, code unnamed) and §3.2 (strip and serve 200). The
evidence the claim missed, which is what makes this concrete rather than theoretical — the
divergence has already happened inside this repo.
/workspace/vayuweb/registry/src/resolve.ts:146-153 implements step 1 as `const bare =
host.replace(/:\d+$/, '').toLowerCase();` then rejects any split that is not exactly 2 parts. I
ran it: `example.vayu:8080` -> `{label:'example',tld:'vayu'}` (accepted, served),
`example.vayu.` -> `null` (LABEL_INVALID/1400). So the one existing implementation follows §3.2
for the port and §2.1/step-1 for the trailing dot — each of the two spec statements is
contradicted by the implementation, in opposite directions. resolve.test.ts:77 pins the port
behaviour as correct ("port stripped"), so the §2.1 MUST is currently contradicted by a passing
test. Third document, which settles the intended direction rather than refuting the finding:
URI-SCHEME.md §2.2 ("A `vayu://` URI MUST NOT contain a port... MUST be rejected, not ignored"),
§2.5 ("Uppercase in the authority MUST be rejected rather than case-folded. Silent normalisation
means two different strings display differently and resolve identically, which is a confusion
surface"), and its conformance item 1 requiring port/uppercase to be "rejected with a distinct
error, not normalised, not ignored". That governs the `vayu://` scheme rather than the proxy's
Host header, so it does not resolve the proxy-path ambiguity on its own, but it makes LOCAL-
SURFACE §3.2 the outlier of three documents and shows the fix direction: drop "and any port"
(and decide the trailing dot) in §3.2, and give step 1 an explicit code. Note that §3.2's
lowercase clause has the same problem against §2.5 — the implementation lowercases the Host too.
Not already fixed and not out-of-scope: CHANGELOG.md `[Unreleased]` records no host-
parsing/spec-reconciliation entry; ROADMAP.md Phase 0 lists "Independent adversarial review" as
"Open — this is the current work" and resolution test vectors as absent ("replication,
convergence and resolution have none"). This is exactly the class of defect that phase exists to
find, and it fails Phase 0's stated acceptance test (Article 44.6: read the specs alone and
produce a client that interoperates). Severity correction — MEDIUM, not high/critical. The
claimed consequence "the disagreement is in the exact place the cache-poisoning defence lives"
overstates it. Conformance item 7 ("two spellings of one name produce one cache entry") is not
actually threatened: under every reading the key is the post-normalisation `(label, tld)` tuple,
so a stripping resolver and a rejecting resolver each still produce at most one entry per name —
the disagreement is over whether to accept the request at all and which numbered code to return,
not over the key. There is also no live exploit: both specs are marked Draft/not-yet-
implemented, and no second implementation exists. What is real is a wire-visible interop
divergence (200 vs 1400 vs 1403 for two ordinary URLs) plus an unnamed error code in a normative
ordered algorithm — a genuine Phase-0 blocker, worth fixing before the vector set is written,
but not a security hole.
```

## arch-resolution-ttl-status-contradiction — LOW

```text
Partly confirmed, partly refuted; severity overstated. VERIFIED VERBATIM:
ARCHITECTURE.md:174-175 says the proxy "caches the IPNS-to-CID mapping for 300 seconds - cheap
page loads, updates visible within five minutes"; RESOLUTION.md:221-223 says "IPNS pointer
cache: min(record validity, 120 seconds). This is the mutable path, and a publisher updating a
site expects it live in about two minutes." Same cache, two defaults, two mutually exclusive
rationales. No other section reconciles them (RESOLUTION.md:218 separately gives the RECORD
cache 300s, so the 300 is not a mislabelled reference to that - ARCHITECTURE names the IPNS-to-
CID mapping specifically). Not fixed: no CHANGELOG entry mentions IPNS or TTLs, and proxy/
contains only a README, so no cache code exists. Drift rather than deliberate simplification:
ARCHITECTURE mirrors every other spec constant exactly (3-hop alias budget at :172, 300s clock
skew at :196 matching REGISTRY.md:155, 4 KiB / 32-entry caps). REFUTED - the status-code half.
ARCHITECTURE.md:186-187 states "Status pages and the control API surface are normative in
RESOLUTION.md", and step 4's output IS a status page, so the "404 or 410" line is explicitly
ceded to RESOLUTION.md rather than competing with it. The claim's argument that this scoping is
too narrow does not hold. It is also already settled in code: registry/src/resolve.ts:42 has
NAME_QUARANTINED: { code: 1409, http: 409 }, matching RESOLUTION.md:344 and :78-79. Nothing is
at risk of being built to 410 for quarantine. SEVERITY CORRECTED to low. The claimed consequence
("a resolver built from which document") overstates it: ARCHITECTURE.md:107 names docs/spec/ as
"the normative specifications", the [0.1.0] release notes state that where code and the
specifications disagree the specifications win, and Phase 3 (the resolution proxy, where the
cache lives) is unbuilt. What remains is a wrong default and a wrong rationale in a non-
normative overview, fixable by editing one number and one clause at ARCHITECTURE.md:174-175
during Phase 0's open adversarial review. Worth fixing; not a fork risk and not comparable to
the two-normative-documents wire-format conflict recorded in CHANGELOG.md:343.
```

## uri-scheme-s7-origin-isolation-self-comparison — LOW

```text
Could not refute the text. docs/spec/URI-SCHEME.md:191 reads verbatim "2. `vayu://a.vayu` and
`vayu://a.vayu` do not share storage, permissions or scripting access." — the two authorities
are byte-identical, so the quote is accurate. Against §3.1 (origin is the tuple ("vayu", label
"." tld), no port) and §3.2 at lines 77-79 (which gives the intended pairs a.vayu/b.vayu and
a.vayu/a.shop), the §7 item asserts that one origin does not share with itself, which is the
negation of the model and unsatisfiable. Not already fixed: git log on the file shows the last
commit was the no-CLA correction, and CHANGELOG.md has no URI-SCHEME §7 entry — the "duplicated
.vayu" Fixed entry at line 124 is the charter TLD list, a different issue. `a.vayu` occurs only
at lines 77, 78, 191; nothing elsewhere in the doc restates §7.2 correctly. However the claimed
consequence is overstated. conformance/vectors.json declares "generatedFor":
"docs/spec/REGISTRY.md" and contains no origin-isolation or URI-scheme vectors;
conformance/README.md never mentions origins; and per VWIP-0003 §4.3 (echoed in CHANGELOG ~397)
no conformance is claimed for areas without vectors. So no implementation is deriving a test
from this list today, and the cross-implementation divergence outcome is not currently
reachable. The safety property itself is stated correctly and unambiguously 114 lines earlier
with both example pairs, so the correction is a single token (b.vayu) and self-evident to any
reader. Real but editorial-to-low, not an origin-isolation/data-leak-grade defect. Fix: line 191
second authority to `vayu://b.vayu`, optionally adding `vayu://a.shop` to mirror §3.2.
```

## privacy-md-secret-storage-contradiction — UNRATED

```text
I tried to refute this and could not, for the control-API token half of it. What I verified in
/workspace/vayuweb: 1. PRIVACY.md:191-197 (§7 Memory hygiene) names the artefact explicitly —
"Secret material — Ed25519 private keys, the content-cache key, the control-API token — MUST be:
... 4. Never written to disk except in the platform keystore, per Constitution Article 6." There
is no "where a keystore is available" qualifier anywhere in §7, and no fallback clause elsewhere
in PRIVACY.md (I read the whole file, §§1-11). 2. PRIVACY.md:116 (§4 disk inventory) — "|
Control-API bearer token | On disk, mode `0600` | Memory only, regenerated per run |". The table
cannot be read as keystore-agnostic, because the row directly above it (PRIVACY.md:114, content
cache) *does* say "with a key held in the OS keychain". The same table therefore distinguishes
keystore-held from plain-file, and puts the token in the plain-file column. 3. The conflict is
not confined to the table, which is the strongest possible refutation angle and it fails.
RESOLUTION.md:154-158 is ordinary normative prose, not an inventory row: the token is "generated
at first run, stored in the resolver's config directory with mode `0600`, and compared in
constant time... MUST regenerate it if the file is missing." That mandates a file on disk
outside any keystore, in a document PRIVACY.md itself lists under "See also" as normative for
the proxy's privacy obligations. 4. LOCAL-SURFACE.md:152-155 (§5.2) confirms the file is the
assumed norm and the keystore the optional extra: "Any process running as the reader can read a
`0600` file owned by that reader... Mitigated by keeping the token in the platform keystore
where one is available." "Where one is available" is precisely the discretion §7.4 forbids. So
two RFC 2119 MUST-level statements about the same named artefact specify different storage. An
implementer reading §7 stores the token in the OS keychain only; one reading §4 + RESOLUTION
writes a 0600 file. Both are conformant to the text they read, and PRIVACY.md §4's own framing
("Every file the resolver may create, and the rule governing it") means one of them is creating
a file the other says must not exist. Refutations I checked and rejected: - Already fixed: no.
`grep` over CHANGELOG.md finds no mention of keystore/keychain/bearer/0600, and `git log`
(through 99dfe25) shows no commit touching this. The two recent spec-fix commits (047d969,
ae3af05) are unrelated. - Not yet built: not a refutation here. Both files carry "Status: Draft
— not yet implemented", and ROADMAP Phase 0's open item is the adversarial spec review plus test
vectors, with the roadmap's own rule that implementation waits on the spec settling. A
contradiction between two mandatory clauses is exactly the Phase 0 deliverable, not a premature
finding. - Style/wording: no. This is not a phrasing preference; the two clauses name different
storage locations for an authentication credential and only one can be implemented. - "The
keystore is on disk too, so 0600 satisfies both": defeated by RESOLUTION.md:155 pinning it to
"the resolver's config directory" and by LOCAL-SURFACE.md §5.2 treating file-vs-keystore as a
choice with a security delta. Where the claim overreaches, and why I lowered severity: - The
Ed25519 half is weak. The evidence offered for it is PRIVACY.md:126, the libp2p PeerID keypair
row, but the table never calls that key Ed25519, and it is a node-identity key, not the
ownership key §7 is most naturally read against. The actual Ed25519 secret key is handled
consistently elsewhere: ARCHITECTURE.md:217-223 puts it in the OS keychain and specifies an
explicit fallback (Argon2id-encrypted file, 256 MiB / 3 iterations / 1 lane) where no Secret
Service exists, and THREAT-MODEL.md:52 agrees. So the finding is really about one artefact, the
control-API token, not two. - The consequence is narrower than stated. LOCAL-SURFACE.md §5.2
already concedes that a same-user process reading a 0600 file is an OS boundary VayuWeb cannot
enforce, and a same-user process can equally open the 0600 control socket; the keystore's
benefit is real but incremental (per-app scoping/prompting on some platforms), not the
difference between safe and compromised. The token is also not a reading record, so the forensic
adversary of §1 learns only that VayuWeb is installed — which the registry log already discloses
by design (PRIVACY.md:130-132). The "not interchangeable for tooling" point is partly true but
the spec does not name a token filename or format anyway, so tooling interop is underspecified
independently of this. Net: a genuine, unambiguous normative contradiction across three specs on
one named credential, worth fixing before any code is written — §7.4 should carry the same
"where a platform keystore is available, otherwise <named fallback>" construction
ARCHITECTURE.md:217 already uses, and RESOLUTION.md:155 and LOCAL-SURFACE.md §5.2 should be
brought into line with whichever way it settles. Medium, not high: it is a spec defect with a
bounded security delta, found at the phase whose job is to find it.
```

## vwip0001-test-count — LOW

```text
Verified in the source. docs/spec/VWIP-0001.md:202 says "Twelve executable tests, specified in
CONTENT-SECURITY.md section 6 and PRIVACY.md section 10." CONTENT-SECURITY.md §6 (lines 316-337)
is a numbered list of exactly 10; PRIVACY.md §10 (lines 229-249) is a numbered list of exactly
7. Overlap is exactly two: PRIVACY 1 (zero-egress under a socket monitor) = CONTENT-SECURITY 3,
and PRIVACY 4 (two installs, byte-identical outbound headers) = CONTENT-SECURITY 5. That gives
15 distinct, not 12. I tried to find a reading producing twelve and could not: restricting to
build-gating tests only removes CONTENT-SECURITY 4 (which states it "MUST NOT gate the build"),
yielding 14. No other document defines a test count (grep "executable test" hits only
VWIP-0001:49/202, CONTENT-SECURITY:318, PRIVACY:231, GLOSSARY:56, none of which state a number).
Not already fixed: commit 9ee6cc2 "spec: correct six inherited count claims" edited this very
file, correcting "twelve accompanying response headers" to "ten" at lines 22 and 70, but left
line 202 alone; the CHANGELOG entry covers only the TLD and header counts. Not covered by CI:
scripts/check-counts.py has only two rules (launch TLDs, accompanying response headers) and no
rule deriving a conformance-test count, so nothing catches this. Severity corrected downward
from the claim's framing. Both cited sections enumerate their tests normatively and
unambiguously, and VWIP-0001's own list of the five gating tests is drawn correctly from them,
so an implementer building the suite works from the enumerations, not the summary sentence.
Unlike the TLD defect, this cannot produce a divergent artifact or a silent fork; the harm is
confined to a reviewer's completeness check on a Draft-status proposal. That is a documentation-
accuracy defect at low, not the correctness-class impact of the precedent it cites. Fix: state
"fifteen" (or spell out ten plus seven with two shared), and add a check-counts.py rule deriving
the number from the two numbered lists.
```

## content-security-md-s3-clipboard-permissions-policy — UNRATED

```text
I tried to refute this and could not. What I checked: 1. The quoted text says what the claim
says it says. /workspace/vayuweb/docs/spec/CONTENT-SECURITY.md:195-197 reads "Note also that
**no Permissions-Policy token exists** for notifications, push, clipboard, canvas, WebGL, Web
Audio or the Network Information API — those are covered, where they can be, in section 5." Line
193 states the floor rule: "A feature not named here SHOULD be denied, and an omission is a
defect to report." 2. The factual assertion is false for clipboard. I fetched the W3C
permissions-policy feature registry (w3c/webappsec-permissions-policy features.md): `clipboard-
read` and `clipboard-write` are listed under "Proposed Features", pointing at w3c/clipboard-apis
PR 120, shipped in Chrome 86. Tokens exist and are honoured by the header in Chromium today. The
other items in the note are correct — notifications, push and Network Information appear nowhere
in that registry. 3. The obvious defence — "the header only enumerates standardized tokens" — is
refuted by the header itself. The canonical block at CONTENT-SECURITY.md:176 already includes
`summarizer`, `translator`, `language-detector` and `speaker-selection` (all "Proposed
Features", the same status as the clipboard pair), plus `browsing-topics` and `local-fonts`
("Experimental") and `private-state-token-issuance`/`-redemption`, which are not in the registry
at all. So maturity is not the document's exclusion criterion, and the clipboard pair is
excluded solely on the stated — untrue — ground that no token exists. 4. Nothing else covers it.
Section 5 (lines 261-314) is 5.1 WebRTC, 5.2 top-level navigation, 5.3 PAC, 5.4 fingerprinting
(canvas, WebGL, Web Audio, fonts, navigator), 5.5 browser behaviour, 5.6 network correlation,
5.7 same-origin timing, 5.8 compromised endpoint — no clipboard entry. `grep -rni clipboard`
over the repo (excluding node_modules) returns exactly one hit: line 196 itself. Not in
PRIVACY.md, THREAT-MODEL.md or any client doc. CHANGELOG.md `[Unreleased]` and `git log` show no
fix. 5. Not out-of-scope by roadmap. docs/ROADMAP.md Phase 0 lists "Independent adversarial
review of the above — **Open — this is the current work**", and the CHANGELOG already records
defects of exactly this shape ("one false justification in the index keyspace layout",
"RESOLUTION.md required the resolver to emit the fingerprint it forbids"). A false justification
in normative prose is a defect class this project already logs, not a style preference. The
header is also pinned across documents by scripts/check-headers.py via the `<!--
canonical:permissions-policy -->` sentinel, so the omission propagates wherever the block is
quoted. Two corrections to the claim's own evidence, neither material: the canonical header
enumerates **44** tokens, not 42; and "byte-pinned by CI" is true only in the cross-document
sense (check-headers.py) — the runtime byte-identical-emission requirement is section 6
conformance test 1, which is unimplemented (browser/proxy layer is a later phase). Severity: the
claim implies more than the impact supports, so I am setting it to low. The clipboard is not an
egress channel — denying these tokens does not close a network leak, which is the document's
primary threat. Chromium's default allowlist for both is `self`, `clipboard-read` additionally
requires a user permission prompt, and `clipboard-write` requires a user gesture; the exposure
is a site's own script (permitted by `script-src 'self'`) doing paste-hijacking or, with a
prompt, reading system clipboard contents. Real hardening gap and a genuinely false statement
about the platform, but low, not medium or high. The fix is two-part and the second half is
normative, so this is not editorial: correct the sentence to drop "clipboard" (the rest of it is
accurate), and add `clipboard-read=(), clipboard-write=()` to the canonical block per the
document's own floor rule, keeping alphabetical order after `camera=()`.
```

## docs-spec-cross-reference-section-numbers — LOW

```text
Could not refute; all six cited cross-references are wrong in the files as they stand. VERIFIED
WRONG: 1. docs/spec/PRIVACY.md:42 "(section 2.1)" — PRIVACY.md §2 "Modes" (L34-57) has no
subsections and no "2.1" exists in the document. Read as cross-doc it is still wrong: CONTENT-
SECURITY.md §2.1 is "Directive rationale" (a CSP directive table), not the full-proxy/own-
webview mandate, which is in PRIVACY.md §5 and CONTENT-SECURITY.md §5.2/§5.5. 2.
docs/spec/PRIVACY.md:84 "CONTENT-SECURITY.md section 4.2" for the top-level-navigation
exfiltration channel — §4.2 is "Response headers the resolver MUST strip"; the channel is §5.2
"Top-level navigation". Note §5's subsections are bold-numbered ("**5.2 Top-level
navigation.**"), not headings, so they exist even though a heading grep misses them. CONTENT-
SECURITY.md:151 itself cites "section 5.2" for this same channel — the two documents contradict
each other. 3-5. VWIP-0001.md:98, VWIP-0001.md:129, RESOLUTION.md:317 (claim said 316; sentence
starts 316, citation on 317) all cite "CONTENT-SECURITY.md section 1.3". §1 has no subsections;
grep '1\.3\b' over that file returns nothing. The two per-site relaxations are §2.3.
PUBLISHING.md:100 cites the same material correctly as "section 2.3", ruling out an alternate
numbering convention. 6. RESOLUTION.md:312 "CONTENT-SECURITY.md section 4 names each" for the
four channels CSP cannot close — §4 is "Header and markup hygiene at the proxy"; the four are
§5.1, §5.2, §5.7, §5.8. REFUTATIONS ATTEMPTED AND FAILED: no CHANGELOG [Unreleased] entry
addresses it (that section is CI/fuzz work); scripts/check-links.py validates markdown links and
explicitly skips anchors, so no CI gate covers prose "section N.M" references; the roadmap does
not defer spec cross-referencing — Phase 0 is precisely spec settling. ONE PART OF THE CLAIM IS
WRONG: `git log --follow docs/spec/CONTENT-SECURITY.md` shows the file was added in a single
commit with its current numbering and never renumbered, so this is not a "systematic renumbering
miss" — the pointers were wrong when written. Same defect, wrong stated cause. SEVERITY
CORRECTED DOWN from the claimed Article 44.6 buildability consequence. Article 44.6 does exist
(constitution/CONSTITUTION.md:2611) and says spec text must suffice to build a conformant client
without reading an implementation, but no normative requirement is missing or contradicted:
CONTENT-SECURITY.md §2.3 fully states the relaxation rules, PRIVACY.md §3.2 states the egress
refusal itself, and RESOLUTION.md:316-317 names the two relaxations inline in the same sentence
as the bad pointer. The reader is delayed, and in the §4.2 case briefly landed on unrelated but
plausible material; nothing is unbuildable. Low.
```

## resolution-control-api-tcp-7653 — UNRATED

```text
Tried to refute it and could not — the quotes are accurate and the contradiction is live in the
working tree. Verified verbatim: - /workspace/vayuweb/docs/spec/RESOLUTION.md:24-26 "A resolver
SHALL expose exactly two listeners, and **only one of them is a network listener**"; :28-29 the
table gives `127.0.0.1:7654 HTTP proxy` and `<runtime-dir>/vayuweb.sock control API`; :38-41
"The control API is served over a **Unix domain socket (or a named pipe on Windows)** ... It
MUST NOT listen on TCP, on any address, including loopback — not even opt-in, not even for
development." - /workspace/vayuweb/docs/spec/RESOLUTION.md:153, under the heading "## The
control API" — the section that actually enumerates the 15 `/v1/...` endpoints — "The control
API on `127.0.0.1:7653` is JSON over HTTP." - /workspace/vayuweb/docs/spec/LOCAL-
SURFACE.md:14-16 and :36-38 say exactly what is quoted, and :36-38 calls a TCP control listener
"non-conformant" outright. Two things strengthen it beyond the evidence offered. First, the
§"The control API" body is not merely a stale port string — its whole rationale is TCP-shaped
and would survive a careless port-only edit: RESOLUTION.md:169-174 requires rejecting `Origin`,
requires `X-VayuWeb-Control: 1` to "force a CORS preflight", and argues "no browser page ... can
reach these endpoints even if it learns the port". A Unix socket has no port to learn and no
browser can preflight it; that paragraph only makes sense for the listener the same file
forbids, so it actively reinforces the wrong reading rather than flagging it. Second,
ARCHITECTURE.md:82-84 does not just repeat the port, it repeats a *justification* that inverts
the rule: "Two ports, not one, so that the control API can be firewalled or disabled without
disabling resolution" — directly against RESOLUTION.md:24-26 — and ARCHITECTURE.md:208 carries a
normative "The control API on 7653 SHALL require a token", i.e. a SHALL attached to the
forbidden transport. Corroborated the corpus spread: `grep -n 7653` (excluding node_modules)
hits RESOLUTION.md:153, NAMES.md:77, GLOSSARY.md:47, ROADMAP.md:85, WHITEPAPER.md:144 and 163,
ARCHITECTURE.md:84, 104, 208. Conversely, "Unix domain socket"/"vayuweb.sock" appears only in
RESOLUTION.md:29/38/45 and LOCAL-SURFACE.md:14/22 — zero occurrences in ROADMAP, ARCHITECTURE,
WHITEPAPER, GLOSSARY or NAMES. So one paragraph in one file states the rule; nine lines across
six files state the opposite. Refutation paths I checked and closed: - Already fixed? No.
Nothing in `## [Unreleased]` or the 0.1.0 section of CHANGELOG.md touches it; the only relevant
entry (CHANGELOG.md:268) announces the move off TCP as an addition, which is what left the rest
of the corpus stale. Working tree at 99dfe25, nothing staged. - Superseded/precedence rule?
RESOLUTION.md:44-46 does point at LOCAL-SURFACE.md "which is normative", but that pointer sits
in §Components, ~115 lines above §The control API, and LOCAL-SURFACE.md is itself marked "Draft
— not yet implemented, proposed formally by VWIP-0001" whose Status is Draft. A draft pointer
does not neutralise an unqualified declarative sentence in the section that owns the endpoint
list. - Not-yet-built feature? Inapplicable in the direction that would excuse it.
RESOLUTION.md:10 says "Nothing described here has been implemented," and ROADMAP Phase 0 is the
current phase with "test vectors for every wire-visible rule" open — settling the specification
*is* the work in flight, so a normative contradiction is the defect class that matters most
right now rather than the one to defer. - Caught by a gate? No. `grep -c 765 scripts/*.py`
returns 0 in all eight check scripts; check-headers.py enforces byte-identical quoting only for
the CSP/security headers. Its own docstring states the exact principle being violated here — "A
profile that drifts between documents is worse than no profile at all -- two implementers read
two different policies and both believe they are conformant" — and the control-API transport has
no equivalent guard. - Style/wording? No. `127.0.0.1:7653` is a bind address for a listener
another paragraph of the same document says MUST NOT exist, and ARCHITECTURE.md attaches a SHALL
to it. Severity: high, not critical. The claimed consequence is real but bounded by two facts
the claim does not weigh — no implementation exists yet (RESOLUTION.md:10), so nothing shipped
is currently exposed, and the correct rule is stated twice, once in the same file. The fix is a
documentation edit before Phase 0 closes: rewrite RESOLUTION.md:153 and its CORS rationale at
:169-174 for a socket transport, correct the eight other call sites (notably
ARCHITECTURE.md:82-84's "Two ports, not one" and :208's SHALL), and add a canonical-sentinel
gate in the check-headers.py style so the transport cannot drift again.
```

## uri-scheme-conformance-2-identical-uris — LOW

```text
Could not refute. Verified verbatim at /workspace/vayuweb/docs/spec/URI-SCHEME.md:191:
conformance item 2 reads "`vayu://a.vayu` and `vayu://a.vayu` do not share storage, permissions
or scripting access" — identical URI on both sides. Section 3.1 (line 74) defines origin as
("vayu", label "." tld) and 3.2 (lines 77-80) gives the two intended distinct-origin pairs,
a.vayu/b.vayu and a.vayu/a.shop, so item 2 as written contradicts the origin model it is meant
to test: it requires a name to be cross-origin with itself. No charitable reading saves it — two
loads of the same URI are also same-origin, so the clause is false under that reading too. Not
already fixed: git log on the file shows only commit 8647baf (CLA wording), and CHANGELOG.md has
no entry for URI-SCHEME section 7 (the nearby "duplicated .vayu" Fixed entry concerns
CONSTITUTION.md Article 35.1 and RESOLUTION.md, a different duplication). Not covered elsewhere:
conformance/vectors.json holds only 40 registry record-state vectors
(record/predecessor/rule/outcome), no URI or origin vectors, so nothing downstream disambiguates
the intent and the TLD-in-authority rule of 3.2 has no test coverage at all. Not a style
preference — section 7 is the normative conformance list and this is its only origin test.
Severity corrected down to low: the claimed consequence "breaks same-origin for every site" is
overstated, since 3.1/3.2 state the rule correctly and there is no implementation yet (roadmap
Phase 0, spec-settling). Actual cost is a one-token transcription slip in a normative clause
plus an untested rule. Fix: item 2 should read `vayu://a.vayu` and `vayu://a.shop` (the pair
that exercises 3.2's non-obvious half), optionally split into 2a/2b to cover the b.vayu pair as
well.
```

## resolution-cs-section-1-3 — LOW

```text
Confirmed. RESOLUTION.md:316-317 says "the two per-site relaxations defined in CONTENT-
SECURITY.md section 1.3". CONTENT-SECURITY.md's heading map shows "## 1. The insecure-context
reality" (line 46) followed immediately by "## 2. Content-Security-Policy" (line 91) — section 1
has no subsections, so 1.3 does not exist. The relaxations are defined at line 157, "### 2.3
What this breaks, and the two relaxations", the only place vayu-wasm / 'wasm-unsafe-eval' and
the per-site named Trusted Types policy are specified. PUBLISHING.md:100 cites the same rule as
"section 2.3", confirming the intended target and ruling out a pending renumbering. Refutation
attempts failed: grep across docs/ finds no section 1.3 anchor or alias anywhere in CONTENT-
SECURITY.md; CHANGELOG.md [Unreleased] contains no fix; git log shows no renumbering commit.
Scope is wider than claimed — VWIP-0001.md:98 and :129 carry the same wrong pointer, so a fix
must touch three call sites. Severity lowered to low: the same sentence names both relaxations
parenthetically ("WebAssembly, or a named Trusted Types policy"), so the reader is not left
without the substance, and 2.3 is one heading scan away; it is a wrong normative cross-
reference, not a specification gap.
```

## names-reserved-labels-vs-art-10-8 — UNRATED

```text
VERIFIED — the quotes are accurate and the conflict is real, in both the spec and the shipped
code. What I checked: 1. `/workspace/vayuweb/docs/spec/NAMES.md` lines 63-81. The "Reserved
labels" section opens: "The following labels are withheld in every TLD. A registration operation
naming one of them is invalid and MUST be rejected by every peer" (65-66). The table withholds
"All 36 single-character labels" and "All 1,296 two-character labels", both with the rationale
"Held pending an allocation VWIP", plus named strings `www`, `localhost`, `example`, `invalid`,
`test`, `vayu`, `control`, `api`, `resolver`, `proxy`, `pac`, `wpad`, `_vayu`. Line 79-81 makes
the reserve-for-later-allocation intent explicit for the whole table: "Reserved labels are not
permanently unregistrable. A VWIP MAY release a class of them under an allocation policy, but
until one is ratified the class stays closed." NAMES.md:204 and :233 extend the scheme — every
future TLD gets "its own reserved-label set" and a creation VWIP "MUST specify ... its
additional reserved labels". 2. `/workspace/vayuweb/constitution/CONSTITUTION.md`. Art. 10.5
(lines 794-806) lists five grounds and closes with "These five grounds are exhaustive. No sixth
ground SHALL be introduced by implementation, convention, VWIP or amendment." Art. 10.8
(820-825) reads exactly as quoted, and its second sentence forecloses the only plausible escape
hatch (10.5.a malformation): structural limits "MUST be uniform, MUST be stated as a rule rather
than a list, and MUST NOT hold any name or class of names in reserve for allocation by any
party." NAMES.md's reserved set is literally a list, and it is literally held for later
allocation by VWIP. Art. 30.5 (1942-1945) — "Short names, single characters, dictionary words
... are subject to exactly the same rules as any other string. The protocol MUST NOT recognise a
category of high-value names" — is a direct hit on the scarcity rationale NAMES.md gives. Art.
10.2 forbids "no reserved-name list held by anyone"; 30.2 forbids reservations for any class of
claimant; 35.8 requires "no reserved-name list" on TLD activation. Art. 10.14 entrenches Article
10; Art. 9.6 carries the substance; 9.17/9.18 make it unamendable (ratchet one way only), so the
claim that the charter side cannot move is correct. 3. It is not theoretical — it is implemented
and gated by a test. `/workspace/vayuweb/registry/src/names.ts:105` `if (label.length <= 2)
return 'RESERVED_LABEL';`, reached from `nameRejection` (141) and from record validation at
`/workspace/vayuweb/registry/src/record.ts:289`.
`/workspace/vayuweb/registry/src/names.test.ts:88` pins it exhaustively over the 1,296 two-
character space. So a peer built from this repo refuses `ab.vayu` on the name's identity, which
is precisely the Art. 10.12 conformance-test failure described ("refuses ... on a ground outside
clause 10.5"), and two peers diverge permanently. 4. The repo's own prose argues against itself,
which rules out "intended design documented elsewhere": `docs/spec/ATTESTATION.md:14,35` frames
a reserved-names list as the clearnet apparatus VayuWeb refuses, citing 30.2/30.4;
`docs/FAQ.md:95` says attestation is "deliberately weaker than a reserved-names list ... but it
protects every name rather than only the listed ones". `docs/spec/NAMESPACE.md:45` and
`NAMESPACE-CATALOGUE.md:11` say "no reserved class". Nothing in CHANGELOG.md (`[Unreleased]`
covers CI gates, fuzzing, merkle/checkpoints, resolution) or ROADMAP.md addresses it, and no
known-conflicts register exists. Not fixed, not a wording preference, not out-of-scope future
work — NAMES.md's own status is "Draft — not yet implemented", but the registry implements the
rule anyway. Corrections to the claim, none of which defeat it: the cite "CONSTITUTION.md:5942"
does not exist (the file is 3,423 lines); the correct anchor is 1942, which the claim also
gives. The table names thirteen strings, not twelve — though `_vayu` is already unregistrable
under the label grammar (underscore is outside `a-z0-9-`), so twelve is defensible as the count
of otherwise-valid strings. Also worth noting for whoever fixes it: only the length class is
enforced in code today; the named strings are spec-only, so the code fix is one line plus a
test, while the spec fix is the real decision. Severity: high rather than critical. It is a
normative contradiction with an entrenched clause plus a namespace-divergence bug in shipped
validation code, and Phase 0 is exactly where it must be resolved — but nothing is running, no
name has ever been registered, and there is no live compromise or data loss. The claim's
conclusion is correct as stated: the entrenched side cannot move, so NAMES.md and
`registry/src/names.ts` are what must change.
```

## registry-epoch-activation-interval — UNRATED

```text
I tried to refute this and could not. Every quotation checks out verbatim. VERIFIED TEXT -
/workspace/vayuweb/docs/spec/REGISTRY.md:484-486 — "A Standards Track activation epoch MUST be
at least **two epochs** beyond the epoch in which the VWIP reached Accepted — roughly sixty days
minimum — so that deployment has time to propagate before behaviour changes. Article 47.3
forbids a silent breaking change; this is the interval that makes the prohibition operable." -
The "roughly sixty days" figure is arithmetically what the section's own epoch definition
yields: REGISTRY.md:464-468 makes an epoch boundary require ">= 2,592,000 seconds (30 days)" of
notBefore time plus a checkpoint, so two epochs is >= 60 days, not >= 180. -
/workspace/vayuweb/constitution/CONSTITUTION.md:1311-1312 (Art. 20.3) — activation epoch
strictly future at **Final** "by no less than 15,552,000 seconds (180 days)"; conformance test
at 1362-1363 repeats it. - CONSTITUTION.md:2762-2763 (Art. 47.6) — "not less than 180 days after
the VWIP reaches **Accepted**". - /workspace/vayuweb/docs/spec/VWIP-0002.md:212 — states its
activation epoch solely as "At least two epochs beyond the epoch in which this proposal reaches
Accepted, per Article 47.3 and the epoch definition in REGISTRY.md". So a live proposal in the
tree already carries an activation interval that can legally be 60 days, which Art. 20.3/47.6
forbid, and Art. 20.3 requires the interval to be stated *in the VWIP itself*. - Final vs
Accepted mismatch is real and non-trivial: VWIP-0000.md:130-161 and
CONSTITUTION.md:2489/2526-2527 make Accepted -> Implemented -> Final distinct states with
"Accepted to Implemented no [minimum]", so the two clauses start the same 180-day clock at two
different, separately-timed events. REFUTATION ATTEMPTS THAT FAILED - "Both are MUST floors, so
the stricter binds and there is no conflict." Partly true and it is why I lowered severity —
Art. 3.7 (CONSTITUTION.md:336) puts the Constitution above spec documents, so a reader of both
computes 180 days. But REGISTRY.md does not present its rule as one floor among several; it
asserts "roughly sixty days minimum" and calls it "the interval that makes the prohibition
operable", and Art. 44.6 (CONSTITUTION.md:2611) requires specification text to be sufficient to
build a conformant client without reading anything else. An implementer building from
REGISTRY.md alone gets the wrong number, and VWIP-0002 demonstrates that this already happened
inside the repo. - Already fixed? No. CHANGELOG.md [Unreleased] contains no epoch/activation
entry (grep -i epoch on CHANGELOG returns nothing), and git log shows no such commit. - Out of
scope / not yet built? No. Nothing in registry/, client/, proxy/ or conformance/ implements
activation intervals, but the roadmap's current Phase 0 is exactly the adversarial spec review,
and CHANGELOG precedent (the merkle-tree commit "closing an Article 44.6 gap", 99d6355) shows
spec-sufficiency gaps are treated as defects here, not as future work. - Misquotation? Only one
small imprecision in the claim's framing: REGISTRY.md cites Article 47.3 (no silent breaking
change), not 47.6. The 180-day rule is 47.6, in the same Article, so the substance stands.
SEVERITY CORRECTION Downgraded to medium. It is a specification/charter inconsistency in an
entrenched Article (20.12), not a live failure: no code implements activation intervals, nothing
is shipped, and Art. 3.7 precedence means a reader of the whole corpus still lands on 180 days.
The fix is editorial-normative — restate REGISTRY.md:484 as "at least two epochs AND not less
than 180 days per Art. 47.6", drop the "roughly sixty days minimum" gloss, correct
VWIP-0002.md:212, and settle whether the clock starts at Accepted (47.6) or Final (20.3) — but
it must be settled before any code encodes an interval, which is Phase 0's stated purpose.
```

## names-tld-retire-24mo-vs-const-35.10 — UNRATED

```text
I tried to refute this and could not. Every quote checks out verbatim and the conflict survives
reading the surrounding sections. VERIFIED QUOTES -
/workspace/vayuweb/constitution/CONSTITUTION.md:2165 (35.10) — exact as offered: TLD-RETIRE
reachable only when no live names remain, or every remaining registrant has migrated by their
own signed action under a path open "not less than five years", and "No name is ever migrated on
a registrant's behalf." - CONSTITUTION.md:827 (10.9) — exact: a TLD open for registration MUST
NOT be retired "in a way that affects names already registered in it"; names in a closed TLD
"MUST continue to be renewable, transferable and resolvable on their original terms." -
/workspace/vayuweb/docs/spec/NAMES.md §"Retiring a TLD" (lines 251–275) — exact: "The minimum
sunset is 24 months from ratification"; "At month 24 the TLD becomes historic … after which the
names enter QUARANTINE and then FREE."; "Holders who never claim their successor name lose it at
month 24."; "Each renewal MUST include an `alias` record pointing at the successor name; a
renewal without one is invalid." REFUTATION ATTEMPTS, ALL FAILED 1. Precedence escape —
NAMES.md:241 does defer to the Constitution, but that sentence is scoped ("These figures are
restated here for readability only … normative source for eligibility, ballot format, quorum and
threshold"). It covers the ratification numbers in the preceding paragraph, not the sunset rule.
There is no general precedence clause in NAMES.md. 2. Different actions — CONSTITUTION.md:1883
lists TLD-RETIRE as a record type alongside TLD-FREEZE. NAMES.md's "Retiring a TLD" is that
action, so 35.10 is on point. 3. Lapse rather than seizure — Art. 11.1 permits loss only on a
signed transfer/relinquish or lapse "under a rule published before that tenure began". NAMES.md
explicitly keeps renewals valid for the whole sunset and still destroys the name at month 24,
and the retirement VWIP is by definition ratified after tenure began. Art. 20.4 independently
says "A validly registered name does not become invalid because the rules later changed." 4.
Some other article authorising it — the opposite. 35.9 (line ~2159): "A TLD with live names
SHALL NOT be deleted, repriced or subjected to new conditions. The only available action is TLD-
FREEZE." 35.11: "This Article is bound by Articles 11 and 20." Articles 10 and 11 are entrenched
(10.14, 11.14) and 9.7 entrenches non-seizure directly. 5. Already fixed — no. CHANGELOG.md has
no retirement entry; the 24-month rule is currently propagated into docs/GLOSSARY.md:15 and
:195, docs/GOVERNANCE.md:92, docs/FAQ.md:112 and docs/spec/NAMESPACE.md §6, the last of which
even asserts "Constitution Article 35 additionally forbids removal that would strand holders"
while restating the 24-month rule that does exactly that. 6. Not-yet-built — the roadmap defers
code, not the spec. Phase 0's stated open item is the adversarial spec review, so a spec that
mandates conduct the ratified, in-force Constitution (v1.0, "In force from the moment of first
publication") forbids is precisely the Phase-0 defect class, not out of scope. ONE PART OF THE
CLAIM IS OVERSTATED — CORRECT IT BEFORE FILING The alias-mandate sub-claim cites the wrong
clauses. Art. 11.9 and 32.4 forbid renewal depending on a counterparty, live service, account,
approval, fee or network reachability beyond publishing one record. An `alias` field the
registrant can produce and sign offline breaches none of those. The alias mandate is still a
defect, but under 10.9 ("renewable … on their original terms") and 35.9 ("SHALL NOT be …
subjected to new conditions") — it retroactively changes the content required for a valid
renewal of an already-registered name. File it under those, not 11.9/32.4. SEVERITY High, not
critical: nothing is implemented (NAMES.md carries "Status: Draft — not yet implemented", and no
VayuWeb name has ever been registered), so no holder can lose anything today. But it is a direct
contradiction of three entrenched clauses by a document labelled normative, it has already
replicated into four other docs, and left standing it would be implemented as a conformance
violation of the charter the project's whole premise rests on.
```

## attestation-registry-record-type-conflict — UNRATED

```text
I tried to refute this and could not break the core of it, though two of its three prongs are
wrong or overstated. VERIFIED (survives): 1. /workspace/vayuweb/docs/spec/ATTESTATION.md:55 does
say verbatim "An attestation is an ordinary registry record type, `attest`", and
ATTESTATION.md:176 frames the doc as extending "the record schema" of REGISTRY.md. 2.
/workspace/vayuweb/docs/spec/REGISTRY.md:65 is normative: "A `records` entry is a map with keys
`type`, `value`, and optional `ttl`". `value` is REQUIRED. The payload at ATTESTATION.md:59-66
is `{type, method, subject, expires}` — no `value` at all. This is stronger than the claim
states: the reference implementation at /workspace/vayuweb/registry/src/record.ts (parseEntry,
~line 202) does `const entryValue = map.get('value'); if (entryValue === undefined)
fail('BAD_RECORD_ENTRY', 'entry value is required')`. So an implementer who copies the
ATTESTATION.md example produces a record that every conforming verifier rejects outright with
BAD_RECORD_ENTRY — the attestation cannot even be published, let alone displayed. The example as
written is not encodable under the schema it claims to extend. 3. REGISTRY.md:77-78 "Unknown
`type` values are stored and replicated unchanged but MUST NOT be acted upon" is real, and
`attest` appears nowhere in REGISTRY.md's type table (peer/ipns/cid/txt/alias). I checked
whether some other document authorises the extension: grep across the repo shows `attest` as a
record type exists only in ATTESTATION.md — not in REGISTRY.md, RESOLUTION.md, VWIP-0000.md,
ARCHITECTURE.md, the roadmap, conformance/vectors.json, or any code. registry/src/record.ts
KNOWN_ENTRY_TYPES is the five, and registry/src/cli.ts:352 renders anything else as "(unknown
type — never acted upon)". So under REGISTRY.md alone, `attest` is unknown and MUST NOT be acted
upon, while ATTESTATION.md:108 and :112 say clients MUST verify it and §5 says they MUST display
it. Nothing reconciles them, and no VWIP registers the type. That is precisely the Phase 0 /
Constitution Article 44.6 bar the roadmap states: "a competent implementer can read the
specifications alone... and produce a client that would interoperate." 4. Not already fixed: no
CHANGELOG entry mentions ATTESTATION.md or the `attest` type; the eight spec defects the roadmap
lists as found-by-implementing do not include this one. REFUTED (drop from the finding): - The
`op` prong is a red herring. Nothing reads `{"type": "attest", ...}` as an `op`; the evidence
concedes it is a `records` entry shape. REGISTRY.md:47/:254 and UNKNOWN_OP are not in conflict
with anything, and citing them inflates the finding. - The revocation prong (4.5 "immediately"
vs 7.5/7 "next resolution") is editorial, not a defect, and its stated consequence is false.
"Immediately" in 4.5 contrasts with a waiting period or third-party approval (the apparatus §1
refuses); §7.7 states when a reader observes it. There is no "unbounded period": revocation is a
change to the registry record, entry `ttl` is capped at 86400 (REGISTRY.md:65), so a cached view
is bounded at 24h. §4.2's 30-day schedule governs re-verifying a still-present attestation
against DNS, not noticing a removed one. The only genuine nit here is terminological —
"revocable... by a signed record" collides with REGISTRY.md's `REVOKE` op, which does something
completely different (kills the name for the rest of its term); the operation meant is `UPDATE`.
SEVERITY: corrected down from the claimed impersonation-gap framing to medium. Nothing is
implemented, no network runs, and no reader can be impersonated today — ATTESTATION.md is marked
"Status: Draft — not yet implemented" and is not scheduled in any roadmap phase. But it is a
wire-visible spec inconsistency in the published spec set that README and docs/FAQ.md:93 point
readers at, and Phase 0's open item is exactly the adversarial spec review meant to catch this
class. The fix is small and belongs in the spec, not the code: register `attest` in
REGISTRY.md's entry-type table (or state explicitly that a type defined by another ratified spec
is "known" for the purposes of :78), and restate the ATTESTATION.md:59-66 example in legal entry
shape — `{"type":"attest","value":"<method;subject;expires>", "ttl":...}` or equivalent — so it
carries a `value`.
```

## pow-log-anchor-missing — UNRATED

```text
VERIFIED — the quotes are accurate and the gap is real, but two parts of the claimed consequence
are wrong and the severity should be "high", not higher. What I checked: -
constitution/CONSTITUTION.md:1962-1965 says exactly what is quoted: a REGISTER and a renewal
record MUST each carry a PoW bound to three things — name, ownership public key, and "a recent
log anchor". Line 1901-1903 likewise: every record MUST carry "the epoch under which it is to be
interpreted, an activation height, and an anchor to a recent log state". - docs/spec/PROOF-OF-
WORK.md:66-76: the preimage is `"vayuweb-pow-v1" || canonical(record without sig and without
powProof.nonce)` and the prose enumerates the covered fields as `name`, `tld`, `ownerKey`,
`seq`, `notBefore`, `notAfter`, `records`, `prevHash`. No log root, no log length, no
checkpoint, no height. Two of the three Article 31.1 bindings are present; the third is not. -
docs/spec/REGISTRY.md:44-58 record schema: `version, op, name, tld, ownerKey, seq, notBefore,
notAfter, records, powProof, prevHash, sig, coSig`. No epoch field, no activation height, no
log-state anchor. `prevHash` is "32 `0x00` when `seq` is 0" (line 56) and REGISTER validation
(REGISTRY.md ~line 147, and the `verify()` pseudocode at ~line 279) requires it be all-zero — so
for the REGISTER case the only field that could carry an anchor is fixed to zero by rule. - The
gap is not repaired elsewhere. REGISTRY.md's "Epochs" section (lines 459-496) deliberately makes
the epoch *derived from the log* and "never taken from a peer's own clock or from any
announcement" — a coherent design, but the opposite of 29.5.d's "every record MUST carry the
epoch". Nothing in PROOF-OF-WORK.md's Verification, Renewal, Parameter Updates or Limits
sections introduces an anchor; `grep -rn anchor docs/spec` returns only unrelated hits (CRYPTO-
AGILITY checkpoint anchoring, a `.anchor` TLD, a CSP mention). - The gap is live in code, not
just prose: registry/src/record.ts parses exactly the spec's field list (`notBefore`,
`prevHash`, no anchor); `grep -rn anchor registry/src/*.ts` is empty. - Not already fixed and
not out of scope: CHANGELOG `[Unreleased]` does not mention it, and docs/ROADMAP.md Phase 0
lists "Independent adversarial review of the above — **Open — this is the current work**", with
the done-when being Article 44.6 interoperability from the specs alone. A charter-vs-spec
conflict is the deliverable of that item, not a future feature. - Precedence makes it a defect
rather than a preference: CONSTITUTION.md 3.7 ranks the Constitution above specifications and
says the lower instrument "is void to the extent of the conflict". So the spec as written cannot
simply win the argument. Corrections to the finding as stated: 1. The claimed consequence
"replay resistance rests entirely on the verifier's wall clock" is WRONG. REGISTRY.md's
"Sequence Numbers and Replay Protection" section gives replay resistance from `seq` (+1 exactly,
per-name) plus `prevHash` binding to the predecessor's exact bytes plus the domain-separation
prefix — that satisfies Art. 29.5.c independently. `clock_check` bounds post/backdating, not
replay. Drop that sentence; it weakens the finding. 2. "produce records the first cannot parse"
is overstated. REGISTRY.md states a peer MUST NOT re-serialise a received record and that "a
record carrying unknown fields still verifies downstream", and the `verify()` pseudocode has no
unknown-key rejection. The fork shows up as one-directional rejection (the charter-following
implementation rejects spec-conformant records for missing mandatory fields), not as a parse
failure. 3. The claim under-states one thing: RENEW is equally unanchored. Art. 31.1 covers
renewals too, and there `prevHash` points at the previous record for that name, which is
typically a year old — an anchor to log state, but not to *recent* log state. 4. Real residual
substance beyond the paperwork: without a recent-log binding, work is precomputable forward
against a known future drop date. `notBefore` is in the preimage and `clock_check` confines a
record to roughly a 24-hour submission window, so a stockpile is bounded per-proof — but a drop-
catcher can grind a proof for a target expiry date well in advance, which is the precise case an
anchor exists to prevent. REGISTRY.md step 4's justification ("stops a squatter pre-signing
dated registrations against a future release") describes the backdating bound and does not cover
forward pre-signing. Severity: high. It is a mandatory-Article conformance gap on the wire
format, it blocks the Phase 0 acceptance test (Art. 44.6 interoperability), and it costs real
anti-squatting strength — but it is not a live exploitable break of an operating system, and
replay/uniqueness are covered by other mechanisms.
```

## check-headers-docstring-clear-site-data — EDITORIAL

```text
Could not refute; verified at HEAD. scripts/check-headers.py:55-57 (load_canonical docstring)
states "the privacy specification owns Clear-Site-Data". That function collects only
`canonical:<name>` sentinels, so "owns a definition" means owning a sentinel. A repo-wide grep
finds exactly three sentinels, all in docs/spec/CONTENT-SECURITY.md (:98 content-security-
policy, :174 permissions-policy, :199 referrer-policy); none in PRIVACY.md, none outside .md.
PRIVACY.md:145 (§5) not only lacks one but forecloses it: "This specification therefore does not
use it, and an implementer who adds it should understand they have added a no-op", with the
trace table routing storage clearing to the ephemeral profile directory "not by any header";
CONTENT-SECURITY.md:62 and :87 agree. So the cited definition does not exist and was
deliberately designed out. Not already fixed: git log shows no commit touching scripts/check-
headers.py since it was introduced (CHANGELOG line 280), and CHANGELOG has no entry for it. Not
a roadmap gap — the script and both specs are present and current. Two corrections to the
claim's framing. (1) It overstates by saying the whole-tree-scan rationale "rests on" the
nonexistent definition: the very next sentence gives an independent and valid reason ("Two files
defining the same key differently is itself the drift this script exists to catch"), so only the
illustrative clause is false, not the rationale. (2) Behaviour is genuinely unaffected —
load_canonical walks the tree either way and the script's comparison logic is correct. Adjacent
residue of the same drift, noted but not part of this finding: CANON at line 31
(docs/spec/CONTENT-SECURITY.md) is assigned and never read, while the module docstring still
calls that file "the single source of truth" — contradicting load_canonical's "definitions may
live in more than one specification". Severity corrected down to editorial: no behavioural, spec
or conformance impact; the fix is one sentence of prose in a docstring, and both specs already
state elsewhere that Clear-Site-Data is inert and unused, so the chance of a maintainer actually
being misled into adding a guarded-looking Clear-Site-Data block is small.
```
