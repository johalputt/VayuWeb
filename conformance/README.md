# Conformance artifacts

Machine-readable artifacts for checking an implementation against the specifications, rather
than against this implementation.

That distinction is the point. Constitution Article 44.6 requires that a competent implementer
can read the specifications alone — without access to any source code, and without asking a
question — and produce a client that interoperates. Prose cannot establish that property.
Bytes can.

## `vectors.json`

Verification vectors for the registry record rules in
[`docs/spec/REGISTRY.md`](../docs/spec/REGISTRY.md).

Each vector is a complete case:

| Field | Meaning |
| --- | --- |
| `name` | Stable identifier, unique across the set. |
| `rule` | The rule being pinned, in the specification's own terms. |
| `record` | The record's exact serialised bytes, hex-encoded. |
| `now` | The instant to verify at, Unix seconds. Never the wall clock. |
| `state` | The registry state to verify against — see below. |
| `expect` | The verdict every conforming implementation must return. |

`state` supplies what a verifier would otherwise read from its own log:

| Field | Meaning |
| --- | --- |
| `predecessor` | Hex bytes of the current accepted record for the name, or `null`. |
| `revoked` | Whether a `REVOKE` has been accepted for the name. |
| `fullyReleased` | Whether a prior registration has finished grace and quarantine. |
| `powVerified` | The result of proof-of-work verification. See the note below. |

### Three things the format asserts deliberately

**The rejection code is part of the contract, not just accept-or-reject.** A record with two
defects must produce the same code on every implementation. If it does not, the code is a fact
about whose verifier you asked rather than about the record — and the order in which checks run
becomes unobservable, which is how two implementations drift while both look correct.

**`defer` is a third verdict, not a kind of rejection.** A record whose term starts beyond the
clock-skew tolerance is held and reconsidered, because the verifier's own clock may be behind.
An implementation that rejects instead will disagree permanently with honest peers about a
valid record.

**`powVerified` is injected rather than evaluated.** Every vector would otherwise cost a 64 MiB
Argon2id evaluation, and a suite nobody runs is not a gate. The proof construction — salt
derivation, the leading-zero-bit test, difficulty — is pinned separately with real solved
nonces. Verifying these vectors does **not** demonstrate a correct proof-of-work
implementation, and should not be reported as if it did.

### Running them against another implementation

Read the file, and for each vector: decode `record` from hex, verify it against `state` at
`now`, and compare your verdict to `expect`. Nothing else is needed — no network, no log, no
shared code.

A disagreement means one of three things, and all three are worth reporting: a bug in your
implementation, a bug in this one, or an ambiguity in the specification that let two people
read it differently. The third is the most valuable, and the reason the vectors exist.

### Regenerating

```sh
cd registry && npm run vectors
```

The artifact is committed and a test compares it against a fresh generation, so a change to any
encoding rule appears as a reviewable diff here rather than as a silently different expectation.
If the bytes move, every implementation built against them needs to know.

### Coverage and its limits

The set covers framing, the record schema, registration, chain integrity, authority, the name
lifecycle and cryptographic suites, including at least one vector for every rejection code the
verifier can return — a test fails if a code is added without one.

That sentence was false for a period, and how it was false is worth stating. The test enforcing
it compared the artifact against a **hand-written** list of codes, so it passed by asking only
about the twenty-two somebody had remembered to type; six genuinely returnable codes were absent
from the list and from the artifact together, and a hand-written expectation cannot detect the
thing it forgot. The list is now derived from the rejection codes themselves, which required
making them a runtime value rather than an erased TypeScript union.

**Exemptions are named, and there is one.** `SUITE_DOWNGRADE` has no wire vector because a
vector states its predecessor as bytes and `CRYPTO-AGILITY.md` 4.2 makes a record naming an
inactive suite unparseable — so the suite-3 predecessor a downgrade needs is not a record any
conforming peer can hold. It is unit-tested against a constructed predecessor, and the VWIP that
activates a second suite must add the wire vector. A test also fails if an exempted code
acquires a vector, so the excuse cannot outlive the reason for it.

The file carries eight suites: `vectors` holds 91 record-verification vectors, and `convergence`,
`resolution`, `replication`, `equivocation`, `pow`, `blockExchange` and `release` hold their own.
Those seven pin what implementations must *agree* about rather than what one of them accepts, which
is where a fork lives.

**`release` answers the one question the record suite cannot ask.** `state.fullyReleased` is an
*input* to every vector in `vectors`: the suite hands the verifier the answer and checks what it
does with it, so an implementation deriving that answer by any rule at all passes the file. The
derivation decides who owns a name — `NAME_TAKEN` or an accepted registration — so two peers
computing it differently accept different owners and neither ever reports an error. `REVOKE` is why
it is published rather than assumed: an ordinary record is released at `notAfter + 2592000 +
2592000`, a revoked one at `notAfter + 2592000`, because grace would be a window in which a
compromised key could renew. An implementation applying the ordinary rule to both holds a revoked
name a month longer than its peers.

**The `lifecycle/term-*` vectors pin what an implementation must COMPUTE**, which is a direction
the rest of `vectors` does not cover. Every other vector hands the verifier a finished record and
asks for a verdict, so an implementation deriving a renewal's expiry by any rule at all — always
from the renewal instant, always from the old expiry — passed the whole file. Two peers would then
hold different expiries for one name, disagree about when it lapses, and therefore about whether it
resolves and whether a stranger may take it: a fork neither side rejected anything to reach.

Each case appears three times — the specified `notAfter` accepted, one second either side refused —
because a rule that only rejects *downward* is one two implementations drift apart under, and
because that is not hypothetical. Relaxing `notAfter !== base + 31536000` to `notAfter < base +
31536000` survived every test in this repository before these vectors existed. For `RENEW` that
equality is the only bound there is: the `notAfter - notBefore == 31536000` check belongs to the
`REGISTER` branch, so a renewal could have claimed a decade — the exact defect
[NAMES.md](../docs/spec/NAMES.md) names when it explains why the renewal window is only sixty days
wide.

**Every wire message has a vector that decodes**, in `replication` and in `blockExchange` alike,
and a test derives that from the message types themselves rather than from a list. Three of the
five replication messages had none for a long time — `RECORDS`, `CHECKPOINT` and `EQUIVOCATION` —
so an implementation could pass the whole suite having never once decoded the message that moves
records, the message that is the whole of what a light client is handed, or the report
REPLICATION.md 6.3 makes a MUST. The coverage test that was supposed to notice derives its
expectations from the *rejection* codes, and a message type with no vector produces no rejection to
be missing: it could not see the gap in principle, not merely in practice.

The `RECORDS` vector carries a real record rather than filler, and a test verifies it as a record.
A `RECORDS` whose payload is arbitrary bytes decodes perfectly well, so a vector built that way
pins the envelope — the part nobody gets wrong — and says nothing about what a runner does next,
which is the only part that matters.

**`blockExchange` is the one suite that is not stable**, and it is marked so in the artifact's own
notes. VWIP-0005 is a Draft; its encodings are generated rather than transcribed precisely so the
proposal carries executed bytes, but a Draft may still change them. Do not build against it
expecting the hex to hold.

One of its vectors carries a `construct` recipe instead of a `message` — a block one octet over
the megabyte limit, which written out is 2.1 MB of hex zeros where every byte after the first
carries no information. A runner builds the buffer from the stated length and tests exactly what
one reading two million zeros would. A vector nobody can read is a vector nobody checks.

**`equivocation` is a pair of record encodings and one boolean**, per `REPLICATION.md` 6.2: two
records, no state, no clock, no prior view. A vector needing any of those would be describing
something other than what the specification says an `EQUIVOCATION` report is.

It went without a vector for a long time, and building one is what found the reason it needed a
contract rather than a unit test. Neither half of a forged report is a record any verifier would
accept, and neither half of a genuine one need be either — so what separates them is a question
no record vector asks. An implementation checking a pair for everything except *who signed it*
will record and forward a report that anyone can mint against anyone, because an owner key is
public. Both answers are pinned, not only the refusals: a suite of nothing but forgeries passes
against an implementation that never reports anything, and under-reporting here is silent.

**`pow` is the proof-of-work arithmetic, with no Argon2id evaluation anywhere in it** — the base
table at each of its boundaries, the rate term at every doubling, the trailing window either side
of an epoch edge, the salt preimage, and the leading-zero-bit test. The split is deliberate:
Argon2id is a standard with published vectors of its own, while everything around it is local to
this protocol and therefore where two implementations actually diverge. **Passing `pow` does not
demonstrate a correct Argon2id**, and it is not offered as evidence of one.

Every expectation in `pow` is a literal transcribed from `PROOF-OF-WORK.md`, with one exception —
the salt, which is a digest no human derives by hand, and which the committed file pins instead.
The first version of the suite computed its expectations by calling the functions under test, and
four of five deliberate mutations to those functions survived it. A vector whose expected value
comes from the implementation is a snapshot of whatever that implementation does, which is the
opposite of a specification.

Absence from this file is still not evidence that an area is settled. What it does cover, it now
covers as a contract between implementations rather than as a test of this one.

## `client-built.json`

Records **built by the Rust client** (`client/src/bin/write-fixtures.rs`) and verified by this
implementation's own verifier in `registry/src/clientbuilt.test.ts`. Where `vectors.json` pins
what a verifier must say about given bytes, this artifact runs the other direction: the client
produces bytes from a described intent — register, update, transfer with countersignature,
renew inside the window, relinquish, revoke, an alias-only pointer name — and the reference
verifier must accept every one of them.

Each case carries its plain-text metadata (`op`, `name`, `tld`, `seq`, term bounds, claimed
difficulty, transferor key where authority tracking needs one), the record's exact hex bytes,
and the `record_hash` the client computed. The consumer checks all three against what it parses,
so a regeneration bug cannot hide behind a verdict that accepts whatever arrived.

The generator is deterministic on purpose: fixed test-only seed byte patterns (documented as
such; they protect nothing and production identities come from the OS CSPRNG), Ed25519's
deterministic signing, and a nonce walk that starts at zero and increments big-endian. CI
regenerates the file and fails on any diff, so the builder cannot silently stop being a pure
function of its inputs — which is also how cross-language drift would announce itself before it
reached the network.

Two real defects were found by exactly this round trip, which is the argument for the artifact's
existence: the first build offered an alias entry beside other entries (a name is either a
pointer or a destination) and scheduled a successor inside a transfer's settlement horizon.
Both are refusals the verifier would have issued after the expensive work ran; both are now
builder-side refusals pinned by tests on each side.

### The publish path, in the same artifact

One case carries a `site` object: the exact files, the root CID the client computed, and every
block. The consumer rebuilds the tree with **this** implementation's importer (`importSite`) and
requires the same root, the same block set byte for byte, and a `cid` record entry whose binary
bytes decode to that root. That is the cross-language check for the DAG: a client that addressed
content differently — a field order reversed here, a sort key chosen differently there — would
publish sites visible to itself alone, with every individual signature still verifying. The
client-side port is pinned against the same IPFS reference blocks as the implementation of
record (empty directory, one-file, two-file ordering, multi-chunk, nested trees), so three
independent computations must agree before a fixture diff stays quiet: the reference importer,
the registry, and the client.

## `rules.json`

The checker's rule set as data — PUBLISHING.md 3.1.6's "one shared definition" between what the
checker demands and what any resolver-side enforcement may demand. Generated by
`client/src/bin/write-fixtures.rs` from the doctor's `RULES` table (the source of truth); each
entry carries the rule `id`, the exact `what`/`why`/`fix` strings a finding renders, and an
`enforcement` classification: `csp` (the emitted headers block it; `evidence` names the header
substrings that do, and `absent` names substrings that must never appear globally),
`scan` (no header can express it, so serving surfaces must refuse the document),
`advice` (disclosed, not blocked), or `publish-check` (meaningful only at publish).
Verified from the registry side by `rules.test.ts`, which independently states the
expected id set AND holds every csp claim against the proxy's actual header constants — so a
header that drifts fails CI even though this file still matches its Rust source. Regenerated by
the same CI step as `client-built.json`; drift fails the build. The ids are the
contract: findings reference them, the fixer matches on them, serving surfaces dispatch on their
enforcement class, and anything that consumes doctor output in another language compiles against
this file rather than against folklore.

## `key-literal-allowlist.txt`

Source files permitted to contain key-shaped literals, checked by the secret-scanning job in
`.github/workflows/security.yml`. Currently one entry: the small-order Curve25519 points that
Ed25519 verification must refuse.
