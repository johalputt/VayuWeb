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

The file carries seven suites: `vectors` holds 73 record-verification vectors, and `convergence`,
`resolution`, `replication`, `equivocation`, `pow` and `blockExchange` hold their own. Those six
pin what implementations must *agree* about rather than what one of them accepts, which is where a
fork lives.

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

## `key-literal-allowlist.txt`

Source files permitted to contain key-shaped literals, checked by the secret-scanning job in
`.github/workflows/security.yml`. Currently one entry: the small-order Curve25519 points that
Ed25519 verification must refuse.
