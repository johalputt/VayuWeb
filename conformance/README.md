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

The set covers framing, the record schema, registration, chain integrity, authority and the
name lifecycle, including at least one vector for every rejection code the verifier can return
— a test fails if a code is added without one.

It does **not** yet cover replication, convergence and its tie-break, equivocation detection, or
resolution. Those belong to later phases and have no vectors here. Absence from this file is not
evidence that an area is settled.

## `key-literal-allowlist.txt`

Source files permitted to contain key-shaped literals, checked by the secret-scanning job in
`.github/workflows/security.yml`. Currently one entry: the small-order Curve25519 points that
Ed25519 verification must refuse.
