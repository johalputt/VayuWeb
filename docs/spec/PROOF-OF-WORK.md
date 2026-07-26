# WebX Proof-of-Work Specification

Status: Draft — not yet implemented.

This document specifies the anti-squatting proof-of-work (PoW) that a WebX registry
operation MUST carry. It defines the construction, the difficulty function, the
verification rule, the renewal rule, and the process by which parameters change. Record
structure and log semantics are owned by [REGISTRY.md](REGISTRY.md); label grammar is owned
by [NAMES.md](NAMES.md). This document does not restate either.

## Goal

WebX has no registrar, no invoice, no token and no treasury. There is therefore no price
signal to make hoarding ten thousand names unattractive. The PoW exists to supply that
signal in the only currency a permissionless network can charge without a payment rail:
wall-clock compute that is burned and paid to nobody.

The design target is asymmetric. Registering **one** name SHALL cost a few seconds of a
single CPU core — an amount an ordinary user will not notice and will not be asked to
understand. Registering **ten thousand** names SHALL cost far more than ten thousand times
that, because the difficulty rises with the registration rate of the TLD being farmed. The
PoW is a rate limiter with a memory of the last thirty days, not a fee.

Two non-goals are stated plainly. The PoW does not confer any claim of right, and it does
not create a scarce asset. No proof is transferable, no proof accrues value, and the work
performed has no use outside validating the one operation it is bound to.

## Why Memory-Hard

A hash-only PoW (SHA-256 preimage search) would price a data centre and a laptop very
differently: ASIC and GPU implementations of a compact hash beat a general-purpose core by
three to five orders of magnitude. A squatting operation with a rack would then face a cost
of effectively zero while an individual registrant waited.

A memory-hard function narrows that gap. Argon2id at 64 MiB per evaluation makes the
bottleneck DRAM bandwidth and capacity rather than gate count. A GPU with 24 GiB of memory
can hold roughly 380 concurrent evaluations, and an ASIC gains little because it must still
buy and address the same memory. The realistic attacker advantage is one to two orders of
magnitude, not five. That is not equality, and this specification does not claim equality;
it claims that the ratio is small enough that the rate-based difficulty term dominates.

## Construction

The proof uses **Argon2id, version 0x13 (RFC 9106)** with these normative parameters:

```text
algorithm identifier : "argon2id-v19-m65536-t2-p1"
memory (m)           : 65536 KiB (64 MiB)
iterations (t)       : 2
parallelism (p)      : 1
tag length           : 32 bytes
```

64 MiB is chosen because it is the largest working set that a low-end mobile device and a
2015-era laptop can both allocate without swapping, while still being large enough that
per-evaluation GPU parallelism is bounded by memory rather than by cores. Two iterations is
the minimum RFC 9106 permits for Argon2id and keeps a single evaluation in the tens of
milliseconds. Parallelism of one makes the cost of a single evaluation independent of the
verifier's core count, so difficulty means the same thing everywhere.

The `powProof` field of a record is the triple `{alg, nonce, bits}`, where `nonce` is 16
bytes and `bits` is the declared difficulty as an unsigned integer.

Salt derivation binds the proof to exactly one record:

```text
preimage = "webx-pow-v1" || canonical(record without sig and without powProof.nonce)
salt     = SHA-256(preimage)[0..16]        // first 16 bytes
tag      = Argon2id(password = nonce, salt = salt, m, t, p, taglen = 32)
```

`canonical()` is the deterministic encoding defined in [REGISTRY.md](REGISTRY.md). Because
the preimage covers `name`, `tld`, `ownerKey`, `seq`, `notBefore`, `notAfter`, `records` and
`prevHash`, a proof cannot be moved to another name, another owner, another term or another
position in the log. It cannot be precomputed for a name a party does not yet intend to
claim under a specific key, and it cannot be replayed after any field changes.

The output test is a leading-zero-bit test on the tag, read most-significant-bit first:

```text
valid(tag, D) := the first D bits of tag are all zero
```

A registrant searches `nonce` until the test passes. The expected number of evaluations is
`2^D`, geometrically distributed, so an unlucky registrant may pay several times the mean.
Clients SHOULD display progress rather than a countdown for this reason.

## Difficulty Function

Required difficulty `D` is a function of the label length and of how fast the target TLD has
been consuming names. Both inputs are derivable from the log alone, so every peer computes
the same `D` without coordination.

```text
function required_bits(label, tld, notBefore):
    L = length(label)                       # characters, per NAMES.md grammar

    if      L <= 2:  base = 10
    else if L == 3:  base = 9
    else if L == 4:  base = 8
    else if L <= 6:  base = 7
    else if L <= 9:  base = 6
    else if L <= 15: base = 5
    else:            base = 4               # 16..63 characters

    epoch = floor(notBefore / 3600)         # 1-hour difficulty epochs
    window_start = (epoch * 3600) - 2592000 # trailing 30 days
    n = count of accepted registration and renewal operations in `tld`
        with notBefore in [window_start, epoch * 3600)

    if n < 512: rate = 0
    else:       rate = min(8, floor(log2(n / 512)))

    return min(20, base + rate)
```

Length weighting exists because short labels are the ones worth hoarding; the schedule makes
a two-character name cost 64 times a fifteen-character name. The rate term is the
superlinear part: every doubling of a TLD's thirty-day registration volume above 512 adds
one bit, doubling the cost of every subsequent registration in that TLD. A bulk registrant
therefore raises the price of its own remaining work, and it raises it for the whole
namespace it is farming rather than only for itself — a deliberate trade discussed under
[Limits](#limits).

The 1-hour epoch quantisation exists so that two peers with slightly different clocks agree
on `n`. A verifier MUST accept a proof whose difficulty was computed for the epoch of
`notBefore` or for the immediately preceding epoch, which absorbs propagation delay without
widening the window enough to be farmable.

`min(20, ...)` is a ceiling, not a target. Twenty bits is roughly a million evaluations —
hours of CPU — and exists only to stop a runaway land rush from making a TLD permanently
unusable.

### Worked Examples

Both examples use an indicative reference cost of **70 ms** per Argon2id evaluation on one
core of a 2020-era laptop CPU. That figure is illustrative and is NOT normative; only the
parameters and `required_bits` are normative.

A 3-character name in a busy TLD with 6,400 registrations in the trailing 30 days:

```text
base = 9                       # L == 3
n    = 6400
rate = floor(log2(6400 / 512)) = floor(log2(12.5)) = 3
D    = 9 + 3 = 12
work = 2^12 = 4096 evaluations ~= 287 s (about 5 minutes)
```

A 12-character name in a quiet TLD with 300 registrations in the trailing 30 days:

```text
base = 5                       # 10 <= L <= 15
n    = 300                     # below 512
rate = 0
D    = 5 + 0 = 5
work = 2^5 = 32 evaluations ~= 2.2 s
```

The second case is the ordinary one, and it is why the client can simply say "preparing your
registration" and finish before the user looks away. If that same quiet TLD absorbed 10,000
bulk registrations, `n` would reach roughly 10,300, `rate` would climb to 4, and each further
name would cost 512 evaluations — about 36 s — a 16-fold increase over the opening price.

## Verification

Verification is one Argon2id evaluation and one bit test, regardless of `D`. The verifier
recomputes the salt from the record's canonical bytes, evaluates the tag with the submitted
nonce, and checks the leading zero bits. The verifier MUST independently recompute
`required_bits` and MUST reject the record if `powProof.bits` is less than the recomputed
value, or if the tag does not satisfy `powProof.bits`. A declared difficulty higher than
required is valid; over-payment is harmless.

The zero-bit test MUST be implemented over the full fixed-length tag with no early exit, so
that verification time does not vary with how close a rejected candidate came to passing.
The tag is not secret, so this is a hygiene requirement rather than a defence against a
concrete attack, but timing-uniform comparison costs nothing and is therefore mandatory.

The honest cost note: 70 ms per record is cheap for one record and is not cheap for a
full-history replay of a large log. A peer that has already verified a prefix of the log
MAY trust its own signed local checkpoint and re-verify only the suffix, as described in
[REGISTRY.md](REGISTRY.md). A peer that has never verified the history and wants full
assurance MUST pay the full cost once.

## Renewal

A renewal is a new signed operation with an incremented `seq` and a new `notBefore`, and it
MUST carry a fresh proof at the difficulty in force at renewal time. Renewal is not free
because a name held for ten years should cost ten years of the anti-squatting price, not one.
Without this rule, a squatter would pay once and hold a portfolio forever, which is exactly
the outcome the PoW exists to prevent. It also means that if a TLD's difficulty has risen,
the cost of keeping a large speculative portfolio rises with it, while the cost of keeping
one name stays in the range of seconds to minutes per year.

Renewal work is bound to the renewal record's own canonical bytes, so a proof from the
previous term cannot be reused. Renewal windows, grace and quarantine are specified in
[REGISTRY.md](REGISTRY.md).

## Parameter Updates

Every value in this document — the Argon2id parameters, the length schedule, the rate
formula, the window, the epoch and the ceiling — is fixed except by a ratified WXIP under
[WXIP-0000.md](WXIP-0000.md). No peer, client or TLD steward may adjust difficulty
unilaterally, and there is no operator with authority to do so.

A parameter change SHALL be introduced as a new algorithm identifier, activated at a stated
log height rather than a wall-clock time, so that activation is unambiguous during
replication. Implementations MUST retain every historical parameter set and every historical
difficulty schedule indefinitely: a record accepted under the rules in force at its height
remains valid forever, and a peer that cannot verify old proofs cannot verify the log. Old
proofs MUST NOT be re-verified against new parameters, and a WXIP that would invalidate
previously accepted records MUST be rejected as out of scope.

## Limits

Proof-of-work is a speed bump. It should be read as one.

A funded adversary can rent a few thousand cores for a day and register a great many names
before the rate term catches up, because the rate term looks backwards over thirty days and
so responds with a lag. The ceiling of twenty bits caps how far the network can push back.
Memory-hardness narrows but does not close the gap between commodity
hardware and purpose-built hardware. Nothing here prevents an attacker from spreading registrations across many
keys and many TLDs to stay under the rate threshold in each, and nothing here distinguishes
a squatter from an enthusiastic early adopter — the registry deliberately cannot tell them
apart, and under the first-valid-signature-wins doctrine it does not try.

The rate term also has a cost borne by the innocent: a genuine surge of legitimate interest
in a TLD raises the price for everyone registering in it, not only for the party causing the
surge. This is accepted because the alternative — per-key rate limiting — is defeated by
generating keys, which is free.

The real defences are structural, not computational. Names are cheap to abandon: a hoarded
name expires after one year, and its holder must pay fresh work every year to keep it, so a
portfolio decays unless it is continuously funded. The namespace is plural: twelve launch
TLDs mean a squatter cannot corner "the" name for anything, and the WXIP process can ratify
more. And the resolution layer is not scarce — nothing about holding a name grants
attention, links or traffic. A more complete accounting of what this defends against and
what it does not is in [THREAT-MODEL.md](../THREAT-MODEL.md).

Status: Draft against the pre-implementation WebX design. No implementation exists; every
parameter here is subject to revision by WXIP before the first release.

See also:

- [REGISTRY.md](REGISTRY.md)
- [NAMES.md](NAMES.md)
- [WXIP-0000.md](WXIP-0000.md)
- [THREAT-MODEL.md](../THREAT-MODEL.md)
