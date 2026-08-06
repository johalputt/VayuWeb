# VayuWeb Cryptographic Agility and Post-Quantum Migration

Every cryptographic primitive VayuWeb uses today will be broken, deprecated, or embarrassing within
the lifetime this protocol is designed for. A naming system whose ownership proof is a signature
must therefore be able to change its signature scheme **without losing a single name**, and it
must be able to do so under time pressure, decades after the people who designed it have stopped
answering email.

This document specifies how. It is the single most important future-proofing artefact in the
repository, because it is the one thing that cannot be retrofitted: a record format without a
suite identifier is a record format that can never migrate.

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

**Status:** Draft — not yet implemented.

## 1. The rule

> **No primitive is named in the protocol. Only suites are, and every signed object carries the
> identifier of the suite that produced it.**

There is no "the VayuWeb signature algorithm". There is a `suite` field, a registry of suites, and a
rule for moving between them. An implementation that hard-codes Ed25519 anywhere outside the
suite-1 module is defective, and the conformance suite is written to catch it.

## 2. Threat, stated precisely

The usual framing — "harvest now, decrypt later" — **does not apply here**, and repeating it would
be sloppy. VayuWeb signatures protect integrity and authorship, not confidentiality. There is no
ciphertext to harvest; the registry is public by design.

The real risks are different and worth naming exactly:

**2.1 Name theft by forgery.** An adversary with a cryptographically relevant quantum computer
recovers a name-holder's private key from their public key — which is published in the registry,
because it must be — and signs a valid `TRANSFER`. Every name whose public key is visible is
exposed simultaneously. This is the critical risk, and it arrives for **every existing name at
once**, not gradually.

**2.2 Alternative-history presentation.** An adversary forges a chain to present to a node that
has no independent copy — a new node, or one under eclipse (threat T7). Peers holding the genuine
replicated history are not fooled, so this risk is bounded by replication, which is a real and
under-appreciated defence of the append-only design.

**2.3 Retroactive repudiation.** Once a scheme is broken, every signature ever made under it
becomes deniable: "that transfer was forged". This one cannot be fixed after the fact. It is
addressed only by anchoring — section 6.

Note what is *not* at risk: content integrity. Content is addressed by hash, and hash functions
degrade gracefully against quantum adversaries (Grover halves the security level; a 256-bit hash
retains 128 bits). The CID layer is comparatively future-proof; the signature layer is not.

## 3. Suite registry

Every signed object carries a `suite` field: a small unsigned integer, assigned only by VWIP,
never reused, never renumbered.

| Suite | Signature | Record hash | Key / signature bytes | Record limit | Status |
|---|---|---|---|---|---|
| 1 | Ed25519 | BLAKE2b-256 | 32 / 64 | 4,096 | **Launch default.** Fast, small, universally implemented. Not quantum-resistant. |
| 2 | Ed25519 **+** ML-DSA-65 (hybrid) | BLAKE2b-256 | 1,984 / 3,373 | 12,288 | Reserved — transition. Both signatures MUST verify; secure if *either* remains unbroken. |
| 3 | ML-DSA-65 | SHA3-256 | 1,952 / 3,309 | 12,288 | Reserved — post-quantum. FIPS 204. |
| 4 | SLH-DSA-SHAKE-128s | SHAKE-256 | 32 / 7,856 | 16,384 | Reserved — conservative fallback. FIPS 205. Hash-based, minimal assumptions, very large signatures. The break-glass suite if lattice assumptions fall. |

The **Record hash** column is the hash a record's `record_hash` uses, not the hash inside the
signature scheme. Suite 1 previously read `SHA-256` here, which disagreed with
[REGISTRY.md](REGISTRY.md) — it specifies BLAKE2b-256, "because Hypercore already uses it, so a
node needs one hash primitive" — with the conformance vectors, and with every implementation. The
specification that defines record bytes is authoritative for them, so this table was the error.
The reserved rows' hashes are proposals the activating VWIP settles, not commitments.

The **Key / signature bytes** and **Record limit** columns are the figures a verifier reads
instead of assuming; suite 2's are the concatenation of its two components, since 4.4 requires
both. `registry/src/suites.ts` holds the same table and a test compares the two, because a table
in code and a table in a document that drift apart are worse than either alone.

3.1 Suites 2, 3 and 4 are **reserved, not active**. They are specified now so that the record
format, the verification path and the conformance vectors can accommodate them from day one. A
reserved suite is activated by VWIP with an activation epoch, per Constitution Article 47.

3.2 **Size is the migration's real cost, and it is not small.** An Ed25519 public key is 32 bytes
and a signature 64. ML-DSA-65 is roughly 1,952 and 3,309. SLH-DSA-SHAKE-128s is 32 and about
7,856. A registry record grows by one to two orders of magnitude on migration. The record size
limits in [REGISTRY.md](REGISTRY.md) MUST therefore be expressed **per suite**, not as one global
constant, and the index and replication design must tolerate the larger figures. An
implementation that assumes 64-byte signatures anywhere is defective.

A verifier consequently checks the size **twice**: once before decoding, against the largest
limit any *active* suite admits, because `suite` is a field inside the record and cannot be read
until the bytes are parsed; and once after, against that record's own suite. Bounding the first
check by the largest *reserved* suite instead would hand an attacker several times the parsing
work per record for suites no key can sign with.

3.3 Suite 4 exists because suites 2 and 3 both rest on lattice assumptions. If those fall,
hash-based signatures remain, resting only on the hash function. It is deliberately the least
convenient option, and deliberately present.

## 4. Verification rules

4.1 A verifier MUST implement **every suite that has ever been active**, forever. The registry is
append-only; a 2026 record must still verify in 2126. Dropping support for a historical suite
silently invalidates history and is prohibited.

4.2 A verifier MUST reject a record whose `suite` it does not know. It MUST NOT skip the
signature, treat the record as unsigned, or accept it provisionally.

4.3 The bytes that get signed MUST include the suite identifier inside the domain-separation
prefix, so that a signature made under one suite cannot be replayed as another. The exact bytes
are specified in [REGISTRY.md](REGISTRY.md), which is authoritative for record encoding, and are
reproduced here so the two cannot drift:

```text
signing_input = "VayuWeb-Registry-Record-v1" || 0x00 || uint8(suite) || det_cbor(core)
```

An earlier revision of this clause showed a different prefix literal — `"vayuweb-record-v1"`,
with no `0x00` separator — which no implementation used and which would have produced signatures
REGISTRY.md's verifier rejects. The requirement was always the *structure*: the suite identifier
inside the domain separation. The literal belongs to the document that defines the bytes.

4.4 For hybrid suite 2, **both** component signatures MUST verify. Accepting either alone would
reduce the hybrid to whichever component an attacker prefers, which is the classic hybrid
implementation error.

4.5 Verification MUST be constant-time with respect to secret material and MUST NOT short-circuit
in a way that leaks which component of a hybrid failed.

## 5. Migration

### 5.1 Downgrade protection

A name's suite MUST move **forward only**. Once a name's record is at suite *n*, no later record
for that name may specify a suite lower than *n*. This is checked as an ordinary validation rule
against the previous record via `prevHash`, and it is what stops an adversary who breaks suite 1
from downgrading a suite-3 name back to a scheme they can forge.

### 5.2 The three phases

**Phase A — Dual-capability.** Every implementation learns to verify the target suite before any
name uses it. Activation of the suite for *signing* is a separate, later VWIP. Verify-before-sign
is not a courtesy; a network where some nodes cannot verify new records partitions the registry.

**Phase B — Hybrid, opt-in then default.** Names move to suite 2. Security holds if *either*
component survives, which means the migration itself is safe even if the target scheme is later
found weak. This is why the path goes through a hybrid rather than jumping to suite 3.

**Phase C — Post-quantum only.** Suite 1 signing is retired. Suite 1 *verification* is retained
permanently, per 4.1, because history does not stop needing to verify.

### 5.3 Migration is a key rotation

Moving suites means generating a new keypair and signing the change with the **old** key, using
the existing rotation machinery in Constitution Article 34 — no new mechanism, no special case.
The last act of a suite-1 key is to authorise its suite-3 successor.

### 5.4 Names whose holders never migrate

The honest problem. Many holders will not act, and their names will still be secured by a broken
scheme.

- A resolver MUST surface a name's suite and warn where it is deprecated.
- Renewal (one year, per [NAMES.md](NAMES.md)) is a natural forcing point: a VWIP MAY require the
  target suite at renewal, giving every active holder at most twelve months to comply.
- VayuWeb MUST NOT auto-migrate a name. Rotating someone's key without their signature means a party
  other than the holder can change ownership, which Constitution Article 11 forbids and which
  would be a far worse outcome than a stale suite.
- A name whose holder is gone will lapse on its own schedule. That is the designed behaviour and
  it needs no special handling.

### 5.5 Emergency

If a suite is catastrophically broken with no warning, Constitution Article 57 governs: emergency
powers exist, are narrow, and **sunset automatically**. The emergency action available is to
freeze `TRANSFER` operations for affected suites — refusing changes of ownership while leaving
resolution working — so that a forged transfer cannot land while the network migrates. Freezing
resolution instead would break every site to protect a minority of names, which is the wrong
trade.

## 6. Anchoring against retroactive repudiation

Risk 2.3 cannot be fixed after a break, only before it. The defence is to make the *ordering* of
history provable by hashes rather than signatures, since hashes survive quantum adversaries.

6.1 The registry SHALL publish periodic **checkpoints**: a hash of the log state at a given
length, signed under the then-current suite.

6.2 Checkpoints SHOULD be anchored externally — published where they cannot be retroactively
altered, by whatever durable public medium exists at the time. The specification deliberately does
not name a medium, because naming one in 2026 would embed a dependency that will not outlive the
decade.

6.3 Anchoring is what lets a reader in 2126 distinguish "this record existed in 2030" from "this
record was forged in 2126 by someone who broke the 2030 signature scheme". Without it, a break
retroactively makes the entire history deniable.

6.4 The anchor set MUST be plural. A single anchoring service is a chokepoint under Constitution
Article 4, and would additionally become the arbiter of history.

## 7. Beyond signatures

**7.1 Hashes.** CIDs are multihash-encoded, so hash agility is already structural. Implementations
MUST NOT assume SHA-256 and MUST carry the algorithm from the CID rather than inferring it.

**7.2 Proof-of-work.** Argon2id parameters change only by VWIP, and **old proofs MUST remain
verifiable forever** — see [PROOF-OF-WORK.md](PROOF-OF-WORK.md). A parameter change is not a
suite change and does not invalidate history.

**7.3 Key storage.** Platform keystores change. `internal/crypto`-style isolation means the
storage backend is replaceable without touching the record format.

**7.4 Transport.** Hypercore, Hyperswarm and IPFS are young, and at least one of them will not
survive a century. The registry's **semantics** — a signed, append-only, verifiable sequence of
records — are what the specification defines; the substrate is an implementation choice behind an
interface. A VWIP replacing the substrate must preserve the semantics and the historical record,
and must not require a single name to be re-registered.

## 8. Conformance

1. No primitive is referenced outside its suite module (static check).
2. A record with an unknown `suite` is rejected, never accepted or skipped.
3. A suite-*n* record followed by a suite-*(n−1)* record for the same name is rejected.
4. A hybrid record with one valid and one invalid component signature is rejected.
5. Signing inputs for the same record under two suites differ (domain separation holds).
6. Test vectors exist for every suite, including reserved ones, and verify offline.
7. No code path assumes a 32-byte key or a 64-byte signature.

## 9. What this does not claim

- It does not claim VayuWeb is quantum-resistant today. Suite 1 is not, and suites 2 to 4 are
  reserved rather than active.
- It does not predict when a cryptographically relevant quantum computer will exist. The design
  assumes only that one eventually might, which is sufficient to justify the mechanism.
- It does not claim migration will be painless. Records grow by one to two orders of magnitude,
  and holders who do not act will lose their names on the ordinary schedule.
- It does not claim the anchoring in section 6 exists yet. It does not.

## See also

- [Registry specification](REGISTRY.md) — the record format that carries `suite`, the per-suite size limits, and the downgrade check
- [Naming and TLD policy](NAMES.md) — renewal as the migration forcing point
- [Longevity review](../LONGEVITY.md) — the non-cryptographic future-proofing
- [The VayuWeb Constitution](../../constitution/CONSTITUTION.md) — Articles 11, 34, 47, 57
