# VayuWeb Registry Specification

This document specifies the VayuWeb registry: the append-only log that holds name ownership, the
index over it, the record format, the signed bytes, the six operations, and the rules by which
every peer independently reaches the same answer. Nothing here has been implemented.

Label grammar lives in [docs/spec/NAMES.md](NAMES.md), difficulty derivation in
[docs/spec/PROOF-OF-WORK.md](PROOF-OF-WORK.md), resolver behaviour in
[docs/spec/RESOLUTION.md](RESOLUTION.md), none of it restated here.

## Scope

The registry answers two questions: is this signature valid, and is this name free. It is not a
trademark court, and an implementation that adds a privileged writer, an admin key or a seizure
path is not a VayuWeb registry.

## The Log

The registry is a single logical append-only sequence, one record per entry. Entries are never
rewritten or deleted; a name changes by appending.

Hypercore is single-writer, so the logical registry SHALL be materialised as a deterministic
linearisation over the per-peer input Hypercores a node knows, in the manner of Autobase: a peer
appends only to its own input log, and every node computes the same merged order from the same
inputs and causal links. Validity never depends on which input log carried a record, and "log
ordering" here means position in that linearised view. Nodes holding different input sets can
compute different orders; that is the partition case, handled in [Convergence](#convergence)
rather than assumed away. Each input log is covered by its own Hypercore merkle tree, so an
entry can be proven to belong to a log at a given length without holding the rest of it.

## The Index

The Hyperbee index is a B-tree whose blocks are appended to a Hypercore, so every tree node is
covered by that log's merkle tree. A lookup is therefore verifiable: a peer serves the
root-to-leaf path plus inclusion proofs, and the requester checks them against a tree root it
already trusts. The index is derived state: it SHALL be rebuildable from the log alone, a node
detecting corruption SHALL rebuild rather than repair, and nothing in it is authority.

## Record Schema

A record is a CBOR map with text keys, spelled exactly as below. Every field is REQUIRED unless
marked otherwise. JSON renderings encode byte strings as unpadded base64url.

| Field | Type | Encoding | Constraints |
| --- | --- | --- | --- |
| `version` | uint | CBOR uint | `1` at launch; a verifier MUST reject a major version it does not implement. |
| `op` | text | ASCII | `REGISTER`, `UPDATE`, `RENEW`, `TRANSFER`, `RELEASE` or `REVOKE`. |
| `name` | text | NFC, lowercase ASCII | 1-63 bytes from `[a-z0-9-]`, per [docs/spec/NAMES.md](NAMES.md). |
| `tld` | text | ASCII, no leading dot | One of the twelve launch TLDs; any other is rejected. |
| `ownerKey` | bstr | 32 bytes | Ed25519 public key: incoming owner for `TRANSFER`, current owner otherwise. |
| `seq` | uint | CBOR uint | 0 for `REGISTER`, `prev.seq + 1` otherwise; max 2^32-1. |
| `notBefore` | uint | Unix seconds, UTC | Second at which the record takes effect. |
| `notAfter` | uint | Unix seconds, UTC | Expiry; computed per operation for `REGISTER` and `RENEW`, else copied from `prev`. |
| `records` | array | array of maps | 0-32 entries; schema below. |
| `powProof` | map or null | see below | REQUIRED for `REGISTER` and `RENEW`, CBOR `null` otherwise. |
| `prevHash` | bstr | 32 bytes | Record hash of the previous accepted record; 32 `0x00` when `seq` is 0. |
| `sig` | bstr | 64 bytes | Ed25519 signature over the signing input. |
| `coSig` | bstr, optional | 64 bytes | `TRANSFER` only: incoming owner's signature over the same input. |

`op` and `coSig` extend the field list in [docs/ARCHITECTURE.md](../ARCHITECTURE.md). Inferring
the operation from a field diff is ambiguous, and an ambiguous validation rule is a fork waiting
to happen. `coSig` exists because a transfer signed only by the outgoing owner can send a name
to a key nobody controls, indistinguishable from a burn.

A `records` entry is a map with keys `type`, `value`, and optional `ttl` (uint, 60-86400,
default 3600, advisory):

| `type` | Value type | Constraints |
| --- | --- | --- |
| `peer` | bstr, 32 bytes | HyperDHT public key to dial for this name. |
| `ipns` | text | IPNS name as a base36 `libp2p-key` CIDv1, 1-128 bytes. |
| `cid` | bstr | Binary CIDv1, 1-64 bytes; rendered base32 in JSON. |
| `txt` | text | 1-255 bytes, UTF-8, no control characters below U+0020. |
| `alias` | text | `label.tld` naming another VayuWeb name; resolvers MUST follow at most 3 hops and MUST fail on a cycle. |

At most one `alias` per record, and an `alias` MUST NOT coexist with another entry type, because
a name is either a pointer or a destination. Unknown `type` values are stored and replicated
unchanged but MUST NOT be acted upon.

`powProof` is a map with keys `alg` (text, `argon2id`), `m` (uint, KiB of memory), `t` (uint,
iterations), `p` (uint, lanes), `salt` (bstr, 16 bytes), `nonce` (uint), and `bits` (uint,
claimed difficulty in leading zero bits). The digest is NOT stored: every verifier recomputes
it, so there is nothing to forge and 32 bytes per record are saved.

## Canonical Serialisation and Signing

Signing bytes are **deterministic CBOR** per RFC 8949 §4.2.1: shortest-form integer and length
encoding, definite-length maps and arrays, map keys sorted by encoded byte sequence. It is
chosen over canonical JSON because number formatting, string escaping and binary-as-base64 each
have several defensible JSON spellings and exactly one CBOR spelling, and because byte strings
are native, so keys, hashes and signatures never round-trip through text.

```text
signing_input = "VayuWeb-Registry-Record-v1" || 0x00 || det_cbor(core)
record_hash   = BLAKE2b-256("VayuWeb-Registry-Hash-v1" || 0x00 || det_cbor(full))
```

`core` is the record map with `sig` and `coSig` removed; `full` is the complete map including
them. Each prefix is the literal ASCII string (26 and 24 bytes) followed by one `0x00`, so a
registry-record signature can never be replayed over another VayuWeb structure and can never be
read as a hash preimage; every other signed structure SHALL use a distinct prefix. BLAKE2b-256
is chosen because Hypercore already uses it, so a node needs one hash primitive.

`sig` is Ed25519 (RFC 8032) over `signing_input`. Verifiers MUST verify strictly: reject
non-canonical encodings of `S`, small-order public keys, and small-order `R`. Permissive
verification makes a signature malleable and therefore the record hash malleable, which hands an
attacker a free grinding surface at the tie-break.

A peer MUST NOT re-serialise a record it did not author: received bytes are stored and
replicated verbatim, so a record carrying unknown fields still verifies downstream. Received
bytes MUST themselves be deterministic CBOR, since any other encoding would admit two byte
strings for one record.

## Operations

Common preconditions, checked before any operation-specific rule: deterministic CBOR encoding;
at most 4096 bytes; `version` implemented; `name` and `tld` satisfying the grammar and the
ratified TLD set; `sig` verifying against the relevant key.

Chain rules, required by every operation except `REGISTER`: a previous accepted record `prev`
for `name.tld` still inside its term or grace period, `seq == prev.seq + 1`,
`prevHash == record_hash(prev)`, `notBefore >= prev.notBefore + 300`, `sig` verifying against
`prev.ownerKey`, and — except for `TRANSFER` — `ownerKey == prev.ownerKey`. The 300-second
minimum interval caps churn at 288 records per name per day, about 1.1 MiB of log at worst, so
update-flooding is expensive and no real editor is inconvenienced.

### REGISTER

Preconditions: `seq == 0`; `prevHash` all-zero; `powProof` present; `name.tld` free, meaning
never registered or past its `notAfter` plus 30 days of grace plus 30 days of quarantine.

Validation, in order:

1. Common preconditions.
2. `seq == 0` and `prevHash` is the all-zero hash.
3. `notAfter - notBefore == 31536000` exactly.
4. `notBefore` is at most 300 seconds ahead of the verifier's clock — beyond that the record is
   deferred, not rejected, since clocks drift — and at most 86400 seconds behind it, which stops
   a squatter pre-signing dated registrations against a future release.
5. The index shows `name.tld` free at this point in the log.
6. `powProof` verifies at or above the difficulty for this label length and this TLD's
   trailing-30-day registration rate, per [docs/spec/PROOF-OF-WORK.md](PROOF-OF-WORK.md).
7. `records` satisfies the entry rules.

Effect: `name.tld` is owned by `ownerKey` until `notAfter`.

### UPDATE

Preconditions: a live `prev`; `notAfter == prev.notAfter`; `powProof` null.

Validation order: common preconditions, chain rules, `notAfter` equality, entry rules. Effect:
`records` is replaced wholesale; there is no partial update.

### RENEW

Preconditions: `prev` live or within its 30-day grace period; `powProof` present; the renewal
window open, meaning `notBefore >= prev.notAfter - 5184000` (60 days).

Validation order: common preconditions, chain rules, window check, proof-of-work, then
`notAfter == max(prev.notAfter, notBefore) + 31536000`, so renewing early extends from the
existing expiry and never truncates a term, while renewing inside grace restarts from the moment
of renewal. A `RENEW` MAY also change `records`.

Effect: the term extends by one year. Proof-of-work is required again, which makes holding ten
thousand names a recurring annual cost rather than a one-off.

### TRANSFER

Preconditions: a live `prev`; `ownerKey` is the incoming key and differs from `prev.ownerKey`;
`coSig` present and verifying against `ownerKey` over the same signing input;
`notAfter == prev.notAfter`; `powProof` null.

Validation order: common preconditions, chain rules, outgoing signature, countersignature,
`notAfter` equality. Effect: ownership moves and the term is unchanged. Transfer to a key whose
secret is unknown is impossible, because the countersignature cannot be produced.

### RELEASE

Preconditions: a live `prev`; `records` empty; `notAfter == notBefore`; `powProof` null.

Validation order: common preconditions, chain rules, empty `records`, `notAfter` equality.
Effect: the name expires at once, enters the 30-day quarantine, then returns to the open pool.
Grace is skipped, since the owner has said they are done; quarantine is not, because its purpose
is to stop a watcher front-running the release.

### REVOKE

Preconditions: a live `prev`; `records` empty; `notAfter == prev.notAfter`; `powProof` null.

Validation order: common preconditions, chain rules, empty `records`, `notAfter` equality.
Effect: the name stops resolving at once, no later record for `name.tld` signed by
`prev.ownerKey` is ever accepted, and the name stays frozen for the rest of its term plus 30
days of quarantine before returning to the open pool.

`REVOKE` is a deadman switch for a compromised key, and it is honest about its limit: a registry
with no identity layer cannot tell an owner from a thief holding the same key, so revocation
destroys rather than recovers. There is no recovery key and no appeal.

## Sequence Numbers and Replay Protection

Per name, `seq` starts at 0 and increases by exactly one, and `prevHash` binds each record to
the exact bytes of its predecessor, so one name's history is a hash chain inside the global log.
No record can be reordered, skipped or silently dropped: a gap shows as a `seq` discontinuity
and a substitution breaks `prevHash`.

Replay of an accepted record fails because `seq` is no longer next; replay into a different name,
TLD or protocol version fails because all three are inside the signing input; replay into another
VayuWeb structure fails on the domain separation prefix. A duplicate arrival is not an error — a
peer receiving a record it already holds MUST drop it silently, and only a different record at
the same `seq` is a conflict.

## Convergence

Two peers on either side of a partition can each accept a valid first registration of the same
free name. The rule, stated for the whole project in [docs/WHITEPAPER.md](../WHITEPAPER.md),
applies to any conflicting pair at the same `seq` for one `name.tld`:

1. If exactly one is valid, that one wins.
2. Otherwise, if the linearised order places one strictly before the other on every peer holding
   both, the earlier wins.
3. Otherwise, the smaller `record_hash`, as a big-endian unsigned integer, wins.

The loser's record and everything chained onto it become void on merge, and a client MUST
surface that rather than hide it behind a silent refresh. Rule 3 is grindable in principle — an
attacker expecting a tie can vary `powProof.nonce` to lower their hash — but each attempt costs
a full proof-of-work and it only matters in the undecidable case. It is recorded as a weakness
in [docs/THREAT-MODEL.md](../THREAT-MODEL.md).

## Verification

```text
verify(rec, bytes, state):
  if bytes != det_cbor(rec):                  reject NON_CANONICAL
  if len(bytes) > 4096:                       reject TOO_LARGE
  if rec.version != 1:                        reject UNSUPPORTED_VERSION
  if rec.op not in OPS:                       reject UNKNOWN_OP
  if not grammar_ok(rec.name):                reject BAD_LABEL
  if rec.tld not in RATIFIED_TLDS:            reject UNKNOWN_TLD
  if len(rec.records) > 32:                   reject TOO_MANY_RECORDS
  if not entries_ok(rec.records):             reject BAD_RECORD_ENTRY

  input = "VayuWeb-Registry-Record-v1" || 0x00 || det_cbor(strip(rec, sig, coSig))
  prev  = state.current(rec.name, rec.tld)     // may be absent

  if rec.op == REGISTER:
      if rec.seq != 0 or rec.prevHash != ZERO32:   reject BAD_CHAIN
      if prev exists and not fully_released(prev): reject NAME_TAKEN
      if rec.notAfter - rec.notBefore != 31536000: reject BAD_TERM
      if rec.notBefore > now + 300:                defer  CLOCK_SKEW
      if rec.notBefore < now - 86400:              reject BACKDATED
      if not ed25519_strict(rec.ownerKey, input, rec.sig): reject BAD_SIG
      if not pow_ok(rec, difficulty(rec.name, rec.tld, state)): reject BAD_POW
      return accept

  if prev is absent:                          reject NO_PREDECESSOR
  if rec.seq != prev.seq + 1:                 reject BAD_SEQ
  if rec.prevHash != record_hash(prev):       reject BAD_CHAIN
  if rec.notBefore < prev.notBefore + 300:    reject TOO_SOON
  if revoked(rec.name, rec.tld):              reject REVOKED
  if not ed25519_strict(prev.ownerKey, input, rec.sig): reject BAD_SIG
  if rec.op != TRANSFER and rec.ownerKey != prev.ownerKey: reject BAD_OWNER
  if rec.op != RENEW and rec.powProof != null:             reject UNEXPECTED_POW

  switch rec.op:
    UPDATE:   require rec.notAfter == prev.notAfter
    RENEW:    require rec.powProof != null
              and rec.notBefore >= prev.notAfter - 5184000
              and rec.notAfter == max(prev.notAfter, rec.notBefore) + 31536000
              and pow_ok(rec, difficulty(rec.name, rec.tld, state))
    TRANSFER: require rec.ownerKey != prev.ownerKey
              and rec.notAfter == prev.notAfter
              and ed25519_strict(rec.ownerKey, input, rec.coSig)
    RELEASE:  require rec.records == [] and rec.notAfter == rec.notBefore
    REVOKE:   require rec.records == [] and rec.notAfter == prev.notAfter
  return accept
```

`state.current` reflects the verifier's own linearised log only. Verification makes no network
call: a verifier that asks another peer for a verdict has replaced verification with trust.

## Index Keyspace Layout

Hyperbee keys are byte strings ordered lexicographically. The registry SHALL use a one-byte
namespace tag, `0x00` separators, and components that contain no `0x00` (guaranteed by the label
grammar and by fixed-width integers):

```text
0x6E 00 <tld> 00 <label>                 -> current record pointer {logIndex, seq, notAfter}
0x6F 00 <ownerKey:32> 00 <tld> 00 <label> -> presence marker (names by owner)
0x78 00 <notAfter:u64be> 00 <tld> 00 <label> -> expiry queue
0x72 00 <tld> 00 <notBefore:u64be> 00 <label> -> registration-rate window
```

The TLD comes first and the label follows, reversing how a human writes `name.tld`, for three
reasons: difficulty depends on a TLD's registration rate over the trailing 30 days, and a TLD
prefix makes that one bounded range scan instead of a full-tree walk; a TLD ratified later by
VWIP occupies a fresh disjoint range, so no existing key moves; and auditing one TLD becomes a
contiguous read. The expiry queue is keyed by big-endian `notAfter`, so names expiring before a
given instant form a prefix range and a node advances grace and quarantine without a full scan.

## Checkpoints, Compaction and Light Clients

The log is never truncated: truncation would invalidate the merkle tree that makes entries
self-authenticating and destroy the history that lets a newcomer verify ownership from first
principles. Storage therefore grows monotonically. There is no pruning scheme at launch; adding
one requires a VWIP and is left here as an open problem.

Every 10,000 entries a node SHALL compute a checkpoint: `{logLength, treeRoot, indexRoot,
liveNames}`. Anyone can derive it from the same log, so it is not an authority and carries no
signature that would make it one. It is a comparison aid: two peers agreeing on `treeRoot` at a
`logLength` have identical history to that point, reducing a divergence check to 32 bytes.

A light client verifies one name without the full history:

1. Obtain a `logLength` and `treeRoot` from one or more peers.
2. Fetch the Hyperbee root-to-leaf path for the name's key with Hypercore inclusion proofs for
   each block and check them against `treeRoot`, proving presence *or absence* at that length.
3. Fetch the name's record chain, `seq` 0 to current, and verify signatures, `prevHash` links
   and proof-of-work — a handful of records, not a share of the whole log.

What this does not prove is freshness. A light client cannot tell that the `logLength` it was
handed is current, so a peer withholding recent entries can present a stale but internally
consistent view. The mitigations are partial — query several independent peers, take the
greatest verified length, and show that length and the observation time with every answer — and
nothing here solves it.

## Epochs

The Constitution and VWIP-0000 both schedule changes against an *activation epoch*, and both
treat "Epoch" as a defined unit. This section defines it.

An **Epoch** is a numbered interval of the registry's life, not of the calendar. Epoch 0 begins
at the genesis entry. An epoch boundary is crossed when **both** of the following hold:

1. at least `2,592,000` seconds (30 days) of `notBefore` time has elapsed since the boundary that
   opened the current epoch, measured at the median of the last 1,000 accepted records rather
   than from any single clock; and
2. at least one checkpoint has been computed since that boundary.

Requiring both conditions is deliberate. Time alone would let a peer with a wrong or hostile
clock disagree with the network about which epoch it is in — the weakness recorded in
[LONGEVITY.md](../LONGEVITY.md) section 3. Log progress alone would stall the epoch counter
whenever registration activity dropped, which over a century is a near certainty. Taking the
median `notBefore` of a thousand records makes a single lying clock irrelevant, because moving
the median requires controlling the majority of recent registrations, which proof-of-work already
prices.

Consequences, all normative:

- The current epoch number is **derived from the log**, identically by every peer, and is never
  taken from a peer's own clock or from any announcement.
- A Standards Track activation epoch MUST be at least **two epochs** beyond the epoch in which
  the VWIP reached Accepted — roughly sixty days minimum — so that deployment has time to
  propagate before behaviour changes. Article 47.3 forbids a silent breaking change; this is the
  interval that makes the prohibition operable.
- A peer that has not yet reached the activation epoch MUST continue to apply the previous rules.
  A peer that has reached it MUST apply the new ones. Because the number is derived from shared
  log state rather than from wall-clock time, peers transition consistently rather than smeared
  across whatever their clocks say.
- Epoch numbers are monotonic and never reused, including across a substrate migration.

The residual: a peer under eclipse sees whatever epoch its attacker's log says it is in. That is
the same limitation as freshness above, with the same partial mitigation — query several
independent peers and take the greatest verified length — and it is not solved here either.

## Size Limits

A serialised record SHALL be at most 4096 bytes, the `records` array SHALL hold at most 32
entries, and no entry value exceeds 512 bytes. At 4 KiB per record, one million names averaging
four records each is roughly 16 GiB of log — large, but within reach of a volunteer peer, which
is the premise of full replication. A verifier MUST reject an oversized record rather than
truncate it, and raising either number requires a ratified VWIP, per
[docs/spec/VWIP-0000.md](VWIP-0000.md).

## Worked Example

A registration of `atlas.vayu` as JSON, byte strings in unpadded base64url.

```json
{
  "version": 1,
  "op": "REGISTER",
  "name": "atlas",
  "tld": "vayu",
  "ownerKey": "1cO7GV1wCsncBtdw9y6Bo4X8sZg5YfRIQMhlWcVohks",
  "seq": 0,
  "notBefore": 1782518400,
  "notAfter": 1814054400,
  "records": [
    { "type": "peer", "value": "YQ4UiKrrd_gkoNTZeEHTPGt-aIZPPLp-WghM6NjNr2U", "ttl": 3600 },
    { "type": "ipns", "value": "k51qzi5uqu5dkkciu33khkzbcmxtyhn376i1e83tya8kuy7z9euedzyr5nhoew" },
    { "type": "txt", "value": "v=vayuweb1; contact=atlas@example.invalid" }
  ],
  "powProof": {
    "alg": "argon2id",
    "m": 262144,
    "t": 3,
    "p": 1,
    "salt": "XaGvK-1McJRNX-agVfElbQ",
    "nonce": 41827366,
    "bits": 22
  },
  "prevHash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "sig": "Uh776MCNj1iWUJDLToU9-pHOMasXTvZNhiA9MzH2yDHzQjSPhRSOICQlslN0FCMn313ju_XvM-3oB2CsgXIVjA"
}
```

A subsequent `UPDATE` would carry `seq: 1`, `prevHash` set to the record hash of the bytes
above, an unchanged `notAfter`, and `powProof: null`.

## Known Limitations

Full replication bounds this design at roughly a million names on ordinary hardware. Light
clients can verify a name but not its freshness. The tie-break is grindable in the undecidable
case. `REVOKE` destroys rather than recovers. IDN labels are out of scope until a homograph
policy is ratified as a VWIP.

## Status

Status: Draft — not yet implemented. This specification describes the pre-implementation design:
no registry code exists, no network is running, and every constant here is subject to change by
the VWIP process before a first release.

## See also

- [docs/spec/NAMES.md](NAMES.md)
- [docs/spec/PROOF-OF-WORK.md](PROOF-OF-WORK.md)
- [docs/spec/RESOLUTION.md](RESOLUTION.md)
- [docs/ARCHITECTURE.md](../ARCHITECTURE.md)
