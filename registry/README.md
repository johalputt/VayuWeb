# registry/ — the VayuWeb name registry

The signed name registry: record format, verification rules, proof-of-work, the index keyspace
and the name lifecycle, with a command-line tool that runs all of it against a local log.

**There is no network yet.** Nothing here discovers, dials or replicates, and the log is a local
file rather than a Hypercore. That is Phase 2. What exists is the part that decides whether a
record is valid — the part every peer must agree on byte for byte.

## State

| Component | State |
|---|---|
| Deterministic CBOR codec (`src/cbor.ts`) | Implemented, tested |
| Domain-separated hashing and signing input (`src/domain.ts`) | Implemented, tested |
| Strict Ed25519 verification (`src/signature.ts`) | Implemented, tested |
| Label grammar and ratified TLD set (`src/names.ts`) | Implemented, tested |
| Record schema validation (`src/record.ts`) | Implemented, tested |
| Verification state machine (`src/verify.ts`) | Implemented, tested |
| Argon2id proof-of-work (`src/pow.ts`) | Implemented, tested |
| Index keyspace codec (`src/keys.ts`) | Implemented, tested |
| Name lifecycle: grace, quarantine, revocation (`src/lifecycle.ts`) | Implemented, tested |
| Local append-only log and index (`src/store.ts`) | Implemented, tested — **not** Hypercore |
| Command-line tool (`src/cli.ts`, `bin/`) | Implemented |
| Conformance vectors ([`../conformance/vectors.json`](../conformance/vectors.json)) | Registry rules only |
| Hypercore log and Hyperbee index | Not started |
| Peer replication and convergence | Not started |
| Equivocation detection, checkpoints, light clients | Not started |

`src/store.ts` is a single-writer, file-backed log with an index rebuilt by replay. It is enough
to finish and test Phase 1 without pulling in the peer-to-peer stack, and the difference from
Hypercore is not cosmetic: there is no merkle tree, so entries are not self-authenticating and a
light client cannot verify anything without replaying the whole log. Phase 2 replaces the
storage beneath these interfaces. The verification rules above them do not change, which is why
they are already separated.

## Using it

```sh
npm ci
npm test          # unit tests and the conformance vectors
npm run vectors   # regenerate the conformance artifact
```

The tool runs straight from TypeScript source under Node 22.6+:

```sh
alias vw='node --experimental-strip-types bin/vayuweb-registry.ts'

vw keygen   --key owner.key
vw register --log ./log --key owner.key --name atlasobservatory.vayu --txt "v=vayuweb1"
vw resolve  --log ./log --name atlasobservatory.vayu
vw list     --log ./log
vw vectors                      # run the conformance suite
```

Exit codes: `0` accepted, `1` rejected or error, `2` deferred for clock skew, `3` name not live.
`--at <unix>` pins the clock, so any result can be reproduced.

Deferral is a real third outcome, not a soft rejection. A record whose term starts beyond the
clock-skew tolerance is held rather than refused, because this machine's clock may be the wrong
one.

### The proof of work is real

`register` and `renew` solve Argon2id at 64 MiB per evaluation. Cost depends on label length: a
16-character label takes about 16 evaluations, a 5-character label about 128, a two-character
label about 1024. Ask before committing:

```sh
vw difficulty --log ./log --name atlas.vayu
```

`--bits` may raise the difficulty — over-payment is valid — but a value below the requirement is
refused up front rather than after the work, since the verifier would reject it anyway.

### Keys are files

`keygen` writes a 32-byte secret as hex, mode 0600. There is no keystore, no passphrase and no
agent, and the tool says so rather than implying hygiene it does not provide. Back the file up
yourself: losing it loses every name it holds, and there is no recovery key and no appeal.

## What it must not do

Hold a privileged writer, adjudicate ownership disputes, or trust a record it has not verified
locally. No admin key, no seizure path, no appeal — the charter forbids all three, and
`.github/workflows/constitution.yml` checks the source for the vocabulary of each.

Two design choices follow from that and are worth naming, because both look like missing
features until you see what they buy:

- **Verification takes no network call.** A verifier that asks a peer for a verdict has replaced
  verification with trust.
- **`RegistryView` has no default implementation.** A view answering permissively — difficulty
  zero, proof accepted — would make every caller that forgot to supply one accept unproven
  records silently, and a passing test suite cannot show that.

## Specifications

Implemented from [`../docs/spec/REGISTRY.md`](../docs/spec/REGISTRY.md),
[`NAMES.md`](../docs/spec/NAMES.md) and
[`PROOF-OF-WORK.md`](../docs/spec/PROOF-OF-WORK.md).

Implementing them found six defects in the specifications themselves, each recorded in
[`../CHANGELOG.md`](../CHANGELOG.md) and fixed in the text as well as the code. Every one was
invisible to reading and obvious to implementing.

If you are writing a second implementation, work from
[the conformance vectors](../conformance/README.md) rather than from this source. That is what
they are for, and a disagreement is worth reporting whichever side turns out to be wrong — the
most valuable outcome is finding a sentence two people can read two ways.

See also: [Architecture](../docs/ARCHITECTURE.md) · [Threat Model](../docs/THREAT-MODEL.md) ·
[Roadmap](../docs/ROADMAP.md)
