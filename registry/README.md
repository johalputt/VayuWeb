# registry/ — the VayuWeb name registry

The signed name registry: record format, verification rules, proof-of-work, the index keyspace
and the name lifecycle, with a command-line tool that runs all of it against a local log.

**There is no discovery yet.** `vw sync` dials and replicates over a socket you name, and two
processes converge over it — `scripts/acceptance-replication.mjs` is that, run — but nothing here
joins a DHT or finds a peer it was not told about, and the log is a local file rather than a
Hypercore. The part that decides whether a record is valid, which every peer must agree on byte
for byte, is what this package is mostly made of.

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
| Convergence and equivocation detection (`src/converge.ts`) | Implemented, tested |
| Equivocation ledger: record and forward (`src/equivocation.ts`) | Implemented, tested |
| Resolution algorithm (`src/resolve.ts`) | Implemented, tested — no network; steps 10-12 are ports |
| Resolution caches and TTL policy (`src/cache.ts`) | Implemented, tested |
| Command-line tool (`src/cli.ts`, `bin/`) | Implemented |
| Conformance vectors ([`../conformance/vectors.json`](../conformance/vectors.json)) | Registry rules only |
| Hypercore log and Hyperbee index | Not started |
| Peer replication (`src/replicate.ts`, `src/swarm.ts`, `vw sync`) | Implemented, tested over TCP; the Hyperswarm binding is injected and unexercised |
| Checkpoints and light clients | Encoded and verified; nothing publishes or consumes one |

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

vw sync     --log ./log --listen 4747          # or --connect host:port
vw equivocations --log ./log                   # what this peer knows about, and from whom

vw serve    --log ./log --site ./public --pointer k51qzi5uqu5d…   # test the ipns-first path
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

### `ipns` is resolved, and `--pointer` is a local declaration

`SOURCE_ORDER` prefers an `ipns` pointer over a `cid` snapshot, because HOSTING.md tells publishers
to carry both: the pointer for the living site, the snapshot for when the pointer cannot be
resolved. Step 10 turns the pointer into a CID before step 11 fetches it, so a content layer never
needs to know what a pointer is, and a pointer that will not resolve is 1505 `IPNS_UNRESOLVED` —
not 1421, which says the name points at nothing fetchable and would be false.

Resolving an IPNS name over the network means the IPFS routing stack, which this package
deliberately does not depend on; `IpnsPort` is the seam, the same shape Hyperswarm has in
`swarm.ts`. `serve --pointer <key>` declares one local answer — "the record I am testing carries
this pointer, and it means the site I just published" — which is what a publisher checking that
path before they publish actually has. Every other pointer resolves to null.

### Equivocation is recorded, and punished by nothing

One owner key signing two different records at the same `seq` for one name is equivocation, and
REPLICATION.md 6.3 makes recording it a MUST. `vw equivocations` is the reading end: reports this
peer detected in its own log, reports peers sent it, and how many were turned away and why.

The evidence is the two record encodings and nothing else, so anyone can check it without trusting
whoever passed it on — which is also why **both signatures are verified before anything is written
down**. An owner key is public, so a pair checked for everything except who signed it can be minted
by anyone against anyone.

Nothing acts on the list. There is no penalty, no exclusion and no loss of a name: a mechanism able
to strip a name on evidence is a mechanism able to strip a name on manufactured evidence, and
REPLICATION.md 6.4 refuses to build one.

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

Implementing them found eight defects in the specifications themselves, each recorded in
[`../CHANGELOG.md`](../CHANGELOG.md) and fixed in the text as well as the code. Every one was
invisible to reading and obvious to implementing.

If you are writing a second implementation, work from
[the conformance vectors](../conformance/README.md) rather than from this source. That is what
they are for, and a disagreement is worth reporting whichever side turns out to be wrong — the
most valuable outcome is finding a sentence two people can read two ways.

See also: [Architecture](../docs/ARCHITECTURE.md) · [Threat Model](../docs/THREAT-MODEL.md) ·
[Roadmap](../docs/ROADMAP.md)
