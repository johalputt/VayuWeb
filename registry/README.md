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
| Checkpoints and light clients (`src/checkpoint.ts`) | Served, compared, forks surfaced; `prove` / `light-verify` run steps 1-2 of the light-client procedure |

`src/store.ts` is a single-writer, file-backed log with an index rebuilt by replay. It is enough
to finish and test Phase 1 without pulling in the peer-to-peer stack, and the difference from
Hypercore is not cosmetic: no merkle tree is *maintained*, so `prove` derives one by rebuilding it
over every entry each time it is asked. That cost falls on the side holding the log — the verifying
side is O(log n) and holds nothing — but it is the reason proving is a command rather than something
the resolver does per request. Phase 2 replaces the storage beneath these interfaces. The verification rules above them do not change, which is why
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

vw prove        --log ./log --name atlasobservatory.vayu > proof.json
vw light-verify --proof proof.json --claims peers.json --name atlasobservatory.vayu
```

Exit codes: `0` accepted, `1` rejected or error, `2` deferred for clock skew, `3` name not live.
`--at <unix>` pins the clock, so any result can be reproduced.

Deferral is a real third outcome, not a soft rejection. A record whose term starts beyond the
clock-skew tolerance is held rather than refused, because this machine's clock may be the wrong
one.

### A light client, and the two things it refuses to conclude

REGISTRY.md's light-client procedure — obtain a length and root from peers, check an inclusion proof
against that root, verify the record chain — had every part implemented and no way to run it.
`proveInclusion`, `verifyNameInclusion` and `greatestCorroboratedLength` were reached only by their
own tests.

**The proof document carries no `treeRoot`, and one that does is refused.** `Proof`'s own comment
says a proof carrying its own leaf "would let a peer prove inclusion of something the light client
never asked about"; a proof carrying the root it is checked against is that defect one level up,
with the peer supplying both the evidence and the standard. `prove` prints its root on stderr
instead, beside the sentence saying to get it from peers. `--claims` is a list of
`{logLength, treeRoot}` — what checkpoint gossip hands over.

Two refusals rather than answers. A length claimed by fewer than `--quorum` peers (default 2) is not
corroborated, so it is refused rather than believed: `greatestCorroboratedLength` fails toward
staleness rather than toward trusting a stranger, and `--quorum 1` is available and says in the
answer what it gave up. Peers claiming one length with different roots are a fork, surfaced and
never resolved — REPLICATION.md 7.3 says do not pick one, and taking the first or the majority would
be picking.

Every answer states the length, the observation time and that **freshness is unproven**: no
inclusion proof shows the length handed over is current, so a peer withholding recent entries can
present a stale but internally consistent view. It also says it ran steps 1 and 2 only; step 3, the
record's own chain, is `vw verify`.

### Unpublishing says what it did and what it cannot do

`release`, `revoke` and `update --clear` each print Constitution Article 19.2's guaranteed acts and
Article 19.6's limits, at the moment the record is accepted. Article 19.8 requires the distinction
in clause 19.7 — VayuWeb ends authorised publication and does not erase — "at the point where
unpublishing is offered, in the interface itself rather than only in a manual", and PUBLISHING.md
section 4 says the same. Both sentences were written and neither was executed: the commands printed
an acceptance line and stopped, which is how an interface implies erasure without claiming it.

The rule keys on the outcome rather than the verb, so `update --clear` counts and `update --cid …`
does not. `TOMBSTONE` — Article 19.2's fourth guaranteed act — is still absent, as REGISTRY.md's
operation table records; `update --clear` breaks the binding but carries neither 19.4's cache bound
nor 19.3's signing rule. The statement still names it, because 19.2 says a registrant can always
publish one; this implementation does not yet give them a record for it.

Both halves are always rendered — the limits alone read as a warning about a failure, the guarantees
alone are the overstatement the Article exists to prevent — and a *refused* append prints neither,
because nothing happened.

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

### The control API answers about a name, and forgets what it remembers

Fourteen of the eighteen endpoints RESOLUTION.md lists now exist: `GET /v1/records/{name}` (the
record and what this resolver resolves it to), `POST /v1/resolve`, `GET /v1/cache/stats`,
`DELETE /v1/cache`, `DELETE /v1/cache/{name}`, and `GET /v1/peers` — which answers `joined: false`
from `serve`, because `sync` is where a peer connection lives and a zero that reads like a
measurement is worse than a sentence.

A name is **the first value a user types that reaches this API's routing**; every other endpoint is
a constant. It is validated against the grammar before it is echoed, keyed, logged or passed onward
— LOCAL-SURFACE.md 3.1's ordering, applied here for the same reason — and the answer echoes the
*validated* name rather than the bytes that arrived. `POST /v1/resolve` takes its name in a body
and runs it through `parseControlName`, the same single function the path routes use: two spellings
of one grammar are two spellings that disagree later, and whoever finds the disagreement finds it
through the more permissive one.

`bytes` is missing from `GET /v1/cache/stats`, which the specification lists, and deliberately so:
nothing measures the memory an entry occupies, and a figure derived from an encoding length would
be a guess wearing the clothes of a measurement. An operator would size a cache with it.

The four that remain are `POST /v1/pin`, `DELETE /v1/pin/{cid}`, `PATCH /v1/config` and
`POST /v1/token/rotate`. Every one of them changes state this process does not yet own — a mutable
pin set, a mutable configuration, a token file it can rewrite — and none of them is blocked on the
transport any more. Reading a body was the shared blocker and it is gone: `serve.ts` now has a
bounded reader, refusing `Transfer-Encoding` outright so one field decides the length, checking
that length against `SERVE_LIMITS.bodyBytes` before a byte is buffered, refusing any byte past it
rather than ignoring it, and holding the head deadline armed across the body so a sender that
promises bytes and goes quiet is closed by the clock.

### What is keeping your site alive, said without overstating it

`GET /v1/pins` on the control API reports what this node holds, and `pins.ts` — the module whose
entire job is to refuse to overstate availability — is what renders it. It had been imported by
nothing that ships, and a module nothing can reach cannot refuse anything.

There is no `total`, no `percentage` and no `durable` field, because Article 23 forbids the figure
and a field is where a dashboard binds to one. `asked` travels beside `answered` so a zero has a
denominator: "no peer answered out of 40 asked" and "no peer was asked" are different facts, and
only one of them is about the content. A self-pin is never summed into a peer count.

`serve --site` says the same thing at startup, because the state it describes is invisible from the
publisher's own machine — from there the site always loads.

**Unpublishing is not implemented.** `UNPUBLISH_EFFECTS` and `tombstonedBindingExpired` still have
no caller: the endpoint that would use them is `DELETE /v1/pin/{cid}`, and there is no mutable pin
set to unpin from. Building one so a constant has a caller would be the defect this section is
about, wearing a different hat.

### A fork is surfaced, and never resolved

A peer states a `CHECKPOINT` over its own log at every multiple of `CHECKPOINT_INTERVAL`, and
compares the ones it is told. Two that disagree at one length are a fork: REPLICATION.md 7.3 says a
client that finds one **MUST surface it** and **MUST NOT pick one**, so `CheckpointLedger` has no
method that could — no winner, no score, no preference for the longer chain or the first seen.

**A checkpoint carries no signature**, which is the whole difference from equivocation evidence. It
is four numbers and two hashes, and anyone can send any of them; there is nothing tying a checkpoint
to the peer that produced the log it describes. So a fork report means "two peers told me different
things" and no more — worth telling the operator, and never forwarded, because a relayed one is
indistinguishable from an invented one. Equivocation evidence is checkable by a third party without
trusting whoever passed it on, which is exactly why that one *is* forwarded.

`verifyNameInclusion` and `greatestCorroboratedLength` are the client half — verifying one name
against a claimed root without holding the log. They are implemented and tested and **nothing in
this package calls them**, because a light client is a client, and this package is a node.

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
