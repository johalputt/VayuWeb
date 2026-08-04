# VayuWeb: A Parallel Web

## Abstract

VayuWeb is a specification for a peer-to-peer naming and hosting protocol — a parallel
web that needs no ICANN, no certificate authority, no hosting company and no single
point of control. Names are registered in an append-only, signed log that is fully
replicated between peers. Content is addressed by cryptographic hash and served by
whoever chooses to serve it. Resolution happens on the user's own machine, behind a
loopback proxy that any browser can be pointed at. Ownership of a name is possession
of an Ed25519 private key and nothing else. Scarcity is enforced by a memory-hard
proof-of-work paid to nobody, rather than by an annual fee paid to an intermediary
who can therefore be leaned on. Change is ratified through the VayuWeb Constitution and
the VWIP process.

This paper states the problem VayuWeb addresses, the design chosen, the reasoning behind
the costliest trade-offs, and — at comparable length — what the design does not do.
Nothing described here is running: no network, no registered name, no user, no
download. Every requirement is in the normative future voice because it describes a
system to be built.

Status: Draft — not yet implemented.

## 1. The problem

A site on the clearnet is not one thing. It is a chain of five permissions, each
granted by a different company, each revocable independently, and each sufficient on
its own to make the site vanish. The failure is worth walking through concretely,
because the usual summary — "the web is centralised" — hides where the actual levers
are.

**The registrar.** A domain is not owned; it is leased through a registrar that
operates under contract to a registry operator, which in turn operates under contract
to ICANN. The registrar holds the authoritative record. A registrar can lock,
transfer, suspend or delete a name on the instruction of a court, a government
agency, a trademark arbitration panel, its own upstream registry, or its own abuse
desk applying its own policy. The domain holder is not a party to most of these
processes. The lever is a database row and the pull takes seconds.

**The DNS.** Even with the registration intact, the name must resolve. Authoritative
nameservers are usually operated by a third party; recursive resolvers are run by ISPs
and by a handful of large public services. Either layer can be made to answer
differently: a national blocklist at ISP resolvers, an authoritative provider
terminating an account, a resolver operator filtering a name for policy reasons. The
registration survives and the site is still unreachable — a distinct failure mode from
seizure, needing a distinct defence.

**The certificate authority.** Browsers treat a site without a valid certificate as
broken and, increasingly, as unvisitable. The certificate is issued by a CA the
operator does not control, is valid for a bounded period, and can be revoked or simply
not renewed. A CA that declines to serve a customer — for sanctions compliance, for
policy, or because its own root was distrusted by a browser vendor — converts a
working site into a full-page interstitial. Trust here is delegated to root programs
run by a few browser vendors.

**The host.** The bytes live on somebody's machine. Hosting providers and cloud
platforms terminate accounts under acceptable-use policies whose text is broad by
design and whose application is discretionary. Termination can take the data with it.
Where the host is also the domain's DNS provider — a common bundle — one decision
removes two layers at once.

**The CDN and the edge.** Sites of any size sit behind a content delivery network for
performance and for denial-of-service absorption. The CDN terminates TLS, sees plain
traffic, and can drop a customer. Because a site large enough to be attacked cannot
easily survive without such absorption, "we will no longer protect you" is
operationally close to "you are offline", without anyone having to take the site down.

**The aggregation.** Each layer has consolidated, and — more importantly — they have
consolidated into overlapping sets of the same companies. A single vendor routinely
supplies registration, DNS, TLS termination, edge caching and origin hosting for the
same site, so five independent permissions collapse into one or two commercial
relationships. An operator who diversifies carefully still depends on a root zone with
one policy authority and a root certificate program with a few. The point is not that
these organisations behave badly; it is that the architecture makes the question of
their behaviour decisive, when it should be irrelevant.

The shape of every one of these failures is the same: a party who is not the
publisher and not the reader holds a switch in the middle. VayuWeb is an attempt to
build a naming and hosting path with no such switch — not by asking the operators to
behave, but by removing the position from the design.

## 2. Design goals and explicit non-goals

Goals, in priority order. Where two conflict, the earlier wins.

1. **No revocable permission in the resolution path.** Registration, renewal,
   transfer and release SHALL be signed operations authored by the key holder. No
   third party SHALL be able to reassign a name.
2. **Independent verifiability.** Every peer SHALL be able to verify the entire
   registry history from first entry to last, offline, with no trusted server.
3. **Resolution without a network confidant.** Looking up a name MUST NOT phone home
   and MUST NOT log queries by default. The resolver runs locally.
4. **Content that survives its publisher.** Content SHALL be addressed by CID, so
   that any peer holding the bytes is as good as any other, and pinning by volunteers
   is possible without the owner's cooperation.
5. **Scarcity without an intermediary.** Registration cost SHALL be paid in
   computation, not in money to a party who could be pressured or corrupted.
6. **Usable by non-technical people.** A desktop client SHALL make registration and
   publication a small number of ordinary steps.
7. **Amendable by its users.** Protocol change SHALL go through a public proposal
   process ratified by peers.

Non-goals, stated as flatly as the goals.

VayuWeb is **not an anonymity system**. It carries no mixnet, no cover traffic and no
onion routing, and it does not attempt to hide who is reading what from a network
observer. VayuWeb is **not a payment system**: there is no token, no coin, no fee, no
treasury and no built-in market for pinning. VayuWeb does **not replace TLS or DNS on
the clearnet**; it runs alongside them and interoperates with neither's trust roots.
VayuWeb is **not a trademark or dispute forum** — see the doctrine in section 5. VayuWeb
does **not attempt global consensus on transaction ordering**, and it does not
provide a smart-contract environment, a general-purpose ledger, or a store of value.
Finally, VayuWeb does not promise availability: see section 8.

## 3. System overview

Five components. Each is specified in detail elsewhere; this section states what each
one is for and how they compose.

**The registry.** An append-only, signed Hypercore log with a Hyperbee (B-tree) index
built over it, fully replicated between peers. Each entry is one operation on one
name: registration, update, transfer or release. A registry record carries `name`,
`tld`, `ownerKey` (an Ed25519 public key), `seq` (monotonic per name), `notBefore`,
`notAfter`, `records`, `powProof`, `prevHash` and `sig`. The `records` field holds a
small typed set — `peer`, `ipns`, `cid`, `txt` and `alias` — deliberately small
because every additional record type is another thing every resolver must implement
identically. Validation is local and total: a peer checks the signature against
`ownerKey`, checks `seq` against the previous record for that name, checks `prevHash`
against the entry it claims to follow, and checks the proof-of-work. See
[docs/spec/REGISTRY.md](spec/REGISTRY.md).

**Discovery.** Peers find one another over Hyperswarm on the HyperDHT. No seed
authority's disappearance stops the network from forming, and a compromised bootstrap
can withhold peers or delay a client but cannot produce a valid entry.

**Content.** Sites are stored in IPFS (Helia) and addressed by CID; mutable pointers
use IPNS. A `cid` record pins one immutable snapshot, so a reader gets exactly what the
owner signed for; an `ipns` record points at a mutable stream for sites that update
often. Pinning is by the owner and by any volunteer. There is no obligatory pinning
service and no built-in payment for pinning — the honest cost described in section 8.
See [docs/spec/HOSTING.md](spec/HOSTING.md).

**Resolution.** A lightweight local proxy listens on 127.0.0.1:7654 for HTTP and
127.0.0.1:7653 for its control API. Loopback is not a detail: the query never leaves
the machine, so there is no resolver operator to subpoena and no query log to leak. Any
browser can be pointed at the proxy without an extension; an optional extension makes
address-bar entry feel native. Resolution consults the locally replicated Hyperbee
index, so the common case is a B-tree lookup with no network round trip at all.

**Client.** A Tauri 2.x desktop application for people who will never run a daemon from
a terminal: key generation and backup, registration with its proof-of-work, publishing
a folder as a site, renewal reminders, transfer.

The resolution path, end to end:

```text
  browser
     |  http://example.vayu/   (proxy set to 127.0.0.1:7654)
     v
  +---------------------------+
  |  local VayuWeb resolver      |
  |  127.0.0.1:7654 (proxy)   |
  |  127.0.0.1:7653 (control) |
  +---------------------------+
     |  1. parse + NFC-normalise label, check grammar
     |  2. look up "example.vayu" in the local Hyperbee index
     v
  +---------------------------+        replicated over Hyperswarm / HyperDHT
  |  registry (Hypercore log) |  <---->  peers ... peers ... peers
  |  + Hyperbee index         |        (append-only, signed, fully verified)
  +---------------------------+
     |  3. verify sig / seq / prevHash / PoW; check notBefore..notAfter
     |  4. read records: cid | ipns | peer | alias | txt
     v
  +---------------------------+
  |  content layer (Helia)    |  <---->  IPFS peers, owner pin, volunteer pins
  |  CID -> bytes, IPNS -> CID|
  +---------------------------+
     |  5. stream bytes back to the browser
     v
  browser renders the site
```

No step in that path contacts a party that could refuse to serve this particular
name. See [docs/spec/RESOLUTION.md](spec/RESOLUTION.md).

## 4. Why an append-only signed log rather than a blockchain

The functional requirement is narrow: prove that a name belongs to a key, in a way
anybody can check, and make it impossible to rewrite that history quietly. That is a
job for an authenticated append-only log with a Merkle structure. It is not a job for
a blockchain, because a blockchain buys one additional property — global agreement on
the total order of unrelated events — at a price VayuWeb declines to pay.

That price is concrete. Global ordering needs a mechanism to choose between competing
histories; every such mechanism yet deployed needs a scarce resource (hashpower,
stake) and therefore an issued token; a token needs an issuance schedule and a founding
allocation, which creates a party with a balance sheet and an interest in protocol
changes. Fees follow, then fee markets, then a governance fight over who receives the
fees. A naming system needs none of this. Names are not fungible, are not traded
against one another for block space, and almost never interact: an operation on
`alice.vayu` has no bearing on one on `bob.p2p`. Ordering is needed only *per name*,
and there it is supplied by the monotonic `seq` plus `prevHash` — a hash chain the
owner extends and anybody can verify.

So VayuWeb is a log: entries are self-authenticating, the structure is append-only and
tamper-evident, and validity is a pure function of the entry and the history preceding
it. There are no miners, validators, tokens, fees or block rewards. A peer's job is to
replicate and to reject invalid entries, and neither requires being paid.

The honest cost is this: **without global consensus there is no global prevention of
double registration at the instant of registration.** Two peers separated by a network
partition can each accept a valid-looking first registration of the same free name.
Both entries are individually valid. Something must decide, and it must decide the
same way on every peer, forever, without a vote.

The convergence rule is: **the earliest valid registration by log ordering wins; where
log ordering does not establish precedence, the entry whose hash is numerically
smaller, compared as a big-endian unsigned integer over its full digest, wins.** Log
ordering decides the ordinary case, including nearly all real races, because the log is
a total order once the partition heals and the entries share a common prefix. The hash
tie-break covers the genuinely undecidable case and has one virtue: it is deterministic
and requires no judgement. Every peer holding both entries reaches the same verdict
with no communication.

Three consequences follow, and all three are costs.

First, the losing registrant's entry becomes void on merge. Their name was accepted,
possibly served, and is then not theirs. The client MUST surface this state rather than
hide it.

Second, there is a window during which two peers give different answers for the same
name, as long as the partition. Replication is normally a matter of seconds; a peer
offline for a week can serve a losing answer for a week. A resolver SHOULD therefore
report the log length and freshness it is answering from, so a caller can distinguish
"verified against a current log" from "verified against what I had in March".

Third, the hash tie-break is grindable in principle: an attacker expecting a tie can
vary a nonce to lower their entry hash. It matters only in the undecidable case, and
each attempt costs a full proof-of-work, so the attack is expensive and narrow. It is
still a real weakness, recorded as one in
[docs/THREAT-MODEL.md](THREAT-MODEL.md) rather than argued away.

## 5. Economics without a token

Names must be scarce or they are worthless. The conventional way to create scarcity is
a price: a yearly fee to a registrar. The problem is not the amount, it is the payee.
A payee is a bank relationship, a jurisdiction and a person who can be served with an
order — so every fee-based naming system reproduces the chokepoint it was built to
remove, one layer down. Payment rails add their own censorship: processors already
decline categories of lawful commerce, and a sanctioned registrant cannot pay at all.

VayuWeb charges in computation instead. Registration and each renewal require a
memory-hard, Argon2id-based proof-of-work, whose difficulty is a function of the label
length and of the TLD's registration rate over the trailing 30 days. Memory-hardness is
chosen so that a commodity laptop and a rack of specialised hardware are within the
same order of magnitude per name; a compute-only puzzle would hand bulk registration to
whoever owns the most silicon. The target is seconds of CPU for a single name — a wait
a person will tolerate once a year — with superlinear growth as one party registers
many, because the trailing-rate term raises the difficulty that party then faces. Ten
thousand names should be painful; one name should be nearly free. The trailing window
is 30 days because it is long enough that a burst cannot be waited out over a weekend
and short enough that a legitimate rise in demand relaxes within a month. Exact
parameters are set in [docs/spec/PROOF-OF-WORK.md](spec/PROOF-OF-WORK.md).

The work is paid to nobody. It is burned. **There is deliberately no treasury.** No
fund accumulates, so there is no fund to capture, tax, sue, freeze or fight over, and
no faction whose income depends on a particular protocol outcome. Development is
funded, if at all, outside the protocol by whoever wants the protocol to exist. This
is a real cost: VayuWeb has no mechanism to pay for its own maintenance, its own security
audits or its own infrastructure, and an unfunded protocol can simply stall. That
outcome is judged preferable to a funded one whose funding becomes the thing worth
capturing.

Two further limits deserve stating. Proof-of-work is regressive against low-powered
devices: registering from a phone will be slow, and the client SHOULD allow the work to
be computed on one device and the signature made on another. And a well-resourced
squatter is not stopped, only made to pay in electricity for names that earn nothing —
because the registry does not adjudicate. The dispute doctrine is
**first-valid-signature-wins**: the registry is not a trademark court and MUST NOT
adjudicate ownership claims. The only questions it answers are whether the signature
is valid and whether the name is free.

## 6. Governance

VayuWeb is governed by the VayuWeb Constitution, which fixes the properties that MUST NOT be
traded away — no privileged key, no revocation of a name by anybody but its owner, no
mandatory phone-home, no token — and by the VWIP process, through which new TLDs and
protocol changes are proposed publicly, reviewed, and ratified by peers who signal
adoption by running the code. Code is MIT licensed; the Constitution and specifications are dedicated
to the public domain, so that a fork inherits the rules without asking. Long-term
development lives on Radicle, with GitHub as a temporary public mirror, so that the
project's own home is not a chokepoint of the kind section 1 describes. See
[constitution/CONSTITUTION.md](../constitution/CONSTITUTION.md),
[docs/GOVERNANCE.md](GOVERNANCE.md) and
[docs/spec/VWIP-0000.md](spec/VWIP-0000.md).

## 7. Threat summary

The adversaries taken seriously are: a peer that serves a partial or stale log; an
attacker who grinds entry hashes to win a tie-break; a bulk squatter with cheap
compute; a network adversary who blocks the DHT bootstrap or the swarm's traffic
patterns; an attacker who steals or coerces an owner's Ed25519 private key, against
which the protocol has no remedy at all, because possession of the key *is* ownership;
a homograph or confusable-name attacker, which is why launch is ASCII-only and an
IDN policy is deferred to a future VWIP; and an attacker who publishes malicious
content under a legitimately held name, which naming cannot address. Each is analysed,
with mitigations and with the cases where there are none, in
[docs/THREAT-MODEL.md](THREAT-MODEL.md).

## 8. What VayuWeb is NOT

**It does not make you anonymous.** Running a VayuWeb peer means participating in a DHT
and a swarm. Your IP address is visible to peers you connect to, and your traffic
pattern is visible to your ISP. Publishing a site and announcing yourself as a provider
for its CID links your address to that content. Anyone who needs anonymity needs a
transport that provides it, and must combine VayuWeb with one; VayuWeb does not ship one and
does not pretend otherwise.

**It does not guarantee availability.** Content lives where somebody keeps it. If the
owner's node is offline and no volunteer has pinned the CID, the name resolves
correctly to content nobody is serving, and the reader gets nothing. There is no
built-in payment for pinning and therefore no economic guarantee of replication. This
is a deliberate trade — a paid pinning market would reintroduce a payee — and it means
availability is a social and operational property, not a protocol guarantee.

**It does not delete anything.** The registry is append-only. Every registration,
transfer and release, including the key that made it, is permanent and replicated to
every peer. A name can expire and pass to somebody else, but the record that you once
held it cannot be redacted and will be copied by strangers. Anyone for whom that
history is itself a hazard should register through an unlinked key, and understand
that the linkage, once made, cannot be undone.

**It does not stop a state from blocking your traffic.** A network operator can block
the DHT bootstrap, throttle the swarm, fingerprint the protocol or cut the connection
entirely. VayuWeb removes the intermediaries who could be ordered to take a site down; it
does not remove the ISP that carries your packets. Censorship-resistance at the naming
layer is not censorship-resistance at the transport layer, and conflating the two would
be dishonest.

**It does not replace TLS on the clearnet.** VayuWeb names are not certified by any CA and
will not appear valid to a browser's clearnet trust logic. Authenticity within VayuWeb
comes from the owner's signature and from content addressing, not from a certificate.
Nothing here improves the security of an ordinary `https://` site, and a VayuWeb name
cannot be used to secure one.

**It does not resolve disputes, recover lost keys, or reverse mistakes.** There is no
support desk. Lose the key and the name is gone until it expires.

## 9. Status and roadmap

VayuWeb is at the specification and charter stage. There is no implementation, no running
network, no registered name, no user, and no release to download. Every number in this
paper — the 1-year term, the 60-day renewal window, the 30-day grace period followed by
a 30-day quarantine before a name returns to the open pool, the loopback ports, the
label grammar, the eleven launch TLDs — is a design decision recorded in the
specification set and open to revision by VWIP until the first implementation freezes
it. The sequencing of that work, from reference registry to resolver to client, is in
[docs/ROADMAP.md](ROADMAP.md). Readers who want the mechanism rather than the argument
should start with [docs/ARCHITECTURE.md](ARCHITECTURE.md).

Status: Draft — not yet implemented. This document describes a pre-implementation
design; no component of VayuWeb exists as running software.

See also:

- [docs/ARCHITECTURE.md](ARCHITECTURE.md)
- [docs/spec/REGISTRY.md](spec/REGISTRY.md)
- [docs/THREAT-MODEL.md](THREAT-MODEL.md)
- [constitution/CONSTITUTION.md](../constitution/CONSTITUTION.md)
