# VayuWeb Glossary

Every term the specifications use, defined once. Where a word has a specific VayuWeb meaning that
differs from its ordinary or industry meaning, that difference is called out.

**Status:** Draft against the pre-implementation design.

## A

**Activation epoch** — A point strictly in the future at which an accepted protocol change takes
effect. Every Standards Track VWIP must carry one; this is what makes retroactive rule changes
impossible by construction rather than by promise.

**Alias record** — A registry record type pointing one name at another. Its main constitutional
role is in TLD retirement: an extension cannot be sunset without mandatory aliases, so holders are
never stranded.

**Append-only log** — A data structure to which entries may be added but never modified or
removed. VayuWeb's registry is one. The consequence people underestimate: it cannot forget.

**Argon2id** — The memory-hard password-hashing function (RFC 9106) used for VayuWeb's
anti-squatting proof-of-work, at 64 MiB per evaluation. Memory-hardness is the point: it keeps a
laptop and a data centre roughly comparable per unit of work.

## B

**Bootstrap node** — A peer whose address is known in advance, used to join the network before
any other peers are known. VayuWeb treats a default bootstrap list as a centralisation risk to be
measured, which is why lists must be plural and swappable.

**Bus-factor rule** — The Constitution's requirement (Article 46) that no role critical to the
project may be held by one person, expressed as a hard minimum panel size rather than a
recommendation.

## C

**Caretaker mode** — The reduced state a dormant project enters under Article 56, in which
verification still works and maintenance is explicitly declared lapsed rather than quietly
implied.

**CID** — Content Identifier. The self-describing hash that addresses a piece of content on IPFS.
A CID names *what* something is, never *where* it is.

**Clause** — A numbered sentence in the Constitution, cited as `Article 30.2`. Clauses are
operative; headings are not.

**Control API** — The resolver's local management interface on `127.0.0.1:7653`, separate from
the browsing proxy. It binds loopback only and requires a per-install bearer token, and a VayuWeb
page must never be able to reach it.

**Convergence rule** — The deterministic rule resolving two conflicting first-registrations of the
same name: earliest valid registration by log ordering, with a deterministic hash tie-break.
Deterministic is not the same as feeling fair to the loser.

**Conformance suite** — The public, offline-runnable, forkable test set that defines what
"correct implementation" means. Under Article 44 it carries both wire vectors and executable tests
of the Title II rights, so correctness and rights are checked by the same machinery.

## D

**Deterministic CBOR** — The canonical binary serialisation used for the bytes that get signed, so
that two implementations always produce identical bytes for identical records. Chosen over
canonical JSON for having fewer ways to disagree.

**DHT** — Distributed Hash Table. The decentralised lookup structure used for peer discovery.
VayuWeb uses HyperDHT via Hyperswarm.

**Domain separation** — A fixed prefix string included in the bytes being signed, so that a
signature valid in one context cannot be replayed in another.

**Dormant** — (1) Of a VWIP: entered automatically after 365 days without substantive activity;
reopenable by anyone. (2) Of the project: the state declared under Article 56 when maintenance
has stopped.

## E

**Eclipse attack** — Surrounding a node with attacker-controlled peers so it sees only what the
attacker chooses. Signature verification prevents forged records but not withheld ones.

**Ed25519** — The elliptic-curve signature scheme establishing name ownership. Possession of the
secret key *is* ownership; there is no other test and no override.

**Entrenched clause** — A constitutional provision the amendment process cannot reach, listed in
Article 9. Entrenchment is what makes the difference between a rule and a preference.

**Equivocation** — Presenting different histories to different peers. Detected by monitors and
cross-checked snapshots under Article 38.

## G

**Grace** — The 30 days after `notAfter` during which only the existing owner may renew. A name
in grace has expired and does not resolve; grace protects the owner's claim, not the name's
function.

## H

**Helia** — The JavaScript IPFS implementation VayuWeb targets for content storage and retrieval.

**Hyperbee** — An append-only B-tree built over a Hypercore, giving the registry an indexed
key-value view over its log.

**Hypercore** — A signed, append-only log with cryptographic verification of any range, replicable
peer-to-peer. The registry's underlying structure.

**HyperDHT** — The distributed hash table underlying Hyperswarm.

**Hyperswarm** — The peer discovery and connection layer used to find other VayuWeb nodes.

## I

**Impossibility-and-capture analysis** — A mandatory VWIP section (Article 5) answering two
questions: what does this change make impossible, and what new thing does it make worth
capturing? VayuWeb prefers impossibilities to policies because an impossibility cannot be petitioned.

**IPFS** — InterPlanetary File System. The content-addressed storage network VayuWeb publishes to.

**IPNS** — InterPlanetary Name System. A mutable pointer to a CID, signed by its owner. In VayuWeb it
is one record type among several, not the naming layer — VayuWeb's naming layer is the registry.

## L

**Label** — The part of a name before the extension: `example` in `example.vayu`. One to 63
characters from `[a-z0-9-]`, not starting or ending with `-`.

## N

**No-chokepoint invariant** — Constitution Article 4: no mechanism may be introduced whose
withdrawal by any single party would degrade the system. Every VWIP must analyse itself against
it.

**notAfter / notBefore** — The validity bounds on a registry record. Registration runs one year.

## O

**Objection Register** — The permanent public record attached to every VWIP holding each
unresolved objection, the reasoning that overruled it, and who recorded that reasoning. It is what
turns "rough consensus" from a euphemism for discretion into a reviewable act.

**ownerKey** — The Ed25519 public key controlling a name. Changing it is a signed operation like
any other.

## P

**Pin / pin set** — To pin is to commit local storage to keeping content available. A pin set is
what a node has chosen to keep alive. Nobody is obliged to pin anything, which is exactly why
availability cannot be guaranteed.

**prevHash** — The link from a registry record to its predecessor for that name, giving each
name's history a verifiable chain.

**Proof-of-work** — In VayuWeb, a memory-hard cost imposed at registration and renewal to price bulk
squatting. Unlike in a blockchain, it establishes **no ordering and no consensus** — it is purely
an anti-abuse cost. Confusing the two is the most common misreading of this design.

## Q

**Quarantine** — The 30 days after grace during which *nobody*, including the former owner, may
register the name. It removes the profit from watching the log for expiries.

**Quorum collapse** — The failure mode where a governance body stops functioning because nobody
shows up. Article 28 addresses it by binding duties to the text and the software rather than to
any body, so that anyone may discharge them without appointment.

## R

**Radicle** — The peer-to-peer code collaboration network that will become VayuWeb's long-term
development home. GitHub is a temporary mirror.

**Ratification** — Formal adoption of a change or a new extension by the peers, under the
thresholds set in the Constitution.

**Registry record** — The signed unit of state for one name: `name`, `tld`, `ownerKey`, `seq`,
`notBefore`, `notAfter`, `records`, `powProof`, `prevHash`, `sig`.

**Resolver proxy** — The local process on `127.0.0.1:7654` that makes VayuWeb names work in an
unmodified browser. It never falls through to clearnet DNS for a VayuWeb name and does not log
queries by default.

**Rights-impact analysis** — A mandatory VWIP section naming every Title II Article a change
touches and stating whether the effect is expansion, restriction, or none.

**Rough consensus** — The absence of unaddressed substantive technical objection. Explicitly *not*
unanimity, a majority, a head count, or the chair's preference. Borrowed from the IETF and
tightened: VayuWeb additionally requires that every objection and its answer be permanently recorded.

## S

**seq** — The monotonic sequence number per name, giving replay protection and a total order for
that name's own history.

**Settlement delay** — The waiting period imposed on a transfer (Article 33), which gives a victim
of key theft or coercion a window to notice and publish.

**Sunset** — A mandatory expiry attached to a transitional mechanism or a retiring extension. TLD
retirement carries a minimum 24-month sunset with mandatory aliases.

**Sybil attack** — Creating many identities to gain disproportionate influence. VayuWeb resists it in
the registry with proof-of-work and in governance by defining consensus negatively, so that adding
supporters cannot manufacture it.

## T

**Tauri** — The desktop application framework (2.x) targeted for the VayuWeb client.

**TLD** — Top-level domain, called an *extension* in user-facing copy. Eleven at launch, all
equal in status.

**Title** — One of the Constitution's six top-level divisions. Titles are navigational; Articles
and clauses are what get cited.

## W

**VWIP** — VayuWeb Improvement Proposal. The numbered, archived, permanently public unit of change.
Defined by [VWIP-0000](spec/VWIP-0000.md).

**VWIP editor** — A holder of a ministerial role: checks completeness, assigns numbers, records
transitions, maintains the archive. Explicitly has **no merit veto** — an editor who rejects a
proposal because they disagree with it has exceeded the role.

## See also

- [The VayuWeb Constitution](../constitution/CONSTITUTION.md)
- [Whitepaper](WHITEPAPER.md)
- [Architecture](ARCHITECTURE.md)
- [VWIP-0000](spec/VWIP-0000.md)
