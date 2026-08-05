# The VayuWeb Constitution

**The founding charter of the VayuWeb protocol.**

| | |
|---|---|
| **Version** | 1.0 |
| **Ratified** | 26 July 2026 |
| **In force** | From the moment of first publication in the VayuWeb repository |
| **Structure** | Six Titles, sixty Articles |
| **Status of the protocol** | Not implemented. This charter governs a system that has not yet been built. |
| **Licence of this text** | Public domain (Creative Commons CC0 1.0 Universal), to the fullest extent permitted by law |
| **Canonical copy** | The `constitution/` directory of the VayuWeb repository, mirrored on Radicle |

This charter was written before the code, deliberately. A naming system inherits whatever
politics it was built with, and no project in the history of this field has successfully
retrofitted governance onto infrastructure people already depended on. The rules therefore come
first, in public, while changing them is still cheap and while the only thing at stake is an
argument.

The text is dedicated to the public domain rather than licensed. A licence on a founding charter
is a leash on a fork, and Article 17 makes the right to fork a right rather than a threat. Any
successor, rival or unrelated project may copy this document entire, adapt it, or improve on it
without asking anyone.

## Preamble

The web was built on the assumption that names and storage were plumbing — dull, neutral, and
too boring to fight over. That assumption is dead. Whoever answers the question "where does this
name point" decides what exists, and whoever holds the bytes decides for how long. Those two
powers have collected into a small number of companies, operating under a small number of
governments, and they are now exercised routinely: a registrar suspends, a resolver declines, an
authority revokes, a host removes, a network decides a publisher is not worth the trouble. None
of this requires malice. It requires only that the power exist and that someone ask.

VayuWeb exists because that power should not exist in a form anyone can be asked for. Not because
its current holders are wicked — most are not — but because a right that depends on the
continued goodwill of an intermediary is a privilege wearing a better coat. The remedy is not to
find kinder intermediaries. It is to build a system in which the request has nowhere to land: no
root to seize, no register to compel, no key that unlocks another person's name, no office that
could grant a favour even if it wanted to.

This charter therefore spends most of its length on refusals. VayuWeb will not issue a token. It
will not hold a treasury. It will not create a body with the authority to decide who deserves a
name. It will not adjudicate trademarks, truth, or merit. It will not build a mechanism to
remove a name, because a mechanism that can rescue you is a mechanism that can be turned against
you, and over a century it always is. What cannot be done under pressure is worth more than what
is merely promised, so wherever this document could have chosen a policy it has tried instead to
choose an impossibility.

It is equally a document of admissions. VayuWeb cannot make anyone anonymous. It cannot promise
that a page will still load tomorrow. It cannot forget what an append-only log already carries,
nor compel a stranger to discard bytes they have lawfully copied. It cannot stop a state from
severing a cable or compelling a person. A charter that overclaims does not survive its first
collision with reality, and the honest limits set out in Title III are as binding as any of the
rights in Title II — and harder to keep.

To whoever is reading this long after everyone who wrote it is gone: nothing here was meant to
bind you to our judgement. The entrenched core exists to protect your ability to make your own,
not to freeze ours. If this project has become the thing it was built to replace — if some
office now decides who may hold a name, if a fee appears, if the log acquires a privileged
writer — then the charter has already failed, and Article 59 is addressed to you. Take the
state, take the specifications, take this text, and leave. That exit is not a failure of the
system. It is the last working part of it, and it was put there on purpose.

## How to read this document

**Normative language.** MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT, MAY and REQUIRED
carry the meanings assigned in Article 3, which is stricter than casual usage. Where a sentence
is not written in those terms, it is context and not obligation.

**Citation.** Cite by Article and clause: `Article 30.2`, or `Art. 30.2` in running text. A
sub-clause is cited `30.2.a`. Title numbers are for navigation and are never cited as authority.

**What is operative.** The numbered clauses are the instrument. Headings, the Title summaries,
this section, and the table below are navigational and carry no obligation. Where a heading and
its clauses appear to diverge, the clauses govern.

**The Preamble.** The Preamble is interpretive, not enforceable. It may be used to resolve a
genuine ambiguity in an Article; it may never be used to create, enlarge or defeat an obligation
that the Articles do not contain. Where the Preamble and an Article conflict, the Article
governs — except as against the entrenched Articles listed in Article 9, which govern
everything, including any amendment that purports to reach them.

**Numbers are deliberate.** Every threshold, period and quorum in this document was chosen
rather than inherited, and the reason is stated in the clause that sets it. Disagreeing with a
number is a legitimate basis for a VWIP; treating it as arbitrary is not.

## Table of Titles

| Title | Subject | Articles |
|---|---|---|
| **I** | Foundations, Doctrine and the Entrenched Core | 1–9 |
| **II** | The Bill of Rights | 10–20 |
| **III** | Limits, Non-Guarantees and Honest Disclosure | 21–28 |
| **IV** | The Registry, the Namespace and Naming Law | 29–38 |
| **V** | Governance and Protocol Evolution | 39–49 |
| **VI** | Trust Chain, Continuity, Amendment and the Last Resort | 50–60 |

The full list of Articles appears at the head of each Title.

---

## Title I — Foundations, Doctrine and the Entrenched Core

*What VayuWeb is, the words that make its rules decidable, and the commitments no process here may undo.*

### Article 1. Name, Nature, Non-Incorporation and the Canonical Text

1.1 VayuWeb is a protocol, a specification and a namespace. It is not a company, a product, a
service, an asset or a legal person.

1.2 VayuWeb SHALL have no seat, domicile, registered office, treasury, account, employees or
officers, and no procedure in this Constitution SHALL create any of them.

1.3 No claim of ownership over VayuWeb has any effect on conformance. An assertion that any
entity — company, foundation, association, collective, trust, estate, or any successor form
of organisation not yet invented — "is" VayuWeb, owns it, controls it, or speaks for it SHALL
be void on its face, and conformance SHALL continue to be determined only by the tests
stated in this Constitution.

1.4 Implementations, clients, indexes, mirrors, gateways and hosted services MAY be owned by
anyone. The protocol MUST NOT be.

1.5 Persons MAY form entities to receive grants, hold equipment or employ people. No such
entity SHALL hold anything load-bearing for registration, renewal, transfer, resolution,
publication or node participation (Arts. 4, 59).

1.6 The name "VayuWeb" is not a controlled asset and confers no authority. A party asserting
exclusive rights in the name, in any jurisdiction and by any instrument, thereby acquires no
power over any Name, Record, Node, Implementation or Reader. Should the name become
encumbered, participants MAY carry these rules forward under a different name without
amending this Constitution. What is entrenched is the substance, never the label.

1.7 This Constitution SHALL have exactly one canonical text, in English, byte-exact,
content-addressed and signed. Its identity is its digest under a hash-function family
recorded in the Annex (Art. 2). Any reader MUST be able to recompute that digest offline
from the text alone, without consulting any party, service or network.

1.8 Hash agility is provided so that the anchor outlives its mathematics. When a hash
function weakens, the Annex MAY admit a successor, and the canonical text SHALL be
re-anchored under both, the two digests being taken over identical bytes. Re-anchoring MUST
NOT alter a single byte of the text; a re-anchoring that alters text is an amendment, and is
void unless made under Title V, and void absolutely where it touches entrenched substance.

1.9 The canonical digest SHALL be anchored in the registry genesis record once a registry
exists, and until then in every published distribution of the specification, so that the
document is carried by the network it governs rather than by a website. Absence or loss of
an anchor confers on no party the authority to declare a different text canonical.

1.10 Where copies differ, the anchored digest prevails, and a copy that does not match it is
not the Constitution. This test is decidable by one reader holding the text and a hash
function, which is the only kind of test this document relies on.

1.11 Recommendation — durability of copies. The canonical text SHOULD be mirrored in no
fewer than three Independent Archives (Art. 2) and deposited in durable print in no fewer
than two physically separated locations. Three is chosen because two mirrors resolve a
difference only by argument, while three let an ordinary reader see which copy is the
outlier. Because no participant can compel another to mirror anything, this is a
Recommendation under Article 3.6: failure to mirror never invalidates the text and never
excuses non-conformance elsewhere.

1.12 Translations are informative. Each translation MUST carry a notice to that effect. A
translated Article never creates an obligation absent from the canonical text, and a
translation MUST NOT be cited as authority against it.

1.13 Charter-stage disclosure. Nothing in this Constitution asserts the present existence of
running infrastructure. VayuWeb is specified here, not shipped. Every operative sentence is
written in the normative future.

1.14 All project material — specification, site, client copy, release notes, presentations —
MUST describe unimplemented components as forthcoming. Describing a component as operating
before it exists is a conformance violation reportable under Article 21.

1.15 Clauses 1.13 and 1.14 describe a drafting condition, not a permanent one. As each
component ships and passes the tests it claims, the charter-stage disclosure retires for
that component alone. The duty of honest claiming does not retire, in any era, for any
component.

1.16 The limits of this Article are stated plainly, because a reader deserves the honest
version. This Constitution creates no legal person, appoints no representative, and confers
on nobody the capacity to accept obligations on behalf of participants. It cannot determine
what any jurisdiction does to any person within its reach. What it can do, and does, is
ensure that no participant holds a key, a switch, an office or a credential whose surrender
would deliver the network: a demand can compel a person, and still not compel the protocol,
because the protocol is what everyone else keeps running.

### Article 2. Definitions, the Layer Map and Authority Boundaries

2.1 This Article defines every term on which a Conformance Test depends, so that a violation
is decidable rather than arguable. A test that relies on an undefined term is not a
Conformance Test.

2.2 **Label** — one syntactic component of a Name. **Name** — an ordered sequence of Labels
terminating in a TLD. **TLD** — a top-level Label admitted to the namespace under Title IV.

2.3 **Registry** — the replicated, append-only, signed log of Records. **Record** — one
signed entry. **Record Chain** — the ordered Records bearing on a single Name.
**Registrant** — the holder of the Ownership Key for a Name.

2.4 **Ownership Key** — the keypair in which ownership of a Name vests (Art. 6).
**Operational Key** — a scoped, expiring key authorised by signature of an Ownership Key.
**Signature Domain** — the domain-separation string binding a signature to one purpose, so
that a signature made for one operation cannot be replayed as another.

2.5 **Epoch** — the protocol's unit of ordered time: a fixed, deterministic interval whose
length is recorded in the Annex. An Epoch boundary MUST be computable offline by any Node
from state it already holds. Epoch length MUST NOT be shorter than one day nor longer than
fourteen days, and MUST NOT be settable, adjustable or announced by any party at run time.
**Activation Epoch** — the Epoch at or after which a ratified change takes effect.

2.6 Time is counted without reference to any calendar, timezone, holiday, era or
jurisdiction. A **day** means eighty-six thousand four hundred SI seconds; a **year** means
three hundred and sixty-five days. Every period in this Constitution is expressed in Epochs
or in days, and a period stated in any other unit is read as the nearest whole number of
days.

2.7 **Resolver** — software mapping a Name to a content pointer. **Local Resolution
Proxy** — a Resolver running under the Reader's own control. **Node** — software holding and
replicating registry state. **Peer** — a Node as seen by another. **Publisher** — a party
offering content. **Reader** — a party requesting it. **Query** — one resolution request.

2.8 **Implementation** — any software speaking the protocol. **Conformant Implementation** —
one passing the public conformance suite (Art. 44) for the version it claims. **Network
View** — the state one Node holds at one moment. **Snapshot** — a checkpointed, verifiable
Network View.

2.9 **Conformance Test** — a procedure that a single Ordinary Participant can run offline,
on their own equipment, that is deterministic and reproducible, and that yields pass or fail
without an act of judgement by anyone.

2.10 The conformance suite is evidence of conformance and never its source. Where no suite
release exists for a claimed version, where the suite cannot be retrieved, or where two
suites disagree, conformance is determined directly against the specification text by the
tests it states. Any participant MAY publish an independent suite, and no suite is
authoritative by virtue of who published it. A definition of conformance that depends on a
particular suite remaining maintained is void under Article 4.

2.11 **Recommendation** — a labelled default, adopted under Article 3.6, that never
determines conformance and never grounds a claim of violation.

2.12 **Published** — reproducible from a content address, carrying its reasoning and any
recorded dissent, and retrievable by any participant without an account, a payment, an
identity check, or the permission of a named party. A decision announced only where entry is
controlled is not Published.

2.13 **Independent Parties** — two or more parties are Independent only if none of the
following holds: they are the same person or entity; one directs or owns part of another;
they are under common ownership, common direction, or common beneficial control; their
relevant work is funded from a common source; their relevant operation runs on
infrastructure controlled by one party; or all of them depend on a single jurisdiction to
continue operating. Where any of these holds, or where the question is genuinely in doubt,
they count as one party. An **Independent Archive** is an archive operated by a party
Independent of every other archive counted.

2.14 **Ordinary Participant** — a participant running unmodified conformant software on a
device of median capability for its time, holding no special privilege, key, office or
relationship with anyone.

2.15 **Tombstone** — a signed Record marking a Name relinquished. **Lapse** — the neutral,
mechanical expiry of a Name under Article 32. **Pin** — a commitment to retain content.
**Serve** — to make retained content retrievable.

2.16 **Fork** has three senses, which MUST NOT be conflated: *protocol fork* (divergent
rules), *state fork* (divergent registry history), *name fork* (a distinct namespace bearing
its own identity).

2.17 Resolution (Name to content pointer), retrieval (pointer to bytes) and rendering are
distinct operations, and rights attach differently at each (Titles II and III).

2.18 The registry is a replicated log. A "registry operator" is a role this Constitution
refuses to create, and no Article SHALL be read as creating one, whether by that name or any
other.

2.19 Five layers exist, and each MAY exercise only its own authority.

2.20 **Identity** — keypairs; the sole source of authority over a Name.

2.21 **Registry** — it records and orders; it never judges.

2.22 **Discovery** — it locates; it never gates.

2.23 **Content** — it addresses and replicates; it never determines ownership.

2.24 **Access** — it translates and caches; it never mediates as a required third party.

2.25 Non-escalation. No layer SHALL acquire authority belonging to another. The test is
mechanical: if changing a fact at one layer changes an outcome reserved to a higher layer,
the design is non-conformant. A design in which content availability determines Name
ownership, or in which discovery determines resolution validity, fails this test.

2.26 This Constitution names functions, not products. Concrete primitive families — an
append-only signed log, a peer-discovery substrate, a content-addressed store, a
signature scheme, a hash function — SHALL be recorded in a versioned Annex maintained under
Title V, and MUST NOT be written into constitutional text. A charter that names its
dependencies dies with them.

2.27 The Annex is a record, not an authority. Where no current Annex exists, the last
published Annex remains in force until superseded under Title V. Staleness or absence of an
Annex never invalidates a Record already valid, never suspends any obligation here, and
never confers on any party the power to declare which primitives are in force.

2.28 Primitive migration. When a primitive weakens, the Annex MAY admit a successor and set
a migration period expressed in Epochs. Migration proceeds only by each Registrant signing
successor key material with the incumbent Ownership Key. No party, process or majority MAY
reassign, freeze, re-issue or re-key a Name on the ground that a primitive has weakened, and
a migration design that permits this is non-conformant under Articles 4 and 6.

2.29 The honest limit. If a primitive is broken outright before a Registrant migrates, that
Name may be lost or contested, and this Constitution provides no rescue. The omission is
deliberate: every mechanism capable of restoring a Name to its rightful holder is a
mechanism capable of handing that Name to someone else.

2.30 The **Namespace Annex** is a distinct instrument from the primitives Annex of 2.26, and
2.27 does not reach it. It is the enumeration of top-level domains incorporated by Article 35.1,
it is normative, and it is pinned: its contents at commencement are fixed by the canonical digest
of Article 1.7, and thereafter it changes only by a ratified Naming-category VWIP under Article
35.6. The two Annexes are separated because they answer to opposite pressures. The primitives
Annex must be replaceable without an amendment, or the charter dies with SHA-2. The Namespace
Annex must not be, because an editable list of valid extensions is a mechanism for deciding
whose Name resolves — which is the power Article 6 vests in a keypair and nowhere else.

2.31 A Node MUST determine TLD validity by membership of the Namespace Annex it holds, computed
offline, with no network access and no query to any party. An implementation that fetches,
subscribes to, syncs or derives the valid set at run time is non-conformant under Article 4,
whatever the source and however reputable — a namespace that arrives over the network is a
namespace someone can withhold.

### Article 3. Normative Language and Rules of Interpretation

3.1 RFC 2119 keywords are adopted under a strict usage discipline, and MUST be used only as
set out in 3.2 to 3.5. No other word carries normative force; where any other term of
obligation appears, it is non-normative prose.

3.2 MUST / MUST NOT — conformance-determining requirements, testable under Article 2.9 and
by the suite of Article 44.

3.3 SHALL / SHALL NOT — standing obligations of the protocol and its processes, of the same
binding force as MUST, and used where the subject is the protocol or a process rather than
an Implementation.

3.4 SHOULD / SHOULD NOT — defaults departable only with a reason Published under Article 2.12.

3.5 MAY — genuine optionality, conferring no obligation on anyone, and never to be read as
permission that others must respect beyond their own conduct.

3.6 The demotion rule. Any obligation that cannot be made self-enforcing — that is, detected
by an Ordinary Participant running unmodified software — MUST be written as a Recommendation
and labelled as such, so that no reader mistakes a wish for a guarantee.

3.7 Precedence, highest first: this Constitution; Final VWIPs; published Annexes; the
published conformance suite; implementation documentation. Where a lower instrument
conflicts with a higher one, the higher governs and the lower is void to the extent of the
conflict.

3.8 Draft VWIPs are informative. They bind nobody, determine no conformance question, and
confer no expectation that they will advance.

3.9 A reference implementation never outranks a specification. Where they disagree, the
specification governs and the implementation is defective.

3.10 Interpretive canons, themselves entrenched under Article 9.

3.11 Ambiguity resolves toward the registrant, the publisher, the reader and the node
operator, and against any party asserting authority over them.

3.12 No power is implied. A capacity not expressly granted by this Constitution or by a
Final VWIP does not exist, and MUST NOT be inferred from silence, custom, convenience,
precedent, emergency or operational necessity.

3.13 Where two readings remain open after 3.11 and 3.12, the reading that leaves the smaller
number of parties able to prevent or compel the operation prevails. Where that number is
equal, the reading requiring the cooperation of fewer parties for an Ordinary Participant to
proceed prevails.

3.14 Interpretation is vested in no body. There is no court, no appellate bench, no panel
and no office of the editor. No person or group SHALL claim final interpretive authority,
and a claim to it is evidence under Article 59.

3.15 Interpretive disputes are settled in three ways only: by Conformance Test, by refusal
to interoperate, and by fork (Art. 59).

3.16 Published reasoning about interpretation accumulates as persuasive record. It binds
nobody, creates no precedent that a later reader MUST follow, and confers no standing on its
author.

3.17 Entrenchment is read as covering substance and effect, not wording (Art. 9.19).

3.18 Headings, the Preamble and any explanatory annotation are non-normative. No obligation
SHALL be read out of them.

3.19 A cross-reference is a convenience, never a condition. Where a referenced Article has
been renumbered, moved, or has not yet been drafted, the reference is read as pointing to
the clause bearing the same substance. A broken, dangling or unwritten reference never voids
an obligation, never suspends a prohibition, and never opens a gap through which a
prohibited act may pass.

3.20 Severability. If a clause that is not entrenched is held inoperable, the remainder
stands. An entrenched clause MUST NOT be severed; where an entrenched clause has been made
inoperable in practice, that condition is not cured by severance and is a fork condition
under Articles 9 and 58.

3.21 Language drift. Terms defined in Article 2 keep their defined meaning however ordinary
usage later shifts. Where an undefined word's ordinary meaning has shifted, the reading
consistent with the purpose stated in Article 9.25 prevails.

3.22 There is no emergency. Nothing in this Constitution creates emergency powers, and no
claim of urgency, attack, defect, hostile fork, legal threat or existential risk enlarges
any power by one clause. A provision purporting to suspend any part of this Constitution,
however briefly and however justified, is void.

### Article 4. The No-Chokepoint Invariant

4.1 This Article states the load-bearing structural rule of VayuWeb, from which most of Title
II follows.

4.2 No function of the protocol SHALL require the cooperation, availability or permission of
any single party, service, name, entity, key or jurisdiction. The functions covered are
registration, renewal, transfer, resolution, publication, update, node participation, client
bootstrap, release verification, specification and Annex retrieval, conformance testing, and
the determination of Epoch boundaries.

4.3 The invariant is specified as an auditable procedure, not a sentiment. For each required
step of each function, a Dependency Enumeration SHALL list every party whose withdrawal
would prevent completion of that step, counting parties that are not Independent under
Article 2.13 as one party.

4.4 Where any step yields a set of size one, the design is non-conformant. Such a step MUST
be redesigned to admit alternatives, or made optional.

4.5 Every release claiming conformance MUST ship its own current Dependency Enumeration, in
machine-readable form, retrievable from the same distribution as the release itself. A
release shipped without one is non-conformant. This is the self-enforcing part of the
Article: any user can check that the file is present and re-run its removal tests.

4.6 Any participant MAY compute and publish an independent enumeration. No enumeration is
authoritative by virtue of who published it, and a contested claim is resolved by re-running
the removal test, never by deference to its author.

4.7 The test binds expressly to the places a chokepoint actually appears: bootstrap peer
lists; release distribution; release signature verification; specification, Annex and
documentation hosting; registration-cost parameters; any shipped default resolver; any
shipped default pinning or retention provider; any single source-code host; any single
package, update or app-distribution channel; any single certificate, attestation or identity
issuer; and any single time source.

4.8 The acceptance criterion, in one line: if the removal of any one party degrades user
experience, that is acceptable; if it breaks correctness, the design is unconstitutional.

4.9 Convenience defaults are permitted; necessity is not.

4.10 Every shipped default MUST be inspectable, editable, replaceable and removable, and the
software MUST function fully with that default removed. A default that cannot be removed is
a requirement wearing a softer word.

4.11 A conformant client MUST be able to complete first-run bootstrap from peer information
supplied entirely by the user, with every shipped source disabled, and MUST NOT require for
that purpose any account, any payment, any naming system outside VayuWeb, or any service
reachable only from a particular jurisdiction.

4.12 The invariant applies to its own audit. No clause of this Constitution requires a named
person or standing group to perform the enumeration, because such a requirement would itself
be a chokepoint. The obligation attaches to the release, and the check is available to
everyone.

4.13 Enumeration results feed the concentration metrics and the periodic withdrawal drill of
Article 53. Failure by anyone to run that drill never suspends 4.5 and never excuses a
release shipped without an enumeration.

4.14 This Article is entrenched under Article 9.

### Article 5. Impossibility Over Policy and the Rule of Self-Enforcement

5.1 Where a power would be dangerous if abused, the protocol MUST be designed so that the
power does not exist, rather than existing under a rule forbidding its use.

5.2 The reasoning is stated so it is not relitigated: a capability that exists will
eventually be demanded by someone holding legal power, market power or a majority, and
policy is a weaker shield than architecture. A rule can be suspended in an afternoon; an
absent capability cannot be invoked at all.

5.3 The companion rule. A constitution for a protocol cannot be enforced by anyone, so it
MUST be enforceable by everyone. Every guarantee in this document SHALL be written so that a
single honest participant, running unmodified software, can detect its breach and continue
operating without asking permission.

5.4 A proposed guarantee that fails 5.3 MUST be demoted to a Recommendation under Article 3.6 rather than adopted as an obligation.

5.5 Every VWIP MUST carry an impossibility-and-capture analysis answering, in writing and in
terms a reader can check: what new capability does this confer; on whom; what new dependency
does it create; who gains power if it is adopted; and why can that capability not be removed
from the design.

5.6 A VWIP that leaves any of the five questions unanswered MUST NOT advance beyond Draft,
regardless of support. Any participant MAY identify the unanswered question by citing it.
Advancement while a question stands unanswered is void under Article 8, not merely
irregular.

5.7 Clients validate substance, not provenance. A change that violates an entrenched clause
MUST be rejected by a conformant client even when signed by every maintainer simultaneously
(Art. 8.3).

5.8 Reviewers are directed to ask not "who would abuse this" but "what does this make
possible". Any answer that includes a party able to affect a Name whose Ownership Key they
do not hold is disqualifying, and the proposal MUST be rejected on that ground alone. Three
things are outside this test and are not disqualifying: the neutral mechanical operation of
Lapse (Art. 32); a party's own decision not to carry, serve, pin or peer, which affects
availability and never ownership; and an arrangement the Registrant authorised in advance by
their own signature (Art. 6).

5.9 The doctrine applies to operational conduct as well as design. A process that depends on
the continued good faith, attention or survival of a named person or a standing group is a
policy shield, and MUST be redesigned toward a mechanism any participant can run alone.

5.10 This Article is entrenched under Article 9.

### Article 6. Sovereignty of Keys

6.1 Ownership of a Name vests in a keypair. It does not vest in an account, an identity, a
person, or a record of a person.

6.2 VayuWeb SHALL NOT define an account. No Article, VWIP or implementation MAY introduce one
as a condition of registration, resolution or publication.

6.3 Ownership MUST NOT depend on identity, nationality, incorporation, payment, reputation,
identity verification, attestation, age, geography, or the approval of any party.

6.4 There is no recovery authority, no administrative key, no custodian, no override key and
no protocol-level escrow. Any such construct is a chokepoint under Article 4 and is
prohibited outright rather than regulated.

6.5 Key rotation, delegation of scoped and expiring Operational Keys, and opt-in designation
of successor keys — whether threshold-based or social — are permitted only where authorised
by a valid signature made in advance by the incumbent Ownership Key. The machinery is at
Article 34.

6.6 A successor arrangement MUST be verifiable from the Record Chain alone; MUST state its
triggering conditions deterministically, so that whether it has triggered is decidable
offline by any Node without an act of judgement; MUST remain revocable by the incumbent
Ownership Key at any time before it triggers; and MUST be surfaced by conformant clients
while it is in force. An arrangement whose trigger requires anyone to form an opinion is
non-conformant.

6.7 A successor arrangement takes effect only on the terms the Registrant signed. No party
MAY construct, alter, extend or invoke such an arrangement on a Registrant's behalf. Such
arrangements are authority the keyholder granted, never authority the network conferred.

6.8 No party, process, majority, editor, steward, court, claim of emergency or amendment
SHALL be able to transfer, suspend, redirect or extinguish a Name against the will of the
keyholder, save by the neutral mechanical operation of Lapse (Art. 32) or by a Tombstone the
Registrant themselves signed.

6.9 Every conformant client MUST surface the consequence at key-generation time, in plain
words on screen, and MUST NOT reduce it to a checkbox or bury it in a document the user is
not shown.

6.10 The consequence, stated as clients MUST state it: loss of the Ownership Key is
permanent loss of the Name until Lapse. This is a deliberate design choice, not an oversight
— any mechanism able to return a Name to its rightful owner is able to give that Name to
someone else, and will eventually be compelled to do so.

6.11 The honest limit. The protocol cannot protect a keyholder from coercion, theft, device
seizure or their own error. A signature made under duress is indistinguishable from a
signature made freely, and the protocol MUST NOT attempt to distinguish them, because every
mechanism that could would also be a mechanism for reversing legitimate transfers. What is
guaranteed is narrower and real: no one else's key will do.

6.12 This Article is entrenched under Article 9.

### Article 7. No Token, No Treasury, No Protocol Fee

7.1 VayuWeb SHALL NOT have a native token, coin, share, unit of account, staking mechanism, fee
market, rent, escrow, bonded deposit redeemable to any party, or protocol-level treasury of
any kind, under any name.

7.2 There SHALL be no premine, no allocation of Names or rights to founders, drafters or
funders, and no instrument conferring governance weight in exchange for value of any kind.

7.3 Registration and renewal SHALL be priced in computation, not in money. The cost SHALL be
burned rather than collected: no party receives value from it, and it MUST be payable by any
participant without transacting with anyone (Art. 31).

7.4 Cost parameters SHALL be derived algorithmically from registry state alone, and MUST be
computable offline by any Node. No party SHALL set, tune, publish or announce them. A design
in which any party performs that role is a chokepoint under Article 4 and is non-conformant.

7.5 The derivation SHALL be bounded so that cost deters bulk acquisition without becoming a
wealth test. It SHALL target a registration attainable within one hour of work by a device
of median capability for its time, and MUST NOT be capable of requiring more than
twenty-four hours of such work for a single registration. The current targets sit in the
Annex; the ceiling in this clause does not.

7.6 The honest limit. Computation is not equally cheap for everyone, and pricing in work
advantages those with more of it. The ceiling in 7.5 bounds that advantage; it does not
abolish it, and this Constitution does not pretend otherwise.

7.7 No participant SHALL be able to acquire, by payment or by any transfer of value, any of:
governance weight; priority resolution; preferential propagation; default placement in any
shipped client; or namespace advantage of any kind.

7.8 Funding of people and infrastructure is permitted and expected, and SHALL always be
external to the protocol. Funds flow to people and to code, never to VayuWeb, so that defunding
a project cannot defund the protocol.

7.9 Funded work MUST be published under the same licence as the rest of the specification
and MUST be forkable on the day it is published.

7.10 Any arrangement that makes continued protocol operation contingent on continued funding
SHALL be unconstitutional, and MUST be redesigned under Article 4 before release.

7.11 Anyone participating in governance MUST disclose material interests into the public
capture register (Art. 53): employment, funding, holdings, Names implicated by a proposal,
and infrastructure a proposal would strengthen.

7.12 Disclosure is a continuing duty. An interest acquired during a proposal's life MUST be
disclosed within the same Epoch in which it arises. Where the register is unavailable,
disclosure Published under Article 2.12 in any archived venue discharges the duty; the
absence of a register never excuses non-disclosure.

7.13 The design intent is stated so later readers understand the omission was chosen: there
is no pot of value large enough to be worth capturing, and therefore nothing to fight over
in year forty. A protocol with a treasury acquires, on the day the treasury is created, a
constituency whose interest is the treasury rather than the protocol.

7.14 This Article is entrenched under Article 9.

### Article 8. Void Ab Initio: Compelled, Purchased and Ultra Vires Acts

8.1 Any change to the specification, the registry, release artefacts or the governance
record SHALL be void where it is procured by legal compulsion, undisclosed payment, threat,
coercion, fraud, or by an actor acting outside the powers this Constitution grants. Voidness
applies whether or not the coercion is disclosed, and whether or not the actor held authority
at the time.

8.2 The grounds in 8.1 divide honestly. An act outside granted powers is detectable by any
client, because the test is substantive and is stated in 8.3. Compulsion, payment, threat
and fraud are detectable only when disclosed or later proven; as to those, this Article
operates by making the act permanently challengeable rather than by promising detection.

8.3 Conformant clients MUST validate substance rather than provenance. A signed change that
violates an entrenched clause MUST be rejected even when signed by every maintainer at once,
and a client that would accept it is non-conformant.

8.4 Signature authority is a necessary condition of validity and never a sufficient one. "It
was properly signed" is not an answer to "it was not permitted".

8.5 Publication is a condition of validity. No decision of any process has effect unless it
is Published under Article 2.12, together with its reasoning and its recorded dissent.
Decisions taken in private are void, and remain void if published afterwards as a fait
accompli.

8.6 Embargo is the narrow exception. It is permitted only for an unpatched security defect
or a specific risk to an identified person's safety.

8.7 An embargo is not a power over other people. It licenses one party to delay its own
disclosure of one fact; it obliges no one else to withhold anything, binds no participant who
learned the fact independently, and suspends no other clause of this Constitution. Any
participant who holds the fact MAY publish it, and doing so is not a violation.

8.8 An embargo MUST be declared at the time it is imposed, stating that an embargo exists
and its category, without disclosing the protected detail.

8.9 An embargo MUST be time-boxed at ninety days or less. It MAY be extended once, declared
in public before the original period expires, for one further period of ninety days or less,
giving an absolute maximum of one hundred and eighty days. No further extension is available
by any means, including re-declaration of the same matter under a different description.
Ninety days is chosen because it is long enough to ship and distribute a fix, and short
enough that indefinite secrecy cannot be reframed as prudence.

8.10 Every embargo expires into mandatory retroactive publication of the decision, its
reasoning and its dissent. An embargo that lapses without publication is a violation, and
the decision it covered is void.

8.11 Non-disclosure of a material interest does not automatically invalidate a decision, but
is grounds for challenge under this Article and is evidence under Article 59.

8.12 A void act creates no rights in anyone, including a third party who relied on it in
good faith. Reliance is remedied by re-deciding in the open, never by ratifying the void act.

8.13 There is no limitation period. A void act does not become valid through the passage of
time, through adoption in practice, through incorporation into a later release, or through
the number of users who came to depend on it.

8.14 The effect this Article is designed to produce is stated plainly: compulsion becomes a
public, self-defeating act rather than a control mechanism. The compelled party can comply,
and the network still will not.

### Article 9. The Entrenched Core

9.1 The clauses listed in 9.2 to 9.16 are entrenched. No procedure in this Constitution —
amendment, repeal, VWIP, claim of emergency, vote, consensus, custom or reinterpretation —
MAY amend, repeal, narrow, suspend, condition or render inoperable any of them. Each is
stated by its substance so that entrenchment survives renumbering, redrafting or the loss of
any Article it points to; the cross-references are for convenience only.

9.2 No function of the protocol may require the cooperation, availability or permission of
any single party (Art. 4).

9.3 Dangerous powers are designed out rather than regulated, and every guarantee must be
detectable by a single honest participant running unmodified software (Art. 5).

9.4 Ownership of a Name vests in a keypair, and no party holds a recovery, override or
administrative capability over it (Art. 6).

9.5 There is no native token, no protocol treasury, and no fee levied by anyone on
registration, renewal, resolution or hosting (Art. 7).

9.6 Anyone may register an unheld Name without permission, identity or approval (Art. 10).

9.7 A registered Name may not be revoked, seized, redirected or suspended by anyone other
than its keyholder, save by neutral mechanical Lapse (Art. 11).

9.8 A Reader may resolve and retrieve without identifying themselves, and resolution
metadata may not be made a condition of service (Arts. 13, 14).

9.9 Anyone may fork the specification, the software and the registry state, and no rule,
licence or process may impede it (Art. 17).

9.10 Anyone may leave with their keys, their Names and their data, and no lock-in mechanism
may be introduced (Art. 18).

9.11 No rule applies to conduct or Records preceding its Activation Epoch (Art. 20).

9.12 Nothing may be claimed to work, exist or be secured beyond what has been demonstrated
(Art. 21).

9.13 No process here adjudicates trademark, likeness, reputation or naming disputes, and no
Name changes hands on such a ground (Art. 36).

9.14 There is no governing body, and none may be created under any name (Art. 39).

9.15 The interpretive canons of Articles 3.10 to 3.13.

9.16 This Article, including its own list.

9.17 Entrenchment is self-referential and closed. This Article MUST NOT be amended to
shorten its own list, to add exceptions to any entry, to narrow the substance of an entry, or
to create a procedure by which the list may later be shortened.

9.18 The list MAY be extended by the ordinary amendment procedure. Entrenchment ratchets in
one direction only: an entry may be added, never removed.

9.19 Entrenchment covers substance and effect, not merely wording. A change that leaves an
entrenched clause textually intact while making it inoperable, unusable in practice, or
conditional on a party's cooperation SHALL be treated as a repeal of that clause and SHALL
be void.

9.20 A purported amendment to an entrenched clause is void ab initio. It MUST NOT be
implemented by any conformant client, has no effect on conformance, and is conclusive
evidence of capture.

9.21 The response to 9.20 does not depend on any body, process or quorum, because a defence
that requires a functioning institution fails exactly when it is needed. Article 59 states
the ordinary route. Where no such process exists, functions, or can be convened, any
participant MAY treat a conformant fork as the continuation of VayuWeb, and conformant clients
MAY follow it, with no further formality and no one's approval.

9.22 A procedurally perfect vote does not cure substantive voidness. Unanimity does not cure
it either. Process is how permitted changes are made, not how the impermissible becomes
permitted.

9.23 The limit of the device is stated honestly, because a reader deserves to know what this
Article can and cannot do. Entrenchment is not a technical impossibility. It cannot
physically stop a determined majority from writing different software and persuading people
to run it.

9.24 What entrenchment does instead is twofold. First, it declares that a network violating
any clause in 9.2 to 9.16 is not VayuWeb, whatever it calls itself, whoever maintains it and
however many users it holds. Second, it converts capture from an ambiguous slide into a
legible, pre-agreed event: the release of the name, the state and the users to a conformant
fork (Arts. 17, 18, 58).

9.25 Every Article of this Constitution is read in light of the purpose stated in this
Title — that a Name belongs to whoever holds the key, that publication requires no
permission, and that no party's withdrawal stops any of it. A reading that satisfies the
words while defeating that purpose is the wrong reading.

---

## Title II — The Bill of Rights

*Eleven rights of registrants, publishers, readers, operators and implementers, each stated
as an obligation on software, bounded by what the protocol can physically deliver, and
checked by a mechanical test that anyone can run.*

### Article 10. The Right to Register a Name Without Permission

10.1 Any party holding an ownership keypair under a signature suite in force at the record's
epoch, and able to produce the proof-of-work required by Article 31, SHALL be able to
register any name that is unregistered at that instant, in any TLD then open for
registration.

10.2 Registration SHALL require no application, no identity, no account, no contact address,
no payment to any party, no allowlist, no reserved-name list held by anyone, no queue
management and no discretionary review. There is no admissions process because this
Constitution establishes no body competent to admit, and forbids the creation of one.

10.3 Implementations MUST accept and propagate a well-formed, validly signed,
sufficiently-worked REGISTER record without regard to who the registrant is, what the name
means, or what content the name will point to. Content-blindness at registration is absolute
and admits no exception, however sympathetic.

10.4 No code path in a conformant implementation MUST consult an external service, a
reputation source, a sanctions list, a blocklist, a trademark database or a classifier
before accepting, storing or relaying a registration. For the purposes of this Title, a
*protocol peer* is a party that speaks the wire protocol of Article 29 and asserts nothing
beyond it; every other correspondent is an external service.

10.5 The only grounds on which a conformant implementation MAY refuse a REGISTER record are:

10.5.a malformation under the canonical encoding of Article 30;

10.5.b an invalid signature under a suite in force at the record's epoch;

10.5.c work below the threshold in force at that epoch;

10.5.d a prior live claim on the same name under Article 32;

10.5.e a uniform resource limit applied under clause 10.6.

These five grounds are exhaustive. No sixth ground SHALL be introduced by implementation,
convention, VWIP or amendment.

10.6 A resource limit under clause 10.5.e MUST be a published numeric rate or size limit,
MUST be applied identically to every submitting party without regard to key, name, TLD or
content, MUST NOT be varied by any property of the record other than its size and arrival
rate, and MUST leave the submitting party able to retry successfully once the limit clears.
A limit whose observable effect differs between two well-formed records of equal size is not
a resource limit but a refusal on a prohibited ground, and violates this Article.

10.7 A refusal on any permitted ground MUST be mechanical, MUST be reported to the
submitting party with the ground named, and MUST be reproducible offline by that party from
public data alone.

10.8 Reserved names are forbidden. No implementation, no VWIP and no amendment SHALL
withhold a string, a pattern or a length class from registration for later allocation by
anyone, including any editor, steward, working group, funder or successor body of this
Constitution. Structural limits imposed by the canonical encoding of Article 30 MUST be
uniform, MUST be stated as a rule rather than a list, and MUST NOT hold any name or class of
names in reserve for allocation by any party.

10.9 A TLD that has been open for registration MUST NOT be closed, retired or suspended in a
way that affects names already registered in it. Closure to *new* registrations MAY occur
only prospectively under Article 20, and names already held in a closed TLD MUST continue to
be renewable, transferable and resolvable on their original terms.

10.10 Visual confusability between names is a display problem and MUST NOT be treated as a
registration problem. Implementations MUST NOT refuse, delay or flag a registration because
a name resembles another. Conformant clients MUST render names in the canonical encoding of
Article 30, MUST make the exact codepoint sequence of any resolved name inspectable in one
action, and SHOULD warn where a displayed name is confusable with one the reader has used
before. Such a warning MUST NOT alter what the name resolves to.

10.11 The honest bound. Registration is free of rent, not free of cost: proof-of-work
consumes energy and time, and that cost is the only thing standing between an open namespace
and a machine that takes all of it. This Article guarantees that no party may charge for a
name or refuse one; it does not guarantee that work will always be cheap for everyone
everywhere.

10.12 **Conformance Test.** An implementation or process violates this Article if there
exists any well-formed, validly signed, sufficiently-worked REGISTER record it refuses to
accept or relay on a ground outside clause 10.5; if two records of equal size and arrival
rate receive different treatment under clause 10.6; or if any registration code path opens a
network connection to a party other than a protocol peer.

10.13 **Machinery.** Articles 29, 29 and 30 make this right operative. This Article is
bounded by Articles 25 and 26: registration is a first-come record of a key's claim, not an
adjudication of entitlement, and confers no immunity from any law that reaches the
registrant.

10.14 This Article is entrenched under Article 9.

### Article 11. The Right to Hold, Renew and Not Be Revoked

11.1 A registered name SHALL remain under the control of its registrant's ownership key
until one of exactly two things occurs: a record signed by that key transfers or relinquishes
the name, or tenure lapses through the absence of a signed renewal under a rule published
before that tenure began.

11.2 The protocol SHALL define no mechanism by which any party, process, majority, editor,
steward, working group, funder, relayed order or declared emergency can revoke, reassign,
suspend, redirect or freeze a name. There is no administrative override, and the absence of
one is a property of the record format itself rather than a promise of restraint. What law
may compel of a person is outside the reach of this document and is addressed in Article 26;
what the protocol offers as a lever is nothing.

11.3 The protocol SHALL NOT define a registry-operator class, a moderator role, a
trusted-notifier channel, or any key whose signature can mutate a record it does not own. An
implementation that ships such a key is non-conformant on that fact alone.

11.4 Lapse MUST be purely mechanical. Tenure length, the renewal window, the redemption
interval and the lapse instant MUST be computable in advance and offline by the registrant
from public data alone, and MUST NOT be contingent on anyone's judgement, on a live service,
or on any party's willingness to act.

11.5 Time. Every epoch in this Constitution is an integer count of SI seconds elapsed since
the fixed origin instant designated 1970-01-01T00:00:00Z, counted without leap seconds.
Every duration in this Title is an exact count of SI seconds and is stated as such. No
calendar, timezone, locale, leap-second table, civil time authority or time-serving party is
required to evaluate any rule in this Title, and no implementation SHALL introduce a
dependency on one.

11.6 Tenure runs for 126,230,400 seconds (1461 days, approximately four years) from the epoch
of the latest REGISTER or RENEW record signed by the ownership key. A RENEW MAY be signed at
any moment while the name is held; it resets tenure to that record's epoch plus 126,230,400
seconds. Tenure does not accumulate, and no sequence of renewals extends it beyond one full
term from the most recent record. This length is chosen so that a holder who is offline, ill,
imprisoned or simply inattentive across one ordinary human interruption does not lose a name,
while a genuinely abandoned name returns to the pool within a single term.

11.7 A record whose declared epoch exceeds the receiving party's own clock by more than
86,400 seconds MUST NOT be treated as current until that epoch arrives, and MUST NOT be
discarded for that reason alone. This bound caps forward-dating without requiring any party
to agree with any other about the time.

11.8 Redemption. For 7,776,000 seconds (90 days) after tenure ends, the only record a
conformant implementation MAY accept for that name is a RENEW signed by the incumbent
ownership key; REGISTER records from other keys MUST be refused under clause 10.5.d during
that interval. When the redemption interval ends without such a renewal, the name enters the
pool.

11.9 Renewal MUST require no counterparty, no live service, no third-party availability and
no fee to any party, and MUST be automatable by the registrant's own software without
supervision.

11.10 Conformant clients MUST warn the holder throughout a window beginning 7,776,000 seconds
(90 days) before tenure ends and continuing through the redemption interval. The warning MUST
appear at every start of the client and no less often than once per 604,800 seconds (7 days)
of continuous running, MUST appear in the ordinary interface rather than only in a log file,
and MUST state the exact lapse epoch and the exact redemption epoch.

11.11 A lapsed name re-enters the pool under Article 32 and SHALL NOT be pre-allocated,
auctioned, held back, prioritised, or offered to any party ahead of the ordinary first-come
rule of Article 10.

11.12 The honest bound. Nobody can renew on the holder's behalf, and this is deliberate: any
mechanism that lets a third party preserve a name is the same mechanism that lets a third
party take one. A key that is lost is lost, a holder who stops acting eventually stops
holding, and the protocol SHALL NOT offer recovery, escrow, guardianship or appeal, because
each of those is a revocation path wearing a kinder name.

11.13 **Conformance Test.** An implementation or process violates this Article if any code
path produces a change in a name's controlling key without a valid signature from the
incumbent key; if the computed lapse or redemption instant for any name depends on any input
the registrant cannot obtain and evaluate offline; or if any accepted record extends tenure
beyond its own epoch plus 126,230,400 seconds.

11.14 **Machinery.** Articles 32, 33 and 35. This Article is entrenched under Article 9.

### Article 12. The Right to Publish and to Be Reachable

12.1 A registrant SHALL be able to bind a name to content, and to change that binding at
will, by signing a record with the ownership key and nothing else.

12.2 The protocol SHALL grant no party the power to permit or withhold publication,
replication, pinning or retrieval. Any peer MAY serve, replicate or pin content, and any
reader MAY retrieve it, without seeking anyone's leave; there is no permission to seek and no
office that issues it.

12.3 Implementations MUST NOT gate publication on review, categorisation, reputation, age of
key, geography, language, content type or file size class. Uniform, published size and rate
limits applied under the terms of clause 10.6 are permitted; anything that varies with the
identity of the publisher or the meaning of the content is not.

12.4 Implementations MUST NOT strip, rewrite, reorder, summarise or annotate a publisher's
records in transit, and MUST NOT interpose any required intermediary between publisher and
reader. Optional caches are permitted; mandatory ones are not.

12.5 The protocol MUST remain content-blind. Refusal is legitimate at the edges and
illegitimate in the core: an individual pinning operator, index, search tool, client or
reader MAY decline to carry, list or display anything at all, for any reason or none, and
this Constitution does not oblige a single person to host a single byte.

12.6 The honest bound, stated here rather than left to be discovered. What this Article
guarantees is the absence of a permission layer. It does not guarantee an audience, uptime,
bandwidth, latency, durability, discoverability, or the existence of anyone willing to
replicate you. A publication no peer chooses to carry is unreachable, and the protocol will
not rescue it. No implementation or document SHALL describe this right as a guarantee of
availability. See Article 23.

12.7 Conformant clients MUST resolve a name to the binding in the registry's signed record. A
client MAY apply a subscribed filter list only where the reader has opted in explicitly, per
list, under Article 37, and MUST disclose at the point of divergence that a filter, and not
the registry, produced the result.

12.8 A filter list MUST be identified by its publisher and by a digest of its exact contents;
MUST NOT be shipped enabled, substituted, widened in scope, or re-enabled by an update; and
MUST be revocable by the reader in a single action, after which its effect MUST cease within
3600 seconds. The unfiltered result MUST remain reachable from the same interface in which
the divergence was disclosed.

12.9 **Conformance Test.** An implementation violates this Article if a conformant client
resolves a name to anything other than the registry's signed binding without an explicit,
user-initiated, per-list opt-in under Article 37; if a shipped build enables any filter list
by default; or if publishing a binding requires a handshake, token or acknowledgement from
any party other than a protocol peer.

12.10 **Machinery.** Articles 29, 29 and 36. Bounded by Article 23.

### Article 13. The Right to Read Anonymously

13.1 Reading SHALL require no identity, no account, no key, no registration, no invitation
and no persistent identifier. A reader owes the network nothing.

13.2 Implementations MUST NOT require, derive or emit a client identifier that is stable
across sessions, and MUST NOT condition resolution or retrieval on the presentation of one.

13.3 The protocol SHALL provide no primitive by which a publisher can compel identification
as a condition of naming or resolution. A publisher MAY build authentication above the
protocol for their own content, at their own layer, using their own credentials; the naming
and resolution layers SHALL remain indifferent to who is asking.

13.4 Ephemeral connection-level identifiers required by transport security are permitted
where they are freshly generated per session, unlinkable across sessions, and never written
to durable storage by a conformant client.

13.5 Implementations MUST NOT record, in durable storage, an association between a reader and
a name resolved, beyond what that reader has deliberately chosen to keep locally, such as
bookmarks or history the reader can inspect and erase in one action.

13.6 The bound, which MUST be stated wherever this right is described in documentation or
interface copy. The protocol requires no identity of a reader and defines no field that
carries one; that much is a property of the format and is verifiable. Anonymity from the
network is a different claim and is not made here. An observer positioned on the reader's
network path, at the reader's operating system or hardware, or at a serving peer may still
infer a great deal, and no wording in this document changes what such an observer can see.
See Article 24.

13.7 **Conformance Test.** An implementation violates this Article if any resolution or
retrieval path transmits a value that is both stable across sessions and unique to the
installation, user or device; if any protocol message defines a mandatory field identifying
the reader; or if any interface copy describes reading as anonymous without the bound in
clause 13.6 stated alongside it.

13.8 **Machinery.** Articles 14, 51 and 52. This Article is entrenched under Article 9.

### Article 14. The Right to Privacy of Resolution

14.1 The act of looking up a name SHALL NOT be logged to durable storage, aggregated,
correlated, reported, sold or exchanged by any component of a conformant implementation.

14.2 Conformant resolvers MUST hold lookup state only in volatile memory, MUST NOT write it
to durable storage, MUST discard it on process exit, and MUST expire each entry no later than
the shorter of the record's own validity interval and 3600 seconds.

14.3 Conformant implementations MUST NOT transmit queries, name lists, resolution history,
crash contents, stack traces, performance samples or usage analytics to any endpoint.

14.4 Conformant implementations MUST NOT contain telemetry enabled by default, and MUST NOT
contact any endpoint on a schedule by default. No phone-home, no remote configuration fetch,
no licence check. An update check MAY be offered; it MUST be off until the operator enables
it, its endpoint MUST be operator-editable and removable, and it MUST carry nothing beyond a
version string — no installation identifier, no user count, no configuration, no name.

14.5 Any optional diagnostic MUST be off by default, MUST be per-session rather than
persistent, MUST be locally inspectable in plaintext before transmission, and MUST be
removable at build time by a documented flag, so that a distributor can ship a build in which
the code does not exist.

14.6 Where a client offers a remote or shared resolver for convenience, that resolver MUST be
off by default; its answers MUST be independently verified against signatures by the client
rather than trusted; the client MUST disclose, in plain language at the point of enabling,
exactly what that resolver's operator can observe; and no update SHALL re-enable it.

14.7 **Conformance Test — executable, and part of the mandatory suite of Article 51.** A
freshly installed client, on a fresh profile, resolving a single name and retrieving its
content, MUST produce no outbound connection other than those required to resolve that name
and retrieve that content. The suite runs the client in an environment that records every
outbound connection attempt and fails on any additional destination, on any repeated contact
with a fixed destination on a timer, and on any durable file written that contains a resolved
name.

14.8 **Machinery.** Articles 51 and 51. This Article is entrenched under Article 9.

### Article 15. The Right to Run a Node

15.1 The protocol SHALL impose no precondition on running a registry replica, a discovery
participant, a pinning node or a resolver: no registration, allowlisting, certification,
stake, bond, coin, seat, invitation or notice, on any hardware and on any connection. What a
law or a network operator may demand of a person in a given place is outside this document
and is addressed in Article 26; the protocol itself demands nothing.

15.2 The protocol SHALL NOT define a privileged node class, a validator set, a committee, a
seat, a supernode, or any role whose membership is granted, ratified or withdrawn by another
party. A record's weight is its validity and its position in the signed log, and nothing else
— not the operator's uptime, holdings, age, reputation or identity.

15.3 Peers MAY choose whom they connect to, and MAY disconnect from anyone at any time for
any reason. The protocol MUST NOT define a global list of acceptable peers, and no
implementation SHALL ship one.

15.4 Any bootstrap list MUST contain no fewer than three entries under distinct operational
control, MUST be editable, replaceable and removable by the operator, and MUST be documented
as a convenience rather than a dependency. A conformant client MUST accept operator-supplied
peer addresses and MUST be able to join the network from any single reachable peer. A client
that cannot participate after every shipped bootstrap entry is deleted and replaced by an
operator-supplied one is non-conformant.

15.5 Peers MUST reject records that do not verify, MUST relay records that do, and MUST NOT
selectively withhold valid records they hold from peers requesting them. Partial replication
is a permitted and expected optimisation; selective suppression of specific valid records is
a defect.

15.6 No operator SHALL be required to carry any particular record or content in order to
remain a peer. Clause 15.5 constrains what an implementation does with what it holds; it does
not compel anyone to hold anything.

15.7 Absence is the attackable answer, so absence is the one that MUST be corroborated. A
conformant client MUST NOT treat the non-existence of a record, the lapse of a name, or the
availability of a name for registration as established on the word of fewer than three
independently reachable peers, MUST report to its operator when peers diverge on any answer,
and MUST NOT silently adopt the smaller view.

15.8 **Conformance Test.** An implementation violates this Article if participation requires
a credential issued by another party; if a node's records are weighted by any property other
than validity and log order; if a shipped default configuration makes a fixed set of hosts
necessary for participation, such that removing them leaves an operator-configured node
unable to join; or if a client reports a name as unregistered on the basis of a single peer.

15.9 **Machinery.** Articles 29, 37 and 51.

### Article 16. The Right to Interoperate and to Implement Independently

16.1 Anyone SHALL be able to write an independent implementation of VayuWeb from the published
specification alone, without licence, fee, permission, certification, registration, notice or
relationship with any party.

16.2 All specifications, test vectors, conformance suites and wire formats SHALL be published
under terms permitting independent implementation, modification and redistribution by anyone,
for any purpose, without royalty. Reference code is published under the MIT licence or terms
no less permissive; normative specification text is published under permissive or
public-domain-equivalent terms. Terms once granted MUST NOT be narrowed retroactively.

16.3 No patent, trademark, trade secret, contractual instrument, terms of service, platform
rule or export claim SHALL be used by any participant to prevent, delay or tax an
interoperating implementation.

16.4 Contributors SHALL make a royalty-free, irrevocable, worldwide non-assertion commitment
covering claims essential to implementing the specification. The commitment MUST run with the
claims and MUST bind successors and assignees, so that selling a patent does not launder it.
Defensive termination is limited to assertions against the protocol itself. Contributors
SHALL disclose essential claims known to them at the time of contribution.

16.5 Copyright assignment to any foundation, company or body MUST NOT be required or
accepted as a condition of contribution. Contributions are accepted on a sign-off basis under
which the contributor retains ownership and grants the stated licence, so that no single actor
ever holds the rights to relicense the whole.

16.6 No party SHALL have the power to declare an implementation non-conformant in a way that
excludes it from the network. Conformance is a public assertion, checkable by anyone against
the public suite under Article 48; it is never a licence granted by an authority, and this
Constitution creates no authority to grant it.

16.7 Specification text MUST be sufficient to build an interoperating client from scratch
without reading the reference implementation. Where behaviour is discoverable only by reading
reference code, the specification is defective, and the defect MUST be filed and fixed as a
specification bug rather than preserved as folklore.

16.8 Publication MUST NOT depend on any single host, forge, registry, archive or service.
Every normative document, test vector and conformance suite MUST be redistributable in full
by anyone, MUST be reproducible from a content-addressed archive, and MUST be published in a
form that remains readable without any specific vendor's tooling. Loss of any one hosting
arrangement MUST NOT be capable of making the specification unavailable.

16.9 **Conformance Test.** An implementation or process violates this Article if any part of
the protocol cannot be implemented from published material alone; if any handshake,
capability exchange or record field distinguishes implementations by vendor, brand or build
origin; if the network refuses a peer on any basis other than its observed protocol
behaviour; or if any normative document exists in only one place under one party's control.

16.10 **Machinery.** Articles 44, 47 and 51.

### Article 17. The Right to Fork the Protocol, the State and the Name

17.1 Three distinct forks are guaranteed by this Constitution, and MUST be named and treated
separately wherever forking is described.

17.1.a **Protocol fork.** Anyone MAY publish a divergent specification and operate a separate
network implementing it.

17.1.b **State fork.** Anyone MAY take a complete, verifiable snapshot of the registry and
continue it under different rules.

17.1.c **Name fork.** A registrant MAY carry a name and its ownership key into a forked
network and be recognised there as the holder, without the incumbent network's cooperation.

17.2 The incumbent network, its implementers and its contributors SHALL NOT impede any of
these, technically or legally. Specifically: no obfuscated, encrypted or unexportable state;
no signature scheme that binds records to one network's identity such that they cannot be
re-verified elsewhere; no anti-fork clause in any licence, contributor agreement, grant or
funding condition; no denial of snapshot access by any party that offers snapshot access at
all; and no trademark or naming action against a fork that names itself honestly and does not
claim to be the incumbent.

17.3 No project resource — repository access, funding, grant, employment, publication
channel, conformance listing or recognition of any kind — SHALL be granted, withheld,
conditioned or withdrawn on the basis that a person has proposed, built, joined or supported
a fork. Individuals remain free to criticise any fork on its merits; what is forbidden is
using position or resources to penalise the act of forking.

17.4 Conformant clients MUST make joining a fork a supported, documented operation rather than
an undocumented hack; MUST display plainly which network the client is currently attached to;
and MUST make cross-network ambiguity — the same name held by different keys on different
networks — visible to the user rather than resolving it silently in favour of either side.

17.5 **Conformance Test.** An implementation violates this Article if a complete registry
state cannot be exported and then independently verified using only published tooling and a
published format; if a client attached to a non-default network fails to say so in its
ordinary interface; or if any licence, agreement or funding condition in force over
contributors contains a term restricting forking.

17.6 This Article states the principle the whole document is built to support. VayuWeb governs
by the consent of those who run it, and consent is meaningless without an exit that is
practised, documented and undramatic. The right to leave is what makes the right to stay
mean something.

17.7 **Machinery.** Articles 38 and 58. This Article is entrenched under Article 9.

### Article 18. The Right to Exit With Your Keys and Your Data

18.1 At any moment, without notice, permission, justification or waiting period, a
registrant, publisher or node operator SHALL be able to export all of the following from
their own installation.

18.1.a Their private keys, in a documented, standard, offline-usable encoding.

18.1.b The complete record chain for every name they control, with signatures intact and
independently verifiable against the published rules.

18.1.c Their content in content-addressed form, together with the addresses that reproduce it
byte-for-byte.

18.1.d Their configuration, peer lists and subscribed filter lists.

18.2 Export MUST be a local operation. It MUST NOT require network access, an account, a
subscription, an unlock code, or a running service the user does not control. It MUST NOT be
rate-limited, throttled, queued or metered.

18.3 The export format is the canonical record form of Article 30, in every case and without
alternative, so that exit, snapshot and fork share one representation. A Final VWIP under
Article 44 MAY specify the container that carries those records; it MUST NOT substitute a
different record form. Where no such VWIP is in force, the canonical record form stands alone
and export remains fully defined. Separate export paths tend to be worse maintained and
quietly break; there SHALL be only the one, exercised constantly by ordinary operation.

18.4 No implementation SHALL store an ownership key in a form the user cannot extract. This
forbids unexportable hardware binding presented as a security feature, vendor-held escrow,
and remote synchronisation that is the only copy. An implementation MAY offer hardware-backed
or passphrase-protected storage, but MUST also offer a documented backup path that the user
can restore using independent software and a secret the user alone holds.

18.5 Deleting the software MUST NOT be capable of destroying the user's only copy of a key.
Conformant clients MUST offer export before uninstall where the host environment allows an
uninstall step to be observed, and MUST document, in the interface and not only in a manual,
the exact location of key material where it does not.

18.6 **Conformance Test.** An implementation violates this Article if any user-held key or
record is retrievable only through a network call, only in a proprietary or undocumented
format, or only by using one specific vendor's software; or if an exported bundle cannot be
verified by an independent implementation using published rules alone.

18.7 **Machinery.** Articles 30 and 37. This Article is entrenched under Article 9.

### Article 19. The Right to Unpublish, and the Limits of Forgetting

19.1 This Article is stated with deliberate precision, because unpublishing is where charters
lie.

19.2 A registrant SHALL always be able to do each of the following: stop serving content;
unpin it from their own infrastructure; break the name-to-content binding; publish a signed
TOMBSTONE record; relinquish the name; and destroy the ownership key.

19.3 Conformant clients MUST implement tombstone honouring. On observing a TOMBSTONE validly
signed by the ownership key in control of the name at that record's epoch, a client MUST
cease to resolve or render the prior binding as current. A TOMBSTONE signed by any other key
MUST be refused, and no party other than the holder SHALL be able to cause one to take
effect; a tombstone that anyone else can issue is a revocation power, which Article 11
forbids.

19.4 Conformant clients MUST NOT serve, display or return a superseded binding as current,
and MUST NOT retain a tombstoned binding in any cache for longer than 3600 seconds after the
tombstone is observed. One hour is short enough to bound exposure and long enough to survive
ordinary propagation delay.

19.5 A holder MAY publish a later binding after a tombstone, signed by the ownership key; the
latest validly signed record by epoch governs, and a tombstone is not a terminal state unless
the holder makes it one by relinquishing the name or destroying the key.

19.6 What CANNOT be guaranteed, stated plainly and required to be stated plainly everywhere:

19.6.a The registry is append-only. The history of records — that a name existed, which key
signed for it, what it pointed to, and when — is permanent for anyone who has already
replicated it. A tombstone adds a record; it removes nothing.

19.6.b Content already retrieved by others may be re-pinned and re-served indefinitely, by
parties the registrant will never identify.

19.6.c No protocol mechanism can compel a third party to delete bytes they already hold, and
this Constitution will not pretend otherwise.

19.7 VayuWeb therefore guarantees the cessation of authorised publication. It does not guarantee
erasure, and no implementation or document SHALL state or imply that it does.

19.8 Implementations and documentation MUST state the distinction in clause 19.7 at the point
where unpublishing is offered, in the interface itself rather than only in a manual, and MUST
NOT use the phrase "right to be forgotten", or any equivalent claim of erasure, without it.

19.9 **Conformance Test.** An implementation violates this Article if a client continues to
resolve a tombstoned binding as current after the bound in clause 19.4; if a tombstone signed
by a key other than the incumbent ownership key takes effect; or if any interface string,
label or confirmation dialogue asserts or implies that deletion is global, irreversible or
complete.

19.10 **Machinery.** Articles 22 and 29.

### Article 20. Freedom From Retroactive Rule Changes

20.1 No change to the protocol, to registry rules, to proof-of-work parameters, to tenure
terms, to TLD status, or to this Constitution SHALL apply retroactively to names already
registered, records already accepted, or tenure already accrued.

20.2 Every rule change SHALL take effect from a stated activation epoch, and SHALL bind only
records created at or after that epoch. Records are evaluated under the rule version in force
at their own epoch, permanently.

20.3 An activation epoch MUST be stated in the VWIP itself and MUST be strictly in the future
at the moment the VWIP reaches Final status, by no less than 15,552,000 seconds (180 days).
Six months is the minimum interval in which an unpaid volunteer maintaining an independent
implementation can read, implement, test and ship a change without abandoning the rest of
their life.

20.4 A validly registered name does not become invalid because the rules later changed. A name
registered under an earlier work threshold, an earlier encoding, or an earlier TLD status
remains valid on its own terms and MUST continue to be renewable and resolvable.

20.5 Where a change genuinely cannot be made prospective-only, it MUST be executed as a fork
under Article 59 and never imposed as an amendment. The community may go wherever it wishes;
it may not rewrite what people already hold and call the result continuity.

20.6 Stasis is the default. If no amendment process is operating — no editor, no quorum, no
working group, no participants willing to serve — the rules in force at the last activation
epoch remain in force indefinitely, and implementations MUST continue to evaluate records
under them without alteration. The absence, dissolution or inaction of any body MUST NOT be
treated as creating discretion, an emergency power, a caretaker authority, or a lapse of the
rules. No clause of this Constitution SHALL be read as conditional on the continued existence
of any organisation, archive, funder, forge, service or person.

20.7 Algorithms age. New signature and digest suites MUST be introduced prospectively under
clause 20.2, MUST be added alongside existing suites rather than in place of them, and records
signed under a superseded suite MUST remain verifiable and MUST continue to resolve. No
suite SHALL be removed from verification, however old.

20.8 The honest bound on cryptographic failure. Where a suite is broken rather than merely
aged, no rule can preserve both a name's security and its holder's total inaction, and this
Constitution will not claim otherwise. In that event: the network MUST NOT reassign, revoke or
silently re-key any name; the existing binding MUST continue to resolve; a strengthened claim
MUST require a record signed under both the superseded and the successor suite, so that only a
party holding the original key can make it; and conformant clients MUST display which suite a
name's controlling key uses, so that a reader can judge the claim for themselves. This is the
sole exception to clause 20.11's prohibition on migrations requiring holder action, it is
stated here rather than discovered later, and it MUST NOT be extended by analogy to any other
change.

20.9 This is the clause that determines whether a naming system is still in use in a century.
A name registered in the first year MUST still resolve in the hundredth, so far as the rules
are concerned: either unchanged, or through an automatic, signed, publicly verifiable
transformation requiring no action whatsoever from a holder who may by then be dead,
imprisoned, offline or simply uninterested. No rule of this protocol SHALL be the reason such
a name stops resolving. Whether any peer is still willing to serve it is a matter of Article 23, not a promise made here.

20.10 Any such transformation MUST be published as a Final VWIP, MUST be independently
computable from the record chain and the published rules alone, and MUST NOT depend on the
survival of any organisation, archive, service or key other than the holder's own.

20.11 **Conformance Test.** An implementation or process violates this Article if any
implementation applies a rule version to a record whose epoch precedes that rule's activation
epoch; if any VWIP reaches Final status without an activation epoch strictly in the future by
at least 15,552,000 seconds; if any verification path refuses a record solely because its
signature suite has been superseded; or if any migration requires an affirmative act by a
holder in order for an existing name to keep resolving, outside the single exception of
clause 20.8.

20.12 **Machinery.** Articles 47, 47 and 57. This Article is entrenched under Article 9.

---

## Title III — Limits, Non-Guarantees and Honest Disclosure

*What VayuWeb cannot do, stated plainly, kept current by a process that survives its custodians, and binding on everyone who speaks in its name.*

### Article 21. The Duty of Honest Claiming

21.1 In this Title, a *VayuWeb document* is any statement issued under the VayuWeb name in any
medium now existing or later devised, including specifications, implementations and the text
they display, release notes, sites, manuals, talks, interviews, filings and promotional
material. *The Project* means whoever, at a given moment, publishes or maintains anything
under the VayuWeb name. Where no such person or body exists, Article 28 governs and every duty in
this Title remains in force.

21.2 A VayuWeb document MUST NOT claim a capability beyond those this Constitution establishes.

21.3 A VayuWeb document MUST NOT omit a limit stated in this Title where that limit is material.
A limit is material if, stated, it would bear on any of the following: the risk of losing a
name; the risk of exposing the identity, location or associations of a publisher or a reader;
the risk of content becoming unretrievable; the cost of avoiding any of these; or the
availability of an alternative the reader could choose instead. Materiality is decided by that
test alone and MUST NOT be decided by the author's estimate of how likely the harm is.

21.4 The following claims MUST NOT be made about VayuWeb, in these or equivalent words, in any
language:

21.4.a "anonymous";

21.4.b "untraceable";

21.4.c "uncensorable";

21.4.d "permanent";

21.4.e "unstoppable";

21.4.f "cannot be taken down";

21.4.g "your data is safe forever";

21.4.h "100% private";

21.4.i any unqualified absolute of the same kind, whether or not it appears above.

21.5 A form of words is equivalent to a claim listed in 21.4 if it asserts totality, perfection
or the absence of any exception, or if any limit stated in this Title contradicts it. The test
is what the words assert to a reader who has read nothing else, not what the author intended
and not what a longer passage elsewhere qualifies.

21.6 Qualified forms MUST be used instead. The following vocabulary is authoritative and SHOULD
be reused verbatim rather than paraphrased into something stronger:

21.6.a "no permission layer" — no party's approval is required to attempt a registration or a
publication, and whether other peers replicate either remains their own choice;

21.6.b "no single party can revoke" — there is no operator holding a revocation power;

21.6.c "resistant to" — never "immune to", "proof against", or "free from";

21.6.d "available as long as at least one peer serves it" — never "always available";

21.6.e "private from the protocol, not from the network" — the protocol collects nothing; the
network observes plenty.

21.7 Overclaiming is a conformance violation. It MUST be reportable through the channel
established in Article 50; where no such channel is operative, a report published in any public
venue the Project uses, or addressed to any person then publishing under the VayuWeb name, is a
valid report and starts the clocks in 21.8. Reports MUST be triaged on the same timeline as a
security defect and disclosed on the same terms. A false safety claim is a safety defect: it
causes people to take risks they would not otherwise take, and the harm lands on the person who
believed it.

21.8 A report of overclaiming MUST be acknowledged within fourteen calendar days of its
publication, and the offending text corrected or withdrawn within thirty calendar days of
acknowledgement. If no acknowledgement is issued, the thirty-day correction period MUST be
counted from the fourteenth day regardless, so that silence cannot extend the deadline. Thirty
days is chosen because correcting a sentence requires no engineering, and a longer window would
only protect the reluctance to correct it.

21.9 If the text is neither corrected nor withdrawn within the period set by 21.8, the claim is
void, the document is non-conformant, and the document MUST NOT continue to be distributed
under the VayuWeb name until corrected. Any participant MAY publish the report, MAY publish the
correction, and MAY distribute a corrected copy; no permission is required for any of these.

21.10 The Project MUST publish and maintain two documents: a threat model, and a statement of
what VayuWeb does not provide. Each MUST carry the date it was last reviewed. A VayuWeb document MUST
NOT claim protection beyond what those two documents support, and a claim in conflict with them
is void rather than a reason to weaken them.

21.11 If either document required by 21.10 is absent, unreachable, or bears a review date more
than twelve months old, it MUST be treated as absent. While either is treated as absent, no
VayuWeb document may make any resistance, privacy or durability claim at all; the plain limits of
this Title may still be stated, since stating a limit can mislead no one.

21.12 Where a posture can be derived mechanically from the running configuration, a derived
report MUST be preferred to prose describing it. Such a report MUST NOT return a perfect or
unqualified result; where every checked condition passes, it MUST still enumerate the conditions
it does not check, and MUST state the time at which the check was performed.

21.13 This Article is entrenched under Article 9 and MUST NOT be amended to permit any claim it
forbids. If the entrenchment procedure of Article 9 is for any reason inoperative, this Article
remains binding, and any amendment purporting to authorise a forbidden claim is void.

### Article 22. What Append-Only Cannot Forget

22.1 This Article generalises the honesty clause of Article 19 to every record the protocol
keeps.

22.2 VayuWeb guarantees the following, and these MAY be described without qualification:

22.2.a a registrant MAY cease publishing at any time;

22.2.b a registrant MAY tombstone a record, marking it withdrawn in the registrant's latest
signed intent;

22.2.c a registrant MAY destroy their key material, after which no further update signed by
that key can be produced by that registrant, and by anyone else only if a copy of that key
material exists or the signature scheme is broken;

22.2.d a registrant MAY unpin content they themselves hold;

22.2.e the answer a peer gives under a name is the latest signed intent that peer has received,
and an earlier signed record never supersedes a later one.

22.3 VayuWeb does not guarantee, and no VayuWeb document may claim, any of the following:

22.3.a erasure of registry history, which is append-only by design;

22.3.b erasure of content already replicated to other peers;

22.3.c erasure from indexes, archives, mirrors, bridges, gateways, caches or any third-party
copy;

22.3.d unlinking a key from a name in the past;

22.3.e any means of compelling a peer to delete, forget or stop serving anything it holds;

22.3.f delivery of a tombstone to every peer, or within any bounded time, since a peer that
never receives it will keep answering with what it has.

22.4 Clients MUST warn users of the following corollaries at the moment the user acts, in the
same view as the action, and not solely in a policy page or manual:

22.4.a personal data MUST NOT be placed in a registry record, because a record cannot be
recalled;

22.4.b registering a name creates a public and enduring association between that name and a
key;

22.4.c pseudonymity here is protected by key hygiene, not by deletion;

22.4.d a name registered today can be linked to a name registered decades later if the same key
signs both.

22.5 Clients MUST make key separation easy and default-safe. Generating a fresh keypair for a
new name MUST be the default path, and reusing an existing key MUST be a deliberate choice
that names, in the same view, what that reuse links. Key hygiene is the only privacy control
the protocol offers at this layer, so an interface that makes it inconvenient has removed the
control.

22.6 Any interface offering deletion, removal, withdrawal or an equivalent MUST state the true
scope of that operation in the same view as the control, and MUST NOT place that statement
behind a link, an expander, a tooltip or a subsequent screen. Where the operation stops
publication but does not erase history, those words MUST appear.

22.7 An interface MUST NOT use the word "delete", or a word of equivalent finality in any
language, for an operation that only tombstones or unpins.

### Article 23. Availability Is Not Guaranteed

23.1 Content resolves only while some peer serves it. Names resolve only while some peer
replicates the registry. There is no protocol-level service commitment, no guaranteed pinning,
no replication promise, and no assurance that a site published today is retrievable tomorrow.

23.2 Clients MUST expose the honest availability signal rather than an indeterminate progress
indicator that implies a service exists behind it. A client MUST be able to show, on request
and without configuration:

23.2.a how many distinct peers it has itself observed serving the requested content, together
with the age of that observation;

23.2.b when the content was last successfully retrieved by that client;

23.2.c whether the client's registry view is stale, and by how much, expressed as a duration
rather than as a word.

23.3 A client MUST report only what it has observed. It MUST NOT estimate, extrapolate, round
up or substitute a network-wide figure for a local one, and it MUST report an observation of
zero peers as zero.

23.4 A client MUST NOT present a failed or unserved resolution as a server error, a network
outage or a fault of the publisher. It MUST say that no peer currently serves the content.

23.5 Clients MUST make self-pinning, and pinning for peers one already trusts, the default
path, and third-party pinning an opt-in one. Clients SHOULD show a publisher the observed
replication count for their own content, because a publisher who can see their dependence can
act on it while it is still cheap to act.

23.6 Pinning services MAY be commercial, MAY refuse any content for any reason, and MAY set
their own terms. They MUST NOT hold any protocol privilege, MUST NOT be discoverable only
through a directory they themselves control, MUST NOT be required for resolution, and MUST NOT
be shipped as a default, preselected, promoted or first-listed provider in any conformant
client.

23.7 Migration away from a pinning provider MUST be completable by the publisher alone, using
only material already in the publisher's possession, without re-signing, renaming or
re-registering, and without any act by the incumbent provider. A provider whose export path
requires its own cooperation, its continued operation, or its consent is not conformant.

23.8 The operating principle MUST be stated in documentation in these terms or terms no weaker:
a site nobody replicates is a site that will disappear. Durable availability is a social and
economic problem that the protocol assists with and does not solve.

23.9 A VayuWeb document MUST NOT describe content as stored, hosted, backed up or preserved by
VayuWeb. VayuWeb addresses content; people keep it.

### Article 24. Anonymity Is Not Guaranteed

24.1 VayuWeb is not an anonymity network. It MUST NOT be described as one, recommended as one, or
compared favourably to one.

24.2 The following exposures are inherent to the design as specified, and MUST be named
concretely in the threat model required by Article 21.10 rather than gestured at:

24.2.a peer addresses are visible to peers participating in discovery;

24.2.b requesting content reveals interest in that content to the serving peer;

24.2.c timing, volume and pinning patterns are correlatable across sessions and across names;

24.2.d publication cadence is a fingerprint;

24.2.e bridges, gateways, proxies and translation services observe everything they carry;

24.2.f the registry is public, so every registration is an enduring public record bound to a
key, as stated in Article 22;

24.2.g a compromised device ends every protection described here, and no protocol measure
survives it.

24.3 What VayuWeb does provide, and MAY be stated: no accounts; no identity requirement at any
layer; no stable client identifier emitted by conformant software; no query logging by
conformant software; and no protocol primitive by which a publisher can compel a reader to
identify themselves.

24.4 Conformant software MUST NOT emit telemetry, usage reporting, error reporting or update
checks that reveal which names are resolved or which content is requested. Any such reporting
MUST be off unless the user has turned it on, MUST be described before it is turned on, and
MUST NOT be a condition of receiving corrections or updates.

24.5 A user requiring network-level anonymity MUST be directed to compose VayuWeb with a dedicated
anonymity transport. Documentation making that recommendation MUST state, in the same passage,
that such composition has leaks of its own, that the composition is not specified by this
Project, and that it MUST NOT be advertised as a solved problem.

24.6 Clients SHOULD support operation over an anonymity transport, and when so operated MUST
NOT weaken any behaviour, disable any check, or open any connection outside that transport. A
client that would otherwise fall back to a direct connection on transport failure MUST fail
closed instead and MUST say that it did.

24.7 The protocol SHALL NOT assert perfect or complete anonymity in any form, and no amendment
may authorise such an assertion.

24.8 Where a client can determine its own exposure posture, it MUST report that posture as
derived facts under Article 21.12 rather than as adjectives, and MUST NOT report a perfect
result.

### Article 25. The Protocol Cannot Adjudicate Truth, Merit or Entitlement

25.1 The registry records who signed first. It does not know who deserves a name.

25.2 VayuWeb has no view on trademarks, impersonation, defamation, fraud, likeness, priority of
use, or good faith, and no mechanism by which it could form one. It SHALL NOT acquire such a
mechanism, because a body able to decide who deserves a name is a body able to take one.

25.3 Squatting is not a wrong the registry corrects. The registration cost function required by
Article 31, together with superlinear cost for bulk holdings and tenure weighting, raises the
price of squatting and does not eliminate it. The residual MUST be disclosed as a residual and
MUST NOT be presented as a solution.

25.4 Clients MUST tell users, in the client interface and not only in documentation, that the
registration of a name says nothing about who operates it, endorses it or is affiliated with
it, and that trust must come from keys, signatures and out-of-band verification.

25.5 A client MUST NOT display any indicator of trustworthiness, verification, authenticity,
official status, reputation or ranking that is derived from the fact of registration, from
registration age, or from registration cost alone.

25.6 The permanence of key loss is restated here as a user-facing limit and not only as a
design rule: if the key controlling a name is lost, the name is lost. No authority capable of
restoring it exists, and none SHALL be created, because the authority that could restore a name
could also seize one.

25.7 The remedies available for a naming grievance are exhaustively the following, and they are
deliberately weak:

25.7.a choose another name;

25.7.b publish out-of-band verification linking a key to an identity the reader already
trusts;

25.7.c adopt, or publish for others to adopt, an opt-in client-side list, which binds only
those who choose it;

25.7.d fork the software, the client-side lists, or the network, under Title VI.

25.8 A list published under 25.7.c MUST NOT be enabled by default, preselected, bundled as
non-removable, or required in order to resolve. A client that ships one enabled has created the
authority this Article forbids, and is non-conformant.

25.9 No remedy in 25.7 alters the registry. Any proposal that creates a remedy which does alter
the registry is an amendment to this Article and MUST be treated as such.

### Article 26. Legal Reality, Bridges, and the Absence of Immunity or Recognition

26.1 Nodes are operated by people who live somewhere. Law reaches operators, publishers,
developers, pinning services, bridge operators and hosting providers, and this Constitution
changes none of that.

26.2 This Constitution provides no shield, no defence, no immunity and no indemnity. The
Project MUST NOT tell anyone that using VayuWeb makes any conduct lawful, and MUST NOT publish
legal advice.

26.3 The Project MUST NOT design a feature that is targeted at a specific proceeding, a
specific order, or a specific identified person, and that has no general purpose beyond
defeating it. Features that remove central points of control are within this Constitution;
features engineered against one named target are not. This Constitution takes no position on
whether any particular legal system, order or proceeding is just; it constrains only what the
Project builds in the name of everyone.

26.4 VayuWeb SHALL NOT seek accreditation, delegation, contract, licence or recognition from any
body claiming central authority over naming, from any registry operator or registrar, or from
any government, and SHALL NOT create any body capable of granting, withholding or revoking
names at the instruction of any of them. This prohibition attaches to the function, not to the
name of any organisation, and applies equally to successors and to bodies not yet founded.

26.5 Bridges into legacy naming systems, gateways and protocol-translation proxies MAY exist
and are useful. Each is subject to the following:

26.5.a a bridge MUST be marked non-authoritative wherever its answers are presented;

26.5.b a conformant client MUST NOT require a bridge for resolution;

26.5.c a bridge MUST NOT be able to answer differently from the registry without the client
being able to detect the divergence by verifying signatures itself;

26.5.d a bridge operator MAY refuse to carry anything, and that refusal MUST NOT propagate to
direct resolution.

26.6 Bridge centralisation, in which convenience concentrates resolution at a small number of
edge intermediaries and reintroduces the chokepoint the protocol removed, is a named failure
mode and MUST be registered under Article 27.

26.7 The commitment that makes compulsion pointless rather than merely resisted is this: no
key, credential, name, account, signing authority, server, funding source or artefact held by
the Project or by any individual SHALL be load-bearing for registration, resolution,
publication or node participation. There SHALL be nothing meaningful to compel, and any
proposal that creates such a dependency is void under Title I.

26.8 The commitment in 26.7 MUST be tested, not asserted. At least once every twelve months,
the Project MUST perform and publish a check demonstrating that registration, resolution,
publication and node participation still succeed when every artefact, host and credential held
by the Project is treated as unavailable. If the check has not been published within thirteen
months, every VayuWeb document making a compulsion-resistance claim MUST carry a notice that the
claim is untested, until the check is published.

26.9 A participant who is compelled by legal process MAY comply, MAY disclose whatever they may
lawfully disclose, and SHOULD step down under Article 54 where compulsion would otherwise make
their continued role misleading. No blame attaches, and no participant is required by this
Constitution to break any law or to accept personal jeopardy on the Project's behalf. Stepping
down under compulsion is the honourable act, and this Constitution says so plainly so that no
one is later shamed for it.

26.10 The Project MAY publish transparency statements, and MUST NOT present the absence,
staleness or removal of such a statement as evidence that no compulsion has occurred. No
scheme in which silence is meant to signal compulsion may be described as a guarantee.

26.11 No participant SHALL be asked, formally or informally, to accept legal or financial risk
on the Project's behalf.

### Article 27. The Register of Named Failure Modes

27.1 The Project MUST maintain a public, enumerated Register of Named Failure Modes describing
the ways in which VayuWeb can fail. Each entry MUST carry a stable identifier, the date it was
opened, a description of the failure mode, and its current mitigation or a plain statement that
there is none.

27.2 The Register is maintained through the VWIP process of Title V. Entries are added, revised
and closed by VWIP, and no entry may be removed because it is unflattering, obsolete-looking or
inconvenient. An entry may be closed only when the mechanism that produced the failure mode no
longer exists in the protocol, and a closure MUST record why, together with the condition whose
recurrence would reopen the entry.

27.3 Where the VWIP process is inoperative, entries MUST still be added by any participant
maintaining the Register, and additions made in that period MUST be marked as provisional
rather than withheld. An inoperative process is never a reason for a known failure mode to go
unrecorded.

27.4 The Register MUST be seeded with at least the following, which are known now:

27.4.a key loss equals permanent name loss (Art. 25.6);

27.4.b eclipse and partition attacks producing divergent views of the network;

27.4.c asymmetry in the cost of registration work, turning "near-free" into cheap for an
industrial actor and dear for an individual;

27.4.d content pointer decay and the dependence on republication;

27.4.e registry log growth pressuring the network toward a small number of full replicas;

27.4.f client monoculture, in which one implementation's behaviour becomes the specification in
practice;

27.4.g the capture pattern in which one convenient public resolver becomes a de facto
authority, and its list becomes de facto censorship;

27.4.h bridge centralisation (Art. 26.6);

27.4.i governance capture by attention and volume rather than by contribution or stake;

27.4.j volunteer exhaustion and the loss of continuity that follows it;

27.4.k the abandonment case, in which development stops and the network is left to run or to
decay unattended;

27.4.l the obsolescence of any cryptographic primitive the protocol depends on, and the
migration problem that follows for records already signed.

27.5 Any VWIP that creates a new failure mode, or worsens one already listed, MUST say so in its
capture analysis and MUST propose the corresponding Register entry or amendment in the same
proposal. A VWIP that omits a foreseeable Register impact MUST be returned rather than rejected,
and MAY be resubmitted once corrected.

27.6 Any VWIP that mitigates a listed failure mode MUST update that entry, and MUST NOT
describe the mitigation as elimination unless the entry is being closed under 27.2.

27.7 The Register MUST be reviewed at least once every twelve months, alongside the
concentration metrics and the continuity drill results required by Article 53 and the check
required by Article 26.8, and the review MUST be published whether or not anything changed. A
year in which nothing changed is itself a finding.

27.8 A review MUST record, for each entry, whether the mitigation was exercised, tested or
merely asserted during the period, and MUST NOT carry forward a prior period's answer without
re-testing.

27.9 If thirteen months elapse without a published review, the Register MUST be marked lapsed at
its head, and every VayuWeb document making a resistance or durability claim MUST carry that lapse
notice until a review is published. A lapse suspends claims; it never suspends the limits stated
in this Title.

27.10 The Register exists for two reasons, and they MUST be stated in it. A project that keeps a
current list of its own weaknesses cannot market its way into obligations it cannot meet. And a
stranger arriving in year forty can tell at once what was known, what was mitigated, and what
was merely hoped.

### Article 28. Duties Without a Custodian

28.1 No duty in this Title depends on the existence of any organisation, any funding, any
election, any quorum, any meeting, or any named person's continued willingness. The duties bind
the text and the software, and they run to whoever publishes either.

28.2 Where a process referenced by this Title is inoperative, unreachable or unfunded, every
prohibition in this Title remains in force. Permissions that such a process would have granted
do not vest by default, and no claim becomes permissible merely because the body that would
have reviewed it has ceased to meet.

28.3 Any participant MAY discharge a duty of this Title: maintaining the Register, publishing
the threat model or the statement of non-provision, performing the check under Article 26.8,
answering a report under Article 21.8, or publishing a correction. Performance by anyone
discharges the duty for that period, and no permission, membership or appointment is required
to perform it.

28.4 A required document that is absent, unreachable or lapsed MUST be treated as absent, and
its absence MUST NOT be read as an assurance. Silence never converts a non-guarantee into a
guarantee.

28.5 Anyone who distributes, forks or republishes under the VayuWeb name assumes the duties of this
Title in full. Anyone unwilling to assume them MUST publish under a different name, as provided
in Title VI. The name and the duties travel together.

28.6 Where twenty-four months pass with no published review under Article 27.7 and no
acknowledged report under Article 21.8, the software and specification MUST NOT be presented as
maintained, and any VayuWeb document published thereafter MUST carry a notice that maintenance has
lapsed and that the limits in this Title remain fully in force.

28.7 This Article is entrenched on the same terms as Article 21.13 and MUST NOT be amended to
make any duty of this Title conditional on the existence, consent, funding or convenience of any
body, any company, any jurisdiction or any individual.

---

## Title IV — The Registry, the Namespace and Naming Law

*The registry records and orders; it never judges. Allocation is mechanical, tenure is renewable, and adjudication stays at the edge.*

### Article 29. Form, Authority and Records of the Registry

29.1 The Registry SHALL be a signed, append-only log with a derived indexed view, replicated
peer-to-peer between equal participants. There SHALL be no privileged writer, no
administrative mutation path, no deletion path and no central index.

29.2 The Registry's authority is exhausted by two functions: recording validly signed records,
and fixing their order. It MAY record and it MAY order. It MUST NOT judge, and no
implementation SHALL extend it with any faculty resembling judgement.

29.3 Every participant MUST be able to verify the whole chain independently from genesis. A
participant that cannot verify a record MUST reject that record. A participant MUST NOT accept
a record on the assertion of a peer, a majority of peers, a signed statement of the Project, or
any reputation signal whatsoever.

29.4 The record types are a closed set: REGISTER, UPDATE, TRANSFER, DELEGATE, KEY-ROTATE,
RELINQUISH, REVOKE, TOMBSTONE, TLD-CREATE, TLD-FREEZE, TLD-RETIRE. There SHALL be no
administrative record type, no operator record type, no reserved opcode and no side channel. A
record bearing an unrecognised type MUST be rejected rather than ignored, so that an
implementation cannot be quietly extended by traffic.

29.5 Record discipline is as follows, and each element is mandatory:

29.5.a Every record MUST use the canonical deterministic encoding published in the
specification; two encodings of the same record MUST NOT be possible, and a non-canonical
encoding MUST be rejected.

29.5.b Every signature MUST be computed over a domain-separated context string unique to the
record type and to the protocol version, so that a signature valid for one type is invalid for
every other.

29.5.c Every record MUST carry a per-name sequence number that increases by exactly one from
the last live record for that name. A gap or repeat MUST be rejected.

29.5.d Every record MUST carry the epoch under which it is to be interpreted, an activation
height, and an anchor to a recent log state, giving replay resistance without any clock shared
between peers.

29.6 Every record MUST be verifiable offline from the record and the chain alone, with no
network lookup, no oracle, no certificate authority, no time server and no name service of any
kind consulted at validation.

29.7 The canonical record form is exactly the export form of Article 18 and the snapshot form
of Article 38. Exit, archive and fork SHALL share one representation, so that leaving costs no
translation.

29.8 Divergence between replicas SHALL be reconciled by a deterministic rule published in the
specification before deployment and applied identically by every conformant implementation. No
process, maintainer, quorum or vote may resolve a divergence by decision. A purported
resolution by decision is void, and records admitted under it MUST be rejected.

29.9 This Article is bound by Articles 10, 11 and 15.

### Article 30. Acquisition Doctrine: First Valid Signature Wins

30.1 The whole of VayuWeb's allocation policy is one rule: a name belongs to the first record that
is well formed, validly signed, sufficiently worked under Article 31, and not preceded by a
live claim on that name.

30.2 There is nothing else. There is no discretion, no queue management, no priority window,
no reservation, no waiting list, no application review, no merit assessment and no sunrise
period for any class of claimant — including trademark holders, governments, incumbent
operators, standards bodies, early contributors and the drafters of this Constitution.

30.3 Ties SHALL be broken mechanically. Where two otherwise valid claims to the same name are
admitted, the earlier position in log order prevails. Where log order does not separate them,
the claim whose record digest is lower under the byte comparison specified in the
specification prevails. Two honest implementations therefore always agree, and no human ever
chooses.

30.4 The genesis Registry SHALL be empty but for the specification anchor. No name SHALL be
reserved, pre-registered, withheld, escrowed, priced differently or allocated to anyone at
genesis — not to the author, the drafters, the first implementers, any funder, any partner
project, or any entity connected to them.

30.5 Short names, single characters, dictionary words, brand strings and every other string
thought valuable are subject to exactly the same rules as any other string. The protocol MUST
NOT recognise a category of high-value names, because recognising the category is the first
step to administering it.

30.6 Any discovery that a class of names was pre-allocated, front-run using non-public
knowledge of an activation epoch, or acquired by a party that controlled the timing of its
availability SHALL be treated as a founding defect. It is grounds for the fork right under
Article 59, and conformant tooling SHOULD make such a finding legible in the log rather than
merely arguable.

30.7 The reason is stated plainly and is meant to be quoted: any allocation at genesis creates
a class with a financial interest in the outcome of every later governance question, and hands
every future critic a permanent and correct objection. A protocol that begins by taking the
good names has already answered the question of whom it is for.

30.8 This Article is bound by Article 10.

### Article 31. Proof-of-Work, Anti-Squatting and Cost Policy

31.1 A REGISTER record and a renewal record MUST each carry a proof-of-work bound to three
things: the name being claimed, the ownership public key, and a recent log anchor. Work is
therefore not precomputable generically, not reusable across names, not transferable to
another key, and not saleable.

31.2 Difficulty SHALL be a published function of the inputs specified in this Article, not a
setting held by anyone. There SHALL be no difficulty operator, no override and no per-name
exception.

31.3 A registrant MUST be able to compute, offline and before committing any work, the exact
difficulty their claim will require. A protocol that cannot tell you the price before you pay
it is a protocol with a discretion hidden in it.

31.4 Difficulty MAY be adjusted only by a ratified VWIP carrying a future activation epoch
under Article 20, and never retroactively against work already performed.

31.5 Difficulty SHALL scale superlinearly in the number of live names held per ownership key
and per work lineage, so that the cost of hoarding grows faster than the holding. The intended
calibration is that one name is trivial on a phone, ten names remain unremarkable, one hundred
names is a deliberate undertaking, and ten thousand names is tedious enough to be a business
decision rather than a side effect.

31.6 Work is not payable, not delegable-for-fee at the protocol level, not transferable and not
refundable. Its cost is burned, not collected. There SHALL be no registration fee, renewal fee,
token, stake, bond or deposit payable to any party, treasury or address (Art. 7).

31.7 The design intent and its honest limit are stated in the same breath. Work is friction,
not fairness. It does not prevent well-resourced bulk registration; a party with capital and
hardware will always be able to take more names than a person with a laptop. It disadvantages
users on weak or old hardware, and it consumes energy to no productive end.

31.8 Hardware asymmetry is a permanent, unresolved tension in this design. It SHALL be recorded
as such under Article 27 and SHALL NOT be described as solved in any specification,
documentation or public statement.

31.9 Clients SHOULD allow work to be performed incrementally and resumed, so that a slow device
is inconvenienced rather than excluded.

31.10 This Article is bound by Articles 10 and 25.

### Article 32. Tenure, Renewal, Grace and Mechanical Lapse

32.1 Registration confers a renewable right to use a name for a fixed published term. It does
not confer property in perpetuity, and no clause of this Constitution SHALL be read as creating
one.

32.2 The term SHALL be five years. Renewal is by a signed liveness record from the ownership or
a scoped rotation key, plus fresh work under Article 31. Five years is chosen because it is
long enough that ordinary people do not lose names to inattention, illness or a lost year, and
short enough that a namespace of abandoned inventory drains within a human generation.

32.3 The renewal window SHALL open twelve months before expiry and SHALL remain open through
expiry and a grace period of one hundred and eighty days thereafter, giving eighteen months in
which a single signed record preserves the name.

32.4 Renewal MUST require no counterparty, no live service, no account, no approval and no
network reachability beyond publishing one record to any peer. Renewal MUST be automatable by
the registrant's own software without disclosing the ownership key to anyone.

32.5 Renewal work for a holder of ten or fewer live names MUST remain computable in minutes on
commodity consumer hardware of the day. If it does not, the difficulty function is defective
and the defect is a conformance failure, not an inconvenience.

32.6 Conformant clients MUST surface a prominent warning within the last ninety days before
expiry and again within the grace period, and MUST NOT bury it in a log or a settings pane.

32.7 A public pending-expiry view SHALL be derivable from the log by any participant, so that
no party holds privileged knowledge of what is about to become available.

32.8 Release after grace SHALL follow a randomised schedule: the exact log position at which a
lapsed name becomes claimable is derived from the name and the log state by the published
function, spreading releases across a window of at least seven days. This denies automated
snipers a deterministic target without giving anyone a queue to manage.

32.9 Lapse is purely mechanical. No party decides that a name has lapsed; the log does, and the
same computation performed by anyone yields the same answer.

32.10 A lapsed name returns to the general pool under Article 30 with no preference for anyone,
including the prior holder. This is stated bluntly so that nobody builds a business, a habit or
an expectation on an implicit right of re-registration. There is none.

32.11 This Article is bound by Article 11.

### Article 33. Transfer, Settlement Delay and the Refusal of a Secondary Market

33.1 Transfer is a signed act by the current ownership key. Absent lapse under Article 32, it
is the only way a name changes hands.

33.2 The protocol SHALL NOT provide, endorse, integrate or reference an auction house, escrow
service, marketplace, offer channel, bidding record, price oracle, valuation feed,
bulk-registration primitive or "for sale" record type. No such faculty is within the closed
record set of Article 29.4.

33.3 Parties MAY trade names privately by any means they like, and the protocol has no view
about it. The protocol simply SHALL NOT help. The distinction is deliberate: VayuWeb declines to
build the machinery, and declines to pretend it can prevent the conduct.

33.4 A TRANSFER record SHALL take effect only after a mandatory settlement delay of fourteen
days, during which any recovery path configured by the transferor under Article 34 MAY revoke
it by signed record.

33.5 The trade-off SHALL be stated wherever the delay is documented. Fourteen days makes
theft-by-transfer recoverable by a person who notices within a fortnight, and makes bulk
flipping slow. It also means no transfer is instant, that legitimate urgent transfers are
delayed, and that a party who notices on day fifteen has no remedy at all.

33.6 The protocol MUST NOT adopt any feature whose principal effect is to increase the
liquidity of names. The capture analysis required of every VWIP MUST answer this question
explicitly and in terms: does this proposal make names easier to buy, sell, price, bundle or
collateralise, and if so, why is that not disqualifying?

33.7 The reason is from the record of every prior namespace. Fee flows and secondary-market
flows are the mechanism by which a namespace becomes a financial instrument, and by which the
regulated parties come to fund, staff and shape their own regulator. Registries with revenue
acquire interests; interests acquire process; process acquires names.

33.8 This Article is bound by Articles 7 and 11.

### Article 34. Rotation, Delegation, Opt-In Succession, Revocation and Contested Names

34.1 Rotation of the ownership key and transfer of a name occur by signature from the incumbent
ownership key alone. No other signature, quorum or process substitutes for it.

34.2 Operational keys MAY be delegated by DELEGATE record with explicit scope and a mandatory
expiry not exceeding twenty-four months, so that day-to-day publishing does not require the
ownership key to be online. A delegated key MUST NOT be able to transfer, relinquish, rotate
ownership, or extend its own scope or expiry.

34.3 Succession is opt-in and pre-declared. A registrant MAY publish in advance any of: a
rotation key held offline; an m-of-n recovery set; a time-locked recovery with a delay during
which the incumbent key may veto; or a dormancy-triggered successor that becomes eligible only
after a stated period without a signed record. Each takes effect only on the terms the
registrant themselves signed, and only if published before it is needed.

34.4 Recovery MUST be slow, loud and public. It MUST be announced in the log, MUST be delayed
by no less than thirty days from announcement, and MUST be vetoable at any point in that period
by a single signature from the incumbent key.

34.5 No maintainer, peer, majority, monitor, court or process may initiate recovery on an
owner's behalf. There is no default successor, no third-party reset, no support channel and no
appeal. A holder who has published no recovery material and loses their key has lost the name,
and this outcome is deliberate.

34.6 An owner SHALL be able to publish a signed REVOKE record marking a key compromised and, if
recovery material exists, handing control to it. Clients MUST treat a revoked key as invalid
for all purposes from its activation height forward.

34.7 Where two mutually inconsistent chains of custody for one name exist, the specification
SHALL define a deterministic outcome computable identically by every implementation. Clients
MUST display the contest to the user rather than silently resolving it in the interface. A
contested name MUST fail visibly rather than resolve wrongly. No human tie-breaker exists at
any point in this procedure.

34.8 This construction is the only approximation of account recovery that VayuWeb permits, for one
reason: it is authorised in advance by the holder, on terms the holder chose, and it creates no
standing capability held by anyone else. A capability that exists can be compelled; a
capability that only the holder ever created cannot be demanded from a party that never had it.

34.9 This Article is bound by Articles 6 and 11.

### Article 35. The Namespace: TLD Equality, Creation, Freeze and Non-Removal

35.1 The initial top-level domains are the one thousand two hundred and seventy extensions
enumerated in the Namespace Annex, which is incorporated into this Article by reference and
fixed at commencement by the canonical digest of Article 1.7. The Annex is enumerative and
closed: a string absent from it is not a top-level domain, and a conformant Node SHALL reject a
Record bearing one. Eleven are named here so that the founding set survives loss of the Annex:
.vayu, .p2p, .free, .decent, .libre, .sov, .dao, .indie, .open, .news and .blog.

35.1.a Breadth at launch is a deliberate choice against a scarcity the clearnet manufactures. A
top-level domain there cost roughly USD 185,000 to apply for in the 2012 round plus about USD
25,000 a year to keep, in an application window that has opened roughly once a decade — a price
that selects for capital rather than for use, and that makes the shape of the namespace a
consequence of who could afford the fee. Here an extension costs a proposal and the
registrations under it cost work, so there is no mechanism by which restricting the initial set
to eleven would benefit anyone except the holders of those eleven. Where a design has no
scarcity to ration, rationing is not prudence.

35.1.b Enumeration is not a limit on breadth; it is what makes breadth safe. A set derived at
run time from anything — a log, a feed, a quorum — is a set two honest Nodes can compute
differently, and two Nodes disagreeing about whether an extension exists is a namespace fork
presenting as an intermittent resolution failure. A closed list of one thousand two hundred and
seventy is as elastic as a list of eleven, because 35.6 is how either one grows, and it is
verifiable offline by a reader holding the text, which is the only kind of test this
Constitution relies on.

35.1.c No extension in the Annex is founding, premium, reserved or default. The eleven named in
35.1 are named for durability, not for rank, and 35.2 governs: a client that orders, promotes,
prices or suggests one extension over another on the strength of this Article has misread it.

35.2 TLDs are flat, equal and non-hierarchical. No TLD confers status, priority, trust,
governance weight or resolution preference over any other. There SHALL be no registry operator,
franchise, sponsor, exclusive delegate, endorsing body or revenue share for any TLD, and no
record type exists by which one could be created.

35.3 The specification SHALL fix label syntax, permitted code points, length bounds, reserved
characters and a single versioned normalisation profile. Exactly one normalisation profile is
in force at a time, and clients MUST reject a label that does not round-trip through it
unchanged.

35.4 Homograph policy SHALL be mechanical: confusable-script mixing within a single label is
rejected at validation, and clients MUST render a label's script composition where it is
visually ambiguous. The protocol does not attempt to decide which similar name is the
legitimate one, because that decision is adjudication (Art. 36).

35.5 Changes to the normalisation profile MUST be strictly additive. A label valid in year one
MUST remain valid in year one hundred. No profile revision may retroactively invalidate a live
name, and a proposal that would do so is inadmissible.

35.6 A new TLD comes into being only by a ratified Naming-category VWIP, which MUST contain:
rationale; a collision review against existing VayuWeb TLDs and against legacy DNS strings likely
to confuse users; a public objection window of not less than ninety days; and a mandatory
dormancy period of not less than one hundred and eighty days between ratification and
availability.

35.7 The activation epoch SHALL be published not less than one hundred and eighty days in
advance, so that advance knowledge confers no landrush advantage on the proposer or on anyone
close to the process.

35.8 On activation there SHALL be no reserved-name list, no sunrise period and no pre-allocation
to anyone, including the proposer, the drafters and the Project. A proposer gains exactly one
thing: the fact of having proposed. TLDs MUST NOT be sold, auctioned, licensed or made subject
to revenue sharing.

35.9 A TLD with live names SHALL NOT be deleted, repriced or subjected to new conditions. The
only available action is TLD-FREEZE: no new registrations accepted, while every existing name
continues to resolve, renew, transfer, delegate and publish indefinitely.

35.10 TLD-RETIRE is reachable only when no live names remain under that TLD, or when every
remaining registrant has migrated by their own signed action under a published migration path
open for not less than five years. No name is ever migrated on a registrant's behalf.

35.11 This Article is bound by Articles 11 and 20.

### Article 36. Due Process, and the Refusal to Be a Trademark Court

36.1 The default is absolute and comes first: a name is altered only by its own key.

36.2 VayuWeb SHALL NOT operate, recognise, fund, staff, host or cooperate with any dispute
resolution body, UDRP analogue, arbitration panel with binding effect on names, abuse desk,
trusted-notifier programme or takedown surface having power over names.

36.3 A VWIP proposing to create such a body is inadmissible. The governance process has no
competence to create it, and the proposal is therefore out of scope rather than merely
unpopular or premature. A chair, maintainer or editor MUST refuse it at intake, and ratifying
it would be void under Article 9.

36.4 The narrow remaining question — whether any process may ever touch a name otherwise — is
governed by making such a process practically unreachable rather than theoretically forbidden,
so that nobody is tempted to improvise one informally in an emergency. Any such process MUST
satisfy every one of the following:

36.4.a It MUST be defined in advance by a ratified VWIP and MUST NOT be invocable
retroactively against conduct or records preceding its activation epoch.

36.4.b It MUST give public written notice in the log, for a minimum period scaled to severity
and never below thirty days.

36.4.c It MUST give standing to object to the registrant and to any peer, without qualification,
fee or membership.

36.4.d It MUST produce a public, reasoned, signed decision that a non-participant can audit
from the log alone.

36.4.e It MUST be time-boxed and self-expiring, with a maximum duration stated in the
authorising VWIP and never exceeding one hundred and eighty days.

36.4.f It MUST NOT transfer a name to any party, under any circumstances, for any reason.

36.5 The only outcomes available to any such process are "no action", or a narrowly scoped,
reversible, publicly recorded action that leaves ownership untouched.

36.6 Emergency action without prior notice is permitted only for a defect that makes records
unsafe to parse. It MUST be content-neutral and identity-neutral, MUST NOT be usable against a
specific name, key, publisher or class of publishers, MUST auto-expire within thirty days, and
MUST be publicly reviewed with a signed post-hoc report.

36.7 Conformance Test. A violation of this Article exists if any name's controlling key changes
without a signature from that key, or if any action against a name occurs without a prior
public record satisfying every element of 35.4.

36.8 This Article is bound by Articles 10, 11 and 25, and is entrenched under Article 9.

### Article 37. Client-Side Filtering Is Not Registry Action

37.1 Curated blocklists, safety lists, allowlists and opinionated resolvers MAY exist. They are
a legitimate expression of a reader's or an operator's own choice about what they wish to see
or carry.

37.2 Adjudication belongs at the edge: opt-in, inspectable and forkable. This is the only
structure that has survived sustained state pressure, because there is no central list to
seize and no operator whose compliance settles the question for everyone.

37.3 Every such list MUST satisfy all of the following to be used by a client claiming
conformance:

37.3.a It MUST be opt-in per list, subscribed to individually rather than as a bundle enabled
by a single consent.

37.3.b It MUST be inspectable in full by the user, entry by entry, offline.

37.3.c It MUST be forkable and replaceable, under terms permitting redistribution of a
modified copy.

37.3.d It MUST disclose its maintainer and the means of contacting them.

37.3.e It MUST be removable in one action, without loss of any other configuration.

37.4 A conformant client MUST NOT enable any list by default without prominent disclosure at
first use and a one-step disable. Defaults are what this Article regulates; lists themselves are
not the hazard.

37.5 No list SHALL write to, annotate or alter the Registry. No list operator SHALL be given any
protocol privilege, standing, record type or recognition of any kind.

37.6 A filtered resolution MUST be distinguishable by the user from a failed one. A client MUST
NOT present a filtered name as though it does not exist, and MUST name the list responsible.

37.7 List operators SHOULD publish additions with reasons and SHOULD offer an appeal path of
their own. This is a SHOULD and not a MUST because the protocol has no means to compel it, and
Article 21 forbids claiming a protection that is not delivered.

37.8 Voluntary arbitration MAY exist between parties who agreed to it in advance. Its awards MAY
affect opt-in lists only. They have no effect on the Registry, and a client MUST NOT treat an
award as a fact about ownership.

37.9 The risk this Article is watching is named openly: a single convenient public resolver
whose default list becomes de facto censorship for most users. That is a listed failure mode
under Article 27, and it is a failure of defaults, not of lists.

37.10 This Article is bound by Articles 12 and 14.

### Article 38. Snapshots, Mirrors, Monitors and Equivocation Detection

38.1 Anyone MAY snapshot the Registry, mirror it, serve it, index it and archive it, without
permission, notice, registration or attribution to anyone.

38.2 The specification SHALL define a normative snapshot format carrying a verifiable root, such
that a third party can prove that a snapshot faithfully represents a prefix of the log. The
snapshot form is the canonical record form of Article 29.7.

38.3 Reference tooling MUST produce and verify snapshots entirely offline. A verification
procedure that requires contacting anyone is not verification; it is trust wearing verification's
clothes.

38.4 Every archive MUST be self-describing. Its verification procedure, its format
specification, its cryptographic parameters and the meaning of each field MUST be documented
inside the archive itself, so that a copy recovered decades hence is independently interpretable
by someone with no living contact and no access to any website.

38.5 A public register of independent Monitors and Auditors SHALL be maintained. Monitors fetch
and compare Registry state across peers; Auditors verify consistency proofs between log states.

38.6 The register SHALL require at all times not fewer than seven Monitors and three Auditors,
operated by not fewer than five distinct operators across not fewer than three jurisdictions.
These floors are low deliberately: they are the minimum at which a single seizure or a single
legal order cannot blind the network, and they are a floor rather than a target.

38.7 Monitors and Auditors MUST NOT be operated by the Project, by its maintainers, or by any
party they fund or control. Measurement that the Project performs on itself is not evidence,
and MUST NOT be presented as evidence in any report.

38.8 If the floors in 38.6 are not met, conformant tooling SHOULD report the shortfall publicly
and the condition SHALL be recorded as an open risk under Article 27 until resolved.

38.9 Clients SHOULD gossip observed log states to peers, so that equivocation — showing
different histories to different peers — is detectable in the field by ordinary participants
rather than discovered afterwards by specialists. A client that detects equivocation MUST
surface it to the user and MUST NOT silently select a branch.

38.10 Monitor measurement is the evidentiary basis for deployment findings under Article 45 and
for implementation-diversity and concentration metrics under Article 53. A finding under those
Articles that rests on no independent measurement is not a finding.

38.11 This Article is what makes the state fork of Article 17 real rather than rhetorical, and
what makes the Project's own disappearance survivable under Article 55. If the Registry can be
copied whole, verified offline and served by a stranger, then no party's withdrawal ends it.

38.12 This Article is bound by Articles 17 and 18.

---

## Title V — Governance and Protocol Evolution

*Change without capture: proposals bind no one, adoption decides everything, and every
procedural role is a clerkship with a term.*

### Article 39. There Is No Governing Body

39.1 VayuWeb SHALL have no council, board, assembly, foundation, membership roll, elected
officer, core team with authority, or seat of any kind. No such body is created by this
Constitution.

39.2 No VWIP MAY create such a body. A proposal that does so is inadmissible under
Article 41 and MUST be closed as out of scope.

39.3 Decisions SHALL be made by rough consensus among those who participate, and bind no
one. Every outcome of the process is a recommendation.

39.4 A recommendation becomes real only when independent operators adopt it in their own
software and configuration (Art. 45). Governance produces text; operators produce reality.

39.5 The consequence is deliberate and SHOULD be understood as protection rather than
weakness: because there is nothing to seize, governance can be captured only into
irrelevance, never into control. Irrelevant governance is survivable — names continue to
resolve and records continue to replicate while the forum is empty (Art. 55).

39.6 The informal recreation of a governing body under another name is prohibited. There
SHALL be no core group, no private maintainers' channel with decision effect, no advisory
board with de facto veto, and no standing invitation-only venue in which outcomes are
settled before publication.

39.7 All governance SHALL occur in public and in writing. There is no private decision
channel and no off-record consensus.

39.8 Discussion held in private has no procedural effect. A decision taken in private is
void under Article 8, and a VWIP transition resting on one MUST be reverted to its prior
state on discovery.

39.9 Participants MAY confer privately; they MUST NOT thereby decide. Any private
exchange that materially shaped a published position SHALL be summarised on the record
before that position is counted.

39.10 The governance archive SHALL be complete, content-addressed, independently
replicated by not fewer than three unaffiliated parties, and retrievable offline. It
SHALL include every proposal, every state transition, every Objection Register
(Art. 43) and every recusal record (Art. 46).

39.11 The archive MUST be usable by a person arriving in fifty years with no context and
no living contact. To that end it SHALL carry its own format documentation, a plain-text
rendering of every document, and an index that does not depend on any running service.

39.12 Once the namespace is capable of carrying it, the archive SHALL be mirrored inside
VayuWeb itself, so that the record of the protocol does not depend on the infrastructure the
protocol exists to replace.

39.13 This Article is entrenched under Article 9 and MUST NOT be amended by any route.

### Article 40. Standing, the Four Constituencies and Sybil Resistance Without Identity

40.1 Four constituencies are recognised for every proposal:

40.1.a name holders;

40.1.b registry replicators;

40.1.c hosting and pinning operators;

40.1.d implementers of conformant clients.

40.2 A proposal is deemed to have rough consensus only where support is concurrent across
all four. No constituency MAY carry a change alone.

40.3 No constituency holds a permanent veto. Sustained absence of one constituency is
recorded as an unresolved condition under Article 43 and does not by itself defeat a
proposal.

40.4 Standing attaches to demonstrated participation only: a name held continuously for
not less than one tenure term; a replica observed by independent Monitors (Art. 38) to
have actually replicated registry state for not less than 90 days; an operator serving
content over that period; an implementation actually released and passing the conformance
suite. Ninety days is chosen as long enough to make fabrication costly and short enough
that a newcomer earns standing within a season.

40.5 Standing SHALL NOT derive from identity, payment, stake, seniority, invitation,
office or self-assertion.

40.6 Because identity cannot be verified without an authority, and an authority cannot be
permitted (Art. 39), Sybil resistance SHALL be achieved by making speech cheap and weight
expensive in quantities that cannot be minted: continuity of participation over time,
work published in the open, and operation independently observable by third parties.

40.7 Weight SHALL NOT derive from account count, wallet balance, message volume, node
count, or any quantity a single party can inflate at will.

40.8 The following are prohibited as inputs to consensus: token or stake weighting; paid
membership; corporate or sponsor seats; delegated, proxy or liquid voting; and any
mechanism by which capital converts into influence.

40.9 Delegation is excluded in form as well as in effect, because delegation is the
mechanism by which one-participant-one-voice systems become plutocracies without any
single visible decision to do so.

40.10 Any tally is advisory only. Consensus SHALL be a documented human judgement,
published with its reasoning, its evidence, and its dissents (Art. 43).

40.11 This Article is mitigation, not solution. A determined party with resources CAN
manufacture apparent support, and this Constitution does not claim otherwise.

40.12 The real defence is Article 45: a Sybil swarm may win an argument and still cannot
make any operator run the code.

### Article 41. Scope and Exclusivity of the VWIP Process

41.1 Every normative change SHALL occur only through a VayuWeb Improvement Proposal (VWIP).
This includes wire behaviour, record types, validation rules, work policy, tenure terms,
TLD lifecycle, the primitives Annex, the conformance suite, and this Constitution.

41.2 A change not published as a VWIP is not part of VayuWeb, regardless of who shipped it,
how widely it spread, or how long it went unnoticed. Wide deployment of an unpublished
change creates an obligation to document it as a VWIP, not a licence to skip the process.

41.3 VWIP categories are: Core, Registry, Naming, Interop, Security, Process,
Informational, and Constitutional Amendment.

41.4 No VWIP MAY address the following subject matter, which is jurisdictionally excluded
rather than merely disfavoured:

41.4.a creating any adjudicating body, arbiter, complaints process or takedown surface
(Art. 36);

41.4.b granting any party the power to revoke, transfer, suspend or seize a name
(Art. 11);

41.4.c giving any rule retroactive effect over records already signed (Art. 20);

41.4.d introducing a token, mandatory fee, treasury, endowment or revenue mechanism
(Art. 7);

41.4.e introducing an identity system, attestation authority, real-name requirement,
key escrow, or any interception, logging or lawful-access facility;

41.4.f amending an entrenched Article by any route other than the amendment procedure of
Title VI, which cannot reach entrenched Articles at all (Art. 58).

41.5 A VWIP falling within 41.4 is inadmissible. Editors MUST close it as out of scope,
with written reasons and a citation to the excluded head, and MUST NOT advance it to
Review.

41.6 An inadmissible proposal MUST NOT be put to consensus. Debating whether to adopt it
establishes that it could have gone the other way, and that impression is itself the
harm this clause prevents.

41.7 Closure for inadmissibility is appealable on the record (Art. 46). The appeal
concerns only whether the proposal falls within 41.4, never whether the excluded thing
would be desirable.

41.8 A proposal MAY be reframed and refiled where the objectionable element is removed.
Repackaging the same excluded power under a new name is itself inadmissible, and editors
SHALL record the relationship between the filings.

41.9 Anyone MAY author a VWIP. Authorship confers no privilege, no standing, no priority
and no ownership of the resulting text.

41.10 Authors MAY act pseudonymously. No process step MAY require, verify or publish an
author's legal identity, employer or location.

41.11 Editors MUST NOT decline a VWIP on grounds of the author's identity, reputation,
affiliation, prior conduct, or the perceived quality of the idea.

### Article 42. The VWIP Lifecycle, Mandatory Sections and Minimum Durations

42.1 The lifecycle is: Draft → Review → Accepted → Implemented → Final → Deprecated →
Retired.

42.2 The lateral and terminal states are Rejected, with recorded reasons; Withdrawn, by
the author only; and Dormant, entered automatically after 365 days without substantive
activity.

42.3 A Dormant VWIP MAY be reopened by anyone, including a person other than its author.
No VWIP in any state SHALL ever be deleted.

42.4 A VWIP MUST NOT advance beyond Draft unless it contains all of the following
sections:

42.4.a abstract;

42.4.b motivation, stating the problem before the solution;

42.4.c normative specification using RFC 2119 keywords correctly and consistently;

42.4.d security considerations;

42.4.e privacy considerations;

42.4.f rights-impact analysis naming every Title II Article touched, and stating for each
whether the effect is expansion, restriction or none;

42.4.g the impossibility-and-capture analysis required by Article 5;

42.4.h centralisation analysis against Article 4, identifying every party whose
withdrawal would degrade the proposed mechanism;

42.4.i migration, rollback and backward-compatibility plan;

42.4.j an activation epoch strictly in the future (Art. 47);

42.4.k an expiry date for every transitional mechanism it introduces (Art. 48).

42.5 Minimum durations SHALL apply: Draft 30 days; Review 90 days, or 180 days for Core,
Registry, Security and Constitutional Amendment categories; Accepted to Implemented no
minimum; Implemented to Final not less than the observation period of Article 45.

42.6 These minima exist so that no change can pass through a quiet week, a holiday
period, or a manufactured emergency. There is no expedited track. A security defect is
remedied by deploying a fix and documenting it, never by shortening review.

42.7 Every state transition MUST be recorded publicly, with its date and the evidence
that justified it. An unrecorded transition has not occurred, and implementations SHOULD
treat the VWIP as remaining in its last recorded state.

42.8 No transition MAY be made by assertion, by silence, or by an editor's discretion
except as Article 49 expressly permits.

42.9 Any VWIP touching a Title II right MUST ship an executable Conformance Test for that
right before leaving Review.

42.10 Any VWIP touching wire behaviour MUST ship test vectors before leaving Review
(Art. 44).

42.11 A VWIP that has been Rejected MAY be refiled with new substance. The refiling MUST
cite the prior rejection and state what changed.

### Article 43. Rough Consensus, the Objection Register and the Limits of Blocking

43.1 Consensus means the absence of unaddressed substantive technical objection. It does
not mean unanimity, a headcount, a majority, or the preference of whoever is chairing.

43.2 Every objection MUST be answered on the record. Answered does not mean
accommodated; a reasoned refusal to change the proposal is a complete answer.

43.3 An objection MUST be specific, technical, and publicly reasoned; MUST identify the
harm it asserts; SHOULD propose a remedy; and MUST be attributable to a persistent
participant identity within the process, which MAY be a pseudonym.

43.4 Objections resting on preference, taste, affiliation or timing alone SHALL be
disregarded, and the disregard SHALL be recorded with its reasoning. Silent dismissal is
prohibited.

43.5 An objection not renewed with new substance within 90 days of being answered SHALL
be treated as spent for the purpose of blocking, and remains in the record.

43.6 Every unresolved objection SHALL be entered permanently in a public Objection
Register attached to the VWIP, together with the reasoning by which it was overruled and
the name or pseudonym of the person who recorded that reasoning.

43.7 The Objection Register converts rough consensus from a euphemism for discretion into
a reviewable act, and gives a reader in fifty years the argument as well as the outcome.

43.8 No participant, however long-serving, MAY block indefinitely without renewed
substance. Repeated blocking without new substance SHALL itself be recorded against that
participant in the Register.

43.9 A participant blocking is entitled to be wrong and to remain unpersuaded. What they
are not entitled to is a veto exercised by repetition.

43.10 Consensus is recorded by editors, never conferred by them (Art. 46). An editor's
determination of consensus is a finding of fact about the record.

43.11 Any determination MAY be challenged on the record by any person with standing under
Article 40. A sustained challenge returns the VWIP to Review and restarts its minimum
duration.

43.12 This Article is to be read against Article 49. Neither an indefinite veto nor
impatience for progress is the governing force; the Objection Register and the silence
rule are the two mechanisms that hold each other in check.

### Article 44. Running Code, Two Independent Implementations and the Conformance Suite

44.1 No VWIP SHALL reach Final without running code.

44.2 The minimum is two independent, interoperating implementations, written by parties
with no common employer, funder or controlling entity, each passing the published test
vectors for the change.

44.3 A change that cannot attract a second independent implementation is evidence of a
single-vendor protocol and MUST NOT advance, however elegant its specification.

44.4 A reference implementation MAY exist for clarity. It SHALL NOT be normative.

44.5 Where an implementation and the specification disagree, the specification governs
and the implementation is defective. Where the specification is genuinely ambiguous, the
remedy is a clarifying VWIP, never deference to whichever code is most widely run.

44.6 Specification text MUST be sufficient to build a conformant client without reading
any implementation's source. Failure of this property is a defect in the specification
and grounds for returning the VWIP to Review.

44.7 The conformance suite SHALL be public, runnable entirely offline, forkable without
permission, and versioned alongside the specification.

44.8 The suite carries both wire vectors and the executable Conformance Tests of
Title II, including the single-name outbound-connection test of Article 14, so that
rights and correctness are checked by the same machinery, in the same run, with the same
visibility.

44.9 An annual implementation-diversity report SHALL be published from independent
measurement (Art. 38), stating the measured share of resolvers, replicas and clients held
by each implementation, with its methodology and its error bounds.

44.10 Where any single implementation exceeds 60 percent of measured resolvers or
measured registry replicas, that condition MUST be published as a structural warning and
reviewed publicly within 90 days. Sixty percent is chosen because below it no single
codebase's defect or capture can carry the network by default.

44.11 A monoculture warning is a shared problem to be remedied by adding diversity —
funding, porting, documenting, testing — and SHALL NOT be treated as an offence by the
popular implementation or its authors. No sanction, throttle or disadvantage MAY attach
to it.

44.12 Monoculture is declared a capture vector and a degraded constitutional state.
Article 16 bounds this Article, and nothing here permits any party to be excluded from
implementing.

### Article 45. Deployment as the Condition of Force

45.1 No process, editor, author, constituency or majority MAY declare a change to be in
force.

45.2 A VWIP becomes Final only when independent measurement shows it voluntarily deployed
by not less than 60 percent of observed resolvers and not less than 60 percent of
observed registry replicas, operated by not fewer than 20 unaffiliated parties, sustained
across an observation period of not less than 180 days.

45.3 The thresholds are set to require a broad majority of real operators rather than a
coordinated minority, and the 180-day period is long enough that a temporary surge cannot
carry a change.

45.4 Adoption, not approval, is the decisive test. The resolution software that people
choose to run is the final arbiter of the protocol, and this Constitution says so in
terms rather than implying it.

45.5 Measurement MUST come from independent Monitors under Article 38, MUST be
reproducible from published method and published data, and MUST state its coverage
limits.

45.6 Measurement produced solely by parties affiliated with the proposal's authors,
implementers or funders is insufficient, whatever its quality. Not fewer than three
unaffiliated Monitors MUST report concordant results.

45.7 Operators are under no duty to deploy, to explain non-deployment, or to answer a
Monitor. Non-response SHALL be reported as unknown, never imputed as either adoption or
refusal.

45.8 This Article is the principal structural defence against both Sybil capture
(Art. 40) and a hostile well-funded fork (Art. 59). Capital can buy speech, tallies,
authorship and even implementations; it cannot compel adoption by sovereign operators.

45.9 The corollary is stated honestly: a change that every participant agrees is correct,
and that nobody deploys, has not happened.

45.10 In that case the VWIP SHALL be recorded as Accepted but not Final, with the
measurement that shows non-adoption. The process MUST NOT paper over the outcome by
declaring it Final anyway, and MUST NOT pressure operators to deploy it.

45.11 Articles 15 and 16 bound this Article. Nothing here permits any operator to be
identified, ranked, penalised or excluded on the basis of what they run.

### Article 46. Editors and Stewards: Clerks, Terms and the Bus-Factor Rule

46.1 Editing is a ministerial function. Editors check completeness, assign numbers,
record state transitions, maintain the archive, and publish the record.

46.2 Editors have no merit veto, no casting vote, and no authority over names, registry
state, resolution, conformance results, or other people's software.

46.3 Refusal to publish a VWIP is appealable on the record and MUST be answered within
30 days. A VWIP deadlocked among editors goes to extended review, never to an editor's
decision.

46.4 Editorship SHALL be held by a rotating panel of not fewer than three persons. It
MUST NOT be held by one person at any time; where the panel falls below three, editorial
transitions are suspended until it is refilled.

46.5 Terms SHALL be fixed at two years and staggered so that no more than one seat turns
over in any eight-month period, with a limit of two consecutive terms.

46.6 An editor MUST recuse from any VWIP in which they, their employer or their funder
has an interest. Every recusal SHALL be entered in a public recusal register.

46.7 No single employer, funder, or commonly controlled group MAY hold more than one
third of the panel. Where a change of employment breaches this limit, the most recently
seated affected seat is vacated automatically.

46.8 An editor unreachable for 120 consecutive days vacates the seat automatically. This
dead-man rule also protects pseudonymous holders who must disappear without explanation,
and no explanation SHALL be required of them.

46.9 Pseudonymous service is permitted in every role. No process MAY compel, verify or
publish anyone's legal identity, and a demand to do so is itself procedural abuse.

46.10 Editors MAY be removed for procedural abuse — falsifying the record, suppressing an
objection, transiting a VWIP without evidence, or breaching recusal — by a documented
determination of the four constituencies under Article 40.

46.11 The Bus-Factor Rule: no role, signing key, credential, account, domain or
publication path MAY have a single holder. Where one is discovered, it is a defect to be
remedied, and its remedy takes priority over feature work.

46.12 A bus-factor audit SHALL be published annually, naming every remaining single point
of human failure and the plan to remove it.

46.13 The founding steward's role is procedural and time-limited, is encoded in no
protocol rule, and confers no vote, veto or priority.

46.14 That role sunsets on the schedule stated in Article 54 and MUST NOT be renewed,
extended, transferred, inherited, or recreated under another name or title.

46.15 No protocol behaviour, default, bootstrap list or validation rule MAY depend on any
named person or on any specific person's key.

46.16 Inactivity of 180 days retires a role holder automatically and without stigma.
Re-entry requires only a statement of availability and the next open seat; no vote, no
sponsorship, and no probation.

### Article 47. Versioning, Activation Epochs and Capability Negotiation

47.1 Version negotiation MUST exist from the first released version. A protocol that adds
negotiation later has already broken its first users.

47.2 Peers MUST negotiate capabilities rather than assume them. Feature identifiers MUST
be explicit, registered in the VWIP record, and never reused for a different meaning.

47.3 There SHALL be no silent breaking change. Any change that would cause an older
conformant peer to misinterpret a message, rather than to reject it cleanly, MUST be
gated behind both an explicit capability and a future activation epoch.

47.4 Forward-compatibility discipline applies to record parsing: unknown fields MUST be
preserved, not dropped, so that a record signed under a newer version survives
round-tripping through older software without being invalidated or having its signature
broken.

47.5 An implementation that discards unknown fields is defective, and the defect is
severe because its damage appears only later and elsewhere.

47.6 Every VWIP MUST state an activation epoch strictly in the future, not less than 180
days after the VWIP reaches Accepted, so that operators have a planning horizon.

47.7 Implementations MUST apply the rule version in force at a record's own epoch, not
the latest rule they know. A record valid when signed remains valid (Art. 20).

47.8 Flag days are prohibited. No change MAY require all peers to switch at a single
moment, and no mechanism MAY penalise, exclude or degrade a peer for not having switched.

47.9 Forced migrations are prohibited. Migration SHALL be driven by each holder's own
signed action or by an operator's own choice.

47.10 A protocol that changes faster than its slowest honest operator centralises by
other means, because only well-resourced operators can keep pace and the rest are quietly
priced out.

47.11 The rate of normative change is therefore capped: not more than two breaking
changes SHALL activate in any 12-month period, and each activation SHALL be followed by a
freeze window of 90 days in which no further breaking change activates.

47.12 The cap exists as much for volunteers as for operators. A protocol maintained by
people who are not paid for it MUST be maintainable at the pace of unpaid attention.

47.13 Non-breaking additions are not counted against the cap, provided they are gated by
capability negotiation and change nothing for a peer that does not advertise them.

### Article 48. Deprecation, Sunset and the Compatibility Horizon

48.1 Deprecation marks a feature as no longer recommended and starts a published clock.
Deprecation by itself never removes anything and never invalidates anything.

48.2 Minimum notice periods scale with blast radius: 12 months for a client-local
behaviour; 24 months for a wire or interoperability feature; 60 months for anything on
which existing names depend.

48.3 The controlling rule: a feature that live names depend on MUST continue to function
until either every dependent name has been migrated by its own signed action, or the
removal is executed as a fork under Article 59.

48.4 Removal in any other circumstance changes the meaning of records already signed. It
is a retroactive change and is prohibited by Article 20.

48.5 The Constitution guarantees a compatibility horizon of not less than ten years. A
conformant client of a version released within the preceding ten years MUST continue to
resolve names correctly, though it MAY lack later features.

48.6 The ten-year horizon is chosen because it exceeds the working life of most deployed
software and most volunteer attention spans, and because a name a person set up once
should still work when they return to it.

48.7 Wire and record formats SHALL be versioned and additive. Fields are added, not
repurposed; meanings are extended, not silently narrowed.

48.8 Every transitional compatibility mechanism MUST carry an expiry date fixed at the
time of its adoption, and that date MUST NOT be extended more than once, by not more than
its original duration, with published reasons.

48.9 The single-extension limit exists because temporary scaffolding otherwise becomes
permanent by inattention, and permanent scaffolding is how a clean protocol becomes
unimplementable by newcomers.

48.10 Superseded work retires with dignity. A Retired VWIP remains published in full,
with its specification, its test vectors and its Objection Register intact.

48.11 No VWIP, objection, dissent or state transition SHALL be deleted, redacted or
rewritten. Deleting the history of a decision destroys the ability to review it, and a
protocol that cannot be reviewed cannot be trusted by anyone who was not present.

48.12 A Retired VWIP MAY be superseded but MUST NOT be contradicted silently. The
superseding VWIP MUST cite it and state what changed and why.

### Article 49. Anti-Ossification Duties

49.1 This Article imposes affirmative maintenance duties, because a protocol intended to
last a century MUST treat "our extension points still work" as a tested property rather
than an assumption.

49.2 Extension points MUST be exercised continuously. Conformant implementations SHALL
emit reserved random capability identifiers, unknown optional fields and reserved record
values at a low rate in ordinary traffic.

49.3 Peers MUST accept and preserve such values without error. Failure to do so is a
defect, discovered by drill rather than by crisis, and reported through the conformance
suite (Art. 44).

49.4 The purpose is to prevent implementations from coming to depend on extension points
being unused, which is how a protocol becomes unchangeable while every implementation
remains individually correct.

49.5 No feature holds permanent mandatory-to-support status. Every mandatory feature
SHALL be reaffirmed by VWIP every five years, on evidence that it is still needed;
reaffirmation is ordinary and expected, and failure to reaffirm moves the feature to
optional, never to removed.

49.6 Every optional extension carries a five-year expiry unless renewed by published
evidence of actual use from independent measurement (Art. 38).

49.7 The silence rule, to prevent paralysis: a VWIP MAY advance from Review to Accepted
without further consensus determination where all of the following hold —

49.7.a it has received no substantive objection under Article 43 for 180 continuous days;

49.7.b it has two interoperating implementations under Article 44;

49.7.c it touches nothing entrenched under Article 9, nothing economic under Article 7,
and nothing constitutional.

49.8 The silence rule is unavailable in every other case, and its use MUST be recorded
explicitly with the dates that satisfy 48.7.a.

49.9 Advancing under the silence rule does not shorten Article 45. Adoption remains the
condition of force, and a silently accepted change that nobody deploys is still not
Final.

49.10 A compatibility exercise SHALL be rehearsed at least every 24 months: a deliberate,
announced round-trip of unknown fields, unknown capabilities, old-version clients and
new-version peers, across at least two independent implementations.

49.11 The results MUST be published in full, including what broke and what was quietly
depended upon. A clean report with no findings SHOULD be treated as evidence that the
exercise was too gentle.

49.12 Ossification and churn are opposite diseases. Article 48 treats churn by slowing
removal and guaranteeing a horizon; this Article treats ossification by exercising the
joints and by permitting uncontested work to move. Where the two pull against each other,
the resolution is a VWIP, argued in public, with its reasoning recorded.

---

## Title VI — Trust Chain, Continuity, Amendment and the Last Resort

*How specification becomes verified software, how this text changes, and how strangers revive
or leave it when everyone here is gone.*

### Article 50. Security Disclosure, Safe Harbour and No Silent Patching

50.1 The Project SHALL publish a security contact address, an Ed25519 or OpenPGP public key
for encrypted reports, and the current disclosure policy, in the canonical text archive
(Art. 1) and in every release artefact.

50.2 A report MUST be acknowledged by a human within 72 hours. Acknowledgement means
confirmation of receipt and a named point of contact; it is not an assessment.

50.3 The standard embargo is 90 days from acknowledgement, with a hard ceiling of 120 days.
The ceiling is absolute and is not extendable by agreement, negotiation, workload or the
absence of a fix.

50.4 Where a defect is under active exploitation, the embargo SHALL be shortened to the
minimum period required to publish a mitigation, and MUST NOT exceed 7 days.

50.5 A researcher acting in good faith SHALL receive safe harbour. The Project and its
participants MUST NOT initiate or threaten legal or administrative action, MUST NOT demand
silence beyond the embargo, and MUST NOT condition safe harbour on the researcher accepting
any term whatsoever.

50.5.a Good faith means testing against one's own infrastructure or with the operator's
consent, avoiding destruction and exfiltration of third-party data, and reporting promptly.

50.5.b Credit SHALL be given by default under the name the researcher supplies, and withheld
only where the researcher asks for anonymity.

50.6 No silent patching. A release containing a security fix MUST be accompanied by an
advisory stating the defect class, the affected version range, the user-visible risk, and any
action the user must take. Publishing a fix without an advisory transfers risk to the users
least able to read a diff, and is PROHIBITED.

50.7 An advisory MUST be published even where the defect was found internally, where no
exploitation is known, and where the fix was trivial. Severity governs urgency, never the
existence of the advisory.

50.8 Violations of Title II and overclaiming under Article 21 are reportable through this
channel and run on the same clock as a technical defect. A false safety claim causes users to
take risks they would otherwise refuse, and SHALL be treated as a safety defect.

50.9 Every embargo expires into mandatory publication (Art. 8). Where the deadline arrives
without a fix, the advisory MUST be published stating that fact and any available mitigation.

50.10 An embargo that is extended without published justification, or extended past the
ceiling by any means, is itself a governance defect and MUST be recorded in the capture
register under Article 27 and Article 53.

50.11 The Project cannot compel any operator to patch, and does not claim to. It can only
ensure that every operator learns of the defect at the same moment.

### Article 51. Release Signing, Reproducible Builds and the Duty to Refuse

51.1 Release artefacts SHALL be bit-for-bit reproducible from published source with pinned
toolchains and recorded build inputs. An artefact that cannot be independently reproduced
MUST NOT be published as a release.

51.2 Releases SHALL be signed by an m-of-n threshold of independently held keys, with a
minimum of 3-of-5, held by people in different jurisdictions who are not employed or funded
by the same party. A release signed by one person's key alone is non-conforming.

51.3 Every release SHALL be recorded in an append-only, content-addressed transparency log
that a user can query and verify without contacting the Project.

51.4 Verification instructions MUST be short enough to print, MUST work offline, and MUST NOT
depend on any single host. A user MUST always be able to build from source and bypass the
release channel entirely.

51.5 Conformant clients:

51.5.a MUST verify threshold signatures against a locally held trust set before executing or
installing any update;

51.5.b MUST render that trust set inspectable and editable by the user, including emptying it
entirely;

51.5.c MUST NOT auto-update without local verification, and MUST allow auto-update to be
disabled permanently;

51.5.d MUST NOT ship any forced-update channel. A forced update is a chokepoint under
Article 4 and a control surface under Article 14.

51.6 Every key class — maintainer, release threshold, specification anchor, bootstrap
advertisement — SHALL have a documented generation ceremony, a rotation cadence of not more
than 24 months, a stated expiry, an offline backup regime, and a written compromise runbook.

51.6.a Key material SHALL be held under threshold across jurisdictions and devices, and MUST
NOT be escrowed with any third party, custodian, employer or platform.

51.6.b Rotation SHALL be rehearsed on schedule, so that an emergency rotation is
operationally indistinguishable from a routine one and signals nothing to an observer.

51.7 Public distrust procedure. Anyone MAY publish evidence that a key holder or maintainer is
compromised, coerced, or acting outside this Constitution. The trust set MAY be updated by
threshold, and evidence and outcome are recorded under Article 53.

51.8 Decisively, every operator MAY unilaterally distrust any key or maintainer in their own
client, without consensus, notice or justification. This SHALL be a documented, first-class
operation with a stable interface, not an undocumented configuration edit.

51.9 The effect is to be stated plainly: seizing the signing keys yields only the ability to
publish a binary that no reproducible build will match. The compromise announces itself. The
ability of each user to refuse is the one revocation mechanism that cannot itself be captured,
because it is exercised on hardware the attacker does not hold.

### Article 52. Supply Chain, Bootstrap and Client Discipline

52.1 Every dependency SHALL be evaluated against Article 4. A dependency that can execute code
on a user's machine, or whose maintainer can, is a chokepoint and MUST be pinned by
cryptographic digest, vendored where practical, minimised, and auditable by a reader of
ordinary skill.

52.2 Build inputs MUST be exhaustively enumerable, and a release build MUST be performable
from a vendored tree with no network access. A build that reaches the network is not
reproducible and is not a release.

52.3 The following are PROHIBITED outright in conformant clients: remote configuration,
kill switches, runtime-fetched feature flags, default-on telemetry, remote-disable capability,
and any component whose behaviour changes in response to an instruction fetched from a server.

52.4 A fresh client MUST be able to join the network without contacting any privileged host.
No party's uptime may be a precondition of first use.

52.5 Bootstrap sets:

52.5.a MUST be plural, with a minimum of 7 entries diverse across operators, jurisdictions,
network providers and funding sources, and no more than 2 under common control;

52.5.b MUST be inspectable, editable, replaceable and emptiable before first use;

52.5.c MUST be revisable without a software release, and MUST NOT be silently updatable by
their incumbents;

52.5.d MUST be signed by the release threshold when shipped, so that a substituted set is
detectable.

52.6 A client MUST be able to join from a user-supplied peer address, a peer on the local
network, a peer address given by an acquaintance, a printed key, or an offline snapshot, and
MUST remain fully functional with the shipped set removed.

52.7 Hardcoding a single bootstrap host, or any set under common control, is non-conforming
and SHALL fail the conformance suite.

52.8 Design for partition. An isolated island of peers MUST continue to resolve, publish and
replicate among themselves, and MUST reconcile on reconnection. Local discovery, manual peer
exchange and offline snapshot import SHALL be supported.

52.9 No feature MAY be specified whose failure mode under a hostile or partitioned network is
silent incorrectness rather than visible unavailability. Where a client cannot verify, it MUST
say so rather than guess.

52.10 This Article is bound by Articles 4 and 15, and its requirements are testable
obligations of the conformance suite rather than aspirations.

### Article 53. Development Home, Mirrors, Concentration Metrics and the Blackout Drill

53.1 The long-term development home SHALL be peer-to-peer and unseizable. Radicle is
designated for this purpose. Centralised forges are designated temporary public mirrors and
hold no authority over the specification, the history or the releases.

53.2 This SHALL remain true in fact and not merely in intention: the loss of any hosted
account, organisation or namespace SHALL be a nuisance requiring a link update, and MUST NOT
be an emergency.

53.3 The full commit history, issue record, specification archive, VWIP archive, test vectors
and release artefacts MUST be reconstructible from at least 3 independent, differently hosted
copies, of which at least 1 is offline and physically separated.

53.4 Concentration indicators SHALL be defined and measured: share of registry replication,
share of content pinning, share of bootstrap contacts, share of resolution volume, share of
release verification, and share of implementation deployment.

53.4.a Conformant clients SHOULD compute and expose these indicators locally where
measurement is feasible without surveillance of peers.

53.4.b Where any single party exceeds 33 percent of any indicator, a structural warning SHALL
be published. The warning is an obligation on everyone else to add capacity, and is NOT an
offence by the operator concerned.

53.5 A public capture register SHALL be maintained, recording interest disclosures,
concentration warnings, drill results, distrust events, compulsion events, emergency
invocations under Article 57, and bus-factor audits.

53.6 A Blackout Drill SHALL be run annually. For a defined window of not less than 24 hours,
the largest operators and every node, relay, gateway, pin, index and mirror operated by the
Project go dark. What broke SHALL be published in full, including what was expected to survive
and did not.

53.6.a A failed drill is a defect of the highest severity and SHALL be remediated before the
next release.

53.6.b Failure to run the drill for two consecutive years is evidence of dormancy under
Article 56.

53.7 The auditable test, stated so that a stranger can apply it without assistance: if every
centralised mirror vanished today, could a new contributor obtain the full specification, the
full VWIP archive, verifiable releases, and the registry state? If the answer is no, that is a
defect to be fixed, not a risk to be accepted.

### Article 54. Marks, Network Identity and the Escrowed Release

54.1 Network identity SHALL be defined by technical invariants and not by a word. The
invariants are the genesis registry record, the specification hash chain, and the resolution
rules.

54.2 Conformant clients MUST identify networks by those invariants in their interface, so that
a community can rename itself in a day and lose nothing but a label.

54.3 Any word mark, if held at all, SHALL be held as a certification mark under a published,
objective conformance standard, and SHALL be used solely to prevent misrepresentation of
unmodified releases.

54.4 Any implementation meeting the published standard receives an automatic, irrevocable,
royalty-free licence to the mark, without application, negotiation, fee or discretion.

54.5 A licence MAY be withdrawn only for demonstrated non-conformance or misrepresentation of
origin, after written notice and a cure period of not less than 60 days. Withdrawal for
governance dissent, for forking, for public criticism, or for competing is PROHIBITED and
void.

54.6 Mark policy governs naming and never existence. It MUST include explicit permission for
honest fork naming, and MUST NOT be used to hinder the distribution of a fork.

54.7 The mark and any custodial material MUST NOT be sold, licensed exclusively, pledged,
encumbered, or transferred to a for-profit entity, and SHALL be held so as to be remote from
the insolvency of any holder.

54.8 An irrevocable conditional licence permitting a conformant successor to use the marks
SHALL be deposited with an independent escrow agent, releasing automatically on any of the
following trigger events:

54.8.a a purported amendment to an entrenched Article (Art. 9, Art. 58);

54.8.b a declaration of capture established under Article 59;

54.8.c failure of the custodians to constitute for 24 consecutive months;

54.8.d a judicial or administrative order compelling breach of Title I.

54.9 Release is automatic on the trigger and requires no decision, no meeting and no
co-operation from the holder. The escrow instrument SHALL be drafted so that the holder's
refusal cannot delay it.

54.10 The purpose is stated openly: this converts the ordinary trademark-hostage endgame into
a pre-committed, mechanical hand-off. A captured project loses the name by operation of the
instrument, and the community that continues the work never has to rebuild its reputation from
zero.

### Article 55. Succession, Incapacity, Founder Sunset and Continuity When Nobody Is Watching

55.1 Every role holding key material SHALL have a named, tested succession path and a
dead-man procedure.

55.1.a Liveness attestation SHALL be signed and published at intervals of not more than 90
days.

55.1.b On two consecutive missed attestations, the holder's share SHALL devolve automatically
to the named successors and the threshold SHALL be re-formed without further decision.

55.2 Succession SHALL be rehearsed at least annually, not merely documented, and the results
SHALL be published to the capture register (Art. 53.5).

55.3 Succession documentation MUST be written for a stranger, in plain language, with no
reliance on tacit knowledge, private channels, or any living person's memory.

55.4 The founder and steward holds no veto, no casting vote, no reserved key, no naming
rights, no tie-breaking authority and no perpetual role. This is stated in the present tense
and its absence is entrenched under Article 9.

55.5 The founding procedural bootstrap role (Art. 46, Art. 60) expires automatically and
irrevocably on its stated schedule. It MUST NOT be renewed, extended, transferred, inherited,
revived, or recreated under another name or in another body.

55.6 Death, incapacity, imprisonment, silencing, purchase, coercion or simple defection of any
participant, including the founder, SHALL be handled by the ordinary succession and distrust
procedures (Art. 51.7, Art. 51.8). Nothing in this protocol depends on any one person.

55.7 A constitution that needs its author has already failed. The author's greatest
contribution is to become structurally unnecessary before it matters, and this Article exists
to make that outcome mandatory rather than admirable.

55.8 The default state of every component MUST be continuing to work. Specifically there SHALL
be: no certificate that expires into failure; no rotation required for continued function; no
registration requiring a live service to renew; no client that phones home; no bootstrap entry
required to be reachable; and no scheduled human act as a precondition of resolution.

55.9 Every mechanism SHALL be evaluated against a single stated question before adoption: what
happens to this if every maintainer disappears tomorrow and nobody notices for ten years?
Where the honest answer is that it breaks, the mechanism MUST be redesigned or removed.

55.10 The Project cannot guarantee that anyone will be present to maintain it. It can only
guarantee that its absence is survivable.

### Article 56. Dormancy, Caretaker Mode, Revival by Strangers and Dissolution

56.1 No quorum is required for the network to keep working. Governance inactivity SHALL NEVER
halt resolution, registration, renewal, replication or publishing, and no protocol operation
MAY be made conditional on a governance body being constituted.

56.2 Dormancy is established by any of: failure to constitute an editorial panel for 12
consecutive months; absence of any VWIP transition for 24 consecutive months; or
unreachability of a majority of role holders for 12 consecutive months.

56.3 Dormancy is an honourable state and SHALL NOT be treated as failure. Apathy is the normal
condition of a century, and the failure to plan for it is what turns a quiet decade into an
unrecoverable one.

56.4 On dormancy, governance enters caretaker mode with maintenance-only authority: publish
security errata under Article 50, keep archives and infrastructure alive, and run the
procedures that restore participation.

56.4.a A caretaker MUST NOT amend this Constitution, charter a TLD, alter the namespace, adopt
any normative change, or spend beyond a published cap.

56.4.b Caretaker status MUST be published on assumption, and expires after 24 months unless
ordinary participation resumes.

56.5 Revival by strangers. After 36 consecutive months of total dormancy, any group of not
fewer than 7 participants MAY reconstitute editorship and continue the VWIP archive by
published procedure, following an open call with a notice period of not less than 90 days.

56.5.a The revival procedure MUST be executable using only this Constitution, the archived
registry and the public record. It MUST require no credential, no key, no permission and no
living participant.

56.5.b Revival requires no succession claim, blessing, or hand-over from whoever was last
active, and their later reappearance does not void it.

56.6 Orderly wind-down. Should the protocol be superseded, the Project SHALL publish the final
archive, mirror the registry state in durable, content-addressed and offline form, document
migration paths to the successor, and release everything irrevocably to the commons. There are
no assets to distribute, because there never were any (Art. 24).

56.7 No majority, maintainer set, custodian, court or successor SHALL be able to declare VayuWeb
ended for those who continue to run it. Dissolution binds only those who choose it, and the
software of everyone else continues to resolve.

### Article 57. Emergency Powers and Their Automatic Sunset

57.1 Emergency provisions are how constitutional orders die. This Article is therefore drafted
as a cage and not as a grant, and SHALL be read narrowly against the party invoking it.

57.2 A reduced procedure MAY be used only for a demonstrated, actively exploited security
defect. Anticipated exploitation, reputational urgency, commercial pressure, legal demand and
public controversy are NOT grounds.

57.3 Invocation requires: published justification identifying the defect and the evidence of
exploitation; the narrowest change capable of mitigating it; adoption by the release threshold
under Article 51.2; and publication of the full change within 7 days of adoption.

57.4 Every emergency change MUST be technical and content-neutral. It MUST NOT:

57.4.a be usable against a specific name, key, publisher, operator or class of content;

57.4.b alter, transfer, encumber or suspend the ownership of any name;

57.4.c add any capability, permission, collection or interface not strictly required for
mitigation;

57.4.d alter governance, economics, the amendment procedure, or anything entrenched under
Article 9.

57.5 Every emergency change carries an automatic sunset of not more than 180 days from
adoption. It expires by operation of this Constitution, without action, vote or notice, unless
ratified through the ordinary VWIP procedure before the sunset date. An expired change SHALL
be removed from conformant clients.

57.6 Emergency powers MUST NOT be invoked twice consecutively for the same matter. A defect
that requires a second emergency has become an ordinary defect and belongs on the ordinary
track.

57.7 Every invocation SHALL be recorded in the capture register (Art. 53.5) with the identity
of every party that invoked it, the date, the sunset date, and the outcome.

57.8 Every invocation MUST be followed within 30 days by a public post-mortem naming what was
done, by whom, and why the ordinary track was insufficient.

57.9 Repeated invocation is itself a governance defect and MUST be entered in the register of
named failure modes under Article 27.

57.10 This Article is bound by Articles 11, 20 and 35, and nothing in it may be read to permit
what those Articles forbid.

### Article 58. Amendment, Entrenchment and the Decennial Review

58.1 Amendment proceeds only by a Constitutional Amendment VWIP, and requires all of the
following:

58.1.a publication of the full replacement text, together with a rights-impact analysis under
Title II and a capture analysis under Article 4;

58.1.b a deliberation period of not less than 12 months, with two readings separated by not
less than 6 months;

58.1.c demonstrated prospective-only effect, with a stated future activation epoch and no
retroactive application to existing names or records;

58.1.d concurrent supermajority support of not less than 75 percent in each of the four
constituencies of Article 40, counted separately, with no constituency's shortfall offset by
another's surplus;

58.1.e double ratification: two separate ratifications separated by not less than 6 months,
the second conducted on an unchanged text.

58.2 A material change in the composition of participants between the two ratifications
restarts the process from the first reading. Failure of any step voids the amendment
entirely.

58.3 The intent is stated openly: amendment is designed to be slower than any plausible
attacker's attention span, slower than a funding cycle, and slower than almost every
manufactured emergency.

58.4 Entrenched Articles are excluded absolutely and cannot be reached by this or any other
procedure (Art. 9). Entrenchment covers substance and effect alike; an amendment that leaves
entrenched words intact while destroying their operation is an amendment to them.

58.5 A purported amendment to an entrenched Article is void ab initio, binds nobody, and is a
capture trigger under Articles 54.8 and 58.

58.6 Amendments take effect on publication of a new canonical anchor under Article 1.
Superseded text SHALL be retained in the archive rather than deleted, together with its
Objection Register, so that constitutional history remains auditable by a reader who arrives
long afterwards.

58.7 Every 10 years a Constitutional Review SHALL be convened to read the whole document and
publish findings. The findings MUST include a section titled "These provisions are not
working", and that section MUST NOT be left empty without stated reasoning.

58.8 A Review MAY propose a consolidated revision, which is subject to the ordinary procedure
of 58.1 in full and receives no expedition by virtue of its origin.

58.9 Failure to convene a Review invalidates nothing. The Constitution continues in force by
default, because a lapsed calendar must never become a mechanism for voiding the charter.

### Article 59. Declaration of Capture, the Right of Fork as Final Remedy, and Fork Hygiene

59.1 Capture is sustained control of the Project's decisions by a party acting against
Title I. It is established by any of: purported amendment of an entrenched Article; seizure or
attempted seizure of names; introduction of a mandatory identity or interception facility;
introduction of a token, fee or treasury contrary to Article 24; sustained refusal to publish
decisions under Article 8; or use of the marks against a good-faith fork.

59.2 Because there is no body competent to declare capture, declaration is evidentiary and not
institutional. Capture is established by published, independently verifiable evidence meeting
the criteria of 59.1, and requires no vote, ruling or recognition.

59.3 On establishment, the consequences follow automatically: the escrowed mark licence
releases under Article 54.8; conformance certification passes to the conformant successor; and
every participant is released from all obligations to the captured effort.

59.4 The right of fork is the final remedy and the reason the rest of this Constitution can
afford to be minimal. Any participant dissatisfied with any decision, including one reached by
entirely proper process, MAY fork the specification, the implementations, the registry state
and this Constitution itself, and MAY carry their names across, without permission, notice,
justification, waiting period or penalty.

59.5 Fork hygiene is stated as SHOULD and never as MUST, because a right conditioned on
courtesy is not a right. A fork SHOULD: name itself distinctly; publish the point of
divergence and the rationale; carry existing registrations forward unaltered; keep its own
state exportable in turn; and avoid deliberately confusing users about which network they are
on.

59.6 A fork MUST NOT retroactively invalidate names held under the parent. Neither parent nor
fork SHALL claim to be the sole legitimate successor. Legitimacy is determined by who runs
what, and by nothing else.

59.7 The hard case is conceded honestly: the incumbent is granted no structural defence
against a better-funded rival. There is no trademark weapon, no privileged bootstrap, no
default lock-in and no treasury to outspend from.

59.8 A well-capitalised fork that honours every entrenched guarantee is not an attack and
SHOULD be allowed to win. A fork that abandons those guarantees will find its own users
holding the same exit right against it, on the same terms, with the same finality.

59.9 This Article is entrenched under Article 9 and cannot be amended, suspended, narrowed or
made conditional by any procedure in this Constitution.

### Article 60. Ratification, Commencement and Transitional Provisions

60.1 Ratification means that those who adopt this Constitution bind their own software, their
own conduct and their own claims to the VayuWeb name. It binds nobody else, and there is no
authority that ratifies on anyone's behalf.

60.2 Ratification is not membership, confers no office, creates no entity, and may be withdrawn
by anyone at any time by ceasing to claim conformance.

60.3 The Constitution enters into force on the publication of the anchored canonical text
under Article 1, together with the first published conformance suite and the first VWIP
archive.

60.4 It governs from that moment even though no code yet runs. Writing it first is the point:
the code cannot be written against a document that already exists and is already anchored.

60.5 Transitional provisions are exhaustively as follows, and each self-repeals on the stated
date or event:

60.5.a the initial editorial panel and the seating of its first members — repeals on the
first ordinary panel constitution under Article 44, and in any event 24 months after
commencement;

60.5.b the initial primitives Annex — repeals on adoption of the first revised Annex, and in
any event 36 months after commencement;

60.5.c the timetable to the first full key rotation under Article 51.6 — repeals on completion
of that rotation, and in any event 24 months after commencement;

60.5.d the genesis registry record and its anchoring of the canonical text — permanent as a
historical anchor, with no operative authority after commencement;

60.5.e the initial conformance suite — repeals on publication of the first
community-maintained suite, and in any event 24 months after commencement;

60.5.f the founding steward's procedural role — repeals 36 months after commencement,
absolutely and without possibility of renewal (Art. 55.5).

60.6 Every transitional provision SHALL be listed in this Article and nowhere else, SHALL
state the date or event on which it self-repeals, and SHALL NOT be extended by any process
other than a full amendment under Article 58. Bootstrap arrangements must not be permitted to
become permanent institutions by inattention.

60.7 On the expiry of each transitional provision, a public statement SHALL be issued
recording that it has expired and what now governs in its place, so that the passage from
bootstrap to ordinary operation is a recorded event rather than a thing that may or may not
have happened.

60.8 The document closes as it began. This Constitution has no court, no police, no treasury
and no officers. It is enforced by conformance tests that anyone can run, by the refusal of
ordinary people to interoperate with software that breaks it, and by the unconditional freedom
to take the state, the names and the keys and go.
