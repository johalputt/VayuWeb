# VayuWeb FAQ

Short answers, including the unwelcome ones. Several of these are "no".

**Status:** Draft against the pre-implementation design. VayuWeb is not built yet.

## Basics

**What is VayuWeb?**
A peer-to-peer naming and hosting protocol. It lets you register a name, publish a site, and have
other people reach it from an ordinary browser — without a registrar, a certificate authority, a
hosting company, or anyone who can be asked to make you disappear.

**Can I use it today?**
No. There is no software. What exists is the [Constitution](../constitution/CONSTITUTION.md), the
specifications, and the [threat model](THREAT-MODEL.md). The
[roadmap](ROADMAP.md) explains the order and what "done" means for each phase.

**Why publish a constitution before any code?**
Because a naming system inherits whatever politics it was built with, and no project in this
field has ever successfully retrofitted governance onto infrastructure people already depend on.
Rules are cheap to change while the only thing at stake is an argument. Once people's identities
live on the system, they are not.

**Is this a blockchain?**
No. There is no global consensus on ordering, no mining, no block reward, and no chain. VayuWeb uses
a signed append-only log per participant with a deterministic convergence rule for the one case
that genuinely conflicts — two people claiming the same free name at the same time. That is
dramatically cheaper than a blockchain and it is sufficient, because naming does not need
double-spend prevention across the whole system, only per name.

**Is there a token?**
No, and there never will be. Constitution Article 7 forbids a token, a treasury and a protocol
fee, and Article 9 entrenches that against amendment. A token creates a class of people whose
interest is the price rather than the protocol, and it makes governance purchasable.

**So how is it funded?**
It isn't. Nobody gets paid. That is a real cost and it is stated honestly rather than solved with
a mechanism that would be worth capturing.

**What does it cost to register a name?**
No money. It costs a few seconds of your computer's time — a memory-hard proof-of-work that is
trivial for one name and grows superlinearly if you try to take ten thousand. See
[spec/PROOF-OF-WORK.md](spec/PROOF-OF-WORK.md).

**Who runs VayuWeb?**
Nobody. Constitution Article 39 is titled "There Is No Governing Body" and means it. Protocol
changes move through the [VWIP process](spec/VWIP-0000.md); the network runs whatever its peers
choose to run.

## Names

**How do I get a name?**
Generate an Ed25519 keypair, do the proof-of-work, sign a registration record, append it. First
valid signature wins.

**What extensions are there?**
1,270 at launch, across 34 categories — everything from `.folio` and `.zine` to `.dissent`,
`.allodial`, `.ghazal` and `.chai`. They are enumerated in the
[Namespace Annex](spec/NAMESPACE-CATALOGUE.md), which the Constitution incorporates by
reference; the list is deliberately not repeated anywhere else, because a restatement is a copy
that can drift and the ones this project used to keep did. Plural on purpose — a single
namespace is a single thing worth capturing. All extensions are equal; none is the "real" one,
and no client may present one as more official than another.

**How long does a registration last?**
One year. The renewal window opens 60 days before expiry. After expiry there is a 30-day grace
period in which only the owner may renew, then a 30-day quarantine in which nobody may register
it, then it returns to the open pool. The quarantine exists so that watching the log for
expiries is not a profitable business.

**What stops squatting?**
Proof-of-work makes bulk registration expensive, renewal requires fresh work so hoarding has an
ongoing cost, and there are 1,270 extensions so no single namespace is the only prize — cornering
a desirable string costs 1,270 registrations renewed forever rather than eleven. This is a speed
bump, not a wall — [spec/PROOF-OF-WORK.md](spec/PROOF-OF-WORK.md) says so explicitly.

**What if I lose my key?**
You lose the name. There is no recovery, no support desk, no override.
This is the answer most people dislike, and it is not going to change: any authority that can
restore your name against your key is an authority that can take your name. You can designate a
successor key in advance under Constitution Article 34 — do that.

**Can someone take my name?**
Not without your key. No maintainer, no editor, no court order served on the project, and no
majority vote can move a name, because no such mechanism exists to be invoked. What can take your
name is theft or coercion of your key — see T1 and T3 in the [threat model](THREAT-MODEL.md).

**What about trademarks? Someone registered my company's name.**
The registry will not take it back, and that is deliberate. Article 36 refuses to make VayuWeb a
trademark court, because a protocol that can adjudicate a dispute is a protocol with an office
that can be petitioned — and once that office exists it can be pointed at anyone.

What you can do instead is **prove who you are**, which turns out to work better. Publish a DNS
TXT record on the domain you already control, binding it to your VayuWeb key. Any reader's client
verifies it mechanically, with no panel involved. The squatter keeps the label and cannot produce
that proof, so it stops being useful for impersonating you. See
[spec/ATTESTATION.md](spec/ATTESTATION.md).

This is deliberately weaker than a reserved-names list in one way and stronger in three. It will
not stop `yourbrand-shop` from being registered. But it protects every name rather than only the
listed ones, it works for a corner shop and a pseudonymous writer as well as a multinational, and
nobody has to apply to anybody.

**Do I get first claim on a VayuWeb name because I own the matching clearnet domain?**
No. Article 30.2 rules out priority windows and sunrise periods for every class of claimant,
naming trademark holders and incumbent operators explicitly — and the drafters of the
Constitution too. First valid signature wins, for everyone. Register early, and attest afterwards.

**Can I sell a name?**
You can transfer it. VayuWeb deliberately declines to build a secondary market: Article 33 imposes a
settlement delay on transfers and refuses to provide market infrastructure. Names are for use.

**Can new extensions be added?**
Yes, through a VWIP with a ratification threshold set by the Constitution. Retiring one is
harder than creating one, and requires a minimum 24-month sunset with mandatory alias records, so
that a retirement cannot strand people who built an identity on it.

## Hosting

**Where do the files actually live?**
On IPFS, on whichever machines have chosen to pin them — starting with yours.

**What happens if I turn my computer off?**
If nobody else pinned your content, it becomes unreachable. The name still resolves; the bytes
are gone. Constitution Article 23 states that availability is not guaranteed, because no
participant is in a position to guarantee it.

**Is it censorship-proof?**
Careful answer: it removes the *specific* chokepoints that are used to silence people today — the
registrar, the resolver, the certificate authority, the host, the content network. It does not
make content immortal, and it does not stop a state from blocking your traffic at the network
layer, seizing your device, or compelling you personally. "Harder to censor at the naming and
hosting layer" is true. "Censorship-proof" is not, and you should distrust anyone who says it.

**Can I delete something?**
You can withdraw the pointer and unpin your copy. You cannot compel other peers to discard bytes
they already hold, and the registry log itself never forgets that a record existed. Article 19
covers the right to unpublish and is explicit about where that right stops.

## Using it

**Do I need a special browser?**
No. A small proxy runs on your own machine and an ordinary browser is pointed at it. There will
be an optional extension for convenience, but Constitution Article 4 means it must never become a
requirement.

**Will ordinary links work?**
Within VayuWeb, yes. A `.vayu` page linking to a clearnet page works. A clearnet page linking to a
`.vayu` name only works for readers who are running the resolver — which is the same bootstrapping
problem every parallel network has, and VayuWeb has no magic answer to it.

**Does a VayuWeb lookup leak to normal DNS?**
No, and this is a hard requirement rather than a preference. The resolver answers VayuWeb names
authoritatively and returns a defined error rather than falling through to a clearnet resolver.
Constitution Article 14 makes it testable: the conformance suite checks the outbound connections
produced by a single-name lookup.

## Privacy

**Does VayuWeb make me anonymous?**
**No, and it is not trying to.** VayuWeb is a parallel web, not a hidden one. It does not hide your
IP address, your traffic patterns, or what you fetched from anyone watching your network. Your
network provider can see that you are using it.

**Isn't that a weakness?**
It is a sequencing decision, and it buys three things worth having. Anonymity done properly means
onion routing or a mixnet: seconds of latency, constant cover traffic, heavy battery use, and a
small anonymity set that provides false assurance until the network is large. Not paying that
cost keeps VayuWeb fast, keeps it simple enough to be secure, and keeps it usable by people who just
want a website nobody can switch off. An optional layer can be added later; latency baked in at
the start cannot be removed.

**So what does VayuWeb actually protect?**
Two things, and both are concrete — and both are narrower than they first sound, so they are
stated at their real size.

First, **there is nobody to petition** to take your name or switch off your site: no registrar,
certificate authority, host or content network sits in the path. That removes the party an order
gets served on. It does not stop a state seizing your device, compelling your key, or blocking the
network you reach peers over, and it does not keep your site reachable if nobody holds a copy.

Second, **a name lookup does not leave your machine**, because resolution runs against your local
replica of the registry. A clearnet DNS lookup tells a resolver operator every name you visit; a
VayuWeb lookup tells nobody *which name you resolved*. It is not silence: fetching the content
afterwards contacts peers, and that traffic reveals which site you are reading. The property is
about the lookup, not about the session.

**What should I use if I need anonymity?**
Tor, and understand its limits too. VayuWeb composes with it rather than replacing it, and
Constitution Article 24 forbids claiming otherwise.

## Governance

**Who decides what changes?**
Anyone may propose; changes advance by rough consensus, meaning the absence of unaddressed
substantive technical objection. Not a vote, not unanimity, not seniority. Every objection is
answered on the record, and unresolved ones go permanently into the Objection Register with the
reasoning that overruled them.

**What stops the founder going bad?**
Structurally: there is no power for a founder to abuse. No privileged writer, no treasury, no
override key, no office that can move a name. Procedurally: Article 55 covers founder sunset,
incapacity and succession. Ultimately: Article 59 and the fork.

**Who owns the name "VayuWeb"?**
Article 54 governs marks and network identity. The important part is that the protocol does not
depend on the word: the registry state, the specifications and the charter are all public and
forkable, so losing the name would be painful and survivable.

**Can I fork it?**
Yes, and it is a **right**, not a threat — Article 17. The charter text is dedicated to the public
domain precisely so a fork can carry it away intact. A governance system that can be exited is
one that has to stay honest, which is the entire mechanism.

**What if governance itself gets captured?**
Article 59 provides for a declaration of capture and treats the fork as the final remedy, with
fork hygiene rules so that a legitimate fork is distinguishable from an opportunistic one. The
remedy deliberately does not route through the body that has been captured.

## The project

**When will it ship?**
No date. See [ROADMAP.md](ROADMAP.md) — phases have acceptance tests instead of dates, so you can
check progress yourself rather than trusting an announcement.

**How can I help?**
Right now, by attacking the design rather than writing code. Finding the clause a bad actor could
exploit is worth more today than any pull request. See [CONTRIBUTING.md](../CONTRIBUTING.md).

**Why Radicle?**
Because a project whose entire purpose is removing dependence on centralised infrastructure
should not permanently live on centralised infrastructure. GitHub is a mirror, kept because it is
where people currently are — which is exactly the dependency VayuWeb exists to end.

**What licence?**
MIT for code, with contributions under a DCO and no contributor licence agreement, so nobody
— including the founder — holds the rights to relicense it later. The Constitution and the
specifications are public domain (CC0), deliberately: a licence on a founding
charter is a leash on a fork.

## See also

- [The VayuWeb Constitution](../constitution/CONSTITUTION.md)
- [Whitepaper](WHITEPAPER.md)
- [Threat model](THREAT-MODEL.md)
- [Glossary](GLOSSARY.md)
