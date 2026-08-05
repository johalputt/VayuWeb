# VayuWeb Threat Model

**Status:** Draft against the pre-implementation design. Nothing described here has been built,
so every mitigation below is a design commitment rather than a tested property. Treat this
document as a specification of what the implementation must defend against, and as an invitation
to find what it misses.

This model is deliberately unflattering. A threat model that concludes the system is safe is not
a threat model, it is marketing. Every entry carries a **residual risk** column, and several of
them say that the residual risk is substantial and unmitigated.

## 1. Assets

What an attacker wants, roughly in order of how badly its loss hurts.

| Asset | Why it matters |
|---|---|
| **Name control** | The ability to keep answering for `example.vayu`. Losing it is losing an identity that others link to. |
| **Owner private keys** | Ed25519 secret keys are the only thing that establishes name control. There is no recovery path that does not also create a seizure path. |
| **Registry integrity** | Every peer's ability to independently verify the whole history. If this breaks, VayuWeb is a slow database with extra steps. |
| **Content availability** | Whether the bytes a name points at can still be fetched. |
| **Reader privacy** | What a person looked up, and when. |
| **Publisher unlinkability** | Whether a name can be tied to a legal identity or a location. |
| **Network liveness** | Whether peers can find each other at all. |
| **The governance record** | The archive of what was decided and what was objected to. An unauditable record is the condition VayuWeb exists to end. |

## 2. Adversaries

| Adversary | Capabilities | Motivation |
|---|---|---|
| **Opportunistic squatter** | Commodity hardware, scripting, patience | Resale value of short or brandable names |
| **Commercial spammer** | Rented compute at scale, many identities | Bulk registration for phishing or SEO-equivalent abuse |
| **Rent-seeking pinning operator** | Large storage, good connectivity, capital | Become the de facto host everyone depends on, then charge |
| **Hostile fork with capital** | Funding, marketing, developer time | Capture the name, the users, or the default client |
| **State actor** | Network-level control, legal compulsion, endpoint access | Suppress specific publishers; deanonymise readers |
| **Compromised maintainer** | Release-signing access, repository write | Ship a backdoor to every user at once |
| **Sybil swarm** | Many cheap identities and nodes | Distort discovery, manufacture governance consensus |
| **Targeted attacker** | Focused effort on one publisher | Take one specific name or unmask one specific person |

Two of these deserve emphasis because they are usually underrated. The **rent-seeking pinning
operator** is the most likely path by which VayuWeb would quietly re-centralise, and it requires no
rule-breaking at all — just being the most convenient option for long enough. The **compromised
maintainer** has the widest blast radius of anything in this table.

## 3. Threats

### 3.1 Keys and name control

**T1 — Owner key theft.**
*Vector:* endpoint compromise, malware, a backup copied from a synced folder, coercion.
*Impact:* total and immediate loss of the name; the attacker can sign a transfer.
*Mitigation:* the secret key lives in the OS keychain and never in a config file or the
replicated log (see [ARCHITECTURE.md](ARCHITECTURE.md)); key rotation and revocation under
Constitution Article 34; the transfer settlement delay of Article 33 gives a window to notice.
*Residual risk:* **High.** A compromised endpoint is game over, and settlement delay only helps a
victim who is watching. VayuWeb does not defend a machine the attacker already owns.

**T2 — Key loss.**
*Vector:* dead disk, forgotten passphrase, death of the holder.
*Impact:* the name is unrecoverable and lapses on schedule.
*Mitigation:* opt-in succession under Article 34 lets a holder designate a successor key in
advance. Nothing else.
*Residual risk:* **Accepted by design.** There is no recovery mechanism, because any authority
that can restore your name against your key is an authority that can take it. This is stated in
the README, the FAQ and Article 11, and it is the single most common reason people will reject
VayuWeb. That is a fair trade to lose people over, not one to soften.

**T3 — Coerced signature.**
*Vector:* legal compulsion or violence directed at the holder.
*Impact:* an attacker obtains a validly signed transfer.
*Mitigation:* Article 8 makes compelled acts void *ab initio* as a matter of charter, and the
settlement delay of Article 33 creates a window in which the coercion can be published.
*Residual risk:* **High and irreducible.** A cryptographically valid signature is
indistinguishable from a freely given one. The charter can refuse to honour coercion socially; it
cannot make the mathematics disagree.

### 3.2 Registry integrity

**T4 — Sybil flooding of the registry.**
*Vector:* thousands of cheap identities submitting registrations.
*Impact:* namespace exhaustion, index bloat, degraded verification for everyone.
*Mitigation:* memory-hard Argon2id proof-of-work with superlinear cost growth
(see [spec/PROOF-OF-WORK.md](spec/PROOF-OF-WORK.md)); per-record size limits; plural TLDs so no
single namespace is the only prize.
*Residual risk:* **Moderate.** Proof-of-work prices bulk registration; it does not prevent a
well-funded actor from taking many names. The real defence is that names are cheap to abandon and
the namespace is plural — which is a mitigation of the *harm*, not of the attack.

**T5 — Log poisoning and replay.**
*Vector:* replaying an old signed operation, or submitting a malformed record that crashes naive
validators.
*Impact:* stale state resurrected; denial of service against peers.
*Mitigation:* per-name monotonic sequence numbers, `prevHash` chaining, and deterministic CBOR
canonical serialisation with a domain-separation prefix
(see [spec/REGISTRY.md](spec/REGISTRY.md)); strict validation ordering; hard size limits.
*Residual risk:* **Low**, conditional on implementations validating before indexing. A defect
here is a specification-conformance failure, which is why the conformance suite is normative.

**T6 — Equivocation: two conflicting first-registrations.**
*Vector:* a partitioned network where two peers each see a different "first" claim.
*Impact:* two parties each believe they own a name.
*Mitigation:* the convergence rule — sole valid claim, else the smaller record digest — plus
monitors and equivocation detection under Article 38.
*Residual risk:* **Moderate.** Convergence is deterministic, but the loser of a tie-break
experiences it as arbitrary confiscation. There is no version of this that feels fair to both
parties.

**T6a — Delivery-order manipulation: choosing who owns a contested name.**
*Vector:* a relay, or merely a better-connected peer, delivers two conflicting registrations to
two peers in opposite orders. Nothing is forged, dropped or noticeably delayed — an order is
chosen, which is a thing every relay does by existing.
*Impact:* under an ordering-based convergence rule, the two peers award the name to different
keys, both correctly, and nothing later revisits it. A permanent namespace fork, with the winner
selected by whoever controls the wire.
*Mitigation:* **designed out rather than defended.** The convergence rule takes no ordering input
at all: a conflict is decided by the record digest, a pure function of bytes both peers already
hold. `ConflictRule` does not contain an ordering verdict, so an implementation cannot report one
without changing the type, and `converge.test.ts` pins the property against seven arrangements of
local log position including the two that produced the fork.
*Residual risk:* **Low, and honestly bounded.** The digest tie-break is grindable — an attacker
expecting a tie can vary `powProof.nonce` to lower their hash — but each attempt costs a full
proof-of-work and buys a chance at a coin flip in a case that was undecidable anyway. That is
strictly narrower than the vector it replaces, which cost nothing and won outright. This entry
exists because the ordering rule was implemented and shipped before it was attacked; it survived
a feature review and its own unit tests, which supplied log positions consistent with a single
order because a single-machine test has only one.

### 3.3 Network

**T7 — Eclipse attack on peer discovery.**
*Vector:* surrounding a target node with attacker-controlled peers in the DHT.
*Impact:* the victim sees a fabricated registry state; can be shown a hijacked pointer.
*Mitigation:* plural, swappable bootstrap sets; independent verification of every record received
(a peer never trusts, it checks); snapshot and monitor cross-checking under Article 38.
*Residual risk:* **Moderate.** Signature verification means an eclipsed node cannot be shown a
*forged* record — but it can be shown a *stale* one, and withholding is invisible from inside the
eclipse.

**T8 — Bootstrap-node centralisation.**
*Vector:* not an attack at all. A default list ships, everyone uses it, and in five years two
operators are load-bearing.
*Impact:* a de facto root, exactly what VayuWeb exists to remove.
*Mitigation:* Article 4's no-chokepoint invariant; bootstrap lists must be plural and swappable;
the concentration metrics and blackout drill of Article 53 measure this deliberately and
publicly.
*Residual risk:* **Moderate, and the most likely way VayuWeb fails.** Convenience defaults are how
decentralised systems acquire a centre, and no clause prevents users from choosing the easy path.
Measurement is the only honest defence offered.

**T9 — Network-level blocking.**
*Vector:* an ISP or state blocking the DHT or IPFS traffic.
*Impact:* VayuWeb unreachable for those users.
*Mitigation:* none within VayuWeb.
*Residual risk:* **Total, and explicitly out of scope.** VayuWeb removes intermediaries from naming
and hosting. It has nothing to say about a severed cable. Pair it with Tor or another transport;
see Article 24.

### 3.4 Content

**T10 — Content unavailability.**
*Vector:* the owner stops pinning and nobody else did.
*Impact:* the name resolves; the content is gone.
*Mitigation:* self-pinning, friend-pinning, volunteer pin sets, optional third-party pinning that
must stay swappable (see [spec/HOSTING.md](spec/HOSTING.md)).
*Residual risk:* **High and accepted.** Article 23 states plainly that availability is not
guaranteed. VayuWeb makes no uptime promise because no participant is in a position to make one.

**T11 — Hijacked pointer serving malicious content.**
*Vector:* T1 or T3 succeeds; the attacker republishes the IPNS pointer.
*Impact:* users fetch attacker content under a trusted name.
*Mitigation:* everything under T1; per-name origin isolation and a restrictive default
Content-Security-Policy in the resolver (see [spec/RESOLUTION.md](spec/RESOLUTION.md)).
*Residual risk:* **Inherits T1.** Once the key is gone, the name is the attacker's, and no
downstream control changes that.

### 3.5 Privacy

**T12 — Reader deanonymisation via the DHT.**
*Vector:* observing which CIDs a peer requests; correlating DHT queries to an IP.
*Impact:* a reading history tied to a network address.
*Mitigation:* no query logging by default and no phone-home in the resolver (Article 14, with an
executable conformance test for outbound connections on a single-name lookup).
*Residual risk:* **High.** This is a property of the underlying content-addressed network, not
something VayuWeb can fix at the naming layer. Article 24 refuses to claim otherwise.

**T13 — Correlation through a pinning service.**
*Vector:* a large pinning operator observes who publishes what, and who fetches it.
*Impact:* publisher and reader linkage at scale.
*Mitigation:* pinning is optional and swappable by charter; the client ships no default provider.
*Residual risk:* **Moderate to high**, and it rises with T8. The operator that becomes convenient
becomes the observer.

**T14 — Traffic analysis at the ISP.**
*Vector:* passive observation of connection patterns.
*Impact:* inference about activity even without content.
*Mitigation:* none within VayuWeb.
*Residual risk:* **Total, out of scope.** See T9.

### 3.6 Project and supply chain

**T15 — Compromised maintainer or stolen release key.**
*Vector:* credential theft, coercion, or a maintainer turning hostile.
*Impact:* a backdoored client shipped to every user simultaneously. The widest blast radius in
this document.
*Mitigation:* reproducible builds and multi-party release signing (Article 51), including an
explicit duty to refuse a release that cannot be reproduced; the three-person minimum and
bus-factor rules of Article 46; escrowed release material under Article 54.
*Residual risk:* **Moderate.** Reproducibility means a backdoor must survive independent
rebuilding, which is a genuinely high bar — but only if someone actually rebuilds and compares.
Verification that nobody performs is not a control.

**T16 — Governance capture.**
*Vector:* supplying most of the review labour; installing sympathetic editors; using the
amendment process to remove the guarantees it was written to protect.
*Impact:* VayuWeb becomes what it replaced, while appearing procedurally correct throughout.
*Mitigation:* the entrenched core of Article 9, which no amendment can reach; the Objection
Register (Article 43.6); editor composition limits (Article 46); and Article 59 — declaration of
capture and the right of fork as final remedy.
*Residual risk:* **Moderate.** Every internal check can in principle be captured together. The
fork is the only remedy that does not depend on the captured body, which is exactly why
Article 17 makes it a right and why the charter text is public domain.

**T17 — Trademark or legal seizure of the name "VayuWeb".**
*Vector:* a third party registers the mark and asserts it; or a court orders a transfer.
*Impact:* the project loses the ability to call itself VayuWeb.
*Mitigation:* Article 54 on marks and network identity; deliberate non-incorporation (Article 1),
so there is no legal entity to serve.
*Residual risk:* **Moderate.** The mitigation is that the protocol does not depend on the name:
the registry state, the specifications and the charter are all forkable and public domain. Losing
the word would be painful and survivable.

**T18 — Protocol ossification.**
*Vector:* nothing changes, because the process is heavy and volunteers are scarce.
*Impact:* VayuWeb calcifies around early mistakes and is displaced by something worse but newer.
*Mitigation:* the anti-ossification duties of Article 49; the decennial review of Article 58.
*Residual risk:* **Moderate.** Listed here because ossification is a security failure, not merely
a product one: a protocol that cannot fix a cryptographic weakness is insecure by construction.

**T19 — Quorum collapse in year 40.**
*Vector:* everyone stops paying attention. No editors, no reviewers, no releases.
*Impact:* the process stops, and with it any ability to respond to anything above.
*Mitigation:* Article 28 — duties bind the text and the software, not any body, and any
participant may discharge them without appointment; Article 56 on dormancy, caretaker mode and
revival by strangers; the 120-day dead-man rule of Article 46.8.
*Residual risk:* **Moderate.** The design degrades to "still verifiable, nobody maintaining"
rather than to "broken", which is the best available outcome. Article 28.6 requires that lapsed
maintenance be *stated* rather than quietly implied.

## 4. Non-goals

Stated as flatly as possible, because every one of these has been claimed by some project in this
space and none of them is true of VayuWeb:

- **VayuWeb is not an anonymity system, by design.** It is a parallel web, not a hidden one — see
  [POSITION.md](POSITION.md). It removes the chokepoints that let a party switch a site off; it
  does not hide your traffic, your address, or your reading. An optional anonymity layer is
  deferred, not refused. Use Tor for what VayuWeb does not do.
  One exception is worth stating positively rather than leaving as an accident: **name resolution
  contacts no peer**, because it runs against the local registry replica, so no party learns which
  name a reader looked up. That property holds while the replica fits on the reader's device.
- **VayuWeb does not defend a compromised endpoint.** If the attacker has your machine, they have
  your keys and your names.
- **VayuWeb does not promise availability.** Content lives while someone pins it, and not one moment
  longer.
- **VayuWeb cannot forget.** An append-only log cannot unlearn, and no peer can be compelled to
  discard bytes it already holds.
- **VayuWeb does not resist a state at the network layer.** Blocking, seizure and compulsion are all
  outside what a naming protocol can address.
- **VayuWeb will not adjudicate.** Not trademarks, not truth, not merit, not who deserves a name.

## See also

- [The VayuWeb Constitution](../constitution/CONSTITUTION.md) — Title III states the limits as
  binding obligations
- [Architecture](ARCHITECTURE.md) — trust boundaries and what each component must not do
- [Registry specification](spec/REGISTRY.md) — validation, convergence and replay protection
- [Security policy](../SECURITY.md) — how to report something this document missed
