# VayuWeb Namespace Specification

How VayuWeb gets a broad namespace, why breadth is safe here and dangerous on the clearnet, and how
new extensions are created without a fee, an application round, or an authority.

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

**Status:** Draft — not yet implemented. Supersedes the launch-list framing in
[NAMES.md](NAMES.md); the label grammar and lifecycle there are unchanged.

## 1. The power the clearnet does not have

Creating a top-level domain on the clearnet costs, in the 2012 application round, a **USD 185,000
evaluation fee** plus a registry agreement carrying fixed annual fees in the region of USD 25,000,
a multi-year application window that opens roughly once a decade, and a corporate applicant able
to survive the process.

That price is not a technical necessity. It is the cost of an authority: evaluation panels,
objection procedures, contractual compliance and the organisation that runs them. It means the
namespace is shaped by who could afford to apply.

On VayuWeb, creating an extension costs **a proposal and proof-of-work**. No fee, no application
round, no authority, no corporate applicant. The namespace can therefore be as broad as the
people using it want it to be, and it can keep growing after launch without anybody's permission.

This is the single clearest example of the project's thesis: the chokepoint was never technical.

## 2. The namespace is elastic, not a list

VayuWeb ships a **broad ratified set that grows by process**, not a fixed small set and not an
open one. Both of those were claimed by earlier revisions of this section, and neither matched
the charter.

2.1 **1,270 extensions are ratified at launch.** They are enumerated in the **Namespace Annex**,
[NAMESPACE-CATALOGUE.md](NAMESPACE-CATALOGUE.md), which Constitution Article 35.1 incorporates
by reference; eleven of them are additionally named in the Article's own text so the founding
set survives loss of the Annex, which confers no rank on those eleven (Article 35.1.c). A
verifier MUST reject any string outside the Annex. [VWIP-0004](VWIP-0004.md) is the ratification
record and carries the Article 35.6 collision review entry by entry.

2.1.a The set is large *and* closed, and the combination is the design rather than a compromise
between two others. Closed is what makes large safe: membership is decidable offline by a reader
holding the text, so two honest Nodes cannot compute different namespaces, and a namespace two
Nodes disagree about is a fork presenting as an intermittent resolution failure. Large is what
makes closed honest: an enumeration of eleven is not a namespace policy, it is a placeholder,
and the only parties served by keeping it small are the holders of the eleven.

2.2 Any participant MAY propose a new extension at any time through the process in section 4,
which is a ratified Naming-category VWIP under Article 35.6 — collision review, a public
objection window of at least ninety days, and at least a hundred and eighty days of dormancy
before availability. There is no cap on the number of extensions and no manufactured scarcity,
but there is a deliberate delay, and it exists so that advance knowledge of a new extension
confers no landrush advantage (Article 35.7).

2.3 An implementation MUST reject any extension outside the Annex, MUST decide membership
offline against the copy it holds, and MUST update that copy only when a Naming VWIP ratifies an
addition (Constitution Article 2.31). An implementation MUST NOT fetch, subscribe to, sync or
otherwise derive the valid set at run time, whatever the source and however reputable: a
namespace that arrives over the network is a namespace someone can withhold, which fails
Article 4.

2.3.a An earlier revision required the opposite — that the set be "derived from the registry
log" and never hard-coded. It cannot be implemented as written, because the record format has
no TLD-creation operation and the log therefore carries nothing to derive a set from, and it
would be wrong if it could: Article 35.6 vests creation in a ratified proposal rather than in a
record anyone can append, so a log-derived namespace would let whoever can append define what
exists.

2.3.b Compiling the Annex in creates a copy, and a copy can drift. That is a real cost of this
design and it is paid rather than argued away: the reference implementation generates its set
from the Annex with `scripts/generate-namespace.py` and CI re-runs the generator with `--check`,
so editing either the Annex or the generated module alone fails the build. Any independent
implementation needs an equivalent discipline. A namespace copy wrong by one entry accepts names
others reject, which is the failure this whole section exists to prevent.

2.4 A client MUST NOT treat any extension as more legitimate than another. There is no premium
tier, no reserved class sold at a higher price, and no "real" extension. Constitution Article 35
requires TLD equality and this is its operational form.

## 3. Why breadth is safe here and costly on the clearnet

Broad namespaces have a bad reputation, earned honestly: ICANN's gTLD expansion produced a
**defensive registration tax**, where a brand felt obliged to register its name across hundreds of
extensions to stop somebody else passing off as them. More extensions meant more cost for the
same protection.

Four properties change that arithmetic on VayuWeb, and they are design decisions rather than luck:

**3.1 Cost scales with breadth, for the squatter.** Registration requires memory-hard
proof-of-work. Taking one label across 500 extensions costs 500 times the work, and renewal
requires fresh work every year. A squatter's cost grows linearly with the namespace; a legitimate
holder wanting one name pays once.

**3.2 There is no resale market to profit from.** Constitution Article 33 imposes a settlement
delay on transfers and explicitly refuses to provide secondary-market infrastructure. The
squatter's business model on the clearnet is resale; here there is no exchange, no auction, no
escrow and no price discovery. Names are for use.

**3.3 There is no advertising or search economy to capture.** Clearnet squatting monetises
through parked-page advertising and search traffic. VayuWeb has neither.

**3.4 Identity is a key, not a string.** This is the deepest one. On the clearnet, controlling
`brand.example` largely *is* controlling the identity. On VayuWeb, a name resolves to a record signed
by a specific keypair, and clients follow keys. A squatter holding a lookalike label cannot
produce a signature from the key readers already follow.

Clients SHOULD make this visible: an interface that shows a reader "this is the key you followed
before" defeats lookalike labels more effectively than any registration policy, and it costs
nothing to implement.

[ATTESTATION.md](ATTESTATION.md) takes this further. A holder of a clearnet domain can prove the
connection mechanically — a DNS TXT record, verified by the reader's own client, with no panel and
no adjudication. A squatter who takes `brand.shop` keeps it, exactly as Article 30 requires, and
cannot produce a signature from the key that controls `brand.com`. The label stays theirs and
becomes worthless for impersonation, which removes the incentive rather than fighting it with a
reservation list.

**3.5 The honest residual.** None of this eliminates squatting or confusion. A determined actor
with hardware will take labels, and a reader who has never seen a publisher before cannot tell a
lookalike from the original. Section 3.4 protects returning readers, not first-time ones.
Constitution Article 36 refuses to make the registry a trademark court and that refusal stands —
VayuWeb declines to adjudicate rather than pretending it has solved the problem.

## 4. Creating an extension

4.1 A new extension requires a ratified Naming-category VWIP, per Constitution Article 35.6 and
[NAMES.md](NAMES.md). Ratification requires, over a 30-day voting period, at least a two-thirds
majority, followed by a dormancy period of not less than 180 days between ratification and first
registration.

4.2 The dormancy period is the anti-landrush mechanism and MUST NOT be shortened. It exists so
that a newly created extension cannot be swept by whoever was watching the proposal, giving
everybody equal notice that a namespace is about to open.

4.3 The proposal MUST state the string, its intended meaning, and — this is the part most
proposals will get wrong — why an existing extension does not already serve the purpose. Breadth
is cheap; redundancy is still noise.

4.4 Proposing an extension carries proof-of-work at a multiple of a single registration, so
proposing hundreds speculatively is expensive while proposing one is not.

## 5. Collision policy

5.1 An extension MUST be **two to twelve characters**.

**Two-letter extensions are permitted.** An earlier draft of this document set a three-character
floor to avoid the ISO 3166 country-code space. That reasoning does not survive examination and
is withdrawn.

VayuWeb defines its own namespace. ISO 3166 is a useful shared reference, not an authority VayuWeb
recognises, and declining to use two-letter strings would mean ceding namespace design to a body
the project exists to route around. The confusion argument is also empirically weak: the clearnet
has already spent two decades treating `.io`, `.ai`, `.co`, `.me`, `.tv` and `.fm` as generic
strings, and essentially nobody believes `.io` sites originate in the British Indian Ocean
Territory. A two-letter string is a string. `in` is an English preposition, `io` is
input/output, `me` is a pronoun.

The scheme settles any residual ambiguity: `vayu://shop.io` and `https://shop.io` are visibly
different systems, and [URI-SCHEME.md](URI-SCHEME.md) section 4.4 already requires clients to
display the full authority without elision.

5.2 An extension MUST NOT duplicate a well-known ICANN generic top-level domain. This rule
survives, and for a different reason than 5.1 did: `vayu://example.com` unrelated to
`https://example.com` teaches readers that VayuWeb names cannot be trusted to mean anything. A
parallel web should be recognisably parallel, not a confusing echo of the most familiar strings
on the clearnet.

5.3 **Country names, government identifiers and the names of living public figures MUST NOT be
created as extensions.** This is the rule that carries the weight 5.1 was wrongly asked to carry,
and the distinction is between a string and a claim.

`.in` is a two-letter string with an ordinary English meaning, and registering it asserts nothing
about India. `.india` or `.bharat` reads as representing a nation, and VayuWeb cannot adjudicate who
does. Creating a namespace that implies it can invites exactly the political pressure the project
exists to avoid.

5.4 An extension MUST NOT be presented, in any client or any official material, as carrying
national, governmental or official affiliation. Constitution Article 35's equality requirement
already forbids treating any extension as more official than another; this makes the national
case explicit.

## 6. Retirement

Retiring an extension is harder than creating one, deliberately. Per [NAMES.md](NAMES.md), it
requires a ratified VWIP and a minimum 24-month sunset with mandatory alias records, so that
nobody who built an identity on it is stranded. Constitution Article 35 additionally forbids
removal that would strand holders.

An extension nobody uses costs the network a single record. There is rarely a good reason to
retire one, and the bar is set to reflect that.

## 7. Conformance

1. No implementation hard-codes an extension list; the valid set is derived from the log.
2. A two-character extension proposal is rejected.
3. A proposal duplicating a well-known ICANN gTLD is rejected.
4. Registering one label across N extensions costs N times the proof-of-work of one.
5. No client interface presents any extension as more legitimate, premium or official.
6. First registration in a new extension is refused until the dormancy period has elapsed.

## See also

- [Naming and TLD policy](NAMES.md) — label grammar and lifecycle
- [Cost model](COST.md) — why registration carries no fee
- [Registry](REGISTRY.md) — how extension records are stored
- [The VayuWeb Constitution](../../constitution/CONSTITUTION.md) — Articles 33, 35, 36
