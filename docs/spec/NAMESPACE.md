# WebX Namespace Specification

How WebX gets a broad namespace, why breadth is safe here and dangerous on the clearnet, and how
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

On WebX, creating an extension costs **a proposal and proof-of-work**. No fee, no application
round, no authority, no corporate applicant. The namespace can therefore be as broad as the
people using it want it to be, and it can keep growing after launch without anybody's permission.

This is the single clearest example of the project's thesis: the chokepoint was never technical.

## 2. The namespace is elastic, not a list

WebX does **not** ship a fixed set of extensions.

2.1 A **launch catalogue** of curated extensions exists so that a new user has good choices
immediately, organised by category. It is a starting point, not a boundary.

2.2 Any participant MAY propose a new extension at any time through the process in section 4.
There is no cap on the number of extensions, and no scarcity is manufactured.

2.3 An implementation MUST NOT hard-code the extension list. The set of valid extensions is
**derived from the registry log**, exactly like every other piece of state, so a client that has
replicated the log knows every extension without an update, an announcement, or a configuration
file.

2.4 A client MUST NOT treat any extension as more legitimate than another. There is no premium
tier, no reserved class sold at a higher price, and no "real" extension. Constitution Article 35
requires TLD equality and this is its operational form.

## 3. Why breadth is safe here and costly on the clearnet

Broad namespaces have a bad reputation, earned honestly: ICANN's gTLD expansion produced a
**defensive registration tax**, where a brand felt obliged to register its name across hundreds of
extensions to stop somebody else passing off as them. More extensions meant more cost for the
same protection.

Four properties change that arithmetic on WebX, and they are design decisions rather than luck:

**3.1 Cost scales with breadth, for the squatter.** Registration requires memory-hard
proof-of-work. Taking one label across 500 extensions costs 500 times the work, and renewal
requires fresh work every year. A squatter's cost grows linearly with the namespace; a legitimate
holder wanting one name pays once.

**3.2 There is no resale market to profit from.** Constitution Article 33 imposes a settlement
delay on transfers and explicitly refuses to provide secondary-market infrastructure. The
squatter's business model on the clearnet is resale; here there is no exchange, no auction, no
escrow and no price discovery. Names are for use.

**3.3 There is no advertising or search economy to capture.** Clearnet squatting monetises
through parked-page advertising and search traffic. WebX has neither.

**3.4 Identity is a key, not a string.** This is the deepest one. On the clearnet, controlling
`brand.example` largely *is* controlling the identity. On WebX, a name resolves to a record signed
by a specific keypair, and clients follow keys. A squatter holding a lookalike label cannot
produce a signature from the key readers already follow.

Clients SHOULD make this visible: an interface that shows a reader "this is the key you followed
before" defeats lookalike labels more effectively than any registration policy, and it costs
nothing to implement.

**3.5 The honest residual.** None of this eliminates squatting or confusion. A determined actor
with hardware will take labels, and a reader who has never seen a publisher before cannot tell a
lookalike from the original. Section 3.4 protects returning readers, not first-time ones.
Constitution Article 36 refuses to make the registry a trademark court and that refusal stands —
WebX declines to adjudicate rather than pretending it has solved the problem.

## 4. Creating an extension

4.1 A new extension requires a ratified Naming-category WXIP, per Constitution Article 35.6 and
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

5.1 An extension MUST be **at least three characters**. Every ISO 3166 country code is two
letters, so a three-character floor keeps WebX clear of the entire ccTLD space at no meaningful
cost.

5.2 An extension MUST NOT duplicate a well-known ICANN generic top-level domain.

Both rules are about the reader, not about law. WebX has no obligation to ICANN and ICANN has no
jurisdiction here — but a `webx://example.com` that is unrelated to `https://example.com` teaches
readers that WebX names cannot be trusted to mean anything, which is a self-inflicted wound. A
parallel web should be recognisably parallel, not a confusing echo.

5.3 Country names, government identifiers and the names of living public figures MUST NOT be
created as extensions. WebX cannot adjudicate who represents a nation, and creating a namespace
that implies it can is an invitation to exactly the political pressure the project exists to
avoid.

5.4 Where an existing clearnet extension carries meaning worth preserving, the catalogue SHOULD
offer an unambiguous alternative that reads clearly rather than a near-clone.

## 6. Retirement

Retiring an extension is harder than creating one, deliberately. Per [NAMES.md](NAMES.md), it
requires a ratified WXIP and a minimum 24-month sunset with mandatory alias records, so that
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
- [The WebX Constitution](../../constitution/CONSTITUTION.md) — Articles 33, 35, 36
