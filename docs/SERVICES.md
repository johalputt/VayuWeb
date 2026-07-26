# Services on VayuWeb

How anyone — including the project's founder — can build a business on VayuWeb without capturing it,
and how VayuPress, VayuMail and VayuTalk fit on top of a name you own.

**Status:** Draft against the pre-implementation design.

## 1. The line

The Constitution forbids a token, a treasury and a protocol fee (Article 7), and entrenches all
three against amendment (Article 9). That is not a prohibition on making money. It is a
prohibition on making money *from the protocol layer*, and the distinction is precise enough to
build on:

| Not allowed | Allowed |
|---|---|
| Charging to register a name | Charging to register it **for** someone |
| A fee that reaches the protocol | A fee for a service the protocol does not require |
| A party whose non-payment loses you your name | A party whose non-payment loses you a convenience |
| An exclusive or default provider | One of many providers, swappable, none default |

**The test is one question: if this business shut down tomorrow, would anybody lose a name?** If
yes, it is a chokepoint and it is forbidden. If they lose only convenience, it is a service and it
is fine.

This is the arrangement that Linux, nginx, PostgreSQL and Let's Encrypt all operate under. The
thing itself is free and nobody can gate it; businesses form around the work of making it easy.

## 2. What a service may sell

Every item here is something a user could do themselves for free, sold because doing it yourself
takes time, hardware or attention.

**2.1 Registration as a service.** Run the proof-of-work on the customer's behalf, on hardware
better than their phone, and hand them a name. The keypair MUST be generated on the customer's
device and MUST NOT be transmitted, so the service never holds the thing that controls the name.
Where a customer asks for custody, it MUST be optional, disclosed plainly, and exportable at any
moment.

**2.2 Pinning and availability.** The largest honest value on offer. A publisher's site is
reachable only while somebody holds it, and most people's laptops are closed most of the time. A
pinning service keeps content available continuously.

It MUST be swappable — content addressed by CID can be served by anyone, so switching providers is
copying bytes, not migrating an account. A pinning service that makes its customers hard to leave
has stopped being a service.

**2.3 Publishing and authoring.** A dashboard, an editor, template hosting, build tooling,
analytics the customer owns.

**2.4 Support, backup and recovery guardianship.** Acting as one of the guardians in a
holder-configured recovery set — as one of several, never as a majority, and never able to move a
name alone.

**2.5 Managed identity for organisations.** Key hygiene, rotation schedules, succession
configuration, staff onboarding.

## 3. What a service may never do

3.1 It MUST NOT be required to use VayuWeb. Every function above MUST remain achievable by a person
with the free client and no account.

3.2 It MUST NOT hold a name such that non-payment loses it. A lapsed subscription may stop the
pinning; it MUST NOT stop the name resolving, and it MUST NOT transfer ownership.

3.3 It MUST NOT be a default in any client. Constitution Article 4's no-chokepoint invariant means
no provider ships pre-selected, however convenient.

3.4 It MUST NOT be exclusive, and MUST NOT hold data in a form that cannot be exported.

3.5 It MUST NOT gate an extension. Nobody sells access to a namespace; extensions are created by
ratified proposal and are equal (Article 35).

## 4. Why this earns more than selling names would

Worth stating, because giving up the name revenue looks like giving up the business:

**A name sold for a dollar is a dollar, once a year, for something the buyer knows costs nothing
to produce.** It invites exactly one competitive response — somebody offering it for free — and
they will win, because the protocol lets them.

**Availability is a recurring cost that never goes away.** Storage and bandwidth are real, they
scale with the customer's success, and a customer whose site is up is a customer who stays.
Nobody can undercut that to zero, because it is not zero.

And the constitutional guarantee is itself a sales argument: a customer can be told, truthfully,
that **nothing you buy here can be taken away by us.** Their name works whether they pay or not.
Very few infrastructure businesses can say that, and the ones that can do not lose customers to
the fear of lock-in.

## 5. The Vayu suite on VayuWeb

The clearest demonstration of what a name you own is actually for.

On the clearnet, a person publishing under their own name needs four relationships: a registrar
for the domain, a host for the site, a mail provider for the mailbox, and a chat account
elsewhere. Four bills, four accounts, four parties who can each end it, and an identity assembled
from things other people control.

On VayuWeb it is **one key and one name**:

| | Product | What it gives the name |
|---|---|---|
| Site | **VayuPress** | Publishes to `vayu://you.vayu` — content-addressed, signed, no server to run |
| Mail | **VayuMail** | `hi@you.vayu`, keyed to the same identity |
| Chat | **VayuTalk** | Messaging bound to the same keypair, no separate account |

One registration. One recovery configuration. One thing to lose or keep.

### 5.1 Rules for the integration

5.1.1 Each product MUST work with a VayuWeb name **and** without one. Neither may become a
requirement for the other, or the suite becomes the chokepoint.

5.1.2 The VayuWeb name MUST remain fully usable with none of these products installed. A name is not
a Vayu account.

5.1.3 Any Vayu-specific record type MUST be specified publicly and implementable by anyone. A
private extension to the record schema would make one vendor's software necessary, which
Article 4 forbids.

5.1.4 Mail and messaging carry the hardest problem here and it MUST NOT be glossed over.
Content-addressed publishing is one-to-many and works naturally; **mail and chat are
one-to-one, require the recipient to be reachable, and involve metadata that a public log must
never carry.** Neither product may put addressing or delivery metadata into the registry. That
design is not settled and MUST NOT be presented as though it is.

5.1.5 The suite MUST NOT be pre-selected in the VayuWeb client, and the client MUST work fully
without it.

## 6. Conformance

1. No protocol code path accepts, records or requires a payment (per [spec/COST.md](spec/COST.md)).
2. Every service function is achievable with the free client and no account.
3. Cancelling any service leaves the customer's name resolving and owned.
4. No provider is pre-selected in any client.
5. Customer data and pinned content are exportable in a form another provider can accept.
6. Keypairs are generated on the customer's device; custody is opt-in and exportable.
7. Each Vayu product runs without a VayuWeb name, and a VayuWeb name runs without any Vayu product.

## See also

- [Position](POSITION.md) — the four commitments
- [Cost model](spec/COST.md) — why the protocol is free
- [Namespace](spec/NAMESPACE.md) — why extensions are not sold
- [The VayuWeb Constitution](../constitution/CONSTITUTION.md) — Articles 4, 7, 9, 35
