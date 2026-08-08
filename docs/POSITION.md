# What VayuWeb Is, and What It Is Not

VayuWeb is a **parallel web**. It runs alongside the clearnet, on the same machine, in the same
browser, addressed `vayu://` instead of `https://`. It is public. Sites are meant to be found,
linked, read and shared.

It is **not a hidden web**, not a dark web, and not an anonymity network. That is a deliberate
choice, not a shortfall, and this document exists so nobody has to infer it.

**Status:** Draft against the pre-implementation design.

## The one-sentence position

> VayuWeb is not a place to hide. It is a place with nobody to petition to take it away.

Everything below follows from that sentence.

The earlier wording promised that the place could never be taken from you, which Article 21.4.f
forbids in those or equivalent words. The correction is not cosmetic: what the design removes is the
*addressable party* — the registrar, the certificate authority, the host — so there is no longer
anyone a court order or a business decision can be served on. It does not remove a state's ability
to seize your device, compel your key, or block the network you reach peers over, and a reader who
sees only the pull-quote should not come away believing otherwise. Article 21.5 makes that reader
the test.

## What VayuWeb removes

Not visibility. **Chokepoints.**

The clearnet works fine until someone with leverage decides it should not work for you. Five
parties hold that leverage, and in practice a handful of organisations hold all five at once:

| Party | What they can do | Under VayuWeb |
|---|---|---|
| Registrar | Suspend or transfer your domain | Does not exist. Ownership is a keypair. |
| DNS resolver | Refuse to answer for your name | Does not exist. Resolution is local. |
| Certificate authority | Revoke your certificate | Does not exist. Integrity comes from the content hash. |
| Host | Delete your account and your files | Does not exist. Content is addressed, not located. |
| Content network | Decide your traffic is not worth carrying | Does not exist. Peers serve peers. |

Each row is a party that can be petitioned, pressured, subpoenaed or simply have a bad quarter.
VayuWeb does not negotiate with them or replace them with better-behaved versions. It removes the
position they occupy.

## What VayuWeb does not attempt

**Anonymity — not in v1, and deferred rather than refused.** VayuWeb does not hide who you are, where
you are, or what you are reading, from anyone watching your network connection.

This is a sequencing decision. Doing anonymity properly means onion routing or a mixnet, and that
means latency measured in seconds, a small anonymity set, and a system ordinary people find too
slow and too strange to use. A design study against VayuWeb concluded that even a well-built
composition would only *substantially reduce* exposure rather than remove it, because a global
passive adversary defeats every low-latency option — so paying the whole cost up front would buy
a partial property while making the system slower, more complex and harder to adopt.

The order is therefore: build the parallel web first, get it fast, cheap and widely used, and
revisit an optional anonymity layer once there is a population large enough for an anonymity set
to mean anything. A layer added later can be optional; a latency cost baked in at the start
cannot be removed. Until then, Tor does that job better than a new network could, and is the
right tool when hiding is what you need.

Being honest about this has three practical benefits, and they are worth stating:

1. **It keeps the system fast.** No cover traffic, no circuit building, no per-hop latency. VayuWeb
   can be as quick as fetching a file, because that is what it is.
2. **It keeps the system simple enough to be secure.** Anonymity systems are hard to get right
   and their failure modes are silent. Not having one removes an entire category of subtle bug.
3. **It keeps the system usable.** A protocol whose main property is "nobody can find you"
   attracts a narrow population and repels everyone else. VayuWeb is for people who want a website
   nobody can switch off — which is most people who publish anything.

**Untraceable publishing.** If you publish on VayuWeb under a name, that name is public and your
peers can see you serving it. This is a feature: a parallel web only works if things can be found.

**Immunity from law.** VayuWeb removes intermediaries, not jurisdictions. If someone can be
identified and compelled, they can be compelled.

## The four commitments

What VayuWeb does promise, and what the rest of the specification set is organised around.

### 1. Secure — by removing the attack surface, not by guarding it

The strongest security property here is structural: **there is no server.**

A VayuWeb site is a signed pointer to content-addressed bytes. Nothing executes on anyone else's
machine. That deletes, entirely rather than mitigates, the categories that account for most real
website compromises:

- No SQL injection, because there is no database behind the page.
- No remote code execution on the origin, because there is no origin process.
- No dependency CVE treadmill in a web stack, because there is no web stack running.
- No stolen hosting credentials, because there is no hosting account.
- No certificate mis-issuance or expiry outage, because there are no certificates.

What remains is the reader's browser, and that is hardened by the strict profile in
[spec/CONTENT-SECURITY.md](spec/CONTENT-SECURITY.md): deny-by-default, no inline execution, every
powerful browser feature denied, and the privileged control surface on a socket a browser cannot
address.

The integrity guarantee is stronger than TLS gives most sites. TLS tells you that you reached the
server that holds the certificate. VayuWeb tells you the bytes are **exactly** what the key holder
signed — verified against their hash on your own machine, with no third party trusted at any
point in the chain.

### 2. Future-proof — because nothing is named in the protocol

Covered in [spec/CRYPTO-AGILITY.md](spec/CRYPTO-AGILITY.md) and [LONGEVITY.md](LONGEVITY.md). No
primitive is hard-coded; only versioned suites are, carried in every signed record from record
zero. Suites move forward only, verifiers keep every historical suite forever, and migration runs
through a hybrid so it stays safe even if the target scheme is later broken.

The test a design must pass: a change of substrate, primitive, format or maintainer must be
possible **without invalidating a single existing name**.

### 3. Cheap — because there is nothing to bill for

| | Clearnet | VayuWeb |
|---|---|---|
| Name | Roughly 10–15 per year, renewable, revocable | A few seconds of CPU |
| Hosting | Roughly 60–300 per year for anything real | Your own disk, or a volunteer's |
| Certificate | Free to issue, but an operational burden and an outage source | None exist |
| Content network | Free tier to hundreds per year | Peers serve peers |
| **Total** | **~75–200 per year, forever, for a modest site** | **No money at any point** |

There is no token, no treasury and no protocol fee — Constitution Article 7 forbids all three and
Article 9 entrenches the prohibition. The only cost of registration is memory-hard proof-of-work,
which exists to price bulk squatting rather than to raise revenue, and which nobody collects.

The honest counterpart: cheap for the publisher does not mean free in aggregate. Someone's disk
and bandwidth carry the content, and if nobody chooses to, it goes away. See
[spec/HOSTING.md](spec/HOSTING.md).

### 4. Easy — or it does not count

A system only experts can operate has already centralised; it just has not admitted it yet. The
usability target is concrete and testable, and it is Phase 5's acceptance test in
[ROADMAP.md](ROADMAP.md): **someone who has never opened a terminal completes install, identity,
registration, publishing and viewing — unassisted, without reading the specifications.**

What that removes compared with running a clearnet site:

- No DNS records, nameservers, or propagation waits.
- No certificate issuance, renewal, or the outage when renewal fails.
- No server to patch, no operating system to keep current, no dependency upgrades.
- No hosting control panel, no billing, no account to lose.
- Publishing is: point the client at a folder.

The strict content-security profile is the main thing that makes authoring harder than it needs to
be, and that cost is paid at **publish time rather than read time** — see
[spec/PUBLISHING.md](spec/PUBLISHING.md), which specifies the checker that tells an author exactly
what will not render before they ship it.

## How this changes the limitations

VayuWeb previously listed "does not make you anonymous" among its limitations, alongside an
instruction to use Tor. That framing was wrong — not factually, but categorically. It presented a
deliberate non-goal as a shortfall.

The corrected list. What VayuWeb does not do **by design**:

- It does not hide you. It is a parallel web, not a hidden one.

What VayuWeb genuinely cannot do, and is working to reduce:

- **Availability is not guaranteed.** Content lives while a peer holds it. Erasure coding and
  assigned replication can turn this into durability arithmetic rather than a hope; it remains a
  probability, never a promise.
- **It cannot forget.** Payloads can be made unrecoverable, and the fact that something existed
  cannot. The claim narrows; it does not disappear.
- **A lost key loses a name** unless recovery was configured in advance. Announced, time-locked,
  vetoable guardian recovery removes this for anyone who prepares, and for nobody who does not.
- **It does not defeat network-layer blocking.** Nothing at this layer does.
- **It does not protect a compromised device.** Nothing anywhere does.

## See also

- [Whitepaper](WHITEPAPER.md) · [Architecture](ARCHITECTURE.md) · [Threat model](THREAT-MODEL.md)
- [Publishing and authoring](spec/PUBLISHING.md) — the "easy" commitment, specified
- [Content security](spec/CONTENT-SECURITY.md) — the "secure" commitment, specified
- [Crypto agility](spec/CRYPTO-AGILITY.md) and [Longevity](LONGEVITY.md) — the "future-proof" commitment
- [The VayuWeb Constitution](../constitution/CONSTITUTION.md)
