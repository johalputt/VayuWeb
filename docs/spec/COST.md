# WebX Cost Model

What WebX costs, who pays it, and why there is no money anywhere in the protocol.

**Status:** Draft against the pre-implementation design. Figures are engineering estimates from
stated parameters, not measurements — nothing has been built or benchmarked.

## 0. The design rule

> **No money in the protocol. Cost is paid in the resources people already own.**

Constitution Article 7 forbids a token, a treasury and a protocol fee; Article 9 entrenches the
prohibition against amendment. This is usually read as a governance decision, and it is — but it
is also the single largest cost decision in the system.

Every payment rail a protocol adds brings with it an accounting layer, a settlement mechanism, a
price oracle, a fee market, a dispute path, and a class of participants whose interest is the
price rather than the protocol. Each of those is engineering that has to be built, secured and
maintained forever, and every one of them ends up billed back to the user.

WebX removes them by never having them. Cost lands where the resource is: CPU at registration,
disk and bandwidth at hosting. Neither is invoiced, because there is nobody to invoice.

## 1. The comparison

A modest personal or small-organisation site, run properly, for one year.

| | Clearnet | WebX |
|---|---|---|
| Name | 10–15/yr, renewable, revocable by the registrar | Seconds of CPU |
| Hosting | 60–300/yr for a VPS or managed host | Own disk, or a peer's |
| TLS certificate | Free to issue; an operational burden and a recurring outage source | Do not exist |
| Content network | Free tier to 240+/yr | Peers serve peers |
| DNS | Bundled or 5–60/yr | Does not exist; resolution is local |
| **Money per year** | **~75–200, indefinitely** | **Zero, at every step** |
| **Renewal risk** | Lapse, chargeback, or registrar policy loses the name | Renewal is a signature plus fresh proof-of-work |

The claim is narrow and worth stating precisely: **WebX costs no money.** It does not cost no
resources. Section 5 is the honest counterpart.

## 2. Registration cost

Registration and renewal require memory-hard proof-of-work — Argon2id, RFC 9106, version 0x13,
`m=65536` (64 MiB), `t=2`, `p=1`. See [PROOF-OF-WORK.md](PROOF-OF-WORK.md).

The design target is **seconds of CPU for one name, superlinear growth for ten thousand**. It
exists to price bulk squatting, not to raise revenue: nobody collects the work, and there is
nothing to collect.

Two consequences for cheapness:

2.1 **A registration must be affordable on the worst device a real user has.** A memory-hard
function at 64 MiB is demanding on a phone, both for RAM and for battery. The difficulty function
MUST therefore be calibrated against low-end mobile hardware rather than a developer's laptop,
and the client MUST show progress and remain responsive. A registration flow that appears to hang
is a registration flow that gets abandoned.

2.2 **Renewal is annual and cheap by construction.** Fresh work is required, which gives hoarding
an ongoing cost while a single name costs one person seconds once a year.

## 3. Storage cost

The largest real resource cost in the system, and the one with the most engineering leverage.

### 3.1 Erasure coding instead of replication

Naive redundancy is full replication: three copies for durability means **3× the storage** of the
original. Erasure coding achieves comparable or better durability at a fraction of that.

A design study for WebX recommends **Reed–Solomon RS(k=16, n=27)** over GF(2⁸), applied per
stripe of the site's content DAG. Any 16 of the 27 shards reconstruct the data.

```text
Full replication (3 copies):   3.00× storage overhead
RS(16, 27) erasure coding:     1.69× storage overhead   (27 ÷ 16)
```

**That is a 44% reduction in the storage the network must carry** for equal-or-better durability,
and storage is the cost that recurs forever. It is the single biggest cheapness lever available,
and it is why erasure coding is specified rather than left as an optimisation.

### 3.2 Deduplication is automatic

Content addressing means identical bytes have identical CIDs. Two sites sharing a library, a
font, or an image store and transfer it once across the entire network, with no coordination and
no configuration. On the clearnet, the same file behind a thousand domains is stored a thousand
times and paid for a thousand times.

### 3.3 Redundancy is earned, not bought

Peers hold each other's content reciprocally — capacity for capacity, in the tradition of
BitTorrent's choking algorithm and Tahoe-LAFS. No payment rail, no accounting, no settlement.
A participant contributing storage receives storage.

This keeps the system free at the point of use, and it is honest about what it cannot do: a
publisher who contributes nothing and knows nobody has no claim on anyone's disk. See section 5.

## 4. Resolution costs nothing, and buys privacy for free

WebX resolves a name against the **local** registry replica. No peer is contacted, so no peer
learns what was looked up.

This deserves to be a stated guarantee rather than an implementation detail, because it is
simultaneously the cheapest and the strongest privacy property in the system:

- A clearnet DNS lookup tells a resolver operator every name you visit. That is the basis of an
  entire data industry.
- A Tor onion lookup still reveals the blinded descriptor identifier to a hidden-service
  directory node.
- A WebX lookup reveals nothing to anybody, because it never leaves the machine.

It costs one local index read, and it requires no anonymity network, no relays, no cover traffic
and no latency budget. **The cheapest privacy in the design is the privacy that comes from not
sending the query.**

The limit is honest and worth recording now: this holds while the registry replica fits on the
reader's device. At roughly 300 bytes per record, one million names is about 300 MB plus index —
comfortable. Ten million is about 3 GB — not comfortable on a phone. Beyond that a light client
must ask somebody, and keeping *that* query private needs Private Information Retrieval, which is
a future WXIP and not a launch commitment.

## 5. What is not free

Required by Constitution Article 21.

**Someone's disk and bandwidth.** "No money" is not "no resources". Content lives because a
participant chose to hold it. A publisher who contributes no capacity and has no reciprocal
relationships is relying on strangers' goodwill, and goodwill is not a durability guarantee.

**The erasure-coding arithmetic assumes a population that does not yet exist.** RS(16, 27) needs
27 independent nodes willing to hold shards in the relevant neighbourhood. At launch there will
not be 27 nodes. The durability figures are a property of the mature network, and quoting them
for the early network would be dishonest.

**Registration is cheap, not free.** Seconds of CPU and 64 MiB of RAM is a real cost on a low-end
phone, and a real battery cost.

**Your own time.** Publishing requires understanding a folder, a key and a name. The
[publishing specification](PUBLISHING.md) exists to keep that to minutes, but it is not zero.

**Bandwidth is asymmetric.** Serving popular content costs the server-side peer more than the
reader. A publisher whose site becomes popular carries that cost, or relies on others choosing
to.

## 6. Why cheap follows from the constitutional prohibitions

Worth making explicit, because the prohibitions read as ideology and are also engineering:

| Prohibition | Cost it removes |
|---|---|
| No token | No exchange, no price, no fee market, no speculative overhead, no securities exposure |
| No treasury | No accounting, no custody, no audit, no governance-of-money |
| No protocol fee | No metering, no billing, no settlement, no disputes |
| No privileged party | No rent extraction at a chokepoint |
| No certificates | No issuance, no renewal, no expiry outage, no CA relationship |
| No server | No compute cost, no patching, no dependency treadmill |

A system with no money in it cannot develop a fee. That is the cheapness guarantee, and unlike a
pricing promise it cannot be revised by whoever is running things in ten years.

## 7. Conformance

1. No code path in any implementation accepts, records, transfers or requires a payment.
2. Registration completes within the stated target on a defined low-end mobile reference device.
3. The client reports the actual storage overhead of a published site, so a publisher can see the
   coding cost rather than infer it.
4. Name resolution issues zero network requests when the local replica holds the name — asserted
   on the observed socket set, per [CONTENT-SECURITY.md](CONTENT-SECURITY.md) test 3.
5. The client reports the current replication factor of anything the user has published, so
   "someone is holding it" is a fact on screen rather than an assumption.

## See also

- [Position](../POSITION.md) — the four commitments, of which this is one
- [Proof-of-work](PROOF-OF-WORK.md) — the registration cost, specified
- [Hosting](HOSTING.md) — where the bytes live
- [Publishing](PUBLISHING.md) — the time cost, minimised
- [The WebX Constitution](../../constitution/CONSTITUTION.md) — Articles 7, 9, 21
