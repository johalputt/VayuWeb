# VayuWeb Replication Protocol

How many machines reach one registry state without a coordinator, an operator, or a party whose
withdrawal stops any of it.

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119, under the usage discipline of Constitution Article 3.

**Status:** Draft — not yet deployed. The protocol state machine is implemented in
`registry/src/replicate.ts` and exercised against paired in-memory peers; no transport binding has
been run against real peers, and this document says so wherever it matters.

## 1. What replication is, and what it is not

1.1 Each peer keeps **its own** append-only log. There is no shared log, no primary, and no
canonical ordering of the network's records. A peer replicates another peer's log by index
because that log is single-writer and therefore totally ordered *by its own author* — and for no
other reason.

1.2 **Merging is set-based.** A peer's registry state MUST be a function of the *set* of valid
records it holds, and MUST NOT depend on which peer supplied a record, in what order it arrived,
or at what index it sat in anyone's log. This is the property Article 30.3 claims and the reason
[REGISTRY.md](REGISTRY.md) has no ordering rule: a state that depends on delivery order is a
state whoever controls delivery can choose.

1.3 Replication therefore transports records. It decides nothing. Every record is verified
locally, by the same `verify()` a locally created record passes, against the receiving peer's own
clock and its own view of prior state. **A peer never accepts a record because a peer it trusts
sent it, because there is no such peer.**

1.4 What this protocol deliberately does not have: a membership list, a peer reputation score, a
vote, a leader, a quorum, a total order, and any notion of a peer being authoritative for
anything. Article 3.12 forbids inferring such powers from silence; they are absent by
construction rather than by omission.

## 2. Transport binding

2.1 The protocol runs over any channel providing **ordered, reliable, framed, bidirectional**
delivery of octet strings. It does not require confidentiality, authentication of the remote
party, or a stable peer identity.

2.2 The reference binding is Hyperswarm over HyperDHT, discovering peers on the topic
`BLAKE2b-256("VayuWeb-Replication-v1")`. **This binding is not normative.** Article 4 forbids any
function of the protocol requiring a single party's availability, and a protocol defined in terms
of one discovery network would make that network's operators load-bearing. An implementation MAY
use any transport, including a local socket, a serial line, or a courier carrying a file.

2.3 An implementation MUST NOT treat the transport's authentication, if any, as evidence about a
record. A record's authority is its signature; nothing about the channel adds to it, and an
implementation that skips verification for a "known" peer has removed the only check there is.

2.4 Because 2.3 holds, a hostile peer's maximum achievable effect is to waste the receiver's
bandwidth and CPU within the limits of section 5. Every limit in section 5 exists for that
reason and MUST be enforced.

## 3. Messages

3.1 Every message is a deterministic CBOR map per [REGISTRY.md](REGISTRY.md), carrying a text key
`t` naming its type. A message whose encoding is not the canonical encoding of its own content
MUST be rejected — the same non-malleability rule records are held to, for the same reason.

3.2 A receiver MUST reject an unknown `t` by ignoring the message. It MUST NOT close the
connection for that reason alone: refusing to speak to a peer that knows a message you do not is
how a protocol becomes unextendable.

| `t` | Direction | Payload |
|---|---|---|
| `HELLO` | both, first | `v` uint protocol version · `len` uint log length · `root` bstr(32) tree root at `len` |
| `WANT` | either | `from` uint first index · `count` uint how many |
| `RECORDS` | reply to `WANT` | `from` uint index of the first · `recs` array of bstr, each a framed record encoding |
| `CHECKPOINT` | either | `len` · `treeRoot` bstr(32) · `indexRoot` bstr(32) · `liveNames` uint |
| `EQUIVOCATION` | either | `a` bstr · `b` bstr — two record encodings |

3.3 `HELLO` MUST be the first message a peer sends and MUST be sent exactly once. A second
`HELLO` on one connection MUST be rejected: a peer that may restate its length can rewind its own
history mid-session and invite a receiver to reconcile against a moving target.

3.4 A peer MUST NOT send `WANT` before receiving the remote `HELLO`. There is nothing to want
until the remote states what it has.

## 4. The exchange

4.1 On connection, both peers send `HELLO`. The exchange is symmetric — there is no client and no
server, and an implementation that assigns those roles has created an asymmetry the design does
not have.

4.2 A peer that has fewer than `len` records of the remote's log MAY send `WANT` for any
sub-range it lacks. Ranges MAY be requested in any order and MAY be interleaved with other
messages.

4.3 A peer receiving `WANT` SHOULD reply with `RECORDS` covering as much of the requested range
as it holds and as section 5's limits permit. It MAY reply with fewer records than requested, and
MAY decline entirely. **Declining is not an error condition** and MUST NOT be reported as one:
serving is voluntary, no peer owes another bandwidth, and Article 28 states duties without a
custodian precisely so that no participant can be said to have failed one.

4.3.a A responder **MUST** truncate a `RECORDS` reply to fit the message bound in section 5,
counting bytes rather than records, and MUST NOT emit a message it cannot encode.

This is stated because leaving it implicit produced a defect in this project's own
implementation, on the commonest request in the protocol. `RECORDS.recs` and `WANT.count` are both
256, which reads as a matched pair, and a responder that gathers 256 records has built a reply of
roughly a megabyte against a 65,536-byte bound. A peer starting from nothing asks for exactly 256,
so the failure was on the first message of every cold sync — and because a sender's own encoder
refuses it at the last step, the error looked like a broken connection rather than a bug.

An honest reply is therefore **routinely split**, for a reason the requester cannot predict: the
split falls on a byte total the requester has not seen. A requester MUST NOT treat a short reply as
evidence of anything, and in particular MUST NOT infer that the responder holds no more — 4.2's
"fewer than requested" is the normal case at scale, not the exception.

4.3.b **A requester MUST bound how long a `WANT` stays outstanding** and MUST reclaim the slot
when that bound elapses, whether or not a reply ever arrives.

This clause exists because the three rules around it are each correct and combine into a free
stall. Section 5 bounds in-flight requests at eight, so memory is bounded. 4.3 makes declining
both legal and *silent*, deliberately — serving is voluntary and Article 28 states duties without
a custodian precisely so nobody can be said to have failed one. And nothing required a requester
ever to give up. A peer that greets and then answers nothing therefore takes all eight slots and
keeps them for the life of the connection, while breaking no rule at all: from the outside it is
indistinguishable from a slow honest peer, which is what makes it cheap to do and hard to see.

The absence of a duty on one side has to be paid for by a bound on the other. The length of the
bound is the requester's to choose; having one is not. Reclaiming a slot is a local decision to
stop waiting — it records nothing about the peer and accuses nobody, which 4.5 requires.

Note also that a reply cannot be matched to the `WANT` that prompted it: no message in section 3
carries a request identifier. A requester therefore releases the **oldest** outstanding slot on a
reply, because the oldest is the most likely to have been abandoned.

That choice does not make the budget exact, and the imprecision is worth stating rather than
implying. If a request's deadline elapses and its reply then arrives, one slot has already been
reclaimed by the deadline and a second is reclaimed by the reply, so a requester may briefly hold
one more request in flight than section 5 allows. No ordering rule fixes this; only a request
identifier would, and the wire format has none. The excess is bounded by the number of late
replies — each costs the responder a message — and it does not accumulate, because the deadline is
re-evaluated on every request. An implementation MAY carry a request identifier as a private
extension; it MUST NOT require one of a peer.

4.4 On receiving `RECORDS`, a peer MUST, for each record independently:

```text
for each encoding in msg.recs:
    if len(encoding) > 4096:              drop it, count it, continue
    rec = parse(encoding)                  // NON_CANONICAL rejects here
    if parse failed:                       drop it, count it, continue
    verdict = verify(rec, encoding, local_state, local_clock)
    if verdict is accept:                  merge(rec)
    if verdict is defer (CLOCK_SKEW):      hold, retry after the skew window
    if verdict is reject:                  drop it, count it, continue
```

4.5 A failure anywhere in 4.4 MUST NOT abort processing of the remaining records in the message.
A single malformed record in a batch of two hundred is an attacker's cheapest denial of service
if it discards the other hundred and ninety-nine.

4.6 A record the peer already holds MUST be dropped silently. It is not an error, not a conflict,
and not evidence of anything.

4.7 A record that conflicts with one already held is resolved by `resolveConflict` in
[REGISTRY.md](REGISTRY.md)'s convergence rule. The result MUST NOT depend on which record arrived
first. A conforming implementation can be tested for this directly, and section 8 says how.

## 5. Limits

Every limit below MUST be enforced. They exist because section 2.4 leaves resource exhaustion as
the only attack a hostile peer retains, and an unbounded field is an invitation.

| Quantity | Limit | Why this number |
|---|---|---|
| Message encoding | 65,536 bytes | Holds **fifteen** maximum-size records, or roughly 190 at the median size in `conformance/vectors.json`. This bound, not `RECORDS.recs`, is what limits a reply's volume. |
| `WANT.count` | 256 | Bounds the work one message can ask for. A syncing peer sends many `WANT`s rather than one large one. |
| `RECORDS.recs` length | 256 | Matches `WANT.count`. It bounds array iteration, not volume — see 4.3a. |
| Each record encoding | 4,096 bytes | The record limit from REGISTRY.md, restated so a receiver checks it before parsing rather than after. |
| Outstanding `WANT`s per connection | 8 | Bounds memory held for in-flight requests. Reclaimed on a deadline as well as by a reply — see 4.3.b. |
| Deferred (`CLOCK_SKEW`) records held | 1,024 **distinct** | Bounded because a deferred record is memory an attacker can allocate by dating records into the near future. Deduplicated by record hash, then oldest evicted first — see 5.4. |

5.4 A bound on the number of held entries bounds **capacity** only if the entries are distinct.
The deferral queue MUST therefore be deduplicated by record hash.

Counting encodings rather than distinct records left one postdated record, resent 1,024 times,
filling the entire queue with copies of itself and evicting every genuine deferral from the front.
The attacker spends one record it already holds; the peer loses clock-skew tolerance for every
other peer it is talking to. 4.6's silent-drop rule does not reach this — that rule covers records
a peer "already holds", and a deferred record is precisely one that is not held.

The bound was doing exactly what it said, and protecting nothing.

5.1 A peer MUST NOT allocate memory proportional to a value a remote peer asserted. In particular
`HELLO.len` is a claim, not a measurement: a peer claiming a length of 2^53 MUST cost the
receiver nothing beyond the message itself. Allocate for what has arrived, never for what was
announced.

5.2 A peer exceeding a limit MAY be disconnected. A peer that merely sends nothing useful MUST
NOT be — there is no liveness obligation anywhere in this protocol, and inventing one creates a
duty that can be failed and therefore enforced.

## 6. Equivocation

6.1 Equivocation is one owner key signing two different records at the same `seq` for one
`name.tld`. It is distinct from an honest partition conflict, which is two *different* owners
racing for a free name.

6.2 The evidence is **self-contained and third-party verifiable**: the two record encodings, and
nothing else. Any recipient can check both signatures, both `seq` values, both names and that the
owner keys are equal, without trusting the sender, holding any prior state, or being online at
the time. This is what makes `EQUIVOCATION` worth forwarding — a report that must be believed is
a report that can be faked.

6.2.1 **Both signatures MUST be checked, and a peer MUST discard a report where either record is
not attributable to the `ownerKey` it names.** An owner key is public — it appears in every record
its holder ever published — so a pair checked for everything except who signed it can be minted by
anyone against anyone. This is not a hypothetical reading of 6.2: an implementation that omitted
the check recorded and forwarded such pairs, which is 6.4's manufactured evidence arriving by the
front door.

6.2.2 Which signature attributes a record depends on its operation, and both are recoverable from
the bytes:

| Operation | The named owner's signature |
| --- | --- |
| `REGISTER`, `UPDATE`, `RENEW`, `RELINQUISH`, `REVOKE` | `sig`, which verifies under `ownerKey` |
| `TRANSFER` | `coSig`. `sig` is the *transferor's*, and the transferor's key is not in these bytes at all |

6.2.3 Attribution is by `ownerKey`, and one case therefore falls outside it: a transferor signing
two different `TRANSFER` records of one name at one `seq` to two *different* recipients is not
reported, because the two records name different owners. Detecting it needs the transferor's key,
which is not in the evidence; evidence that needs outside state is evidence that can be faked by
whoever supplies the state. This is a stated limit, not an oversight.

6.2.4 A peer MUST NOT require either record to be *acceptable*. Expiry, proof of work, chain
position and lifecycle state are reasons a record would be refused, and requiring them would let
an equivocator escape the record by breaking their own proof of work in both halves. A signature
is different in kind from those: it is what makes a record attributable, and equivocation is a
claim about who signed.

6.3 A peer detecting equivocation MUST record it and SHOULD forward the evidence. A peer
receiving `EQUIVOCATION` MUST verify it independently before recording or forwarding it, and MUST
discard a report whose two records do not in fact equivocate.

6.4 **This protocol does not punish equivocation.** There is no penalty, no exclusion, no
blacklist and no loss of the name. Article 25 refuses adjudication, Article 11 makes a name
unrevocable save by mechanical lapse, and a mechanism able to strip a name on evidence is a
mechanism able to strip a name on *manufactured* evidence. Detection produces a legible record,
which Article 38 asks for; what a reader does with it is not the protocol's business.

6.5 The honest limit: equivocation by an owner against their own name harms mainly that owner.
The case that matters is a compromised key, and this protocol does not distinguish the two,
because nothing on the wire can.

## 7. Snapshots and light clients

7.1 A peer MAY serve `CHECKPOINT` for any log length that is a multiple of `CHECKPOINT_INTERVAL`.
A checkpoint commits to the log's merkle tree root and to the index root over live names, so a
light client can verify a single name's inclusion without replaying history.

7.2 A light client's answer carries `freshnessUnproven: true` and MUST continue to. A checkpoint
proves that a name was in a log of a stated length; it does **not** prove that no longer log
exists. Corroboration across peers raises confidence and never becomes proof, because a client
cannot distinguish "no peer has a longer log" from "no peer told me about one".

7.3 A client comparing two checkpoints at the same length that differ has detected a fork and
MUST surface it. It MUST NOT pick one.

## 8. Conformance

An implementation is conformant when, against the published vectors:

8.1 **Order independence.** For every permutation of a record set, the resulting registry state is
byte-identical. Testable exhaustively for small sets and by seeded shuffling above that.

8.2 **Partition convergence.** Two peers fed disjoint record sets, then allowed to exchange,
reach identical state — and identical conflict outcomes, including which chains are void.

8.3 **Nothing is trusted on receipt.** A peer that sends records failing local verification
changes no state. Testable by feeding every rejection vector in the conformance suite over the
wire and asserting the state is unchanged.

8.4 **Limits hold.** A peer asserting an enormous `HELLO.len`, requesting an oversized `WANT`,
or sending an oversized batch is refused without proportional allocation.

8.5 **Equivocation is detected and provable.** A third party given only the two encodings reaches
the same verdict as the detector. Pinned by the `equivocation` suite in
[`conformance/vectors.json`](../../conformance/vectors.json), which carries both answers rather
than only the refusals — an implementation that never reports anything passes a suite made
entirely of forgeries, and under-reporting here is silent.

8.6 **Forged evidence is refused.** Two records naming a key as `ownerKey` that the holder of that
key never signed are not equivocation, and a peer given the pair records nothing and forwards
nothing. Testable without a network: the pair is a vector.

## See also

- [Registry](REGISTRY.md) — the record format, verification and the convergence rule
- [Namespace Annex](NAMESPACE-CATALOGUE.md) — the ratified extensions a received record is checked against
- [Threat model](../THREAT-MODEL.md) — T6 and T6a, the conflict and delivery-order vectors
- [Roadmap](../ROADMAP.md) — Phase 2, and what remains untestable without peers
