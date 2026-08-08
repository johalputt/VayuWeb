# VayuWeb Attestation Specification

How the holder of a clearnet domain, or of any other verifiable identity, proves the connection
to their VayuWeb name — mechanically, permissionlessly, and without any body deciding anything.

The key words MUST, MUST NOT, SHALL, SHALL NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

**Status:** Draft — not yet implemented.

## 1. The problem this solves, and the one it refuses

**The problem.** Somebody registers `nike.shop` on VayuWeb and passes themselves off as a shoe
company. A reader cannot tell. On the clearnet the answer was a sunrise period, a reserved-names
list, and a dispute panel — an apparatus that took ICANN two decades to build, made it a
political target, and still did not stop `nikeshoes.example` from being registered the next day.

**What VayuWeb refuses.** Constitution Article 30.2 forbids reservations, priority windows, waiting
lists and sunrise periods for every class of claimant, naming trademark holders explicitly.
Article 30.4 forbids withholding any name at genesis. Article 36.2 forbids operating or
cooperating with any dispute-resolution body, and Article 36.3 makes a proposal to create one
*inadmissible* rather than merely unpopular — an editor must refuse it at intake, and ratifying
it would be void under Article 9.

Those provisions are not an oversight to route around. They exist because every mechanism that
can take a name from its holder is a mechanism that can be pointed at anybody, and because
whoever staffs it becomes the chokepoint the entire project exists to remove.

**What this specification does instead.** It attacks the same problem from the other end. Rather
than restricting *who may hold a label*, it makes *identity provable* — so that holding the label
stops being worth much.

## 2. The inversion

A reserved-names list protects the names on the list. An attestation protects every name.

Consider a squatter who registers `nike.shop` before anyone else. Under this design they keep it,
exactly as Article 30 requires. What they cannot do is produce a signature from a key that
controls `nike.com`. The label is theirs and it is worthless for impersonation, because the
reader's client shows plainly that nothing vouches for it.

This is a better outcome than reservation on four counts:

1. **It is mechanical.** Verifying a DNS TXT record is a lookup, not a judgement. No panel, no
   evidence, no jurisdiction, nobody to subpoena or capture.
2. **It covers everything.** A list protects listed names. Attestation works for a corner shop,
   a pseudonymous writer and a multinational equally, without anyone applying.
3. **It survives the near-miss.** A reservation on `nike` does nothing about `nikeshoes` or
   `nike-official`. An attestation makes every unattested variant visibly unvouched.
4. **It removes the incentive rather than fighting it.** Squatting is profitable when a label
   confers identity. Here it does not.

## 3. Attestation records

An attestation is a **`records` entry** of type `attest` — not an operation — carrying a claim
that an external identity and this VayuWeb name are controlled by the same party. It is published
by an ordinary `UPDATE`. It confers **no allocation priority whatsoever**, and an implementation
MUST NOT treat it as conferring any.

**Neither layer carries it yet, and this document does not add it.** The distinction matters
because "registry record type" is the phrase Constitution Article 29.4 uses for *operations*, and
an earlier revision of this sentence used it here — leaving two readings, both unimplementable.
As an operation, `attest` is outside 29.4's closed set and outside `REGISTRY.md`'s six, so a
conformant peer rejects it `UNKNOWN_OP`. As an entry type it is outside `REGISTRY.md`'s five, and
that document's rule is explicit: "Unknown `type` values are stored and replicated unchanged but
MUST NOT be acted upon" — so an attestation would propagate and no resolver could display it,
which is the entire mechanism.

The entry reading is the intended one and is the cheaper of the two: it needs a row in
`REGISTRY.md`'s entry-type table and a validation rule, not a seventh operation. But this
document does not get to add either. `REGISTRY.md` owns the record schema, and a subordinate
specification describing a type the schema does not carry is how a type acquires an
implementation without ever being reviewed — the same defect withdrawn from `PUBLISHING.md`
(inline digests) and `LOCAL-SURFACE.md` (a cross-name allowance) this month. Adding `attest` is a
Standards Track VWIP against `REGISTRY.md`, and until one is ratified this specification is a
design, not a mechanism.

**Status is `Draft` for exactly this reason**, and the rest of this document should be read as
what the mechanism would be, not as what a peer does today.

```json
{
  "type": "attest",
  "method": "dns-txt",
  "subject": "example.com",
  "expires": 1801526400
}
```

### 3.1 Method: `dns-txt`

The holder publishes a TXT record at `_vayu.example.com`:

```text
_vayu.example.com.  IN  TXT  "vayu-attest=v1; key=<base64url ed25519 public key>; name=example.shop"
```

Verification, performed independently by any client:

1. Resolve `_vayu.<subject>` TXT.
2. Parse the `vayu-attest=v1` payload.
3. Check `key` equals the `ownerKey` of the VayuWeb record.
4. Check `name` equals the VayuWeb name being attested.

All four MUST pass. This is the same shape as the ACME DNS-01 challenge that issues most of the
web's certificates, for the same reason: control of the DNS zone is the strongest mechanical proof
of control of the domain, and it needs nobody's permission to perform.

### 3.2 Method: `https-well-known`

For a holder who controls the site but not the zone, a document at
`https://example.com/.well-known/vayu-attest.json` carrying the same fields. Weaker than
`dns-txt` — it proves control of a path rather than a zone — and clients MUST distinguish the two
in what they display.

### 3.3 Method: `vayu-cross`

One VayuWeb name attesting another under the same key, so an organisation can bind
`acme.shop`, `acme.dev` and `acme.zine` into one visible identity. This is the only method with
no external dependency, and it is the one that keeps working if the clearnet does not.

### 3.4 Multiple attestations

A name MAY carry several. Independent proofs compound: a name attested by a DNS zone, a published
site and three other VayuWeb names under one key is considerably harder to fake than any one of
them. Clients SHOULD show the count and the methods.

## 4. Verification rules

4.1 Verification MUST be performed by the reader's own client. A resolver MUST NOT accept another
party's assertion that an attestation is valid — that would recreate the authority this design
exists to avoid.

4.2 An attestation MUST be re-verified on a schedule, at most every 30 days, because domain
control changes hands. A stale one MUST be displayed as stale, never as valid.

4.3 Failure to verify MUST NOT affect resolution. The name still resolves, the content still
loads. Only the displayed identity signal changes. **An attestation is never a condition of
service** — otherwise DNS becomes load-bearing for VayuWeb, which is precisely the dependency the
protocol exists to remove.

4.4 In Private Mode, DNS-based verification is disabled by default, because performing it emits a
clearnet DNS query and section 4.3 means nothing is lost by skipping it. `vayu-cross` still works.

4.5 An attestation MUST be revocable by its holder at any time by a signed record, taking effect
immediately.

4.6 **Verification fetches are outbound connections, and are bound like every other one.** A
client performing `dns-txt` or `https-well-known` verification MUST route it through the single
guarded transport of [PRIVACY.md](PRIVACY.md) 3.1, and MUST refuse loopback, link-local,
multicast and RFC 1918 destinations **unconditionally** — exactly as
[LOCAL-SURFACE.md](LOCAL-SURFACE.md) 2.1.1 and 2.2 require of the resolver's other outbound verbs,
and for the reason stated there: forwarding to the reader's own network is an SSRF pivot whatever
the verb is.

`subject` MUST be a valid DNS name of at most 253 bytes with **no IP literal**, no port and no
userinfo, and it MUST be **validated before it is used to construct a URL**, dialled, or
displayed — section 5.2 renders it into the identity chrome, so the same value reaches a second
untrusted surface. **Redirects MUST NOT be followed.** The fetched document MUST be refused above
**8 KiB**, which is ample for four fields.

Without 4.6, `subject` was chosen by whoever registered the name and constrained nowhere. An
attacker registers any name, publishes `subject: "169.254.169.254"` with method
`https-well-known`, and every reader's client issues that request from inside the reader's own
network — on first view and again on 4.2's thirty-day re-verification schedule, without the reader
doing anything. The response never reaches the attacker, but section 5 makes displaying
attestation state mandatory, so success, failure and staleness become a rendered blind-SSRF
oracle over the reader's LAN, and an unbounded response body is a memory sink any host can fill.
4.4 disables only DNS verification in Private Mode, so the https path was live in both.

The rule this clause states was not a new idea. It was already written for the resolver's other
two outbound verbs and simply never extended to the third.

## 5. Display rules

What a client shows is where this design succeeds or fails, so the rules are normative.

5.1 A client MUST NOT display an attestation in a way that resembles a TLS padlock or implies a
certificate authority vouched for anything. Nobody vouched. A DNS record was checked.

5.2 The wording MUST name the proof, not assert a conclusion. "Attested by the holder of
nike.com, verified 2 days ago" is correct. "Verified business" and "Official" are not — those are
judgements, and VayuWeb makes none.

5.3 An unattested name MUST NOT be marked as suspicious, untrusted or dangerous. Most names will
never carry an attestation and there is nothing wrong with that; a pseudonymous writer has no
domain to prove. The absence of a signal is not a negative signal, and a client that renders it
as one has quietly created the second-class citizenship Article 35 forbids.

5.4 A client SHOULD show whether the reader has seen this key before. That signal is stronger
than any attestation for a returning reader, and it costs nothing.

## 6. What this does not do

Required by Constitution Article 21.

- **It does not reserve, withhold or grant any name.** Article 30 is untouched: first valid
  signature still wins, for everyone, including trademark holders.
- **It does not adjudicate a trademark.** It proves control of a DNS zone. Two parties who both
  hold a mark in different jurisdictions will both be able to attest, from their respective
  domains, and VayuWeb will show both without deciding between them. That is the correct outcome and
  it is deliberate.
- **It does not stop a lookalike label.** `nike-shoes.shop` remains registrable. It is visibly
  unattested, which is the whole mechanism, and a reader who does not look is not protected.
- **It does not protect a first-time reader who ignores the signal.** Section 5.4's returning-key
  signal is stronger, and neither helps somebody determined not to look.
- **It does not make DNS authoritative over VayuWeb.** An attestation is an optional annotation.
  Losing a clearnet domain later does not affect the VayuWeb name in any way.

## 7. Conformance

1. An attestation record has no effect on allocation; a name with one and a name without are
   registered on identical terms.
2. Verification runs in the reader's client; no external verification result is accepted.
3. A failed or expired attestation does not prevent resolution.
4. No client displays a padlock-equivalent or the words "official" or "verified business".
5. An unattested name carries no negative indicator.
6. Private Mode performs no DNS lookup for attestation by default.
7. Revocation takes effect on the next resolution.

## See also

- [Namespace](NAMESPACE.md) — why breadth does not create a defensive-registration tax
- [Registry](REGISTRY.md) — the record schema this would extend, and which does not yet carry `attest`
- [Naming and TLD policy](NAMES.md) — allocation, unchanged by this document
- [The VayuWeb Constitution](../../constitution/CONSTITUTION.md) — Articles 21, 30, 35, 36
