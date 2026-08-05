# VayuWeb Naming and TLD Policy

This document is the normative specification for VayuWeb names: what a label may
contain, which labels are withheld, how a registration moves through its
lifecycle, how ownership is handed between keys, which top-level domains exist
at launch, and how a TLD is created or retired. It is a design document. No part
of the system described here has been implemented, and no VayuWeb name has ever
been registered.

Record format, signature rules and log semantics are specified in
[REGISTRY.md](./REGISTRY.md); the cost function in
[PROOF-OF-WORK.md](./PROOF-OF-WORK.md); resolver behaviour in
[RESOLUTION.md](./RESOLUTION.md). This document does not restate them.

## Scope and conformance

The key words MUST, MUST NOT, SHALL, SHOULD, SHOULD NOT and MAY are to be
interpreted as described in RFC 2119.

A VayuWeb name is a single label joined to a single top-level domain by a full
stop: `label.tld`. VayuWeb has no subdomains at the protocol layer in v1. The
registry indexes exactly one label per TLD and nothing beneath it, because
subdomain delegation would require either a second namespace layer inside each
record or a per-name delegation log, and neither has a ratified design.

## Label grammar

A label is 1 to 63 characters drawn from `a-z`, `0-9` and `-`. It MUST NOT begin
or end with `-`, and MUST NOT carry `-` at both position 3 and position 4. It is
stored NFC-normalised, lowercase, and ASCII-only.

```abnf
name        = label "." tld

label       = alnum                        ; 1 character
            / alnum alnum                  ; 2 characters
            / alnum body alnum             ; 3 to 63 characters

body        = *61ldh

ldh         = alnum / "-"
alnum       = %x61-7A / %x30-39            ; "a"-"z" / "0"-"9"

tld         = %x61-7A *11( %x61-7A / %x30-39 ) ; letter, then letters/digits
```

Three constraints are normative but are not expressed in the ABNF above, because
encoding them there would obscure more than it clarifies:

1. For any label of 4 or more characters, characters 3 and 4 MUST NOT both be
   `-`. This reserves the `xx--` shape, which is how internationalised labels
   are signalled in the wider naming world, so that a future IDN VWIP can adopt
   a prefixed encoding without colliding with names already registered.
2. The submitted label MUST already be NFC-normalised, lowercase ASCII. A peer
   MUST reject a non-conforming label rather than silently canonicalising it, so
   that the byte sequence a user signs is exactly the one the log stores.
3. The label MUST NOT be a reserved label for that TLD (see below).

Peers and resolvers MUST perform the same validation. A resolver that receives a
syntactically invalid name MUST fail locally and MUST NOT put the query on the
wire.

## Reserved labels

The following labels are withheld in every TLD. A registration operation naming
one of them is invalid and MUST be rejected by every peer, not merely ignored;
an invalid operation never becomes an ownership fact.

| Reserved | Reason |
| --- | --- |
| All 36 single-character labels (`a`-`z`, `0`-`9`) | Only 36 exist per TLD and their value is set by scarcity, not by use. First-come allocation turns a governance question into a race. Held pending an allocation VWIP. |
| All 1,296 two-character labels | Scarcity, not sovereignty. Only 1,296 exist per TLD and their value comes from that scarcity rather than from use, so first-come allocation turns a governance question into a race. Held pending an allocation VWIP, on the same reasoning as single-character labels. The earlier rationale here — that they read as sovereign claims because they collide with ISO 3166 codes — is withdrawn: [NAMESPACE.md](NAMESPACE.md) section 5.3 establishes that a two-letter string is a string, and that a country *name* is the thing that constitutes a claim. |
| `www` | Universally read as a host prefix rather than a site. Registering it invites a name that resolves to something other than what a user typed. |
| `localhost` | Special-use in RFC 6761. A resolver MUST treat it as loopback and MUST NOT resolve it through VayuWeb. |
| `example`, `invalid`, `test` | RFC 2606 reserves these for documentation and testing. Documentation that uses a live name eventually points somewhere its author did not intend. |
| `vayu` | Protocol identity. It is withheld in every TLD, including `.vayu`, so that no holder can speak as the protocol. |
| `control`, `api`, `resolver`, `proxy`, `pac`, `wpad`, `_vayu` | These collide with the resolver's control surface on `127.0.0.1:7653` or with proxy auto-configuration conventions. `wpad` in particular is a long-standing proxy-hijack vector; a name that a browser might fetch as configuration MUST NOT be registrable by a stranger. |

Reserved labels are not permanently unregistrable. A VWIP MAY release a class of
them under an allocation policy, but until one is ratified the class stays
closed. Withholding is reversible; a bad allocation is not.

## Lifecycle

A registration term is 1 year, defined as exactly 31,536,000 seconds — a fixed
count of seconds rather than a calendar year, so that every peer computes the
same `notAfter` from the same `notBefore` without timezone or leap-second
disagreement.

```text
                +-----------------------------------------------+
                |                                               |
                v                                               |
   +--------+  register (PoW + sig)   +------------+            |
   |  FREE  | ----------------------> | REGISTERED |            |
   +--------+                         +------------+            |
        ^                                    |                  |
        |                       notAfter - 60 days              |
        |                                    v                  |
        |                             +------------+   renew    |
        |                             | RENEWABLE  | -----------+
        |                             +------------+  (PoW+sig)
        |                                    |
        |                            notAfter reached
        |                                    v
        |                             +------------+   renew
        |                             |   GRACE    | -----------+
        |                             | 30 days    |  owner only
        |                             +------------+
        |                                    |
        |                          grace expires unrenewed
        |                                    v
        |                             +------------+
        +---- 30 days elapsed ------- | QUARANTINE |
                                      | 30 days    |
                                      +------------+
                                             ^
                                             |
                                    release (signed by owner)
                                    from REGISTERED or RENEWABLE
```

State definitions:

- FREE — no unexpired record exists for the name. Any key MAY register it by
  appending a signed registration carrying a valid proof-of-work.
- REGISTERED — a valid record exists and `now < notAfter - 60 days`. Records MAY
  be updated and the name MAY be offered for transfer. Renewal is refused, since
  early renewal would let a well-funded holder buy a decade of term at today's
  difficulty.
- RENEWABLE — `notAfter - 60 days <= now < notAfter`. Renewal is accepted from
  the owner key and extends `notAfter` by one further term measured from the old
  `notAfter`, not from the renewal instant, so renewing early costs nothing and
  gains nothing. Sixty days is chosen to be longer than any plausible holiday,
  outage or hardware-key replacement.
- GRACE — `notAfter <= now < notAfter + 30 days`. Resolution MUST fail for the
  name during grace; a name that has expired is not a name that still works.
  Only the incumbent owner key MAY renew, and renewal restarts the term from the
  renewal instant. Thirty days exists because a lapse is usually an accident,
  and the failure mode of a short grace period is a hijacked identity.
- QUARANTINE — the 30 days following grace. Nobody, including the former owner,
  MAY register the name. Quarantine removes the value of watching the log for
  expiries and appending a registration in the same second grace ends; when
  nobody can win the race, there is no race to run.

A holder MAY end a registration early by appending a signed release. A released
name enters QUARANTINE for 30 days, not FREE, so that "release" cannot become a
tool for coordinated re-registration by a confederate.

Lifecycle timestamps are evaluated against the record's own `notBefore` and
`notAfter` as validated by [REGISTRY.md](./REGISTRY.md). Peers with badly skewed
clocks will disagree at the boundaries; that is an unavoidable limitation of a
system with no authoritative time source, and the registry specification bounds
it rather than eliminating it.

## Transfer

Transfer is a two-signature handover. It is never a single operation.

1. The current owner appends an `offer` operation naming the recipient's Ed25519
   public key. The offer carries its own expiry: exactly 14 days from the
   offer's `notBefore`.
2. The recipient appends an `accept` operation, signed by the offered key,
   referencing the offer by its hash. On acceptance, `ownerKey` becomes the
   recipient's key, `seq` increments, and `notAfter` is unchanged. A transfer
   is not a renewal and requires no proof-of-work; the anti-squatting cost is
   attached to acquiring term, not to moving an existing term between keys.

If the recipient never countersigns, the offer expires 14 days after it was
made and the name is unaffected — same owner, same records, same expiry. Nothing
is lost and nothing is stranded. Fourteen days is long enough for a recipient
whose key lives on a hardware token in another country, and short enough that a
forgotten offer is not a standing liability against the name.

Further rules:

- At most one offer MAY be open for a name at a time. A second offer from the
  owner supersedes and voids the first.
- The owner MAY append a `revoke` operation at any time before acceptance.
- An `accept` MUST be rejected if the name is in GRACE. A recipient should not
  inherit a name with days left on it; the owner renews first, then transfers.
- Records carry across unchanged; a recipient who wants different ones appends
  an update after acceptance.
- Transfer moves the name only. It does not move pinned content, and it does not
  move the IPNS key that publishes it. A recipient who does not also receive
  that material out of band gets a working name pointing at content only the
  previous owner can update. This is a real gap, and implementations SHOULD warn
  about it at transfer time.

## Launch TLDs

**1,270 extensions are ratified at launch**, and a verifier rejects any other. They are
enumerated in [NAMESPACE-CATALOGUE.md](NAMESPACE-CATALOGUE.md) — the **Namespace Annex**,
which Constitution Article 35.1 incorporates by reference. [REGISTRY.md](REGISTRY.md)
enforces membership of that Annex and nothing else.

This is the third answer this document has given, and the two before it were wrong in
opposite directions, so the history is worth a paragraph. An earlier revision called the
catalogue the launch set while the charter named eleven extensions and the verifier enforced
eleven — a hundredfold disagreement, in which an implementer reading one document built a
different namespace from one reading the other and each conformed to what they read. The
revision after that resolved it downward, demoting all 1,267 catalogue entries to candidates.
That was faithful to the charter as it then stood, and it was still the wrong resolution: the
eleven were an arbitrary starting list rather than a considered judgement about how large a
namespace should be, and honouring them cost 1,256 extensions.
[VWIP-0004](VWIP-0004.md) resolved it where a namespace decision belongs — by amending
Article 35.1 — and carries the collision review for every ratified entry.

**The Annex is closed and enumerated, and that is what makes it safe to be large.** A verifier
decides validity by membership, computed offline from the copy it holds (Article 2.31). It
never derives the set from the log, fetches it, or accepts a string on the strength of a
well-formed proof-of-work. Proof-of-work prices a *registration*; it has never created an
extension, and a revision of this paragraph once said it did.

**Growth after commencement is slow by construction.** A new extension comes into being only
through a ratified Naming-category VWIP carrying a collision review, a public objection window
of at least ninety days, and a dormancy of at least a hundred and eighty days between
ratification and availability, with the activation epoch published at least that far ahead so
advance knowledge confers no landrush advantage (Articles 35.6 and 35.7). Nothing shortens
that path, and unanimity least of all — the dormancy exists to deny a head start to exactly
the people who would be agreeing to waive it.

Creating a top-level domain on the clearnet cost USD 185,000 in the 2012 application round
plus roughly USD 25,000 a year, in a window that has opened about once a decade. Here it
costs a proposal and some CPU. That is the whole argument for breadth: where a design has no
scarcity to ration, rationing is not prudence, and a namespace restricted to eleven benefits
nobody except the holders of those eleven.

Each extension has its own reserved-label set (the common set above, plus anything
its charter adds) and its own proof-of-work difficulty curve, driven by its
registration rate over the trailing 30 days.

Eleven extensions are additionally named in the text of Article 35.1 itself, so that the
founding set survives loss of the Annex: `.vayu`, `.p2p`, `.free`, `.decent`, `.libre`,
`.sov`, `.dao`, `.indie`, `.open`, `.news` and `.blog`. **This confers no rank.** Article
35.1.c says so in terms and Article 35.2 requires it — no extension is founding, premium,
reserved or default, and a client that orders, promotes or suggests one over another on the
strength of that list has misread the Article.

The Annex describes what each extension is *for*. Those characterisations are descriptive,
not enforced. The registry answers whether a signature is valid and whether a name is free;
it does not audit whether a `.news` site publishes news. A TLD MAY adopt an enforced
eligibility rule through a VWIP, but none does at launch, and such a rule would have to
survive Article 25 — the protocol does not adjudicate merit or entitlement.

## Creating a TLD

A new TLD requires a ratified **Naming-category** VWIP (Article 35.6). The proposal MUST
specify the string, the character of the TLD, its additional reserved labels, its initial
proof-of-work parameters, and a collision review against existing VayuWeb TLDs and against
legacy DNS strings likely to confuse a user. It MUST carry a public objection window of not
less than ninety days, and not less than one hundred and eighty days of dormancy between
ratification and availability, with the activation epoch published at least that far ahead
(Article 35.7). The shortest possible path from Draft to a registrable extension is therefore
30 + 90 + 180 days, and nothing shortens it.

An earlier revision of this section specified ratification by **a two-thirds supermajority of
ballots cast over 30 days, with a quorum of 25 percent of eligible signing keys**. That was
wrong twice over and is recorded here rather than quietly deleted. It contradicted Article
43.1, under which consensus is the absence of unaddressed substantive technical objection and
is expressly *not* a head count, a majority or a vote — Article 43.5.4 lists "a vote count"
among the things that do not constitute consensus. And a quorum computed from "eligible
signing keys active in the trailing 90 days" is a franchise anyone can mint keys to enlarge,
which is the Sybil problem Article 40 addresses by refusing to count identities at all. There
is no ballot, no threshold and no quorum anywhere in VayuWeb naming.
[CONSTITUTION.md](../../constitution/CONSTITUTION.md) is the normative source and governs
where any restatement differs; the process itself is in [VWIP-0000](VWIP-0000.md) and, in
plain language, in [GOVERNANCE.md](../GOVERNANCE.md).

A limitation worth stating plainly: VayuWeb cannot prevent ICANN from later
delegating a string that VayuWeb already uses. The collision analysis reduces the
chance of user confusion at the moment of creation; it does not bind anyone
outside VayuWeb, and it never will.

## Retiring a TLD

**A TLD with live names cannot be retired.** Article 35.9 permits exactly one action against
it — **TLD-FREEZE**, under which no new registration is accepted while every existing name
continues to resolve, renew, transfer, delegate and publish indefinitely. Not for 24 months;
indefinitely. TLD-RETIRE becomes reachable only when no live names remain, or when every
remaining registrant has migrated **by their own signed action** under a published migration
path open for not less than five years (Article 35.10).

A previous revision of this section specified a 24-month sunset after which unclaimed names
were lost. It is recorded rather than deleted because it is instructive about how this kind of
defect gets written: every individual clause read as protective — a two-renewal window, a
reserved successor label, a free claim, a 12-month alias tail — and the aggregate was a
mechanism by which a name held by a key was taken from that key by the passage of time and a
ratified proposal. Article 11 makes a Name unrevocable save by neutral mechanical Lapse, and
Article 9.7 entrenches it. A sunset that expropriates an inattentive holder is a revocation
with a calendar in front of it.

Under the charter, then:

- On FREEZE, peers MUST immediately refuse new registrations in the frozen TLD, and MUST
  continue to accept renewals, transfers, delegations and updates from existing holders for as
  long as those holders keep renewing. There is no terminal date.
- A retirement VWIP MAY designate a successor TLD and MAY reserve the identical label under it
  for each existing `ownerKey`, claimable by a signed registration with no proof-of-work. The
  reservation MUST remain open for not less than five years, and it is an offer rather than a
  migration: no name is ever moved on a registrant's behalf.
- A renewal MUST NOT be conditioned on including an alias to the successor name. Requiring one
  makes continued tenure contingent on accepting a migration, which is a new condition imposed
  on a live TLD and is void under Article 35.9.
- The TLD becomes historic only once the log shows no live names under it. Resolvers SHOULD
  keep serving any aliases holders chose to publish, so links in the wild keep working.
- A holder who never migrates keeps their name. VayuWeb has no mechanism to act on an absent
  holder's behalf, and inventing one would mean someone other than the key holder controls the
  name — which is the thing this protocol exists to make impossible.

VayuWeb cannot compel third parties to update links that point at a frozen or historic TLD.
Voluntary aliases are mitigation, not a fix.

## Deferred: internationalised labels and homograph defence

Labels are ASCII-only at launch. Internationalised labels and any homograph
policy are explicitly out of scope for v1 and MUST be addressed by a future
VWIP.

The reasoning is that VayuWeb's dispute doctrine is first-valid-signature-wins and
the registry is not a court. Where an adjudicator exists, a homograph
registration is a reversible mistake; here it is permanent. Admitting
mixed-script labels before a confusable policy is ratified would create a class
of names that look identical to existing names, cannot be revoked, and cannot be
appealed. That is not a rough edge; it is an unrecoverable failure mode.

A future VWIP will need to settle, at minimum: which Unicode scripts are
admissible; whether mixed-script labels are permitted at all; a confusable
skeleton computation in the manner of Unicode Technical Standard 39, and whether
a colliding skeleton blocks registration or merely flags it; the exact Unicode
version pinned for normalisation, since a version bump can change what
normalises to what; and how resolvers display a non-ASCII name so that what a
user reads matches what was signed. Until those questions have ratified answers,
a non-ASCII label MUST be rejected at validation.

## Status

Status: Draft — not yet implemented. This document specifies intended behaviour
against the pre-implementation VayuWeb design; nothing described here is running.

## See also

- [REGISTRY.md](./REGISTRY.md)
- [PROOF-OF-WORK.md](./PROOF-OF-WORK.md)
- [RESOLUTION.md](./RESOLUTION.md)
- [CONSTITUTION.md](../../constitution/CONSTITUTION.md)
