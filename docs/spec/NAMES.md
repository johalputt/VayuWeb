# WebX Naming and TLD Policy

This document is the normative specification for WebX names: what a label may
contain, which labels are withheld, how a registration moves through its
lifecycle, how ownership is handed between keys, which top-level domains exist
at launch, and how a TLD is created or retired. It is a design document. No part
of the system described here has been implemented, and no WebX name has ever
been registered.

Record format, signature rules and log semantics are specified in
[REGISTRY.md](./REGISTRY.md); the cost function in
[PROOF-OF-WORK.md](./PROOF-OF-WORK.md); resolver behaviour in
[RESOLUTION.md](./RESOLUTION.md). This document does not restate them.

## Scope and conformance

The key words MUST, MUST NOT, SHALL, SHOULD, SHOULD NOT and MAY are to be
interpreted as described in RFC 2119.

A WebX name is a single label joined to a single top-level domain by a full
stop: `label.tld`. WebX has no subdomains at the protocol layer in v1. The
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

tld         = 2*15( %x61-7A )              ; lowercase ASCII letters
```

Three constraints are normative but are not expressed in the ABNF above, because
encoding them there would obscure more than it clarifies:

1. For any label of 4 or more characters, characters 3 and 4 MUST NOT both be
   `-`. This reserves the `xx--` shape, which is how internationalised labels
   are signalled in the wider naming world, so that a future IDN WXIP can adopt
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
| All 36 single-character labels (`a`-`z`, `0`-`9`) | Only 36 exist per TLD and their value is set by scarcity, not by use. First-come allocation turns a governance question into a race. Held pending an allocation WXIP. |
| All 1,296 two-character labels | They collide with ISO 3166-1 alpha-2 country codes. A registry that cannot adjudicate disputes should not hand out strings that read as sovereign claims. |
| `www` | Universally read as a host prefix rather than a site. Registering it invites a name that resolves to something other than what a user typed. |
| `localhost` | Special-use in RFC 6761. A resolver MUST treat it as loopback and MUST NOT resolve it through WebX. |
| `example`, `invalid`, `test` | RFC 2606 reserves these for documentation and testing. Documentation that uses a live name eventually points somewhere its author did not intend. |
| `webx` | Protocol identity. It is withheld in every TLD, including `.webx`, so that no holder can speak as the protocol. |
| `control`, `api`, `resolver`, `proxy`, `pac`, `wpad`, `_webx` | These collide with the resolver's control surface on `127.0.0.1:7653` or with proxy auto-configuration conventions. `wpad` in particular is a long-standing proxy-hijack vector; a name that a browser might fetch as configuration MUST NOT be registrable by a stranger. |

Reserved labels are not permanently unregistrable. A WXIP MAY release a class of
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

**The launch catalogue holds 349 extensions across ten categories.** It is listed in
[NAMESPACE-CATALOGUE.md](NAMESPACE-CATALOGUE.md), and the reasoning behind a broad
namespace — why breadth is safe here and expensive on the clearnet — is in
[NAMESPACE.md](NAMESPACE.md).

The catalogue is a starting point, not a boundary. The namespace is **elastic**:
anyone may propose a new extension at any time, it costs proof-of-work rather than
a fee, and no implementation hard-codes the list. Creating a top-level domain on
the clearnet cost USD 185,000 in the 2012 application round plus roughly USD
25,000 a year; here it costs a ratified proposal and some CPU.

Each extension has its own reserved-label set (the common set above, plus anything
its charter adds) and its own proof-of-work difficulty curve, driven by its
registration rate over the trailing 30 days.

The twelve below are the protocol's founding extensions, described here because
they carry meaning specific to WebX itself. They hold no privileged status:
Constitution Article 35 requires every extension to be equal, and no client may
present one as more official than another.

- `.webx` — the protocol's own namespace; general-purpose, the default suggestion.
- `.vayu` — general-purpose, for projects in the Vayu ecosystem and its neighbours.
- `.p2p` — peer-to-peer software, protocols and node operators.
- `.free` — projects whose defining claim is that they cost nothing to use.
- `.decent` — decentralisation as subject matter: research, tooling, commentary.
- `.libre` — free-software projects and their documentation.
- `.sov` — self-sovereign identity, personal data stores, individual homesteads.
- `.dao` — collectively governed organisations and their public records.
- `.indie` — independent creators, small studios, one-person operations.
- `.open` — open data, open standards, open hardware.
- `.news` — reporting and current affairs.
- `.blog` — personal and topical writing.

These characterisations are descriptive, not enforced. The registry answers
whether a signature is valid and whether a name is free; it does not audit
whether a `.news` site publishes news. A TLD MAY adopt an enforced eligibility
rule through a WXIP, but none does at launch.

## Creating a TLD

A new TLD requires a ratified WXIP. The proposal MUST specify the string, the
character of the TLD, its additional reserved labels, its initial proof-of-work
parameters, and a collision analysis against existing WebX TLDs and against
currently delegated public DNS TLDs.

Ratification requires, over a 30-day voting period, at least a two-thirds
supermajority of ballots cast, with a quorum of ballots from at least 25 percent
of eligible signing keys — those active in the log during the trailing 90 days.
These figures are restated here for readability only:
[CONSTITUTION.md](../../constitution/CONSTITUTION.md) is the normative source
for eligibility, ballot format, quorum and threshold, and governs where the two
differ. The WXIP process itself is described in
[GOVERNANCE.md](../GOVERNANCE.md).

A limitation worth stating plainly: WebX cannot prevent ICANN from later
delegating a string that WebX already uses. The collision analysis reduces the
chance of user confusion at the moment of creation; it does not bind anyone
outside WebX, and it never will.

## Retiring a TLD

A TLD MAY be retired only by a ratified WXIP, and retirement MUST NOT strand its
holders. The minimum sunset is 24 months from ratification, chosen so that every
holder meets at least two renewal prompts inside the window; a single-cycle
sunset would silently drop anyone who renewed the week before the vote.

- At ratification, peers MUST immediately refuse new registrations in the
  retiring TLD.
- The retirement WXIP MUST designate a successor TLD. For every name live at
  ratification, the identical label in the successor TLD is reserved for that
  name's `ownerKey` for the full 24 months, claimable by a signed registration
  with no proof-of-work.
- Renewals in the retiring TLD MUST continue to be accepted for the whole
  sunset. Each renewal MUST include an `alias` record pointing at the successor
  name; a renewal without one is invalid. Resolvers MUST follow the alias.
- At month 24 the TLD becomes historic. Resolvers MUST keep serving the alias
  for a further 12 months so links in the wild keep working, after which the
  names enter QUARANTINE and then FREE.
- Holders who never claim their successor name lose it at month 24. WebX has no
  mechanism to act on an absent holder's behalf, and inventing one would mean
  someone other than the key holder controls the name.

WebX cannot compel third parties to update links that point at a retired TLD.
The 12-month alias tail is mitigation, not a fix.

## Deferred: internationalised labels and homograph defence

Labels are ASCII-only at launch. Internationalised labels and any homograph
policy are explicitly out of scope for v1 and MUST be addressed by a future
WXIP.

The reasoning is that WebX's dispute doctrine is first-valid-signature-wins and
the registry is not a court. Where an adjudicator exists, a homograph
registration is a reversible mistake; here it is permanent. Admitting
mixed-script labels before a confusable policy is ratified would create a class
of names that look identical to existing names, cannot be revoked, and cannot be
appealed. That is not a rough edge; it is an unrecoverable failure mode.

A future WXIP will need to settle, at minimum: which Unicode scripts are
admissible; whether mixed-script labels are permitted at all; a confusable
skeleton computation in the manner of Unicode Technical Standard 39, and whether
a colliding skeleton blocks registration or merely flags it; the exact Unicode
version pinned for normalisation, since a version bump can change what
normalises to what; and how resolvers display a non-ASCII name so that what a
user reads matches what was signed. Until those questions have ratified answers,
a non-ASCII label MUST be rejected at validation.

## Status

Status: Draft — not yet implemented. This document specifies intended behaviour
against the pre-implementation WebX design; nothing described here is running.

## See also

- [REGISTRY.md](./REGISTRY.md)
- [PROOF-OF-WORK.md](./PROOF-OF-WORK.md)
- [RESOLUTION.md](./RESOLUTION.md)
- [CONSTITUTION.md](../../constitution/CONSTITUTION.md)
