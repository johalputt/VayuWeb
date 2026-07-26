# WebX Governance

How WebX is actually governed, in practical terms.

This document is a guide, not the law. Where it and the
[Constitution](../constitution/CONSTITUTION.md) differ, the Constitution governs and this
file is wrong and should be fixed.

**Status:** Draft against the pre-implementation design. The governance instruments described
here are in force from the moment the repository publishes them; the protocol they govern has
not been built yet.

## The three instruments

WebX is governed by three things and nothing else.

**The Constitution** says what the project is, what every participant is owed, and what can
never be changed no matter how many people want to change it. It is the only instrument with
entrenched clauses. It is deliberately hard to amend and deliberately easy to copy: its text
is in the public domain so that any fork carries it away intact.

**The WXIP process** ([WXIP-0000](spec/WXIP-0000.md)) is how everything else changes. A new
extension, a wire-format change, a difficulty parameter, a policy — all of it moves through a
numbered proposal with an author, a rationale, a mandatory security and privacy section, a
recorded objection set, and a permanent archive.

**The maintainers** execute. They merge, tag, publish and keep the lights on. They do not
decide what is correct — the WXIP process does that, and the Constitution bounds it. A
maintainer who overrules a settled WXIP is not exercising authority, they are exceeding it.

## How a decision is actually made

1. Someone writes a WXIP. Anyone may; there is no membership to obtain first.
2. It gets a number and enters Draft. Nothing is gatekept at this stage except spam.
3. Review happens in public and is archived, including the objections — especially the
   objections that were overruled. A decision whose dissent is unrecorded cannot be audited
   later, and auditability is the whole point.
4. An editor calls rough consensus, or calls that it has not been reached.
5. A Standards Track proposal needs a working reference implementation before it can be Final.
   Running code settles arguments that prose cannot.

## Rough consensus, precisely

Rough consensus is not a vote and not unanimity. It is the judgement that every sustained
technical objection has been *answered on its merits* — accepted and incorporated, or rejected
with a stated reason that survives scrutiny.

What does not count as consensus:

- A head count. Fifty people agreeing does not answer one correct objection.
- Volume. Repeating a point does not strengthen it, and a swarm of accounts is not a
  community.
- Seniority. "I have been here longer" is not an argument.
- Silence. Absence of objection from people who never read the proposal is not agreement.

What does not count as an objection worth blocking on:

- A preference stated without a consequence. "I would have done it differently" is noted, not
  binding.
- A concern already answered, repeated verbatim.
- An objection to the outcome rather than the reasoning, once the reasoning has been tested.

An editor who calls consensus writes down *why*. That written call is itself reviewable, and
being wrong about it is a reason to remove an editor.

## Roles

**Contributors** write proposals, reviews, attacks and code. No status required.

**WXIP editors** judge process, never merit. They check that a proposal is complete, correctly
formatted, has its mandatory sections, and has genuinely had its objections answered. An editor
MUST NOT reject a proposal because they disagree with it. That separation is what stops the
process from becoming a taste filter.

**Maintainers** hold merge and release authority for the reference implementation. Plural,
always: a single maintainer is a single point of legal and personal failure, and the
Constitution treats one-key control as a defect to be repaired rather than a state to be
tolerated.

**Everyone else who runs a node** is the actual ratifying body. Governance in a peer-to-peer
system is ultimately descriptive: the network runs whatever its peers choose to run. Formal
process exists to make that choice informed and coordinated, not to override it.

## Ratifying a new extension

New top-level extensions are the most capturable surface in the system — a namespace is worth
money, and whoever controls its creation controls a rent. So the process is deliberately slow
and the criteria are deliberately narrow. See [spec/NAMES.md](spec/NAMES.md) for the mechanics,
and the Constitution for the ratification threshold and the entrenched limits on it.

Retiring an extension is harder than creating one, and correctly so. People will have built
identities on it. The sunset requirements exist so that a retirement cannot strand holders.

## What is deliberately absent

Most governance failures in this space were not accidents of process. They were the predictable
consequence of a structure that had something worth capturing. WebX removes those structures
rather than promising to guard them:

- **No treasury.** There is no pot of money, so there is nothing to fight over, embezzle,
  freeze, tax, or subpoena. It also means nobody gets paid, which is a real cost, stated
  honestly.
- **No token.** No token means no speculators with an interest in governance outcomes, no
  securities exposure, and no voting power for sale.
- **No foundation with a board.** A legal entity is an address, a jurisdiction, and a list of
  people who can be compelled. Where a legal entity later proves genuinely necessary, the
  Constitution constrains what it may hold — never the registry, never the keys.
- **No privileged root.** No default pinning service, no blessed bootstrap node, no fallback
  resolver. Every one of those is a convenience that becomes a chokepoint in about five years.
- **No paid seats, no sponsorship tiers with influence.** Money may fund work. It may not buy
  a decision.

## When governance fails

It will, at some point, and a charter that does not plan for its own failure is decoration.

**Deadlock.** A proposal that cannot reach consensus does not advance. That is a legitimate
outcome, not a bug — the status quo wins ties, because changing a naming system is more
dangerous than not changing it.

**Absent maintainers.** The Constitution defines what happens when maintainers stop appearing:
how vacancy is established, how the project is revived, and how a dormant project is declared
dormant rather than quietly rotting behind a repository that still looks alive.

**Capture attempt.** If the process itself is captured — editors installed, objections
suppressed, an amendment used to remove the guarantees it was written to protect — the remedy
is not an appeal to the captured body. It is the fork.

## The right to fork

The right to fork the protocol, the registry state, the specifications and the charter is the
last check that survives when every other one has failed. It is written into the Constitution
as a right rather than tolerated as a threat, and the practical conditions that make it real
are treated as obligations: a permissive licence on the code, a public-domain charter, an
independently reproducible registry state, and specifications complete enough that a second
implementation can be written from them without asking anyone's permission.

A governance system that can be exited is a governance system that has to stay honest. That is
the entire mechanism, and it works precisely because nobody has to invoke it often.

## How to participate

Read the [Constitution](../constitution/CONSTITUTION.md). Read
[WXIP-0000](spec/WXIP-0000.md). Then attack the design — see
[CONTRIBUTING.md](../CONTRIBUTING.md) for what is most useful right now, which at this stage is
adversarial review rather than code.

## See also

- [The WebX Constitution](../constitution/CONSTITUTION.md)
- [WXIP-0000: the improvement proposal process](spec/WXIP-0000.md)
- [Naming and TLD policy](spec/NAMES.md)
- [Threat model](THREAT-MODEL.md)
