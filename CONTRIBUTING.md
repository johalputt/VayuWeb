# Contributing to VayuWeb

VayuWeb is at the specification stage, and there is now a reference implementation of the parts
that can be built on one machine — the registry, replication, resolution, the browsing proxy and
the content encoders, in [`registry/src`](registry/src). No network is running and no phase past
0 is finished, which still changes what a useful contribution looks like.

**Adversarial review is worth more than code, and the implementation is the evidence.** Every
defect found in this project so far was a defect in a document before it was a defect in a
module, and most of them were found by holding two documents open at once. Finding the clause in
the [Constitution](constitution/CONSTITUTION.md) that a determined bad actor could drive a truck
through, or the step in the [resolution spec](docs/spec/RESOLUTION.md) that leaks a lookup to a
clearnet resolver, is still the highest-value thing anyone can do here.

**Any language.** The protocol fixes formats, not runtimes, and the conformance vectors are hex
and JSON so that they can be read from anything. Rust is a first-class choice and the expected one
for the desktop client, the resolver and the proof-of-work worker — see
[ARCHITECTURE.md](docs/ARCHITECTURE.md), "Implementation Language". A component in another
language passes the same suites or it is not the same component.

The second-highest thing you can do is run [`conformance/vectors.json`](conformance/vectors.json)
against your own code. It is readable without any of this repository, and a disagreement means one of three
things — a bug in yours, a bug in ours, or an ambiguity in the specification that let two people
read it differently. The third is the most valuable and the reason the file exists.

## Where to start

1. Read the [Constitution](constitution/CONSTITUTION.md). It governs everything else, including
   this file.
2. Read [VWIP-0000](docs/spec/VWIP-0000.md). It defines how changes are proposed and accepted.
3. Read the [Threat Model](docs/THREAT-MODEL.md) and try to add to it.

## What we want

- **Attacks on the design.** Concrete ones. "A Sybil swarm could do X, here is the sequence"
  beats "this seems centralised".
- **Attacks on the governance.** A capture path through the amendment rules, a quorum that
  fails when volunteers get bored, an entrenched clause that is not actually entrenched.
- **Specification defects.** Ambiguity, an undefined failure path, a missing test vector, a
  number that was chosen without justification.
- **Prior art we got wrong.** If a system already solved this and we reinvented it worse, say
  so and point at it.
- **Plain-language corrections.** If a document overclaims — on anonymity, availability,
  deletion, or censorship-resistance — that is a bug, and it is a serious one.

## What we do not want

- Token proposals, treasury proposals, or any mechanism that creates a pot of money.
  Article-level prohibitions in the Constitution rule these out; a proposal to add one is a
  proposal to amend the Constitution, and should be argued there rather than smuggled in as a
  feature.
- Adding a privileged party — a default pinning service, a blessed bootstrap node, a fallback
  resolver — as a convenience. Convenience is how a decentralised system acquires a centre.
- Reformatting sweeps, dependency churn, or "modernising" pull requests with no behavioural
  argument.

## How to propose a change

**Small corrections** — typos, broken links, a clarified sentence, an added test vector —
open a pull request directly.

**Anything that changes behaviour, wire format, policy or governance** — open a
[VWIP](docs/spec/VWIP-0000.md). The process exists so that a decision has an author, a
rationale, a recorded objection set, and a permanent archive. Skipping it makes the project's
history unauditable, which is the failure mode VayuWeb exists to fix.

Every VWIP MUST include a Security and Privacy Considerations section, and it MUST NOT say
"none". If a change genuinely has no security consequence, explain why — that explanation is
the reviewable artefact.

## Pull request expectations

- One logical change per pull request. A branch that fixes a typo and redefines the grace
  period is two pull requests.
- Explain the *why* in the description. The diff already shows the *what*.
- Link the VWIP if one applies.
- Documents must pass the markdown lint that runs in CI. Fenced blocks need a language tag,
  files start with a single H1, and a wrapped line must never begin with `*` or `+` — a linter
  reads that as a list bullet.
- If your change makes the system sound better than it is, it will be sent back. Accuracy about
  limits is a hard requirement, not a stylistic preference.

## Commit and review conventions

- Commit messages: a short imperative subject line, then a body explaining the reasoning when
  it is not obvious. Reference the VWIP number where one exists.
- Review is on the merits. A sustained technical objection must be answered on its substance;
  it can be overruled, but it cannot be ignored, and the answer goes in the archive.
- Volume is not consensus. Neither is seniority.

## Security issues

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md), which is deliberately
short and is enforced against behaviour, not opinions.

## Licensing of contributions

### Sign off every commit

Contributions are accepted under the **Developer Certificate of Origin 1.1**, the mechanism the
Linux kernel uses. Add a sign-off line to each commit:

```bash
git commit -s
```

which appends:

```text
Signed-off-by: Your Name <your@email>
```

By signing off you certify the statements in the [DCO](https://developercertificate.org/): that
you wrote the contribution or have the right to submit it, and that you understand it is public
and will be redistributed.

**There is no Contributor Licence Agreement, and there will never be one.** You keep the
copyright in your own work; it is not assigned to anyone.

What that forecloses is the commercial dual-licence business: only a party holding the copyright
can sell proprietary terms over a codebase, and every well-known conversion of a community
project into a paid product was built on rights a CLA had gathered first. That path is closed
here permanently, to the author as much as to anyone else.

What it does not do is freeze the outbound licence — MIT permits releasing a derivative work
under different terms, so a future version could carry a reciprocal licence without every
contributor's consent. The commitment, which is a promise rather than a legal constraint, is that
any such change would be forward-only, announced in advance, and put to contributors first. What
nobody can do, ever, is retract a grant already made: every published release stays under the
terms it shipped with. See [LICENSE](LICENSE) and [VWIP-0002](docs/spec/VWIP-0002.md).

### What licence your contribution carries

By contributing code you agree it is released under the [MIT Licence](LICENSE). By contributing
text to the Constitution you agree it is dedicated to the public domain under CC0, so that any
fork can carry it.

## A note on where this lives

Long-term development moves to **Radicle**. GitHub is a temporary public mirror, kept because
it is where people currently are — which is precisely the dependency VayuWeb exists to end. When
the migration happens it will be announced in this repository, and the GitHub mirror will stay
readable.
