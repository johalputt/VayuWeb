# Contributing to WebX

WebX is at the specification stage. There is no implementation yet, which changes what a
useful contribution looks like.

**Right now, adversarial review is worth more than code.** Finding the clause in the
[Constitution](constitution/CONSTITUTION.md) that a determined bad actor could drive a truck
through, or the step in the [resolution spec](docs/spec/RESOLUTION.md) that leaks a lookup to
a clearnet resolver, is the highest-value thing anyone can do to this project today. Once code
exists, those mistakes cost a hundred times more to fix.

## Where to start

1. Read the [Constitution](constitution/CONSTITUTION.md). It governs everything else, including
   this file.
2. Read [WXIP-0000](docs/spec/WXIP-0000.md). It defines how changes are proposed and accepted.
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
[WXIP](docs/spec/WXIP-0000.md). The process exists so that a decision has an author, a
rationale, a recorded objection set, and a permanent archive. Skipping it makes the project's
history unauditable, which is the failure mode WebX exists to fix.

Every WXIP MUST include a Security and Privacy Considerations section, and it MUST NOT say
"none". If a change genuinely has no security consequence, explain why — that explanation is
the reviewable artefact.

## Pull request expectations

- One logical change per pull request. A branch that fixes a typo and redefines the grace
  period is two pull requests.
- Explain the *why* in the description. The diff already shows the *what*.
- Link the WXIP if one applies.
- Documents must pass the markdown lint that runs in CI. Fenced blocks need a language tag,
  files start with a single H1, and a wrapped line must never begin with `*` or `+` — a linter
  reads that as a list bullet.
- If your change makes the system sound better than it is, it will be sent back. Accuracy about
  limits is a hard requirement, not a stylistic preference.

## Commit and review conventions

- Commit messages: a short imperative subject line, then a body explaining the reasoning when
  it is not obvious. Reference the WXIP number where one exists.
- Review is on the merits. A sustained technical objection must be answered on its substance;
  it can be overruled, but it cannot be ignored, and the answer goes in the archive.
- Volume is not consensus. Neither is seniority.

## Security issues

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md), which is deliberately
short and is enforced against behaviour, not opinions.

## Licensing of contributions

By contributing code you agree it is released under the [MIT Licence](LICENSE). By contributing
text to the Constitution you agree it is dedicated to the public domain under CC0, so that any
fork can carry it.

## A note on where this lives

Long-term development moves to **Radicle**. GitHub is a temporary public mirror, kept because
it is where people currently are — which is precisely the dependency WebX exists to end. When
the migration happens it will be announced in this repository, and the GitHub mirror will stay
readable.
