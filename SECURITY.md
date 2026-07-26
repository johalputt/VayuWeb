# Security Policy

## Current status

WebX has **no implementation**. There is no released software, no running network, and no
deployed registry. Today the attack surface is the *design*: the
[Constitution](constitution/CONSTITUTION.md), the specifications in [docs/spec](docs/spec),
and the [Threat Model](docs/THREAT-MODEL.md).

A flaw in a specification is a real vulnerability. It is cheaper to fix now than at any later
point in this project's life, and it is treated with the same seriousness as a flaw in code.

## What counts as a security issue

Report privately if you find:

- A way to take, block or destroy a name that its holder controls.
- A way to make a resolver accept a record it should reject, or reject one it should accept.
- A path that leaks a WebX lookup to a clearnet DNS resolver, an analytics endpoint, or any
  third party.
- A deanonymisation path that the [Threat Model](docs/THREAT-MODEL.md) does not already
  acknowledge.
- A governance capture path — a sequence of legitimate-looking moves that ends with one party
  controlling the registry, the release keys, the name, or the amendment process.
- A break in the signing, canonical-serialisation, proof-of-work or convergence rules.
- Anything that would let a single party become a mandatory intermediary.

Report publicly (an ordinary issue is fine) for: documentation errors, broken links, unclear
wording, and design questions that are not exploitable.

## How to report

Email **security@webx.dev** with:

- What the flaw is, stated as an attack: who does what, in what order, to get what.
- Which document and which clause or section it applies to.
- The impact, and what it costs the attacker.
- A suggested fix if you have one. You are not obliged to have one.

If you prefer encrypted mail, say so in a first message with no details and a key will be
provided in reply. When a signing key is published for this project it will be listed in this
file and mirrored on Radicle, so that a compromised repository cannot silently swap it.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 72 hours |
| Initial assessment | 10 days |
| Fix or documented decision not to fix | 90 days |

If a report goes unacknowledged for 14 days, escalate by opening a public issue that says only
that an unacknowledged security report exists — no details. Silence is a failure mode this
project should not be allowed to hide.

## Disclosure

Coordinated disclosure, with a hard ceiling: **90 days** from acknowledgement, after which you
are free to publish regardless of the fix status. A permanent embargo is a way for a project to
avoid fixing things, and this one does not get that option.

Every accepted report is published after the embargo, including the ones that resulted in a
decision *not* to change anything, with the reasoning. The archive is the point.

## Credit

Reporters are credited by name or handle unless they ask not to be. There is no bounty
programme — there is no treasury, by design, and there will not be one. See the
[Constitution](constitution/CONSTITUTION.md) on why the absence of a pot of money is a feature.

## Scope

In scope: everything in this repository, and any successor mirror published under the project's
own keys.

Out of scope: GitHub itself, Radicle itself, IPFS, Hypercore, Hyperswarm and other upstream
dependencies — report those to their maintainers. If an upstream flaw has a WebX-specific
consequence, report that consequence here as well.
