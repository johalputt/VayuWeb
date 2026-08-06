# scripts/ — build and project tooling

Tooling that supports the repository itself rather than the protocol.

| Script | Purpose |
|---|---|
| `build-assets.py` | Regenerates every file in `assets/` from the source artwork: trims the canvas, converts the white background to transparency, produces light and dark ink variants, and thickens hairlines for favicon sizes so the mark stays legible at 32px. |
| `build-catalogue.py` | Regenerates the Namespace Annex from `catalogue-sources/`. |
| `generate-namespace.py` | Generates `registry/src/namespace.generated.ts` from the Annex; `--check` verifies the committed file matches. |

## The checkers

Nine, all standard-library Python and all run by CI. `check-workflows.py` fails if any of them is
not invoked by a workflow, because a checker nothing runs is a file that looks like a gate and is
not one.

| Script | What it refuses |
|---|---|
| `check-charter-consistency.py` | The charter disagreeing with itself or with a specification, in three shapes: **quantities** (one number stated several ways), **terms** (one word defined as two kinds of thing) and **memberships** (a name one clause excludes while another depends on it). It never decides — both sides are Articles, so Article 58 reserves the choice to an amendment — it refuses to let a conflict be closed by editing one side. |
| `check-counts.py` | A number in prose that disagrees with the source defining it, and **paired statements**: a rule settled in one document and left standing in its sibling. |
| `check-deadcode.py` | An export nothing imports or exercises. |
| `check-headers.py` | A quoted header block that has drifted from `CONTENT-SECURITY.md`. |
| `check-links.py` | A relative link that does not resolve. |
| `check-listeners.py` | The control API on TCP, and the superseded loopback port outside a file that records its history. |
| `check-source-hygiene.py` | Type-system escape hatches, ambient nondeterminism, focused tests, suite-1 primitive sizes outside their suite module — and **required call sites**, for rules nothing else can hold. |
| `check-vwips.py` | A VWIP beyond Draft missing a section `VWIP-0000` makes mandatory for its type. The list is read from that document's own table, never restated. |
| `check-workflows.py` | A workflow without a permissions block, an unpinned third-party action, an expression in `cancel-in-progress`, and any checker CI does not run. |

Most of these exist because the thing they refuse already happened once. The cross-document ones
exist because that class of defect has no other way of being caught: fourteen of the eighteen
HIGH findings in `docs/AUDIT-FINDINGS.md` were invisible to reading any single document.

## Regenerating the brand assets

```bash
pip install Pillow numpy
python3 scripts/build-assets.py assets/
```

**The wordmark artwork still spells the project's former name.** The spider mark contains no
text and carries over unchanged, so it is the only lockup used in the README and on the website;
the wordmark and full-lockup outputs are generated but not yet published anywhere. Redrawing the
wordmark is an open task, and until it is done the name is set as live type rather than as an
image.

The source artwork (`assets/vayuweb-logo-source.jpg` and `assets/vayuweb-logo-alt-source.png`) is
the original design and is kept in the repository so every derived asset can be rebuilt from
it rather than edited by hand.
