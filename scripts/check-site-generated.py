#!/usr/bin/env python3
"""The published site's generated files must still match what they were generated from.

`site/` is a landing page, and three of the things on it are not written by hand:
the brand mark, the namespace, and the list of claims the charter forbids. Each
is produced from the repository's own source of truth by a tool under
`site/tools/`, and each of those tools takes `--check`.

WHY THIS IS A GATE rather than a convention. A generated file that has drifted
looks exactly like one that has not — it is checked in, it renders, and the page
is fine. What has gone wrong is only visible by comparison:

  * `assets/brand.css` carries the mark's bytes. Replace the artwork and the site
    keeps serving the old spider until somebody remembers this step.
  * `assets/namespace.js` carries the namespace. The Annex is NORMATIVE — Article
    35.1 incorporates it, the enumeration is closed, and Article 2.31 requires a
    Node to decide validity offline from the copy it holds. A stale copy on the
    project's own front page is a second, divergent namespace published with the
    project's authority.
  * `assets/claims.js` carries Article 21.4. It is the one file exempt from
    `check-absolute-claims.py`, because it has to be able to quote what it
    forbids. An exempt file that has stopped matching its source is the worst
    case of the three: the exemption stays, and the words it protects are no
    longer the charter's.

    python3 scripts/check-site-generated.py

Exits non-zero listing every generated file that no longer matches its source.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TOOLS = [
    ("site/tools/embed-mark.py", "the brand mark in assets/brand.css and the favicon"),
    ("site/tools/embed-namespace.py", "the namespace in assets/namespace.js"),
    ("site/tools/embed-claims.py", "Article 21.4's claims in assets/claims.js"),
]


def main():
    stale = []
    for tool, what in TOOLS:
        path = os.path.join(ROOT, tool)
        if not os.path.exists(path):
            stale.append((tool, f"{tool} is missing, so nothing regenerates {what}"))
            continue
        done = subprocess.run(
            [sys.executable, path, "--check"], cwd=ROOT,
            capture_output=True, text=True, check=False)
        report = (done.stdout + done.stderr).strip().splitlines()
        print(f"  {tool}: {report[-1] if report else 'no output'}")
        if done.returncode != 0:
            stale.append((tool, f"{what} is stale — run `python3 {tool}`"))

    if stale:
        print(f"\n{len(stale)} generated file(s) no longer match their source:\n", file=sys.stderr)
        for tool, why in stale:
            print(f"  {why}", file=sys.stderr)
        return 1
    print("\nOK — every generated file on the site matches what it was generated from.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
