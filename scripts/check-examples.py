#!/usr/bin/env python3
"""Worked examples in the specification set must parse, and must not model a misconfiguration.

An example is the part of a specification that gets copied. Nobody reimplements a paragraph of
prose from memory; they paste the JSON block and edit it. So an example that contradicts the
normative rule three paragraphs above it is worse than no example at all -- the rule is read once
and the block is copied verbatim, and the publisher's result comes from the block.

**PUBLISHING.md's own manifest example was one.** Section 2 shows a manifest declaring
`"fallback": "index.html"` and `"notFound": "404.html"` together. Section 2.3, immediately below
it, is the precedence: "On no path match the resolver SHALL serve `notFound` with HTTP 404 if
present; otherwise, if `fallback` is declared, serve it with HTTP 200 so the site's own router can
handle the path." `notFound` is present, so `fallback` is unreachable -- in the one manifest the
specification puts forward as canonical. A publisher with client-side routing who copies it gets
HTTP 404 on every deep link, which is exactly and only the failure section 2.3 exists to prevent.

Two checks, both cheap and both about drift the author cannot see by rereading:

1. Every fenced ```json block in the specification set parses as JSON. An example that is not
   valid JSON is a defect regardless of what it says.
2. Any block carrying site-manifest keys satisfies PUBLISHING.md 2.3's precedence: declaring both
   `notFound` and `fallback` leaves the second unreachable, so an example must not declare both.

Exit 0 clean, 1 with the offending file, block and reason.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

FENCE = re.compile(r"^```json\s*$(.*?)^```\s*$", re.MULTILINE | re.DOTALL)

# The keys that identify a block as a site manifest rather than some other JSON. `version` alone
# is far too common to key on; these three are the manifest's own vocabulary.
MANIFEST_KEYS = {"index", "fallback", "notFound"}


def blocks(path: Path):
    """Yield (line_number, text) for every fenced JSON block in a file."""
    text = path.read_text(encoding="utf-8")
    for match in FENCE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        yield line, match.group(1)


def problems() -> list[str]:
    found: list[str] = []
    for path in sorted(DOCS.rglob("*.md")):
        rel = path.relative_to(ROOT)
        for line, body in blocks(path):
            try:
                value = json.loads(body)
            except json.JSONDecodeError as error:
                found.append(f"{rel}:{line}: fenced json does not parse: {error}")
                continue
            if not isinstance(value, dict):
                continue
            if not MANIFEST_KEYS & set(value):
                continue
            if value.get("notFound") is not None and value.get("fallback") is not None:
                found.append(
                    f"{rel}:{line}: this manifest example declares both `notFound` "
                    f"({value['notFound']!r}) and `fallback` ({value['fallback']!r}). "
                    "PUBLISHING.md 2.3 serves `notFound` first, so the `fallback` a publisher "
                    "copying this block is relying on can never be reached, and every deep link "
                    "gets the 404 page. Show one or the other."
                )
    return found


def self_test() -> None:
    """Each case is something this checker has to get right to be worth running."""
    cases = [
        ({"index": "index.html", "notFound": "404.html", "fallback": "index.html"}, True),
        ({"index": "index.html", "notFound": "404.html"}, False),
        ({"index": "index.html", "fallback": "index.html"}, False),
        # An explicit null is a declaration of absence, not a declaration.
        ({"index": "index.html", "notFound": None, "fallback": "index.html"}, False),
        # Not a manifest at all: a record example that happens to carry a `version`.
        ({"version": 1, "seq": 3, "ownerKey": "ab"}, False),
    ]
    for value, expected in cases:
        both = (
            bool(MANIFEST_KEYS & set(value))
            and value.get("notFound") is not None
            and value.get("fallback") is not None
        )
        if both is not expected:
            raise SystemExit(f"self-test failed for {value}: expected {expected}, got {both}")
    print("self-test: 5 cases pass")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0
    found = problems()
    for problem in found:
        print(problem)
    if found:
        print(f"\n{len(found)} example(s) contradict the rule beside them")
        return 1
    print("examples: every fenced json parses, and no manifest example is unreachable-by-design")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
