#!/usr/bin/env python3
"""Verify that every relative link in the repository resolves to a file that exists.

A broken cross-reference in a specification is a real defect: it sends an implementer to a
document that does not say what they were told it says, or to nothing at all. This runs in CI
and exits non-zero on the first repository that cannot be navigated.

    python3 scripts/check-links.py [root]

External links (http, https, mailto and friends) are not fetched -- this is an offline,
deterministic check. Pure anchors (#section) are skipped; a link with an anchor is validated
on its path component only.
"""
import os
import re
import sys
from urllib.parse import unquote, urlparse

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", ".venv", "venv"}

# [text](target) but not ![image](target) handled separately -- both are checked identically.
MD_LINK = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
HTML_ATTR = re.compile(r"(?:src|href|srcset)\s*=\s*\"([^\"]+)\"", re.IGNORECASE)
FENCE = re.compile(r"^\s*(```|~~~)")


def is_external(target: str) -> bool:
    scheme = urlparse(target).scheme
    return bool(scheme) or target.startswith("//")


def targets_in(path: str):
    """Yield (line_number, target) for every link outside a fenced code block."""
    in_fence = False
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if FENCE.match(line):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for match in MD_LINK.finditer(line):
                yield lineno, match.group(1)
            for match in HTML_ATTR.finditer(line):
                # srcset may carry a comma-separated candidate list.
                for candidate in match.group(1).split(","):
                    candidate = candidate.strip().split(" ")[0]
                    if candidate:
                        yield lineno, candidate


def main() -> int:
    failures = []
    checked = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".md"):
                continue
            path = os.path.join(dirpath, name)
            rel_source = os.path.relpath(path, ROOT)
            for lineno, target in targets_in(path):
                if is_external(target) or target.startswith("#"):
                    continue
                clean = unquote(target.split("#")[0].split("?")[0])
                if not clean:
                    continue
                resolved = os.path.normpath(os.path.join(dirpath, clean))
                checked += 1
                if not os.path.exists(resolved):
                    failures.append(f"{rel_source}:{lineno}: {target}")

    if failures:
        print(f"{len(failures)} broken relative link(s):\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"OK -- {checked} relative link(s) resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
