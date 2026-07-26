#!/usr/bin/env python3
"""Verify that the security headers are quoted identically everywhere.

The strict content-security profile is normative, and it appears in more than one
document: the specification that defines it, the resolution specification that
implements it, and any prose that quotes it. A profile that drifts between
documents is worse than no profile at all -- two implementers read two different
policies and both believe they are conformant.

This is the guard. `docs/spec/CONTENT-SECURITY.md` is the single source of truth.
Each normative header value there is fenced and preceded by a sentinel comment:

    <!-- canonical:content-security-policy -->
    ```text
    default-src 'none'; ...
    ```

Every other fenced block anywhere in the repository that begins with the same
header name must carry byte-identical content once whitespace is normalised.

    python3 scripts/check-headers.py [root]

Exits non-zero listing every divergence.
"""
import os
import re
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CANON = os.path.join(ROOT, "docs", "spec", "CONTENT-SECURITY.md")
SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", ".venv", "venv"}

SENTINEL = re.compile(r"<!--\s*canonical:([a-z0-9-]+)\s*-->\s*\n```[a-z]*\n(.*?)\n```", re.S)
FENCE = re.compile(r"```[a-z]*\n(.*?)\n```", re.S)


def normalise(value):
    """Collapse runs of whitespace so a rewrapped line is not a false positive."""
    return " ".join(value.split())


def strip_header_name(block):
    """Drop a leading 'Header-Name: ' so both sides of a comparison are just the value."""
    first, _, rest = block.partition("\n")
    match = re.match(r"[A-Za-z][A-Za-z0-9-]+:\s*(.*)$", first)
    if match:
        return (match.group(1) + ("\n" + rest if rest else "")).strip()
    return block.strip()


def load_canonical():
    """Collect every canonical:<name> sentinel in the repository.

    Definitions may live in more than one specification -- the content-security
    profile owns most of them, the privacy specification owns Clear-Site-Data --
    so the whole tree is scanned. Two files defining the same key differently is
    itself the drift this script exists to catch.
    """
    canon, source = {}, {}
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if not name.endswith(".md"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ROOT)
            for match in SENTINEL.finditer(open(path, encoding="utf-8").read()):
                key, value = match.group(1), normalise(strip_header_name(match.group(2)))
                if key in canon and canon[key] != value:
                    print(f"two different canonical definitions of '{key}': "
                          f"{source[key]} and {rel}", file=sys.stderr)
                    return None
                canon[key], source[key] = value, rel
    return canon


def header_name_of(block):
    """Return the canonical key a fenced block claims to be, or None."""
    first = block.strip().split("\n", 1)[0]
    match = re.match(r"([A-Za-z][A-Za-z0-9-]+):", first)
    if match:
        return match.group(1).lower()
    # A bare policy body, recognised by its directives.
    if re.match(r"^\s*default-src\b", block):
        return "content-security-policy"
    return None


def main():
    canon = load_canonical()
    if canon is None:
        return 1
    if not canon:
        print("no canonical:<name> sentinels found -- nothing to enforce", file=sys.stderr)
        return 1

    print("canonical values:")
    for key in sorted(canon):
        print(f"  {key} ({len(canon[key])} chars)")

    failures = []
    compared = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".md"):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ROOT)
            text = open(path, encoding="utf-8").read()
            # Blocks that are themselves the canonical definition are the yardstick.
            canonical_spans = [m.span(2) for m in SENTINEL.finditer(text)]
            for match in FENCE.finditer(text):
                if any(match.span(1) == span for span in canonical_spans):
                    continue
                block = match.group(1)
                key = header_name_of(block)
                if key is None or key not in canon:
                    continue
                body = strip_header_name(block)
                compared += 1
                if normalise(body) != canon[key]:
                    line = text[:match.start()].count("\n") + 1
                    failures.append(
                        f"{rel}:{line}: '{key}' diverges from the canonical value\n"
                        f"      here:      {normalise(body)[:160]}\n"
                        f"      canonical: {canon[key][:160]}"
                    )

    if failures:
        print(f"\n{len(failures)} header divergence(s):\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"\nOK -- {compared} quoted header block(s) match the canonical values.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
