#!/usr/bin/env python3
"""Produce the deployable bundle in site/dist/ from the authored source in site/.

The source under `site/` is written to be read: the CSS explains why the orbit
scales are what they are, the JavaScript explains which Alpine expressions the
CSP build will refuse, and the markup explains why the script order is
load-bearing. Every one of those comments earns its place in the repository and
none of them earns a place in what the domain serves.

That matters more than tidiness here. The bundle is published by handing the
whole file set to the install in ONE call, so its size is a hard constraint on
whether it can be published at all rather than a performance preference.

What this does NOT do is minify. Renaming identifiers or rewriting selectors
would mean the served bytes no longer correspond, line for line, to the bytes
that were reviewed and verified in a browser — and the verification harness runs
against the source. Stripping comments and collapsing runs of whitespace is
enough to matter and keeps the two legible against each other.

    python3 site/tools/build-bundle.py

Writes site/dist/ and prints what each file cost.
"""
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "site")
DIST = os.path.join(SRC, "dist")

FILES = [
    "index.html",
    "assets/brand.css",
    "assets/site.css",
    "assets/namespace.js",
    "assets/claims.js",
    "assets/site.js",
]


def strip_css(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    # Collapse whitespace and drop it around the punctuation that cannot be a
    # separator. Selectors keep their single spaces, so `.a .b` (descendant) is
    # never fused into `.a.b` (both-classes) — a rewrite that changes which
    # elements match and produces a page that is subtly, silently wrong.
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s*([{};:,>])\s*", r"\1", text)
    text = re.sub(r";}", "}", text)
    return text.strip() + "\n"


def strip_js(text):
    # Line comments only where the line has nothing else on it, and block
    # comments anywhere. A naive `//` strip corrupts the URLs in this file —
    # `vayu://` and `https://` both contain one — which is a mistake that
    # produces a bundle that loads and quietly does the wrong thing.
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"^[ \t]*//[^\n]*\n", "", text, flags=re.M)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip() + "\n"


def strip_html(text):
    # Never touch a conditional comment or anything inside a tag.
    text = re.sub(r"<!--(?!\[if).*?-->", "", text, flags=re.S)
    text = re.sub(r"\n\s*\n+", "\n", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    # Drop indentation but KEEP the newline. In HTML the newline is itself
    # whitespace, so `word\n  word` and `word\nword` render identically —
    # whereas joining the lines outright would fuse the two words.
    text = re.sub(r"\n[ \t]+", "\n", text)
    return text.strip() + "\n"


STRIPPERS = {".css": strip_css, ".js": strip_js, ".html": strip_html}


def main():
    if os.path.isdir(DIST):
        shutil.rmtree(DIST)
    total_in = total_out = 0
    for rel in FILES:
        source = os.path.join(SRC, rel)
        if not os.path.exists(source):
            print(f"FAIL — {rel} is missing")
            return 1
        with open(source, encoding="utf-8") as handle:
            text = handle.read()
        out = STRIPPERS[os.path.splitext(rel)[1]](text)
        target = os.path.join(DIST, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(out)
        total_in += len(text)
        total_out += len(out)
        print(f"  {rel:<24} {len(text):>7} → {len(out):>7}")
    print(f"  {'TOTAL':<24} {total_in:>7} → {total_out:>7}"
          f"  ({100 - round(100 * total_out / total_in)}% smaller)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
