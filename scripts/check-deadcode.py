#!/usr/bin/env python3
"""Refuse exported symbols that nothing imports and nothing tests.

An export is a promise: it says another module may depend on this. An export nobody uses is a
promise to nobody that still has to be kept working, still appears in the public surface, and
still has to be reasoned about by the next person. VayuPress gates this with
`scripts/deadcode-gate.sh`; this is the same rule for a TypeScript tree.

The bar is deliberately "imported somewhere OR named in a test". Something exercised only by
tests is not dead — it is verified surface, and this project deliberately exports internals so
they can be attacked directly.

    python3 scripts/check-deadcode.py [root]

Exits non-zero listing every unused export.
"""
import os
import re
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "registry", "src")
EXTRA_ROOTS = [
    os.path.join(ROOT, "registry", "bin"),
    os.path.join(ROOT, "registry", "scripts"),
]

EXPORT = re.compile(
    r"^export\s+(?:async\s+)?(?:function|class|const|let|interface|type|enum)\s+([A-Za-z_$][\w$]*)",
    re.M,
)


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def ts_files(root):
    if not os.path.isdir(root):
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"node_modules", "dist"}]
        for name in sorted(filenames):
            if name.endswith(".ts"):
                yield os.path.join(dirpath, name)


def main():
    sources = [p for p in ts_files(SRC)]
    if not sources:
        print("::error::no source files found — this check is enforcing nothing", file=sys.stderr)
        return 1

    consumers = list(sources)
    for extra in EXTRA_ROOTS:
        consumers.extend(ts_files(extra))
    corpus = {path: read(path) for path in consumers}

    unused = []
    total = 0

    for path in sources:
        name = os.path.basename(path)
        if name.endswith(".test.ts"):
            continue
        rel = os.path.relpath(path, ROOT)
        text = corpus[path]

        for match in EXPORT.finditer(text):
            symbol = match.group(1)
            total += 1
            # Referenced anywhere other than its own definition line?
            used = False
            word = re.compile(rf"\b{re.escape(symbol)}\b")
            for other, body in corpus.items():
                if other == path:
                    # Within the defining file, a use elsewhere in that file counts too.
                    hits = len(word.findall(body))
                    if hits > 1:
                        used = True
                        break
                    continue
                if word.search(body):
                    used = True
                    break
            if not used:
                line = text[:match.start()].count("\n") + 1
                unused.append(f"{rel}:{line}: '{symbol}' is exported but never imported or tested")

    print(f"checked {total} export(s) across {len(sources)} source file(s)")
    if unused:
        print(f"\n{len(unused)} unused export(s):\n", file=sys.stderr)
        for u in unused:
            print(f"  {u}", file=sys.stderr)
        print("\n  Either use it, test it, or stop exporting it.", file=sys.stderr)
        return 1
    print("OK — every export is imported or exercised by a test.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
