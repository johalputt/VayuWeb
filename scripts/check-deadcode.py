#!/usr/bin/env python3
"""Refuse exported symbols that nothing imports and nothing tests.

An export is a promise: it says another module may depend on this. An export nobody uses is a
promise to nobody that still has to be kept working, still appears in the public surface, and
still has to be reasoned about by the next person. VayuPress gates this with
`scripts/deadcode-gate.sh`; this is the same rule for a TypeScript tree.

The bar is deliberately "imported somewhere OR named in a test". Something exercised only by
tests is not dead -- it is verified surface, and this project deliberately exports internals so
they can be attacked directly.

## Five ways this check was not doing its job

Every one was found by mutating it -- deliberately re-breaking the code after fixing the defect
before it -- and none by reading it. That matters, because the previous version reads perfectly
well.

**`export { X }` was not matched at all.** The pattern covered `export function`, `export const`
and their siblings, and a bare re-export statement is none of those. `fetch.ts` re-exporting
`ContentError` for no reason was not merely passed over, it was never examined. A gate that
silently declines to look at a whole syntactic form is worse than one that looks and is wrong,
because nothing in its output says so. Both `export { A, B as C }` and
`export { A } from './m.ts'` are now read, and it is the *exported* name that has to be used.

**A hit could come from anywhere.** Searching for the bare word across the corpus meant any
symbol sharing a name with something used elsewhere was invisible: an `export const sha256Helper`
counted as used because `sha256` appears in another module. The evidence has to be a dependency,
so a consuming file must both name the symbol and import from the module that defines it.

**A re-export could justify itself.** With both fixes in place the `ContentError` case still
passed, and this third cause is the one worth remembering: a re-export names its symbol twice in
the defining file -- once to import it, once to export it -- so the "used elsewhere in this file"
rule was satisfied by the re-export statement itself. That rule is right for a helper a module
uses internally and exactly wrong here, because a re-export exists for another module by
definition. Re-exported names therefore require an external dependent.

Fixing those three immediately surfaced a real one: `store.ts` re-exported `GRACE_SECONDS` and
`QUARANTINE_SECONDS`, which every consumer imports from `lifecycle.ts` instead. The re-export and
the import feeding it were both inert, and had been invisible the whole time.

**A doc comment counted as a use.** The in-file rule asked whether the symbol's name appeared more
than once in the defining file, over the raw text -- and a well-documented export names itself in
its own doc comment, which is the second occurrence. `swarm.ts`'s `joinSwarm`, the sole entry point
of the reference transport binding, was certified live on the strength of the sentence describing
it; nothing imported it and no test named it. Comments and string literals are therefore blanked
out before any name is counted. Import specifiers are strings, so the module-dependency test still
reads the untouched source -- stripping both at once fails ninety-two live exports and looks, from
the output alone, exactly like a real regression.

**And there was no floor.** Narrowing the export pattern so `function`, `const`, `interface` and
`type` were ignored dropped the corpus from 305 matches to 18 and still printed OK, because
nothing asked whether the number was plausible. A gate that has stopped matching is
indistinguishable from a gate with nothing to report unless it says how much it looked at.

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

# A floor on how many exports the patterns must find. Not a bound on the codebase: it is here so
# that a pattern which stops matching fails loudly instead of reporting a clean run over almost
# nothing. Today's corpus is a little over 300; a broken pattern drops it to double digits.
MINIMUM = 150

EXPORT = re.compile(
    r"^export\s+(?:async\s+)?(?:function|class|const|let|interface|type|enum)\s+([A-Za-z_$][\w$]*)",
    re.M,
)

# `export { A, B as C };` and `export { A } from './m.ts';`. A separate pattern because the
# declaration form above cannot express it, and its absence meant re-exports went unexamined.
REEXPORT = re.compile(r"^export\s+(?:type\s+)?\{([^}]*)\}", re.M)


COMMENTS_AND_STRINGS = re.compile(
    r"""/\*[\s\S]*?\*/|//[^\n]*|'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|`(?:\\.|[^`\\])*`""",
    re.M,
)


def strip_noise(text):
    """Blank out comments and string literals, preserving line numbers.

    Replacement is space-for-character rather than deletion so that every reported line number
    still points at the line it came from.
    """
    return COMMENTS_AND_STRINGS.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def exported_symbols(text):
    """Every name a file exports, as `(symbol, line, is_reexport)`.

    The third element matters: a re-export may not be justified by a mention in its own file,
    because that mention IS the export.
    """
    found = []
    for match in EXPORT.finditer(text):
        found.append((match.group(1), text[: match.start()].count("\n") + 1, False))
    for match in REEXPORT.finditer(text):
        line = text[: match.start()].count("\n") + 1
        for piece in match.group(1).split(","):
            piece = piece.strip()
            if not piece:
                continue
            # `B as C` exports C, so C is the name a consumer imports and therefore the name to
            # check. Taking B would ask whether the *source* symbol is used, which it always is.
            name = piece.split(" as ")[-1].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", name) and name != "default":
                found.append((name, line, True))
    return found


def depends_on(body, module_filename):
    """Does `body` import from the module in `module_filename`?

    Matched on the module specifier rather than on any mention of the name, because the point is
    to require a dependency and not a coincidence. Both `./foo.ts` and `../src/foo.ts` count; a
    bare mention of the word `foo` in prose does not.
    """
    return re.search(rf"""from\s+['"][^'"]*/{re.escape(module_filename)}['"]""", body) is not None


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
        print("::error::no source files found -- this check is enforcing nothing", file=sys.stderr)
        return 1

    consumers = list(sources)
    for extra in EXTRA_ROOTS:
        consumers.extend(ts_files(extra))
    # Two views of the same files. `corpus` has comments and string literals blanked, because a
    # mention of a symbol in prose is not a use of it. `raw` is untouched, because an import
    # specifier is a string literal and the dependency test below has to still see it.
    raw = {path: read(path) for path in consumers}
    corpus = {path: strip_noise(body) for path, body in raw.items()}

    unused = []
    total = 0

    for path in sources:
        name = os.path.basename(path)
        if name.endswith(".test.ts"):
            continue
        rel = os.path.relpath(path, ROOT)
        text = corpus[path]

        for symbol, line, is_reexport in exported_symbols(text):
            total += 1
            used = False
            word = re.compile(rf"\b{re.escape(symbol)}\b")
            for other, body in corpus.items():
                if other == path:
                    # Within the defining file, a use elsewhere in that file counts too -- but
                    # never for a re-export, whose two mentions are the import and the export.
                    if is_reexport:
                        continue
                    if len(word.findall(body)) > 1:
                        used = True
                        break
                    continue
                # The name AND a dependency on the module that defines it. Without the second
                # half, a symbol whose name appears anywhere -- in an unrelated module, in a
                # comment, in another module's export of the same name -- counts as used, and the
                # check silently stops enforcing anything for that symbol.
                if word.search(body) and depends_on(raw[other], name):
                    used = True
                    break
            if not used:
                unused.append(f"{rel}:{line}: '{symbol}' is exported but never imported or tested")

    print(f"checked {total} export(s) across {len(sources)} source file(s)")
    if total < MINIMUM:
        print(f"::error::only {total} export(s) matched, below the floor of {MINIMUM} -- the "
              f"export patterns have stopped matching rather than the code having shrunk",
              file=sys.stderr)
        return 1
    if unused:
        print(f"\n{len(unused)} unused export(s):\n", file=sys.stderr)
        for u in unused:
            print(f"  {u}", file=sys.stderr)
        print("\n  Either use it, test it, or stop exporting it.", file=sys.stderr)
        return 1
    print("OK -- every export is imported or exercised by a test.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
