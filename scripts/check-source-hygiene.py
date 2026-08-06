#!/usr/bin/env python3
"""Refuse source that would weaken the guarantees the rest of CI checks.

Each rule here exists because the thing it forbids has either already caused a defect in this
repository or would silently disable a check that did.

    python3 scripts/check-source-hygiene.py [root]

Exits non-zero listing every violation.
"""
import os
import re
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "registry")
SKIP_DIRS = {".git", "node_modules", "dist", "coverage"}

# (pattern, message, files it does NOT apply to)
RULES = [
    (
        re.compile(r"\bas any\b|\bas unknown as\b"),
        "an escape hatch out of the type system; `as any` and unchecked `as unknown as` "
        "silence exactly the checks that caught the nonce this repository dropped on the floor",
        (),
    ),
    (
        re.compile(r"@ts-(ignore|nocheck|expect-error)"),
        "a suppressed type error. If the type is wrong, fix the type",
        (),
    ),
    (
        re.compile(r"\bdebugger\b"),
        "a debugger statement",
        (),
    ),
    (
        re.compile(r"\b(test|it|describe)\.only\("),
        "a focused test. It passes CI while silently skipping every other test in the file, "
        "which is the failure mode where a green run means nothing",
        (),
    ),
    (
        re.compile(r"\bconsole\.(log|debug|info|warn|error)\("),
        "console output from library code; the CLI writes through process.stdout/stderr "
        "deliberately, everything else should return values rather than print",
        ("cli.ts", "generate-vectors.ts"),
    ),
    (
        re.compile(r"\bMath\.random\(|\bDate\.now\(|\bnew Date\("),
        "ambient nondeterminism. Every clock enters through an injected `now` parameter and "
        "every random value through an explicit generator, so that a verdict is reproducible "
        "from its inputs alone",
        ("cli.ts",),
    ),
    (
        re.compile(r"\b(TODO|FIXME|XXX|HACK)\b"),
        "an unresolved marker. Either do it or write down why it is not being done",
        (),
    ),
    (
        re.compile(r"\b(PUBLIC_KEY_LENGTH|SIGNATURE_LENGTH)\b"),
        "a suite-1 primitive size used outside its suite module. CRYPTO-AGILITY.md conformance "
        "item 1 requires that no primitive be referenced outside its suite module and item 7 "
        "that no code path assume a 32-byte key or a 64-byte signature. Lengths come from the "
        "suite table in suites.ts; ML-DSA-65 signs in 3,309 bytes and SLH-DSA-SHAKE-128s in "
        "about 7,856, so a constant named after Ed25519 is a migration that cannot happen",
        ("signature.ts", "signature.test.ts", "suites.ts"),
    ),
]

# (file, exact string that must appear, why)
#
# The inverse of a forbidden pattern, and a different job: these rules hold a call site that
# nothing else can reach. Both cover suite handling that is correct today and UNEXERCISED today,
# because only one suite is active — so the per-suite limit equals the global one and the
# suite's key and signature lengths equal Ed25519's. Deleting either check leaves every test
# passing. That is not a reason to skip the check; it is the reason it has to be static.
#
# Exact strings rather than a proximity heuristic, for the reason check-listeners.py records:
# three heuristic versions of that check each survived a mutation before the shape changed.
REQUIRED = [
    (
        "record.ts",
        "suite.publicKeyLength",
        "the owner key's length must come from the suite table, not from a constant",
    ),
    (
        "record.ts",
        "suite.signatureLength",
        "the signature's length must come from the suite table, not from a constant",
    ),
    (
        "record.ts",
        "suiteOf(record.suite)?.maxRecordBytes",
        "the per-suite size limit must be applied AFTER parsing. The bound before decoding "
        "cannot know the suite, so a verifier that checked only that one would accept records "
        "the suite forbids the day a second suite activates",
    ),
]


def source_files():
    for dirpath, dirnames, filenames in os.walk(SRC):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if name.endswith(".ts"):
                path = os.path.join(dirpath, name)
                yield os.path.relpath(path, ROOT), path, name


def strip_comments(text):
    """Blank out comments and string literals so prose about a rule is not a violation of it.

    This file, the specifications and the code comments all discuss `as any` and `Math.random`
    in order to forbid them. A checker that matched inside comments would fail on the very
    sentences explaining the rule -- the mistake the CLA check made and had to be rewritten for.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(c if c == "\n" else " " for c in text[i:j]))
            i = j
        elif text[i] in "'\"`":
            quote = text[i]
            j = i + 1
            while j < n and text[j] != quote:
                if text[j] == "\\":
                    j += 1
                j += 1
            j = min(j + 1, n)
            out.append("".join(c if c == "\n" else " " for c in text[i:j]))
            i = j
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def check_required(violations):
    """Every REQUIRED string must still be present in the file that has to carry it."""
    found = 0
    for name, needle, why in REQUIRED:
        path = os.path.join(SRC, "src", name)
        if not os.path.exists(path):
            violations.append(f"{name}: file is missing, so its required call site cannot be checked")
            continue
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        if needle not in text:
            violations.append(f"registry/src/{name}: '{needle}' is gone — {why}")
            continue
        found += 1
    return found


def main():
    violations = []
    checked = 0

    allowed = 0
    for rel, path, name in source_files():
        with open(path, encoding="utf-8") as handle:
            raw = handle.read()
        code = strip_comments(raw)
        raw_lines = raw.split("\n")
        checked += 1

        for pattern, message, exempt in RULES:
            if name in exempt:
                continue
            for match in pattern.finditer(code):
                line = code[:match.start()].count("\n") + 1
                # A deliberate exception is written as `hygiene:allow <reason>` in a comment on
                # the line or the one above it. Matching happens in stripped code and the
                # exemption is read from the raw text, so a rule can never be disabled by
                # prose that merely mentions it -- and every exception has to state why, in
                # writing, next to the thing it excuses.
                context = "\n".join(raw_lines[max(0, line - 2):line])
                waiver = re.search(r"hygiene:allow\s+(\S.*)", context)
                if waiver is not None:
                    allowed += 1
                    continue
                violations.append(f"{rel}:{line}: '{match.group(0).strip()}' — {message}")

    required = check_required(violations)

    if checked == 0:
        print("::error::no source files found — this check is enforcing nothing", file=sys.stderr)
        return 1
    if required == 0:
        print("::error::no required call site verified — this check is enforcing nothing",
              file=sys.stderr)
        return 1

    print(f"checked {checked} source file(s) against {len(RULES)} rules and {required} "
          f"required call site(s); {allowed} explicit waiver(s)")
    if violations:
        print(f"\n{len(violations)} hygiene violation(s):\n", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print("OK — no hygiene violations.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
