#!/usr/bin/env python3
"""Constitution Article 21.4 forbids a list of claims. Nothing checked whether they were made.

Article 21.4 is a MUST NOT, not a style note: "The following claims MUST NOT be made about
VayuWeb, in these or equivalent words, in any language" -- anonymous, untraceable, uncensorable,
permanent, unstoppable, "cannot be taken down", "your data is safe forever", "100% private", and
21.4.i, "any unqualified absolute of the same kind, whether or not it appears above".

Article 21.5 supplies the test, and it is the part that makes this checkable at all:

    A form of words is equivalent to a claim listed in 21.4 if it asserts totality, perfection or
    the absence of any exception, or if any limit stated in this Title contradicts it. The test is
    what the words assert to a reader who has read nothing else, not what the author intended and
    not what a longer passage elsewhere qualifies.

"Not what a longer passage elsewhere qualifies" is why a human reading in good faith kept missing
these. Every one of the violations found on the first run sat within a few paragraphs of an honest
caveat, and the author had that caveat in mind while writing the sentence. A reader arriving at
the pull-quote has not.

The list of literal phrases is READ OUT OF THE CONSTITUTION rather than restated here, so amending
Article 21.4 changes this check in the same commit. The equivalents below are a second list and
they are a judgement, so each one carries the file it was found in -- they are evidence of a
mistake actually made, not a guess at one.

SINGLE-WORD ENTRIES ARE NOT SCANNED, and the reason is the whole design of this check. Scanning
for "permanent" and "anonymous" produced fifty-nine hits on the first run and every one was
innocent: "a permanent archive", "the Objection Register is permanently public", "it does NOT make
you anonymous", and a heading reading "**Untraceable publishing.**" that introduces the paragraph
explaining VayuWeb does not provide it. Article 21.4 forbids making a claim *about VayuWeb*, and a
regex cannot tell an assertion from a denial or from a heading naming the limitation. Scanning a
bare word measures vocabulary. A checker with sixty false positives is a checker somebody switches
off, and the seven real violations go with it.

So the literal scan keeps only multi-word phrases, which are assertions in their own right, and
skips a line carrying a denial near the phrase. The equivalents list below carries the rest.

WHAT THIS DOES NOT CATCH, stated because a checker trusted beyond its reach is worse than none: a
new paraphrase nobody has written yet, and any violation built from single words. 21.4.i is a
standard for a reader, not a regex, and the honest division of labour is that this catches
recurrences while a person catches inventions. When you find a new one, add it here with its
source so the next one is caught for free.

    python3 scripts/check-absolute-claims.py [root]

Exits non-zero listing every file and line that makes a forbidden claim.
"""
import os
import re
import sys

ROOT = os.path.abspath(
    sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
CHARTER = os.path.join(ROOT, "constitution", "CONSTITUTION.md")

# Documents whose text is deliberately exempt, each with a written reason. An exemption is a
# reason or it is not an exemption.
EXEMPT = {
    "constitution/CONSTITUTION.md": "defines the prohibition; it must be able to quote what it forbids.",
    "docs/AUDIT-FINDINGS.md": "the frozen record of a dated audit. Its own preamble forbids editing "
    "finding bodies after the fact, and a finding that quotes a violation is evidence of it.",
    "CHANGELOG.md": "records what was fixed, which means quoting the sentence that was wrong.",
    "scripts/check-absolute-claims.py": "this file.",
}

# Equivalents under 21.5. Each was found in the corpus; the source is kept so that nobody has to
# wonder whether a pattern is real or speculative.
EQUIVALENTS = [
    (r"cannot be taken away from you", "docs/POSITION.md — 21.4.f in equivalent words"),
    # Anchored on the absolute FORM, not on the subject matter. The first version matched any
    # mention of "switch off your site" and then fired on the corrected sentence -- "there is
    # nobody to petition to take your name or switch off your site", which asserts the absence of
    # a PARTY rather than the impossibility of the outcome, and states its limits in the next
    # breath. A pattern that flags the fix as well as the defect teaches people to ignore it.
    (r"nobody can\b[^.]{0,60}\b(take your name|switch off your site)",
     "docs/FAQ.md — unqualified absolute, 21.4.i and 21.4.f"),
    (r"tells nobody anything", "docs/FAQ.md — equivalent to 21.4.h"),
    (r"impossible to rewrite that history quietly", "docs/WHITEPAPER.md — asserts absence of any exception"),
    (r"no step in that path contacts a party that could refuse",
     "docs/WHITEPAPER.md — asserts totality over a path whose own step 5 can refuse"),
]


def read(path):
    try:
        with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None


def charter_phrases():
    """The literal claims Article 21.4 enumerates, taken from the Article itself."""
    text = read("constitution/CONSTITUTION.md")
    if text is None:
        return None, "constitution/CONSTITUTION.md is missing"
    block = re.search(r"^21\.4 .*?^21\.5 ", text, re.S | re.M)
    if block is None:
        return None, "Article 21.4 is no longer where this check expects it"
    phrases = re.findall(r'^21\.4\.[a-z] "([^"]+)";', block.group(0), re.M)
    if len(phrases) < 5:
        return None, f"Article 21.4 enumerates only {len(phrases)} quoted claims; the format changed"
    return phrases, None


def documents():
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "target", "dist", ".venv"}]
        for name in files:
            if name.endswith(".md") or name.endswith(".py"):
                yield os.path.relpath(os.path.join(base, name), ROOT)


def main():
    phrases, error = charter_phrases()
    if error is not None:
        print(f"ERROR -- {error}")
        return 1
    print(f"Article 21.4 enumerates {len(phrases)} forbidden claim(s); "
          f"{len(EQUIVALENTS)} equivalent form(s) are also checked")

    # Multi-word only -- see the header. A single word is vocabulary; a phrase is a claim.
    literal = [
        (re.compile(re.escape(p), re.I), f'Article 21.4: "{p}"')
        for p in phrases
        if " " in p
    ]
    skipped = [p for p in phrases if " " not in p]
    equivalent = [(re.compile(p, re.I), why) for p, why in EQUIVALENTS]

    violations = []
    for path in sorted(documents()):
        if path in EXEMPT:
            continue
        text = read(path)
        if text is None:
            continue
        for number, line in enumerate(text.split("\n"), 1):
            for pattern, why in literal + equivalent:
                match = pattern.search(line)
                if match is None:
                    continue
                # A denial is not a claim. "It does not make you anonymous" and "we never say your
                # data is safe forever" are the corpus obeying 21.4, not breaking it.
                #
                # The window stops at the previous sentence boundary, and that matters: the first
                # version looked back sixty characters and swallowed POSITION.md's thesis --
                # "VayuWeb is NOT a place to hide. It is a place that cannot be taken away from
                # you" -- because the negation belonged to the sentence before. A guard that
                # silently drops the most prominent violation in the corpus is worse than no
                # guard, since the count still looks like a result.
                head = line[:match.start()]
                clause = re.split(r"[.;:!?]\s", head)[-1].lower()
                if re.search(r"\b(not|never|no|cannot|refuses to|denies|neither)\b", clause):
                    continue
                violations.append((path, number, why, line.strip()))

    for path, reason in sorted(EXEMPT.items()):
        print(f"  exempt   {path} -- {reason}")
    if skipped:
        print(f"  unscanned  {', '.join(skipped)} -- single words, see the header; a person "
              f"checks these")

    if violations:
        print(f"\n{len(violations)} forbidden claim(s):\n")
        for path, number, why, line in violations:
            print(f"  {path}:{number}: {why}")
            print(f"      {line[:110]}")
        print("\nArticle 21.5: the test is what the words assert to a reader who has read nothing")
        print("else, not what a longer passage elsewhere qualifies.")
        return 1

    print("\nOK -- no document makes a claim Article 21.4 forbids.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
