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

The scan runs over the document FLATTENED to one line, because it used to run per line and this
corpus hard-wraps at about a hundred columns -- a forbidden phrase straddling a wrap was invisible,
and wrapping is what an editor does by default, so evading the check required no intent. The denial
window is the sentence, cut again at any word that introduces a new assertion ("so", "but",
"therefore"), because "there is no company to subpoena, so it cannot be taken down" is a violation
whose exemption came from a "no" about something else -- and that is the natural shape of one here.

WHAT THIS DOES NOT CATCH, stated because a checker trusted beyond its reach is worse than none: a
new paraphrase nobody has written yet, and any violation built from single words. A denial split
across a full stop from its claim still reads as a violation and is reported as one, which is 21.5
working rather than a defect. 21.4.i is a standard for a reader, not a regex, and the honest
division of labour is that this catches recurrences while a person catches inventions. When you
find a new one, add it here with its source so the next one is caught for free.

    python3 scripts/check-absolute-claims.py --self-test

runs the cases this checker has previously got wrong, so its reach is measured rather than
described.

    python3 scripts/check-absolute-claims.py [root]

Exits non-zero listing every file and line that makes a forbidden claim.
"""
import os
import re
import sys

# `--self-test` is a mode, not a root. Reading it as one made the self-test report that the
# Constitution was missing, which is a checker failing in the direction that looks like a finding.
_ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
ROOT = os.path.abspath(
    _ARGS[0] if _ARGS else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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


def flatten(text):
    """The document as one line, with an index back to the original offsets.

    **The scan used to run per line, and the corpus hard-wraps at about a hundred columns.** A
    forbidden phrase straddling a wrap point was therefore invisible -- and the wrapped form is
    the one an editor produces by default, so evading this check required no intent at all.
    Measured before this change: the sentence that ends "...and it cannot be taken\ndown by
    anyone." passed, and the identical sentence on one line was caught. `blockx.test.ts` had
    already learned this and grown a `SPEC_FLAT()` helper for it; the lesson did not travel.
    """
    flat = []
    offsets = []
    in_space = False
    for index, character in enumerate(text):
        if character.isspace():
            if not in_space:
                flat.append(" ")
                offsets.append(index)
                in_space = True
            continue
        in_space = False
        flat.append(character)
        offsets.append(index)
    return "".join(flat), offsets


# Words that introduce a NEW assertion rather than continuing the one being denied. A negation
# before one of these governs the clause before it, not the claim after it.
CLAUSE_BREAK = re.compile(
    r"\b(?:so|but|yet|therefore|which is why|and so|meaning that|so that)\b", re.I
)

DENIAL = re.compile(r"\b(?:not|never|no|cannot|refuses to|denies|neither|without)\b", re.I)


def is_denial(head):
    """Whether the text before a match denies the claim rather than making it.

    A denial is not a claim: "it does NOT make you anonymous" is the corpus obeying 21.4.

    Two windows have been wrong here already. Sixty characters swallowed POSITION.md's thesis --
    "VayuWeb is NOT a place to hide. It is a place that cannot be taken away from you" -- because
    the negation belonged to the sentence before. Widening to the sentence then admitted the
    commonest honest framing in this corpus as cover: "there is no company to subpoena, so it
    cannot be taken down" is a 21.4 violation whose exemption was supplied by the word "no" in a
    clause about something else, and that is the natural SHAPE of a violation here rather than a
    contrived one.

    So the window is the sentence, cut again at the last word that introduces a new assertion.
    """
    clause = re.split(r"[.;:!?]\s", head)[-1]
    breaks = list(CLAUSE_BREAK.finditer(clause))
    if breaks:
        clause = clause[breaks[-1].end():]
    return DENIAL.search(clause) is not None


def scan(path, text, patterns):
    """Every forbidden claim in one document, as (path, line, why, quote)."""
    flat, offsets = flatten(text)
    found = []
    for pattern, why in patterns:
        for match in pattern.finditer(flat):
            if is_denial(flat[: match.start()]):
                continue
            origin = offsets[match.start()] if match.start() < len(offsets) else len(text)
            line = text.count("\n", 0, origin) + 1
            # The quote comes from the FLATTENED text, so a wrapped violation is reported as the
            # reader meets it rather than as the editor left it.
            start = max(0, match.start() - 40)
            found.append((path, line, why, flat[start : match.end() + 40].strip()))
    return found


SELF_TESTS = [
    # (text, must_be_caught, why this case exists)
    (
        "VayuWeb is built so that a site stays up, and it cannot be taken\ndown by anyone.",
        True,
        "a violation straddling a hard wrap -- the defect this self-test was written for",
    ),
    (
        "VayuWeb is built so that a site stays up, and it cannot be taken down by anyone.",
        True,
        "the same sentence on one line, which was already caught",
    ),
    (
        "There is no company to subpoena, so it cannot be taken down.",
        True,
        'the commonest honest framing used as cover: "no" governs the clause before "so"',
    ),
    (
        "It does not follow that it cannot be taken down; a host can still be seized.",
        False,
        "a genuine denial, which must stay exempt",
    ),
    (
        "We never say your data is safe forever, because no such promise is true.",
        False,
        "a denial of the exact phrase, in the corpus's own voice",
    ),
    (
        "VayuWeb is NOT a place to hide. It is a place that cannot be taken away from you.",
        True,
        "the negation belongs to the previous sentence -- the first window's failure",
    ),
]


def self_test():
    """Measure this checker's reach instead of asserting it.

    Every case here is a sentence this file got wrong at some point. A checker whose limits are
    described in a docstring and nowhere else is a checker whose limits are a guess -- and both
    defects these cases pin were introduced by a change that also EDITED that docstring to say the
    problem was handled.
    """
    phrases, error = charter_phrases()
    if error is not None:
        print(f"ERROR -- {error}")
        return 1
    patterns = [
        (re.compile(re.escape(p), re.I), f'Article 21.4: "{p}"') for p in phrases if " " in p
    ]
    patterns += [(re.compile(p, re.I), why) for p, why in EQUIVALENTS]

    failures = 0
    for text, expected, why in SELF_TESTS:
        caught = len(scan("<self-test>", text, patterns)) > 0
        status = "ok  " if caught == expected else "FAIL"
        if caught != expected:
            failures += 1
        verb = "caught" if caught else "missed"
        print(f"  {status} {verb:7} {why}")
    if failures:
        print(f"\n{failures} self-test(s) failed -- this checker does not do what it claims.")
        return 1
    print(f"\nOK -- {len(SELF_TESTS)} self-test(s) pass; the checker catches what it says it does.")
    return 0


def main():
    if "--self-test" in sys.argv[1:]:
        return self_test()
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
        violations.extend(scan(path, text, literal + equivalent))

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
