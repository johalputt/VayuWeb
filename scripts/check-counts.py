#!/usr/bin/env python3
"""Verify that counted claims in prose agree with the normative source that defines them.

A specification says "the eleven launch TLDs" in one document and enumerates them in
another. Nothing keeps the two in step. When they drift, the prose is not merely untidy:
an implementer who validates against the sentence builds a different namespace from one
who validates against the list, and both believe they conform.

This is not hypothetical here. The launch TLD list contained `.vayu` twice, so a
straight count of the bullets returned twelve while only eleven distinct extensions
existed. Eight documents inherited the wrong number from it, and fixing the two that
were noticed left six still asserting twelve. That is precisely the failure a count
derived from the source cannot have.

Each rule below names one source of truth, derives a number from it mechanically, and
then requires every prose claim matching a pattern to agree. Rules are deliberately
narrow: a rule that guesses at what a sentence means produces false failures, and a
check people learn to override is worse than no check.

    python3 scripts/check-counts.py [root]

Exits non-zero listing every disagreement.
"""
import os
import re
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", ".venv", "venv"}

# Files that quote historical, known-wrong text as evidence. An audit record has to reproduce the
# defect verbatim to be worth anything, so checking it for the defect fails on the document
# reporting it -- the same mistake the CLA check made, where a grep for "contributor licence
# agreement" failed on four documents promising there would never be one.
#
# This is deliberately a short, named list rather than a pattern. A wildcard here would let any
# future file opt out of the check by its name, which is how a gate quietly stops gating.
EVIDENCE_FILES = {"docs/AUDIT-FINDINGS.md"}

NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
    "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
    "nineteen": 19, "twenty": 20,
}


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def launch_tld_set():
    """The ratified extensions themselves, as a set. Source of truth for enumeration checks.

    The source moved when VWIP-0004 amended Article 35.1: the namespace is the Namespace Annex,
    not a bullet list in NAMES.md. Deriving it from the Annex is also what lets the
    anti-restatement rule below work, since that rule has to recognise a ratified extension in
    prose wherever one appears.
    """
    text = read("docs/spec/NAMESPACE-CATALOGUE.md")
    return set(re.findall(r"^\| `\.([a-z0-9]+)` \|", text, re.M))


def count_launch_tlds():
    """The ratified extensions, enumerated as table rows in the Namespace Annex.

    Counts DISTINCT extensions. A duplicated row is itself a defect, reported separately,
    because the count and the list must both be right -- a list with a repeat is wrong even when
    its length happens to match the sentence. `.vayu` was once listed twice, which made a list
    introduced as "twelve" hold eleven distinct entries.
    """
    text = read("docs/spec/NAMESPACE-CATALOGUE.md")
    found = re.findall(r"^\| `\.([a-z0-9]+)` \|", text, re.M)
    if not found:
        return None, "the Namespace Annex matched no extension rows -- the table format changed"
    duplicates = sorted({t for t in found if found.count(t) > 1})
    if duplicates:
        return None, ("docs/spec/NAMESPACE-CATALOGUE.md lists a duplicate extension: "
                      + ", ".join(duplicates))
    return len(found), None


def count_accompanying_headers():
    """Response headers sent alongside the CSP, defined in CONTENT-SECURITY.md section 3.

    Two arrive as canonical fenced blocks (Permissions-Policy, Referrer-Policy) and the
    rest as rows of the table that closes the section. The Content-Security-Policy
    itself lives in section 2 and is always cited separately from its accompaniment, so
    it is not counted here.
    """
    text = read("docs/spec/CONTENT-SECURITY.md")
    section = re.search(r"^## 3\. Accompanying response headers$(.*?)^## 4\.", text, re.S | re.M)
    if section is None:
        return None, "could not locate section 3 of docs/spec/CONTENT-SECURITY.md"
    body = section.group(1)
    fenced = re.findall(r"<!--\s*canonical:([a-z0-9-]+)\s*-->", body)
    tabled = re.findall(r"^\|\s*`([A-Z][A-Za-z-]+)`\s*\|", body, re.M)
    names = {n.lower() for n in fenced} | {n.lower() for n in tabled}
    if not names:
        return None, "section 3 yielded no headers -- the format changed"
    return len(names), None


def count_csp_relaxations():
    """Rows of the 2.3 table that grant something, rather than saying `None`.

    This number drifted three ways at once: CONTENT-SECURITY.md said two, PUBLISHING.md said "the
    two remaining relaxations" while its own preceding section defined a third, and RESOLUTION.md
    said "one of the two per-site relaxations" while pointing at a document that had grown to
    three. The count is derived from the table that closes the list, so a document that says a
    different number now fails rather than being noticed by a reader who happened to hold both
    files open.
    """
    text = read("docs/spec/CONTENT-SECURITY.md")
    if text is None:
        return None, "docs/spec/CONTENT-SECURITY.md is missing"
    section = re.search(r"### 2\.3 [^\n]*\n(.*?)(?=\n## )", text, re.S)
    if section is None:
        return None, "could not locate section 2.3 of docs/spec/CONTENT-SECURITY.md"
    rows = re.findall(r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*$", section.group(1), re.M)
    grants = [r for r in rows
              if r[0] not in ("Breaks", "---")
              and not r[1].startswith("---")
              and not r[1].startswith("None")]
    if not grants:
        return None, "section 2.3 yielded no relaxation rows -- the table format changed"
    return len(grants), None


# Each rule: a label, a function deriving the true number, and the claim patterns that
# must agree with it. A pattern's one capture group is the asserted quantity.
RULES = [
    {
        "label": "ratified extensions",
        "derive": count_launch_tlds,
        "source": "docs/spec/NAMESPACE-CATALOGUE.md (the Namespace Annex)",
        "patterns": [
            re.compile(r"\b([\w,]+) launch TLDs\b", re.I),
            re.compile(r"\b([\w,]+) ratified extensions\b", re.I),
            re.compile(r"\b([\w,]+) extensions are ratified\b", re.I),
            re.compile(r"\b([\w,]+) (?:at launch|extensions so no single namespace)\b", re.I),
            re.compile(r"\bone of the ([\w,]+) launch TLDs\b", re.I),
        ],
    },
    {
        "label": "accompanying response headers",
        "derive": count_accompanying_headers,
        "source": "docs/spec/CONTENT-SECURITY.md section 3",
        "patterns": [
            re.compile(r"\b(\w+) accompanying response headers\b", re.I),
            re.compile(r"\b(\w+) response headers are added\b", re.I),
        ],
    },
    {
        "label": "per-site CSP relaxations",
        "derive": count_csp_relaxations,
        "source": "docs/spec/CONTENT-SECURITY.md section 2.3",
        "patterns": [
            re.compile(r"\b(\w+) relaxations\b", re.I),
            re.compile(r"\bone of the (\w+) per-site relaxations\b", re.I),
        ],
    },
]


# Where an inline run of ratified extensions is legitimate, each with the reason. Everywhere
# else, a restatement is the defect -- see check_tld_enumerations.
#
# Named files rather than a pattern, for the same reason EVIDENCE_FILES is: a wildcard would let
# any future document opt out of the rule by its name, which is how a gate quietly stops gating.
RESTATEMENT_ALLOWED = {
    "constitution/CONSTITUTION.md":
        "Article 35.1 names eleven in the charter's own text so the founding set survives loss "
        "of the Annex. This is the one authoritative inline list.",
    "docs/spec/NAMESPACE-CATALOGUE.md":
        "the Namespace Annex itself -- the enumeration every other document defers to.",
    "docs/spec/VWIP-0004.md":
        "the ratification record, which must reproduce Article 35.1's full replacement text "
        "verbatim (Article 58.1.a).",
    "docs/spec/NAMES.md":
        "restates the eleven charter-named extensions once, explicitly as the Article 35.1 "
        "subset and explicitly as conferring no rank.",
    "CHANGELOG.md":
        "records what the namespace was before VWIP-0004, which cannot be done without "
        "reproducing it.",
}

# How many chained extensions constitute a restatement rather than an example.
#
# Set from the corpus rather than picked. Every historical restatement enumerated the full
# founding set -- eleven. The longest legitimate non-enumerating run is six: NAMESPACE.md section
# 5.3 argues about two-letter strings and names `.io`, `.ai`, `.co`, `.me`, `.tv` and `.fm` as
# CLEARNET examples, which happen to be ratified here too. Illustrative samples in README.md and
# FAQ.md run to four.
#
# Eight sits between the two populations with room either side. A lower threshold would flag
# every sample, and a rule that fires on good prose is a rule people learn to override -- which
# is worse than no rule, because it also looks like a gate in CI.
RESTATEMENT_THRESHOLD = 8


def check_tld_enumerations(truth_set):
    """No document may restate the namespace inline, outside a short named allowlist.

    This rule inverted when VWIP-0004 amended Article 35.1. It used to require that every inline
    list of extensions match the ratified set exactly, which was the right rule for a set of
    eleven: `.vayu` appeared twice in the charter, every derived document inherited the
    duplicate, and fixing the ones that stated a number left the charter and RESOLUTION.md still
    listing it twice because neither said "eleven".

    With 1,270 ratified extensions no document can restate the set, so "must match exactly"
    would check nothing -- it would pass on every file, forever, while looking like a gate. The
    property worth enforcing now is the one VWIP-0004 section 4.2 states: documents REFERENCE
    the Annex, they do not repeat it. Every restatement is a copy that can drift, and the
    restatements in this corpus did drift by a factor of a hundred -- RESOLUTION.md hard-coded
    eleven strings inline, NAMES.md asserted 1,267, REGISTRY.md said "the eleven launch TLDs",
    and the verifier enforced its own list. Four copies, three answers.

    A restatement is a CHAIN of at least RESTATEMENT_THRESHOLD distinct ratified extensions where
    nothing separates each from the next but punctuation, whitespace and the words "and" or "or".

    Two conditions, and both are load-bearing. Chaining distinguishes a restatement from prose: a
    paragraph discussing `.vayu`, `.blog` and `.news` in three separate sentences is not a copy of
    the namespace. The threshold distinguishes a restatement from an illustration: naming four
    extensions to show a reader what the namespace feels like is good writing, and a rule that
    fires on it is a rule people learn to override.
    """
    failures = []
    checked = 0
    extension = re.compile(r"(?<![\w.])\.([a-z0-9]{2,12})\b")
    joiner = re.compile(r"^[\s,;`*_()\[\]/·—–-]*(?:and|or|plus)?[\s,;`*_()\[\]/·—–-]*$")

    for rel, path in markdown_files():
        with open(path, encoding="utf-8") as handle:
            text = handle.read()

        hits = [m for m in extension.finditer(text) if m.group(1) in truth_set]

        chain = []
        for index, match in enumerate(hits):
            if chain:
                gap = text[hits[index - 1].end():match.start()]
                if len(gap) > 12 or joiner.match(gap) is None:
                    checked += report_chain(rel, text, chain, truth_set, failures)
                    chain = []
            chain.append(match)
        checked += report_chain(rel, text, chain, truth_set, failures)

    return checked, failures


def report_chain(rel, text, chain, truth_set, failures):
    """Record one candidate restatement. Returns 1 if it was a chain worth checking, else 0."""
    del truth_set
    listed = {match.group(1) for match in chain}
    if len(listed) < RESTATEMENT_THRESHOLD:
        return 0
    if rel in RESTATEMENT_ALLOWED:
        return 1
    line = text[:chain[0].start()].count("\n") + 1
    failures.append(
        f"{rel}:{line}: restates the namespace inline ({len(listed)} ratified extensions in a "
        f"row). Reference docs/spec/NAMESPACE-CATALOGUE.md instead -- a restatement is a copy "
        f"that can drift, and the ones in this corpus did, by a factor of a hundred. If this "
        f"document genuinely must carry the list, add it to RESTATEMENT_ALLOWED with the reason.")
    return 1


def as_number(word):
    """Interpret an asserted quantity, or None if it is not one."""
    lowered = word.lower()
    if lowered in NUMBER_WORDS:
        return NUMBER_WORDS[lowered]
    if lowered.isdigit():
        return int(lowered)
    return None


def markdown_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if name.endswith(".md"):
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
                if rel in EVIDENCE_FILES:
                    continue
                yield rel, path


def main():
    failures = []
    checked = 0

    truths = []
    for rule in RULES:
        value, problem = rule["derive"]()
        if problem is not None:
            # A rule that cannot find its source is a failure, never a silent skip. That
            # is how a check quietly stops checking while still reporting success.
            print(f"::error::{rule['label']}: {problem}", file=sys.stderr)
            return 1
        truths.append((rule, value))
        print(f"derived: {value} {rule['label']} (from {rule['source']})")

    for rel, path in markdown_files():
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        for rule, truth in truths:
            for pattern in rule["patterns"]:
                for match in pattern.finditer(text):
                    claimed = as_number(match.group(1))
                    if claimed is None:
                        continue
                    checked += 1
                    if claimed != truth:
                        line = text[:match.start()].count("\n") + 1
                        failures.append(
                            f"{rel}:{line}: claims {match.group(1)} {rule['label']}, "
                            f"but {rule['source']} defines {truth}\n"
                            f"      {match.group(0).strip()}"
                        )

    truth_set = launch_tld_set()
    if not truth_set:
        print("::error::could not read the ratified set from docs/spec/NAMESPACE-CATALOGUE.md",
              file=sys.stderr)
        return 1
    listed, list_failures = check_tld_enumerations(truth_set)
    # The set itself is 1,270 entries; printing it would bury every other line of output. The
    # size is the reviewable figure, and generate-namespace.py names the entries when they move.
    print(f"derived: {len(truth_set)} ratified extension(s) "
          f"(from docs/spec/NAMESPACE-CATALOGUE.md)")
    print(f"checked {listed} inline extension chain(s)")
    if listed == 0:
        print("::error::no extension chains matched -- this check is enforcing nothing",
              file=sys.stderr)
        return 1
    failures.extend(list_failures)
    checked += listed

    if not checked:
        # Every rule above exists because a real document makes the claim. Matching none
        # means the prose was reworded past the patterns, and the check is now inert.
        print("::error::no counted claims matched -- the patterns no longer find the prose "
              "they guard, so this check is enforcing nothing", file=sys.stderr)
        return 1

    if failures:
        print(f"\n{len(failures)} counted claim(s) disagree with their source:\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"\nOK -- {checked} counted claim(s) agree with the source that defines them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
