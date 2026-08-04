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
    """The ratified extensions themselves, as a set. Source of truth for enumeration checks."""
    text = read("docs/spec/NAMES.md")
    anchor = re.search(r"below are the protocol's founding extensions", text)
    if anchor is None:
        return None
    run = re.search(r"(?:^- `\.[a-z0-9]+`.*\n)+", text[anchor.end():], re.M)
    if run is None:
        return None
    return set(re.findall(r"^- `\.([a-z0-9]+)`", run.group(0), re.M))


def count_launch_tlds():
    """The founding extensions, enumerated as bullets in NAMES.md.

    Counts DISTINCT extensions. A duplicated bullet is itself a defect, reported
    separately, because the count and the list must both be right -- a list with a
    repeat is wrong even when its length happens to match the sentence.
    """
    text = read("docs/spec/NAMES.md")
    anchor = re.search(r"below are the protocol's founding extensions", text)
    if anchor is None:
        return None, "could not locate the founding-extensions list in docs/spec/NAMES.md"
    # Take the first unbroken run of extension bullets after the anchor. Bounding by the
    # next paragraph does not work: the intro paragraph wraps, and a wrapped line starts
    # at column zero just as a new paragraph does.
    run = re.search(r"(?:^- `\.[a-z0-9]+`.*\n)+", text[anchor.end():], re.M)
    if run is None:
        return None, "no extension bullets follow the founding-extensions sentence"
    found = re.findall(r"^- `\.([a-z0-9]+)`", run.group(0), re.M)
    if not found:
        return None, "the founding-extensions list matched no bullets -- the format changed"
    duplicates = sorted({t for t in found if found.count(t) > 1})
    if duplicates:
        return None, f"docs/spec/NAMES.md lists a duplicate extension: {', '.join(duplicates)}"
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


# Each rule: a label, a function deriving the true number, and the claim patterns that
# must agree with it. A pattern's one capture group is the asserted quantity.
RULES = [
    {
        "label": "launch TLDs",
        "derive": count_launch_tlds,
        "source": "docs/spec/NAMES.md (founding-extensions list)",
        "patterns": [
            re.compile(r"\b(\w+) launch TLDs\b", re.I),
            re.compile(r"\b(\w+) (?:at launch|extensions so no single namespace)\b", re.I),
            re.compile(r"\bone of the (\w+) launch TLDs\b", re.I),
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
]


def check_tld_enumerations(truth_set):
    """Every ENUMERATION of the launch TLDs must match the ratified set exactly.

    The count rules below guard sentences like "the eleven launch TLDs". They do not guard a
    document that lists the extensions without stating how many there are -- and that is exactly
    where the original defect survived. `.vayu` appeared twice in Article 35.1 of the charter,
    every derived document inherited it, and correcting the ones that stated a number left the
    charter and RESOLUTION.md still listing it twice, because neither says "eleven".

    A list is matched by finding three or more consecutive ratified extensions on the same line
    or the next, then reading the whole run.
    """
    failures = []
    checked = 0
    pattern = re.compile(r"\.([a-z0-9]+)")

    for rel, path in markdown_files():
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        # Collapse wrapped lines so a list broken across two lines is still one run.
        for match in re.finditer(r"\.vayu[,`\s].{0,400}?\.blog", text, re.S):
            run = match.group(0)
            found = [m.group(1) for m in pattern.finditer(run)]
            listed = [t for t in found if t in truth_set]
            if len(listed) < 3:
                continue
            checked += 1
            duplicates = sorted({t for t in listed if listed.count(t) > 1})
            missing = sorted(truth_set - set(listed))
            line = text[:match.start()].count("\n") + 1
            if duplicates:
                failures.append(
                    f"{rel}:{line}: extension list repeats {', '.join(duplicates)}")
            if missing:
                failures.append(
                    f"{rel}:{line}: extension list omits {', '.join(missing)}")
    return checked, failures


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
                yield os.path.relpath(path, ROOT), path


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
    if truth_set is None:
        print("::error::could not read the founding-extension list from docs/spec/NAMES.md",
              file=sys.stderr)
        return 1
    listed, list_failures = check_tld_enumerations(truth_set)
    print(f"derived: {sorted(truth_set)} (the ratified extensions)")
    print(f"checked {listed} extension enumeration(s)")
    if listed == 0:
        print("::error::no extension enumerations matched -- this check is enforcing nothing",
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
