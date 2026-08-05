#!/usr/bin/env python3
"""Require the charter to agree with itself, and the specifications to agree with the charter.

The Constitution is the supreme document: specifications are subordinate to it and code is
subordinate to them. That hierarchy only decides anything if the charter is internally
consistent, and a corpus-wide audit found it is not — Article 11.6 sets tenure at 126,230,400
seconds while Article 32.2, which Article 11.14 names as Article 11's own *machinery*, says the
term "SHALL be five years". An implementer cannot obey both, and whichever they pick they can
show a clause that endorses them.

That defect survived every check this project had, because every existing check compares prose
to a list or a number to its source. Nothing compared two Articles to each other.

Each quantity below names every place that states it. The check does not decide which value is
correct — deciding that is an amendment, not a lint — it only refuses to let the disagreement go
unnoticed again.

    python3 scripts/check-charter-consistency.py [root]

Exits non-zero listing every quantity whose sources disagree.
"""
import os
import re
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHARTER = "constitution/CONSTITUTION.md"
REGISTRY = "docs/spec/REGISTRY.md"

DAY = 86_400
YEAR = 31_536_000

# A quantity, and every place that states it. Each source yields a value in SECONDS.
#
# `known_conflict` records a disagreement that has been found, written up, and referred to the
# amendment process rather than resolved by an implementer. It keeps the check green while the
# decision is pending WITHOUT hiding it: the conflict is printed on every run, and the check
# fails if the conflict changes shape, is silently "fixed" by editing one side, or disappears —
# because any of those is someone deciding by edit what should be decided by amendment.
QUANTITIES = [
    {
        "name": "registration term",
        "sources": [
            (CHARTER, r"11\.6 Tenure runs for ([\d,]+) seconds", "seconds", "Article 11.6"),
            (CHARTER, r"32\.2 The term SHALL be (\w+) years", "years", "Article 32.2"),
            (REGISTRY, r"notAfter - notBefore == (\d+)`", "seconds", "REGISTRY.md"),
        ],
        "known_conflict": {
            "Article 11.6": 126_230_400,
            "Article 32.2": 5 * YEAR,
            "REGISTRY.md": 31_536_000,
        },
        "note": (
            "Article 11 is entrenched under Article 9 and names Article 32 as its machinery, so "
            "the entrenched right and its implementing Article state different terms. The "
            "specification states a third value. Resolving this is a constitutional amendment "
            "under Article 9, not an editorial fix: every other duration in the design — "
            "difficulty, renewal window, grace, redemption — is expressed relative to the term."
        ),
    },
]

WORD_NUMBERS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
}


def read(rel):
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def to_seconds(raw, unit):
    raw = raw.replace(",", "")
    value = WORD_NUMBERS.get(raw.lower()) if not raw.isdigit() else int(raw)
    if value is None:
        return None
    return value * YEAR if unit == "years" else value


def main():
    failures = []
    checked = 0

    for quantity in QUANTITIES:
        observed = {}
        for rel, pattern, unit, label in quantity["sources"]:
            text = read(rel)
            if text is None:
                failures.append(f"{quantity['name']}: source file {rel} is missing")
                continue
            match = re.search(pattern, text)
            if match is None:
                # A source that no longer states the quantity is a failure, not a skip. Silently
                # dropping it is how a check stops comparing anything while still passing.
                failures.append(
                    f"{quantity['name']}: {label} no longer states it "
                    f"(pattern did not match in {rel}) — update this check or restore the clause")
                continue
            seconds = to_seconds(match.group(1), unit)
            if seconds is None:
                failures.append(f"{quantity['name']}: could not read a number from {label}")
                continue
            observed[label] = seconds
            checked += 1

        expected = quantity.get("known_conflict")
        distinct = set(observed.values())

        if expected is None:
            if len(distinct) > 1:
                failures.append(
                    f"{quantity['name']}: sources disagree — "
                    + ", ".join(f"{k} = {v}s" for k, v in sorted(observed.items())))
            continue

        # A recorded conflict must stay exactly as recorded until the amendment resolves it.
        if observed != expected:
            failures.append(
                f"{quantity['name']}: the recorded conflict changed.\n"
                f"      recorded: " + ", ".join(f"{k}={v}s" for k, v in sorted(expected.items()))
                + "\n      found:    " + ", ".join(f"{k}={v}s" for k, v in sorted(observed.items()))
                + "\n      If this was resolved by amendment, update this check in the same "
                  "commit. If one side was edited to match another, that is an implementer "
                  "deciding what Article 9 reserves to an amendment.")
        else:
            print(f"UNRESOLVED — {quantity['name']}")
            for label, value in sorted(observed.items(), key=lambda kv: -kv[1]):
                print(f"    {label:<14} {value:>12,} s  ({value / DAY:.0f} days)")
            print(f"    {quantity['note']}")
            print()

    if checked == 0:
        print("::error::no quantities checked — this check is enforcing nothing", file=sys.stderr)
        return 1

    if failures:
        print(f"\n{len(failures)} charter consistency failure(s):\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"OK — {checked} charter/specification quantity source(s) read; "
          f"{len(QUANTITIES)} quantity(ies) tracked, unresolved conflicts printed above.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
