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

Three kinds of disagreement are tracked, because three kinds have been found:

- **QUANTITIES** — one number stated in several places. The registration term, the renewal window
  and the post-expiry interval each have three disagreeing sources.
- **TERMS** — one word defined as two different KINDS of thing. "Epoch" is an interval under
  Article 2.5 and an instant under Article 11.5; those cannot be compared, only shown.
- **MEMBERSHIPS** — one name a closed set excludes while another clause depends on it, or
  includes while another clause forbids it. `RENEW` and `TLD-CREATE`, both against Article 29.4.

None of them decides anything. Deciding is an amendment, not a lint; this refuses to let the
disagreement go unnoticed again, and fails if one is closed by editing whichever side is
convenient.

    python3 scripts/check-charter-consistency.py [root]

Exits non-zero when a tracked conflict changes shape, disappears, or a source stops saying what
it was recorded as saying.
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
MONTH = YEAR // 12  # the charter says "twelve months" where it means a year; 12 * MONTH == YEAR

# Article 11.6 states its renewal window as a *condition* rather than a duration — a RENEW may be
# signed "at any moment while the name is held" — so the window is the whole of tenure. Reading it
# as a number is the only way to compare it with the two clauses that do state numbers, and the
# phrase is spelled out here rather than inferred so that a change to the clause breaks the match
# instead of silently changing the value.
PHRASE_SECONDS = {
    "at any moment while the name is held": 126_230_400,
}

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
    {
        "name": "renewal window",
        "sources": [
            (CHARTER, r"(?s)11\.6 Tenure runs.*?A RENEW MAY be signed\s+"
                      r"(at\s+any\s+moment\s+while\s+the\s+name\s+is\s+held)",
             "phrase", "Article 11.6"),
            (CHARTER, r"32\.3 The renewal window SHALL open (\w+) months before expiry",
             "months", "Article 32.3"),
            (REGISTRY, r"notBefore >= prev\.notAfter - (\d+)`", "seconds", "REGISTRY.md"),
        ],
        "known_conflict": {
            "Article 11.6": 126_230_400,
            "Article 32.3": 12 * MONTH,
            "REGISTRY.md": 5_184_000,
        },
        "note": (
            "How early a holder may renew is the difference between a name kept and a name lost, "
            "and the three instruments differ by a factor of twenty-four. Article 11.6 imposes no "
            "window at all — a RENEW is valid at any moment while the name is held — while "
            "Article 32.3, which Article 11.14 names as Article 11's own machinery, opens the "
            "window twelve months before expiry, and the specification opens it sixty days "
            "before. The disagreement is not academic in either direction: an implementation "
            "following the charter accepts a record the specification refuses, and one following "
            "the specification refuses a record Article 11.6 expressly permits. Article 44.6 "
            "names precisely this — two implementers producing non-interoperating rules on a "
            "wire-visible, name-loss-bearing operation."
        ),
    },
    {
        "name": "post-expiry interval reserved to the incumbent",
        "sources": [
            (CHARTER, r"11\.8 Redemption\. For ([\d,]+) seconds", "seconds", "Article 11.8"),
            (CHARTER, r"a grace period of ([a-z ]+) days thereafter", "days", "Article 32.3"),
            (REGISTRY, r"if now >= prev\.notAfter \+ (\d+):\s+reject EXPIRED",
             "seconds", "REGISTRY.md"),
        ],
        "known_conflict": {
            "Article 11.8": 7_776_000,
            "Article 32.3": 180 * DAY,
            "REGISTRY.md": 2_592_000,
        },
        "note": (
            "Article 11.8 reserves the ninety days after tenure ends to the incumbent key alone "
            "and requires every other key's REGISTER to be refused throughout. Article 32.3 makes "
            "the same interval one hundred and eighty days. The specification makes it thirty, "
            "after which a further thirty days of quarantine pass before the name is claimable — "
            "so under REGISTRY.md the incumbent loses the name on day 31 and a stranger may take "
            "it on day 61, both inside the interval Article 11.8 reserves. A day-45 RENEW is the "
            "worked case: valid under the charter, rejected EXPIRED by the specification. The "
            "thirty-day figure is not a stray line — it is `GRACE_SECONDS` in "
            "registry/src/lifecycle.ts and is restated in NAMES.md, FAQ.md, GLOSSARY.md, "
            "PROOF-OF-WORK.md and CRYPTO-AGILITY.md — so aligning it is a coordinated change to "
            "the code and the corpus, downstream of an amendment rather than instead of one."
        ),
    },
]

# A term the charter defines more than once, where the disagreement is about the KIND of thing the
# term names rather than about a number. `check_terms` proves both definitions are still present
# and still incompatible; it cannot compare them, because they are not the same sort of value —
# which is exactly the defect.
TERMS = [
    {
        "name": "epoch",
        "definitions": [
            (CHARTER, r"2\.5 \*\*Epoch\*\* — the protocol's unit of ordered time: a fixed,\s+"
                      r"deterministic interval", "Article 2.5", "an INTERVAL of 1-14 days"),
            (CHARTER, r"11\.5 Time\. Every epoch in this Constitution is an integer count of SI\s+"
                      r"seconds elapsed since", "Article 11.5", "an INSTANT, in Unix seconds"),
        ],
        "note": (
            "Article 2.5 makes an Epoch a fixed interval of one to fourteen days whose boundary a "
            "Node computes offline. Article 11.5 makes every epoch in the Constitution an integer "
            "count of SI seconds since 1970 — an instant. Usage follows 11.5 throughout (11.6 "
            "'the epoch of the latest REGISTER or RENEW record', 11.7 comparing an epoch against "
            "'the receiving party's own clock', 20.2 'records created at or after that epoch'). "
            "Precedence cannot resolve it: Article 3.7 ranks the Constitution above the "
            "specifications, and both clauses are inside the Constitution. Article 3.21 points at "
            "11.5 as the text in conflict without curing it. An implementer still cannot tell "
            "what TYPE of value a VWIP's activation epoch carries, and Article 20.11 makes that "
            "term the subject of a conformance test."
        ),
    },
]

# A name the charter both requires and excludes. Not a number and not a definition: a question of
# MEMBERSHIP in a closed set, where one clause enumerates and another clause depends on something
# the enumeration leaves out — or forbids something it lets in.
#
# `check_membership` proves the excluding clause still excludes and every requiring clause still
# requires. Like the terms above it deliberately does not decide, because both sides are inside
# the Constitution and Article 3.7 ranks the Constitution above everything, not above itself.
MEMBERSHIPS = [
    {
        "name": "RENEW",
        "set": (CHARTER, r"29\.4 The record types are a closed set: ([^.]+)\.", "Article 29.4"),
        # The name must be ABSENT from the set the pattern above captures.
        "expect": "absent",
        "verdict": ("Article 29.4 omits it and requires unrecognised types to be REJECTED; "
                    "Articles 11.6, 11.8 and 31.1 each make a RENEW record normative by name"),
        "against": [
            (CHARTER, r"from the epoch\s+of the latest REGISTER or RENEW record", "Article 11.6"),
            (CHARTER, r"the only record a\s+conformant implementation MAY accept for that name is "
                      r"a RENEW", "Article 11.8"),
            (CHARTER, r"31\.1 A REGISTER record and a renewal record MUST each carry a "
                      r"proof-of-work", "Article 31.1"),
        ],
        "note": (
            "Article 29.4 closes the record set to eleven types and requires an unrecognised type "
            "to be REJECTED rather than ignored — so a peer obeying 29.4 literally must refuse "
            "every RENEW. Articles 11.6, 11.8 and 31.1 each make a RENEW record normative by "
            "name, and Article 11 is entrenched under Article 9. 29.4 is therefore the erroneous "
            "clause, but it is also the higher-precedence instrument as written, and removing "
            "RENEW from the implementation would break the entrenched Article while adding it to "
            "29.4 is an amendment under Article 58. The specification implements RENEW, because "
            "the alternative is a registry in which no name can ever be renewed; this is recorded "
            "so that the choice is visible rather than silent."
        ),
    },
    {
        "name": "TLD-CREATE",
        "set": (CHARTER, r"29\.4 The record types are a closed set: ([^.]+)\.", "Article 29.4"),
        # Here the name must be PRESENT in the set, and the conflict is what another Article says
        # about it.
        "expect": "present",
        "against": [
            (CHARTER, r"35\.6 A new TLD comes into being only by a ratified Naming-category VWIP",
             "Article 35.6"),
        ],
        "verdict": "Article 29.4 makes it a record; Article 35.6 makes it a ratified proposal",
        "note": (
            "29.4 makes TLD-CREATE a record type, which means an extension comes into existence "
            "by someone appending a record. Article 35.6 vests creation in a ratified proposal "
            "instead. The two cannot both hold: if a record creates a TLD then the ratification "
            "is decorative, and if ratification creates it then the record type has nothing to "
            "do. This is the same defect that already reached NAMESPACE.md, which required an "
            "implementation to derive the valid set 'from the registry log' when the log carries "
            "nothing to derive it from — corrected there, uncorrected here, and the charter is "
            "where it originated."
        ),
    },
]

WORD_NUMBERS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    "twelve": 12, "ninety": 90, "one hundred and eighty": 180,
}

UNIT_SECONDS = {"seconds": 1, "days": DAY, "months": MONTH, "years": YEAR}


def read(rel):
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def to_seconds(raw, unit):
    raw = raw.replace(",", "").strip()
    if unit == "phrase":
        # A clause that states a duration as a condition rather than a number. The phrase must be
        # one this check knows; an unrecognised one is a failure, never a guess.
        return PHRASE_SECONDS.get(" ".join(raw.split()).lower())
    multiplier = UNIT_SECONDS.get(unit)
    if multiplier is None:
        return None
    value = int(raw) if raw.isdigit() else WORD_NUMBERS.get(raw.lower())
    if value is None:
        return None
    return value * multiplier


def check_terms(failures):
    """Both definitions must still be present, and still be the two incompatible ones.

    Deliberately not a comparison. An interval and an instant cannot be compared, and pretending
    otherwise would produce a number that looked like a resolution. What this proves is narrower
    and is the whole point: the disagreement is still exactly where it was recorded, so nobody has
    closed it by deleting one side.
    """
    checked = 0
    for term in TERMS:
        found = []
        for rel, pattern, label, sense in term["definitions"]:
            text = read(rel)
            if text is None:
                failures.append(f"{term['name']}: source file {rel} is missing")
                continue
            if re.search(pattern, text) is None:
                failures.append(
                    f"{term['name']}: {label} no longer defines it as {sense} "
                    f"(pattern did not match in {rel}). If this was resolved by amendment, update "
                    f"this check in the same commit. If one definition was simply edited away, "
                    f"that is an implementer deciding what Article 58 reserves to an amendment.")
                continue
            found.append((label, sense))
            checked += 1

        if len(found) == len(term["definitions"]):
            print(f"UNRESOLVED — {term['name']} is defined {len(found)} ways")
            for label, sense in found:
                print(f"    {label:<14} {sense}")
            print(f"    {term['note']}")
            print()
    return checked


def check_membership(failures):
    """The excluding clause must still exclude, and every requiring clause must still require.

    Not a decision, for the same reason as `check_terms`: both sides are Articles, and precedence
    ranks the Constitution above the specifications rather than above itself. What this proves is
    that the disagreement is still exactly where it was recorded — so it cannot be closed by
    quietly editing whichever side is inconvenient.
    """
    checked = 0
    for item in MEMBERSHIPS:
        rel, pattern, label = item["set"]
        text = read(rel)
        if text is None:
            failures.append(f"{item['name']}: source file {rel} is missing")
            continue
        match = re.search(pattern, text)
        if match is None:
            failures.append(
                f"{item['name']}: {label} no longer states a closed set "
                f"(pattern did not match in {rel}) — update this check or restore the clause")
            continue
        members = {m.strip() for m in re.split(r",\s*", match.group(1))}
        present = item["name"] in members
        want_present = item["expect"] == "present"
        if present != want_present:
            failures.append(
                f"{item['name']}: {label} now {'lists' if present else 'omits'} it, where this "
                f"check recorded the opposite. If an amendment resolved this, update the check in "
                f"the same commit; if a clause was edited to make the conflict go away, that is an "
                f"implementer deciding what Article 58 reserves to an amendment.")
            continue
        checked += 1

        others = []
        for orel, opattern, olabel in item["against"]:
            otext = read(orel)
            if otext is None:
                failures.append(f"{item['name']}: source file {orel} is missing")
                continue
            if re.search(opattern, otext) is None:
                failures.append(
                    f"{item['name']}: {olabel} no longer conflicts with that "
                    f"(pattern did not match in {orel}) — update this check or restore the clause")
                continue
            others.append(olabel)
            checked += 1

        if len(others) == len(item["against"]):
            print(f"UNRESOLVED — {item['name']}")
            print(f"    {item['verdict']}")
            print(f"    sources: {label}, {', '.join(others)}")
            print(f"    {item['note']}")
            print()
    return checked


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

    checked += check_terms(failures)
    checked += check_membership(failures)

    if checked == 0:
        print("::error::no quantities checked — this check is enforcing nothing", file=sys.stderr)
        return 1

    if failures:
        print(f"\n{len(failures)} charter consistency failure(s):\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"OK — {checked} charter/specification source(s) read; "
          f"{len(QUANTITIES)} quantity(ies), {len(TERMS)} term(s) and {len(MEMBERSHIPS)} "
          f"membership(s) tracked, unresolved conflicts printed above.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
