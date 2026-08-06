#!/usr/bin/env python3
"""Every VWIP carries the sections VWIP-0000 makes mandatory for its type.

VWIP-0000 section 3 lists twelve sections a proposal MUST contain before it advances beyond
Draft, plus two more that apply only to Naming and to Constitutional Amendment proposals. It says
what the check is: "An editor checks their presence, never their merit." That is a mechanical
check described in prose and performed by nobody.

The consequence was not hypothetical. VWIP-0000 is itself `Status: Final` and was missing five of
its own mandatory sections -- Centralisation analysis, Migration and rollback, Activation epoch,
Expiry of transitional mechanisms and Test vectors -- so the document defining the completeness
bar was the one document that had never been measured against it. VWIP-0002 was missing Migration
and rollback.

The list here is read from VWIP-0000's own table rather than restated, so amending the table
changes the check in the same commit. A restatement is how the two would drift, which is the
defect this whole corpus keeps producing.

That does mean deleting a row lowers the bar, and it should: the table is the source of truth and
amending it is a real editorial act, not a way round the check. What the check refuses is doing it
silently -- the section count is printed on every run, and a floor refuses a table that has
collapsed to fewer than ten rows, which is a format break rather than an amendment.

    python3 scripts/check-vwips.py [root]

Exits non-zero listing every VWIP missing a section its type requires.
"""
import os
import re
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SPEC = os.path.join(ROOT, "docs", "spec")
PROCESS = "docs/spec/VWIP-0000.md"

# Sections the table marks as applying to one kind of proposal only. The marker is in the table's
# own prose, so this maps the marker to the header field that decides it.
CONDITIONAL = {
    "Collision review": ("Category", "Naming"),
    "Full replacement text": ("Type", "Constitutional Amendment"),
}

# Draft is the one status that may be incomplete: VWIP-0000 3 says a proposal "MUST NOT advance
# beyond Draft" without these. Everything else is held to the full list.
INCOMPLETE_OK = {"Draft"}


def read(rel):
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def mandatory_sections(text):
    """The section names from VWIP-0000's own table, in order."""
    table = re.search(r"### 3\. Mandatory sections\n(.*?)(?=\n3\.1 )", text, re.S)
    if table is None:
        return None, "could not locate VWIP-0000's mandatory-sections table"
    rows = re.findall(r"^\| ([A-Z][^|]*?) \| ", table.group(1), re.M)
    names = [r.strip() for r in rows if r.strip() not in ("Section", "---")]
    if len(names) < 10:
        return None, f"the table yielded only {len(names)} sections -- its format changed"
    return names, None


def header_field(text, field):
    match = re.search(rf"^{field}:\s*(.+?)\s*$", text, re.M)
    return None if match is None else match.group(1).strip()


def main():
    process = read(PROCESS)
    if process is None:
        print(f"::error::{PROCESS} is missing", file=sys.stderr)
        return 1
    names, problem = mandatory_sections(process)
    if problem is not None:
        print(f"::error::{problem}", file=sys.stderr)
        return 1

    violations = []
    pending = []
    checked = 0

    for filename in sorted(os.listdir(SPEC)):
        if not re.fullmatch(r"VWIP-\d{4}\.md", filename):
            continue
        rel = f"docs/spec/{filename}"
        text = read(rel)
        if text is None:
            continue
        checked += 1

        status = header_field(text, "Status")
        if status is None:
            violations.append(f"{rel}: no `Status:` in the header block")
            continue

        present = set(re.findall(r"^## (.+?)\s*$", text, re.M))
        missing = []
        for name in names:
            condition = CONDITIONAL.get(name)
            if condition is not None:
                field, wanted = condition
                if header_field(text, field) != wanted:
                    continue
            if name not in present:
                missing.append(name)

        if not missing:
            continue
        # A Draft may be incomplete -- that is what Draft means. It is REPORTED rather than
        # skipped, because a gap nobody has been told about is one that surfaces on the day
        # somebody tries to advance the proposal, which is the worst moment to discover it.
        if status in INCOMPLETE_OK:
            pending.append(f"{rel} ({status}) still needs: {', '.join(missing)}")
            continue
        for name in missing:
            violations.append(
                f"{rel}: Status is {status} and it has no `## {name}` section, which "
                f"VWIP-0000 section 3 makes mandatory. An editor checks presence, never "
                f"merit -- so this is a completeness failure, not a judgement about content")

    if checked == 0:
        print("::error::no VWIPs found -- this check is enforcing nothing", file=sys.stderr)
        return 1

    print(f"checked {checked} VWIP(s) against {len(names)} mandatory section(s) "
          f"read from {PROCESS}")
    for line in pending:
        print(f"  pending  {line}")
    if violations:
        print(f"\n{len(violations)} VWIP completeness failure(s):\n", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print("OK -- every VWIP beyond Draft carries every section its type requires.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
