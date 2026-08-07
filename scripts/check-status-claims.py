#!/usr/bin/env python3
"""A document may not say it is unimplemented while implementation source cites it.

`docs/ROADMAP.md` opened with "Nothing here is implemented" for a long time after that stopped
being true, `CONTRIBUTING.md` told contributors "there is no implementation yet" while sixteen
modules cited `REGISTRY.md` by name, and nine specification documents carried "Status: Draft --
not yet implemented" against code that implements them. Nobody wrote a false sentence; a true one
went stale, which is the failure mode this corpus produces more reliably than any other.

The direction of the check matters. A hand-written map from document to module is another
restatement, and restatements are what go stale -- so the evidence comes from the source instead:
a non-test file under `registry/src/` that names `FOO.md` is citing it as the thing it implements,
which is a convention the codebase already follows everywhere. Delete the citation and the claim
becomes true again; add the code and the claim fails. Neither requires anybody to remember this
script exists.

What it does NOT check is the reverse -- a document with no citing module is free to say whatever
it likes, because "unimplemented" is the honest default and there is no way to distinguish a
specification nobody has started from one whose implementation forgot to cite it. This check
catches overstatement of incompleteness, not understatement.

    python3 scripts/check-status-claims.py [root]

Exits non-zero listing every document whose claim its own source contradicts.
"""
import os
import re
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOURCE_DIR = os.path.join(ROOT, "registry", "src")

# The phrasings that assert no implementation exists. Kept as patterns rather than one regex so
# that a failure can quote the exact wording back, which is what makes the fix obvious.
CLAIMS = [
    re.compile(r"not yet implemented", re.I),
    re.compile(r"no implementation (?:yet|exists)", re.I),
    re.compile(r"there is no implementation", re.I),
    # `\w+ ` absorbs an adjective. "Nothing DESCRIBED here has been implemented" sat in
    # RESOLUTION.md, unmatched, while a browser rendered pages through resolve.ts, proxy.ts and
    # fetch.ts -- a pattern that is exact about a sentence nobody writes twice the same way.
    re.compile(r"nothing (?:\w+ )?(?:here |below |in this document )?(?:has been |is )implemented", re.I),
    re.compile(r"no (?:registry|proxy|client) code exists", re.I),
]

# Documents whose text is deliberately frozen, and why. An exemption is a written reason or it is
# not an exemption.
EXEMPT = {
    "docs/AUDIT-FINDINGS.md":
        "the raw record of a dated audit. Its own preamble says finding bodies are never edited "
        "after the fact -- a finding that says 'not yet implemented' is describing the corpus on "
        "2026-08-04, not today, and rewriting it would destroy the evidence it exists to keep.",
    "docs/spec/VWIP-0000.md":
        "the status vocabulary itself. It lists `Implemented` as one of the values a proposal's "
        "Status field may take, which is a definition rather than a claim about this project.",
}

# Documents this check reads. Everything tracked as prose, minus the exemptions.
ROOTS = [("docs", False), ("docs/spec", False), (".", True)]

# Documents that describe the PROJECT rather than one protocol area.
#
# These need their own rule, and finding out why is the reason this script was mutation-tested.
# The citation rule above is blind to them by construction: no module implements `CONTRIBUTING.md`,
# so no module cites it, so a stale claim there can never be caught -- and reverting
# CONTRIBUTING.md's "there is no implementation yet" passed the first version of this check
# cleanly. That sentence is the single worst place in the repository for the claim to be wrong,
# because it is the file a newcomer opens to decide what to do.
#
# For these, the evidence is simply whether any implementation module exists at all.
PROJECT_SCOPE = {
    "README.md",
    "CONTRIBUTING.md",
    "docs/ROADMAP.md",
    "docs/WHITEPAPER.md",
    "docs/ARCHITECTURE.md",
}

# Phrasings that assert the PROJECT has no implementation, as opposed to one document's subject.
# Narrower than CLAIMS on purpose: a project-scope document may still say a particular component
# is unwritten, and several correctly do.
PROJECT_CLAIMS = [
    re.compile(r"there is no implementation", re.I),
    re.compile(r"no implementation (?:yet|exists)", re.I),
    # `\w+ ` absorbs an adjective. "Nothing DESCRIBED here has been implemented" sat in
    # RESOLUTION.md, unmatched, while a browser rendered pages through resolve.ts, proxy.ts and
    # fetch.ts -- a pattern that is exact about a sentence nobody writes twice the same way.
    re.compile(r"nothing (?:\w+ )?(?:here |below |in this document )?(?:has been |is )implemented", re.I),
    re.compile(r"no code to write", re.I),
    re.compile(r"not yet implemented", re.I),
]


def read(rel):
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def asserted(text):
    """`text` with quoted and code-spanned material removed.

    A document that says it *used to* claim something has to contain the claim in order to say
    so, and a checker that cannot tell the two apart makes recording a correction impossible --
    which would push this corpus back toward silently overwriting stale sentences, the habit
    every guard here exists to break. Quoting is the marker: a phrase in double quotes or
    backticks is being discussed, and one in running prose is being asserted.

    Deliberately crude. It cannot distinguish a scare quote from a citation, and it does not try:
    the failure mode is a claim that escapes the check by being quoted, which requires somebody
    to have written quotation marks around a sentence they meant seriously.

    **Fenced blocks are prose here, and finding that out took a mutation.** The first version
    stripped inline code with a single regex, which on a triple-backtick fence consumed the whole
    block as one enormous code span -- so `README.md`'s repository-layout tree, which annotated
    `registry/` as "not yet implemented", was invisible to the check. Reverting that annotation
    survived cleanly. A fence in this corpus holds pseudocode, wire formats and directory
    listings: every one of them an assertion about the system, none of them a quotation. So fence
    contents are read, and only the fence markers are dropped.
    """
    out = []
    in_fence = False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            # Inside a fence, backticks and quotes are content rather than markup.
            out.append(line)
            continue
        without_code = re.sub(r"`[^`\n]*`", " ", line)
        out.append(re.sub(r"[\"“”][^\"“”\n]*[\"“”]", " ", without_code))
    return "\n".join(out)


def documents():
    """Every markdown file this check covers, as repo-relative paths."""
    found = []
    for directory, top_level_only in ROOTS:
        base = os.path.join(ROOT, directory)
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            if not name.endswith(".md"):
                continue
            rel = name if directory == "." else f"{directory}/{name}"
            if top_level_only and os.path.dirname(rel):
                continue
            found.append(rel)
    return found


def implementation_modules():
    """Every non-test module under registry/src. Evidence that an implementation exists at all."""
    if not os.path.isdir(SOURCE_DIR):
        return []
    return sorted(n for n in os.listdir(SOURCE_DIR)
                  if n.endswith(".ts") and not n.endswith(".test.ts"))


def citing_modules(basename):
    """Non-test files under registry/src that name this document.

    Tests are excluded on purpose. A test citing a specification is describing what it checks,
    which is true whether or not the behaviour exists yet; a module citing one is describing what
    it implements.
    """
    if not os.path.isdir(SOURCE_DIR):
        return []
    hits = []
    for name in sorted(os.listdir(SOURCE_DIR)):
        if not name.endswith(".ts") or name.endswith(".test.ts"):
            continue
        with open(os.path.join(SOURCE_DIR, name), encoding="utf-8") as handle:
            if basename in handle.read():
                hits.append(name)
    return hits


def main():
    if not os.path.isdir(SOURCE_DIR):
        print(f"::error::{SOURCE_DIR} is missing -- this check is enforcing nothing",
              file=sys.stderr)
        return 1

    built = implementation_modules()
    violations = []
    checked = 0
    claiming = 0

    for rel in documents():
        if rel in EXEMPT:
            continue
        text = read(rel)
        if text is None:
            continue
        checked += 1

        prose = asserted(text)
        claim = None
        for pattern in CLAIMS:
            match = pattern.search(prose)
            if match is not None:
                claim = match.group(0)
                break
        if claim is None:
            continue
        claiming += 1

        if rel in PROJECT_SCOPE:
            # Whole-project claim: the evidence is whether any implementation exists at all.
            project_claim = None
            for pattern in PROJECT_CLAIMS:
                match = pattern.search(prose)
                if match is not None:
                    project_claim = match.group(0)
                    break
            if project_claim is None or not built:
                continue
            violations.append(
                f"{rel}: says \"{project_claim}\" as a statement about the project, but "
                f"registry/src holds {len(built)} implementation module(s). This is the class of "
                f"document a newcomer reads first, and the citation rule cannot see it -- nothing "
                f"implements a README")
            continue

        modules = citing_modules(os.path.basename(rel))
        if not modules:
            continue
        shown = ", ".join(modules[:4]) + (f" and {len(modules) - 4} more" if len(modules) > 4
                                          else "")
        violations.append(
            f"{rel}: says \"{claim}\", but {len(modules)} module(s) under registry/src cite it "
            f"as what they implement ({shown}). Either the sentence is stale or the citation is "
            f"wrong, and both are worth knowing about")

    if checked == 0:
        print("::error::no documents found -- this check is enforcing nothing", file=sys.stderr)
        return 1

    # A guard whose evidence has vanished must say so rather than pass. If registry/src ever
    # empties, every project-scope claim becomes true again and this check silently stops
    # enforcing anything -- which is the shape of the defect it exists to catch.
    if not built:
        print("::error::registry/src holds no implementation modules -- this check is enforcing "
              "nothing", file=sys.stderr)
        return 1

    print(f"checked {checked} document(s) against {len(built)} implementation module(s); "
          f"{claiming} assert no implementation exists")
    for rel, why in sorted(EXEMPT.items()):
        print(f"  exempt   {rel} -- {why.split('.')[0]}")
    if violations:
        print(f"\n{len(violations)} document(s) contradicted by their own source:\n",
              file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print("OK -- no document claims to be unimplemented while source cites it as implemented.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
