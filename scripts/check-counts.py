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
import json
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
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
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


def count_open_conflicts():
    """Conflicts check-charter-consistency.py holds open: quantities + terms + memberships.

    Derived because the first draft of ROADMAP.md's sentence said four and the answer was six --
    written in the same paragraph that explains why numbers in this corpus have to be derived.
    """
    text = read("scripts/check-charter-consistency.py")
    if text is None:
        return None, "scripts/check-charter-consistency.py is missing"
    total = 0
    for listname in ("QUANTITIES", "TERMS", "MEMBERSHIPS"):
        block = re.search(rf"^{listname} = \[(.*?)^\]", text, re.S | re.M)
        if block is None:
            return None, f"could not locate {listname} -- the checker's format changed"
        total += len(re.findall(r'^        "name": ', block.group(1), re.M))
    if total == 0:
        return None, "no tracked conflicts parsed -- the checker's format changed"
    return total, None


def count_untriaged_medium():
    """MEDIUM findings with no row in AUDIT-FINDINGS.md's disposition table.

    Derived because the first version of that sentence said eight and the answer was six -- a
    number asserted from memory in the very file that exists to stop numbers being asserted from
    memory. Counting it is two lines; guessing it was wrong on the first try.
    """
    text = read("docs/AUDIT-FINDINGS.md")
    if text is None:
        return None, "docs/AUDIT-FINDINGS.md is missing"
    marker = "## Disposition — MEDIUM and LOW"
    end = "**Every HIGH, MEDIUM and LOW finding now carries an outcome.**"
    if marker not in text or end not in text:
        return None, "could not locate the disposition table -- its format changed"
    table = text[text.index(marker):text.index(end)]
    triaged = set(re.findall(r"^\| `([^`]+)`", table, re.M))
    heads = re.findall(r"^## (.+?) — MEDIUM$", text, re.M)
    if not heads:
        return None, "no MEDIUM findings parsed -- the heading format changed"
    return len([h for h in heads if h not in triaged]), None


def count_conformance_tests():
    """Numbered items in CONTENT-SECURITY.md section 6 plus PRIVACY.md section 10.

    Derived because VWIP-0001 stated a total of twelve against an actual seventeen. A proposal
    that undercounts its own acceptance criteria is claiming a smaller bar than it set.
    """
    total = 0
    for rel, heading in (
        ("docs/spec/CONTENT-SECURITY.md", r"## 6\. Conformance"),
        ("docs/spec/PRIVACY.md", r"## 10\. Conformance"),
    ):
        text = read(rel)
        if text is None:
            return None, f"{rel} is missing"
        section = re.search(heading + r"\n(.*?)(?=\n## |\Z)", text, re.S)
        if section is None:
            return None, f"could not locate the conformance section of {rel}"
        items = re.findall(r"^(\d+)\. ", section.group(1), re.M)
        if not items:
            return None, f"{rel}'s conformance section yielded no numbered items"
        total += len(items)
    return total, None


def count_residual_channels():
    """Numbered subsections of CONTENT-SECURITY.md section 5.

    Derived because VWIP-0001 summarised this section as "the four channels CSP cannot close"
    when there are eight, and because the number is the substance of the claim: a security
    document that undercounts what it cannot close is making the opposite of a disclosure.
    """
    text = read("docs/spec/CONTENT-SECURITY.md")
    if text is None:
        return None, "docs/spec/CONTENT-SECURITY.md is missing"
    section = re.search(r"## 5\. What no header can close\n(.*?)(?=\n## )", text, re.S)
    if section is None:
        return None, "could not locate section 5 of docs/spec/CONTENT-SECURITY.md"
    subs = re.findall(r"^\*\*5\.(\d+) ", section.group(1), re.M)
    if not subs:
        return None, "section 5 yielded no numbered channels -- the format changed"
    return len(set(subs)), None


def count_record_vectors():
    """Record-verification vectors in the committed artifact.

    Derived because a number written into prose beside a generated file is a number that drifts
    the next time the file is regenerated, and this README's coverage claim had already been
    false once for a different reason.
    """
    text = read("conformance/vectors.json")
    if text is None:
        return None, "conformance/vectors.json is missing"
    try:
        data = json.loads(text)
    except ValueError as exc:
        return None, f"conformance/vectors.json is not valid JSON: {exc}"
    vectors = data.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        return None, "conformance/vectors.json has no `vectors` array"
    return len(vectors), None


def count_vector_suites():
    """Top-level vector suites in the committed artifact.

    A separate rule from the vector count, because the two go stale for different reasons. The
    count drifts when the generator changes. The suite count drifts when somebody ADDS a suite —
    which is exactly the moment two documents were left asserting "four suites" while the file
    carried five, each of them a sentence somebody had written once and had no reason to reread.
    """
    text = read("conformance/vectors.json")
    if text is None:
        return None, "conformance/vectors.json is missing"
    try:
        data = json.loads(text)
    except ValueError as exc:
        return None, f"conformance/vectors.json is not valid JSON: {exc}"
    suites = [k for k, v in data.items() if isinstance(v, list) and v]
    if not suites:
        return None, "conformance/vectors.json carries no non-empty suite arrays"
    return len(suites), None


def count_two_letter_tlds():
    """Two-letter extensions in the Annex.

    Derived because a conformance item in NAMESPACE.md asserted that "a two-character extension
    proposal is rejected" while the Annex it enumerates ratifies sixty of them, and because
    VWIP-0004's collision review turns on the number: 35 of the 60 share a string with an ISO
    3166-1 code, which is the whole substance of the review.
    """
    text = read("docs/spec/NAMESPACE-CATALOGUE.md")
    if text is None:
        return None, "docs/spec/NAMESPACE-CATALOGUE.md is missing"
    tlds = re.findall(r"^\| `\.([a-z0-9]+)`", text, re.M)
    if not tlds:
        return None, "the Annex yielded no extensions -- the table format changed"
    return len([t for t in tlds if len(t) == 2]), None


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


# A rule two documents both state, where fixing one and not the other has already happened.
#
# Not a count: a phrase that must be present in EVERY listed file, or absent from every one. It
# exists because the failure mode is specific and has occurred — NAMES.md specified ratification
# by "a two-thirds supermajority of ballots cast over 30 days, with a quorum of 25 percent of
# eligible signing keys", found it contradicted Article 43.1 (consensus is expressly not a vote)
# and withdrew it; NAMESPACE.md carried the same rule and was not touched in that change, so the
# vote survived in the document that names the extensions. Each file's own text looked settled.
AGREEMENTS = [
    {
        "label": "no ballot in VayuWeb naming",
        "files": ["docs/spec/NAMES.md", "docs/spec/NAMESPACE.md"],
        # `\s+` rather than a literal space: these documents are hard-wrapped, so the sentence
        # falls across a line break in one of them and not the other.
        "present": re.compile(
            r"no ballot,\s+no threshold and no quorum\s+anywhere\s+in VayuWeb naming", re.I),
        "absent": re.compile(
            r"(?<!\")(?:two-thirds (?:super)?majority|30-day voting period)(?![^\n]*\")"),
        "note": (
            "Article 43.1 makes consensus the absence of unaddressed substantive technical "
            "objection and 43.5.4 lists a vote count among the things that do not constitute it; "
            "Article 35.6's window is for objections, not ballots."
        ),
    },
    {
        # PRIVACY.md section 7 said secrets are "Never written to disk except in the platform
        # keystore" with no fallback, while section 4's inventory listed the control-API token as
        # "On disk, mode 0600". One document, two rules, the table describing the fallback as
        # though it were the rule -- the same shape already corrected in this file for Private
        # Mode's ephemeral profile, recurring after that lesson.
        "label": "the keystore fallback is stated where it applies",
        "files": ["docs/spec/PRIVACY.md"],
        "absent": re.compile(r"\| Control-API bearer token \| On disk, mode"),
        "note": (
            "Constitution Article 6 puts secrets in the platform keystore. Where none exists the "
            "control-API token alone may fall back to a 0600 file, and the client must say so."
        ),
    },
    {
        # Articles 29.5.d and 31.1 both require a log anchor in every record and no field carries
        # one. The gap is acknowledged in both documents an implementer would look in, and a
        # rule that only required it in one would let the other quietly stop saying it.
        "label": "the missing log anchor is acknowledged",
        "files": ["docs/spec/PROOF-OF-WORK.md", "docs/spec/REGISTRY.md"],
        "present": re.compile(r"log anchor"),
        "note": (
            "Article 31.1 binds the proof to three things and the schema delivers two. Closing "
            "it is a VWIP; leaving it unstated is how an implementer concludes the third was "
            "never required."
        ),
    },
    {
        # LOCAL-SURFACE.md section 4 specified the behaviour of a cross-name subresource
        # allowance that CONTENT-SECURITY.md 2.3's closed list does not contain, and whose
        # section 1 names it FIRST among the widenings that revalue every unfixable
        # fingerprinting vector. It escaped check-headers.py because that gate compares fenced
        # canonical blocks and this section quoted none. Same rule PUBLISHING.md broke with
        # inline hashes: a relaxation not in the table does not exist.
        "label": "there is no cross-name subresource allowance",
        "files": ["docs/spec/LOCAL-SURFACE.md", "docs/spec/CONTENT-SECURITY.md"],
        "absent": re.compile(
            r"Where `allow_cross_name_subresources` is offered"
            r"|MUST widen only `img-src`"),
        "note": (
            "CONTENT-SECURITY.md 2.3 closes the list of relaxations; specifying how a forbidden "
            "setting would behave is how a forbidden setting acquires an implementation."
        ),
    },
    {
        # PRIVACY.md's mode table said Private Mode's browser is "Contained, because full-proxy
        # configuration and the client's own webview are mandatory". CONTENT-SECURITY.md 5.5
        # makes the webview one of two permitted configurations, and 5.1 says WebRTC ignores the
        # HTTP proxy entirely -- so neither stated reason delivers containment under a locked
        # third-party profile. A summary asserting the strongest configuration's property, in a
        # document whose section 11 exists to list what it does not claim.
        "label": "Private Mode narrows the browser rather than containing it",
        "files": ["docs/spec/PRIVACY.md"],
        "absent": re.compile(
            r"Contained\*?\*?, because full-proxy|own webview are mandatory"),
        "note": (
            "CONTENT-SECURITY.md 5.5: 'the client's own webview OR a locked browser profile'. "
            "5.1: WebRTC 'ignores the HTTP proxy entirely, so full-proxy mode does not contain "
            "it either'."
        ),
    },
    {
        # RESOLUTION.md defined a passthrough mode; LOCAL-SURFACE.md required every non-VayuWeb
        # Host rejected before routing and never mentioned the word. An implementer reading one
        # built a proxy that cannot do browser-integration option 2; one reading the other built
        # an open relay. Both conformed, which is what makes this the audit's recurring shape.
        "label": "passthrough is carved out, not silently contradicted",
        "files": ["docs/spec/LOCAL-SURFACE.md", "docs/spec/RESOLUTION.md"],
        "present": re.compile(r"passthrough"),
        "note": (
            "LOCAL-SURFACE.md 2.1.1 states the carve-out and its four constraints; RESOLUTION.md "
            "step 3 references it. Neither may describe the mode without the other."
        ),
    },
    {
        # Three documents attached a signature to the checkpoint that REGISTRY.md and the code
        # deliberately leave unsigned. CRYPTO-AGILITY.md's version was the sharpest: it made the
        # anchoring mechanism rest on a signature two sentences after arguing that anchoring must
        # rest on hashes because signatures do not survive a quantum adversary.
        "label": "checkpoints are unsigned",
        "files": [
            "docs/spec/REGISTRY.md",
            "docs/spec/PROOF-OF-WORK.md",
            "docs/spec/CRYPTO-AGILITY.md",
        ],
        # Three spellings, because the three documents each had their own. The last is the
        # literal CRYPTO-AGILITY.md used, and a length-bounded pattern missed it -- the clause
        # puts 45 characters between "checkpoints" and ", signed", so a {0,40} window read as
        # generous was not.
        "absent": re.compile(
            r"signed (?:local )?checkpoint"
            r"|checkpoints?[^.]{0,80}?, signed"
            r"|signed under the then-current suite"),
        "note": (
            "REGISTRY.md: a checkpoint 'is not an authority and carries no signature that would "
            "make it one'. Anyone derives it from the same log, so trusting one is recomputing "
            "it, and a signature would turn it into an attestation instead."
        ),
    },
    {
        # ARCHITECTURE.md gave the IPNS-to-CID cache 300 seconds against RESOLUTION.md's 120,
        # with rationales arguing for opposite numbers -- and the 300 was not a mislabelled
        # reference to the record cache, which is separately 300 in the same list. An overview
        # that invents a figure the specification already sets is the overview's defect, so the
        # rule is that only the specification states it.
        "label": "the IPNS pointer cache lifetime",
        "files": ["docs/spec/RESOLUTION.md", "docs/ARCHITECTURE.md"],
        "present": re.compile(r"min\(record validity, 120 seconds\)"),
        "absent": re.compile(r"IPNS-to-CID mapping for 300 seconds"),
        "note": (
            "RESOLUTION.md sets the three cache lifetimes and their reasons; ARCHITECTURE.md is "
            "an overview and references them."
        ),
    },
    {
        # A count rule only fires when a claim it can PARSE disagrees. Delete the number and the
        # claim goes unchecked -- which is how the overstatement below survived the first
        # mutation of the residual-channel count untouched. This forbids the overstatement itself.
        "label": "the residual channels are not all closed",
        "files": [
            "docs/spec/CONTENT-SECURITY.md",
            "docs/spec/VWIP-0001.md",
            "docs/spec/RESOLUTION.md",
        ],
        # Both spellings: RESOLUTION.md carried the singular, so a rule matching only the plural
        # left the third copy of the same overstatement standing.
        "absent": re.compile(r"what closes (?:them|it) instead"),
        "note": (
            "Section 5.7 says 'Not closable, and not claimed' and 5.8 says 'Complete and "
            "irreducible'; four more are narrowed by a control that cannot be enforced in a "
            "third-party browser. A summary promising a remedy for all eight is the failure "
            "section 5 opens by naming."
        ),
    },
    {
        # No positive counterpart: this is a rule that must not be stated, anywhere. A count rule
        # catches a wrong NUMBER of two-letter extensions; only this catches a sentence that
        # rejects all sixty of them while the Annex three sections away ratifies them.
        "label": "two-letter extensions are ratified, not refused",
        "files": ["docs/spec/NAMESPACE.md", "docs/spec/NAMES.md"],
        "absent": re.compile(r"^\s*\d+\. A two-(?:character|letter) extension[^\n]*rejected", re.M),
        "note": (
            "The Annex ratifies 60 of them and VWIP-0004's collision review turns on that number. "
            "NAMESPACE.md section 5.3 holds that a two-letter string is a string and a country "
            "*name* is what constitutes a claim."
        ),
    },
    {
        "label": "the TLD production",
        "files": ["docs/spec/NAMES.md", "docs/spec/URI-SCHEME.md"],
        "present": re.compile(r"tld\s+= %x61-7A \*11\( %x61-7A / %x30-39 \)"),
        # The letters-only spelling, in an ABNF line rather than in prose recording it.
        "absent": re.compile(r"^tld\s+= 2\*12", re.M),
        "note": (
            "URI-SCHEME.md once read `tld = 2*12( %x61-7A )` -- letters only -- which is not a "
            "narrower restatement of NAMES.md's rule but a different one. It excluded `.p2p`, a "
            "TLD Article 35.1 names in its own text, so a parser built from one document could "
            "not address a founding extension a resolver built from the other resolves."
        ),
    },
]


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
        "label": "executable conformance tests",
        "derive": count_conformance_tests,
        "source": "CONTENT-SECURITY.md section 6 plus PRIVACY.md section 10",
        "patterns": [
            re.compile(r"\*\*([\w]+)\*\* executable tests", re.I),
        ],
    },
    {
        "label": "residual channels no header can close",
        "derive": count_residual_channels,
        "source": "docs/spec/CONTENT-SECURITY.md section 5",
        "patterns": [
            re.compile(r"the \*\*([\w]+)\*\*\s+channels no\s+header can close", re.I),
            re.compile(r"naming the ([\w]+)\s+channels CSP cannot close", re.I),
            re.compile(r"\*\*([\w]+)\*\* channels are not closable by CSP", re.I),
            re.compile(r"\b([\w]+) channels, and they are not all of a kind\b", re.I),
        ],
    },
    {
        "label": "conflicts held open for an amendment",
        "derive": count_open_conflicts,
        "source": "scripts/check-charter-consistency.py",
        "patterns": [
            re.compile(r"\*\*([\w]+) conflicts\*\* are now held open", re.I),
            re.compile(r"\*\*([\w]+) conflicts are held open\*\*", re.I),
        ],
    },
    {
        "label": "record-verification vectors",
        "derive": count_record_vectors,
        "source": "conformance/vectors.json",
        "patterns": [
            re.compile(r"`vectors` holds ([\w,]+) record-verification vectors", re.I),
        ],
    },
    {
        "label": "conformance vector suites",
        "derive": count_vector_suites,
        "source": "conformance/vectors.json",
        "patterns": [
            re.compile(r"[Tt]he file carries ([\w]+) suites", re.I),
            re.compile(r"\*\*([\w]+) suites\*\*, in \[`conformance/vectors\.json`\]", re.I),
        ],
    },
    {
        "label": "two-letter extensions",
        "derive": count_two_letter_tlds,
        "source": "docs/spec/NAMESPACE-CATALOGUE.md (the Namespace Annex)",
        "patterns": [
            re.compile(r"\bcontains ([\w,]+) two-letter extensions\b", re.I),
            re.compile(r"\bAnnex ratifies \*\*([\w,]+)\*\* two-letter\b", re.I),
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


def check_evidence_self_count(failures):
    """The one claim inside an evidence file that this checker still has to verify.

    `docs/AUDIT-FINDINGS.md` is in EVIDENCE_FILES and is therefore skipped by every rule that
    walks the corpus, for the reason recorded there: it quotes defects verbatim, so a check for a
    defect fails on the document reporting it. That exclusion is right and is not weakened here.

    But its disposition section makes a claim about its OWN structure -- how many MEDIUM findings
    have no disposition row -- and that is not a quoted defect, it is a count like any other. The
    first version of the sentence said eight; the answer was six. A number asserted from memory,
    in the file that exists to stop numbers being asserted from memory.

    So this one claim is read directly rather than through `markdown_files()`, and it is the only
    thing here that reaches into an evidence file. Adding a second would mean the exclusion had
    stopped meaning anything.
    """
    rel = "docs/AUDIT-FINDINGS.md"
    text = read(rel)
    if text is None:
        failures.append(f"{rel} is missing")
        return 0
    marker = "## Disposition — MEDIUM and LOW"
    end = "**Every HIGH, MEDIUM and LOW finding now carries an outcome.**"
    if marker not in text or end not in text:
        failures.append(f"{rel}: could not locate the disposition table -- its format changed")
        return 0
    table = text[text.index(marker):text.index(end)]
    triaged = set(re.findall(r"^\| `([^`]+)`", table, re.M))
    heads = re.findall(r"^## (.+?) — MEDIUM$", text, re.M)
    if not heads:
        failures.append(f"{rel}: no MEDIUM findings parsed -- the heading format changed")
        return 0
    actual = len([h for h in heads if h not in triaged])

    claim = re.search(r"implying: ([\w]+) MEDIUM", text)
    if claim is None:
        failures.append(f"{rel}: the untriaged-count sentence is gone -- restore it or drop this "
                        f"check, but do not leave the number unstated")
        return 0
    stated = NUMBER_WORDS.get(claim.group(1).lower())
    if stated is None:
        failures.append(f"{rel}: could not read a number from '{claim.group(1)}'")
        return 0
    if stated != actual:
        failures.append(
            f"{rel}: says {stated} untriaged MEDIUM finding(s); {actual} have no disposition row")
        return 0
    print(f"derived: {actual} untriaged MEDIUM finding(s) (from {rel}'s own headings and table)")
    return 1


def check_agreements(failures):
    """Each paired statement must be present in every listed file, and its withdrawn form absent.

    Both halves matter. Requiring only the presence lets the old rule sit two paragraphs below
    the new one, which is exactly how a document ends up saying both things; requiring only the
    absence lets a document drop the subject entirely and look compliant by silence.

    The `absent` pattern is applied to the text with quoted spans removed, so that a paragraph
    recording what was withdrawn -- which has to quote it -- is not itself a violation.
    """
    checked = 0
    for item in AGREEMENTS:
        if item.get("present") is None and item.get("absent") is None:
            failures.append(
                f"{item['label']}: has neither a `present` nor an `absent` pattern, so it "
                f"enforces nothing")
            continue
        for rel in item["files"]:
            text = read(rel)
            if text is None:
                failures.append(f"{item['label']}: {rel} is missing")
                continue
            present = item.get("present")
            if present is not None and present.search(text) is None:
                failures.append(
                    f"{rel}: does not carry the settled rule '{item['label']}'. If it was "
                    f"amended, update this check in the same commit; if the other document was "
                    f"fixed and this one was not, that is the defect this rule exists for. "
                    f"{item['note']}")
                continue
            absent = item.get("absent")
            if absent is None:
                # Some rules are purely positive: the statement must be present in every listed
                # document, with no withdrawn form to forbid. `present` is likewise optional for
                # the mirror case. A rule with neither would check nothing, and is refused below.
                checked += 1
                continue
            unquoted = re.sub(r'"[^"]*"|\*\*[^*]+\*\*', " ", text)
            stale = absent.search(unquoted)
            if stale is not None:
                failures.append(
                    f"{rel}: still states '{stale.group(0)}' outside a quotation, against "
                    f"'{item['label']}'. {item['note']}")
                continue
            checked += 1
    return checked


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

    agreed = check_agreements(failures)
    checked += check_evidence_self_count(failures)

    if failures:
        print(f"\n{len(failures)} counted claim(s) disagree with their source:\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    if agreed == 0:
        print("::error::no paired statement checked -- that half is enforcing nothing",
              file=sys.stderr)
        return 1

    print(f"\nOK -- {checked} counted claim(s) agree with the source that defines them, and "
          f"{agreed} paired statement(s) agree across documents.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
