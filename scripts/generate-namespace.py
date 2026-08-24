#!/usr/bin/env python3
"""Generate the ratified TLD set from the Namespace Annex, or verify the checked-in copy.

Constitution Article 35.1 incorporates `docs/spec/NAMESPACE-CATALOGUE.md` by reference, so the
Annex is the single source of truth for which extensions exist. Article 2.31 forbids a Node from
fetching that set at run time — a namespace that arrives over the network is a namespace someone
can withhold — so the verifier has to carry it, and carrying it means a copy that can drift.

This script is the answer to the drift. It parses the Annex and emits
`registry/src/namespace.generated.ts` **and** `client/src/namespace_generated.rs`; `--check`
regenerates in memory and fails if either checked-in file differs by a byte. Two languages carry
the set because the desktop client decides label validity for itself, without asking the
registry, so a copy that drifts on either side is a namespace fork presenting as an
intermittent failure of a different program. The generated files are committed rather than
built on demand because a conformance-critical constant produced by a build step is a constant
nobody reviews in a diff.

    python3 scripts/generate-namespace.py            # write both files
    python3 scripts/generate-namespace.py --check    # fail if either is stale

Every entry is validated against the TLD grammar of docs/spec/NAMES.md on the way through. A
malformed Annex row is a hard failure here rather than a name nobody can register later: the
previous revision of this corpus shipped a founding extension that violated its own ABNF, and the
only reason it was caught is that somebody implemented the grammar.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANNEX = os.path.join(ROOT, "docs", "spec", "NAMESPACE-CATALOGUE.md")
GENERATED = os.path.join(ROOT, "registry", "src", "namespace.generated.ts")
RUST_GENERATED = os.path.join(ROOT, "client", "src", "namespace_generated.rs")

# `| `.example` | who registers it |` — the one row shape the Annex uses.
ROW = re.compile(r"^\| `\.([a-z0-9-]+)` \|", re.M)
SECTION_COUNT = re.compile(r"^\*(\d+) extensions?\*$", re.M)
HEADLINE = re.compile(r"^\*\*(\d+) ratified extensions\*\*", re.M)

# docs/spec/NAMES.md: tld = ALPHA *11(ALPHA / DIGIT), two to twelve characters. The leading-letter
# rule is what keeps a TLD from being read as a number by anything downstream.
TLD_GRAMMAR = re.compile(r"^[a-z][a-z0-9]{1,11}$")

# Article 35.1 names these in the charter text itself, so that the founding set survives loss of
# the Annex. If the Annex ever fails to contain one, the two disagree and the charter wins.
NAMED_IN_CHARTER = [
    "vayu", "p2p", "free", "decent", "libre", "sov", "dao", "indie", "open", "news", "blog",
]

HEADER = """/**
 * The ratified top-level domains — GENERATED, do not edit by hand.
 *
 * Source of truth: docs/spec/NAMESPACE-CATALOGUE.md, the Namespace Annex incorporated into
 * Constitution Article 35.1 by reference. Regenerate with:
 *
 *     python3 scripts/generate-namespace.py
 *
 * `scripts/generate-namespace.py --check` runs in CI and fails if this file has drifted from the
 * Annex. Editing it directly does not change the namespace; it only makes this copy wrong, and
 * a copy that is wrong by one entry accepts names other implementations reject, which is a
 * namespace fork presenting as an intermittent resolution failure.
 *
 * Article 2.31: a Node decides TLD validity from the copy it holds, computed offline, with no
 * query to any party. That is why this set is compiled in rather than fetched.
 */

/** Every ratified extension, sorted, exactly as enumerated in the Namespace Annex. */
export const NAMESPACE_ANNEX: readonly string[] = [
"""

FOOTER = """];

/** How many extensions the Annex ratifies. Stated so a miscount is a failing test. */
export const NAMESPACE_ANNEX_SIZE = %d;
"""

# The Rust copy carries the same prose argument, because the file a Rust reader opens is the one
# they will consult about why the set is compiled in rather than fetched.
RUST_HEADER = """//! The ratified top-level domains — GENERATED, do not edit by hand.
//!
//! Source of truth: docs/spec/NAMESPACE-CATALOGUE.md, the Namespace Annex incorporated into
//! Constitution Article 35.1 by reference. Regenerate both copies of this constant with
//! `python3 scripts/generate-namespace.py`.
//!
//! `scripts/generate-namespace.py --check` runs in CI and fails if either checked-in copy has
//! drifted from the Annex. Editing this file directly does not change the namespace; it only
//! makes this copy wrong, and a copy that is wrong by one entry accepts names other
//! implementations reject, which is a namespace fork presenting as an intermittent resolution
//! failure.
//!
//! Article 2.31: a Node decides TLD validity from the copy it holds, computed offline, with no
//! query to any party. That is why this set is compiled in rather than fetched.

/// Every ratified extension, sorted, exactly as enumerated in the Namespace Annex.
///
/// `large_const_arrays` is allowed because GENERATED code is not hand-shaped to suit a lint:
/// the array is a literal transcription of the Annex, and making it a `static` would change
/// what the file IS (a compile-time constant table) to silence a style rule.
#[rustfmt::skip]
#[allow(clippy::large_const_arrays)]
pub const NAMESPACE_ANNEX: [&str; %(size)d] = [
"""

RUST_FOOTER = """];

/// How many extensions the Annex ratifies. Stated so a miscount is a failing test.
pub const NAMESPACE_ANNEX_SIZE: usize = %(size)d;
"""


def parse_annex(text):
    """Return the sorted extension list, or raise ValueError describing the first defect."""
    rows = ROW.findall(text)
    if not rows:
        raise ValueError("no extension rows found — has the Annex table format changed?")

    seen = {}
    for index, entry in enumerate(rows):
        if entry in seen:
            raise ValueError(
                f"`.{entry}` is listed twice (rows {seen[entry] + 1} and {index + 1}). A "
                f"duplicate silently shrinks the namespace: this exact defect once made a list "
                f"introduced as twelve hold eleven distinct entries.")
        seen[entry] = index
        if not TLD_GRAMMAR.match(entry):
            raise ValueError(
                f"`.{entry}` does not satisfy the TLD grammar of docs/spec/NAMES.md "
                f"(ALPHA *11(ALPHA / DIGIT), 2-12 characters)")

    declared = [int(value) for value in SECTION_COUNT.findall(text)]
    if sum(declared) != len(rows):
        raise ValueError(
            f"the per-section counts sum to {sum(declared)} but there are {len(rows)} rows — "
            f"a section heading and its table disagree")

    headline = HEADLINE.search(text)
    if headline is None:
        raise ValueError("the Annex does not state its own size in the form "
                         "`**N ratified extensions**`")
    if int(headline.group(1)) != len(rows):
        raise ValueError(
            f"the Annex says {headline.group(1)} ratified extensions and lists {len(rows)}")

    missing = [tld for tld in NAMED_IN_CHARTER if tld not in seen]
    if missing:
        raise ValueError(
            "the Annex omits extensions named in the text of Constitution Article 35.1: "
            + ", ".join(f".{tld}" for tld in missing)
            + ". The charter names them so the founding set survives loss of this file, so an "
              "Annex without them contradicts the Article that incorporates it.")

    return sorted(seen)


def render(entries):
    body = "".join(f"  '{entry}',\n" for entry in entries)
    return HEADER + body + (FOOTER % len(entries))


def render_rust(entries):
    body = "".join(f'    "{entry}",\n' for entry in entries)
    return (RUST_HEADER % {"size": len(entries)}) + body + (RUST_FOOTER % {"size": len(entries)})


def main():
    check = "--check" in sys.argv[1:]

    with open(ANNEX, encoding="utf-8") as handle:
        text = handle.read()

    try:
        entries = parse_annex(text)
    except ValueError as error:
        print(f"::error::Namespace Annex is malformed: {error}", file=sys.stderr)
        return 1

    rendered = render(entries)
    rust_rendered = render_rust(entries)

    if not check:
        # newline="\n": a Python text-mode write translates to \r\n on Windows, which would make
        # both generated files differ from their committed LF form on every regeneration and
        # leave --check green only on the platform that produced them.
        with open(GENERATED, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
        with open(RUST_GENERATED, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(rust_rendered)
        print(f"wrote {os.path.relpath(GENERATED, ROOT)} and "
              f"{os.path.relpath(RUST_GENERATED, ROOT)} — {len(entries)} ratified extensions")
        return 0

    for path, expected in ((GENERATED, rendered), (RUST_GENERATED, rust_rendered)):
        rel = os.path.relpath(path, ROOT)
        if not os.path.exists(path):
            print(f"::error::{rel} does not exist. Run "
                  f"`python3 scripts/generate-namespace.py`.", file=sys.stderr)
            return 1

        with open(path, encoding="utf-8") as handle:
            current = handle.read()

        if current == expected:
            continue

        print(f"::error::{rel} has drifted from the Namespace Annex. Run "
              f"`python3 scripts/generate-namespace.py` and commit the result.", file=sys.stderr)
        if path is GENERATED:
            current_set = set(re.findall(r"^  '([a-z0-9]+)',$", current, re.M))
            for entry in sorted(set(entries) - current_set):
                print(f"  in the Annex, missing from the generated file: .{entry}", file=sys.stderr)
            for entry in sorted(current_set - set(entries)):
                print(f"  in the generated file, missing from the Annex: .{entry}", file=sys.stderr)
        else:
            # The Rust literal is a second copy of one list; a per-entry diff names the side that
            # moved rather than leaving two files whose disagreement has no explanation.
            def literals(text):
                return re.findall(r'^    "([a-z0-9]+)",$', text, re.M)
            for entry in sorted(set(entries) - set(literals(current))):
                print(f"  in the Annex, missing from the generated file: .{entry}", file=sys.stderr)
            for entry in sorted(set(literals(current)) - set(entries)):
                print(f"  in the generated file, missing from the Annex: .{entry}", file=sys.stderr)
        return 1

    print(f"OK — {len(entries)} ratified extensions; both generated files match the Annex.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
