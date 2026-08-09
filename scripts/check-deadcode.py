#!/usr/bin/env python3
"""Refuse exported symbols that nothing imports and nothing tests.

An export is a promise: it says another module may depend on this. An export nobody uses is a
promise to nobody that still has to be kept working, still appears in the public surface, and
still has to be reasoned about by the next person. VayuPress gates this with
`scripts/deadcode-gate.sh`; this is the same rule for a TypeScript tree.

The bar is deliberately "imported somewhere OR named in a test". Something exercised only by
tests is not dead -- it is verified surface, and this project deliberately exports internals so
they can be attacked directly.

## Five ways this check was not doing its job

Every one was found by mutating it -- deliberately re-breaking the code after fixing the defect
before it -- and none by reading it. That matters, because the previous version reads perfectly
well.

**`export { X }` was not matched at all.** The pattern covered `export function`, `export const`
and their siblings, and a bare re-export statement is none of those. `fetch.ts` re-exporting
`ContentError` for no reason was not merely passed over, it was never examined. A gate that
silently declines to look at a whole syntactic form is worse than one that looks and is wrong,
because nothing in its output says so. Both `export { A, B as C }` and
`export { A } from './m.ts'` are now read, and it is the *exported* name that has to be used.

**A hit could come from anywhere.** Searching for the bare word across the corpus meant any
symbol sharing a name with something used elsewhere was invisible: an `export const sha256Helper`
counted as used because `sha256` appears in another module. The evidence has to be a dependency,
so a consuming file must both name the symbol and import from the module that defines it.

**A re-export could justify itself.** With both fixes in place the `ContentError` case still
passed, and this third cause is the one worth remembering: a re-export names its symbol twice in
the defining file -- once to import it, once to export it -- so the "used elsewhere in this file"
rule was satisfied by the re-export statement itself. That rule is right for a helper a module
uses internally and exactly wrong here, because a re-export exists for another module by
definition. Re-exported names therefore require an external dependent.

Fixing those three immediately surfaced a real one: `store.ts` re-exported `GRACE_SECONDS` and
`QUARANTINE_SECONDS`, which every consumer imports from `lifecycle.ts` instead. The re-export and
the import feeding it were both inert, and had been invisible the whole time.

**A doc comment counted as a use.** The in-file rule asked whether the symbol's name appeared more
than once in the defining file, over the raw text -- and a well-documented export names itself in
its own doc comment, which is the second occurrence. `swarm.ts`'s `joinSwarm`, the sole entry point
of the reference transport binding, was certified live on the strength of the sentence describing
it; nothing imported it and no test named it. Comments and string literals are therefore blanked
out before any name is counted. Import specifiers are strings, so the module-dependency test still
reads the untouched source -- stripping both at once fails ninety-two live exports and looks, from
the output alone, exactly like a real regression.

**And there was no floor.** Narrowing the export pattern so `function`, `const`, `interface` and
`type` were ignored dropped the corpus from 305 matches to 18 and still printed OK, because
nothing asked whether the number was plausible. A gate that has stopped matching is
indistinguishable from a gate with nothing to report unless it says how much it looked at.

    python3 scripts/check-deadcode.py [root]

Exits non-zero listing every unused export.
"""
import os
import re
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "registry", "src")
EXTRA_ROOTS = [
    os.path.join(ROOT, "registry", "bin"),
    os.path.join(ROOT, "registry", "scripts"),
]

# A floor on how many exports the patterns must find. Not a bound on the codebase: it is here so
# that a pattern which stops matching fails loudly instead of reporting a clean run over almost
# nothing. Today's corpus is a little over 300; a broken pattern drops it to double digits.
MINIMUM = 150

# Exports that no shipping code path reaches, each with the reason it is waiting rather than
# broken. Everything in this table was found by hand during one long session, and every entry that
# was NOT waiting turned out to be a defect: a spec MUST nothing could satisfy, a message type with
# no sender, a module whose whole job was to refuse and which nothing could ask.
#
# The bar above -- "imported somewhere OR named in a test" -- is deliberately generous and stays
# that way; a test-only export is verified surface, not dead code. This second question is
# different: it asks whether anything a *user* can reach ever gets there. An entry here is a
# promise that the answer is "not yet, and here is why", and the check fails when one goes stale.
REACHED_ONLY_BY_TESTS = {
    # The light-client half. A light client is a client; this package is a node.
    "checkpoint.ts:verifyNameInclusion":
        "REPLICATION.md 7.2's answer shape. Needs a client that holds no log -- Phase 5/7.",
    "checkpoint.ts:greatestCorroboratedLength":
        "Chooses a length to trust from several peers' claims. Same missing client.",
    "merkle.ts:proveInclusion":
        "The proof a light client checks. Nothing here produces one because nothing here asks.",
    # Block exchange: the wire format only, by design. VWIP-0005 is a Draft and ROADMAP.md says
    # code written before a specification settles is code that will be thrown away.
    "blockx.ts:decodeBlockMessage": "VWIP-0005 is Draft; the session and transport wait for it.",
    "blockx.ts:blocksReplyFor": "VWIP-0005 is Draft; no session exists to send a reply.",
    "blockx.ts:blockDoneFor": "VWIP-0005 is Draft; no session exists to end an exchange.",
    # The index keyspace. REGISTRY.md specifies it for Hyperbee; this store uses in-memory maps,
    # so only `currentKey` is reached, through the checkpoint's index root.
    "keys.ts:byOwnerKey": "Hyperbee keyspace; the in-memory index does not use it yet.",
    "keys.ts:byOwnerPrefix": "Hyperbee keyspace; the in-memory index does not use it yet.",
    "keys.ts:expiryKey": "Hyperbee keyspace; the in-memory index does not use it yet.",
    "keys.ts:expiryRange": "Hyperbee keyspace; the in-memory index does not use it yet.",
    "keys.ts:rateKey": "Hyperbee keyspace; the in-memory index does not use it yet.",
    "keys.ts:rateRange": "Hyperbee keyspace; the in-memory index does not use it yet.",
    "keys.ts:currentPrefix": "Hyperbee keyspace; the in-memory index does not use it yet.",
    "keys.ts:decodeCurrentKey": "Decoder for the keyspace above; nothing reads those keys back.",
    "keys.ts:decodeByOwnerKey": "Decoder for the keyspace above; nothing reads those keys back.",
    "keys.ts:decodeExpiryKey": "Decoder for the keyspace above; nothing reads those keys back.",
    "keys.ts:decodeRateKey": "Decoder for the keyspace above; nothing reads those keys back.",
    # Unpublishing. The endpoint that would use it is DELETE /v1/pin/{cid} and there is no mutable
    # pin set; building one so a constant has a caller would be this defect wearing a hat.
    "pins.ts:tombstonedBindingExpired": "Article 19.4's window; no unpin path exists to apply it.",
    # The Hyperswarm binding. Not a dependency -- installing it took the package to 601 resolved
    # packages against a ceiling of 40 -- so nothing here can call it, which is the design.
    "swarm.ts:joinSwarm": "Takes an injected Hyperswarm; this package deliberately has none.",
    # Tooling and library surface that is genuinely for callers outside this tree.
    "store.ts:writeLog": "Writes a log from scratch for tooling and tests; never used in service.",
    "blockstore.ts:prepareStoreDirectory": "For an embedder wiring Helia, which is not a dependency.",
    "blockstore.ts:prefetch": "Walks a tree over an async blockstore; needs the Helia this package does not depend on.",
    "blockstore.ts:publish": "Adds a built tree to an injected blockstore; same missing dependency.",
    "fetch.ts:blockSourceOf": "Adapts an async blockstore for an embedder; same missing dependency.",
    "blockx.ts:BLOCK_EXCHANGE_TOPIC_PREIMAGE": "VWIP-0005 is Draft; nothing joins that topic yet.",

    # Declared policy, checked against the code by a test. Not an island: the list IS the
    # specification of what the code does, and the test is what makes the two agree. Worth naming
    # rather than exempting silently, because a list only tests read is how a header nobody emits
    # came to be enumerated once already.
    "proxy.ts:FORBIDDEN_RESPONSE_HEADERS": "Policy list; a test asserts no response carries one.",
    "proxy.ts:DIAGNOSTIC_HEADERS": "Policy list; tests assert each is emitted when enabled and absent otherwise.",
    "replicate.ts:MESSAGE_TYPES": "Policy record; a test derives conformance coverage from it.",
    "blockx.ts:BLOCK_MESSAGE_TYPES": "Policy record; the same coverage test reads it.",
    "namespace.generated.ts:NAMESPACE_ANNEX_SIZE": "Generated count; a test pins it against the Annex.",

    # `UNPUBLISH_EFFECTS` was exempt here and is not any more: `release`, `revoke` and
    # `update --clear` render it, which Article 19.8 requires at the point unpublishing is offered.
    # The exemption was wrong about WHY it was waiting -- it named a missing pin endpoint, when what
    # it actually lacked was any command willing to say what unpublishing does. This gate's second
    # direction is what noticed, which is the whole argument for checking a table both ways.

    # **A second way to do something the shipping path does differently.** Not waiting on anything
    # — waiting on a decision. Each of these is a public function whose job is already done by
    # another one that ships, so either it has a caller nobody has written or it should go. Named
    # here so the next pass reconciles them rather than rediscovering them.
    "domain.ts:recordHash": "Hashes a parsed record; everything that ships hashes bytes with recordHashFromBytes.",
    "lifecycle.ts:resolves": "Asks whether a name resolves now; callers use stateAt and read the state.",
    "names.ts:isValidLabel": "Boolean form of labelRejection, which is what every caller uses.",
    "pow.ts:checkRecordPow": "Record-shaped wrapper over verifyPow, which is what the store calls.",
    "signature.ts:assertValidSignature": "Throwing form of verifyStrict, which is what every caller uses.",
    "signature.ts:isCanonicalScalar": "A component of the strict check, exported for direct attack.",
    "content.ts:rawLeafCid": "Convenience over cidFromBytes; the importer builds leaves itself.",
    "content.ts:fitsInOneLeaf": "Chunking predicate; unixfs.ts decides chunk boundaries inline.",
}

EXPORT = re.compile(
    r"^export\s+(?:async\s+)?(?:function|class|const|let|interface|type|enum)\s+([A-Za-z_$][\w$]*)",
    re.M,
)

# `export { A, B as C };` and `export { A } from './m.ts';`. A separate pattern because the
# declaration form above cannot express it, and its absence meant re-exports went unexamined.
REEXPORT = re.compile(r"^export\s+(?:type\s+)?\{([^}]*)\}", re.M)


# Tokens after which a `/` opens a regular expression rather than dividing. The list is the
# ordinary one: anything that cannot end an expression. Stated here so a reader can judge it,
# because the alternative -- a scanner that guesses silently -- is what this replaced.
CANNOT_END_EXPRESSION = set("(,=:[!&|?{};+-*%~^<>")
KEYWORDS_BEFORE_REGEX = {"return", "typeof", "case", "in", "of", "new", "delete", "void",
                         "instanceof", "do", "else", "yield", "await"}


def regex_can_start(emitted):
    """Would a `/` here open a regular expression?

    Judged from what has already been emitted, which is the scanned text with comments and strings
    already blanked -- so a slash inside a comment cannot influence the answer.
    """
    text = "".join(emitted)
    stripped = text.rstrip()
    if not stripped:
        return True
    last = stripped[-1]
    if last in CANNOT_END_EXPRESSION:
        return True
    word = re.search(r"[A-Za-z_$][\w$]*$", stripped)
    return word is not None and word.group(0) in KEYWORDS_BEFORE_REGEX


class StripError(Exception):
    """The scanner finished inside a string. See `strip_noise`."""


def strip_noise(text):
    """Blank out comments and string literals, preserving line numbers.

    Replacement is space-for-character rather than deletion so that every reported line number
    still points at the line it came from.

    ## Why this is a scanner and not a regular expression

    It was one alternation -- block comment, line comment, then each quote -- and **a regular
    expression whose character class contains a quote silently blanked lines of real code.**
    `serve.ts` has the RFC 7230 token class:

        if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) {

    The apostrophe in there is an ordinary character to JavaScript and the start of a string to an
    alternation that does not know what a regex literal is. It runs to the next apostrophe, several
    lines later, taking the backtick with it -- and the backtick after *that* opens what looks like
    a template literal, which blanks everything up to the following one. Seven lines of `serve.ts`
    disappeared, and with them the only call to `parseHead`, which is how the sole entry point of
    the request parser came to look like an export nothing reaches.

    That is the doc-comment failure this file already records, arriving from the other side: there,
    prose counted as code; here, code counted as prose. A checker that mis-reads its input is not
    conservative in either direction -- it is wrong, quietly, in whichever direction the input
    happens to push it.

    Two things follow, and both are here:

    **Template interpolations are kept**, because `${symbol}` is a use of `symbol` and blanking it
    would lose exactly the evidence this file counts.

    **A regex literal is recognised by what precedes it**, which is the only way to tell one from
    division in JavaScript: a `/` opens a regex when the last meaningful token cannot end an
    expression. The heuristic is stated rather than hidden, and the backstop is that the scan
    refuses to finish inside a string -- a file that ends mid-string has been mis-read, and
    {@link StripError} says so instead of returning a plausible answer.
    """
    out = []
    i = 0
    n = len(text)
    # Stack of open template literals, so `${ ... }` nesting is tracked rather than guessed at.
    template_depth = []
    brace_depth = 0

    def blank(chunk):
        out.append(re.sub(r"[^\n]", " ", chunk))

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            blank(text[i:end])
            i = end
            continue
        if ch == "/" and nxt == "/":
            end = text.find("\n", i)
            end = n if end == -1 else end
            blank(text[i:end])
            i = end
            continue
        if ch == "/" and regex_can_start(out):
            j = i + 1
            in_class = False
            while j < n:
                c = text[j]
                if c == "\\":
                    j += 2
                    continue
                if c == "[":
                    in_class = True
                elif c == "]":
                    in_class = False
                elif c == "/" and not in_class:
                    break
                elif c == "\n":
                    break
                j += 1
            if j < n and text[j] == "/":
                # Flags, which are identifier characters and must not be read as a name.
                k = j + 1
                while k < n and text[k].isalpha():
                    k += 1
                blank(text[i:k])
                i = k
                continue
            # Not a regex after all -- fall through and treat the slash as an ordinary character.
            out.append(ch)
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            j = i + 1
            while j < n and text[j] != quote and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            if j >= n or text[j] == "\n":
                raise StripError(f"unterminated {quote} string at offset {i}")
            blank(text[i : j + 1])
            i = j + 1
            continue
        if ch == "`":
            template_depth.append(brace_depth)
            out.append(" ")
            i += 1
            # Blank the literal parts and keep the interpolations, which are code.
            while i < n:
                if text[i] == "\\":
                    blank(text[i : i + 2])
                    i += 2
                    continue
                if text[i] == "`":
                    template_depth.pop()
                    out.append(" ")
                    i += 1
                    break
                if text[i] == "$" and i + 1 < n and text[i + 1] == "{":
                    out.append("  ")
                    i += 2
                    depth = 1
                    # Copy the interpolation through, verbatim, so names inside it are counted.
                    while i < n and depth > 0:
                        if text[i] == "{":
                            depth += 1
                        elif text[i] == "}":
                            depth -= 1
                            if depth == 0:
                                out.append(" ")
                                i += 1
                                break
                        out.append(text[i])
                        i += 1
                    continue
                blank(text[i])
                i += 1
            continue

        if ch == "{":
            brace_depth += 1
        elif ch == "}":
            brace_depth -= 1
        out.append(ch)
        i += 1

    if template_depth:
        raise StripError("file ends inside a template literal")
    return "".join(out)


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def exported_symbols(text):
    """Every name a file exports, as `(symbol, line, is_reexport)`.

    The third element matters: a re-export may not be justified by a mention in its own file,
    because that mention IS the export.
    """
    found = []
    for match in EXPORT.finditer(text):
        found.append((match.group(1), text[: match.start()].count("\n") + 1, False))
    for match in REEXPORT.finditer(text):
        line = text[: match.start()].count("\n") + 1
        for piece in match.group(1).split(","):
            piece = piece.strip()
            if not piece:
                continue
            # `B as C` exports C, so C is the name a consumer imports and therefore the name to
            # check. Taking B would ask whether the *source* symbol is used, which it always is.
            name = piece.split(" as ")[-1].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", name) and name != "default":
                found.append((name, line, True))
    return found


def depends_on(body, module_filename):
    """Does `body` import from the module in `module_filename`?

    Matched on the module specifier rather than on any mention of the name, because the point is
    to require a dependency and not a coincidence. Both `./foo.ts` and `../src/foo.ts` count; a
    bare mention of the word `foo` in prose does not.
    """
    return re.search(rf"""from\s+['"][^'"]*/{re.escape(module_filename)}['"]""", body) is not None


def ts_files(root):
    if not os.path.isdir(root):
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"node_modules", "dist"}]
        for name in sorted(filenames):
            if name.endswith(".ts"):
                yield os.path.join(dirpath, name)


def problems(islands, stale, table):
    """Every complaint the second question has, as lines. Empty means nothing to say.

    Extracted from `main` so it can be exercised directly. Three of this file's behaviours are
    invisible against today's corpus -- there is no stale exemption, no export referenced only
    inside a template interpolation, and no unterminated string -- so mutating each of them
    changed nothing and the mutation survived. A check whose branches cannot be observed is a
    check that is trusted rather than tested, which is the thing this file is for.
    """
    lines = []
    if islands:
        lines.append(f"{len(islands)} export(s) reached only by tests and not named:")
        lines.extend(f"  {i}" for i in islands)
        lines.append("  Connect it to something that ships, delete it, or add it to "
                     "REACHED_ONLY_BY_TESTS with the reason it is waiting.")
    for key in stale:
        lines.append(f"::error::REACHED_ONLY_BY_TESTS names '{key}', which is now reached by "
                     f"shipping code or no longer exists -- drop the entry: {table.get(key, '')}")
    return lines


def self_test():
    """Prove the scanner and the reporting do what the prose above says.

    Run as `python3 scripts/check-deadcode.py --self-test`.
    """
    failures = []

    def check(label, condition, detail=""):
        if not condition:
            failures.append(f"{label}{(' -- ' + detail) if detail else ''}")

    # The defect that started this: a regex whose character class holds a quote and a backtick.
    # Everything after it must survive, because that is where the call site lived.
    source = "const ok = /^[!#$%&'*+.^_`|~a-z-]+$/.test(name);\nconst used = parseHead(head);\n"
    scanned = strip_noise(source)
    check("a regex literal does not swallow the code after it", "parseHead" in scanned, scanned)
    check("and its own contents are not read as names", "test" in scanned)

    # Interpolations are code. Blanking them loses exactly the evidence this file counts.
    scanned = strip_noise("const s = `a ${symbolInside} b`;\n")
    check("a template interpolation is preserved", "symbolInside" in scanned, scanned)
    check("but the literal text around it is not", " a " not in scanned.replace("const s", ""))

    # An apostrophe in prose must not start a string, in either kind of comment.
    scanned = strip_noise("// it isn't a header\nconst x = realName;\n")
    check("an apostrophe in a line comment is inert", "realName" in scanned, scanned)
    scanned = strip_noise("/* it isn't a header */\nconst y = otherName;\n")
    check("an apostrophe in a block comment is inert", "otherName" in scanned, scanned)

    # Line numbers must survive, or every reported location is wrong.
    source = "const a = 1;\n// comment\nconst b = `x`;\nconst c = 2;\n"
    check("line numbers are preserved", strip_noise(source).count("\n") == source.count("\n"))

    # A file that ends mid-string has been mis-read, and saying so beats a plausible answer.
    try:
        strip_noise("const a = 'unterminated;\n")
        check("an unterminated string is refused", False, "no StripError raised")
    except StripError:
        pass

    # Division is not a regex. `a / b` must not eat the rest of the line.
    scanned = strip_noise("const half = total / divisor;\nconst after = stillHere;\n")
    check("division is not read as a regex", "stillHere" in scanned, scanned)

    # The reporting half, which has no stale entry in the real table to exercise it.
    check("an unnamed island is reported", problems(["a.ts:1: 'x'"], [], {}) != [])
    check("a stale exemption is reported",
          any("no longer exists" in line for line in problems([], ["a.ts:x"], {"a.ts:x": "why"})))
    check("and a clean run says nothing", problems([], [], {}) == [])

    for failure in failures:
        print(f"::error::self-test: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("OK -- self-test passed (9 cases over the scanner and the reporting).")
    return 0


def main():
    sources = [p for p in ts_files(SRC)]
    if not sources:
        print("::error::no source files found -- this check is enforcing nothing", file=sys.stderr)
        return 1

    consumers = list(sources)
    for extra in EXTRA_ROOTS:
        consumers.extend(ts_files(extra))
    # Two views of the same files. `corpus` has comments and string literals blanked, because a
    # mention of a symbol in prose is not a use of it. `raw` is untouched, because an import
    # specifier is a string literal and the dependency test below has to still see it.
    raw = {path: read(path) for path in consumers}
    corpus = {path: strip_noise(body) for path, body in raw.items()}

    unused = []
    islands = []
    claimed = set()
    total = 0

    for path in sources:
        name = os.path.basename(path)
        if name.endswith(".test.ts"):
            continue
        rel = os.path.relpath(path, ROOT)
        text = corpus[path]

        for symbol, line, is_reexport in exported_symbols(text):
            total += 1
            used = False
            # Tracked apart from `used`, because the two questions have different answers and the
            # second is the one that has found things. See REACHED_ONLY_BY_TESTS.
            ship_reached = False
            word = re.compile(rf"\b{re.escape(symbol)}\b")
            for other, body in corpus.items():
                if other == path:
                    # Within the defining file, a use elsewhere in that file counts too -- but
                    # never for a re-export, whose two mentions are the import and the export.
                    if is_reexport:
                        continue
                    if len(word.findall(body)) > 1:
                        used = True
                        ship_reached = True
                    continue
                # The name AND a dependency on the module that defines it. Without the second
                # half, a symbol whose name appears anywhere -- in an unrelated module, in a
                # comment, in another module's export of the same name -- counts as used, and the
                # check silently stops enforcing anything for that symbol.
                if word.search(body) and depends_on(raw[other], name):
                    used = True
                    if not os.path.basename(other).endswith(".test.ts"):
                        ship_reached = True
            if not used:
                unused.append(f"{rel}:{line}: '{symbol}' is exported but never imported or tested")
            elif not ship_reached:
                key = f"{name}:{symbol}"
                if key in REACHED_ONLY_BY_TESTS:
                    claimed.add(key)
                else:
                    islands.append(
                        f"{rel}:{line}: '{symbol}' is reached only by its own tests"
                    )

    print(f"checked {total} export(s) across {len(sources)} source file(s)")
    if total < MINIMUM:
        print(f"::error::only {total} export(s) matched, below the floor of {MINIMUM} -- the "
              f"export patterns have stopped matching rather than the code having shrunk",
              file=sys.stderr)
        return 1
    if unused:
        print(f"\n{len(unused)} unused export(s):\n", file=sys.stderr)
        for u in unused:
            print(f"  {u}", file=sys.stderr)
        print("\n  Either use it, test it, or stop exporting it.", file=sys.stderr)
        return 1

    stale = sorted(set(REACHED_ONLY_BY_TESTS) - claimed)
    complaints = problems(islands, stale, REACHED_ONLY_BY_TESTS)
    if complaints:
        print("", file=sys.stderr)
        for line in complaints:
            print(line, file=sys.stderr)
        return 1

    print(f"OK -- every export is imported or exercised by a test; "
          f"{len(claimed)} reached only by tests, each with a stated reason.")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else main())
