#!/usr/bin/env python3
"""Require the corpus to agree on what each local listener IS, not merely where it is.

The resolver exposes two local surfaces of deliberately different KINDS. The browsing proxy is
TCP on 127.0.0.1:7654, because a browser has to reach it. The control API is a Unix domain socket
(a named pipe on Windows), because a browser must never reach it: no fetch, form, img, WebSocket
or XMLHttpRequest can name a socket, so moving the privileged surface off TCP deletes DNS
rebinding, CSRF, WebSocket Upgrade reach and browser port scanning outright, rather than requiring
a correct defence against each one forever.

That decision was made in LOCAL-SURFACE.md section 1 and landed NOWHERE ELSE. Five documents went
on describing the control API as `127.0.0.1:7653` — including RESOLUTION.md, which carried the
endpoint table an implementer would actually build from, and ARCHITECTURE.md, which attached a
normative SHALL to the forbidden transport. An implementer reading top-to-bottom would have built
the listener the security model forbids, and every existing check passed throughout, because each
compares prose to a list or a number to its source and none asked what KIND of thing a listener is.

## Why this check is three exact rules and not a smarter one

The first version of this script tried to be clever: find every mention of the control API, look
for an address within a couple of hundred characters, and decide from the surrounding words
whether the sentence was specifying the binding or retiring it. It was mutation-tested three
times and survived none of them cleanly. Proximity cannot separate "specifies" from "retires"
when a document legitimately contains both in one paragraph — which every corrected document now
does, because correcting them meant writing down what they used to say.

Each patch made it worse in the usual way: the escape hatch that stopped the false positive also
opened the door for the mutation. A window wide enough to catch the association was wide enough
to catch the historical note excusing it.

So the shape changed. The rules below are exact string tests with no windows, no distances and no
inference about intent. They are narrower than the heuristic pretended to be, and unlike it, they
hold.

## What this does NOT prove

It does not detect a document that puts the control API on the *proxy's* port, or on a port this
script has never heard of, phrased in prose that avoids `127.0.0.1`. Rule 2 makes that unlikely by
requiring the socket sentence where it matters most, but the gap is real and is stated rather than
papered over. A check that claims more than it does is worse than a narrow one.

    python3 scripts/check-listeners.py [root]
"""
import os
import re
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", ".venv", "venv"}

# The port the control API used to be specified on, and must never be specified on again.
RETIRED_CONTROL_PORT = "7653"

# The one port the browsing proxy binds.
PROXY_PORT = "7654"

# Files permitted to contain the retired port, each with the reason. A short named list rather
# than a pattern: a wildcard would let any future file opt out by its name, which is how a gate
# quietly stops gating. Every entry here is a document whose *job* is to record what was wrong.
RETIRED_PORT_ALLOWED = {
    "docs/AUDIT-FINDINGS.md":
        "reproduces the defect verbatim as the evidence for the finding; an audit record that "
        "paraphrases its evidence is not evidence.",
    "CHANGELOG.md":
        "records what the specifications used to say, which cannot be done without saying it.",
    "docs/spec/RESOLUTION.md":
        "carries one paragraph naming the superseded address in order to retire it, because this "
        "is the document an implementer would have built the wrong listener from.",
    "docs/ARCHITECTURE.md":
        "same, for the section that attached a normative SHALL to the forbidden transport.",
    "scripts/check-listeners.py":
        "this file.",
    "registry/src/control.ts":
        "assertSocketAddress names the refused address in the error it raises. A guard that "
        "refuses a value has to be able to say which value.",
    "registry/src/control.test.ts":
        "proves assertSocketAddress refuses the address, which cannot be done without naming "
        "it. This is the one test that must mention the retired port, and it is named rather "
        "than covered by a blanket test exemption — a blanket one would let a test specify 7653 "
        "as a live binding.",
    "docs/ROADMAP.md":
        "records that five documents specified the superseded address, as part of saying what "
        "Phase 3 had to clear before it could start.",
}

# The binding rule below fires on any loopback address that is not the proxy's. That is the right
# rule for prose and for production source, and the wrong rule for a test, whose job is to name
# hostile inputs: `127.0.0.1:22` in an SSRF case is a destination an attacker asks for, not a
# listener anyone opens. The sharp rule above still applies to tests, so a test naming the retired
# control port fails; only the broad one is relaxed.
TEST_FILE = re.compile(r"\.test\.[jt]s$|/tests?/")

# Documents that describe the control API normatively enough that a reader could build it, and
# must therefore carry the socket requirement rather than leave it to another file. This is the
# rule that would have caught the original regression: the decision landed in LOCAL-SURFACE.md
# and these three went on describing a TCP listener.
MUST_STATE_SOCKET = {
    "docs/spec/LOCAL-SURFACE.md",
    "docs/spec/RESOLUTION.md",
    "docs/ARCHITECTURE.md",
    "docs/GLOSSARY.md",
}

SOCKET_WORDING = re.compile(r"unix[- ]domain socket|unix socket|named pipe", re.I)
CONTROL = re.compile(r"control[ -]api|control surface|control listener", re.I)


def files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if not (name.endswith(".md") or name.endswith(".py") or name.endswith(".ts")):
                continue
            path = os.path.join(dirpath, name)
            yield os.path.relpath(path, ROOT).replace(os.sep, "/"), path


def main():
    failures = []
    checked_retired = 0
    checked_socket = 0
    proxy_bindings = 0

    seen = {}
    for rel, path in files():
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        seen[rel] = text

        # Rule 1. The retired port may appear only where a document's job is to record history.
        if RETIRED_CONTROL_PORT in text:
            checked_retired += 1
            if rel not in RETIRED_PORT_ALLOWED:
                line = text[: text.index(RETIRED_CONTROL_PORT)].count("\n") + 1
                failures.append(
                    f"{rel}:{line}: mentions port {RETIRED_CONTROL_PORT}. The control API is a "
                    f"Unix domain socket and has no TCP port; LOCAL-SURFACE.md section 1 forbids "
                    f"one on any address including loopback. If this document must record the "
                    f"superseded address, add it to RETIRED_PORT_ALLOWED with the reason.")

        # Rule 3. Any loopback binding that is not the proxy's is a listener nobody specified.
        for match in re.finditer(r"127\.0\.0\.1:(\d+)", text):
            port = match.group(1)
            if port == PROXY_PORT:
                proxy_bindings += 1
            elif rel not in RETIRED_PORT_ALLOWED and not TEST_FILE.search(rel):
                line = text[: match.start()].count("\n") + 1
                failures.append(
                    f"{rel}:{line}: binds a loopback listener on port {port}. The browsing proxy "
                    f"on {PROXY_PORT} is the resolver's only TCP listener.")

    # Rule 2. A document that specifies the control API must say what kind of thing it is.
    for rel in sorted(MUST_STATE_SOCKET):
        text = seen.get(rel)
        if text is None:
            failures.append(f"{rel}: listed in MUST_STATE_SOCKET but not found — update this check")
            continue
        if CONTROL.search(text) is None:
            failures.append(
                f"{rel}: no longer mentions the control API. Either it moved, and this check "
                f"needs updating, or the corpus lost the description.")
            continue
        checked_socket += 1
        if SOCKET_WORDING.search(text) is None:
            failures.append(
                f"{rel}: describes the control API without stating that it is served on a Unix "
                f"domain socket. This is the exact shape of the regression this check exists "
                f"for: the socket decision was made in LOCAL-SURFACE.md and landed nowhere else, "
                f"so every other document went on specifying a TCP listener.")

    if checked_socket != len(MUST_STATE_SOCKET):
        print("::error::not every document that must state the socket was checked", file=sys.stderr)
        return 1
    if proxy_bindings == 0:
        print(f"::error::no document binds the proxy on 127.0.0.1:{PROXY_PORT} — either the port "
              f"moved and this check was not updated, or the corpus lost the statement",
              file=sys.stderr)
        return 1

    if failures:
        print(f"\n{len(failures)} listener failure(s):\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"OK — {checked_socket} document(s) state the control API is a Unix socket; "
          f"port {RETIRED_CONTROL_PORT} appears only in {checked_retired} history-bearing "
          f"file(s); {proxy_bindings} proxy binding(s), all on 127.0.0.1:{PROXY_PORT}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
