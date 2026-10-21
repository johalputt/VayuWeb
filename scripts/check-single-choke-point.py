#!/usr/bin/env python3
"""Require that one place opens a socket, and that the place is the one PRIVACY.md names.

PRIVACY.md section 3.1: "Every outbound byte — registry replication, peer discovery, content
fetch, and any future subsystem — MUST pass through **one** guarded transport constructor. No
component may open a socket by any other means." Section 10 item 6 asks for the other half of
that: "A build-time check that no code outside `egress` constructs a socket."

Neither half existed. There was no `egress` module in either implementation, and the one outbound
socket in the registry — the `sync --connect` peer connection — was opened inline in the command
that needed it, which is the shape the specification is written against. The section says why
that shape is dangerous: "The recurring failure in systems like this is not a broken guard — it is
a **new call site that never called the guard**, added a year later by someone who did not know
it existed." A guard with no check behind it is a convention; a guard with a check behind it is a
compile error.

So this check pins two things, and both of them are cheap to state exactly:

1. **The choke point exists.** `registry/src/egress.ts` must be there and must be where the
   socket is opened. A check that only forbade sockets would be satisfied by a tree that opened
   none, which is not the same claim.
2. **Nothing else opens one.** Every file in the shipping source of both implementations is
   scanned for the calls that open a socket, and a match outside the choke point is a failure.

## The rules are exact string tests, and that is deliberate

The first version of this idea was a heuristic: look for `net`, `socket`, `connect` and `dial`
anywhere in a file, and report a file that mentioned them outside a short allowlist. It would
have failed on `registry/src/proxy.ts`, whose `ContentPort` interface declares a method called
`fetch`, and on `registry/src/blockstore.ts`, whose `prefetch` function contains the letters
`fetch`. Both are not sockets. A check that reports those is a check whose author learns to skip
it, and a skipped check is the same as no check.

So the rules below are the exact call forms that open a socket, matched with no window and no
distance. Two of them need a little care, and the care is stated rather than assumed:

- `fetch(` is matched only where it is the **global** function — not preceded by a word
  character or a dot. `inner.fetch(...)` is a method on a collaborator, and `prefetch(` is a
  function whose name happens to end in those letters. A call written at the start of a line as
  `fetch(` is not distinguished from a declaration of the same name, because telling them apart
  needs a parser, and a parser here would be a parser to maintain forever. The declaration form
  is the only one in the tree today, and the false negative it buys is a call that begins its
  line — an unusual way to write one, and the kind of thing a reviewer sees.
- `TcpStream::connect` is matched with any suffix, so `connect_timeout` is caught too, and the
  client's `use std::net::{... TcpStream ...}` import is not: an import is not a socket.

## What this does NOT prove

It does not prove the guard is the right guard. It proves there is one place a socket is opened
and that the place is named. Whether that place's rules are correct is the work of the tests
beside it, and this script has no opinion on them.

It is accident and drift detection, not an enforcement of intent. A determined author can alias
`createConnection` to something else and open a socket through the alias, and this check will
not see it. What it does stop is the failure mode the specification names: a new call site,
written by someone who did not know the guard existed, that a check turns into a build failure.

It does not look at the test suites. `client/tests/vayu_serve.rs` opens sockets to talk to the
servers it is testing, and `registry/scripts/acceptance-browser.mjs` fetches from a stub it
started. A check that flagged those would be flagging the tests for testing.

    python3 scripts/check-single-choke-point.py [root]
"""
import os
import re
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SKIP_DIRS = {".git", "node_modules", "target", "dist", "build", ".venv", "venv"}

# The one file in each implementation that is allowed to open an outbound socket. The client has
# no outbound socket at all yet — the transport is Phase 4 — so its entry is the place one will
# have to be written, not a place that has one.
CHOKE_POINTS = {
    "registry/src/egress.ts": "the registry's guarded transport constructor",
    "client/src/egress.rs": "the client's guarded transport constructor",
}

# The choke point that must exist, and the call that must be inside it. Without this the check
# would be satisfied by a tree that opens no sockets at all, which is a different claim.
REQUIRED_CHOKE_POINT = "registry/src/egress.ts"
REQUIRED_CALL = "createConnection("

# The tree, and what is excluded from it. The exclusions are the test suites, and the reason is
# in the module docstring: a test that opens a socket to test a server is doing its job.
SCAN_TREES = [
    ("registry/src", (".ts",), ("*.test.ts",)),
    ("registry/bin", (".ts",), ()),
    ("client/src", (".rs",), ()),
]

# Calls that open an outbound socket, exactly.
TS_CALLS = [
    (re.compile(r"\bcreateConnection\("), "createConnection("),
    (re.compile(r"\bnet\.connect\("), "net.connect("),
    (re.compile(r"\bnew\s+Socket\("), "new Socket("),
    (re.compile(r"\bhttps?\.request\("), "http.request("),
    (re.compile(r"\bhttps?\.get\("), "http.get("),
    (re.compile(r"\bglobalThis\.fetch\("), "globalThis.fetch("),
    # The global `fetch`, and only the global one: not `inner.fetch(`, and not `prefetch(`.
    (re.compile(r"(?<![.\w])fetch\("), "fetch("),
]

RS_CALLS = [
    (re.compile(r"\bTcpStream::connect\w*\("), "TcpStream::connect("),
    (re.compile(r"\bUdpSocket::bind\("), "UdpSocket::bind("),
    (re.compile(r"\bTcpSocket::"), "TcpSocket::"),
    (re.compile(r"\breqwest::"), "reqwest::"),
    (re.compile(r"\bureq::"), "ureq::"),
]

# Lines that are allowed to open a socket outside the choke point, each with the reason it is
# not egress. The key is the file, the value is the exact text the line must contain.
ALLOWED_LINES = {
    "client/src/serve.rs": [
        # A loopback self-connect to unblock this process's own accept() loop. It never leaves
        # the machine and it carries nothing, but it is a socket and the check is about sockets.
        "TcpStream::connect(self.addr)",
    ],
}

# A declaration of a method or function named `fetch` is not a call to the global one. The
# exclusion is a line that begins with one, which is how a declaration is written.
DECLARATION = re.compile(r"^\s*fetch\s*\(")


def skipped(path):
    """Whether a path is excluded from the scan, and why it is not a violation."""
    parts = path.replace("\\", "/").split("/")
    if any(part in SKIP_DIRS for part in parts):
        return True
    name = parts[-1]
    return name.endswith(".test.ts") or name.endswith(".test.mjs")


def calls_for(path):
    """The call patterns that apply to a file, by its extension."""
    return RS_CALLS if path.endswith(".rs") else TS_CALLS


def scan_file(path, relative):
    """The outbound socket constructions in one file, outside the choke points."""
    found = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            found.extend(scan_file_line(line, relative, number))
    return found


def scan_file_line(line, relative, number=0):
    """The calls in one line of a file, with the file's exclusions applied.

    The self-test needs to ask about a single line, so this is the part of the scan that takes
    the line rather than the path, and everything that decides whether a line is a violation
    lives here: the choke point is exempt, the allowlist is honoured, and a declaration of a
    method named `fetch` is not a call to the global one.
    """
    if relative in CHOKE_POINTS:
        return []
    allowed = ALLOWED_LINES.get(relative, [])
    if any(text in line for text in allowed):
        return []
    found = []
    for pattern, name in calls_for(relative):
        if not pattern.search(line):
            continue
        if name == "fetch(" and DECLARATION.match(line):
            continue
        found.append((relative, number, name, line.strip()))
    return found


def scan_tree(root):
    """Every outbound socket construction in the shipping source of both implementations."""
    found = []
    for tree, extensions, excludes in SCAN_TREES:
        base = os.path.join(root, tree.replace("/", os.sep))
        if not os.path.isdir(base):
            continue
        for directory, subdirs, files in os.walk(base):
            subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS]
            for name in files:
                if not name.endswith(extensions):
                    continue
                path = os.path.join(directory, name)
                relative = os.path.relpath(path, root).replace("\\", "/")
                if any(relative.endswith(exclude) for exclude in excludes):
                    continue
                if skipped(relative):
                    continue
                found.extend(scan_file(path, relative))
    return found


def check_choke_point(root):
    """The choke point must exist, and the socket must be opened inside it."""
    problems = []
    path = os.path.join(root, REQUIRED_CHOKE_POINT.replace("/", os.sep))
    if not os.path.isfile(path):
        problems.append(
            f"{REQUIRED_CHOKE_POINT} is missing: PRIVACY.md 3.1 requires one guarded transport "
            "constructor, and a check that forbids sockets is satisfied by a tree that opens none"
        )
        return problems
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        source = handle.read()
    if REQUIRED_CALL not in source:
        problems.append(
            f"{REQUIRED_CHOKE_POINT} does not open a socket ({REQUIRED_CALL} is not in it), so it "
            "is not the choke point it is named as"
        )
    return problems


def self_test():
    """Prove the scanner and the reporting do what the prose above says.

    Run as `python3 scripts/check-single-choke-point.py --self-test`.
    """
    failures = []

    def check(label, condition, detail=""):
        if not condition:
            failures.append(f"{label}{(' -- ' + detail) if detail else ''}")

    # The false positives that killed the heuristic version.
    found = scan_file_line("  fetch(source: { type: string }, path: string): ContentResult;",
                           "registry/src/proxy.ts")
    check("a declaration of a method named fetch is not a call", found == [], str(found))

    found = scan_file_line("export async function prefetch(base: string): Promise<void> {",
                           "registry/src/blockstore.ts")
    check("a function whose name ends in fetch is not a call", found == [], str(found))

    found = scan_file_line("  const r = await inner.fetch(chosen, path);", "registry/src/cli.ts")
    check("a method call named fetch is not the global one", found == [], str(found))

    # The real positives.
    found = scan_file_line("  const socket = createConnection({ host, port });",
                           "registry/src/cli.ts")
    check("createConnection is a call", len(found) == 1, str(found))

    found = scan_file_line("  const r = await fetch('https://example.invalid/');",
                           "registry/src/whatever.ts")
    check("the global fetch is a call", len(found) == 1, str(found))

    found = scan_file_line("  let s = TcpStream::connect(addr);", "client/src/x.rs")
    check("a Rust connect is a call", len(found) == 1, str(found))

    found = scan_file_line("  let s = TcpStream::connect_timeout(addr, dur)?;", "client/src/x.rs")
    check("a Rust connect with a suffix is a call", len(found) == 1, str(found))

    found = scan_file_line("use std::net::{SocketAddr, TcpListener, TcpStream};",
                           "client/src/serve.rs")
    check("an import of a socket type is not a call", found == [], str(found))

    # The choke point itself is allowed to open a socket.
    found = scan_file_line("    const socket = createConnection({ host, port });",
                           "registry/src/egress.ts")
    check("the choke point may open a socket", found == [], str(found))

    # The allowlist, and only for the file it names.
    found = scan_file_line("        let _ = TcpStream::connect(self.addr);",
                           "client/src/serve.rs")
    check("the allowed line is allowed where it is listed", found == [], str(found))

    found = scan_file_line("        let _ = TcpStream::connect(self.addr);", "client/src/other.rs")
    check("the allowed line is not allowed elsewhere", len(found) == 1, str(found))

    if failures:
        for failure in failures:
            print(f"FAIL  {failure}")
        return 1
    print("OK  the self-test passed.")
    return 0


def main():
    if "--self-test" in sys.argv:
        return self_test()
    problems = check_choke_point(ROOT)
    for relative, number, name, line in scan_tree(ROOT):
        problems.append(
            f"{relative}:{number}: {name} opens a socket outside the choke point: {line}"
        )
    if problems:
        for problem in problems:
            print(f"FAIL  {problem}")
        print()
        print("PRIVACY.md 3.1: every outbound byte passes through one guarded transport")
        print("constructor. Put the socket in registry/src/egress.ts, or client/src/egress.rs")
        print("when the client grows one, and let that place meet the guard.")
        return 1
    print("OK  one place opens a socket, and it is the place PRIVACY.md names.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
