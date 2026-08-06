#!/usr/bin/env python3
"""Check the CI workflows themselves.

CI is the one place in this repository that runs with more authority than a reader has, so the
workflows are worth the same scrutiny as the protocol code. A compromised or over-permissioned
workflow can do everything a maintainer can, and it does it on every push without anyone
watching.

    python3 scripts/check-workflows.py [root]

Exits non-zero listing every violation.
"""
import os
import re
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")

# Actions published by GitHub itself, from repositories this project already trusts to run its
# checkout and toolchain. Everything else must be pinned to a commit SHA, because a mutable tag
# is a promise by a third party that they will not change what runs here.
FIRST_PARTY = ("actions/", "github/")

USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.M)
JOB = re.compile(r"^  ([a-zA-Z0-9_-]+):\s*$", re.M)
PERMISSIONS = re.compile(r"^permissions:\s*$", re.M)
WRITE_PERMISSION = re.compile(r"^\s+[a-z-]+:\s*write\s*$", re.M)
SECRET = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
PR_TARGET = re.compile(r"^\s*pull_request_target:", re.M)


CANCEL_EXPR = re.compile(r"^\s*cancel-in-progress:\s*(.*\$\{\{.*)$", re.M)


def workflow_files():
    if not os.path.isdir(WORKFLOWS):
        return
    for name in sorted(os.listdir(WORKFLOWS)):
        if name.endswith((".yml", ".yaml")):
            path = os.path.join(WORKFLOWS, name)
            yield os.path.relpath(path, ROOT), path


def main():
    violations = []
    checked = 0
    jobs = 0

    for rel, path in workflow_files():
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        checked += 1
        jobs += len(JOB.findall(text.split("jobs:", 1)[-1]))

        # 0. `cancel-in-progress` must be a literal, never an expression.
        #
        #    GitHub evaluates `${{ ... }}` there to a STRING, and every non-empty string is
        #    truthy — so `cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}` is `true`
        #    on main as well, and four workflows here carried exactly that while their comments
        #    said main runs are never superseded. It was not caught by reading, because the line
        #    says what it means to do. It was caught by a run on `main` being cancelled one
        #    second after the next push started, with no jobs recorded.
        #
        #    The working form puts the discriminator in the group: `github.sha` for main gives
        #    each commit a group of its own, so nothing can supersede it.
        for match in CANCEL_EXPR.finditer(text):
            violations.append(
                f"{rel}: `cancel-in-progress: {match.group(1).strip()}` is an expression. It "
                f"evaluates to a non-empty string, which is truthy, so the condition never "
                f"refuses — put the discriminator in `group:` instead")

        # 1. Every workflow states its permissions. Without the key, a workflow inherits the
        #    repository default, which on many repositories is write to everything.
        if PERMISSIONS.search(text) is None:
            violations.append(
                f"{rel}: no top-level `permissions:` block. Without one the workflow inherits "
                f"the repository default, which is not a decision anyone made here")

        # 2. Third-party actions are pinned to a commit SHA. A tag can be moved by whoever owns
        #    the action, and moving it changes what runs in this repository without a commit.
        for match in USES.finditer(text):
            ref = match.group(1)
            if ref.startswith(("./", "docker://")):
                continue
            if ref.startswith(FIRST_PARTY):
                continue
            if "@" not in ref or not re.fullmatch(r"[0-9a-f]{40}", ref.split("@", 1)[1]):
                line = text[:match.start()].count("\n") + 1
                violations.append(
                    f"{rel}:{line}: third-party action '{ref}' is not pinned to a commit SHA")

        # 3. pull_request_target runs with the base repository's secrets against a fork's code.
        #    It is the single most abused trigger in GitHub Actions.
        if PR_TARGET.search(text) is not None:
            violations.append(
                f"{rel}: uses `pull_request_target`, which runs with this repository's "
                f"credentials against code from a fork")

        # 4. The only secret this project needs is the automatic token. Anything else is a
        #    credential someone added, and it should be a visible decision rather than a
        #    surprise found while reading a workflow later.
        for match in SECRET.finditer(text):
            name = match.group(1)
            if name != "GITHUB_TOKEN":
                line = text[:match.start()].count("\n") + 1
                violations.append(f"{rel}:{line}: uses secret '{name}'")

        # 5. Write permission is allowed, but only where it is scoped to a job rather than
        #    granted to the whole workflow.
        head = text.split("jobs:", 1)[0]
        if WRITE_PERMISSION.search(head) is not None:
            violations.append(
                f"{rel}: grants a write permission at workflow level. Scope it to the one job "
                f"that needs it, so every other job in the file runs read-only")

    if checked == 0:
        print("::error::no workflows found — this check is enforcing nothing", file=sys.stderr)
        return 1

    print(f"checked {checked} workflow(s), {jobs} job(s)")
    if violations:
        print(f"\n{len(violations)} workflow violation(s):\n", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print("OK — workflows declare their permissions, pin third-party actions, use no "
          "credential beyond the automatic token, and cancel by group rather than by an "
          "expression that is always true.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
