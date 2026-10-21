#!/usr/bin/env python3
"""COST.md section 7 item 1, decided rather than trusted.

    "No code path in any implementation accepts, records, transfers or requires a payment."

The charter says the same thing in Article 7 -- "No Token, No Treasury, No Protocol Fee" -- and
Article 7.3 says why it is not a market: "Registration and renewal SHALL be priced in
computation, not in money. The cost SHALL be burned rather than collected."

Both statements were prose. Nothing decided them, so a payment integration could have been
added to either implementation in a commit that changed no rule and broke no test, and the
corpus would still have said the project takes no money. A guarantee nobody checks is a
preference.

**What this decides.** Two things a payment integration cannot arrive without:

  1. A package. Every payment provider ships a client library, and a client library is a
     dependency. The dependency set of both implementations is scanned for one.
  2. An API. A provider's name or one of its unmistakable calls appearing in the source.

**What this does not decide, and says so.** A determined author writes their own payment code
and calls it something else. This catches drift and accident, which is the honest failure mode,
and it is not a proof about the code's behaviour. The workflow that runs it says the same
thing in its own output.

**Why the vocabulary is narrow.** A greedy one would fail on the project's own words. This
repository says "payment" and "price" constantly and legitimately: the proof of work's
over-payment is a payment in COMPUTATION, which is what Article 7.3 requires, and "over-payment"
appears in both implementations. The namespace annex contains a TLD called "paddle" and
"checkout" and "invoice" and "treasury", all of them legitimate names. So the scan matches
providers and provider APIs -- the things that cannot be innocent -- and not the vocabulary of
the subject.

    python3 scripts/check-no-payment.py [root]

Exits non-zero listing every violation.
"""
import os
import re
import sys

ROOT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Where source lives, and what is not source. The two namespace files are generated from the
# Namespace Annex, whose entries are TLD names, and one of those names is a payment provider's
# product name. They are excluded for the same reason the specifications are excluded from the
# privileged-writer check: matching prose would fail on the very documents that forbid the
# thing, which is how a check teaches people to ignore it.
SOURCE_DIRS = (
    os.path.join("registry", "src"),
    os.path.join("registry", "bin"),
    os.path.join("registry", "scripts"),
    os.path.join("client", "src"),
    os.path.join("client", "tests"),
)
# Where source lives, and what is not source. The generated namespace files are excluded for the
# same reason the specifications are excluded from the privileged-writer check: matching prose
# would fail on the very documents that forbid the thing, which is how a check teaches people to
# ignore it. The namespace is generated from the Namespace Annex, whose entries are TLD names,
# and one of those names is a payment provider's product name.
#
# Excluding them is safe because their contents are decided elsewhere: the constitution workflow
# runs `generate-namespace.py --check`, which requires the compiled copy to be exactly the
# Annex, so nothing can hide in them.
EXCLUDED_PATTERNS = (re.compile(r"namespace[._]generated\.(ts|js|mjs|rs)$"),)

# The dependency manifests. The lock files matter as much as the manifests: a provider can
# arrive transitively, and the lock file is where a transitive arrival is written down.
MANIFESTS = (
    os.path.join("registry", "package.json"),
    os.path.join("registry", "package-lock.json"),
    os.path.join("client", "Cargo.toml"),
    os.path.join("client", "Cargo.lock"),
)

# A provider's name, as it appears in a package name, an import, or a URL.
PROVIDERS = (
    r"stripe", r"paypal", r"braintree", r"adyen", r"razorpay", r"paddle", r"gocardless",
    r"worldpay", r"lemonsqueezy", r"gumroad", r"squareup", r"checkout\.com", r"bitpay",
    r"nowpayments", r"mollie", r"klarna", r"authorise\.net", r"epay", r"skrill",
)

# A provider's API, where the provider's own name is absent.
APIS = (
    r"payment_?intent", r"create_?charge", r"charge_?customer", r"payment_?method_?token",
    r"card_?number", r"card_?holder", r"\bcvv\b", r"\bcvc\b", r"\bcvn\b", r"paywall",
    r"billing_?plan", r"subscription_?key", r"invoice_?item", r"checkout_?session",
    r"money_?order", r"payment_?link", r"payment_?receipt",
)

VOCABULARY = re.compile(r"\b(?:%s|%s)\b" % ("|".join(PROVIDERS), "|".join(APIS)), re.I)


def source_files():
    for base in SOURCE_DIRS:
        directory = os.path.join(ROOT, base)
        if not os.path.isdir(directory):
            continue
        for current, dirs, names in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in ("node_modules", "target", "dist", ".git")]
            for name in sorted(names):
                if not name.endswith((".ts", ".rs", ".mjs", ".js")):
                    continue
                path = os.path.join(current, name)
                relative = os.path.relpath(path, ROOT)
                if any(pattern.search(relative.replace("\\", "/")) for pattern in EXCLUDED_PATTERNS):
                    continue
                yield relative, path


def manifest_files():
    for relative in MANIFESTS:
        path = os.path.join(ROOT, relative)
        if os.path.isfile(path):
            yield relative, path


def scan(label, relative, text, violations):
    for number, line in enumerate(text.splitlines(), start=1):
        for match in VOCABULARY.finditer(line):
            violations.append(
                f"{relative}:{number}: {label} mentions '{match.group(0)}' — "
                f"COST.md section 7 item 1 and Article 7 forbid a payment in any code path")
            break


def main():
    violations = []
    scanned = 0

    for relative, path in manifest_files():
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        scanned += 1
        scan("a dependency manifest", relative, text, violations)

    for relative, path in source_files():
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        scanned += 1
        scan("source", relative, text, violations)

    # The positive half: the rule being enforced must still be written down. A check that
    # enforces a rule nobody can find is enforcing the checker's own idea of the rule.
    cost = os.path.join(ROOT, "docs", "spec", "COST.md")
    charter = os.path.join(ROOT, "constitution", "CONSTITUTION.md")
    for path, needle, what in (
        (cost, "accepts, records, transfers or requires a payment", "COST.md section 7"),
        (charter, "No Token, No Treasury, No Protocol Fee", "Article 7"),
    ):
        if not os.path.isfile(path):
            violations.append(f"{os.path.relpath(path, ROOT)}: missing — the rule is gone")
            continue
        with open(path, encoding="utf-8") as handle:
            if needle not in handle.read():
                violations.append(
                    f"{os.path.relpath(path, ROOT)}: no longer states '{needle}' — {what} has "
                    f"been reworded or removed, and this check no longer enforces a written rule")

    print(f"scanned {scanned} file(s) for payment capability")
    if violations:
        print(f"\n{len(violations)} violation(s):\n", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1
    print("OK — no payment provider in either dependency set, and no provider API in either "
          "implementation.")
    print("Scope note: drift and accident detection only. A determined author writes their own "
          "payment code and names it something else.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
