#!/usr/bin/env python3
"""Regenerate docs/spec/NAMESPACE-CATALOGUE.md, enforcing every namespace rule.

The catalogue is generated, not hand-maintained, so that the collision and grammar
rules in NAMESPACE.md are enforced by code rather than by review.

Rules enforced here rather than trusted from the generator:
  - 3 to 12 characters, lowercase ASCII letters only
  - never 2 characters (that is the entire ISO 3166 ccTLD space)
  - never a well-known ICANN gTLD
  - no duplicates across categories (first category to claim it keeps it)
"""
import json
import re
import sys

JOURNAL = sys.argv[1]
OUT = sys.argv[2]

# Well-known ICANN generic top-level domains WebX must not echo. Not exhaustive --
# it is the set a reader would plausibly confuse with the clearnet.
GTLD = {
    "com", "net", "org", "info", "biz", "xyz", "top", "site", "online", "club", "shop", "app",
    "dev", "page", "blog", "wiki", "art", "cloud", "tech", "store", "live", "life", "world",
    "today", "news", "media", "email", "link", "click", "space", "website", "host", "press",
    "studio", "design", "agency", "company", "group", "team", "work", "fun", "cool", "run",
    "bar", "rest", "menu", "pizza", "fit", "care", "health", "law", "legal", "money", "bank",
    "fund", "trade", "market", "sale", "deal", "gift", "toys", "game", "games", "play", "film",
    "movie", "music", "audio", "radio", "photo", "pics", "gallery", "book", "guru", "expert",
    "pro", "plus", "one", "now", "vip", "ltd", "inc", "llc", "gmbh", "edu", "gov", "mil", "int",
    "name", "mobi", "asia", "tel", "jobs", "travel", "museum", "aero", "coop", "cat", "post",
    "xxx", "wtf", "lol", "fyi", "ink", "wine", "beer", "cafe", "bike", "guide", "zone", "center",
    "systems", "solutions", "services", "software", "digital", "network", "social", "chat",
    "video", "photos", "pictures", "graphics", "computer", "academy", "school", "university",
    "church", "charity", "green", "eco", "earth", "city", "town", "land", "house", "home",
    "estate", "properties", "rentals", "tours", "vacations", "flights", "cruises", "cash",
    "credit", "loans", "insure", "tax", "accountant", "lawyer", "attorney", "dentist", "doctor",
    "clinic", "surgery", "fitness", "yoga", "coach", "fashion", "style", "boutique", "jewelry",
    "watch", "shoes", "clothing", "furniture", "garden", "farm", "florist", "coffee", "kitchen",
    "recipes", "restaurant", "catering", "bakery", "vodka", "pub", "golf", "tennis", "football",
    "soccer", "racing", "fishing", "hockey", "rugby", "ski", "surf", "camp", "fan", "band",
    "theater", "show", "events", "party", "dance", "art", "gallery", "museum", "auction",
    "reviews", "guide", "how", "wiki", "faith", "bible", "church", "christmas", "gives", "give",
}

ok = re.compile(r"^[a-z]{3,12}$")

seen, rejected, cats = {}, [], []
for line in open(JOURNAL, encoding="utf-8"):
    result = json.loads(line).get("result")
    if not isinstance(result, dict) or "extensions" not in result:
        continue
    key = result.get("category", "uncategorised")
    kept = []
    for entry in result["extensions"]:
        ext = entry["ext"].strip().lower().lstrip(".")
        if not ok.match(ext):
            rejected.append((ext, "grammar"))
            continue
        if ext in GTLD:
            rejected.append((ext, "gTLD collision"))
            continue
        if ext in seen:
            rejected.append((ext, f"duplicate of {seen[ext]}"))
            continue
        seen[ext] = key
        kept.append((ext, entry["purpose"].strip().rstrip(".")))
    if kept:
        cats.append((key, sorted(kept)))

TITLES = {
    "core-identity": "Core and identity",
    "publishing": "Writing and publishing",
    "creative-media": "Art and media",
    "commerce": "Commerce and craft",
    "technology": "Technology",
    "community": "Community",
    "sovereignty": "Sovereignty and peer-to-peer",
    "learning-civic": "Learning and civic life",
    "life-culture": "Life and culture",
    "regional-cultural": "Regional and cultural",
}

with open(OUT, "w", encoding="utf-8") as fh:
    w = fh.write
    w("# WebX Launch Catalogue\n\n")
    w(f"**{len(seen)} extensions**, grouped by what people actually register them for.\n\n")
    w("This is a starting point, not a boundary. The WebX namespace is **elastic**: anyone may\n"
      "propose a new extension at any time, it costs proof-of-work rather than a fee, and the\n"
      "valid set is derived from the registry log rather than hard-coded in any client. See\n"
      "[NAMESPACE.md](NAMESPACE.md) for the creation process and\n"
      "[NAMES.md](NAMES.md) for the label grammar and lifecycle.\n\n")
    w("Every extension here is equal. There is no premium tier, no reserved class, and no\n"
      "extension that is more official than another — Constitution Article 35 requires it and\n"
      "no client may present otherwise.\n\n")
    w("## Rules every entry satisfies\n\n")
    w("- **Three characters minimum.** Every ISO 3166 country code is two letters, so a\n"
      "  three-character floor keeps WebX clear of the entire country-code space.\n")
    w("- **No echo of a well-known ICANN generic domain.** A `webx://` name that looks like a\n"
      "  clearnet one teaches readers that WebX names mean nothing.\n")
    w("- **Lowercase ASCII, three to twelve characters**, pronounceable, and meaning something.\n\n")
    w("**Status:** Draft — not yet implemented. No extension is registrable until the protocol\n"
      "exists and each has completed the 180-day dormancy period required by Article 35.\n\n")
    w("---\n\n")
    for key, items in cats:
        w(f"## {TITLES.get(key, key)}\n\n")
        w(f"*{len(items)} extensions*\n\n")
        w("| Extension | Who registers it |\n|---|---|\n")
        for ext, purpose in items:
            w(f"| `.{ext}` | {purpose} |\n")
        w("\n")
    w("---\n\n## See also\n\n")
    w("- [Namespace](NAMESPACE.md) — how new extensions are created, and why breadth is safe here\n")
    w("- [Naming and TLD policy](NAMES.md) — label grammar and lifecycle\n")
    w("- [Cost model](COST.md) — why registration costs work rather than money\n")

print(f"wrote {OUT}: {len(seen)} extensions across {len(cats)} categories")
if rejected:
    from collections import Counter
    print("rejected:", dict(Counter(r for _, r in rejected)))
