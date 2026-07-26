#!/usr/bin/env python3
"""Regenerate docs/spec/NAMESPACE-CATALOGUE.md, enforcing every namespace rule.

The catalogue is generated, not hand-maintained, so that the collision and grammar
rules in NAMESPACE.md are enforced by code rather than by review.

Rules enforced here rather than trusted from the generator:
  - 2 to 12 characters, lowercase ASCII letters only
  - never a well-known ICANN gTLD
  - no duplicates across categories (first category to claim it keeps it)

Two-letter extensions are permitted and curated by hand below. VayuWeb defines its own
namespace, and ISO 3166 is a shared reference rather than an authority here. What is
forbidden is a country NAME -- see NAMESPACE.md section 5.3.
"""
import json
import re
import sys

OUT = sys.argv[-1]
JOURNALS = sys.argv[1:-1]

# Well-known ICANN generic top-level domains VayuWeb must not echo. Not exhaustive --
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

ok = re.compile(r"^[a-z]{2,12}$")

# Two-letter extensions, curated by hand rather than generated.
#
# VayuWeb defines its own namespace; ISO 3166 is a shared reference, not an authority
# here. Each entry below is included for its ordinary meaning as a string, never as
# a country reference -- see NAMESPACE.md section 5.3, which forbids country NAMES
# (.india, .bharat) precisely because those read as a claim rather than a word.
TWO_LETTER = [
    # pronouns and greetings
    ("me", "An individual's own page, the shortest personal address there is"),
    ("my", "Anything a person calls theirs"),
    ("we", "Collectives, co-ops and shared projects"),
    ("us", "Groups speaking in the first person plural"),
    ("hi", "Introduction and landing pages"),
    ("yo", "Short, informal, attention-getting addresses"),
    ("ok", "Plain, unfussy sites that do one thing"),
    # prepositions and small words
    ("in", "Membership, inclusion and being part of something"),
    ("on", "Live things: broadcasts, streams, status pages"),
    ("at", "Location and presence — where someone can be found"),
    ("to", "Directories, redirects and pointers to elsewhere"),
    ("by", "Attribution — work credited to its maker"),
    ("of", "Collections and belonging"),
    ("up", "Launches, status pages and things going live"),
    ("go", "Short links, launchers and jumping-off points"),
    ("do", "Task tools, checklists and action-oriented sites"),
    ("be", "Identity, philosophy and personal statements"),
    ("so", "Conclusions, essays and commentary"),
    ("if", "Speculation, fiction and thought experiments"),
    ("is", "Definitional and reference pages"),
    ("it", "Technology generally, and information tools"),
    ("as", "Comparison, analogy and framing"),
    ("an", "Single-subject sites and short essays"),
    ("no", "Refusals, campaigns and statements against"),
    # technology
    ("io", "Input and output — developer tools and services"),
    ("ai", "Machine learning projects, research and tooling"),
    ("ui", "Interface design and component libraries"),
    ("ux", "Experience research and design practice"),
    ("os", "Operating systems and low-level software"),
    ("db", "Databases, datasets and storage projects"),
    ("js", "JavaScript libraries, tooling and communities"),
    ("py", "Python libraries, tooling and communities"),
    ("ml", "Machine learning models and pipelines"),
    ("vr", "Virtual reality projects and worlds"),
    ("ar", "Augmented reality tools and experiences"),
    ("xr", "Extended reality generally"),
    ("hd", "High-definition media and video projects"),
    ("cc", "Creative commons and open-licensed collections"),
    ("cd", "Continuous delivery, and record collections"),
    ("ci", "Continuous integration and build tooling"),
    ("kb", "Knowledge bases and internal documentation"),
    ("qa", "Testing, quality assurance and question-answer sites"),
    ("ip", "Intellectual property, and networking projects"),
    ("fx", "Visual effects, and audio effects"),
    ("gg", "Gaming clans, tournaments and esports"),
    ("dj", "Disc jockeys, mixes and sets"),
    ("tv", "Video channels and episodic programming"),
    ("fm", "Audio stations, podcasts and radio"),
    ("pm", "Product management, and project management"),
    ("hr", "People operations and hiring"),
    ("pr", "Public relations and press pages"),
    ("cv", "Curricula vitae and professional histories"),
    ("id", "Identity pages and credential endpoints"),
    ("op", "Operations, runbooks and on-call documentation"),
    ("rd", "Research and development groups"),
    ("ad", "Advertising, and public notices"),
    ("co", "Companies, cooperatives and joint ventures"),
    ("ex", "Former things: archives, retrospectives, post-mortems"),
    ("ax", "Sharp, minimal single-purpose tools"),
    ("wp", "Wallpapers, whitepapers and working papers"),
]

# The protocol's founding extensions. They carry meaning specific to VayuWeb
# itself and are claimed before anything else so their descriptions survive.
# They hold no privileged status -- Constitution Article 35 requires every
# extension to be equal, and no client may present one as more official.
#
# Two of the original twelve are absent on purpose: .news and .blog are live
# ICANN generic domains, and .webx went with the rename.
FOUNDING = [
    ("vayu", "The protocol's own namespace; general-purpose, the default suggestion"),
    ("p2p", "Peer-to-peer software, protocols and node operators"),
    ("free", "Projects whose defining claim is that they cost nothing to use"),
    ("decent", "Decentralisation as subject matter: research, tooling, commentary"),
    ("sov", "Self-governing projects and sovereignty-focused publishing"),
    ("dao", "Collectively governed organisations publishing their rules"),
    ("indie", "Independent creators, studios and small publishers"),
    ("open", "Open standards, open data and open-by-default projects"),
]

seen, rejected, cats = {}, [], []

founding = []
for ext, purpose in FOUNDING:
    if ext in GTLD or not ok.match(ext):
        rejected.append((ext, "founding rejected"))
        continue
    seen[ext] = "founding"
    founding.append((ext, purpose))
if founding:
    cats.append(("founding", sorted(founding)))

# The hand-curated two-letter set is claimed next, so a generated duplicate
# defers to it rather than the other way round.
two = []
for ext, purpose in TWO_LETTER:
    if ext in GTLD or not ok.match(ext):
        rejected.append((ext, "two-letter rejected"))
        continue
    seen[ext] = "two-letter"
    two.append((ext, purpose))
if two:
    cats.append(("two-letter", sorted(two)))

lines = []
for journal in JOURNALS:
    lines.extend(open(journal, encoding="utf-8").readlines())

for line in lines:
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
    "founding": "Founding extensions",
    "two-letter": "Two letters",
    "professions": "Trades and professions",
    "industry": "Industry and sectors",
    "science": "Science and research",
    "medicine": "Medicine and wellbeing",
    "sport": "Sport and outdoors",
    "games": "Games and play",
    "food": "Food and drink",
    "nature": "Nature and environment",
    "animals": "Animals",
    "home": "Home, garden and making",
    "transport": "Transport and vehicles",
    "finance": "Money and cooperative finance",
    "fashion": "Fashion and textiles",
    "music": "Music",
    "screen": "Film, stage and performance",
    "literature": "Books and literary forms",
    "history": "History and heritage",
    "philosophy": "Philosophy and belief",
    "language": "Languages and linguistics",
    "society": "Law, rights and social movements",
    "space": "Space and astronomy",
    "agriculture": "Agriculture",
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
    w("# VayuWeb Launch Catalogue\n\n")
    w(f"**{len(seen)} extensions**, grouped by what people actually register them for.\n\n")
    w("This is a starting point, not a boundary. The VayuWeb namespace is **elastic**: anyone may\n"
      "propose a new extension at any time, it costs proof-of-work rather than a fee, and the\n"
      "valid set is derived from the registry log rather than hard-coded in any client. See\n"
      "[NAMESPACE.md](NAMESPACE.md) for the creation process and\n"
      "[NAMES.md](NAMES.md) for the label grammar and lifecycle.\n\n")
    w("Every extension here is equal. There is no premium tier, no reserved class, and no\n"
      "extension that is more official than another — Constitution Article 35 requires it and\n"
      "no client may present otherwise.\n\n")
    w("## Rules every entry satisfies\n\n")
    w("- **Two to twelve characters.** Two-letter extensions are permitted: VayuWeb defines its\n"
      "  own namespace, and a two-letter string is a string. The clearnet has treated `.io`,\n"
      "  `.ai` and `.me` as generic for two decades. What is forbidden is a country *name*\n"
      "  such as `.india` — that reads as a claim rather than a word, and VayuWeb cannot\n"
      "  adjudicate who represents a nation. See NAMESPACE.md section 5.3.\n")
    w("- **No echo of a well-known ICANN generic domain.** A `vayu://` name that looks like a\n"
      "  clearnet one teaches readers that VayuWeb names mean nothing.\n")
    w("- **Lowercase ASCII**, pronounceable, and meaning something.\n\n")
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
