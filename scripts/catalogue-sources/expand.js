export const meta = {
  name: 'webx-namespace-expand',
  description: 'Expand the WebX extension catalogue past 1000 across 22 further categories',
  phases: [{ title: 'Expand', detail: '22 category experts, each avoiding the existing 409' }],
}

const EXISTING = "abacus abode ad advocacy agora ai airwave alias allodial almanac alpine an anchor anglers anime anthology apiary ar archive artisan as ashram assembly at atelier autarky autonomy avatar ax ballot bangla barnraise barter basket bastion bazaar be bedrock bhangra binary bio birding birthright biryani bodega bokeh bookme breathe broadsheet bulletin by byline bytes cache campfire campus canvas card cart caucus cc cd chai chapbook chapter charter chatroom checkout chords chronicle ci cipher circle citadel citation civic classroom clubhouse cluster co codex cohort collage colophon commons compile congress consign council cradle creole crew curator cv daemon darkroom db debug deed deploy desk dhaba dharma digest diploma dispatch dissent diwali dj do dojo donate doodle dukan easel emporium encore escrow essay eternal ex exhibit exploit fandom fellow firmware flamenco fm folio folk folkname footnote forage forge forum freehold frontier fx gather gazette gg ghazal glossary glyph go gossip guild gurukul haggle hall handle handmade harvest haveli haven hawker hd hearth hello herald here hi homestead homework hr huddle human iam id ident if imprint in inkwell innings invoice io ip is it jamboree journal js justice kb kernel keystone kiln kin kinship kiosk knead kollektiv labs langar learn lecture ledger lens lesson lexicon library libre lineage literacy lodge longread loom main maker mandi mandir mantra marathi masala masthead matte me meetup mehndi mela memoir mender mentor mesh mine ml mural muse mutual my myself namaste named navratri neighbor nest neural no nook nordic notes octave of offgrid ok on op opendata opensource orchard os outpost own packet paddle palette panchayat pardesi patch payout peer permanent person petition pilgrim pixel pledge pm polis pongal potluck pr preprint primer prose proto punjabi py qa qawwali qubit query quill quorum quote raga ramble rangoli rd receipt reel refuge relay remix render resale resist restock resume robot roof root roster router runtime sakura salon samosa sandbox sangha sanskrit schema scholar score screening scriptorium scrum self selfhost selfrule seller seminar serif servo shard shutter signet silicon simmer sitar sketch so society socket sojourn solace solder souk soul sourdough sovereign stack stacks stagecraft stall stanza stills stitch stoic storefront sunshine supplier swahili swarm syllabus tabla tally tamil teach telemetry tempo tensor thali thrift tiffin tipjar to tome toon trader trailhead tribe tutor tv typeset ui unbound uncensored union up urdu us ux vaisakhi vault vector vendor vespers vidya village vinyl volunteer vr wafer wander wares watchdog waveform we wellspring whittle whois wholesale works wp xr yo zine"

const CATS = [
  [
    "professions",
    "Trades, crafts and professions: builders, electricians, plumbers, welders, tailors, barbers, chefs, drivers, nurses, engineers, surveyors, translators, accountants, consultants."
  ],
  [
    "industry",
    "Industry and sectors: manufacturing, mining, shipping, logistics, warehousing, energy, utilities, construction, textiles, steel, chemicals, packaging, wholesale."
  ],
  [
    "science",
    "Sciences and research: physics, chemistry, biology, genetics, neuroscience, ecology, geology, oceanography, mathematics, statistics, laboratories, field research."
  ],
  [
    "medicine",
    "Medicine and wellbeing: clinical specialties, therapy, nursing, pharmacy, rehabilitation, mental health, caregiving, public health, first aid, midwifery."
  ],
  [
    "sport",
    "Sport and outdoor pursuits: team sports, athletics, martial arts, climbing, cycling, swimming, sailing, motorsport, hiking, coaching, stadiums, leagues."
  ],
  [
    "games",
    "Games and play: video games, board games, tabletop roleplay, card games, puzzles, esports, speedrunning, game modding, arcades, toys."
  ],
  [
    "food",
    "Food and drink: cooking, baking, brewing, distilling, butchery, cheese, spices, street food, catering, nutrition, foraging, preserving, tea and coffee."
  ],
  [
    "nature",
    "Nature and environment: climate, conservation, wildlife, forests, rivers, oceans, mountains, deserts, rewilding, sustainability, renewable energy, weather."
  ],
  [
    "animals",
    "Animals and pets: dogs, cats, horses, birds, fish, reptiles, insects, veterinary care, rescue, breeding, training, wildlife photography."
  ],
  [
    "home",
    "Home, garden and making: interiors, renovation, repair, woodworking, metalwork, sewing, knitting, pottery, gardening, allotments, tools, restoration."
  ],
  [
    "transport",
    "Transport and vehicles: cars, motorcycles, bicycles, trains, aviation, boats, trucking, public transit, electric vehicles, restoration, racing, navigation."
  ],
  [
    "finance",
    "Money, economics and cooperative finance: budgeting, accounting, mutual aid funds, credit unions, insurance, economics research, financial literacy. Avoid anything implying WebX sells or brokers anything."
  ],
  [
    "fashion",
    "Fashion, style and textiles: clothing, tailoring, streetwear, vintage, cosmetics, jewellery, footwear, modelling, sustainable fashion, costume."
  ],
  [
    "music",
    "Music genres and scenes: jazz, blues, folk, classical, electronic, hip hop, metal, reggae, world music, choirs, orchestras, venues, labels, instruments."
  ],
  [
    "screen",
    "Film, television, theatre and performance: directing, screenwriting, documentary, comedy, dance, opera, circus, puppetry, festivals, criticism."
  ],
  [
    "literature",
    "Books and literary forms: fiction genres, poetry forms, criticism, translation, bookselling, libraries, reading groups, literary history."
  ],
  [
    "history",
    "History and heritage: archaeology, genealogy, museums, oral history, restoration, antiquities, historiography, local history, war history, monuments."
  ],
  [
    "philosophy",
    "Philosophy, religion and spirituality: ethics, logic, metaphysics, world faiths, meditation, monasticism, theology, secularism, ritual, pilgrimage."
  ],
  [
    "language",
    "Languages and linguistics: translation, interpreting, grammar, etymology, endangered languages, sign language, calligraphy, scripts, phonetics, dialects."
  ],
  [
    "society",
    "Law, rights, justice and social movements: human rights, labour organising, housing, migration, prison reform, disability rights, legal aid, advocacy, transparency."
  ],
  [
    "space",
    "Space and astronomy: astrophysics, observatories, satellites, rocketry, planetary science, cosmology, amateur astronomy, space policy."
  ],
  [
    "agriculture",
    "Agriculture and food production: farming, permaculture, beekeeping, aquaculture, viticulture, seeds, soil, irrigation, livestock, agroforestry."
  ]
]

const RULES = `
=== WebX extensions (TLDs) ===
WebX is a peer-to-peer parallel web addressed webx://name.ext, its own namespace, independent of
ICANN. Extensions cost proof-of-work rather than a fee, so the namespace can be broad.

=== HARD RULES for every string ===
1. 2 to 12 characters, lowercase ASCII letters only. No digits, no hyphens. Two-letter strings
   are allowed but nearly all good ones are already taken, so do not force them.
2. MUST NOT be a well-known ICANN gTLD. Avoid at least: com net org info biz xyz top site
   online club shop app dev page blog wiki art cloud tech store live life world today news
   media email link click space website host press studio design agency company group team
   work fun cool run bar rest menu pizza fit care health law legal money bank fund trade
   market sale deal gift toys game games play tv film movie music audio radio photo pics
   gallery book guru expert pro plus one now vip ltd inc llc edu gov mil int name mobi asia
   tel jobs travel museum aero coop cat post wine beer cafe bike guide zone center systems
   solutions services software digital network social chat video photos academy school
   university church charity green eco earth city town land house home estate farm coffee
   kitchen recipes restaurant golf tennis football soccer racing fishing ski surf camp band
   theater show events party dance auction reviews faith bible
3. MUST NOT be a country NAME or government identifier (no india, bharat, france, usa, britain,
   nippon). A two-letter string is fine; a country name is a claim WebX cannot make.
4. MUST NOT be a live trademark of a major company.
5. MUST NOT appear in the EXCLUSION LIST below.
6. Pronounceable, memorable, and meaning something. No random syllables.

=== EXCLUSION LIST (already catalogued, never repeat) ===
${EXISTING}

=== WRITING ===
- Never mention Claude, Anthropic, or any AI model. No emoji.
- Each entry: the string, and a purpose under 12 words naming who registers it.
`.trim()

const SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['category', 'extensions'],
  properties: {
    category: { type: 'string' },
    extensions: {
      type: 'array', minItems: 32, maxItems: 42,
      items: {
        type: 'object', additionalProperties: false,
        required: ['ext', 'purpose'],
        properties: {
          ext: { type: 'string', description: 'Extension WITHOUT leading dot, 2-12 lowercase letters' },
          purpose: { type: 'string', description: 'Under 12 words: who registers this and why' },
        },
      },
    },
  },
}

phase('Expand')

const out = await pipeline(
  CATS,
  (c) => agent(`${RULES}

=== YOUR CATEGORY: ${c[0]} ===
${c[1]}

Produce 32 to 42 extensions for this category. Before returning, re-check every string against
rule 2 (gTLD), rule 3 (country names) and rule 5 (the exclusion list).

Return via the structured-output tool.`,
    { label: `x:${c[0]}`, phase: 'Expand', schema: SCHEMA, effort: 'medium' }),
)

const alive = out.filter(Boolean)
log(`expansion: ${alive.length}/${CATS.length} categories, raw ${alive.reduce((n, r) => n + r.extensions.length, 0)}`)
return { categories: alive.map((r, i) => ({ key: CATS[i] ? CATS[i][0] : r.category, extensions: r.extensions })) }
