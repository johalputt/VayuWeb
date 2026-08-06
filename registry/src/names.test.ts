import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  RATIFIED_TLDS,
  MAX_LABEL_LENGTH,
  labelRejection,
  isValidLabel,
  isWellShapedTld,
  RESERVED_LABELS,
  isRatifiedTld,
  nameRejection,
  assertValidName,
  parseAlias,
  NameError,
} from './names.ts';
import { NAMESPACE_ANNEX_SIZE } from './namespace.generated.ts';

/* -------------------------------------------------------------------------- */
/* The ratified set is wire-visible and frozen                                 */
/* -------------------------------------------------------------------------- */

test('the ratified TLD set is exactly the Namespace Annex', () => {
  // Wire-visible: REGISTRY.md rejects any TLD outside this set. A peer whose set differs by one
  // entry accepts names others refuse, which is a namespace fork presenting as an intermittent
  // resolution failure. The set is generated from docs/spec/NAMESPACE-CATALOGUE.md, so this
  // reads the Annex back and compares — a drifted generated file fails here as well as in the
  // `generate-namespace.py --check` CI gate. Two independent detections, because this constant
  // has already been wrong by a factor of a hundred once.
  const annex = readFileSync(
    new URL('../../docs/spec/NAMESPACE-CATALOGUE.md', import.meta.url),
    'utf8',
  );
  const listed = [...annex.matchAll(/^\| `\.([a-z0-9]+)` \|/gm)].map((m) => m[1]);

  assert.equal(listed.length, new Set(listed).size, 'the Annex must not repeat an extension');
  assert.deepEqual([...listed].sort(), [...RATIFIED_TLDS].sort());
  assert.equal(RATIFIED_TLDS.size, NAMESPACE_ANNEX_SIZE);
  assert.equal(RATIFIED_TLDS.size, 1270);
});

test('the Annex contains every extension named in the text of Article 35.1', () => {
  // Article 35.1 names eleven in the charter's own text "so that the founding set survives loss
  // of the Annex". An Annex missing one contradicts the Article that incorporates it, and the
  // charter wins — so this must fail rather than silently drop a namespace. That exact failure
  // has already happened: .blog, .news and .p2p were absent from the 1,267-entry catalogue
  // while Article 35.1 named all three.
  const charter = readFileSync(
    new URL('../../constitution/CONSTITUTION.md', import.meta.url),
    'utf8',
  );
  const clause = charter.split('35.1 The initial top-level domains')[1]?.split('35.1.a')[0] ?? '';
  const named = [...clause.matchAll(/(?:^|\s)\.([a-z][a-z0-9]{1,11})\b/g)].map((m) => m[1]);

  assert.ok(named.length >= 11, 'Article 35.1 must still name the founding extensions');
  for (const tld of named) {
    assert.ok(RATIFIED_TLDS.has(tld), `.${tld} is named in Article 35.1 but not in the Annex`);
  }
});

test('no two ratified extensions collide after case folding', () => {
  // Two entries differing only by case would be one namespace presented as two, and whichever
  // row lost the race would be unregistrable with no error able to explain why.
  const folded = new Map<string, string>();
  for (const tld of RATIFIED_TLDS) {
    const key = tld.toLowerCase();
    const previous = folded.get(key);
    assert.equal(previous, undefined, `.${tld} folds onto .${previous}`);
    folded.set(key, tld);
  }
});

test('every ratified TLD satisfies the TLD grammar', () => {
  // The defect that started this: `.p2p` was in the founding set while the ABNF admitted
  // letters only, so the founding set was invalid under its own grammar.
  for (const tld of RATIFIED_TLDS) {
    assert.ok(isWellShapedTld(tld), `${tld} must satisfy the grammar it was ratified under`);
  }
});

/* -------------------------------------------------------------------------- */
/* Label grammar                                                               */
/* -------------------------------------------------------------------------- */

test('ordinary labels of three characters and up are valid', () => {
  for (const label of ['atlas', 'abc', 'a-b', 'a1', 'my-long-project-name', '0abc', 'a0-0z']) {
    if (label.length <= 2) continue;
    assert.ok(isValidLabel(label), `${label} should be valid`);
  }
});

test('a hyphen may not lead or trail', () => {
  assert.equal(labelRejection('-atlas'), 'LEADING_HYPHEN');
  assert.equal(labelRejection('atlas-'), 'TRAILING_HYPHEN');
  assert.equal(labelRejection('---'), 'LEADING_HYPHEN');
});

test('the xx-- shape is reserved for a future IDN encoding', () => {
  // Reserving it now means a later IDN VWIP can adopt a prefixed encoding without colliding
  // with names already registered.
  assert.equal(labelRejection('ab--cd'), 'RESERVED_IDN_SHAPE');
  assert.equal(labelRejection('xn--abc'), 'RESERVED_IDN_SHAPE');
  // Hyphens at 3 and 4 specifically — not merely two hyphens anywhere.
  assert.ok(isValidLabel('abc--de'), 'hyphens at 4 and 5 are fine');
  assert.ok(isValidLabel('a-b-c'), 'separated hyphens are fine');
});

test('all one and two character labels are reserved in every TLD', () => {
  // 36 single-character and 1,296 two-character labels, withheld pending an allocation VWIP.
  for (const label of ['a', 'z', '0', '9', 'ab', 'zz', '00', 'a0', 'a-']) {
    const rejection = labelRejection(label);
    assert.ok(
      rejection === 'RESERVED_LABEL' || rejection === 'TRAILING_HYPHEN',
      `${label} must not be registrable, got ${rejection}`,
    );
  }
  // Exhaustive over the two-character space, since "1,296" is a claim worth checking.
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let registrable = 0;
  for (const a of alphabet) for (const b of alphabet) if (isValidLabel(a + b)) registrable++;
  assert.equal(registrable, 0, 'no two-character label may be registrable');
});

test('I register wpad.vayu and your browser fetches its proxy configuration from me', () => {
  // The attack, in the attacker's voice.
  //
  // `wpad` is Web Proxy Auto-Discovery. A browser configured to find its proxy automatically
  // fetches `wpad.<domain>/wpad.dat` and runs the JavaScript it finds there to decide where every
  // request goes. It is a proxy-hijack vector old enough to have its own CVE history, and
  // NAMES.md withholds the label for exactly that reason: "a name that a browser might fetch as
  // configuration MUST NOT be registrable by a stranger".
  //
  // `pac` is the same attack under the file's own name. `control`, `api`, `resolver` and `proxy`
  // collide with the resolver's own control surface. `vayu` is protocol identity — withheld in
  // every extension including `.vayu`, so that no holder can speak as the protocol. `localhost`
  // is RFC 6761 special-use. `example`, `invalid` and `test` are RFC 2606.
  //
  // The second harm is worse than the first and needs no attacker at all. An implementation
  // written from NAMES.md refuses all of these as BAD_LABEL. One that does not accepts them. Two
  // peers then hold different ownership facts for the same name, permanently — the namespace fork
  // Article 44.6 and the Phase 0 acceptance test exist to prevent, on the exact label set the
  // specification singles out as dangerous.
  for (const label of RESERVED_LABELS) {
    assert.equal(
      labelRejection(label),
      'RESERVED_LABEL',
      `${label} is withheld by NAMES.md and must be refused`,
    );
    assert.equal(nameRejection(label, 'vayu'), 'RESERVED_LABEL', label);
  }
});

test('the reserved set is exactly the one NAMES.md withholds', () => {
  // Read back from the specification rather than trusted to have been transcribed. A reserved
  // set that drifts from the table is a set that refuses names others accept, or accepts names
  // others refuse, and both are the fork this rule exists to prevent.
  const spec = readFileSync(new URL('../../docs/spec/NAMES.md', import.meta.url), 'utf8');
  const section = spec.split('## Reserved labels')[1]?.split('Reserved labels are not')[0] ?? '';
  const named = [...section.matchAll(/`([a-z_][a-z0-9_]*)`/g)]
    .map((m) => m[1]!)
    .filter((word) => !['a', 'z', '0', '9'].includes(word));

  for (const label of named) {
    assert.ok(
      RESERVED_LABELS.has(label) || label.startsWith('_'),
      `${label} is named in NAMES.md but not in RESERVED_LABELS`,
    );
  }
  // `_vayu` is refused by the grammar before reservation is consulted: underscore is not in the
  // label character set at all. Named in the table for the reader, not needed in the set.
  assert.equal(labelRejection('_vayu'), 'BAD_CHARACTER');
});

test('a reserved label is refused in every extension, not only in .vayu', () => {
  // "Withheld in every TLD" is the rule. A per-extension carve-out would make `vayu.blog`
  // registrable, and a holder of it could speak as the protocol on a page a reader trusts.
  for (const tld of ['vayu', 'blog', 'news', 'p2p', 'zine']) {
    assert.equal(nameRejection('wpad', tld), 'RESERVED_LABEL', tld);
    assert.equal(nameRejection('vayu', tld), 'RESERVED_LABEL', tld);
  }
});

test('non-ASCII and uppercase are rejected rather than normalised', () => {
  // NAMES.md: a peer must reject rather than silently canonicalise, so the bytes a user signs
  // are exactly the bytes the log stores.
  assert.equal(labelRejection('Atlas'), 'BAD_CHARACTER');
  assert.equal(labelRejection('atlás'), 'BAD_CHARACTER');
  assert.equal(labelRejection('ätlas'), 'BAD_CHARACTER');
  assert.equal(labelRejection('atlas.vayu'), 'BAD_CHARACTER');
  assert.equal(labelRejection('at las'), 'BAD_CHARACTER');
  assert.equal(labelRejection('at_las'), 'BAD_CHARACTER');
});

test('length bounds are enforced at the boundary', () => {
  assert.equal(labelRejection(''), 'EMPTY');
  assert.ok(isValidLabel('a'.repeat(MAX_LABEL_LENGTH)));
  assert.equal(labelRejection('a'.repeat(MAX_LABEL_LENGTH + 1)), 'TOO_LONG');
});

/* -------------------------------------------------------------------------- */
/* TLD shape versus ratification                                               */
/* -------------------------------------------------------------------------- */

test('shape and ratification are separate questions', () => {
  // A well-shaped unratified TLD is a legitimate VWIP proposal, not an error.
  assert.ok(isWellShapedTld('example'));
  assert.ok(!isRatifiedTld('example'));
  assert.equal(nameRejection('atlas', 'example'), 'UNKNOWN_TLD');
});

test('a TLD may not begin with a digit or contain other characters', () => {
  assert.ok(!isWellShapedTld('2p2'));
  assert.ok(!isWellShapedTld('p-2'));
  assert.ok(!isWellShapedTld('P2P'));
  assert.ok(!isWellShapedTld('a'));
  assert.ok(!isWellShapedTld('a'.repeat(13)));
  assert.ok(isWellShapedTld('p2p'), 'digits after the first character are permitted');
});

test('a badly shaped TLD reports shape rather than ratification', () => {
  assert.equal(nameRejection('atlas', 'P2P'), 'BAD_TLD_SHAPE');
});

/* -------------------------------------------------------------------------- */
/* Full names and aliases                                                      */
/* -------------------------------------------------------------------------- */

test('a full name validates both parts', () => {
  assert.equal(nameRejection('atlas', 'vayu'), null);
  assert.equal(nameRejection('ab', 'vayu'), 'RESERVED_LABEL');
  assert.equal(nameRejection('atlas', 'nope'), 'UNKNOWN_TLD');

  assert.throws(
    () => assertValidName('ab', 'vayu'),
    (e: unknown) => e instanceof NameError && e.code === 'RESERVED_LABEL',
  );
});

test('parseAlias accepts exactly one dot and a ratified target', () => {
  assert.deepEqual(parseAlias('atlas.vayu'), { label: 'atlas', tld: 'vayu' });

  for (const bad of [
    'atlas',
    '.vayu',
    'atlas.',
    'a.b.c',
    'atlas.nope',
    'ab.vayu',
    'atlas.P2P',
    '',
  ]) {
    assert.equal(parseAlias(bad), null, `${bad} must not parse as an alias`);
  }
});

test('an alias target that cannot exist is refused at parse time', () => {
  // Otherwise a malformed target consumes one of the three permitted hops before failing.
  assert.equal(parseAlias('-atlas.vayu'), null);
  assert.equal(parseAlias('ab--cd.vayu'), null);
});

/* -------------------------------------------------------------------------- */
/* AUDIT FINDING: the reserved set in code and the one in the spec              */
/* -------------------------------------------------------------------------- */

test('AUDIT: RESERVED_LABELS is exactly the set NAMES.md withholds', () => {
  // NAMES.md is authoritative and this module enforces it, so the two lists have to be the same
  // list. They were not: the specification's table named `_vayu` and this set does not carry it.
  //
  // That gap was not a hole — `_` is not in the label grammar, so `_vayu` can never be a label
  // at all — and that is exactly why it was worth correcting rather than silently adding. Listing
  // an ungrammatical string among the reserved labels implies the reservation is what withholds
  // it, and therefore that lifting the reservation would make it registrable. It would not. A
  // reader deciding which labels a VWIP could release would have got that wrong.
  const spec = readFileSync(new URL('../../docs/spec/NAMES.md', import.meta.url), 'utf8');
  const section = /## Reserved labels\n([\s\S]*?)\n## /.exec(spec);
  assert.ok(section, 'the Reserved labels section must exist, or this check is inert');

  // Every backticked label in the table's first column, which is where the named ones live.
  const rows = section[1]!.matchAll(/^\| ((?:`[a-z0-9_]+`(?:, )?)+) \|/gm);
  const named = new Set<string>();
  for (const row of rows) {
    for (const label of row[1]!.matchAll(/`([a-z0-9_]+)`/g)) named.add(label[1]!);
  }
  assert.ok(named.size >= 10, `only ${named.size} labels parsed — the table format changed`);

  assert.deepEqual(
    [...named].sort(),
    [...RESERVED_LABELS].sort(),
    'the specification and the enforced set name different labels',
  );

  // And the reservation is what withholds each of them: every one is grammatical, so removing it
  // from the set would genuinely make it registrable. That is the property that makes the list
  // meaningful, and the property `_vayu` did not have.
  for (const label of RESERVED_LABELS) {
    assert.equal(
      labelRejection(label),
      'RESERVED_LABEL',
      `${label} must be refused as reserved, not by some other rule`,
    );
  }
});
