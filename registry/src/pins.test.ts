import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  PinError,
  TOMBSTONE_CACHE_SECONDS,
  UNPUBLISH_EFFECTS,
  onlyThisNodeHoldsIt,
  report,
  summarise,
  tombstonedBindingExpired,
  type Observation,
} from './pins.ts';

const NOW = 1_782_518_400;
const STALE = 3_600;
const CID = 'bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e';

const peer = (id: string, at = NOW): Observation => ({
  holder: { kind: 'peer', id },
  observedAt: at,
});
const self = (at = NOW): Observation => ({ holder: { kind: 'self' }, observedAt: at });
const service = (name: string, at = NOW): Observation => ({
  holder: { kind: 'service', name },
  observedAt: at,
});

/* -------------------------------------------------------------------------- */
/* Three ways a correct number lies                                            */
/* -------------------------------------------------------------------------- */

test('silence is reported as silence, never as absence', () => {
  // A client cannot distinguish "no peer holds this" from "no peer told me". Rendering both as
  // zero invents a fact — and it is the more alarming of the two facts, so the invention pushes a
  // publisher toward panic about a site that may be perfectly well replicated.
  const asked40 = report(CID, 40, [], STALE, NOW);
  assert.equal(asked40.answered, 0);
  assert.equal(asked40.asked, 40);
  assert.match(summarise(asked40), /No peer answered out of 40 asked/);
  assert.match(summarise(asked40), /not the same as nobody holding it/);

  const askedNobody = report(CID, 0, [], STALE, NOW);
  assert.match(summarise(askedNobody), /No peers were asked/);
  assert.match(summarise(askedNobody), /Nothing is known/);
});

test('your own pin is never counted as redundancy', () => {
  // "1 peer holds this site" reads as reassurance and means nothing when that peer is you.
  // Self-pinning-only is the most common self-inflicted failure in content-addressed publishing,
  // and it looks perfect from the publisher's own machine, where the site always loads.
  const alone = report(CID, 12, [self()], STALE, NOW);
  assert.equal(alone.peersHolding, 0, 'self is not a peer');
  assert.equal(alone.servicesHolding, 0);
  assert.equal(alone.selfPinned, true);
  assert.equal(onlyThisNodeHoldsIt(alone), true);
  assert.match(summarise(alone), /pinned here/);
  assert.equal(/\b1 other peer/.test(summarise(alone)), false, 'never summed into a peer count');
});

test('there is no total, no percentage and no durability field to render', () => {
  // Article 23 forbids an uptime figure and HOSTING.md says any document quoting one is wrong. The
  // defence is that the number does not exist as a field, so a dashboard cannot bind to it.
  const full = report(CID, 5, [self(), peer('a'), peer('b'), service('s')], STALE, NOW);
  const keys = Object.keys(full).sort();
  assert.deepEqual(keys, [
    'answered',
    'asked',
    'availabilityUnguaranteed',
    'cid',
    'observedAt',
    'peersHolding',
    'selfPinned',
    'servicesHolding',
  ]);
  for (const forbidden of ['total', 'percentage', 'percent', 'durability', 'uptime', 'replicas']) {
    assert.equal(forbidden in full, false, forbidden);
  }
  assert.equal(full.availabilityUnguaranteed, true, 'and the caveat is a field, not a comment');
});

test('a peer answering twice is one holder, not two copies', () => {
  // Otherwise an adversary manufactures apparent redundancy by answering repeatedly — and an
  // honest peer with a retry does the same thing by accident.
  const twice = report(CID, 3, [peer('a', NOW - 10), peer('a', NOW)], STALE, NOW);
  assert.equal(twice.peersHolding, 1);
  assert.equal(twice.answered, 1);
  assert.equal(twice.observedAt, NOW, 'the newest observation stamps the report');
});

test('a stale observation is not evidence about now', () => {
  const old = report(CID, 3, [peer('a', NOW - STALE - 1)], STALE, NOW);
  assert.equal(old.peersHolding, 0);
  assert.equal(old.observedAt, null, 'no fresh observation means no observation time');

  const justFresh = report(CID, 3, [peer('a', NOW - STALE + 1)], STALE, NOW);
  assert.equal(justFresh.peersHolding, 1);
});

test('more answers than peers asked is refused rather than reported', () => {
  // A report built on a miscounted denominator is worse than no report: it is a wrong number
  // presented with the authority of a measurement.
  assert.throws(
    () => report(CID, 1, [peer('a'), peer('b'), peer('c')], STALE, NOW),
    /denominator is wrong/,
  );
  assert.throws(() => report(CID, -1, [], STALE, NOW), PinError);
  // One more than asked is allowed: this node may hold it without having asked itself.
  assert.equal(report(CID, 1, [self(), peer('a')], STALE, NOW).answered, 2);
});

test('services are counted apart from peers, because they are a different dependency', () => {
  // A paid service is legitimate and it works. It is also a party that can drop you, which two
  // volunteer peers are not — so summing them would flatten the distinction a publisher most
  // needs when deciding whether they are actually safe.
  const mixed = report(CID, 6, [peer('a'), service('somewhere'), service('elsewhere')], STALE, NOW);
  assert.equal(mixed.peersHolding, 1);
  assert.equal(mixed.servicesHolding, 2);
  assert.equal(onlyThisNodeHoldsIt(mixed), false);
});

test('the summary never promises, in any branch', () => {
  const reports = [
    report(CID, 0, [], STALE, NOW),
    report(CID, 9, [], STALE, NOW),
    report(CID, 9, [self()], STALE, NOW),
    report(CID, 9, [self(), peer('a')], STALE, NOW),
    report(CID, 9, [peer('a'), peer('b'), service('s')], STALE, NOW),
  ];
  for (const r of reports) {
    const text = summarise(r);
    // Bare promise words, not the word "guaranteed" — which appears in every positive branch as
    // "Observed, not guaranteed", where it is the caveat rather than the claim. An earlier version
    // of this test banned the substring and failed on the very sentence that does the honest work.
    for (const promise of ['is safe', 'durable', 'backed up', 'always available', 'permanent']) {
      assert.equal(text.toLowerCase().includes(promise), false, `${promise} in "${text}"`);
    }
    const positive = r.selfPinned || r.peersHolding > 0 || r.servicesHolding > 0;
    if (positive) {
      assert.match(text, /Observed, not guaranteed\.$/, 'every positive answer carries the caveat');
    }
  }
});

/* -------------------------------------------------------------------------- */
/* Unpublishing: Article 19, "where charters lie"                              */
/* -------------------------------------------------------------------------- */

test('what unpublishing cannot do is data, not prose a UI can drop', () => {
  // Article 19.1 opens by saying it is "stated with deliberate precision, because unpublishing is
  // where charters lie", and 19.6 requires the limits to be stated plainly EVERYWHERE. Holding
  // them as a list means an interface has to render them or deliberately drop them, rather than
  // simply never having had them.
  assert.equal(UNPUBLISH_EFFECTS.guaranteed.length, 6, 'the six acts of Article 19.2');
  assert.ok(UNPUBLISH_EFFECTS.notGuaranteed.length >= 4);
  const limits = UNPUBLISH_EFFECTS.notGuaranteed.join(' ');
  assert.match(limits, /append-only/);
  assert.match(limits, /adds a record; it removes nothing/);
  assert.match(limits, /re-pinned and re-served/);
  assert.match(limits, /no protocol mechanism can compel a third party to delete/);
});

test('nothing here claims erasure', () => {
  // Article 19.7: VayuWeb guarantees the cessation of authorised publication, not erasure, "and no
  // implementation or document SHALL state or imply that it does".
  const everything = [...UNPUBLISH_EFFECTS.guaranteed, ...UNPUBLISH_EFFECTS.notGuaranteed]
    .join(' ')
    .toLowerCase();
  for (const word of ['erase', 'erasure', 'delete everywhere', 'permanently remove', 'wipe']) {
    assert.equal(everything.includes(word), false, word);
  }
  assert.match(UNPUBLISH_EFFECTS.guaranteed.join(' '), /stop serving/);
});

test('a tombstoned binding expires at exactly the charter bound', () => {
  // Article 19.4 caps retention at 3600 seconds after the tombstone is OBSERVED — a client cannot
  // be held to a deadline that started before it heard anything.
  assert.equal(TOMBSTONE_CACHE_SECONDS, 3_600);
  assert.equal(tombstonedBindingExpired(NOW, NOW + 3_599), false);
  assert.equal(tombstonedBindingExpired(NOW, NOW + 3_600), true);
  assert.equal(tombstonedBindingExpired(NOW, NOW + 10_000), true);
});

test('the charter still says what this module implements', () => {
  // These constants are restatements, and a restatement that drifts is worse than a reference.
  const charter = readFileSync(
    new URL('../../constitution/CONSTITUTION.md', import.meta.url),
    'utf8',
  );
  assert.match(charter, /MUST NOT retain a tombstoned binding in any cache for longer than 3600/);
  assert.match(charter, /does not guarantee\nerasure/);
});
