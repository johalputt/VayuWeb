import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  currentKey,
  byOwnerKey,
  expiryKey,
  rateKey,
  currentPrefix,
  byOwnerPrefix,
  expiryRange,
  rateRange,
  decodeCurrentKey,
  decodeByOwnerKey,
  decodeExpiryKey,
  decodeRateKey,
  encodeTimestamp,
  decodeTimestamp,
  KeyError,
  TAG_CURRENT,
  TAG_EXPIRY,
  MAX_TIMESTAMP,
} from './keys.ts';

/** A real second in this century: its u64be encoding begins with four zero bytes. */
const NOW = 1_782_518_400;

/** An owner key deliberately containing embedded zero bytes. */
const ZEROISH_OWNER = (() => {
  const key = new Uint8Array(32).fill(0x41);
  key[0] = 0x00;
  key[7] = 0x00;
  key[31] = 0x00;
  return key;
})();

const startsWith = (key: Uint8Array, prefix: Uint8Array): boolean =>
  key.length >= prefix.length && prefix.every((b, i) => key[i] === b);

const lessThan = (a: Uint8Array, b: Uint8Array): boolean => {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    if (a[i]! !== b[i]!) return a[i]! < b[i]!;
  }
  return a.length < b.length;
};

/* -------------------------------------------------------------------------- */
/* AUDIT: fixed-width components are NOT free of the separator byte            */
/* -------------------------------------------------------------------------- */

test('AUDIT: a real timestamp is full of separator bytes', () => {
  // REGISTRY.md justified the layout by saying components "contain no 0x00 (guaranteed by the
  // label grammar and by fixed-width integers)". The label grammar half is true. The
  // fixed-width half is not: every second in this century encodes with four leading zero
  // bytes. An implementer who reads that sentence and splits a key on 0x00 parses the expiry
  // and rate keyspaces wrongly on EVERY key.
  const encoded = encodeTimestamp(NOW);
  assert.deepEqual(Array.from(encoded.subarray(0, 4)), [0, 0, 0, 0]);
  assert.ok(encoded.includes(0x00));

  // Decoding must therefore be positional, and must survive it.
  const key = expiryKey(NOW, 'vayu', 'atlas');
  assert.deepEqual(decodeExpiryKey(key), { notAfter: NOW, tld: 'vayu', label: 'atlas' });
});

test('AUDIT: an owner key containing zero bytes still round-trips', () => {
  // An Ed25519 public key is uniform random, so it holds at least one 0x00 about 12% of the
  // time — roughly one key in eight. A separator-scanning decoder truncates those and returns
  // another owner's names.
  assert.ok(ZEROISH_OWNER.includes(0x00));
  const key = byOwnerKey(ZEROISH_OWNER, 'vayu', 'atlas');
  const decoded = decodeByOwnerKey(key);
  assert.deepEqual(decoded.ownerKey, ZEROISH_OWNER);
  assert.equal(decoded.tld, 'vayu');
  assert.equal(decoded.label, 'atlas');
});

test('AUDIT: splitting on the separator would mis-parse, which is why decoding is positional', () => {
  // Demonstrates the wrong implementation against the right one, so the hazard is recorded as
  // behaviour rather than as a warning in a comment.
  const key = byOwnerKey(ZEROISH_OWNER, 'vayu', 'atlas');

  const naive: Uint8Array[] = [];
  let start = 0;
  for (let i = 0; i < key.length; i += 1) {
    if (key[i] === 0x00) {
      naive.push(key.slice(start, i));
      start = i + 1;
    }
  }
  naive.push(key.slice(start));

  // The naive split yields more fields than the layout has, because the owner key broke apart.
  assert.ok(naive.length > 4, 'a zero-containing owner key fragments under a naive split');
  assert.deepEqual(decodeByOwnerKey(key).ownerKey, ZEROISH_OWNER);
});

/* -------------------------------------------------------------------------- */
/* Round trips                                                                 */
/* -------------------------------------------------------------------------- */

test('every keyspace round-trips', () => {
  assert.deepEqual(decodeCurrentKey(currentKey('vayu', 'atlas')), {
    tld: 'vayu',
    label: 'atlas',
  });
  assert.deepEqual(decodeRateKey(rateKey('p2p', NOW, 'zenith')), {
    tld: 'p2p',
    notBefore: NOW,
    label: 'zenith',
  });
  assert.deepEqual(decodeExpiryKey(expiryKey(0, 'blog', 'a-b-c')), {
    notAfter: 0,
    tld: 'blog',
    label: 'a-b-c',
  });
});

test('timestamps round-trip across the representable range', () => {
  for (const value of [0, 1, 255, 256, NOW, 2 ** 32, 2 ** 40, MAX_TIMESTAMP]) {
    assert.equal(decodeTimestamp(encodeTimestamp(value), 0), value, String(value));
  }
});

test('a timestamp outside the representable range is refused, not truncated', () => {
  assert.throws(() => encodeTimestamp(-1), KeyError);
  assert.throws(() => encodeTimestamp(MAX_TIMESTAMP + 1), KeyError);
  assert.throws(() => encodeTimestamp(1.5), KeyError);
});

/* -------------------------------------------------------------------------- */
/* Ordering — the property the whole layout exists for                         */
/* -------------------------------------------------------------------------- */

test('big-endian timestamps make byte order agree with numeric order', () => {
  // If this fails, the expiry queue silently returns the wrong set: a range scan is only a
  // range if lexicographic order is numeric order.
  const instants = [0, 1, 255, 256, 65_535, 65_536, NOW, NOW + 1, 2 ** 32, 2 ** 40];
  for (let i = 1; i < instants.length; i += 1) {
    assert.ok(
      lessThan(encodeTimestamp(instants[i - 1]!), encodeTimestamp(instants[i]!)),
      `${instants[i - 1]} must sort before ${instants[i]}`,
    );
  }
});

test('names expiring earlier sort earlier regardless of their label', () => {
  const early = expiryKey(NOW, 'vayu', 'zzzzz');
  const late = expiryKey(NOW + 1, 'vayu', 'aaaaa');
  assert.ok(lessThan(early, late), 'the timestamp must dominate the label');
});

test('one TLD occupies a contiguous range, so a later TLD moves no existing key', () => {
  const inRange = [currentKey('vayu', 'atlas'), currentKey('vayu', 'zenith')];
  const prefix = currentPrefix('vayu');
  for (const key of inRange) assert.ok(startsWith(key, prefix), 'key must sit under its prefix');
  assert.ok(!startsWith(currentKey('p2p', 'atlas'), prefix));
  assert.ok(!startsWith(currentKey('vayux', 'atlas'), prefix), 'a longer TLD must not collide');
});

test('an owner prefix scan finds exactly that owner', () => {
  const prefix = byOwnerPrefix(ZEROISH_OWNER);
  assert.ok(startsWith(byOwnerKey(ZEROISH_OWNER, 'vayu', 'atlas'), prefix));
  const other = new Uint8Array(32).fill(0x41);
  assert.ok(!startsWith(byOwnerKey(other, 'vayu', 'atlas'), prefix));
});

test('the four keyspaces are disjoint', () => {
  const tags = new Set([
    currentKey('vayu', 'a')[0],
    byOwnerKey(new Uint8Array(32), 'vayu', 'a')[0],
    expiryKey(0, 'vayu', 'a')[0],
    rateKey('vayu', 0, 'a')[0],
  ]);
  assert.equal(tags.size, 4, 'each keyspace needs its own tag or scans bleed into each other');
});

/* -------------------------------------------------------------------------- */
/* Ranges                                                                      */
/* -------------------------------------------------------------------------- */

test('the expiry range is half-open and brackets exactly the right keys', () => {
  const { gte, lt } = expiryRange(NOW, NOW + 100);
  const inside = expiryKey(NOW + 50, 'vayu', 'atlas');
  const atStart = expiryKey(NOW, 'vayu', 'atlas');
  const atEnd = expiryKey(NOW + 100, 'vayu', 'atlas');

  assert.ok(!lessThan(atStart, gte), 'the start is included');
  assert.ok(lessThan(atStart, lt));
  assert.ok(!lessThan(inside, gte));
  assert.ok(lessThan(inside, lt));
  assert.ok(!lessThan(atEnd, lt), 'the end is excluded');
});

test('the rate range is confined to one TLD', () => {
  const { gte, lt } = rateRange('vayu', NOW, NOW + 100);
  assert.ok(!lessThan(rateKey('vayu', NOW + 50, 'atlas'), gte));
  assert.ok(lessThan(rateKey('vayu', NOW + 50, 'atlas'), lt));
  // A different TLD sits outside the bracket entirely, which is what makes the difficulty
  // window one bounded scan rather than a filtered full walk.
  const otherTld = rateKey('p2p', NOW + 50, 'atlas');
  assert.ok(lessThan(otherTld, gte) || !lessThan(otherTld, lt));
});

test('an inverted range is refused rather than silently returning nothing', () => {
  assert.throws(() => expiryRange(NOW + 1, NOW), KeyError);
  assert.throws(() => rateRange('vayu', NOW + 1, NOW), KeyError);
});

/* -------------------------------------------------------------------------- */
/* Rejections                                                                  */
/* -------------------------------------------------------------------------- */

test('a component carrying the separator is refused, since it would collide', () => {
  // Two distinct names must never encode to one key.
  assert.throws(() => currentKey('va yu', 'atlas'), KeyError);
  assert.throws(() => currentKey('vayu', 'at las'), KeyError);
  assert.throws(() => currentKey('', 'atlas'), KeyError);
  assert.throws(() => currentKey('vayu', ''), KeyError);
});

test('an owner key of the wrong width is refused', () => {
  assert.throws(() => byOwnerKey(new Uint8Array(31), 'vayu', 'atlas'), KeyError);
  assert.throws(() => byOwnerPrefix(new Uint8Array(33)), KeyError);
});

test('decoding refuses a key from another keyspace', () => {
  assert.throws(() => decodeCurrentKey(expiryKey(NOW, 'vayu', 'atlas')), KeyError);
  assert.throws(() => decodeExpiryKey(currentKey('vayu', 'atlas')), KeyError);
  assert.throws(() => decodeByOwnerKey(Uint8Array.of(TAG_CURRENT, 0x00)), KeyError);
});

test('decoding refuses truncated keys rather than inventing components', () => {
  assert.throws(() => decodeExpiryKey(Uint8Array.of(TAG_EXPIRY, 0x00, 0x00)), KeyError);
  assert.throws(() => decodeCurrentKey(Uint8Array.of(TAG_CURRENT)), KeyError);
  const key = byOwnerKey(ZEROISH_OWNER, 'vayu', 'atlas');
  assert.throws(() => decodeByOwnerKey(key.slice(0, 20)), KeyError);
});
