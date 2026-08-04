import { test } from 'node:test';
import assert from 'node:assert/strict';

import { encode, decode, isDeterministic, CborError, type CborMap, type CborValue } from './cbor.ts';

const hex = (s: string): Uint8Array =>
  Uint8Array.from(s.match(/../g)?.map((b) => parseInt(b, 16)) ?? []);

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

const rejects = (bytes: Uint8Array, code: string): void => {
  assert.throws(
    () => decode(bytes),
    (err: unknown) => err instanceof CborError && err.code === code,
    `expected ${code} for ${toHex(bytes)}`,
  );
};

/* -------------------------------------------------------------------------- */
/* Preferred (shortest) integer encoding — RFC 8949 §4.2.1 rule 1              */
/* -------------------------------------------------------------------------- */

test('unsigned integers use the shortest head form', () => {
  assert.equal(toHex(encode(0)), '00');
  assert.equal(toHex(encode(23)), '17');
  assert.equal(toHex(encode(24)), '1818');
  assert.equal(toHex(encode(255)), '18ff');
  assert.equal(toHex(encode(256)), '190100');
  assert.equal(toHex(encode(65535)), '19ffff');
  assert.equal(toHex(encode(65536)), '1a00010000');
  assert.equal(toHex(encode(4294967295)), '1affffffff');
  assert.equal(toHex(encode(4294967296n)), '1b0000000100000000');
});

test('a non-shortest integer head is rejected, not silently accepted', () => {
  // Every one of these decodes to 5 under permissive CBOR. Accepting any of them would
  // mean five byte strings encode one record, and record_hash stops being unique.
  rejects(hex('1805'), 'NON_CANONICAL');
  rejects(hex('190005'), 'NON_CANONICAL');
  rejects(hex('1a00000005'), 'NON_CANONICAL');
  rejects(hex('1b0000000000000005'), 'NON_CANONICAL');
});

test('a non-shortest length head is rejected', () => {
  // Byte string of length 1, written with a one-byte length argument.
  rejects(hex('5801aa'), 'NON_CANONICAL');
  // Text string of length 1, likewise.
  rejects(hex('780161'), 'NON_CANONICAL');
});

test('integers round-trip through the safe-integer boundary', () => {
  for (const n of [0, 1, 23, 24, 1000, Number.MAX_SAFE_INTEGER]) {
    assert.equal(decode(encode(n)), n);
  }
  assert.equal(decode(encode(2n ** 63n)), 2n ** 63n);
});

/* -------------------------------------------------------------------------- */
/* Map key ordering — RFC 8949 §4.2.1 rule 3                                   */
/* -------------------------------------------------------------------------- */

test('map keys are sorted by encoded bytes, not by code point', () => {
  const m: CborMap = new Map();
  // Inserted in deliberately wrong order.
  m.set('version', 1);
  m.set('op', 'REGISTER');
  m.set('seq', 0);

  const bytes = encode(m);
  const decoded = decode(bytes) as CborMap;

  // Sorting is by encoded key: shorter keys sort first because their head byte is smaller.
  assert.deepEqual([...decoded.keys()], ['op', 'seq', 'version']);
  assert.ok(isDeterministic(bytes));
});

test('encoded-byte ordering differs from naive code-point ordering', () => {
  const m: CborMap = new Map();
  m.set('z', 1); // encodes 61 7a  (length 1)
  m.set('aa', 2); // encodes 62 61 61 (length 2)

  // Code point would put "aa" first. Encoded bytes put "z" first, because 0x61 < 0x62.
  assert.deepEqual([...(decode(encode(m)) as CborMap).keys()], ['z', 'aa']);
});

test('a map with keys out of order is rejected on decode', () => {
  // {"b": 1, "a": 2} — valid CBOR, not deterministic.
  rejects(hex('a2616201616102'), 'KEYS_OUT_OF_ORDER');
});

test('a duplicate map key is rejected in both directions', () => {
  // {"a": 1, "a": 2}
  rejects(hex('a2616101616102'), 'DUPLICATE_KEY');

  const m = new Map<string | Uint8Array, number>();
  m.set('a', 1);
  // A JS Map cannot hold a duplicate string key, so exercise the byte-string path where
  // two distinct Uint8Array objects encode identically.
  const dup = new Map<string | Uint8Array, number>();
  dup.set(Uint8Array.of(1), 1);
  dup.set(Uint8Array.of(1), 2);
  assert.throws(() => encode(dup as CborMap), (e: unknown) => e instanceof CborError && e.code === 'DUPLICATE_KEY');
  assert.ok(encode(m as CborMap).length > 0);
});

/* -------------------------------------------------------------------------- */
/* Definite length only — RFC 8949 §4.2.1 rule 2                               */
/* -------------------------------------------------------------------------- */

test('indefinite-length items are rejected', () => {
  rejects(hex('5f42010243030405ff'), 'INDEFINITE_LENGTH'); // indefinite byte string
  rejects(hex('7f6161616bff'), 'INDEFINITE_LENGTH'); // indefinite text string
  rejects(hex('9f0102ff'), 'INDEFINITE_LENGTH'); // indefinite array
  rejects(hex('bf616101616202ff'), 'INDEFINITE_LENGTH'); // indefinite map
});

/* -------------------------------------------------------------------------- */
/* Types outside the profile                                                   */
/* -------------------------------------------------------------------------- */

test('types outside the registry profile are rejected', () => {
  rejects(hex('20'), 'UNSUPPORTED_MAJOR'); // negative integer -1
  rejects(hex('c11a514b67b0'), 'UNSUPPORTED_MAJOR'); // tag 1 (epoch time)
  rejects(hex('f5'), 'UNSUPPORTED_SIMPLE'); // true
  rejects(hex('f4'), 'UNSUPPORTED_SIMPLE'); // false
  rejects(hex('f7'), 'UNSUPPORTED_SIMPLE'); // undefined
  rejects(hex('fb3ff199999999999a'), 'FLOAT_NOT_ALLOWED'); // double 1.1
  rejects(hex('f97e00'), 'FLOAT_NOT_ALLOWED'); // half NaN
});

test('null is the only simple value in the profile', () => {
  assert.equal(toHex(encode(null)), 'f6');
  assert.equal(decode(hex('f6')), null);
});

test('negative and non-integer numbers are refused on encode', () => {
  assert.throws(() => encode(-1), (e: unknown) => e instanceof CborError && e.code === 'NEGATIVE_INT');
  assert.throws(() => encode(1.5), (e: unknown) => e instanceof CborError && e.code === 'NON_INTEGER');
  assert.throws(() => encode(NaN), (e: unknown) => e instanceof CborError && e.code === 'NON_INTEGER');
});

/* -------------------------------------------------------------------------- */
/* Framing                                                                     */
/* -------------------------------------------------------------------------- */

test('trailing bytes are rejected', () => {
  // A record is exactly its bytes. A tolerated suffix would let two inputs carry one
  // record while hashing differently.
  rejects(hex('00ff'), 'TRAILING_BYTES');
});

test('truncated input is rejected rather than padded', () => {
  rejects(hex('42aa'), 'TRUNCATED'); // byte string claims 2 bytes, supplies 1
  rejects(hex('a1'), 'TRUNCATED'); // map claims 1 pair, supplies none
});

test('a declared length larger than the input cannot allocate', () => {
  // Claims a 2^32-byte string in a 5-byte input.
  rejects(hex('5affffffff'), 'LENGTH_TOO_LARGE');
});

/* -------------------------------------------------------------------------- */
/* Text handling                                                               */
/* -------------------------------------------------------------------------- */

test('invalid UTF-8 in a text string is rejected, not replaced', () => {
  // 0xff is never valid UTF-8. Substituting U+FFFD would change the signed value.
  rejects(hex('61ff'), 'INVALID_UTF8');
});

test('a lone surrogate is refused on encode', () => {
  assert.throws(
    () => encode('\ud800'),
    (e: unknown) => e instanceof CborError && e.code === 'INVALID_TEXT',
  );
});

/* -------------------------------------------------------------------------- */
/* Structural limits                                                           */
/* -------------------------------------------------------------------------- */

test('excessive nesting is refused in both directions', () => {
  let deep: unknown = 0;
  for (let i = 0; i < 40; i++) deep = [deep];
  assert.throws(
    () => encode(deep as never),
    (e: unknown) => e instanceof CborError && e.code === 'DEPTH_EXCEEDED',
  );

  // 40 nested single-element arrays: 0x81 repeated, then 0x00.
  rejects(hex('81'.repeat(40) + '00'), 'DEPTH_EXCEEDED');
});

/* -------------------------------------------------------------------------- */
/* Round-trip and aliasing                                                     */
/* -------------------------------------------------------------------------- */

test('a decoded byte string does not alias the input buffer', () => {
  const input = hex('43010203');
  const out = decode(input) as Uint8Array;
  out[0] = 0xff;
  assert.equal(input[1], 0x01, 'mutating the decoded value must not corrupt the input');
});

test('isDeterministic accepts canonical bytes and rejects the rest', () => {
  const m: CborMap = new Map<string | Uint8Array, CborValue>([
    ['a', 1],
    ['b', Uint8Array.of(1, 2, 3)],
  ]);
  assert.ok(isDeterministic(encode(m)));
  assert.ok(!isDeterministic(hex('a2616201616102'))); // keys out of order
  assert.ok(!isDeterministic(hex('1805'))); // non-shortest integer
  assert.ok(!isDeterministic(hex('00ff'))); // trailing byte
});

test('a nested registry-shaped record round-trips byte-identically', () => {
  const entry: CborMap = new Map<string | Uint8Array, unknown>([
    ['type', 'peer'],
    ['value', new Uint8Array(32).fill(7)],
    ['ttl', 3600],
  ]) as CborMap;

  const pow: CborMap = new Map<string | Uint8Array, unknown>([
    ['alg', 'argon2id'],
    ['m', 262144],
    ['t', 3],
    ['p', 1],
    ['salt', new Uint8Array(16).fill(9)],
    ['nonce', 41827366],
    ['bits', 22],
  ]) as CborMap;

  const record: CborMap = new Map<string | Uint8Array, unknown>([
    ['version', 1],
    ['op', 'REGISTER'],
    ['name', 'atlas'],
    ['tld', 'vayu'],
    ['ownerKey', new Uint8Array(32).fill(1)],
    ['seq', 0],
    ['notBefore', 1782518400],
    ['notAfter', 1814054400],
    ['records', [entry]],
    ['powProof', pow],
    ['prevHash', new Uint8Array(32)],
  ]) as CborMap;

  const bytes = encode(record);
  assert.ok(isDeterministic(bytes));
  assert.equal(toHex(encode(decode(bytes) as CborMap)), toHex(bytes));
});
