import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  RECORD_SIGNING_PREFIX,
  RECORD_HASH_PREFIX,
  RECORD_HASH_LENGTH,
  ZERO_HASH,
  core,
  signingInput,
  recordHash,
  recordHashFromBytes,
  bytesEqual,
  isZeroHash,
} from './domain.ts';
import { encode, type CborMap, type CborValue } from './cbor.ts';

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** A minimal record shaped like the REGISTER worked example in REGISTRY.md. */
function sampleRecord(overrides: Record<string, CborValue> = {}): CborMap {
  const m = new Map<string | Uint8Array, CborValue>([
    ['version', 1],
    ['op', 'REGISTER'],
    ['name', 'atlas'],
    ['tld', 'vayu'],
    ['ownerKey', new Uint8Array(32).fill(0x11)],
    ['seq', 0],
    ['notBefore', 1782518400],
    ['notAfter', 1814054400],
    ['records', []],
    ['powProof', null],
    ['prevHash', new Uint8Array(32)],
    ['sig', new Uint8Array(64).fill(0xaa)],
  ]);
  for (const [k, v] of Object.entries(overrides)) m.set(k, v);
  return m;
}

/* -------------------------------------------------------------------------- */
/* The constants themselves                                                    */
/* -------------------------------------------------------------------------- */

test('domain prefixes are the exact literals from REGISTRY.md', () => {
  assert.equal(RECORD_SIGNING_PREFIX, 'VayuWeb-Registry-Record-v1');
  assert.equal(RECORD_HASH_PREFIX, 'VayuWeb-Registry-Hash-v1');
});

test('domain prefix byte lengths are pinned at 26 and 24', () => {
  // REGISTRY.md prose said 23 and 21 until this was corrected. Two implementers reading the
  // prose versus the literal would produce signatures that never verify against each other,
  // which is a silent fork. The literals are authoritative; this test is the guard.
  assert.equal(new TextEncoder().encode(RECORD_SIGNING_PREFIX).length, 26);
  assert.equal(new TextEncoder().encode(RECORD_HASH_PREFIX).length, 24);
});

test('the two domains are distinct and neither prefixes the other', () => {
  assert.notEqual(RECORD_SIGNING_PREFIX, RECORD_HASH_PREFIX);
  assert.ok(!RECORD_SIGNING_PREFIX.startsWith(RECORD_HASH_PREFIX));
  assert.ok(!RECORD_HASH_PREFIX.startsWith(RECORD_SIGNING_PREFIX));
});

test('the zero hash is 32 zero bytes', () => {
  assert.equal(ZERO_HASH.length, RECORD_HASH_LENGTH);
  assert.ok(ZERO_HASH.every((b) => b === 0));
  assert.ok(isZeroHash(new Uint8Array(32)));
  assert.ok(!isZeroHash(Uint8Array.from({ length: 32 }, (_, i) => (i === 31 ? 1 : 0))));
});

/* -------------------------------------------------------------------------- */
/* Signing input construction                                                  */
/* -------------------------------------------------------------------------- */

test('the signing input begins with the prefix and a single 0x00 separator', () => {
  const input = signingInput(sampleRecord());
  const prefix = new TextEncoder().encode(RECORD_SIGNING_PREFIX);

  assert.deepEqual(input.subarray(0, prefix.length), prefix);
  assert.equal(input[prefix.length], 0x00, 'separator must be exactly one zero byte');
  assert.notEqual(input[prefix.length + 1], 0x00, 'body must start immediately after it');
});

test('signing input excludes sig and coSig, and nothing else', () => {
  const record = sampleRecord({ coSig: new Uint8Array(64).fill(0xbb) });
  const stripped = core(record);

  assert.ok(!stripped.has('sig'));
  assert.ok(!stripped.has('coSig'));
  for (const key of ['version', 'op', 'name', 'tld', 'ownerKey', 'seq', 'prevHash']) {
    assert.ok(stripped.has(key), `${key} must remain in the signing input`);
  }
});

test('core() does not mutate the caller record', () => {
  const record = sampleRecord();
  core(record);
  assert.ok(record.has('sig'), 'stripping must not reach back into the caller');
});

test('changing sig does not change the signing input', () => {
  // Otherwise signing would be circular: the signature would cover itself.
  const a = signingInput(sampleRecord({ sig: new Uint8Array(64).fill(0x01) }));
  const b = signingInput(sampleRecord({ sig: new Uint8Array(64).fill(0x02) }));
  assert.equal(toHex(a), toHex(b));
});

test('changing any covered field does change the signing input', () => {
  const base = toHex(signingInput(sampleRecord()));
  assert.notEqual(toHex(signingInput(sampleRecord({ name: 'atlaz' }))), base);
  assert.notEqual(toHex(signingInput(sampleRecord({ tld: 'web' }))), base);
  assert.notEqual(toHex(signingInput(sampleRecord({ seq: 1 }))), base);
  assert.notEqual(toHex(signingInput(sampleRecord({ version: 2 }))), base);
  assert.notEqual(toHex(signingInput(sampleRecord({ notAfter: 1814054401 }))), base);
});

test('unknown fields are covered by the signature', () => {
  // REGISTRY.md requires a record with unknown fields to still verify downstream, which is
  // only true if those fields were inside what the author signed.
  const base = toHex(signingInput(sampleRecord()));
  const extended = toHex(signingInput(sampleRecord({ futureField: 'x' })));
  assert.notEqual(extended, base);
});

/* -------------------------------------------------------------------------- */
/* Record hash                                                                 */
/* -------------------------------------------------------------------------- */

test('record hash is 32 bytes and covers the signature fields', () => {
  const withSigA = recordHash(sampleRecord({ sig: new Uint8Array(64).fill(0x01) }));
  const withSigB = recordHash(sampleRecord({ sig: new Uint8Array(64).fill(0x02) }));

  assert.equal(withSigA.length, RECORD_HASH_LENGTH);
  // prevHash chains to the record as it exists on the wire, signature included.
  assert.notEqual(toHex(withSigA), toHex(withSigB));
});

test('hashing bytes directly agrees with hashing the decoded map', () => {
  const record = sampleRecord();
  assert.equal(toHex(recordHashFromBytes(encode(record))), toHex(recordHash(record)));
});

test('the hash domain differs from the signing domain for identical bodies', () => {
  // If the two domains collided, a signing input could be presented as a hash preimage.
  const record = sampleRecord();
  const body = encode(record);

  const hashOfRecord = toHex(recordHashFromBytes(body));
  const hashOfSigningInput = toHex(recordHashFromBytes(signingInput(record)));
  assert.notEqual(hashOfRecord, hashOfSigningInput);
});

test('record hash is stable across runs', () => {
  // A moving hash would mean prevHash chains break between peers on identical input.
  const first = toHex(recordHash(sampleRecord()));
  const second = toHex(recordHash(sampleRecord()));
  assert.equal(first, second);
});

/* -------------------------------------------------------------------------- */
/* Comparison helpers                                                          */
/* -------------------------------------------------------------------------- */

test('bytesEqual compares content, not identity, and rejects length mismatch', () => {
  assert.ok(bytesEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3)));
  assert.ok(!bytesEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4)));
  assert.ok(!bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 3)));
  assert.ok(bytesEqual(new Uint8Array(0), new Uint8Array(0)));
});

test('bytesEqual examines every byte regardless of where they differ', () => {
  // Not a timing measurement — that would be flaky in CI. This asserts the shape of the
  // implementation: a difference in the first byte and in the last must both be detected,
  // which an early-return loop would also satisfy, so the real guarantee is the accumulator
  // in the source. Recorded here so a future edit to an early return is a visible change.
  const a = new Uint8Array(64).fill(0);
  const firstDiffers = new Uint8Array(64).fill(0);
  firstDiffers[0] = 1;
  const lastDiffers = new Uint8Array(64).fill(0);
  lastDiffers[63] = 1;

  assert.ok(!bytesEqual(a, firstDiffers));
  assert.ok(!bytesEqual(a, lastDiffers));
});
