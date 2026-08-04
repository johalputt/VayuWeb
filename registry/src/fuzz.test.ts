import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  encode,
  decode,
  isDeterministic,
  CborError,
  type CborValue,
  type CborMap,
} from './cbor.ts';
import { treeOf, proveInclusion, verifyInclusion, MerkleTree } from './merkle.ts';
import { encodeTimestamp, decodeTimestamp, currentKey, decodeCurrentKey } from './keys.ts';
import { compareHashes } from './converge.ts';

/**
 * A seeded generator, so a failure is reproducible from its seed.
 *
 * `Math.random` is forbidden in this repository precisely so that a fuzz failure can be replayed
 * rather than merely reported. xorshift128 is not cryptographic and does not need to be: it is
 * generating test inputs, not keys.
 */
function rng(seed: number) {
  let x = seed | 0 || 1;
  return () => {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    return (x >>> 0) / 0x1_0000_0000;
  };
}

const ITERATIONS = 400;

function randomValue(next: () => number, depth = 0): CborValue {
  const roll = next();
  if (depth > 3 || roll < 0.3) {
    if (roll < 0.1) return Math.floor(next() * 1_000_000);
    if (roll < 0.2) {
      const len = Math.floor(next() * 12);
      return new Uint8Array(Array.from({ length: len }, () => Math.floor(next() * 256)));
    }
    return Array.from({ length: Math.floor(next() * 8) }, () =>
      String.fromCharCode(97 + Math.floor(next() * 26)),
    ).join('');
  }
  if (roll < 0.65) {
    return Array.from({ length: Math.floor(next() * 4) }, () => randomValue(next, depth + 1));
  }
  const map: CborMap = new Map<string | Uint8Array, CborValue>();
  const count = Math.floor(next() * 5);
  for (let i = 0; i < count; i += 1) {
    const key = Array.from({ length: 1 + Math.floor(next() * 5) }, () =>
      String.fromCharCode(97 + Math.floor(next() * 26)),
    ).join('');
    map.set(key, randomValue(next, depth + 1));
  }
  return map;
}

/* -------------------------------------------------------------------------- */
/* CBOR: the encoding must be the unique one, or record_hash is malleable      */
/* -------------------------------------------------------------------------- */

test('fuzz: encode then decode returns the same value, and re-encodes identically', () => {
  const next = rng(0x5eed);
  for (let i = 0; i < ITERATIONS; i += 1) {
    const value = randomValue(next);
    const bytes = encode(value);
    const back = decode(bytes);
    const again = encode(back);
    assert.deepEqual(
      Array.from(again),
      Array.from(bytes),
      `round trip changed the bytes at iteration ${i}`,
    );
    assert.ok(isDeterministic(bytes), `encoder produced non-canonical bytes at iteration ${i}`);
  }
});

test('fuzz: every single-byte mutation is either rejected or changes the value', () => {
  // The property that makes record_hash meaningful: no two byte strings decode to one value.
  // A mutation that both decoded and produced an identical value would be a second encoding.
  const next = rng(0xc0ffee);
  let mutations = 0;
  let rejected = 0;

  for (let i = 0; i < 120; i += 1) {
    const value = randomValue(next);
    const bytes = encode(value);
    if (bytes.length === 0) continue;

    const at = Math.floor(next() * bytes.length);
    const flipped = new Uint8Array(bytes);
    flipped[at] = (flipped[at]! ^ (1 << Math.floor(next() * 8))) & 0xff;
    if (flipped[at] === bytes[at]) continue;
    mutations += 1;

    let decoded: CborValue | null = null;
    try {
      decoded = decode(flipped);
    } catch (error) {
      assert.ok(error instanceof CborError, 'a malformed encoding must fail as CborError');
      rejected += 1;
      continue;
    }
    // If it decoded, its canonical re-encoding must differ from the original bytes — otherwise
    // two byte strings would map to one value.
    const reencoded = encode(decoded);
    assert.notDeepEqual(
      Array.from(reencoded),
      Array.from(bytes),
      `mutation at byte ${at} produced a second encoding of the same value`,
    );
  }
  assert.ok(mutations > 50, 'the fuzzer must actually be mutating');
  assert.ok(rejected > 0, 'some mutations must be outright malformed');
});

test('fuzz: decoding arbitrary bytes never hangs and never returns silently wrong data', () => {
  const next = rng(0xbadbeef);
  for (let i = 0; i < ITERATIONS; i += 1) {
    const len = Math.floor(next() * 40);
    const bytes = new Uint8Array(Array.from({ length: len }, () => Math.floor(next() * 256)));
    try {
      const value = decode(bytes);
      // Anything that decodes must re-encode to exactly the input, or the decoder accepted a
      // non-canonical encoding.
      assert.deepEqual(Array.from(encode(value)), Array.from(bytes));
    } catch (error) {
      assert.ok(error instanceof CborError, `unexpected error kind: ${String(error)}`);
    }
  }
});

/* -------------------------------------------------------------------------- */
/* Merkle: incremental and rebuilt must agree at every length                  */
/* -------------------------------------------------------------------------- */

test('fuzz: incremental appends match a rebuild, at random lengths and sizes', () => {
  const next = rng(0x7ee7);
  for (let round = 0; round < 30; round += 1) {
    const count = 1 + Math.floor(next() * 40);
    const entries = Array.from({ length: count }, () => {
      const size = 1 + Math.floor(next() * 30);
      return new Uint8Array(Array.from({ length: size }, () => Math.floor(next() * 256)));
    });

    const incremental = new MerkleTree();
    for (const e of entries) incremental.append(e);
    assert.deepEqual(
      Array.from(incremental.root()),
      Array.from(treeOf(entries).root()),
      `incremental and rebuilt roots differ for ${count} entries`,
    );
  }
});

test('fuzz: every leaf proves inclusion, and no leaf proves another', () => {
  const next = rng(0x1337);
  for (let round = 0; round < 20; round += 1) {
    const count = 1 + Math.floor(next() * 24);
    const entries = Array.from({ length: count }, (_, i) => {
      const size = 1 + Math.floor(next() * 12);
      return new Uint8Array(Array.from({ length: size }, () => (i * 7 + 3) % 256));
    });
    const root = treeOf(entries).root();

    for (let leaf = 0; leaf < count; leaf += 1) {
      const proof = proveInclusion(entries, leaf);
      assert.ok(verifyInclusion(entries[leaf]!, proof, root), `leaf ${leaf}/${count}`);

      const other = (leaf + 1) % count;
      if (count > 1 && entries[other]!.length !== entries[leaf]!.length) {
        assert.equal(
          verifyInclusion(entries[other]!, proof, root),
          false,
          `leaf ${other} must not verify against leaf ${leaf}'s proof`,
        );
      }
    }
  }
});

/* -------------------------------------------------------------------------- */
/* Keys and ordering                                                           */
/* -------------------------------------------------------------------------- */

test('fuzz: timestamps round-trip and sort numerically at every magnitude', () => {
  const next = rng(0xfeed);
  const values: number[] = [];
  for (let i = 0; i < ITERATIONS; i += 1) {
    const value = Math.floor(next() * 2 ** 40);
    values.push(value);
    assert.equal(decodeTimestamp(encodeTimestamp(value), 0), value);
  }
  const sorted = [...values].sort((a, b) => a - b);
  const byBytes = [...values].sort((a, b) => compareHashes(encodeTimestamp(a), encodeTimestamp(b)));
  assert.deepEqual(byBytes, sorted, 'byte order must equal numeric order');
});

test('fuzz: name keys round-trip for every label the grammar admits', () => {
  const next = rng(0xabcd);
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789-';
  for (let i = 0; i < ITERATIONS; i += 1) {
    const length = 1 + Math.floor(next() * 20);
    let label = '';
    for (let j = 0; j < length; j += 1) {
      label += alphabet[Math.floor(next() * alphabet.length)];
    }
    const decoded = decodeCurrentKey(currentKey('vayu', label));
    assert.equal(decoded.label, label);
    assert.equal(decoded.tld, 'vayu');
  }
});
