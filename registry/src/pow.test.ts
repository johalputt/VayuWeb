import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  POW_ALGORITHM,
  POW_NONCE_LENGTH,
  MAX_DIFFICULTY_BITS,
  RATE_FLOOR,
  baseBits,
  requiredBits,
  rateWindow,
  powSalt,
  powTag,
  tagSatisfies,
  verifyPow,
  checkRecordPow,
  solvePow,
} from './pow.ts';
import { parseRecord, RecordError } from './record.ts';
import { type CborMap, type CborValue } from './cbor.ts';

const entry = (type: string, value: CborValue): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['type', type],
    ['value', value],
  ]);

const proof = (over: Record<string, CborValue> = {}): CborMap => {
  const m = new Map<string | Uint8Array, CborValue>([
    ['alg', POW_ALGORITHM],
    ['nonce', new Uint8Array(POW_NONCE_LENGTH).fill(7)],
    ['bits', 10],
  ]);
  for (const [k, v] of Object.entries(over)) {
    if (v === undefined) m.delete(k);
    else m.set(k, v);
  }
  return m;
};

const record = (over: Record<string, CborValue> = {}): CborMap => {
  const m = new Map<string | Uint8Array, CborValue>([
    ['version', 1],
    ['suite', 1],
    ['op', 'REGISTER'],
    ['name', 'atlas'],
    ['tld', 'vayu'],
    ['ownerKey', new Uint8Array(32).fill(0x11)],
    ['seq', 0],
    ['notBefore', 1782518400],
    ['notAfter', 1782518400 + 31536000],
    ['records', [entry('txt', 'v=vayuweb1')]],
    ['powProof', proof()],
    ['prevHash', new Uint8Array(32)],
    ['sig', new Uint8Array(64).fill(0xaa)],
  ]);
  for (const [k, v] of Object.entries(over)) m.set(k, v);
  return m;
};

const rejectsShape = (map: CborMap, needle: string): void => {
  assert.throws(
    () => parseRecord(map),
    (e: unknown) =>
      e instanceof RecordError && e.code === 'BAD_POW_SHAPE' && e.message.includes(needle),
    `expected BAD_POW_SHAPE mentioning ${needle}`,
  );
};

/* -------------------------------------------------------------------------- */
/* AUDIT FINDING: the proof must not carry its own cost or its own salt        */
/* -------------------------------------------------------------------------- */

test('AUDIT: a proof may not name its own cost parameters', () => {
  // REGISTRY.md's record schema listed `m`, `t` and `p` as record fields. That hands the
  // attacker the dial: submit m = 8 KiB and the "memory-hard" function fits in L1 cache. The
  // proof still verifies, because the verifier is evaluating the function the attacker chose.
  // Only rejecting zero — as an earlier implementation did — stops nothing: m = 1 is not zero.
  for (const knob of ['m', 't', 'p']) {
    rejectsShape(record({ powProof: proof({ [knob]: 1 }) }), knob);
  }
});

test('AUDIT: a proof may not carry its own salt, or one proof buys every name', () => {
  // A carried salt is a free parameter. Grind one (salt, nonce) pair to twenty bits once, then
  // staple that same proof onto every record you ever sign: the salt travels with it, so the
  // tag is unchanged and every one verifies. The anti-squatting cost collapses from per-name
  // to once, forever, which is the entire mechanism gone.
  rejectsShape(record({ powProof: proof({ salt: new Uint8Array(16) }) }), 'salt');
});

test('AUDIT: a salt smuggled into the proof is never used as the salt', () => {
  // The schema check above is one layer, and it only guards records that go through
  // parseRecord. verifyPow takes a raw map, so a caller that verifies before parsing would
  // reach the derivation directly with an attacker-controlled `salt` field present.
  //
  // This pins the second layer: derivation reads the record's bytes, never a field named
  // `salt`. Without it, relaxing the schema check silently restores the one-proof-buys-
  // everything attack, and the whole suite still passes — which is exactly what a mutation
  // test of that fix showed.
  const carried = new Uint8Array(16).fill(0xab);
  const derived = powSalt(record({ powProof: proof({ salt: carried }) }));
  assert.notDeepEqual(derived, carried, 'a carried salt must not become the salt');

  // And the tag follows the derivation, so the smuggled value buys nothing.
  const nonce = new Uint8Array(POW_NONCE_LENGTH).fill(7);
  assert.notDeepEqual(powTag(nonce, derived), powTag(nonce, carried));
});

test('AUDIT: a proof is bound to one record and cannot be moved to another', () => {
  // The positive statement of the same property, tested through the salt rather than the
  // schema: every field an attacker would want to vary changes the salt, so the work is void.
  const original = record();
  const salt = powSalt(original);

  const moved: Array<[string, CborValue]> = [
    ['name', 'zenith'],
    ['tld', 'p2p'],
    ['ownerKey', new Uint8Array(32).fill(0x22)],
    ['seq', 1],
    ['notBefore', 1782518401],
    ['notAfter', 1782518400 + 31536000 + 1],
    ['prevHash', new Uint8Array(32).fill(3)],
    ['records', [entry('txt', 'different')]],
  ];
  for (const [field, value] of moved) {
    const other = powSalt(record({ [field]: value }));
    assert.notDeepEqual(other, salt, `changing ${field} must change the salt`);
  }
});

test('the claimed difficulty is bound into the salt', () => {
  // `bits` stays in the salt preimage, so a proof produced at one difficulty cannot be
  // relabelled as satisfying another.
  assert.notDeepEqual(
    powSalt(record({ powProof: proof({ bits: 11 }) })),
    powSalt(record({ powProof: proof({ bits: 10 }) })),
  );
});

test('the nonce is excluded from the salt preimage', () => {
  // It must be, or the salt would move on every search step and the work would be unbounded
  // rather than merely expensive.
  assert.deepEqual(
    powSalt(record({ powProof: proof({ nonce: new Uint8Array(POW_NONCE_LENGTH).fill(1) }) })),
    powSalt(record({ powProof: proof({ nonce: new Uint8Array(POW_NONCE_LENGTH).fill(2) }) })),
  );
});

test('the signature is excluded from the salt preimage', () => {
  // The proof is produced before the record is signed, so including sig would be circular.
  assert.deepEqual(
    powSalt(record({ sig: new Uint8Array(64).fill(1) })),
    powSalt(record({ sig: new Uint8Array(64).fill(2) })),
  );
});

/* -------------------------------------------------------------------------- */
/* Schema                                                                      */
/* -------------------------------------------------------------------------- */

test('an unknown algorithm identifier is refused', () => {
  // The identifier names its parameters, so a proof from a different cost regime is
  // distinguishable rather than silently comparable.
  rejectsShape(record({ powProof: proof({ alg: 'argon2id' }) }), 'argon2id');
  rejectsShape(record({ powProof: proof({ alg: 'scrypt' }) }), 'scrypt');
});

test('the nonce is a fixed-width byte string', () => {
  assert.throws(
    () => parseRecord(record({ powProof: proof({ nonce: 41827366 }) })),
    (e: unknown) => e instanceof RecordError,
  );
  assert.throws(
    () => parseRecord(record({ powProof: proof({ nonce: new Uint8Array(15) }) })),
    (e: unknown) => e instanceof RecordError,
  );
});

test('a well-formed proof parses to exactly three fields', () => {
  const parsed = parseRecord(record());
  assert.ok(parsed.powProof);
  assert.equal(parsed.powProof.alg, POW_ALGORITHM);
  assert.equal(parsed.powProof.bits, 10);
  assert.equal(parsed.powProof.nonce.length, POW_NONCE_LENGTH);
});

/* -------------------------------------------------------------------------- */
/* Difficulty                                                                  */
/* -------------------------------------------------------------------------- */

test('short labels cost more', () => {
  assert.equal(baseBits(1), 10);
  assert.equal(baseBits(2), 10);
  assert.equal(baseBits(3), 9);
  assert.equal(baseBits(4), 8);
  assert.equal(baseBits(6), 7);
  assert.equal(baseBits(9), 6);
  assert.equal(baseBits(15), 5);
  assert.equal(baseBits(16), 4);
  assert.equal(baseBits(63), 4);
  // A two-character name costs 2^10 evaluations against 2^4 for a long one: 64 times.
  assert.equal(2 ** baseBits(2) / 2 ** baseBits(16), 64);
});

test('the rate term is silent below the floor and doubles with volume above it', () => {
  assert.equal(requiredBits(5, 0), 7);
  assert.equal(requiredBits(5, RATE_FLOOR - 1), 7);
  assert.equal(requiredBits(5, RATE_FLOOR), 7, 'exactly at the floor adds nothing');
  assert.equal(requiredBits(5, RATE_FLOOR * 2), 8);
  assert.equal(requiredBits(5, RATE_FLOOR * 4), 9);
});

test('the declared 20-bit cap is unreachable: the schedule tops out at 18', () => {
  // A claim check rather than a code check. PROOF-OF-WORK.md presents min(20, ...) as the
  // ceiling and describes twenty bits as "roughly a million evaluations — hours of CPU". The
  // schedule cannot produce it: base tops out at 10 and the rate term at 8, so the real worst
  // case is 18 bits, about 262,144 evaluations. The cap never binds.
  //
  // Pinned as a test because the number in the prose is the one a registrant budgets against,
  // and because a later schedule change that DID make 20 reachable should be a deliberate act
  // that fails here first.
  let reachable = 0;
  for (let length = 1; length <= 63; length += 1) {
    for (const volume of [
      0,
      RATE_FLOOR,
      RATE_FLOOR * 2,
      RATE_FLOOR * 256,
      RATE_FLOOR * 1_000_000,
    ]) {
      reachable = Math.max(reachable, requiredBits(length, volume));
    }
  }
  assert.equal(reachable, 18);
  assert.ok(reachable < MAX_DIFFICULTY_BITS, 'the cap is a ceiling the schedule never touches');
  assert.equal(requiredBits(63, RATE_FLOOR * 1_000_000), 4 + 8);
});

test('the rate window is quantised to the hour so skewed clocks agree', () => {
  const a = rateWindow(1782518400 + 60);
  const b = rateWindow(1782518400 + 3000);
  assert.deepEqual(a, b, 'two instants in one hour yield one window');
  assert.equal(a.end - a.start, 2_592_000);
  assert.equal(a.end % 3600, 0);
});

/* -------------------------------------------------------------------------- */
/* The bit test                                                                */
/* -------------------------------------------------------------------------- */

test('the leading-zero test counts from the most significant bit', () => {
  const tag = new Uint8Array(32);
  assert.ok(tagSatisfies(tag, 256), 'an all-zero tag satisfies every difficulty');

  tag[0] = 0b0000_0001; // seven leading zeros
  assert.ok(tagSatisfies(tag, 7));
  assert.ok(!tagSatisfies(tag, 8));

  const high = new Uint8Array(32);
  high[0] = 0b1000_0000;
  assert.ok(!tagSatisfies(high, 1));
  assert.ok(tagSatisfies(high, 0));
});

test('a one bit anywhere stops the count, including past the first byte', () => {
  const tag = new Uint8Array(32);
  tag[1] = 0b0100_0000; // eight zeros, then one zero, then a one
  assert.ok(tagSatisfies(tag, 9));
  assert.ok(!tagSatisfies(tag, 10));
});

test('the bit test examines the whole tag with no early exit', () => {
  // Normative in PROOF-OF-WORK.md. A getter on every index proves each byte was read even
  // though the answer was settled by the first.
  const read = new Set<number>();
  const probe = new Proxy(new Uint8Array(32).fill(0xff), {
    get(target, prop) {
      if (typeof prop === 'string' && /^\d+$/.test(prop)) read.add(Number(prop));
      // Deliberately without the receiver: forwarding the proxy as `this` makes TypedArray's
      // internal-slot getters (notably `length`) throw on an incompatible receiver.
      return Reflect.get(target, prop);
    },
  });
  // hygiene:allow the Proxy is the instrument under test; there is no honest type for it
  tagSatisfies(probe as unknown as Uint8Array, 1);
  assert.equal(read.size, 32, 'every byte must be read regardless of the verdict');
});

/* -------------------------------------------------------------------------- */
/* End to end                                                                  */
/* -------------------------------------------------------------------------- */

test('a solved proof verifies, and the same proof on another record does not', () => {
  // Four bits keeps this to ~16 Argon2id evaluations; the property does not depend on the
  // difficulty, and 64 MiB per evaluation makes a realistic difficulty unsuitable for a test.
  const target = record({ powProof: proof({ bits: 4 }) });
  const nonce = solvePow(target, 4, { limit: 4096 });
  assert.ok(nonce, 'a nonce must be found within the attempt limit');

  const solved = record({ powProof: proof({ bits: 4, nonce }) });
  assert.deepEqual(verifyPow(solved, 4), { ok: true });

  // Over-payment is valid.
  assert.deepEqual(verifyPow(solved, 3), { ok: true });

  // Under-payment is not: the verifier's own computation is what counts, never the claim.
  assert.deepEqual(verifyPow(solved, 5), { ok: false, code: 'POW_INSUFFICIENT_DIFFICULTY' });

  // The same proof moved to a different name fails, because the salt is derived from the record.
  const stolen = record({ name: 'zenith', powProof: proof({ bits: 4, nonce }) });
  assert.deepEqual(verifyPow(stolen, 4), { ok: false, code: 'POW_TAG_FAILS' });
});

test('verifyPow refuses a malformed proof before spending an Argon2id evaluation', () => {
  assert.deepEqual(verifyPow(record({ powProof: proof({ alg: 'argon2id' }) }), 4), {
    ok: false,
    code: 'POW_BAD_ALGORITHM',
  });
  assert.deepEqual(verifyPow(record({ powProof: proof({ nonce: new Uint8Array(8) }) }), 4), {
    ok: false,
    code: 'POW_BAD_NONCE',
  });
  assert.deepEqual(verifyPow(record({ powProof: null }), 4), {
    ok: false,
    code: 'POW_BAD_ALGORITHM',
  });
});

test('checkRecordPow ties the verdict to the recomputed difficulty, not the claim', () => {
  // A proof claiming 10 bits but solved for 4 must fail once the requirement is recomputed,
  // however loudly the record asserts otherwise.
  const target = record({ powProof: proof({ bits: 4 }) });
  const nonce = solvePow(target, 4, { limit: 4096 });
  assert.ok(nonce);
  const solved = record({ powProof: proof({ bits: 4, nonce }) });

  // 'atlas' is 5 characters -> base 7, and a quiet TLD adds nothing. 7 > 4, so this is refused.
  assert.deepEqual(checkRecordPow(solved, 5, 0), {
    ok: false,
    code: 'POW_INSUFFICIENT_DIFFICULTY',
  });

  // A 16-character label in the same quiet TLD requires 4 bits, which this proof meets.
  assert.deepEqual(checkRecordPow(solved, 16, 0), { ok: true });
});

test('the tag is deterministic for one nonce and salt', () => {
  const salt = powSalt(record());
  const nonce = new Uint8Array(POW_NONCE_LENGTH).fill(9);
  assert.deepEqual(powTag(nonce, salt), powTag(nonce, salt));
});
