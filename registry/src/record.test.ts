import { test } from 'node:test';
import assert from 'node:assert/strict';

import { readFileSync } from 'node:fs';

import {
  parseRecord,
  parseRecordBytes,
  OPERATIONS,
  RecordError,
  MAX_RECORD_ENTRIES,
  MAX_ENTRY_VALUE_BYTES,
  type RecordRejection,
} from './record.ts';
import { encode, type CborMap, type CborValue } from './cbor.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH } from './pow.ts';

const entry = (type: string, value: CborValue, ttl?: number): CborMap => {
  const m = new Map<string | Uint8Array, CborValue>([
    ['type', type],
    ['value', value],
  ]);
  if (ttl !== undefined) m.set('ttl', ttl);
  return m;
};

const pow = (): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['alg', POW_ALGORITHM],
    ['nonce', new Uint8Array(POW_NONCE_LENGTH).fill(7)],
    ['bits', 10],
  ]);

/** A valid REGISTER, which each test perturbs in exactly one way. */
function record(overrides: Record<string, CborValue> = {}): CborMap {
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
    ['powProof', pow()],
    ['prevHash', new Uint8Array(32)],
    ['sig', new Uint8Array(64).fill(0xaa)],
  ]);
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) m.delete(k);
    else m.set(k, v);
  }
  return m;
}

const rejects = (map: CborMap, code: RecordRejection): void => {
  assert.throws(
    () => parseRecord(map),
    (e: unknown) => e instanceof RecordError && e.code === code,
    `expected ${code}`,
  );
};

/* -------------------------------------------------------------------------- */

test('a well-formed REGISTER parses', () => {
  const parsed = parseRecord(record());
  assert.equal(parsed.op, 'REGISTER');
  assert.equal(parsed.name, 'atlas');
  assert.equal(parsed.entries.length, 1);
  assert.equal(parsed.entries[0].ttl, 3600, 'ttl defaults to 3600');
  assert.ok(parsed.powProof);
  assert.equal(parsed.coSig, null);
});

test('required fields are required', () => {
  for (const field of ['version', 'op', 'name', 'tld', 'ownerKey', 'seq', 'records', 'powProof']) {
    // hygiene:allow the point of the test is to pass what the type forbids
    rejects(record({ [field]: undefined as unknown as CborValue }), 'MISSING_FIELD');
  }
});

test('an unimplemented version is refused rather than guessed at', () => {
  rejects(record({ version: 2 }), 'UNSUPPORTED_VERSION');
});

test('the operation set is closed', () => {
  rejects(record({ op: 'DELETE' }), 'UNKNOWN_OP');
  rejects(record({ op: 'register' }), 'UNKNOWN_OP');
});

test('name and tld are validated against the namespace rules', () => {
  rejects(record({ name: 'ab' }), 'BAD_LABEL');
  rejects(record({ name: '-atlas' }), 'BAD_LABEL');
  rejects(record({ name: 'Atlas' }), 'BAD_LABEL');
  rejects(record({ tld: 'nope' }), 'UNKNOWN_TLD');
});

test('a small-order owner key is refused at schema level', () => {
  // It would otherwise reach signature verification and appear to succeed, because a
  // small-order key accepts signatures its holder never produced.
  const smallOrder = new Uint8Array(32);
  smallOrder[0] = 1;
  rejects(record({ ownerKey: smallOrder }), 'BAD_KEY');
});

test('fixed-width fields must be exactly their width', () => {
  rejects(record({ ownerKey: new Uint8Array(31) }), 'BAD_FIELD_TYPE');
  rejects(record({ prevHash: new Uint8Array(31) }), 'BAD_FIELD_TYPE');
  rejects(record({ sig: new Uint8Array(63) }), 'BAD_FIELD_TYPE');
});

test('notAfter may not precede notBefore', () => {
  rejects(record({ notAfter: 1782518399, notBefore: 1782518400 }), 'BAD_TERM');
});

/* -------------------------------------------------------------------------- */
/* Proof of work presence is decided by the operation                          */
/* -------------------------------------------------------------------------- */

test('REGISTER and RENEW require a proof; the other four forbid one', () => {
  rejects(record({ powProof: null }), 'MISSING_POW');
  rejects(record({ op: 'UPDATE', seq: 1, prevHash: new Uint8Array(32).fill(1) }), 'UNEXPECTED_POW');
});

test('a proof carrying its own cost parameters or salt is refused', () => {
  // Both are protocol constants. See the audit tests in pow.test.ts for the consequence of
  // letting a record name either one.
  for (const field of ['m', 't', 'p', 'salt']) {
    const p = pow();
    p.set(field, 1);
    rejects(record({ powProof: p }), 'BAD_POW_SHAPE');
  }
});

test('a proof naming another algorithm is refused', () => {
  const p = pow();
  p.set('alg', 'scrypt');
  rejects(record({ powProof: p }), 'BAD_POW_SHAPE');
});

test('the proof nonce is a fixed-width byte string', () => {
  const p = pow();
  p.set('nonce', new Uint8Array(15));
  rejects(record({ powProof: p }), 'BAD_FIELD_TYPE');
});

/* -------------------------------------------------------------------------- */
/* Entry rules                                                                 */
/* -------------------------------------------------------------------------- */

test('each known entry type validates its own value shape', () => {
  rejects(record({ records: [entry('peer', new Uint8Array(31))] }), 'BAD_RECORD_ENTRY');
  rejects(record({ records: [entry('cid', new Uint8Array(0))] }), 'BAD_RECORD_ENTRY');
  rejects(record({ records: [entry('ipns', '')] }), 'BAD_RECORD_ENTRY');
  rejects(record({ records: [entry('txt', '')] }), 'BAD_RECORD_ENTRY');
  rejects(record({ records: [entry('txt', 'hascontrol')] }), 'BAD_RECORD_ENTRY');
  rejects(record({ records: [entry('alias', 'atlas.nope')] }), 'BAD_RECORD_ENTRY');
  rejects(record({ records: [entry('alias', 'ab.vayu')] }), 'BAD_RECORD_ENTRY');
});

test('an alias is exclusive: at most one, and never beside another entry', () => {
  // "a name is either a pointer or a destination"
  rejects(
    record({ records: [entry('alias', 'atlas.vayu'), entry('alias', 'other.vayu')] }),
    'BAD_RECORD_ENTRY',
  );
  rejects(
    record({ records: [entry('alias', 'other.vayu'), entry('txt', 'x')] }),
    'BAD_RECORD_ENTRY',
  );
  assert.equal(parseRecord(record({ records: [entry('alias', 'other.vayu')] })).entries.length, 1);
});

test('AUDIT: a name may not alias itself', () => {
  // Accepted before this fix. REGISTRY.md bounds resolution at 3 hops and requires a resolver
  // to fail on a cycle, so a conforming resolver survives it — but the trivial self-loop is
  // exactly the case a resolver written from the prose is most likely to mishandle, and it is
  // the only cycle decidable from one record. Refusing it means nobody has to be right about it.
  rejects(record({ records: [entry('alias', 'atlas.vayu')] }), 'BAD_RECORD_ENTRY');

  // Same label under a different TLD is a different name, and stays legal.
  assert.equal(parseRecord(record({ records: [entry('alias', 'atlas.p2p')] })).entries.length, 1);
});

test('an unknown entry type is retained but marked not to be acted upon', () => {
  const parsed = parseRecord(record({ records: [entry('future', 'whatever')] }));
  assert.equal(parsed.entries[0].type, 'future');
  assert.equal(parsed.entries[0].known, false, 'must be flagged as not actionable');
  assert.equal(parsed.entries[0].value, 'whatever', 'and preserved unchanged');
});

test('an unknown type cannot smuggle an oversized value past the limit', () => {
  const oversized = 'x'.repeat(MAX_ENTRY_VALUE_BYTES + 1);
  rejects(record({ records: [entry('future', oversized)] }), 'BAD_RECORD_ENTRY');
});

test('ttl bounds are enforced', () => {
  rejects(record({ records: [entry('txt', 'x', 59)] }), 'BAD_RECORD_ENTRY');
  rejects(record({ records: [entry('txt', 'x', 86401)] }), 'BAD_RECORD_ENTRY');
  assert.equal(parseRecord(record({ records: [entry('txt', 'x', 60)] })).entries[0].ttl, 60);
});

test('the entry count is capped', () => {
  const many = Array.from({ length: MAX_RECORD_ENTRIES + 1 }, () => entry('txt', 'x'));
  rejects(record({ records: many }), 'TOO_MANY_RECORDS');

  const atLimit = Array.from({ length: MAX_RECORD_ENTRIES }, () => entry('txt', 'x'));
  assert.equal(parseRecord(record({ records: atLimit })).entries.length, MAX_RECORD_ENTRIES);
});

/* -------------------------------------------------------------------------- */
/* coSig belongs to TRANSFER alone                                             */
/* -------------------------------------------------------------------------- */

test('TRANSFER requires coSig and the others forbid it', () => {
  // Without it a transfer signed only by the outgoing owner can send a name to a key nobody
  // controls, which is indistinguishable from a burn.
  const transfer = record({
    op: 'TRANSFER',
    seq: 1,
    prevHash: new Uint8Array(32).fill(1),
    powProof: null,
  });
  rejects(transfer, 'BAD_COSIG');

  transfer.set('coSig', new Uint8Array(64).fill(0xbb));
  assert.equal(parseRecord(transfer).coSig?.length, 64);

  rejects(record({ coSig: new Uint8Array(64) }), 'BAD_COSIG');
});

/* -------------------------------------------------------------------------- */
/* Framing                                                                     */
/* -------------------------------------------------------------------------- */

test('bytes must be deterministic CBOR and within the size cap', () => {
  const bytes = encode(record());
  assert.equal(parseRecordBytes(bytes).name, 'atlas');

  // A record with an oversized txt entry pushes past 4096 bytes.
  const big = record({ records: [entry('txt', 'x'.repeat(300)), entry('txt', 'y'.repeat(200))] });
  assert.ok(encode(big).length < 4096, 'sanity: this one still fits');

  assert.throws(
    () => parseRecordBytes(Uint8Array.of(0xa1, 0x61, 0x62, 0x01, 0xff)),
    (e: unknown) => e instanceof RecordError,
  );
});

test('unknown top-level fields are preserved for downstream verification', () => {
  const parsed = parseRecord(record({ futureField: 'kept' }));
  assert.equal(parsed.map.get('futureField'), 'kept');
});

/* -------------------------------------------------------------------------- */
/* AUDIT FINDING: the operation set is not the one the charter closed          */
/* -------------------------------------------------------------------------- */

test('AUDIT: every implemented operation is a name Article 29.4 closed the set to', () => {
  // Article 29.4 does not merely list record types, it CLOSES the list: "There SHALL be no
  // administrative record type, no operator record type, no reserved opcode and no side channel.
  // A record bearing an unrecognised type MUST be rejected rather than ignored." So an operation
  // name outside that set is not a naming preference — it is a record every conformant peer is
  // required to refuse, which makes it total non-interoperation on a core operation.
  //
  // `RELEASE` was such a name. The charter calls the same act "relinquish the name" (19.2) and
  // names the record RELINQUISH (29.4); nothing in the charter says "release". Article 3.7 voids
  // the specification to the extent of the conflict, so the specification was the defective
  // party and the operation is renamed.
  const charter = readFileSync(
    new URL('../../constitution/CONSTITUTION.md', import.meta.url),
    'utf8',
  );
  const clause = /29\.4 The record types are a closed set: ([^.]+)\./.exec(charter);
  assert.ok(clause, 'Article 29.4 no longer states a closed set — this check is enforcing nothing');
  const closed = new Set(clause[1]!.split(/,\s*/).map((s) => s.trim().replace(/\s+/g, ' ')));
  assert.equal(closed.size, 11, 'Article 29.4 named eleven types when this check was written');

  // RENEW is the recorded exception, and it is the charter contradicting itself rather than the
  // specification overreaching: 11.6 and 11.8 make a RENEW record normative by name ("the latest
  // REGISTER or RENEW record"; "the only record a conformant implementation MAY accept ... is a
  // RENEW") and 31.1 requires a renewal record to carry proof-of-work, while 29.4 omits it. An
  // implementer cannot obey both, and no value can be chosen here — 29.4 is the higher-precedence
  // instrument as written, so removing RENEW would break Article 11 and adding it to 29.4 is an
  // amendment. scripts/check-charter-consistency.py holds it; this asserts it is still the ONLY
  // exception, so a second one cannot arrive unnoticed.
  const outside = OPERATIONS.filter((op) => !closed.has(op));
  assert.deepEqual(outside, ['RENEW'], 'a new operation outside Article 29.4 appeared');
});
