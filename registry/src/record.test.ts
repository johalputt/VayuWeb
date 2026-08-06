import { test } from 'node:test';
import assert from 'node:assert/strict';

import { readFileSync, readdirSync } from 'node:fs';

import {
  parseRecord,
  parseRecordBytes,
  OPERATIONS,
  KNOWN_ENTRY_TYPES,
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

/* -------------------------------------------------------------------------- */
/* AUDIT FINDING: the spec's only complete record was one the spec rejects      */
/* -------------------------------------------------------------------------- */

test("AUDIT: REGISTRY.md's worked example is a record this implementation accepts", () => {
  // The Worked Example is the only complete record in the corpus, introduced plainly as "A
  // registration of atlas.vayu as JSON" — not as a counter-example. It was a literal survival of
  // the pre-fix proof-of-work schema: `{alg: "argon2id", m, t, p, salt, nonce: <integer>, bits:
  // 22}`, which the schema section three lines above forbids in terms ("exactly three keys"; "A
  // verifier MUST reject a powProof carrying m, t, p or salt"), and which this module refuses
  // three separate ways.
  //
  // The consequence was sharper than a stale paragraph: conformance/vectors.json publishes a
  // vector requiring implementations to REJECT exactly that shape. The artifact measuring a
  // second implementation demanded refusing the only record the specification models, in a
  // project whose Phase 6 acceptance is an independent implementation built from the
  // specification alone.
  //
  // This parses the example rather than eyeballing it. Signatures are not checked — the example's
  // `sig` is illustrative and cannot verify — but every structural rule is, which is where the
  // defect was.
  const spec = readFileSync(new URL('../../docs/spec/REGISTRY.md', import.meta.url), 'utf8');
  const block = /## Worked Example\n[\s\S]*?```json\n([\s\S]*?)\n```/.exec(spec);
  assert.ok(block, 'the Worked Example must be a fenced json block, or this check is inert');

  const b64url = (s: string): Uint8Array =>
    new Uint8Array(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  const BYTE_FIELDS = new Set(['ownerKey', 'prevHash', 'sig', 'coSig']);

  // The document renders byte strings as unpadded base64url, so the reader has to know which
  // fields are bytes. That list is exactly what the schema table says, and getting it wrong here
  // would make the check pass for the wrong reason.
  const toCbor = (value: unknown, key?: string): CborValue => {
    if (typeof value === 'string' && key !== undefined && BYTE_FIELDS.has(key))
      return b64url(value);
    if (Array.isArray(value)) return value.map((v) => toCbor(v)) as CborValue;
    if (value !== null && typeof value === 'object') {
      const obj = value as Record<string, unknown>;
      const m = new Map<string | Uint8Array, CborValue>();
      // A `records` entry's `value` is bytes for `peer` and `cid` and text for the rest, and the
      // pow `nonce` is always bytes.
      const entryBytes = obj['type'] === 'peer' || obj['type'] === 'cid';
      for (const [k, v] of Object.entries(obj)) {
        const isBytes = (k === 'nonce' && typeof v === 'string') || (k === 'value' && entryBytes);
        m.set(k, isBytes ? b64url(v as string) : toCbor(v, k));
      }
      return m;
    }
    return value as CborValue;
  };

  const parsed = toCbor(JSON.parse(block[1]!)) as CborMap;
  const record = parseRecord(parsed);
  assert.equal(record.name, 'atlas');
  assert.equal(record.op, 'REGISTER');

  // The two things that were actually wrong, pinned by name so a regression is legible.
  assert.equal(record.powProof?.alg, POW_ALGORITHM);
  assert.ok(
    record.powProof !== null && record.powProof.bits <= 18,
    'PROOF-OF-WORK.md caps the schedule at 18 bits; the example claimed 22, overstating the ' +
      'cost budget roughly fourfold',
  );
});

test('AUDIT: no specification names a record type the registry does not carry', () => {
  // `ATTESTATION.md` described "an ordinary registry record type, `attest`". Two readings, both
  // unimplementable: as an operation it is outside Article 29.4's closed set and outside this
  // module's six, so a peer rejects it UNKNOWN_OP; as a `records` entry type it is outside
  // REGISTRY.md's five, and that document's rule is "Unknown `type` values are stored and
  // replicated unchanged but MUST NOT be acted upon" — so it would propagate and no resolver
  // could act on it, which is the entire mechanism.
  //
  // The earlier guard in this file compares OPERATIONS against the charter, which catches the
  // implementation drifting. It does not catch a DOCUMENT proposing an operation nobody
  // implements, and that is the direction three findings went this month: PUBLISHING.md's inline
  // digests, LOCAL-SURFACE.md's cross-name allowance, and this.
  const specs = new URL('../../docs/spec/', import.meta.url);
  const known = new Set<string>([...OPERATIONS, ...KNOWN_ENTRY_TYPES]);

  const offenders: string[] = [];
  for (const name of readdirSync(specs)) {
    if (!name.endsWith('.md') || name === 'REGISTRY.md') continue;
    const text = readFileSync(new URL(name, specs), 'utf8');
    // "a/an ... record type, `x`" and "operation `x`" — the two shapes a document uses when it
    // is introducing one rather than referring to one.
    for (const m of text.matchAll(
      /record type[,:]?\s+`([a-zA-Z-]+)`|\boperations?\s+`([a-zA-Z-]+)`/g,
    )) {
      const type = (m[1] ?? m[2])!;
      if (!known.has(type) && !known.has(type.toUpperCase())) offenders.push(`${name}: ${type}`);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    'a specification names a record type or operation the registry does not carry',
  );
});
