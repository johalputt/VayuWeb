/**
 * Registry record schema: structural validation of a decoded CBOR map.
 *
 * docs/spec/REGISTRY.md, "Record Schema" and "Size Limits". This module answers only
 * "is this a well-formed record?" — it does not consult registry state, so it cannot decide
 * whether a name is free, whether `seq` follows its predecessor, or whether the proof-of-work
 * meets current difficulty. Those need the log and live in the verifier.
 *
 * The split is deliberate. Structural validation is a total function of the bytes: given the
 * same input every peer reaches the same verdict, with no clock, no index and no network. A
 * bug here is therefore reproducible from the record alone, which is the difference between
 * a defect someone can file and a divergence nobody can explain.
 *
 * Unknown fields and unknown entry types are preserved rather than stripped: REGISTRY.md
 * requires a record carrying fields this version does not understand to still verify
 * downstream, and requires unknown entry types to be "stored and replicated unchanged but
 * MUST NOT be acted upon".
 */

import { decode, isDeterministic, type CborMap, type CborValue } from './cbor.ts';
import { isRatifiedTld, labelRejection, parseAlias } from './names.ts';
import { PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, isSmallOrderKey } from './signature.ts';
import { RECORD_HASH_LENGTH } from './domain.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH } from './pow.ts';

/** The six operations. Order is irrelevant; membership is what validation asks. */
export const OPERATIONS = ['REGISTER', 'UPDATE', 'RENEW', 'TRANSFER', 'RELEASE', 'REVOKE'] as const;
export type Operation = (typeof OPERATIONS)[number];

/** Protocol version implemented here. A verifier must reject a major version it lacks. */
export const SUPPORTED_VERSION = 1;

/** Maximum serialised record size in bytes. */
export const MAX_RECORD_BYTES = 4096;

/** Maximum number of entries in `records`. */
export const MAX_RECORD_ENTRIES = 32;

/** Maximum size of a single entry value, in bytes for byte strings or characters for text. */
export const MAX_ENTRY_VALUE_BYTES = 512;

/** `seq` is a CBOR uint capped at 2^32-1. */
export const MAX_SEQ = 0xffffffff;

/** Entry TTL bounds, advisory but validated so peers agree on what is well-formed. */
export const MIN_TTL = 60;
export const MAX_TTL = 86400;
export const DEFAULT_TTL = 3600;

/** Known entry types. Unknown types are retained but never acted upon. */
export const KNOWN_ENTRY_TYPES = ['peer', 'ipns', 'cid', 'txt', 'alias'] as const;
export type KnownEntryType = (typeof KNOWN_ENTRY_TYPES)[number];

/** Rejection codes. These are the wire-visible reasons in REGISTRY.md's verify() pseudocode. */
export type RecordRejection =
  | 'NON_CANONICAL'
  | 'TOO_LARGE'
  | 'NOT_A_MAP'
  | 'MISSING_FIELD'
  | 'BAD_FIELD_TYPE'
  | 'UNSUPPORTED_VERSION'
  | 'UNKNOWN_OP'
  | 'BAD_LABEL'
  | 'UNKNOWN_TLD'
  | 'BAD_KEY'
  | 'BAD_SEQ'
  | 'BAD_TERM'
  | 'TOO_MANY_RECORDS'
  | 'BAD_RECORD_ENTRY'
  | 'BAD_POW_SHAPE'
  | 'UNEXPECTED_POW'
  | 'MISSING_POW'
  | 'BAD_CHAIN'
  | 'BAD_COSIG';

export class RecordError extends Error {
  readonly code: RecordRejection;
  constructor(code: RecordRejection, message: string) {
    super(`${code}: ${message}`);
    this.name = 'RecordError';
    this.code = code;
  }
}

export interface PowProof {
  readonly alg: string;
  /** The searched nonce. The salt is derived from the record, never carried by it. */
  readonly nonce: Uint8Array;
  /** Claimed difficulty in leading zero bits. A verifier recomputes what was required. */
  readonly bits: number;
}

export interface RecordEntry {
  readonly type: string;
  readonly value: CborValue;
  readonly ttl: number;
  /** False when `type` is outside {@link KNOWN_ENTRY_TYPES}: keep it, never act on it. */
  readonly known: boolean;
}

export interface RegistryRecord {
  readonly version: number;
  readonly op: Operation;
  readonly name: string;
  readonly tld: string;
  readonly ownerKey: Uint8Array;
  readonly seq: number;
  readonly notBefore: number;
  readonly notAfter: number;
  readonly entries: readonly RecordEntry[];
  readonly powProof: PowProof | null;
  readonly prevHash: Uint8Array;
  readonly sig: Uint8Array;
  readonly coSig: Uint8Array | null;
  /** The decoded map exactly as received, including unknown fields. */
  readonly map: CborMap;
}

// Deliberately a `function` declaration rather than a `const` arrow. TypeScript only applies
// never-returning control-flow narrowing when the callee is a function declaration or a const
// with an explicit type annotation; an inferred arrow silently does not narrow. The earlier
// arrow form meant every `if (x === undefined) fail(...)` left `x` possibly-undefined, which
// was then papered over with `as` casts — and a cast keeps compiling after someone deletes the
// guard above it, which is precisely the check this module exists to make impossible.
function fail(code: RecordRejection, message: string): never {
  throw new RecordError(code, message);
}

function uintField(map: CborMap, key: string): number {
  const value = map.get(key);
  if (value === undefined) fail('MISSING_FIELD', `${key} is required`);
  if (typeof value === 'bigint') fail('BAD_FIELD_TYPE', `${key} exceeds the supported range`);
  if (typeof value !== 'number') fail('BAD_FIELD_TYPE', `${key} must be an unsigned integer`);
  return value;
}

function textField(map: CborMap, key: string): string {
  const value = map.get(key);
  if (value === undefined) fail('MISSING_FIELD', `${key} is required`);
  if (typeof value !== 'string') fail('BAD_FIELD_TYPE', `${key} must be text`);
  return value;
}

function bytesField(map: CborMap, key: string, length: number): Uint8Array {
  const value = map.get(key);
  if (value === undefined) fail('MISSING_FIELD', `${key} is required`);
  if (!(value instanceof Uint8Array)) fail('BAD_FIELD_TYPE', `${key} must be a byte string`);
  if (value.length !== length) {
    fail('BAD_FIELD_TYPE', `${key} must be ${length} bytes, got ${value.length}`);
  }
  return value;
}

const utf8Length = (text: string): number => new TextEncoder().encode(text).length;

/**
 * `powProof` is exactly `{alg, nonce, bits}` — three fields, and deliberately not five more.
 *
 * The cost parameters and the salt are NOT record fields. A record carrying its own `m`, `t`
 * and `p` lets the registrant pick them, and `m = 8` KiB turns a memory-hard function into a
 * cheap one that still verifies, because the verifier evaluates the function the attacker
 * named. A record carrying its own salt is worse: the salt becomes a free parameter, so one
 * ground (salt, nonce) pair can be attached to every record its author ever signs, and a single
 * proof of work buys unlimited names.
 *
 * The salt is derived from the record's own canonical bytes instead — see pow.ts — which is
 * what makes a proof valid for exactly one record.
 */
function parsePowProof(value: CborValue): PowProof {
  if (!(value instanceof Map)) fail('BAD_POW_SHAPE', 'powProof must be a map or null');
  const map: CborMap = value;

  const alg = textField(map, 'alg');
  if (alg !== POW_ALGORITHM) fail('BAD_POW_SHAPE', `unsupported pow algorithm: ${alg}`);

  // Refuse a proof carrying tuning knobs rather than ignoring them. Ignoring would let a record
  // that an attacker believes is cheap round-trip unchanged through the log, and the field would
  // become load-bearing for some future implementation that did read it.
  for (const forbidden of ['m', 't', 'p', 'salt']) {
    if (map.has(forbidden)) {
      fail('BAD_POW_SHAPE', `powProof must not carry '${forbidden}': it is a protocol constant`);
    }
  }

  const proof: PowProof = {
    alg,
    nonce: bytesField(map, 'nonce', POW_NONCE_LENGTH),
    bits: uintField(map, 'bits'),
  };

  if (proof.bits === 0 || proof.bits > 256) {
    fail('BAD_POW_SHAPE', `claimed difficulty out of range: ${proof.bits}`);
  }
  return proof;
}

function parseEntry(value: CborValue): RecordEntry {
  if (!(value instanceof Map)) fail('BAD_RECORD_ENTRY', 'entry must be a map');
  const map: CborMap = value;

  const type = textField(map, 'type');
  const entryValue = map.get('value');
  if (entryValue === undefined) fail('BAD_RECORD_ENTRY', 'entry value is required');

  const rawTtl = map.get('ttl');
  let ttl = DEFAULT_TTL;
  if (rawTtl !== undefined) {
    if (typeof rawTtl !== 'number') fail('BAD_RECORD_ENTRY', 'ttl must be an unsigned integer');
    ttl = rawTtl;
    if (ttl < MIN_TTL || ttl > MAX_TTL) {
      fail('BAD_RECORD_ENTRY', `ttl ${ttl} outside ${MIN_TTL}-${MAX_TTL}`);
    }
  }

  const known = (KNOWN_ENTRY_TYPES as readonly string[]).includes(type);

  // Size bound applies to every entry, known type or not: an unknown type must not be a way
  // to smuggle an oversized value past the limit.
  const size =
    entryValue instanceof Uint8Array
      ? entryValue.length
      : typeof entryValue === 'string'
        ? utf8Length(entryValue)
        : 0;
  if (size > MAX_ENTRY_VALUE_BYTES) {
    fail('BAD_RECORD_ENTRY', `entry value ${size} bytes exceeds ${MAX_ENTRY_VALUE_BYTES}`);
  }

  if (known) {
    switch (type as KnownEntryType) {
      case 'peer':
        if (!(entryValue instanceof Uint8Array) || entryValue.length !== 32) {
          fail('BAD_RECORD_ENTRY', 'peer value must be a 32-byte key');
        }
        break;
      case 'ipns':
        if (typeof entryValue !== 'string' || entryValue.length < 1 || entryValue.length > 128) {
          fail('BAD_RECORD_ENTRY', 'ipns value must be 1-128 characters');
        }
        break;
      case 'cid':
        if (!(entryValue instanceof Uint8Array) || entryValue.length < 1 || entryValue.length > 64) {
          fail('BAD_RECORD_ENTRY', 'cid value must be 1-64 bytes');
        }
        break;
      case 'txt': {
        if (typeof entryValue !== 'string') fail('BAD_RECORD_ENTRY', 'txt value must be text');
        const text: string = entryValue;
        const bytes = utf8Length(text);
        if (bytes < 1 || bytes > 255) fail('BAD_RECORD_ENTRY', 'txt value must be 1-255 bytes');
        for (const character of text) {
          if (character.codePointAt(0)! < 0x20) {
            fail('BAD_RECORD_ENTRY', 'txt value must not contain control characters');
          }
        }
        break;
      }
      case 'alias':
        if (typeof entryValue !== 'string' || parseAlias(entryValue) === null) {
          fail('BAD_RECORD_ENTRY', 'alias must name a valid, ratified label.tld');
        }
        break;
    }
  }

  return { type, value: entryValue, ttl, known };
}

/**
 * Parse and structurally validate a decoded record map.
 *
 * Does not verify signatures or proof-of-work: those need the signing input and the current
 * difficulty respectively, and mixing them here would make a pure function depend on state.
 */
export function parseRecord(map: CborMap): RegistryRecord {
  const version = uintField(map, 'version');
  if (version !== SUPPORTED_VERSION) {
    fail('UNSUPPORTED_VERSION', `version ${version} is not implemented`);
  }

  const op = textField(map, 'op');
  if (!(OPERATIONS as readonly string[]).includes(op)) fail('UNKNOWN_OP', `unknown op: ${op}`);

  const name = textField(map, 'name');
  const labelProblem = labelRejection(name);
  if (labelProblem !== null) fail('BAD_LABEL', `${name}: ${labelProblem}`);

  const tld = textField(map, 'tld');
  if (!isRatifiedTld(tld)) fail('UNKNOWN_TLD', `${tld} is not a ratified TLD`);

  const ownerKey = bytesField(map, 'ownerKey', PUBLIC_KEY_LENGTH);
  // A small-order key certifies itself: signatures verify under it that its holder never
  // made. It cannot arise from key generation, so it is refused at schema level rather than
  // reaching signature verification where it would appear to succeed.
  if (isSmallOrderKey(ownerKey)) fail('BAD_KEY', 'ownerKey is a small-order point');

  const seq = uintField(map, 'seq');
  if (seq > MAX_SEQ) fail('BAD_SEQ', `seq ${seq} exceeds 2^32-1`);

  const notBefore = uintField(map, 'notBefore');
  const notAfter = uintField(map, 'notAfter');
  if (notAfter < notBefore) fail('BAD_TERM', 'notAfter precedes notBefore');

  const rawEntries = map.get('records');
  if (rawEntries === undefined) fail('MISSING_FIELD', 'records is required');
  if (!Array.isArray(rawEntries)) fail('BAD_FIELD_TYPE', 'records must be an array');
  const entryValues: CborValue[] = rawEntries;
  if (entryValues.length > MAX_RECORD_ENTRIES) {
    fail('TOO_MANY_RECORDS', `${entryValues.length} entries exceeds ${MAX_RECORD_ENTRIES}`);
  }
  const entries = entryValues.map(parseEntry);

  // "At most one alias per record, and an alias MUST NOT coexist with another entry type,
  // because a name is either a pointer or a destination."
  const aliases = entries.filter((e) => e.type === 'alias');
  if (aliases.length > 1) fail('BAD_RECORD_ENTRY', 'at most one alias per record');
  if (aliases.length === 1 && entries.length > 1) {
    fail('BAD_RECORD_ENTRY', 'an alias must not coexist with another entry');
  }
  // A name may not alias itself. REGISTRY.md bounds resolution at 3 hops and requires a
  // resolver to fail on a cycle, so this cannot be reached by a conforming resolver — but the
  // trivial self-loop is the case a resolver written straight from the prose is most likely to
  // get wrong, and it is the one case decidable from a single record. Refusing it here means
  // no implementation has to be correct about it.
  //
  // It does NOT remove the need for cycle detection: a → b → a spans two records and is
  // invisible from either one. The hop limit remains the real defence.
  if (aliases.length === 1) {
    const target = parseAlias(aliases[0]!.value as string);
    if (target !== null && target.label === name && target.tld === tld) {
      fail('BAD_RECORD_ENTRY', `${name}.${tld} may not alias itself`);
    }
  }

  const rawPow = map.get('powProof');
  if (rawPow === undefined) fail('MISSING_FIELD', 'powProof is required, use null when absent');
  const powProof = rawPow === null ? null : parsePowProof(rawPow);

  const needsPow = op === 'REGISTER' || op === 'RENEW';
  if (needsPow && powProof === null) fail('MISSING_POW', `${op} requires a proof of work`);
  if (!needsPow && powProof !== null) fail('UNEXPECTED_POW', `${op} must carry powProof null`);

  const prevHash = bytesField(map, 'prevHash', RECORD_HASH_LENGTH);
  const sig = bytesField(map, 'sig', SIGNATURE_LENGTH);

  const rawCoSig = map.get('coSig');
  let coSig: Uint8Array | null = null;
  if (rawCoSig !== undefined && rawCoSig !== null) {
    if (!(rawCoSig instanceof Uint8Array) || rawCoSig.length !== SIGNATURE_LENGTH) {
      fail('BAD_COSIG', 'coSig must be a 64-byte signature');
    }
    coSig = rawCoSig as Uint8Array;
  }
  // "coSig exists because a transfer signed only by the outgoing owner can send a name to a
  // key nobody controls, indistinguishable from a burn."
  if (op === 'TRANSFER' && coSig === null) fail('BAD_COSIG', 'TRANSFER requires coSig');
  if (op !== 'TRANSFER' && coSig !== null) fail('BAD_COSIG', `${op} must not carry coSig`);

  return {
    version, op: op as Operation, name, tld, ownerKey, seq,
    notBefore, notAfter, entries, powProof, prevHash, sig, coSig, map,
  };
}

/**
 * Decode and validate bytes received from a peer.
 *
 * Enforces the two framing rules before anything else: the encoding must already be
 * deterministic, and the record must be within the size cap. Both are cheap, and both must
 * hold before a signature over these bytes means anything.
 */
export function parseRecordBytes(bytes: Uint8Array): RegistryRecord {
  if (bytes.length > MAX_RECORD_BYTES) {
    fail('TOO_LARGE', `${bytes.length} bytes exceeds ${MAX_RECORD_BYTES}`);
  }
  if (!isDeterministic(bytes)) fail('NON_CANONICAL', 'record is not deterministic CBOR');

  const value = decode(bytes);
  if (!(value instanceof Map)) fail('NOT_A_MAP', 'a record must be a CBOR map');
  return parseRecord(value as CborMap);
}
