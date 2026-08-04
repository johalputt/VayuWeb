/**
 * Deterministic CBOR (RFC 8949 §4.2.1) — encoder and strict decoder.
 *
 * docs/spec/REGISTRY.md requires that signing bytes are deterministic CBOR, and that
 * "Received bytes MUST themselves be deterministic CBOR, since any other encoding would
 * admit two byte strings for one record."
 *
 * That is a security property, not a formatting preference: if two byte strings can encode
 * one record, then `record_hash` is malleable, and a malleable hash hands an attacker a free
 * grinding surface at the convergence tie-break (REGISTRY.md, Convergence, rule 3).
 *
 * This module therefore implements the deterministic profile ONLY, in both directions:
 *
 *   - the encoder emits nothing but the deterministic form; and
 *   - the decoder REJECTS any input that is not already in that form, rather than
 *     accepting it leniently and re-encoding.
 *
 * A general-purpose CBOR library is deliberately not used. Determinism is the property being
 * relied upon, and a library that merely *can* emit canonical output still accepts
 * non-canonical input by default. The supported type set is exactly what the registry record
 * schema uses, which keeps the attack surface small:
 *
 *   unsigned integers, byte strings, text strings, arrays, maps, null.
 *
 * Everything else — floats, tags, indefinite-length items, negative integers, booleans,
 * undefined, simple values — is rejected on both encode and decode. Floats in particular are
 * excluded on purpose: NaN payloads and ±0 give one value several defensible encodings.
 */

/** Values representable in the registry's deterministic CBOR profile. */
export type CborValue =
  | number // unsigned integer only, must be a safe non-negative integer
  | bigint // unsigned integer only, for values above Number.MAX_SAFE_INTEGER
  | Uint8Array // byte string
  | string // text string, encoded UTF-8
  | CborValue[] // array
  | CborMap
  | null;

export type CborMap = Map<string | Uint8Array, CborValue>;

/** Thrown when input is not valid deterministic CBOR, or a value is outside the profile. */
export class CborError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = 'CborError';
    this.code = code;
  }
}

const MAJOR_UINT = 0;
const MAJOR_BSTR = 2;
const MAJOR_TSTR = 3;
const MAJOR_ARRAY = 4;
const MAJOR_MAP = 5;
const MAJOR_SIMPLE = 7;

const SIMPLE_NULL = 22;

const textEncoder = new TextEncoder();
// `fatal` rejects malformed UTF-8 rather than substituting U+FFFD, which would let two
// distinct byte strings decode to one text string.
const textDecoder = new TextDecoder('utf-8', { fatal: true });

/* -------------------------------------------------------------------------- */
/* Encoding                                                                    */
/* -------------------------------------------------------------------------- */

class Writer {
  #chunks: Uint8Array[] = [];
  #length = 0;

  push(bytes: Uint8Array): void {
    this.#chunks.push(bytes);
    this.#length += bytes.length;
  }

  /**
   * Write a major type and argument in *preferred* (shortest) form — RFC 8949 §4.2.1
   * rule 1. Anything longer for the same value would be a second valid encoding.
   */
  head(major: number, argument: bigint): void {
    if (argument < 0n) {
      throw new CborError('NEGATIVE_ARGUMENT', 'argument must be non-negative');
    }
    const base = major << 5;
    if (argument < 24n) {
      this.push(Uint8Array.of(base | Number(argument)));
    } else if (argument <= 0xffn) {
      this.push(Uint8Array.of(base | 24, Number(argument)));
    } else if (argument <= 0xffffn) {
      const b = new Uint8Array(3);
      b[0] = base | 25;
      new DataView(b.buffer).setUint16(1, Number(argument), false);
      this.push(b);
    } else if (argument <= 0xffffffffn) {
      const b = new Uint8Array(5);
      b[0] = base | 26;
      new DataView(b.buffer).setUint32(1, Number(argument), false);
      this.push(b);
    } else if (argument <= 0xffffffffffffffffn) {
      const b = new Uint8Array(9);
      b[0] = base | 27;
      new DataView(b.buffer).setBigUint64(1, argument, false);
      this.push(b);
    } else {
      throw new CborError('ARGUMENT_TOO_LARGE', 'argument exceeds 64 bits');
    }
  }

  concat(): Uint8Array {
    const out = new Uint8Array(this.#length);
    let offset = 0;
    for (const chunk of this.#chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }
}

function assertUint(value: number | bigint): bigint {
  if (typeof value === 'bigint') {
    if (value < 0n) throw new CborError('NEGATIVE_INT', 'negative integers are not in the profile');
    return value;
  }
  if (!Number.isInteger(value)) {
    throw new CborError('NON_INTEGER', `not an integer: ${value}`);
  }
  if (value < 0) throw new CborError('NEGATIVE_INT', 'negative integers are not in the profile');
  if (!Number.isSafeInteger(value)) {
    throw new CborError('UNSAFE_INTEGER', 'use a bigint above Number.MAX_SAFE_INTEGER');
  }
  return BigInt(value);
}

/**
 * Compare two encoded map keys bytewise, as unsigned octets.
 *
 * RFC 8949 §4.2.1 rule 3 orders map keys by their *encoded* byte sequence, not by the
 * decoded value. Sorting decoded strings by code point would put text keys in a different
 * order than sorting their CBOR encodings, because the encoding carries a length-bearing
 * head byte first.
 */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const shared = Math.min(a.length, b.length);
  for (let i = 0; i < shared; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  if (a.length === b.length) return 0;
  return a.length < b.length ? -1 : 1;
}

function encodeValue(value: CborValue, writer: Writer, depth: number): void {
  if (depth > 32) {
    throw new CborError('DEPTH_EXCEEDED', 'nesting deeper than 32 levels');
  }

  if (value === null) {
    writer.push(Uint8Array.of((MAJOR_SIMPLE << 5) | SIMPLE_NULL));
    return;
  }

  if (typeof value === 'number' || typeof value === 'bigint') {
    writer.head(MAJOR_UINT, assertUint(value));
    return;
  }

  if (value instanceof Uint8Array) {
    writer.head(MAJOR_BSTR, BigInt(value.length));
    writer.push(value);
    return;
  }

  if (typeof value === 'string') {
    const bytes = textEncoder.encode(value);
    // A lone surrogate survives TextEncoder as U+FFFD, which would silently change the
    // value being signed. Reject rather than corrupt.
    if (textDecoderSafe(bytes) !== value) {
      throw new CborError('INVALID_TEXT', 'string is not well-formed UTF-8 (lone surrogate?)');
    }
    writer.head(MAJOR_TSTR, BigInt(bytes.length));
    writer.push(bytes);
    return;
  }

  if (Array.isArray(value)) {
    writer.head(MAJOR_ARRAY, BigInt(value.length));
    for (const item of value) encodeValue(item, writer, depth + 1);
    return;
  }

  if (value instanceof Map) {
    const entries: Array<{ key: Uint8Array; value: CborValue }> = [];
    for (const [k, v] of value) {
      const keyWriter = new Writer();
      if (typeof k === 'string') {
        encodeValue(k, keyWriter, depth + 1);
      } else if (k instanceof Uint8Array) {
        encodeValue(k, keyWriter, depth + 1);
      } else {
        throw new CborError('BAD_MAP_KEY', 'map keys must be text or byte strings');
      }
      entries.push({ key: keyWriter.concat(), value: v });
    }

    entries.sort((a, b) => compareBytes(a.key, b.key));

    for (let i = 1; i < entries.length; i++) {
      if (compareBytes(entries[i - 1].key, entries[i].key) === 0) {
        throw new CborError('DUPLICATE_KEY', 'duplicate map key');
      }
    }

    writer.head(MAJOR_MAP, BigInt(entries.length));
    for (const entry of entries) {
      writer.push(entry.key);
      encodeValue(entry.value, writer, depth + 1);
    }
    return;
  }

  throw new CborError('UNSUPPORTED_TYPE', `type not in the deterministic profile: ${typeof value}`);
}

function textDecoderSafe(bytes: Uint8Array): string | null {
  try {
    return textDecoder.decode(bytes);
  } catch {
    return null;
  }
}

/** Encode a value as deterministic CBOR. Throws {@link CborError} outside the profile. */
export function encode(value: CborValue): Uint8Array {
  const writer = new Writer();
  encodeValue(value, writer, 0);
  return writer.concat();
}

/* -------------------------------------------------------------------------- */
/* Decoding                                                                    */
/* -------------------------------------------------------------------------- */

class Reader {
  readonly bytes: Uint8Array;
  offset = 0;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  take(n: number): Uint8Array {
    if (n < 0 || this.offset + n > this.bytes.length) {
      throw new CborError('TRUNCATED', 'input ended mid-item');
    }
    const slice = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return slice;
  }

  byte(): number {
    if (this.offset >= this.bytes.length) {
      throw new CborError('TRUNCATED', 'input ended mid-item');
    }
    return this.bytes[this.offset++];
  }
}

/**
 * Read a head and return its argument, rejecting any non-shortest encoding.
 *
 * This is the check that makes the decoder strict: `0x18 0x05` and `0x05` both mean 5 in
 * general CBOR, but only the second is deterministic. Accepting the first would mean two
 * byte strings decode to one record — exactly what the spec forbids.
 */
function readArgument(reader: Reader, additional: number): bigint {
  if (additional < 24) return BigInt(additional);

  if (additional === 24) {
    const v = reader.byte();
    if (v < 24) throw new CborError('NON_CANONICAL', 'value should use the shorter head form');
    return BigInt(v);
  }
  if (additional === 25) {
    const b = reader.take(2);
    const v = (b[0] << 8) | b[1];
    if (v <= 0xff) throw new CborError('NON_CANONICAL', 'value should use the shorter head form');
    return BigInt(v);
  }
  if (additional === 26) {
    const b = reader.take(4);
    const v = new DataView(b.buffer, b.byteOffset, 4).getUint32(0, false);
    if (v <= 0xffff) throw new CborError('NON_CANONICAL', 'value should use the shorter head form');
    return BigInt(v);
  }
  if (additional === 27) {
    const b = reader.take(8);
    const v = new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, false);
    if (v <= 0xffffffffn) {
      throw new CborError('NON_CANONICAL', 'value should use the shorter head form');
    }
    return v;
  }
  if (additional === 31) {
    throw new CborError('INDEFINITE_LENGTH', 'indefinite-length items are not deterministic');
  }
  throw new CborError('RESERVED_ADDITIONAL', `reserved additional information ${additional}`);
}

function toLength(argument: bigint, limit: number): number {
  if (argument > BigInt(limit)) {
    throw new CborError('LENGTH_TOO_LARGE', 'declared length exceeds the input');
  }
  return Number(argument);
}

function decodeValue(reader: Reader, depth: number): CborValue {
  if (depth > 32) {
    throw new CborError('DEPTH_EXCEEDED', 'nesting deeper than 32 levels');
  }

  const initial = reader.byte();
  const major = initial >> 5;
  const additional = initial & 0x1f;

  switch (major) {
    case MAJOR_UINT: {
      const v = readArgument(reader, additional);
      return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
    }

    case MAJOR_BSTR: {
      const len = toLength(readArgument(reader, additional), reader.bytes.length);
      // Copy: subarray would alias the input buffer, so a caller mutating the returned
      // value would silently change bytes that may still be needed for verification.
      return Uint8Array.from(reader.take(len));
    }

    case MAJOR_TSTR: {
      const len = toLength(readArgument(reader, additional), reader.bytes.length);
      const raw = reader.take(len);
      const text = textDecoderSafe(raw);
      if (text === null) throw new CborError('INVALID_UTF8', 'text string is not valid UTF-8');
      return text;
    }

    case MAJOR_ARRAY: {
      const len = toLength(readArgument(reader, additional), reader.bytes.length);
      const out: CborValue[] = [];
      for (let i = 0; i < len; i++) out.push(decodeValue(reader, depth + 1));
      return out;
    }

    case MAJOR_MAP: {
      const len = toLength(readArgument(reader, additional), reader.bytes.length);
      const out: CborMap = new Map();
      let previousKey: Uint8Array | null = null;

      for (let i = 0; i < len; i++) {
        const keyStart = reader.offset;
        const key = decodeValue(reader, depth + 1);
        const keyBytes = reader.bytes.subarray(keyStart, reader.offset);

        if (typeof key !== 'string' && !(key instanceof Uint8Array)) {
          throw new CborError('BAD_MAP_KEY', 'map keys must be text or byte strings');
        }

        if (previousKey !== null) {
          const order = compareBytes(previousKey, keyBytes);
          if (order === 0) throw new CborError('DUPLICATE_KEY', 'duplicate map key');
          if (order > 0) throw new CborError('KEYS_OUT_OF_ORDER', 'map keys are not sorted');
        }
        previousKey = Uint8Array.from(keyBytes);

        out.set(key, decodeValue(reader, depth + 1));
      }
      return out;
    }

    case MAJOR_SIMPLE: {
      if (additional === SIMPLE_NULL) return null;
      if (additional === 25 || additional === 26 || additional === 27) {
        throw new CborError('FLOAT_NOT_ALLOWED', 'floats are not in the deterministic profile');
      }
      throw new CborError('UNSUPPORTED_SIMPLE', `simple value ${additional} is not in the profile`);
    }

    default:
      // Major 1 (negative integer) and 6 (tag) are outside the profile.
      throw new CborError('UNSUPPORTED_MAJOR', `major type ${major} is not in the profile`);
  }
}

/**
 * Decode deterministic CBOR, rejecting any non-deterministic input.
 *
 * Trailing bytes are an error: a record is exactly its bytes, and tolerating a suffix would
 * let two inputs carry one record while hashing differently.
 */
export function decode(bytes: Uint8Array): CborValue {
  const reader = new Reader(bytes);
  const value = decodeValue(reader, 0);
  if (reader.offset !== bytes.length) {
    throw new CborError('TRAILING_BYTES', `${bytes.length - reader.offset} unconsumed byte(s)`);
  }
  return value;
}

/**
 * True when `bytes` is already in deterministic form.
 *
 * The registry needs this as a precondition rather than a normalisation step: REGISTRY.md
 * requires that "A peer MUST NOT re-serialise a record it did not author".
 */
export function isDeterministic(bytes: Uint8Array): boolean {
  try {
    const value = decode(bytes);
    return compareBytes(encode(value), bytes) === 0;
  } catch {
    return false;
  }
}

export { compareBytes };
