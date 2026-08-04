/**
 * Hyperbee index keyspace.
 *
 * docs/spec/REGISTRY.md, "Index Keyspace Layout". Keys are byte strings ordered
 * lexicographically, so the encoding decides which questions are a bounded range scan and which
 * are a full-tree walk. Getting a byte wrong here does not throw; it silently changes which
 * records a scan returns.
 *
 * Four keyspaces, each with a one-byte namespace tag:
 *
 *     n  0x6E 00 <tld> 00 <label>                      current record pointer
 *     o  0x6F 00 <ownerKey:32> 00 <tld> 00 <label>     names by owner
 *     x  0x78 00 <notAfter:u64be> 00 <tld> 00 <label>  expiry queue
 *     r  0x72 00 <tld> 00 <notBefore:u64be> 00 <label> registration-rate window
 *
 * TLD before label, reversing how a person writes `name.tld`, because difficulty depends on a
 * TLD's registration rate: a TLD prefix makes that one bounded scan rather than a full walk, a
 * TLD ratified later occupies a fresh disjoint range so no existing key moves, and auditing one
 * TLD is a contiguous read.
 *
 * ## Separators are not delimiters for every component
 *
 * REGISTRY.md justifies the `0x00` separators by saying components "contain no `0x00`
 * (guaranteed by the label grammar and by fixed-width integers)". That is true of `tld` and
 * `label`, whose grammar is `[a-z0-9-]`, and false of the other two:
 *
 * - A `u64be` timestamp is mostly zero bytes. Any second in this century begins
 *   `00 00 00 00`.
 * - An Ed25519 public key is uniform random, so it contains at least one `0x00` about 12% of
 *   the time.
 *
 * The layout is still sound, because a fixed-width component is read by offset and never by
 * scanning for a separator. But an implementer who takes the sentence at face value and splits
 * a key on `0x00` gets a correct parse of the `n` keyspace and a wrong one of the other three —
 * on roughly one key in eight for owner keys, and on every key in the two time-indexed spaces.
 * The decoders here therefore consume fixed-width fields positionally, and the tests pin that
 * against keys chosen to contain embedded zero bytes.
 */

import { PUBLIC_KEY_LENGTH } from './signature.ts';

export const TAG_CURRENT = 0x6e;
export const TAG_BY_OWNER = 0x6f;
export const TAG_EXPIRY = 0x78;
export const TAG_RATE = 0x72;

export const SEPARATOR = 0x00;

/** Timestamps occupy eight big-endian bytes so that lexicographic order is numeric order. */
export const TIMESTAMP_BYTES = 8;

/** The largest timestamp representable in the key encoding. */
export const MAX_TIMESTAMP = 2 ** 53 - 1;

export class KeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyError';
  }
}

const ASCII = new TextEncoder();
const TEXT = new TextDecoder('utf-8', { fatal: true });

/**
 * Encode a component that must be free of the separator byte.
 *
 * The check is not defensive noise. A component containing `0x00` would make two distinct names
 * encode to keys that a separator-based decoder reads identically, and the resulting collision
 * would surface as one name resolving to another's record.
 */
function textComponent(value: string, what: string): Uint8Array {
  const bytes = ASCII.encode(value);
  if (bytes.length === 0) throw new KeyError(`${what} must not be empty`);
  if (bytes.includes(SEPARATOR)) throw new KeyError(`${what} must not contain a zero byte`);
  return bytes;
}

/** Big-endian, so that byte order and numeric order agree and a range scan means what it says. */
export function encodeTimestamp(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > MAX_TIMESTAMP) {
    throw new KeyError(`timestamp out of range: ${value}`);
  }
  const out = new Uint8Array(TIMESTAMP_BYTES);
  let remaining = value;
  for (let i = TIMESTAMP_BYTES - 1; i >= 0; i -= 1) {
    out[i] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  return out;
}

export function decodeTimestamp(bytes: Uint8Array, offset: number): number {
  if (offset + TIMESTAMP_BYTES > bytes.length) throw new KeyError('truncated timestamp');
  let value = 0;
  for (let i = 0; i < TIMESTAMP_BYTES; i += 1) {
    value = value * 256 + bytes[offset + i]!;
  }
  if (value > MAX_TIMESTAMP) throw new KeyError('timestamp exceeds the safe integer range');
  return value;
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

const sep = Uint8Array.of(SEPARATOR);
const tag = (value: number): Uint8Array => Uint8Array.of(value);

/* -------------------------------------------------------------------------- */
/* Encoders                                                                    */
/* -------------------------------------------------------------------------- */

/** `n`: the current accepted record for one name. */
export function currentKey(tld: string, label: string): Uint8Array {
  return concat([
    tag(TAG_CURRENT),
    sep,
    textComponent(tld, 'tld'),
    sep,
    textComponent(label, 'label'),
  ]);
}

/** `o`: presence marker, so "every name this key holds" is one prefix scan. */
export function byOwnerKey(ownerKey: Uint8Array, tld: string, label: string): Uint8Array {
  if (ownerKey.length !== PUBLIC_KEY_LENGTH) {
    throw new KeyError(`ownerKey must be ${PUBLIC_KEY_LENGTH} bytes`);
  }
  return concat([
    tag(TAG_BY_OWNER),
    sep,
    ownerKey,
    sep,
    textComponent(tld, 'tld'),
    sep,
    textComponent(label, 'label'),
  ]);
}

/**
 * `x`: expiry queue, keyed by big-endian `notAfter`, so every name expiring before an instant
 * forms a prefix range and a node advances grace and quarantine without a full scan.
 */
export function expiryKey(notAfter: number, tld: string, label: string): Uint8Array {
  return concat([
    tag(TAG_EXPIRY),
    sep,
    encodeTimestamp(notAfter),
    sep,
    textComponent(tld, 'tld'),
    sep,
    textComponent(label, 'label'),
  ]);
}

/**
 * `r`: registration-rate window. TLD precedes the timestamp here — unlike the expiry queue —
 * because the question is "how many in THIS TLD over the trailing 30 days", which is one scan
 * bounded at both ends within a single TLD's range.
 */
export function rateKey(tld: string, notBefore: number, label: string): Uint8Array {
  return concat([
    tag(TAG_RATE),
    sep,
    textComponent(tld, 'tld'),
    sep,
    encodeTimestamp(notBefore),
    sep,
    textComponent(label, 'label'),
  ]);
}

/* -------------------------------------------------------------------------- */
/* Range bounds                                                                */
/* -------------------------------------------------------------------------- */

/** Every key in one TLD's slice of the `n` keyspace. */
export function currentPrefix(tld: string): Uint8Array {
  return concat([tag(TAG_CURRENT), sep, textComponent(tld, 'tld'), sep]);
}

/** Every name held by one key. */
export function byOwnerPrefix(ownerKey: Uint8Array): Uint8Array {
  if (ownerKey.length !== PUBLIC_KEY_LENGTH) {
    throw new KeyError(`ownerKey must be ${PUBLIC_KEY_LENGTH} bytes`);
  }
  return concat([tag(TAG_BY_OWNER), sep, ownerKey, sep]);
}

/**
 * Half-open bounds `[gte, lt)` over the expiry queue, for names expiring in `[from, to)`.
 *
 * Half-open rather than inclusive because an inclusive upper bound would need the successor of
 * the largest key sharing that timestamp, and constructing a successor over a variable-length
 * suffix is the kind of thing that is wrong once and then wrong quietly.
 */
export function expiryRange(from: number, to: number): { gte: Uint8Array; lt: Uint8Array } {
  if (to < from) throw new KeyError('expiry range end precedes its start');
  const bound = (at: number) => concat([tag(TAG_EXPIRY), sep, encodeTimestamp(at)]);
  return { gte: bound(from), lt: bound(to) };
}

/** Half-open bounds over one TLD's registrations in `[from, to)` — the difficulty window. */
export function rateRange(
  tld: string,
  from: number,
  to: number,
): { gte: Uint8Array; lt: Uint8Array } {
  if (to < from) throw new KeyError('rate range end precedes its start');
  const bound = (at: number) =>
    concat([tag(TAG_RATE), sep, textComponent(tld, 'tld'), sep, encodeTimestamp(at)]);
  return { gte: bound(from), lt: bound(to) };
}

/* -------------------------------------------------------------------------- */
/* Decoders                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Read a text component running to the next separator, or to the end of the key.
 *
 * Used only after every fixed-width component has been consumed positionally.
 */
function readText(key: Uint8Array, offset: number, what: string): { value: string; next: number } {
  let end = offset;
  while (end < key.length && key[end] !== SEPARATOR) end += 1;
  if (end === offset) throw new KeyError(`${what} is empty`);
  try {
    return { value: TEXT.decode(key.subarray(offset, end)), next: end + 1 };
  } catch {
    throw new KeyError(`${what} is not valid UTF-8`);
  }
}

function expectTag(key: Uint8Array, expected: number, what: string): void {
  if (key.length < 2 || key[0] !== expected || key[1] !== SEPARATOR) {
    throw new KeyError(`not a ${what} key`);
  }
}

export function decodeCurrentKey(key: Uint8Array): { tld: string; label: string } {
  expectTag(key, TAG_CURRENT, 'current');
  const tld = readText(key, 2, 'tld');
  const label = readText(key, tld.next, 'label');
  if (label.next !== key.length + 1) throw new KeyError('trailing bytes after label');
  return { tld: tld.value, label: label.value };
}

export function decodeByOwnerKey(key: Uint8Array): {
  ownerKey: Uint8Array;
  tld: string;
  label: string;
} {
  expectTag(key, TAG_BY_OWNER, 'by-owner');
  // Positional, not separator-scanned: an owner key contains a zero byte about 12% of the time.
  const end = 2 + PUBLIC_KEY_LENGTH;
  if (key.length < end + 1 || key[end] !== SEPARATOR) throw new KeyError('truncated ownerKey');
  const ownerKey = key.slice(2, end);
  const tld = readText(key, end + 1, 'tld');
  const label = readText(key, tld.next, 'label');
  if (label.next !== key.length + 1) throw new KeyError('trailing bytes after label');
  return { ownerKey, tld: tld.value, label: label.value };
}

export function decodeExpiryKey(key: Uint8Array): {
  notAfter: number;
  tld: string;
  label: string;
} {
  expectTag(key, TAG_EXPIRY, 'expiry');
  // Positional: every timestamp in this century starts with four zero bytes.
  const end = 2 + TIMESTAMP_BYTES;
  if (key.length < end + 1 || key[end] !== SEPARATOR) throw new KeyError('truncated timestamp');
  const notAfter = decodeTimestamp(key, 2);
  const tld = readText(key, end + 1, 'tld');
  const label = readText(key, tld.next, 'label');
  if (label.next !== key.length + 1) throw new KeyError('trailing bytes after label');
  return { notAfter, tld: tld.value, label: label.value };
}

export function decodeRateKey(key: Uint8Array): {
  tld: string;
  notBefore: number;
  label: string;
} {
  expectTag(key, TAG_RATE, 'rate');
  const tld = readText(key, 2, 'tld');
  const end = tld.next + TIMESTAMP_BYTES;
  if (key.length < end + 1 || key[end] !== SEPARATOR) throw new KeyError('truncated timestamp');
  const notBefore = decodeTimestamp(key, tld.next);
  const label = readText(key, end + 1, 'label');
  if (label.next !== key.length + 1) throw new KeyError('trailing bytes after label');
  return { tld: tld.value, notBefore, label: label.value };
}
