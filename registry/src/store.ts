/**
 * Local append-only log and index.
 *
 * docs/spec/REGISTRY.md, "The Log" and "The Index".
 *
 * ## What this is not, stated first
 *
 * This is **not** Hypercore and **not** Hyperbee. It is a single-writer, file-backed log with an
 * in-memory index rebuilt by replay, and it exists so that Phase 1 can be finished and tested —
 * "a command-line tool can register a name into a local log, resolve it back, and reject every
 * malformed and replayed record" — without dragging the peer-to-peer stack in first.
 *
 * The difference matters and is not cosmetic. A Hypercore log is a merkle tree whose entries are
 * self-authenticating, which is what lets a light client verify a record without replaying
 * history. This log has no merkle tree, no checkpoints and no replication. Phase 2 replaces the
 * storage beneath these interfaces; the verification rules above them do not change, which is
 * why they are already separated.
 *
 * ## Framing
 *
 * Each entry is a 4-byte big-endian length followed by that many bytes of deterministic CBOR.
 * Nothing else — no per-entry metadata, no framing version. The log is append-only and never
 * truncated: truncation would destroy the history that lets a newcomer verify ownership from
 * first principles, and there is no pruning scheme at launch.
 *
 * ## Replay is the only way state is built
 *
 * The index is derived, never authoritative. Every entry is re-verified on load rather than
 * trusted because it is already on disk — a file an attacker can append to is not a file whose
 * contents are known-good, and "we checked it when it arrived" is exactly the assumption that
 * makes a corrupted store undetectable.
 */

import {
  openSync,
  readFileSync,
  writeFileSync,
  appendFileSync,
  existsSync,
  mkdirSync,
} from 'node:fs';
import { closeSync } from 'node:fs';
import { dirname } from 'node:path';

import { parseRecordBytes, type RegistryRecord } from './record.ts';
import { recordHashFromBytes } from './domain.ts';
import {
  verify,
  predecessorFrom,
  type Predecessor,
  type RegistryView,
  type Verdict,
} from './verify.ts';
import { verifyPow, rateWindow, requiredBits, EPOCH_SECONDS } from './pow.ts';
import { lifecycleOf, isFullyReleased, GRACE_SECONDS, QUARANTINE_SECONDS } from './lifecycle.ts';

const LENGTH_PREFIX_BYTES = 4;

/** Guards against a corrupt length prefix turning into a multi-gigabyte allocation. */
const MAX_ENTRY_BYTES = 65_536;

export class StoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StoreError';
  }
}

export interface LogEntry {
  readonly index: number;
  readonly bytes: Uint8Array;
  readonly record: RegistryRecord;
  readonly hash: Uint8Array;
}

/** One name's current state, as the index holds it. */
export interface NameEntry {
  readonly current: Predecessor;
  readonly logIndex: number;
  readonly revoked: boolean;
}

/**
 * Index key for one name. A space is unambiguous because the label grammar admits only
 * `[a-z0-9-]`, so neither component can contain one.
 */
const nameKey = (name: string, tld: string): string => `${tld} ${name}`;

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** Index of the first element >= value in a sorted array. */
function lowerBound(sorted: readonly number[], value: number): number {
  let low = 0;
  let high = sorted.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (sorted[mid]! < value) low = mid + 1;
    else high = mid;
  }
  return low;
}

/**
 * Insert into a sorted array, preserving order.
 *
 * Records usually arrive in time order, but nothing guarantees it: a peer replicating a
 * partition's backlog receives them in whatever order they arrive, and `notBefore` is chosen by
 * the record's author. Inserting at the correct position rather than appending keeps the array
 * a valid input to binary search under every arrival order.
 */
function insertSorted(sorted: number[], value: number): void {
  sorted.splice(lowerBound(sorted, value), 0, value);
}

/**
 * Frame entries for the log. Exported because the framing is wire-visible to anything that
 * reads the file, and a test pins it.
 */
export function frame(bytes: Uint8Array): Uint8Array {
  if (bytes.length > MAX_ENTRY_BYTES) {
    throw new StoreError(`entry of ${bytes.length} bytes exceeds ${MAX_ENTRY_BYTES}`);
  }
  const out = new Uint8Array(LENGTH_PREFIX_BYTES + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, LENGTH_PREFIX_BYTES);
  return out;
}

/** Split a log file into its entries, refusing anything malformed rather than guessing. */
export function unframe(file: Uint8Array): Uint8Array[] {
  const entries: Uint8Array[] = [];
  let at = 0;
  while (at < file.length) {
    if (at + LENGTH_PREFIX_BYTES > file.length) {
      throw new StoreError(`truncated length prefix at byte ${at}`);
    }
    const view = new DataView(file.buffer, file.byteOffset + at, LENGTH_PREFIX_BYTES);
    const length = view.getUint32(0, false);
    if (length === 0) throw new StoreError(`zero-length entry at byte ${at}`);
    if (length > MAX_ENTRY_BYTES) {
      throw new StoreError(`entry length ${length} at byte ${at} exceeds ${MAX_ENTRY_BYTES}`);
    }
    const start = at + LENGTH_PREFIX_BYTES;
    if (start + length > file.length) {
      throw new StoreError(`truncated entry at byte ${at}: wanted ${length} bytes`);
    }
    entries.push(file.subarray(start, start + length));
    at = start + length;
  }
  return entries;
}

/**
 * A local registry: the log, the index derived from it, and the {@link RegistryView} the
 * verifier consults.
 */
export class Store implements RegistryView {
  readonly path: string;
  private readonly entries: LogEntry[] = [];
  private readonly names = new Map<string, NameEntry>();

  /**
   * Record hashes already held, for the duplicate check.
   *
   * A set rather than a scan of `entries`. Duplicate detection runs on every arrival, so a
   * linear scan makes replaying a log of N records cost O(N^2).
   */
  private readonly seen = new Set<string>();

  /**
   * Per-TLD sorted `notBefore` values for REGISTER and RENEW, for the difficulty window.
   *
   * Maintained incrementally and searched with two binary searches, because this was the
   * sharpest thing the audit found. Difficulty depends on the trailing thirty days of
   * registrations in a TLD, so verifying one record consulted this twice, and a linear scan
   * made a full replay O(N^2).
   *
   * That is an amplification, not merely slow code. Adding a record costs an attacker one
   * proof of work — linear in what they spend — while the replay cost they impose on every
   * peer that ever joins grows quadratically. REGISTRY.md offers no relief: the log is never
   * truncated, and "a peer that has never verified the history and wants full assurance MUST
   * pay the full cost once". Making that cost quadratic is a way to price newcomers out of
   * verifying, and a registry only newcomers-who-trust-someone can join is not this registry.
   */
  private readonly rates = new Map<string, number[]>();

  private constructor(path: string) {
    this.path = path;
  }

  /**
   * Open a log, replaying and re-verifying every entry.
   *
   * A record already in the log is verified again rather than trusted. The file is ordinary
   * bytes on an ordinary disk; treating "it is already here" as evidence it was ever checked is
   * how a tampered store stays undetected.
   */
  static open(path: string, now: number): Store {
    const store = new Store(path);
    if (!existsSync(path)) return store;

    const file = readFileSync(path);
    const raw = unframe(new Uint8Array(file.buffer, file.byteOffset, file.byteLength));

    for (const [position, bytes] of raw.entries()) {
      // Replay verifies against the state as it stood when the record was appended, not against
      // the clock now — otherwise every registration would be BACKDATED the moment it aged a day.
      const record = parseRecordBytes(bytes);
      const verdict = store.verifyAt(bytes, record.notBefore);
      if (verdict.outcome !== 'accept') {
        const why = verdict.outcome === 'reject' ? verdict.code : verdict.reason;
        throw new StoreError(`log entry ${position} no longer verifies: ${why}`);
      }
      store.apply(bytes, record);
    }
    // `now` is accepted so callers cannot forget that a store is a view at an instant; replay
    // itself deliberately does not use it.
    void now;
    return store;
  }

  /** Verify a record against current state at a given instant, without appending it. */
  verifyAt(bytes: Uint8Array, now: number): Verdict {
    return verify(bytes, this, now);
  }

  /**
   * Verify and append. Returns the verdict; the log is unchanged unless it was an accept.
   *
   * A duplicate arrival is not an error — REGISTRY.md requires a peer receiving a record it
   * already holds to drop it silently — so an identical byte string already in the log returns
   * its original acceptance rather than a rejection.
   */
  append(bytes: Uint8Array, now: number): Verdict {
    if (this.has(bytes)) {
      return { outcome: 'accept', record: parseRecordBytes(bytes) };
    }
    const verdict = this.verifyAt(bytes, now);
    if (verdict.outcome !== 'accept') return verdict;

    mkdirSync(dirname(this.path), { recursive: true });
    if (!existsSync(this.path)) closeSync(openSync(this.path, 'w'));
    appendFileSync(this.path, frame(bytes));

    this.apply(bytes, verdict.record);
    return verdict;
  }

  private has(bytes: Uint8Array): boolean {
    return this.seen.has(hex(recordHashFromBytes(bytes)));
  }

  private apply(bytes: Uint8Array, record: RegistryRecord): void {
    const index = this.entries.length;
    const hash = recordHashFromBytes(bytes);
    this.entries.push({ index, bytes, record, hash });
    this.seen.add(hex(hash));

    // Maintained incrementally rather than recomputed. See the note on `rates`.
    if (record.op === 'REGISTER' || record.op === 'RENEW') {
      const times = this.rates.get(record.tld) ?? [];
      insertSorted(times, record.notBefore);
      this.rates.set(record.tld, times);
    }

    const key = nameKey(record.name, record.tld);
    const wasRevoked = this.names.get(key)?.revoked ?? false;
    this.names.set(key, {
      current: predecessorFrom(record, bytes),
      logIndex: index,
      // Revocation is sticky. A REGISTER accepted after quarantine clears it, because that is a
      // new registration of a name back in the open pool rather than a continuation.
      revoked: record.op === 'REGISTER' ? false : wasRevoked || record.op === 'REVOKE',
    });
  }

  /* -- RegistryView ------------------------------------------------------- */

  current(name: string, tld: string): Predecessor | null {
    return this.names.get(nameKey(name, tld))?.current ?? null;
  }

  revoked(name: string, tld: string): boolean {
    return this.names.get(nameKey(name, tld))?.revoked ?? false;
  }

  fullyReleased(previous: Predecessor, now: number): boolean {
    return isFullyReleased(previous.record, now);
  }

  /**
   * Proof-of-work verification at the difficulty this log requires.
   *
   * PROOF-OF-WORK.md permits a proof computed for the epoch of `notBefore` or the immediately
   * preceding one, to absorb propagation delay. Taking the lower of the two requirements
   * implements that: a registrant who computed against either epoch is accepted, and a
   * verifier whose count differs by a few late arrivals does not reject an honest record.
   */
  powVerified(record: RegistryRecord): boolean {
    return verifyPow(record.map, this.requiredBitsFor(record)).ok;
  }

  /**
   * The difficulty this log requires of a record, taking the lower of the two permitted epochs.
   *
   * Exposed so a registrant can ask what it must solve for before spending the work, and so the
   * CLI reports the same number the verifier will apply rather than a second estimate of it.
   */
  requiredBitsFor(record: RegistryRecord): number {
    const thisEpoch = this.registrationsInWindow(record.tld, record.notBefore);
    const previousEpoch = this.registrationsInWindow(record.tld, record.notBefore - EPOCH_SECONDS);
    return Math.min(
      requiredBits(record.name.length, thisEpoch),
      requiredBits(record.name.length, previousEpoch),
    );
  }

  /**
   * Registrations and renewals accepted in one TLD over the trailing 30 days ending at the
   * epoch containing `at`.
   */
  registrationsInWindow(tld: string, at: number): number {
    const { start, end } = rateWindow(at);
    const times = this.rates.get(tld);
    if (times === undefined) return 0;
    // Two binary searches over a sorted per-TLD array. See the note on `rates` for why this is
    // not a linear scan.
    return lowerBound(times, end) - lowerBound(times, start);
  }

  /**
   * The obvious implementation, kept as a differential-testing oracle and never used in
   * production. {@link registrationsInWindow} is the fast path; this is what it must agree with.
   *
   * Retained deliberately rather than deleted with the optimisation. An optimisation with no
   * reference to check against is an assertion, and this one is load-bearing: a wrong count is
   * a wrong difficulty, and a wrong difficulty is a fork.
   */
  registrationsInWindowNaive(tld: string, at: number): number {
    const { start, end } = rateWindow(at);
    let count = 0;
    for (const entry of this.entries) {
      const r = entry.record;
      if (r.tld !== tld) continue;
      if (r.op !== 'REGISTER' && r.op !== 'RENEW') continue;
      if (r.notBefore >= start && r.notBefore < end) count += 1;
    }
    return count;
  }

  /* -- reads -------------------------------------------------------------- */

  /** The current record for a name, or null. Does not consider whether it still resolves. */
  lookup(name: string, tld: string): NameEntry | null {
    return this.names.get(nameKey(name, tld)) ?? null;
  }

  /** Names this log knows about, with their state at `now`. */
  list(now: number): Array<{ name: string; tld: string; state: string; notAfter: number }> {
    const out: Array<{ name: string; tld: string; state: string; notAfter: number }> = [];
    for (const entry of this.names.values()) {
      const r = entry.current.record;
      const life = lifecycleOf(r);
      const state = entry.revoked
        ? 'REVOKED'
        : now < life.liveUntil
          ? 'LIVE'
          : now < life.graceUntil
            ? 'GRACE'
            : now < life.quarantineUntil
              ? 'QUARANTINE'
              : 'FREE';
      out.push({ name: r.name, tld: r.tld, state, notAfter: r.notAfter });
    }
    return out.sort((a, b) => (a.tld + a.name).localeCompare(b.tld + b.name));
  }

  get length(): number {
    return this.entries.length;
  }

  entryAt(index: number): LogEntry | null {
    return this.entries[index] ?? null;
  }

  /** Difficulty currently required to register this label in this TLD. */
  difficultyFor(label: string, tld: string, at: number): number {
    return requiredBits(label.length, this.registrationsInWindow(tld, at));
  }
}

export { GRACE_SECONDS, QUARANTINE_SECONDS };

/** Write a log file from scratch. Used by tooling and tests, never during normal operation. */
export function writeLog(path: string, entries: readonly Uint8Array[]): void {
  mkdirSync(dirname(path), { recursive: true });
  const framed = entries.map(frame);
  let total = 0;
  for (const f of framed) total += f.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const f of framed) {
    out.set(f, at);
    at += f.length;
  }
  writeFileSync(path, out);
}
