/**
 * Local append-only log and index.
 *
 * docs/spec/REGISTRY.md, "The Log" and "The Index".
 *
 * ## What this is not, stated first
 *
 * This is **not** Hypercore and **not** Hyperbee. It is a single-writer, file-backed log with an
 * in-memory index rebuilt by replay, and it exists so that Phase 1's tooling can be built and
 * tested — "a command-line tool can register a name into a local log, resolve it back, reject
 * every malformed and replayed record in the test-vector set, and a second tool written from the
 * specification agrees on every vector" — without dragging the peer-to-peer stack in first. The
 * second tool is not in this repository, so the phase is not finished by this code.
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
import { compareHashes, resolveConflict, voidedChain } from './converge.ts';
import { compareBytes } from './cbor.ts';
import { recordHashFromBytes } from './domain.ts';
import {
  verify,
  MAX_BACKDATE_SECONDS,
  predecessorFrom,
  controllingKey,
  type Predecessor,
  type RegistryView,
  type Verdict,
} from './verify.ts';
import { verifyPow, rateWindow, requiredBits, EPOCH_SECONDS } from './pow.ts';
import { lifecycleOf, isFullyReleased } from './lifecycle.ts';
import { treeOf } from './merkle.ts';
import { checkpointOf, isCheckpointLength, type Checkpoint } from './checkpoint.ts';
import { signedByNamedOwner, type ReplicationSink } from './replicate.ts';
import type { EquivocationRecorder } from './equivocation.ts';

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
  /**
   * The `record_hash` of the REGISTER this name's chain descends from.
   *
   * Held so a convergence conflict can be judged without scanning the log. A newcomer conflicts
   * with the chain's *root*, not with whatever `UPDATE` happens to be current, because a conflict
   * is two records at the same `seq` and `seq` 0 is where a registration race happens. Storing it
   * also makes the "could this newcomer possibly win?" comparison a map lookup, which is what
   * stops an attacker making us verify Argon2id proofs for names that are plainly held.
   */
  readonly rootHash: Uint8Array;
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

  /**
   * Where a detected equivocation goes, or null if nobody is listening.
   *
   * Optional because the store is the wrong place to decide that a detection should be persisted:
   * a caller running against a temporary log in a test wants nothing written beside it, and a
   * caller with no log path at all has nowhere to write. Null is therefore a working store that
   * detects nothing, and the CLI attaches one for every command that can append.
   */
  private equivocation: EquivocationRecorder | null = null;

  private constructor(path: string) {
    this.path = path;
  }

  /**
   * Send detected equivocation to a recorder.
   *
   * Deliberately not a constructor argument. `Store.open` replays a log that *cannot* contain
   * equivocation — the second of two conflicting records would have been refused on arrival, and
   * replay throws on anything that no longer verifies — so there is nothing to record during open,
   * and taking a recorder there would suggest otherwise.
   */
  watchEquivocation(recorder: EquivocationRecorder): void {
    this.equivocation = recorder;
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
      return { outcome: 'accept', record: parseRecordBytes(bytes), duplicate: true };
    }
    const verdict = this.verifyAt(bytes, now);
    if (verdict.outcome === 'reject' && verdict.code === 'NAME_TAKEN') {
      const merged = this.mergeConflict(bytes, now, verdict);
      // An accepted merge is a race between *strangers* that the newcomer won, which is the one
      // outcome that cannot be equivocation: `mergeConflict` returns early when the owner keys are
      // equal, so reaching acceptance means they were not.
      if (merged.outcome !== 'accept') this.noteEquivocation(bytes);
      return merged;
    }
    if (verdict.outcome !== 'accept') {
      this.noteEquivocation(bytes);
      return verdict;
    }

    this.write(bytes);
    this.apply(bytes, verdict.record);
    return verdict;
  }

  /**
   * Did the record we just refused equivocate with one we hold? If so, write the pair down.
   *
   * REPLICATION.md 6.3: "A peer detecting equivocation MUST record it". This is the detection, and
   * it runs on every rejection rather than only on the two codes that happen to be reachable
   * today. Equivocation is defined at 6.1 as one owner key signing two different records at one
   * `seq` for one `name.tld` — the operation is not part of the definition, and the two rejections
   * this actually fires on are different codes for the same fact: a second REGISTER at `seq` 0 is
   * `NAME_TAKEN`, while a second UPDATE or RENEW at a `seq` the chain has passed is `BAD_SEQ`.
   * Keying on the codes would have recorded the first case and silently missed every later one.
   *
   * ## Why it verifies rather than comparing owner keys
   *
   * An `ownerKey` is public — it appears in every record its holder ever published. The conflict
   * path in {@link mergeConflict} compares owner keys as *bytes*, which is correct for what it is
   * deciding (whether to award a name) and catastrophic as a basis for a report: anyone can copy a
   * held name's owner key into a record they signed themselves, send it here, and have this peer
   * write down and then forward a fabricated accusation against its holder. That is 6.4's
   * manufactured evidence arriving by the front door, and 6.2.1 says so in terms.
   *
   * So the pair goes through {@link EquivocationRecorder.record}, which runs the same
   * `verifyEquivocation` a wire report passes and checks *both* signatures against the key they
   * name. `NAME_TAKEN` is decided before the signature is ever checked, so at this point nothing
   * has established that the arriving record is the owner's at all.
   *
   * ## Why `settled` is asked first
   *
   * A rejected record is cheap for a hostile peer to produce — most rejections are reached before
   * any proof of work is verified — so a scan of the log per rejection would be a linear amplifier
   * over a file that is never truncated. `settled` answers in two map lookups from the incoming
   * record alone, because a verified pair agrees on all four components of its identity. After the
   * first report about a fact, every repetition costs a lookup.
   */
  private noteEquivocation(bytes: Uint8Array): void {
    const recorder = this.equivocation;
    if (recorder === null) return;
    let incoming: RegistryRecord;
    try {
      incoming = parseRecordBytes(bytes);
    } catch {
      return;
    }
    const key = nameKey(incoming.name, incoming.tld);
    if (!this.names.has(key)) return;
    if (recorder.settled(incoming, 'detected')) return;
    // One signature, before any scan. A forged pair would be refused by the recorder anyway — it
    // runs the same check on both halves — but only after this function had walked the whole log
    // to find the half to pair it with, on a rejection the attacker got for the price of an
    // encode. Checking the arriving record first means a name's own owner is the only party who
    // can make this peer look.
    if (!signedByNamedOwner(incoming)) return;

    const incomingHash = hex(recordHashFromBytes(bytes));
    for (const entry of this.entries) {
      if (entry.record.seq !== incoming.seq) continue;
      if (nameKey(entry.record.name, entry.record.tld) !== key) continue;
      if (compareBytes(entry.record.ownerKey, incoming.ownerKey) !== 0) continue;
      // Identical bytes are a duplicate, which `append` has already answered; a different record
      // at the same seq by the same owner is the fact 6.1 defines.
      if (hex(entry.hash) === incomingHash) continue;
      recorder.record({ a: entry.bytes, b: bytes }, 'detected');
      return;
    }
  }

  /**
   * A registration arrived for a name this peer already holds. Decide it by the convergence rule.
   *
   * This is the path that makes `converge.ts` reachable, and its absence was a real defect: the
   * rule was specified, implemented and unit-tested while nothing in the merge path called it, so
   * the effective rule was "whoever arrived first". Under replication that is the delivery-order
   * fork the rule exists to prevent, one layer down — two peers handed the same pair in opposite
   * orders kept different owners, permanently, and a relay chose which.
   *
   * ## Convergence resolves a partition, and only a partition
   *
   * Two guards decide whether this is a race at all, and without them wiring the rule in is worse
   * than leaving it unreachable. Both were found by attacking this function after writing it.
   *
   * **A late claim is not a concurrent claim.** Nothing in the digest rule bounds *when* a
   * conflicting registration may arrive, so without a window "first valid signature wins" decays
   * into "lowest digest ever produced wins": a name held for a decade could be taken by anyone
   * who grinds a lower digest. The grinding is not even expensive — an incumbent digest is
   * uniform over 256 bits, so beating a given one takes about two attempts on average. That would
   * make roughly half of all names stealable for a couple of proofs of work, and it would destroy
   * Article 11's non-revocability, which Article 9.7 entrenches.
   *
   * The window is `MAX_BACKDATE_SECONDS`, taken rather than invented: it is already the
   * protocol's own answer to "how far apart can two records be and still both be arrivable now",
   * since a record older than that is rejected as `BACKDATED`. Only the late direction needs
   * guarding — clock discipline means an incoming record can never be more than a day *older*
   * than the incumbent, because it would have been refused before reaching here.
   *
   * Deciding by `notBefore` is not a delivery-order rule, which would reintroduce the fork this
   * whole path exists to prevent. `notBefore` is in the record, identical on every peer, and
   * bounded by clock discipline against the receiver's own clock.
   *
   * **Equivocation is not a race.** One owner signing two registrations for one name is not two
   * parties who each did the work; it is one party rewriting their own history, or a compromised
   * key. The name already belongs to that key, so the incumbent stands and the second record is
   * refused — awarding it by digest would let an owner replace their own registration at will and
   * would silently mutate state on exactly the evidence Article 38 wants surfaced instead.
   *
   * ## The order of work, which is also security-relevant
   *
   *   1. The two guards above, from record fields alone. Free.
   *   2. Compare digests. Under the convergence rule a newcomer with the larger digest cannot
   *      win — rule 1 never favours it, since the incumbent is in our log — so this exits before
   *      any expensive verification. An attacker wanting to make us verify an Argon2id proof at
   *      64 MiB for a held name must first grind their digest below the incumbent's, at the cost
   *      of a full proof of work per attempt.
   *   3. Only then verify properly, with the incumbent set aside, to learn whether the newcomer
   *      would have been accepted had it arrived first. `NAME_TAKEN` alone cannot answer that:
   *      it is checked before the signature and the proof of work.
   *   4. Only then resolve, and only then rewrite the index.
   */
  private mergeConflict(bytes: Uint8Array, now: number, taken: Verdict): Verdict {
    let incoming: RegistryRecord;
    try {
      incoming = parseRecordBytes(bytes);
    } catch {
      return taken;
    }
    // Convergence is for a registration race. A non-REGISTER cannot reach NAME_TAKEN, but the
    // guard is written rather than assumed: this function replaces a live name, and it must not
    // do so on the strength of a code that happened to match.
    if (incoming.op !== 'REGISTER' || incoming.seq !== 0) return taken;

    const key = nameKey(incoming.name, incoming.tld);
    const held = this.names.get(key);
    if (held === undefined) return taken;

    const root = this.rootEntryFor(key);
    if (root === null) return taken;

    // Step 1a. A late claim is not a concurrent claim.
    //
    // Without this the digest rule decays from "first valid signature wins" into "lowest digest
    // ever produced wins", and a name held for a decade falls to anyone who grinds a lower one.
    // The grinding is cheap: an incumbent digest is uniform over 256 bits, so beating a given one
    // takes about two attempts on average, which would put roughly half of all names within reach
    // of a couple of proofs of work.
    if (incoming.notBefore - root.record.notBefore > MAX_BACKDATE_SECONDS) return taken;

    // Step 1b. Equivocation is not a race.
    //
    // One key signing two registrations for one name is not two parties who each did the work. It
    // is that party rewriting their own history, or a compromised key. The name already belongs to
    // the key either way, so the incumbent stands — and the evidence stays reportable under
    // Article 38 rather than being silently applied.
    if (compareBytes(incoming.ownerKey, root.record.ownerKey) === 0) return taken;

    const incomingHash = recordHashFromBytes(bytes);
    if (compareHashes(incomingHash, held.rootHash) >= 0) {
      // Step 2. It cannot win, so it is refused for the reason it was already refused for, and
      // no proof of work is verified.
      return taken;
    }

    // Step 3. Judge it as though the name were free.
    const onMerits = verify(bytes, this, now, { ignoreIncumbent: true });
    if (onMerits.outcome !== 'accept') return onMerits;

    // Step 4. Both are valid and the newcomer's digest is lower, so it wins. `resolveConflict` is
    // still called rather than the result assumed: the rule lives in one place, and a second
    // implementation of it here is a second implementation to keep in step.
    const incumbentRoot = root;

    const resolution = resolveConflict([
      { record: incoming, hash: incomingHash, logIndex: null, valid: true },
      {
        record: incumbentRoot.record,
        hash: incumbentRoot.hash,
        logIndex: incumbentRoot.index,
        valid: true,
      },
    ]);
    if (compareHashes(resolution.winner.hash, incomingHash) !== 0) return taken;

    const chain = this.entries
      .filter((e) => nameKey(e.record.name, e.record.tld) === key)
      .map((e) => ({ record: e.record, hash: e.hash, logIndex: e.index, valid: true }));
    const voided = voidedChain(
      {
        record: incumbentRoot.record,
        hash: incumbentRoot.hash,
        logIndex: incumbentRoot.index,
        valid: true,
      },
      chain,
    );

    // The loser's records stay in the log. It is append-only, both parties did the work, and
    // erasing the losing history would erase the evidence that the race happened at all.
    this.write(bytes);
    this.apply(bytes, incoming);

    return {
      outcome: 'accept',
      record: incoming,
      voided: voided
        .map((candidate) => this.encodingOf(candidate.hash))
        .filter((bytes): bytes is Uint8Array => bytes !== null),
    };
  }

  /** The seq-0 REGISTER a name's chain descends from, or null. */
  private rootEntryFor(key: string): LogEntry | null {
    for (const entry of this.entries) {
      if (nameKey(entry.record.name, entry.record.tld) !== key) continue;
      if (entry.record.op === 'REGISTER' && entry.record.seq === 0) return entry;
    }
    return null;
  }

  private encodingOf(hash: Uint8Array): Uint8Array | null {
    const target = hex(hash);
    for (const entry of this.entries) if (hex(entry.hash) === target) return entry.bytes;
    return null;
  }

  private write(bytes: Uint8Array): void {
    mkdirSync(dirname(this.path), { recursive: true });
    if (!existsSync(this.path)) closeSync(openSync(this.path, 'w'));
    appendFileSync(this.path, frame(bytes));
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
    const held = this.names.get(key);
    const wasRevoked = held?.revoked ?? false;
    // Who signed this record, which for a TRANSFER is not the key it names. The verifier has
    // just answered the same question to check the signature; asking it the same way here rather
    // than reimplementing it is what keeps the index and the verifier from drifting apart on the
    // one operation where `ownerKey` and "who controls the name" are different keys.
    const signerKey =
      record.op === 'TRANSFER' && held !== undefined
        ? controllingKey(held.current, record.notBefore)
        : record.ownerKey;
    this.names.set(key, {
      current: predecessorFrom(record, bytes, signerKey),
      logIndex: index,
      // Revocation is sticky. A REGISTER accepted after quarantine clears it, because that is a
      // new registration of a name back in the open pool rather than a continuation.
      revoked: record.op === 'REGISTER' ? false : wasRevoked || record.op === 'REVOKE',
      // A REGISTER starts a chain, so it is its own root — whether it is the first registration
      // of a free name, a re-registration after quarantine, or the winner of a convergence
      // conflict displacing an incumbent. Anything else inherits the root it chains onto.
      rootHash: record.op === 'REGISTER' ? hash : (held?.rootHash ?? hash),
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

  /**
   * A checkpoint over this log, or null when its length is not one a peer may serve.
   *
   * REPLICATION.md 7.1: "a peer MAY serve `CHECKPOINT` for any log length that is a multiple of
   * `CHECKPOINT_INTERVAL`". Returning null at every other length is what makes that a rule rather
   * than a suggestion — a caller cannot serve one it was never given.
   *
   * Here rather than in `checkpoint.ts` because the index it commits to is private to this class,
   * and exposing the index to build one outside would expose it to everything else as well.
   */
  checkpoint(now: number): Checkpoint | null {
    if (!isCheckpointLength(this.entries.length)) return null;
    const snapshot = this.indexSnapshot();
    return checkpointOf(
      this.entries.map((entry) => entry.bytes),
      snapshot.current,
      snapshot.records,
      now,
    );
  }

  /**
   * The index as a checkpoint commits to it: `label.tld` to the hash of the record that holds it.
   *
   * **Separate from {@link checkpoint} so it can be tested at all.** `CHECKPOINT_INTERVAL` is
   * 10,000 and every record in a test log costs a real proof of work, so the only branch of
   * `checkpoint` a test can reach is the one that returns null — which would have left the
   * conversion below unexercised until somebody had a ten-thousand-record log. The conversion is
   * not obvious: `nameKey` is `tld name`, and `indexRoot` takes `label.tld` because it derives the
   * keyspace entry itself rather than being handed one, so an error here is a wrong index root
   * rather than a crash, and a wrong index root looks exactly like a fork.
   *
   * Lowering the interval to make it testable was the other option and is the worse one: a
   * protocol constant with a test-only value is a constant two implementations can disagree about.
   */
  indexSnapshot(): {
    current: ReadonlyMap<string, Uint8Array>;
    records: ReadonlyMap<string, RegistryRecord>;
  } {
    const current = new Map<string, Uint8Array>();
    const records = new Map<string, RegistryRecord>();
    for (const [key, held] of this.names) {
      const space = key.indexOf(' ');
      const readable = `${key.slice(space + 1)}.${key.slice(0, space)}`;
      current.set(readable, held.current.hash);
      records.set(readable, held.current.record);
    }
    return { current, records };
  }

  /** Difficulty currently required to register this label in this TLD. */
  difficultyFor(label: string, tld: string, at: number): number {
    return requiredBits(label.length, this.registrationsInWindow(tld, at));
  }
}

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

/**
 * A {@link ReplicationSink} over a real log.
 *
 * **`HELLO.root` had never carried a real value in any run this project made.** Fifteen test
 * sinks stub `treeRoot: () => new Uint8Array(32)`, and no other sink existed — so the field
 * REPLICATION.md gives a peer as the cheap check that two logs agree before either asks for
 * anything was a constant, and a constant agrees with everybody. The tree code was written, the
 * root was computed privately inside `cli.ts` for the control API, and nothing joined the two.
 * That is the same shape as `retryDeferred` having no caller and `joinSwarm` having none.
 *
 * **It reads through rather than snapshotting.** A driver holds one sink for the life of a
 * connection while the log grows underneath it — from its own peer, and from this process's other
 * connections — so a `length()` captured at construction would go stale in exactly the situation
 * the protocol exists for.
 *
 * The root is recomputed per call rather than cached. `HELLO` is sent once per connection and the
 * control API asks rarely, so the cost is a hash over the log at a moment when nothing else is
 * happening; a cache would need invalidating on every append and this module has enough state.
 */
export function sinkOver(store: Store): ReplicationSink {
  return {
    append: (bytes, now) => store.append(bytes, now),
    length: () => store.length,
    encodingAt: (index) => store.entryAt(index)?.bytes ?? null,
    treeRoot: () => {
      const entries: Uint8Array[] = [];
      for (let i = 0; i < store.length; i += 1) {
        const entry = store.entryAt(i);
        if (entry === null) break;
        entries.push(entry.bytes);
      }
      return treeOf(entries).root();
    },
  };
}
