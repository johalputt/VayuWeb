/**
 * The equivocation ledger: where a detection goes so that it survives the process that made it.
 *
 * docs/spec/REPLICATION.md section 6 is authoritative. 6.3 is one sentence and it is a MUST:
 *
 * > A peer detecting equivocation MUST record it and SHOULD forward the evidence.
 *
 * Before this module, neither half happened. `converge.ts` could tell equivocation from an honest
 * race, `replicate.ts` could verify a report a peer sent, and the driver in `swarm.ts` incremented
 * a counter that died with the process. A detection nobody can read afterwards is not a record,
 * and no shipping code path had ever constructed an outbound `EQUIVOCATION` message at all — the
 * type had an encoder, a decoder, a verifier and a conformance vector, and no sender.
 *
 * ## Why the log cannot be the ledger
 *
 * The evidence is a *pair*, and the log can only ever hold one half of it. Equivocation is found
 * when a record arrives that conflicts with one already held: the incumbent is in the log and the
 * newcomer is refused, so `Store.append` returns a rejection and the newcomer's bytes are dropped
 * on the floor. `Store.open` re-verifies every entry and throws if one no longer verifies, which
 * means a log *cannot* contain both halves — the second would have been refused when it arrived.
 * So without somewhere else to put it, the refused half is unrecoverable and the detection is
 * gone the moment the function returns.
 *
 * ## What a hostile peer can do to a ledger, which sets every bound below
 *
 * 6.2.4 forbids requiring either record to be **acceptable** — no proof of work, no expiry, no
 * chain position — and it is right to, because requiring them would hand an equivocator a one-line
 * evasion. The consequence is that **minting verifiable evidence costs two signatures and nothing
 * else.** Anyone can sign two records for any name at any `seq` with their own key and produce a
 * pair that every conforming peer will verify, record and forward. That is not a flaw in 6.2; it
 * is what "self-contained and third-party verifiable" buys, and the price is paid here:
 *
 * - **Identity, not bytes, is the deduplication key.** Two records at one `seq` for one name by
 *   one owner are one fact. An attacker who varies `notBefore` by a second mints unlimited
 *   distinct *pairs* about the same fact; keying on `(ownerKey, tld, name, seq)` collapses them
 *   to one entry and one forward. Keying on the encodings would have been an unbounded stream.
 * - **Two budgets, and one cannot spend the other's.** A report this peer *detected* is anchored
 *   to a record in its own log, and every record in that log cost a proof of work — so the count
 *   is bounded by work somebody did. A report a peer *sent* is bounded by nothing, so it gets its
 *   own smaller budget and can never displace a detection.
 * - **A full budget refuses; it never evicts.** Eviction would let an attacker flush a genuine
 *   report by minting cheap ones after it. Refusing means an attacker can instead deny space to
 *   later genuine third-party reports, which is the other half of the same trade — stated rather
 *   than hidden, and made visible in {@link EquivocationLedger.refused} so an operator sees a
 *   ledger that is turning things away instead of a ledger that has quietly stopped growing.
 *
 * ## And what it is not
 *
 * 6.4: **this protocol does not punish equivocation.** Nothing here is a blocklist, a score or an
 * input to any decision. No name is lost, no key is excluded, and nothing in the resolver or the
 * verifier reads this file. It is a legible record, which Article 38 asks for, and what a reader
 * does with it is not the protocol's business. A mechanism able to act on evidence is a mechanism
 * able to act on manufactured evidence, so this one acts on nothing.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { decode, encode, type CborMap, type CborValue } from './cbor.ts';
import { parseRecordBytes, type RegistryRecord } from './record.ts';
import { LIMITS, verifyEquivocation, type EquivocationMessage } from './replicate.ts';
import { frame } from './store.ts';

/**
 * The two record encodings, which is the whole of the evidence.
 *
 * Structurally what an {@link EquivocationMessage} carries minus its tag, so a message is usable
 * as evidence directly and evidence is one field short of a message. Deliberately not the message
 * type itself: a record this peer detected in its own log never was a message, and typing it as
 * one would suggest it arrived from somewhere.
 */
export interface EquivocationEvidence {
  readonly a: Uint8Array;
  readonly b: Uint8Array;
}

/**
 * Where a report came from, which is the only thing that distinguishes the two budgets.
 *
 * `detected` is anchored to this peer's own log. `received` arrived over a wire from a party this
 * peer knows nothing about, and REPLICATION.md is explicit that it knows nothing about them:
 * "there is no trusted peer". Both are verified identically — the origin buys no credibility, only
 * a different bound.
 */
export type EvidenceOrigin = 'detected' | 'received';

/** What {@link EquivocationLedger.record} did, reported rather than inferred. */
export type RecordOutcome = 'recorded' | 'duplicate' | 'unverified' | 'full';

/** One report as the ledger holds it. */
export interface LedgerEntry {
  readonly origin: EvidenceOrigin;
  /** `(ownerKey, tld, name, seq)` rendered as a string. The identity of the fact, not of the pair. */
  readonly key: string;
  readonly evidence: EquivocationEvidence;
}

/**
 * Every bound this ledger enforces, in one place, for the same reason {@link
 * import('./replicate.ts').LIMITS} is: a limit nobody can enumerate is a limit nobody audits.
 */
export const EQUIVOCATION_LIMITS = {
  /**
   * Reports detected locally.
   *
   * Generous because each one is anchored to a record in this peer's own log, and every record in
   * that log carried a proof of work somebody paid for. A thousand of them is a thousand solves.
   */
  detected: 1_024,
  /**
   * Reports a peer sent.
   *
   * An order of magnitude smaller, because this is the number that costs an attacker two
   * signatures each. At the maximum record size a full budget is about two megabytes on disk.
   */
  received: 256,
  /**
   * Reports forwarded on one connection.
   *
   * A peer holding a full ledger would otherwise open every connection with ten megabytes of
   * evidence nobody asked for, which is an amplifier built out of a SHOULD.
   */
  perConnection: 32,
} as const;

/**
 * Bytes a single ledger entry may occupy on disk, framing included.
 *
 * **Derived rather than chosen**, because the only place it is enforced is the reader — where the
 * length comes from a file somebody else may have written — and a writer that could exceed it
 * would be a writer whose entry vanishes on the next open. `verifyEquivocation` refuses either
 * record over `LIMITS.recordBytes` before anything reaches here, so two of them plus a three-key
 * CBOR map cannot reach this number; the 512 is the map, the keys and the two byte-string headers,
 * several times over.
 *
 * It was a round 16,384 for one commit, with a size check in the writer that returned silently on
 * a value it could not produce. That is the shape of thing this project keeps finding: a branch
 * nobody can reach, which would have left an entry in memory and not on disk, with no counter to
 * say so. Deriving the bound deletes the branch instead of testing it.
 */
const MAX_LEDGER_ENTRY_BYTES = 2 * LIMITS.recordBytes + 512;

const LENGTH_PREFIX_BYTES = 4;

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * The identity of the fact a report is about.
 *
 * Derived from one record because a verified pair agrees on all four components — `isEquivocation`
 * requires the same name, the same tld, the same `seq` and equal owner keys, and refuses anything
 * else. So either half yields the same key, and a caller holding only the incoming record can ask
 * whether the fact is already recorded before doing any work to find the other half.
 */
export function equivocationKey(record: RegistryRecord): string {
  return `${hex(record.ownerKey)} ${record.tld} ${record.name} ${record.seq}`;
}

/**
 * What {@link import('./store.ts').Store} needs in order to hand a detection somewhere durable.
 *
 * Narrow on purpose, and narrower than the ledger: the store can write a report and ask whether
 * one is already settled, and cannot read the ledger back or forward anything. A store that could
 * enumerate reports would be a store that could act on them, which 6.4 refuses.
 */
export interface EquivocationRecorder {
  /**
   * Is there nothing to be gained by looking for the other half of this record's pair?
   *
   * True when the fact is already recorded, or when the budget it would go in is full. It exists
   * so the store can answer in two map lookups rather than by scanning its log: a rejected record
   * is cheap for a hostile peer to produce — no proof of work is verified before most rejections —
   * so a scan per rejection would be a linear amplifier over the whole log.
   */
  settled(record: RegistryRecord, origin: EvidenceOrigin): boolean;
  record(evidence: EquivocationEvidence, origin: EvidenceOrigin): RecordOutcome;
}

/** What a driver needs: the recorder, plus the ability to read back what it holds in order to forward it. */
export interface EquivocationReader extends EquivocationRecorder {
  entries(): readonly LedgerEntry[];
}

/** How many reports a ledger turned away, by reason. Zero is the ordinary state; anything else is news. */
export interface Refusals {
  /** Reports that did not verify. On a wire, this is somebody trying it on. */
  unverified: number;
  /** Reports refused because their budget was full. */
  full: number;
  /** Entries on disk that could not be read back, which includes a truncated tail. */
  unreadable: number;
}

/** The conventional path of the ledger belonging to a log. */
export const ledgerPathFor = (logPath: string): string => `${logPath}.equivocations`;

/**
 * A durable, bounded, deduplicating record of equivocation this peer knows about.
 *
 * ## Replay verifies, exactly as the log does
 *
 * `store.ts` states the principle and this file inherits it: "a file an attacker can append to is
 * not a file whose contents are known-good". Every entry is re-verified on load with the same
 * {@link verifyEquivocation} a wire report passes, so appending a fabricated pair to the file by
 * hand achieves nothing — it is dropped on the next open and counted in {@link refused}.
 *
 * It differs from the log in what it does about a bad entry, and the difference is deliberate. A
 * log entry that no longer verifies makes the whole store unopenable, because the state derived
 * from it would be wrong. A ledger entry that does not verify makes nothing wrong: the ledger is
 * an appendix that nothing reads for state. Refusing to open would let anyone with write access to
 * a sidecar file take a registry offline, so a bad entry is dropped and counted instead.
 */
export class EquivocationLedger implements EquivocationReader {
  readonly path: string;
  private readonly held: LedgerEntry[] = [];
  private readonly byKey = new Set<string>();
  private readonly counts: Record<EvidenceOrigin, number> = { detected: 0, received: 0 };
  private readonly refusals: Refusals = { unverified: 0, full: 0, unreadable: 0 };

  private constructor(path: string) {
    this.path = path;
  }

  /** Open the ledger at a path, replaying and re-verifying whatever is there. Missing is empty. */
  static open(path: string): EquivocationLedger {
    const ledger = new EquivocationLedger(path);
    if (!existsSync(path)) return ledger;
    const file = readFileSync(path);
    const raw = new Uint8Array(file.buffer, file.byteOffset, file.byteLength);
    for (const { origin, evidence } of readEntries(raw, ledger.refusals)) {
      // Through the same door a wire report comes in by, budgets and all. A file is not a
      // privileged source; it is a source whose author had write access to a path.
      if (ledger.record(evidence, origin, { persist: false }) !== 'recorded') {
        ledger.refusals.unreadable += 1;
      }
    }
    return ledger;
  }

  /** An in-memory ledger, for a caller with nowhere to put a file. Never persists. */
  static ephemeral(): EquivocationLedger {
    return new EquivocationLedger('');
  }

  settled(record: RegistryRecord, origin: EvidenceOrigin): boolean {
    return this.byKey.has(equivocationKey(record)) || this.counts[origin] >= this.budget(origin);
  }

  /**
   * Verify a report and write it down, or say why not.
   *
   * The order is not arrangeable: verification first, because everything after it — the identity
   * used for deduplication, the budget it is charged to, the bytes written to disk — is derived
   * from a pair that has been checked. A ledger that deduplicated before verifying could be taught
   * to reject a genuine report by being shown a forged one with the same identity first.
   */
  record(
    evidence: EquivocationEvidence,
    origin: EvidenceOrigin,
    options: { persist?: boolean } = {},
  ): RecordOutcome {
    const message: EquivocationMessage = { t: 'EQUIVOCATION', a: evidence.a, b: evidence.b };
    if (!verifyEquivocation(message)) {
      this.refusals.unverified += 1;
      return 'unverified';
    }
    let key: string;
    try {
      key = equivocationKey(parseRecordBytes(evidence.a));
    } catch {
      // Unreachable while `verifyEquivocation` parses both halves before it returns true, and
      // written anyway: this function's contract is that it never throws for anything a peer
      // controls, and that must not depend on another function's internals.
      this.refusals.unverified += 1;
      return 'unverified';
    }
    if (this.byKey.has(key)) return 'duplicate';
    if (this.counts[origin] >= this.budget(origin)) {
      this.refusals.full += 1;
      return 'full';
    }

    const entry: LedgerEntry = { origin, key, evidence: { a: evidence.a, b: evidence.b } };
    if (options.persist !== false) this.persist(entry);
    this.held.push(entry);
    this.byKey.add(key);
    this.counts[origin] += 1;
    return 'recorded';
  }

  entries(): readonly LedgerEntry[] {
    return this.held;
  }

  /** How many reports were turned away, by reason. A ledger that is refusing is a ledger under load. */
  get refused(): Refusals {
    return { ...this.refusals };
  }

  /** How many reports are held, by origin. */
  countOf(origin: EvidenceOrigin): number {
    return this.counts[origin];
  }

  get size(): number {
    return this.held.length;
  }

  private budget(origin: EvidenceOrigin): number {
    return origin === 'detected' ? EQUIVOCATION_LIMITS.detected : EQUIVOCATION_LIMITS.received;
  }

  private persist(entry: LedgerEntry): void {
    if (this.path === '') return;
    const map: CborMap = new Map<string | Uint8Array, CborValue>([
      ['o', entry.origin === 'detected' ? 'd' : 'r'],
      ['a', entry.evidence.a],
      ['b', entry.evidence.b],
    ]);
    mkdirSync(dirname(this.path), { recursive: true });
    appendFileSync(this.path, frame(encode(map)));
  }
}

/**
 * Read as many entries as the file yields, and stop at the first one that does not parse.
 *
 * Tolerant of a truncated tail on purpose. The ledger is appended to while a process may be
 * killed, and a half-written final entry is the ordinary consequence of that — not evidence of
 * tampering, and not a reason to lose the entries before it. What is *not* tolerated is a bad
 * entry being skipped over: the framing is length-prefixed, so a length that does not lead
 * anywhere means every offset after it is a guess. Stopping is the only honest response, and the
 * remainder is counted rather than passed over in silence.
 */
function readEntries(
  file: Uint8Array,
  refusals: Refusals,
): Array<{ origin: EvidenceOrigin; evidence: EquivocationEvidence }> {
  const out: Array<{ origin: EvidenceOrigin; evidence: EquivocationEvidence }> = [];
  let at = 0;
  while (at < file.length) {
    if (at + LENGTH_PREFIX_BYTES > file.length) break;
    const view = new DataView(file.buffer, file.byteOffset + at, LENGTH_PREFIX_BYTES);
    const length = view.getUint32(0, false);
    if (length === 0 || length + LENGTH_PREFIX_BYTES > MAX_LEDGER_ENTRY_BYTES) {
      refusals.unreadable += 1;
      break;
    }
    const start = at + LENGTH_PREFIX_BYTES;
    if (start + length > file.length) break;
    const parsed = parseEntry(file.subarray(start, start + length));
    if (parsed === null) {
      refusals.unreadable += 1;
      break;
    }
    out.push(parsed);
    at = start + length;
  }
  return out;
}

function parseEntry(
  bytes: Uint8Array,
): { origin: EvidenceOrigin; evidence: EquivocationEvidence } | null {
  let map: CborValue;
  try {
    map = decode(bytes);
  } catch {
    return null;
  }
  if (!(map instanceof Map)) return null;
  const origin = map.get('o');
  const a = map.get('a');
  const b = map.get('b');
  if (origin !== 'd' && origin !== 'r') return null;
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return null;
  return { origin: origin === 'd' ? 'detected' : 'received', evidence: { a, b } };
}
