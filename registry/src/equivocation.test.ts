/**
 * REPLICATION.md section 6, from the side that wants it to fail.
 *
 * 6.3 is a MUST — "a peer detecting equivocation MUST record it and SHOULD forward the evidence" —
 * and every one of these tests was written against a codebase where neither half happened: the
 * detection was a boolean nobody stored, the wire report was a counter that died with the process,
 * and no shipping path had ever constructed an outbound `EQUIVOCATION` message.
 *
 * The tests are in the attacker's voice because the interesting half of this feature is not that
 * it records — it is everything it must refuse to record. Evidence costs two signatures to mint
 * (6.2.4 forbids requiring a valid proof of work, and is right to), so a ledger that believes what
 * it is told is a disk-filling sink and an amplifier, and a ledger that believes a pair on the
 * strength of a public owner key is 6.4's manufactured evidence with a front door.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  EQUIVOCATION_LIMITS,
  EquivocationLedger,
  equivocationKey,
  ledgerPathFor,
} from './equivocation.ts';
import { Store, frame } from './store.ts';
import { drivePeer } from './swarm.ts';
import { frame as wireFrame } from './swarm.ts';
import {
  decodeMessage,
  encodeMessage,
  verifyEquivocation,
  PROTOCOL_VERSION,
  type Message,
  type ReplicationSink,
} from './replicate.ts';
import { encode, type CborMap, type CborValue } from './cbor.ts';
import { parseRecordBytes } from './record.ts';
import { signingInput, recordHashFromBytes } from './domain.ts';
import { sign, publicKeyFrom } from './signature.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH, solvePow, requiredBits } from './pow.ts';
import { TERM_SECONDS } from './verify.ts';

const NOW = 1_782_518_400;

/** Two owners, so "one owner signing twice" is distinguishable from "two owners racing". */
const SECRET_A = new Uint8Array(32).fill(0x42);
const SECRET_B = new Uint8Array(32).fill(0x43);
const OWNER_A = publicKeyFrom(SECRET_A);
const OWNER_B = publicKeyFrom(SECRET_B);

/** 16 characters, so the base difficulty is the four-bit floor and one solve is ~16 evaluations. */
const LABEL = 'atlasobservatory';

const scratch = (name: string): string => join(mkdtempSync(join(tmpdir(), 'vayuweb-equiv-')), name);

const entry = (type: string, value: CborValue): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['type', type],
    ['value', value],
  ]);

function registerMap(options: {
  label?: string;
  owner?: Uint8Array;
  txt?: string;
  at?: number;
  nonce?: Uint8Array;
  bits?: number;
}): CborMap {
  const label = options.label ?? LABEL;
  const at = options.at ?? NOW;
  return new Map<string | Uint8Array, CborValue>([
    ['version', 1],
    ['suite', 1],
    ['op', 'REGISTER'],
    ['name', label],
    ['tld', 'vayu'],
    ['ownerKey', options.owner ?? OWNER_A],
    ['seq', 0],
    ['notBefore', at],
    ['notAfter', at + TERM_SECONDS],
    ['records', [entry('txt', options.txt ?? 'v=vayuweb1')]],
    [
      'powProof',
      new Map<string | Uint8Array, CborValue>([
        ['alg', POW_ALGORITHM],
        ['nonce', options.nonce ?? new Uint8Array(POW_NONCE_LENGTH)],
        ['bits', options.bits ?? requiredBits(label.length, 0)],
      ]),
    ],
    ['prevHash', new Uint8Array(32)],
  ]);
}

/**
 * A registration signed by the key it names, with a deliberately unsolved proof of work.
 *
 * Free, and legitimate evidence: 6.2.4 says a peer "MUST NOT require either record to be
 * *acceptable*", precisely so that an equivocator cannot escape the record by breaking their own
 * proof of work in both halves. Every pair below is built this way except where a record has to be
 * ACCEPTED into a log, which is the only thing a real solve buys.
 */
function signedRegistration(options: {
  label?: string;
  owner?: Uint8Array;
  secret?: Uint8Array;
  txt?: string;
  at?: number;
}): Uint8Array {
  const map = registerMap(options);
  map.set('sig', sign(options.secret ?? SECRET_A, signingInput(map)));
  return encode(map);
}

/**
 * The one genuinely solved registration in this file, memoised.
 *
 * A four-bit proof is about sixteen Argon2id evaluations at 64 MiB each, which is the single
 * most expensive thing here. Every test that needs a record a `Store` will *accept* shares this
 * one; everything else is unsolved and signed, which costs nothing and is still valid evidence.
 */
let accepted: Uint8Array | null = null;
function acceptedRegistration(): Uint8Array {
  if (accepted !== null) return accepted;
  const bits = requiredBits(LABEL.length, 0);
  const nonce = solvePow(registerMap({ txt: 'v=vayuweb1;first' }), bits, { limit: 8192 });
  assert.ok(nonce, 'the seed registration must be solvable at the four-bit floor');
  const map = registerMap({ txt: 'v=vayuweb1;first', nonce });
  map.set('sig', sign(SECRET_A, signingInput(map)));
  accepted = encode(map);
  return accepted;
}

/**
 * A successor at a chosen seq, signed by the owner. No proof of work: only RENEW carries one.
 *
 * `SUCCESSOR_GAP` is not decoration. A successor less than 300 seconds after its predecessor is
 * refused as `TOO_SOON`, so the obvious `NOW + 60` produced a rejection that had nothing to do with
 * what these tests are about — and, being a rejection, would have made the equivocation test below
 * pass for the wrong reason.
 */
const SUCCESSOR_GAP = 400;

function successor(options: {
  seq: number;
  prevHash: Uint8Array;
  txt: string;
  at?: number;
  secret?: Uint8Array;
}): Uint8Array {
  const at = options.at ?? NOW + SUCCESSOR_GAP;
  const map = new Map<string | Uint8Array, CborValue>([
    ['version', 1],
    ['suite', 1],
    ['op', 'UPDATE'],
    ['name', LABEL],
    ['tld', 'vayu'],
    ['ownerKey', OWNER_A],
    ['seq', options.seq],
    ['notBefore', at],
    ['notAfter', NOW + TERM_SECONDS],
    ['records', [entry('txt', options.txt)]],
    ['powProof', null],
    ['prevHash', options.prevHash],
  ]);
  map.set('sig', sign(options.secret ?? SECRET_A, signingInput(map)));
  return encode(map);
}

/* -------------------------------------------------------------------------- */
/* 6.3 — a detection that is not written down is not a record                  */
/* -------------------------------------------------------------------------- */

test('6.3 a REGISTER conflict by the name’s own owner is recorded, and survives the process', () => {
  // The whole finding, in one test. Before this, `mergeConflict` identified this exact case —
  // "Equivocation is not a race", step 1b — refused the record and returned. The refused half is
  // the only copy of it that ever existed: the log cannot hold it (it was refused) and `append`
  // discards it on return. The detection was unrecoverable the moment the function ended.
  const path = scratch('log');
  const ledger = EquivocationLedger.open(ledgerPathFor(path));
  const store = Store.open(path, NOW);
  store.watchEquivocation(ledger);

  const first = acceptedRegistration();
  assert.equal(store.append(first, NOW).outcome, 'accept', 'the seed must be accepted');

  const twin = signedRegistration({ txt: 'v=vayuweb1;second' });
  const verdict = store.append(twin, NOW);
  assert.equal(verdict.outcome, 'reject', 'the name is held by this very key; it stands');

  assert.equal(ledger.size, 1, 'the detection must be recorded — REPLICATION.md 6.3 is a MUST');
  assert.equal(ledger.countOf('detected'), 1);
  const [report] = ledger.entries();
  assert.ok(report);
  assert.equal(report.origin, 'detected');
  assert.equal(report.key, equivocationKey(parseRecordBytes(twin)));

  // And it is on disk, not in a field of an object about to be garbage collected.
  const reopened = EquivocationLedger.open(ledgerPathFor(path));
  assert.equal(reopened.size, 1, 'a record that does not outlive the process is not a record');
  assert.equal(reopened.entries()[0]?.key, report.key);
});

test('6.3 equivocation after seq 0 is recorded too, not only the registration race', () => {
  // The narrow implementation to write is one keyed to `NAME_TAKEN`, because that is the code the
  // conflict path already handled. 6.1 defines equivocation as one owner signing two different
  // records at one `seq` for one `name.tld` — the operation is not part of it. A second UPDATE at
  // a seq the chain has passed is refused as `BAD_SEQ`, a different code for the same fact, and an
  // implementation keyed to codes records the first case and misses every later one for the life
  // of the name.
  const path = scratch('log');
  const ledger = EquivocationLedger.open(ledgerPathFor(path));
  const store = Store.open(path, NOW);
  store.watchEquivocation(ledger);

  const first = acceptedRegistration();
  assert.equal(store.append(first, NOW).outcome, 'accept');
  const rootHash = recordHashFromBytes(first);

  const one = successor({ seq: 1, prevHash: rootHash, txt: 'v=vayuweb1;a' });
  assert.equal(
    store.append(one, NOW + SUCCESSOR_GAP).outcome,
    'accept',
    'the first update must land',
  );
  assert.equal(ledger.size, 0, 'an ordinary successor is not equivocation');

  const two = successor({ seq: 1, prevHash: rootHash, txt: 'v=vayuweb1;b' });
  assert.equal(store.append(two, NOW + SUCCESSOR_GAP).outcome, 'reject');
  assert.equal(ledger.size, 1, 'two futures at one seq is the fact 6.1 names, whatever the op');
  assert.equal(ledger.entries()[0]?.key.endsWith(' 1'), true, 'and it is recorded at that seq');
});

test('6.3 an honest race between two strangers is not written down as equivocation', () => {
  // The false positive that would matter most. Two different owners each registering a free name
  // is the ordinary outcome of a partition — 6.1 separates the two cases in its first sentence —
  // and a peer that files it as equivocation has published an accusation about two people who did
  // nothing but both be online.
  const path = scratch('log');
  const ledger = EquivocationLedger.open(ledgerPathFor(path));
  const store = Store.open(path, NOW);
  store.watchEquivocation(ledger);
  assert.equal(store.append(acceptedRegistration(), NOW).outcome, 'accept');

  const stranger = signedRegistration({ owner: OWNER_B, secret: SECRET_B, txt: 'v=vayuweb1;b' });
  store.append(stranger, NOW);
  assert.equal(ledger.size, 0, 'a race between different keys is not one key signing twice');
});

/* -------------------------------------------------------------------------- */
/* 6.2.1 / 6.4 — manufactured evidence, by the front door                      */
/* -------------------------------------------------------------------------- */

test('6.4 an owner key is public, so a pair I signed myself is not evidence about its holder', () => {
  // The attack the local detection path invites, and the reason it verifies rather than comparing
  // keys. `mergeConflict` decides a name by comparing owner keys as BYTES, which is correct for
  // what it decides and useless as grounds for a report: an owner key appears in every record its
  // holder ever published. Copy one into a record you signed yourself, send it to a peer, and a
  // peer that records on key equality has written down — and will hand onward — an accusation
  // against a name whose owner did nothing. 6.2.1 names this exact implementation.
  //
  // Note what does NOT save you here: `NAME_TAKEN` is decided before the signature is ever
  // checked, so at the moment of detection nothing has established that the arriving record is the
  // owner's at all.
  const path = scratch('log');
  const ledger = EquivocationLedger.open(ledgerPathFor(path));
  const store = Store.open(path, NOW);
  store.watchEquivocation(ledger);
  assert.equal(store.append(acceptedRegistration(), NOW).outcome, 'accept');

  const forged = signedRegistration({ owner: OWNER_A, secret: SECRET_B, txt: 'v=vayuweb1;forged' });
  const verdict = store.append(forged, NOW);
  assert.equal(verdict.outcome, 'reject', 'the record is refused either way');
  assert.equal(ledger.size, 0, 'and nothing is recorded against a key that signed neither half');
  assert.equal(
    ledger.refused.unverified,
    0,
    'and the ledger was never even offered it: the store checks the arriving signature before it ' +
      'will walk its log looking for a half to pair with, so a forgery costs one verification ' +
      'and not a scan',
  );

  // The same pair offered to the ledger directly, because the guard above is a bound and not the
  // security property — a later caller finding another way in must still be refused.
  assert.equal(
    ledger.record({ a: acceptedRegistration(), b: forged }, 'detected'),
    'unverified',
    'one genuine half and one minted half is a forgery, not a report',
  );
  assert.equal(ledger.refused.unverified, 1, 'and it is counted, not silently dropped');
});

test('6.2.4 a record nobody could accept still equivocates, if its owner signed it', () => {
  // The other side of the same line, because the tempting fix for the test above is "verify the
  // record properly" and that is the wrong fix. Both halves here carry an unsolved proof of work,
  // so no verifier would accept either — and both are genuinely signed by the key they name. An
  // equivocator who could escape the record by breaking their own proof of work would have a
  // one-line evasion, which is why 6.2.4 forbids requiring acceptability.
  const ledger = EquivocationLedger.ephemeral();
  const one = signedRegistration({ txt: 'v=vayuweb1;one' });
  const two = signedRegistration({ txt: 'v=vayuweb1;two' });
  assert.equal(ledger.record({ a: one, b: two }, 'detected'), 'recorded');
});

/* -------------------------------------------------------------------------- */
/* The budgets, which exist because evidence is cheap to mint                  */
/* -------------------------------------------------------------------------- */

test('a thousand variants of one fact cost one ledger entry', () => {
  // Deduplicating on the ENCODINGS would have been the obvious implementation and an unbounded
  // stream: every field an attacker can vary — `notBefore`, a record entry, the unsolved nonce —
  // mints a distinct pair that verifies, about a fact already recorded. The key is
  // `(ownerKey, tld, name, seq)`, so all of them collapse to one entry and one forward.
  const ledger = EquivocationLedger.ephemeral();
  const one = signedRegistration({ txt: 'v=vayuweb1;one' });
  assert.equal(
    ledger.record({ a: one, b: signedRegistration({ txt: 'x0' }) }, 'received'),
    'recorded',
  );

  for (let i = 1; i < 200; i += 1) {
    const outcome = ledger.record(
      { a: one, b: signedRegistration({ txt: `v=vayuweb1;${i}`, at: NOW + i }) },
      'received',
    );
    assert.equal(outcome, 'duplicate', `variant ${i} is the same fact and must not be a new entry`);
  }
  assert.equal(ledger.size, 1);
  assert.equal(
    ledger.refused.full,
    0,
    'a duplicate is not a refusal; the budget was never touched',
  );
});

test('a peer cannot fill the disk with facts it invented, and the refusal is visible', () => {
  // Distinct names, so the deduplication above does not do this test's work for it — this is the
  // bound that stops an attacker who bothers to vary the name. Each of these costs the attacker
  // one signature; the budget is what makes them stop mattering.
  const ledger = EquivocationLedger.ephemeral();
  const mint = (n: number): { a: Uint8Array; b: Uint8Array } => {
    const label = `mintedname${String(n).padStart(6, '0')}`;
    return {
      a: signedRegistration({ label, owner: OWNER_B, secret: SECRET_B, txt: 'a' }),
      b: signedRegistration({ label, owner: OWNER_B, secret: SECRET_B, txt: 'b' }),
    };
  };
  for (let i = 0; i < EQUIVOCATION_LIMITS.received; i += 1) {
    assert.equal(ledger.record(mint(i), 'received'), 'recorded', `report ${i} is within budget`);
  }
  assert.equal(
    ledger.record(mint(EQUIVOCATION_LIMITS.received), 'received'),
    'full',
    'the budget binds',
  );
  assert.equal(ledger.size, EQUIVOCATION_LIMITS.received, 'and nothing grew past it');
  assert.equal(ledger.refused.full, 1, 'a cap nobody can see is a cap nobody audits');
});

test('a peer flooding me cannot flush what I detected myself', () => {
  // Two budgets, and this is the whole reason for them. A single pool with eviction would let an
  // attacker erase a genuine local detection by minting cheap reports after it; a single pool
  // without eviction would let them deny space to it by minting cheap reports before it. A
  // detection is anchored to a record in this peer's own log, which cost a proof of work, so it
  // is charged to a budget an attacker cannot spend.
  const ledger = EquivocationLedger.ephemeral();
  for (let i = 0; i < EQUIVOCATION_LIMITS.received; i += 1) {
    const label = `floodedname${String(i).padStart(5, '0')}`;
    ledger.record(
      {
        a: signedRegistration({ label, owner: OWNER_B, secret: SECRET_B, txt: 'a' }),
        b: signedRegistration({ label, owner: OWNER_B, secret: SECRET_B, txt: 'b' }),
      },
      'received',
    );
  }
  assert.equal(ledger.countOf('received'), EQUIVOCATION_LIMITS.received);

  const mine = {
    a: signedRegistration({ txt: 'v=vayuweb1;mine-one' }),
    b: signedRegistration({ txt: 'v=vayuweb1;mine-two' }),
  };
  assert.equal(ledger.record(mine, 'detected'), 'recorded', 'my own detection still has room');
  assert.equal(ledger.countOf('detected'), 1);
});

test('a peer flooding me cannot switch off my own detection', () => {
  // Found by a mutation that SURVIVED. The test above proves the budgets are separate on the
  // ledger's write path, and a single-pool mutation of `record` failed it — but the same mutation
  // of `settled` passed, because nothing exercised that path at a full budget.
  //
  // `settled` is not a detail. It is the question the store asks BEFORE it will look for the other
  // half of a pair, so a `settled` that answers "there is no room" when the received budget is
  // full does not merely fail to record: it stops the store detecting at all. A peer that mints
  // 256 reports about names nobody has heard of would have turned off this peer's own detection,
  // for every name it holds, and the ledger would have shown nothing wrong.
  const path = scratch('log');
  const ledger = EquivocationLedger.open(ledgerPathFor(path));
  for (let i = 0; i < EQUIVOCATION_LIMITS.received; i += 1) {
    const label = `noisyname${String(i).padStart(6, '0')}`;
    assert.equal(
      ledger.record(
        {
          a: signedRegistration({ label, owner: OWNER_B, secret: SECRET_B, txt: 'a' }),
          b: signedRegistration({ label, owner: OWNER_B, secret: SECRET_B, txt: 'b' }),
        },
        'received',
      ),
      'recorded',
    );
  }

  const store = Store.open(path, NOW);
  store.watchEquivocation(ledger);
  assert.equal(store.append(acceptedRegistration(), NOW).outcome, 'accept');
  store.append(signedRegistration({ txt: 'v=vayuweb1;mine' }), NOW);

  assert.equal(
    ledger.countOf('detected'),
    1,
    'a full received budget must not stop this peer detecting equivocation about its own names',
  );
});

test('the store stops scanning its log once a fact is settled', () => {
  // Not a performance nicety. Most rejections are reached before any proof of work is verified, so
  // a hostile peer produces a rejected record for the price of an encode — and a scan of the log
  // per rejection is a linear amplifier over a file REGISTRY.md never truncates. `settled` answers
  // from the incoming record alone, in two map lookups.
  const path = scratch('log');
  const store = Store.open(path, NOW);
  let scans = 0;
  store.watchEquivocation({
    settled: (record, origin) => {
      scans += 1;
      assert.equal(origin, 'detected');
      assert.equal(record.name, LABEL);
      return scans > 1;
    },
    record: () => 'recorded',
  });
  assert.equal(store.append(acceptedRegistration(), NOW).outcome, 'accept');

  for (let i = 0; i < 5; i += 1) {
    store.append(signedRegistration({ txt: `v=vayuweb1;flood-${i}` }), NOW);
  }
  assert.equal(scans, 5, 'every rejection asks, because asking is two lookups');
});

/* -------------------------------------------------------------------------- */
/* The file on disk, which is a file an attacker may be able to write          */
/* -------------------------------------------------------------------------- */

test('a report appended to the ledger file by hand is dropped on the next open', () => {
  // `store.ts` states the principle for the log — "a file an attacker can append to is not a file
  // whose contents are known-good" — and a sidecar file is no different. Anyone who can write
  // beside somebody's log could otherwise plant an accusation that every peer they later sync with
  // is handed as though this peer had verified it.
  const path = scratch('log');
  const ledgerPath = ledgerPathFor(path);
  const ledger = EquivocationLedger.open(ledgerPath);
  const real = {
    a: signedRegistration({ txt: 'v=vayuweb1;one' }),
    b: signedRegistration({ txt: 'v=vayuweb1;two' }),
  };
  assert.equal(ledger.record(real, 'detected'), 'recorded');

  const planted = encode(
    new Map<string | Uint8Array, CborValue>([
      ['o', 'd'],
      [
        'a',
        signedRegistration({ label: 'victimsname', owner: OWNER_A, secret: SECRET_B, txt: '1' }),
      ],
      [
        'b',
        signedRegistration({ label: 'victimsname', owner: OWNER_A, secret: SECRET_B, txt: '2' }),
      ],
    ]),
  );
  appendFileSync(ledgerPath, frame(planted));

  const reopened = EquivocationLedger.open(ledgerPath);
  assert.equal(reopened.size, 1, 'the genuine report survives');
  assert.equal(reopened.entries()[0]?.key, ledger.entries()[0]?.key);
  assert.ok(reopened.refused.unverified >= 1, 'and the planted one is refused and counted');
});

test('a length prefix nobody could have written is refused before it is believed', () => {
  // The bound on an entry is now enforced in exactly one place — the reader — because that is the
  // only place the length comes from a file somebody else may have written. A four-byte prefix
  // that reserves however much memory the writer felt like naming is the cheapest denial of
  // service a length-prefixed format offers, and `swarm.ts` has the same check on the wire for the
  // same reason.
  const path = scratch('log');
  const ledgerPath = ledgerPathFor(path);
  const lie = new Uint8Array(64);
  new DataView(lie.buffer).setUint32(0, 0xffff_fff0, false);
  writeFileSync(ledgerPath, lie);

  const ledger = EquivocationLedger.open(ledgerPath);
  assert.equal(ledger.size, 0);
  assert.equal(ledger.refused.unreadable, 1, 'refused and counted, not read and not silent');
});

test('a half-written final entry loses that entry and nothing before it', () => {
  // The ordinary consequence of a process being killed mid-append, which is not tampering and must
  // not cost the operator the reports they already had. The log's own reader is right to be strict
  // — state derived from a bad entry would be wrong — but nothing derives state from this file.
  const path = scratch('log');
  const ledgerPath = ledgerPathFor(path);
  const ledger = EquivocationLedger.open(ledgerPath);
  assert.equal(
    ledger.record(
      { a: signedRegistration({ txt: 'v=vayuweb1;one' }), b: signedRegistration({ txt: 'two' }) },
      'detected',
    ),
    'recorded',
  );
  const whole = readFileSync(ledgerPath);
  writeFileSync(ledgerPath, whole.subarray(0, whole.length - 40));

  const reopened = EquivocationLedger.open(ledgerPath);
  assert.equal(reopened.size, 0, 'the truncated entry is gone');

  writeFileSync(ledgerPath, Buffer.concat([whole, whole.subarray(0, whole.length - 40)]));
  const partial = EquivocationLedger.open(ledgerPath);
  assert.equal(partial.size, 1, 'and a whole entry before a truncated one is kept');
});

/* -------------------------------------------------------------------------- */
/* 6.3's SHOULD — forwarding, which no shipping path had ever done             */
/* -------------------------------------------------------------------------- */

interface Fake {
  written: Uint8Array[];
  feed(bytes: Uint8Array): void;
  write(bytes: Uint8Array): void;
  on(event: 'data' | 'error' | 'close', listener: (chunk: Uint8Array) => void): void;
  destroy(): void;
}

function fakeStream(): Fake {
  const listeners = new Map<string, (chunk: Uint8Array) => void>();
  return {
    written: [],
    feed(bytes) {
      listeners.get('data')?.(bytes);
    },
    write(bytes) {
      this.written.push(bytes);
    },
    on(event, listener) {
      listeners.set(event, listener);
    },
    destroy() {
      listeners.get('close')?.(new Uint8Array(0));
    },
  };
}

const emptySink = (): ReplicationSink => ({
  append: () => ({ outcome: 'accept' }) as never,
  length: () => 0,
  encodingAt: () => null,
  treeRoot: () => new Uint8Array(32),
});

const greeting = (): Uint8Array =>
  wireFrame(encodeMessage({ t: 'HELLO', v: PROTOCOL_VERSION, len: 0, root: new Uint8Array(32) }));

/**
 * How many EQUIVOCATION messages a driver actually put on the wire.
 *
 * Decoded rather than searched for as a byte pattern, and re-verified as evidence rather than
 * merely counted. A test that counted frames containing the right substring would pass against a
 * driver that forwarded something malformed, or something that decoded but did not verify — which
 * is exactly the shape of check this project keeps finding green about the wrong thing.
 */
function forwardedEvidence(stream: Fake): number {
  let seen = 0;
  for (const written of stream.written) {
    let message: Message;
    try {
      message = decodeMessage(written.subarray(4));
    } catch {
      continue;
    }
    if (message.t !== 'EQUIVOCATION') continue;
    assert.ok(
      verifyEquivocation(message),
      'a forwarded report must itself verify; forwarding one that does not is 6.3 broken outward',
    );
    seen += 1;
  }
  return seen;
}

test('6.3 a peer that greets me is handed the evidence I hold', () => {
  // The SHOULD, and before this nothing in the codebase constructed an outbound EQUIVOCATION at
  // all — the type had an encoder, a decoder, a verifier and a conformance vector, and no sender.
  const stream = fakeStream();
  const ledger = EquivocationLedger.ephemeral();
  ledger.record(
    { a: signedRegistration({ txt: 'one' }), b: signedRegistration({ txt: 'two' }) },
    'detected',
  );

  const outcome = drivePeer(stream, emptySink(), () => NOW, {
    ledger,
    timers: { setInterval: () => 'handle', clearInterval: () => undefined },
  });
  assert.equal(
    forwardedEvidence(stream),
    0,
    'nothing is offered before the peer has introduced itself',
  );

  stream.feed(greeting());
  assert.equal(forwardedEvidence(stream), 1, 'and the report goes over once it has');
  assert.equal(outcome.forwarded, 1);

  stream.feed(greeting());
  assert.equal(forwardedEvidence(stream), 1, 'a second HELLO does not re-send it');
});

test('6.3 one connection is not handed the whole ledger, and is told what it did not get', () => {
  // A peer holding a full ledger would otherwise open every connection with megabytes of evidence
  // nobody asked for, which is an amplifier built out of a SHOULD. The withheld count is reported
  // because a silent trim reads as "you have everything".
  const stream = fakeStream();
  const ledger = EquivocationLedger.ephemeral();
  const over = EQUIVOCATION_LIMITS.perConnection + 5;
  for (let i = 0; i < over; i += 1) {
    const label = `budgetedname${String(i).padStart(4, '0')}`;
    ledger.record(
      {
        a: signedRegistration({ label, txt: 'a' }),
        b: signedRegistration({ label, txt: 'b' }),
      },
      'detected',
    );
  }
  assert.equal(ledger.size, over);

  const outcome = drivePeer(stream, emptySink(), () => NOW, {
    ledger,
    timers: { setInterval: () => 'handle', clearInterval: () => undefined },
  });
  stream.feed(greeting());
  assert.equal(forwardedEvidence(stream), EQUIVOCATION_LIMITS.perConnection);
  assert.equal(outcome.forwarded, EQUIVOCATION_LIMITS.perConnection);
  assert.equal(outcome.withheld, 5, 'and the operator is told, rather than shown a clean number');
});

test('6.3 evidence a peer sends is written down, not counted and discarded', () => {
  // What `drivePeer` did before: `outcome.equivocations += result.equivocations.length`, and the
  // evidence itself went out of scope. The session verified it correctly and then nothing kept it.
  const stream = fakeStream();
  const ledger = EquivocationLedger.ephemeral();
  const outcome = drivePeer(stream, emptySink(), () => NOW, {
    ledger,
    timers: { setInterval: () => 'handle', clearInterval: () => undefined },
  });
  stream.feed(greeting());

  const evidence = {
    a: signedRegistration({ txt: 'v=vayuweb1;one' }),
    b: signedRegistration({ txt: 'v=vayuweb1;two' }),
  };
  stream.feed(wireFrame(encodeMessage({ t: 'EQUIVOCATION', ...evidence })));
  assert.equal(outcome.equivocations, 1, 'it verified');
  assert.equal(outcome.recorded, 1, 'and it was kept');
  assert.equal(ledger.size, 1);

  // Sent again, forever, by a peer with nothing better to do.
  stream.feed(wireFrame(encodeMessage({ t: 'EQUIVOCATION', ...evidence })));
  assert.equal(outcome.equivocations, 2, 'still verifies');
  assert.equal(outcome.recorded, 1, 'and is still one fact');
  assert.equal(ledger.size, 1);
});

test('6.3 a forged report from a peer reaches no ledger', () => {
  const stream = fakeStream();
  const ledger = EquivocationLedger.ephemeral();
  const outcome = drivePeer(stream, emptySink(), () => NOW, {
    ledger,
    timers: { setInterval: () => 'handle', clearInterval: () => undefined },
  });
  stream.feed(greeting());
  stream.feed(
    wireFrame(
      encodeMessage({
        t: 'EQUIVOCATION',
        a: signedRegistration({ label: 'victimsname', owner: OWNER_A, secret: SECRET_B, txt: '1' }),
        b: signedRegistration({ label: 'victimsname', owner: OWNER_A, secret: SECRET_B, txt: '2' }),
      }),
    ),
  );
  assert.equal(outcome.equivocations, 0, 'the session refuses it');
  assert.equal(ledger.size, 0, 'so there is nothing for the ledger to refuse');
});
