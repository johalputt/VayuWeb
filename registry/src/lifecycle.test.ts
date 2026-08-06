import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  lifecycleOf,
  stateAt,
  isFullyReleased,
  acceptsSuccessor,
  resolves,
  GRACE_SECONDS,
  QUARANTINE_SECONDS,
} from './lifecycle.ts';
import { parseRecord } from './record.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH } from './pow.ts';
import { type CborMap, type CborValue } from './cbor.ts';

const NOW = 1_782_518_400;
const TERM = 31_536_000;

const pow = (): CborMap =>
  new Map<string | Uint8Array, CborValue>([
    ['alg', POW_ALGORITHM],
    ['nonce', new Uint8Array(POW_NONCE_LENGTH).fill(7)],
    ['bits', 10],
  ]);

function make(op: string, over: Record<string, CborValue> = {}) {
  const m = new Map<string | Uint8Array, CborValue>([
    ['version', 1],
    ['op', op],
    ['name', 'atlas'],
    ['tld', 'vayu'],
    ['ownerKey', new Uint8Array(32).fill(0x11)],
    ['seq', op === 'REGISTER' ? 0 : 1],
    ['notBefore', NOW],
    ['notAfter', NOW + TERM],
    ['records', op === 'REGISTER' ? [] : []],
    ['powProof', op === 'REGISTER' || op === 'RENEW' ? pow() : null],
    ['prevHash', op === 'REGISTER' ? new Uint8Array(32) : new Uint8Array(32).fill(1)],
    ['sig', new Uint8Array(64).fill(0xaa)],
  ]);
  for (const [k, v] of Object.entries(over)) m.set(k, v);
  return parseRecord(m);
}

const registration = () => make('REGISTER');

/* -------------------------------------------------------------------------- */

test('a registration runs live, then grace, then quarantine, then free', () => {
  const r = registration();
  const life = lifecycleOf(r);
  assert.equal(life.liveUntil, NOW + TERM);
  assert.equal(life.graceUntil, NOW + TERM + GRACE_SECONDS);
  assert.equal(life.quarantineUntil, NOW + TERM + GRACE_SECONDS + QUARANTINE_SECONDS);

  assert.equal(stateAt(r, NOW - 1), 'PENDING');
  assert.equal(stateAt(r, NOW), 'LIVE');
  assert.equal(stateAt(r, NOW + TERM - 1), 'LIVE');
  assert.equal(stateAt(r, NOW + TERM), 'GRACE');
  assert.equal(stateAt(r, life.graceUntil - 1), 'GRACE');
  assert.equal(stateAt(r, life.graceUntil), 'QUARANTINE');
  assert.equal(stateAt(r, life.quarantineUntil - 1), 'QUARANTINE');
  assert.equal(stateAt(r, life.quarantineUntil), 'FREE');
});

test('a name in grace no longer resolves but still accepts a renewal', () => {
  // These two must part company, or an expired registration keeps serving content to anyone
  // who never re-queried.
  const r = registration();
  const inGrace = NOW + TERM + 1;
  assert.equal(resolves(r, inGrace), false, 'an expired name must stop resolving');
  assert.equal(acceptsSuccessor(r, inGrace, 'RENEW'), true, 'the owner may still renew');
  assert.equal(acceptsSuccessor(r, inGrace, 'UPDATE'), false, 'but there is nothing to update');
});

test('past grace the name accepts nothing, so an expired holder cannot jump the queue', () => {
  const r = registration();
  const life = lifecycleOf(r);
  assert.equal(acceptsSuccessor(r, life.graceUntil, 'RENEW'), false);
  assert.equal(acceptsSuccessor(r, life.graceUntil + 1, 'RENEW'), false);
});

test('quarantine is not skippable, which is the point of it', () => {
  // Without quarantine, watching the log for expiries and registering the instant grace lapses
  // is a business. The name must be unavailable to EVERYONE for the full window.
  const r = registration();
  const life = lifecycleOf(r);
  assert.equal(isFullyReleased(r, life.graceUntil), false, 'free at grace end would be the bug');
  assert.equal(isFullyReleased(r, life.quarantineUntil - 1), false);
  assert.equal(isFullyReleased(r, life.quarantineUntil), true);
});

/* -------------------------------------------------------------------------- */
/* RELINQUISH                                                                     */
/* -------------------------------------------------------------------------- */

test('RELINQUISH skips grace but not quarantine', () => {
  const at = NOW + 600;
  const r = make('RELINQUISH', { notBefore: at, notAfter: at });
  const life = lifecycleOf(r);

  assert.equal(life.graceUntil, at, 'grace is skipped: the owner said they are done');
  assert.equal(life.quarantineUntil, at + QUARANTINE_SECONDS, 'quarantine still runs');

  assert.equal(stateAt(r, at), 'QUARANTINE');
  assert.equal(isFullyReleased(r, at), false);
  assert.equal(isFullyReleased(r, at + QUARANTINE_SECONDS - 1), false);
  assert.equal(isFullyReleased(r, at + QUARANTINE_SECONDS), true);
});

test('a released name stops resolving immediately', () => {
  const at = NOW + 600;
  const r = make('RELINQUISH', { notBefore: at, notAfter: at });
  assert.equal(resolves(r, at), false);
  assert.equal(acceptsSuccessor(r, at, 'RENEW'), false);
});

/* -------------------------------------------------------------------------- */
/* REVOKE                                                                      */
/* -------------------------------------------------------------------------- */

test('REVOKE stops resolution at once and freezes the name for the rest of its term', () => {
  const at = NOW + 600;
  const r = make('REVOKE', { notBefore: at, notAfter: NOW + TERM });
  const life = lifecycleOf(r);

  assert.equal(life.revoked, true);
  assert.equal(resolves(r, at), false, 'a revoked name stops resolving immediately');
  assert.equal(life.graceUntil, NOW + TERM, 'frozen for the remainder of the term');
  assert.equal(life.quarantineUntil, NOW + TERM + QUARANTINE_SECONDS);
});

test('a revoked name accepts nothing from anyone, including its owner', () => {
  // The deadman switch destroys rather than recovers. A registry with no identity layer cannot
  // tell an owner from a thief holding the same key, so "let the real owner back in" is not
  // available — and a rule that tried would be the thief's rule too.
  const at = NOW + 600;
  const r = make('REVOKE', { notBefore: at, notAfter: NOW + TERM });
  for (const when of [at, at + 1, NOW + TERM, NOW + TERM + QUARANTINE_SECONDS + 1]) {
    assert.equal(acceptsSuccessor(r, when, 'RENEW'), false, `at ${when}`);
  }
});

test('a revoked name is not freed early: freezing is what stops the watcher', () => {
  const at = NOW + 600;
  const r = make('REVOKE', { notBefore: at, notAfter: NOW + TERM });
  assert.equal(isFullyReleased(r, at), false, 'immediate release would hand it to a watcher');
  assert.equal(isFullyReleased(r, NOW + TERM), false, 'quarantine still follows the term');
  assert.equal(isFullyReleased(r, NOW + TERM + QUARANTINE_SECONDS), true);
});

/* -------------------------------------------------------------------------- */
/* Boundaries                                                                  */
/* -------------------------------------------------------------------------- */

test('every boundary is half-open, so no instant belongs to two states', () => {
  const r = registration();
  const life = lifecycleOf(r);
  const boundaries = [life.liveFrom, life.liveUntil, life.graceUntil, life.quarantineUntil];
  const states = boundaries.map((at) => stateAt(r, at));
  assert.deepEqual(states, ['LIVE', 'GRACE', 'QUARANTINE', 'FREE']);

  // And the instant before each boundary belongs to the previous state.
  assert.deepEqual(
    boundaries.map((at) => stateAt(r, at - 1)),
    ['PENDING', 'LIVE', 'GRACE', 'QUARANTINE'],
  );
});

test('the total unavailable window after expiry is 60 days', () => {
  const r = registration();
  const life = lifecycleOf(r);
  assert.equal(life.quarantineUntil - life.liveUntil, GRACE_SECONDS + QUARANTINE_SECONDS);
  assert.equal(life.quarantineUntil - life.liveUntil, 5_184_000);
});
