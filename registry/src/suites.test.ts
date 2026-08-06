import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { SUITES, LAUNCH_SUITE, suiteOf, activeSuites, MAX_ACTIVE_RECORD_BYTES } from './suites.ts';

const spec = (name: string): string =>
  readFileSync(new URL(`../../docs/spec/${name}`, import.meta.url), 'utf8');

/* -------------------------------------------------------------------------- */
/* AUDIT FINDING: the agility mechanism had no field to read                   */
/* -------------------------------------------------------------------------- */

test('AUDIT: every record carries the suite that produced it', () => {
  // CRYPTO-AGILITY.md section 1: "No primitive is named in the protocol. Only suites are, and
  // every signed object carries the identifier of the suite that produced it." Section 4.2
  // requires an unknown suite to be REJECTED; 5.1 requires a name's suite to move forward only;
  // conformance items 2, 3, 6 and 7 each test the field. None of it was implementable: the
  // record schema had no suite field at all, and pinned `ownerKey` to 32 bytes and `sig` to 64 —
  // "an implementation that assumes 64-byte signatures anywhere is defective", by that
  // document's own rule.
  //
  // This is the one property the document says cannot be retrofitted: "a record format without
  // a suite identifier is a record format that can never migrate."
  assert.equal(SUITES.get(LAUNCH_SUITE)?.signature, 'Ed25519');
  assert.match(spec('REGISTRY.md'), /\| `suite` \| uint \|/);
});

test('AUDIT: only suite 1 is active, and the reserved ones are not usable by accident', () => {
  // 3.1: "Suites 2, 3 and 4 are reserved, not active." A reserved suite that a record could
  // name would be an unimplemented signature scheme accepted as valid.
  assert.deepEqual(
    [...activeSuites()].map((s) => s.id),
    [1],
  );
  for (const id of [2, 3, 4]) {
    assert.equal(SUITES.get(id)?.active, false, `suite ${id} must be reserved, not active`);
  }
  assert.equal(suiteOf(0), null);
  assert.equal(suiteOf(5), null);
  assert.equal(suiteOf(1.5), null);
});

test('AUDIT: the record size limit is per suite, not one global constant', () => {
  // 3.2: "The record size limits in REGISTRY.md MUST therefore be expressed per suite, not as
  // one global constant." A flat 4096 makes migration to ML-DSA-65 — 1,952-byte keys and
  // 3,309-byte signatures — impossible without changing the constant that every deployed
  // verifier already enforces, which is the retrofit the document says cannot be done.
  const launch = SUITES.get(LAUNCH_SUITE)!;
  assert.equal(launch.maxRecordBytes, 4096);
  for (const id of [3, 4]) {
    assert.ok(
      SUITES.get(id)!.maxRecordBytes > launch.maxRecordBytes,
      `suite ${id} needs more room than suite 1, or the migration cannot happen`,
    );
  }
  // The pre-decode bound cannot know the suite, so it must admit the largest ACTIVE suite and
  // no more. Sizing it to the largest reserved suite would hand an attacker a free 20 KiB of
  // parsing per record for a suite nothing can sign with.
  assert.equal(MAX_ACTIVE_RECORD_BYTES, launch.maxRecordBytes);
});

test('AUDIT: no key or signature length is assumed outside the suite table', () => {
  // Conformance item 7: "No code path assumes a 32-byte key or a 64-byte signature." The table
  // is what a verifier consults; the point of this assertion is that the numbers differ between
  // suites, so a hard-coded 32/64 anywhere is a bug the table would expose.
  const launch = SUITES.get(LAUNCH_SUITE)!;
  assert.equal(launch.publicKeyLength, 32);
  assert.equal(launch.signatureLength, 64);
  assert.equal(SUITES.get(3)!.publicKeyLength, 1952);
  assert.equal(SUITES.get(3)!.signatureLength, 3309);
  assert.equal(SUITES.get(4)!.signatureLength, 7856);
});

test('AUDIT: the suite table and CRYPTO-AGILITY.md state the same sizes', () => {
  // 3.2 states these figures in prose and section 3 restates them in a table. A table in code
  // and a table in a document that drift apart are worse than either alone, because each looks
  // authoritative — so every row is compared, not just the prose.
  const text = spec('CRYPTO-AGILITY.md');
  assert.match(text, /ML-DSA-65 is roughly 1,952 and 3,309/);
  assert.match(text, /SLH-DSA-SHAKE-128s is 32 and about\s+7,856/);

  const group = (n: number) => n.toLocaleString('en-US');
  for (const suite of SUITES.values()) {
    const row = new RegExp(
      `^\\| ${suite.id} \\|[^|]+\\| ${suite.hash} \\| ` +
        `${group(suite.publicKeyLength)} / ${group(suite.signatureLength)} \\| ` +
        `${group(suite.maxRecordBytes)} \\|`,
      'm',
    );
    assert.match(text, row, `suite ${suite.id}'s row must match the table in code`);
  }

  // Suite 1's record hash is BLAKE2b-256, not SHA-256. The document said SHA-256 against
  // REGISTRY.md, the vectors and every implementation; this pins the corrected value on both
  // sides so it cannot drift back.
  assert.equal(SUITES.get(1)!.hash, 'BLAKE2b-256');
  assert.match(spec('REGISTRY.md'), /BLAKE2b-256\s+is chosen because Hypercore already uses it/);
});
