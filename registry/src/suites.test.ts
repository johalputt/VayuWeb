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

test('AUDIT: each reserved record limit is the number its own stated derivation produces', () => {
  // REGISTRY.md gives the rule and then tells the reader not to check it: the reserved limits are
  // "suite 1's non-signature content plus that suite's own key and signature material, rounded to
  // a whole number of KiB", followed by **"They are not extra room."**
  //
  // They were extra room. Suite 1's non-signature content is 4,096 - 96 = 4,000 bytes, so suite 4
  // needs 4,000 + 32 + 7,856 = 11,888 -> 12 KiB, and it carried 16,384 — 4,096 bytes of slack,
  // more than an entire suite-1 record. Suites 2 and 3 each carried 2,048.
  //
  // This is the pre-decode bound on untrusted input, so the slack is not cosmetic: on the day the
  // break-glass suite activates, every verifier would parse a third more attacker-supplied bytes
  // per record than the derivation justifies, forever, with no VWIP having decided it. The old
  // test only asserted each reserved limit exceeded 4,096, so nothing derived them from the rule.
  //
  // "They are not extra room" is the sentence that tells a reviewer not to check, and it is the
  // one that was false. That pairing is worth more than the arithmetic.
  const launch = SUITES.get(1)!;
  const nonSignatureContent =
    launch.maxRecordBytes - launch.publicKeyLength - launch.signatureLength;
  assert.equal(nonSignatureContent, 4000);

  const failures: string[] = [];
  for (const [id, suite] of SUITES) {
    if (id === 1) continue;
    const needed = nonSignatureContent + suite.publicKeyLength + suite.signatureLength;
    const derived = Math.ceil(needed / 1024) * 1024;
    if (suite.maxRecordBytes !== derived) {
      failures.push(
        `suite ${id}: needs ${needed} -> ${derived}, carries ${suite.maxRecordBytes} ` +
          `(${suite.maxRecordBytes - derived} bytes of slack)`,
      );
    }
  }
  assert.deepEqual(failures, []);
});

test('the parsing-work factor REGISTRY.md quotes is the one the limits produce', () => {
  // "Sizing the outer bound to the largest reserved suite instead would hand an attacker four
  // times the parsing work per record." Four was 16,384/4,096 — true of the inflated value and
  // not of the derivation, so correcting the limits silently made an adjacent claim wrong. A
  // number stated beside a number that changed is the one that goes stale unnoticed.
  const largestReserved = Math.max(
    ...[...SUITES.entries()].filter(([id]) => id !== 1).map(([, s]) => s.maxRecordBytes),
  );
  const factor = largestReserved / SUITES.get(1)!.maxRecordBytes;
  const spec = readFileSync(new URL('../../docs/spec/REGISTRY.md', import.meta.url), 'utf8');
  const stated = /would hand an attacker ([a-z]+)\n?\s*times the parsing work/.exec(spec);
  assert.ok(stated, 'REGISTRY.md must state the parsing-work factor');
  const words: Record<string, number> = { two: 2, three: 3, four: 4, five: 5 };
  assert.equal(words[stated[1]!], factor);
});
