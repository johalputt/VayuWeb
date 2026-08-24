import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { fromHex, toHex } from './vectors.ts';
import { verify, predecessorFrom, type RegistryView, type Verdict } from './verify.ts';
import { parseRecordBytes } from './record.ts';
import { recordHashFromBytes } from './domain.ts';
import { requiredBits, verifyPow } from './pow.ts';

/**
 * The golden fixtures BUILT BY THE RUST CLIENT, verified here by the reference implementation.
 *
 * Every case in `conformance/client-built.json` was produced by
 * `client/src/bin/write-fixtures.rs`: real keys from fixed seeds, a deterministic nonce walk at
 * the schedule the specification requires, canonical CBOR throughout. This file runs each byte
 * sequence through `verify()` exactly as an independent peer would — bytes in, verdict out,
 * registry state supplied per name. If the Rust builder and this implementation ever disagree
 * about what a record is, the disagreement lands here as a failing test rather than on the
 * network as two halves that cannot read each other.
 *
 * CI regenerates the artifact and fails on any diff, so drift between regenerations is itself
 * a signal: the builder is supposed to be a pure function of its fixed inputs.
 */

const ARTIFACT = fileURLToPath(new URL('../../conformance/client-built.json', import.meta.url));

interface ClientBuiltCase {
  description: string;
  op: string;
  name: string;
  tld: string;
  seq: number;
  notBefore: number;
  notAfter: number;
  claimedBits: number | null;
  transferorKey: string | null;
  bytes: string;
  hash: string;
}

const artifact = JSON.parse(readFileSync(ARTIFACT, 'utf8')) as {
  cases: ClientBuiltCase[];
};

/**
 * The trailing-window count the fixture generator assumed, per operation. The RENEW case was
 * built with the window at twice the rate floor — the first rung where the rate term
 * contributes a bit — so its proof carries base+1 bits; everything else assumes an empty
 * window. A view must answer with the SAME numbers the builder assumed or the difficulty
 * checks disagree for reasons that have nothing to do with interoperability.
 */
const windowCountFor = (op: string): number => (op === 'RENEW' ? 1024 : 0);

test('every client-built fixture verifies under the reference implementation', () => {
  const current = new Map<string, ReturnType<typeof predecessorFrom>>();
  const transferors = new Map<string, Uint8Array>();
  const revokedNames = new Set<string>();

  const failures: string[] = [];
  for (const [index, fixture] of artifact.cases.entries()) {
    const label = `case ${index} (${fixture.op} ${fixture.name}.${fixture.tld}): ${fixture.description}`;
    const bytes = fromHex(fixture.bytes);
    const key = `${fixture.name}.${fixture.tld}`;

    const previous = current.get(key) ?? null;
    const view: RegistryView = {
      current: () => previous,
      fullyReleased: () => false,
      revoked: (_name: string, _tld: string) => revokedNames.has(key),
      // Always false: force the REAL Argon2id evaluation rather than trusting a cached
      // verdict. Five proofs across ten cases cost under a second and are the point.
      powVerified: (record) =>
        verifyPow(record.map, requiredBits(record.name.length, windowCountFor(record.op))).ok,
    };

    let verdict: Verdict;
    try {
      verdict = verify(bytes, view, fixture.notBefore);
    } catch (error) {
      failures.push(`${label} threw: ${error instanceof Error ? error.message : error}`);
      continue;
    }
    if (verdict.outcome !== 'accept') {
      failures.push(`${label} -> ${verdict.outcome}: ${JSON.stringify(verdict)}`);
      continue;
    }

    // The record_hash the client computed must match this implementation byte for byte: it is
    // the convergence tie-break, and two implementations hashing differently would split the
    // log while every individual signature still verified.
    if (toHex(recordHashFromBytes(bytes)) !== fixture.hash.toLowerCase()) {
      failures.push(`${label}: record_hash mismatch`);
    }

    // Metadata cross-checks: the artifact's plain-text claims must match the parsed record, so
    // a regeneration bug cannot hide behind a verdict that accepts whatever arrived.
    const parsed = parseRecordBytes(bytes);
    if (parsed.op !== fixture.op || parsed.seq !== fixture.seq) {
      failures.push(`${label}: op/seq mismatch with metadata`);
    }
    if (parsed.notBefore !== fixture.notBefore || parsed.notAfter !== fixture.notAfter) {
      failures.push(`${label}: term mismatch with metadata`);
    }
    const claimed = parsed.powProof === null ? null : parsed.powProof.bits;
    if (claimed !== fixture.claimedBits) {
      failures.push(`${label}: claimedBits mismatch (${claimed} vs ${fixture.claimedBits})`);
    }

    // Index the accepted record for the next case in this chain.
    const transferor = fixture.transferorKey === null ? undefined : fromHex(fixture.transferorKey);
    current.set(key, predecessorFrom(parsed, bytes, transferor));
    if (transferor !== undefined) transferors.set(key, transferor);
    if (parsed.op === 'REVOKE') revokedNames.add(key);
  }
  assert.deepEqual(failures, []);
});

test('a corrupted fixture signature does NOT verify — the check is real', () => {
  const first = artifact.cases[0];
  const bytes = fromHex(first.bytes);
  bytes[bytes.length - 1] ^= 0x01;

  const view: RegistryView = {
    current: () => null,
    fullyReleased: () => false,
    revoked: () => false,
    powVerified: () => true, // isolate the signature check from the work check
  };
  const verdict = verify(bytes, view, first.notBefore);
  assert.equal(verdict.outcome, 'reject');
});
