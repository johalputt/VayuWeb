/**
 * The other half of PUBLISHING.md 3.1.6's "one shared definition".
 *
 * `conformance/rules.json` is generated from the desktop checker's RULES table by
 * `write-fixtures.rs`; CI regenerates it and fails on any drift, so what this test reads is
 * guaranteed to be what the Rust checker compiles against TODAY. What this file adds on top:
 * an independent statement of WHICH rules exist, written from this side of the protocol. A
 * rule added or removed without updating the EXPECTED_IDS set here fails both halves of CI --
 * which is the point. Cross-language agreement nobody enforces is a hope, not a property.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const artifact = JSON.parse(readFileSync(`${here}/../../conformance/rules.json`, 'utf8'));

/** The rule set as THIS implementation understands the specification, in artifact order. */
const EXPECTED_IDS = [
  // PUBLISHING.md section 3.1, the authoring restrictions.
  'inline-style',
  'inline-script',
  'remote-subresource',
  'external-link',
  'data-image',
  'base-tag',
  'iframe',
  'form-remote-action',
  'speculative-link',
  'meta-referrer',
  'meta-refresh',
  'wasm-undeclared',
  'service-worker',
  'missing-index',
  // The size ladder, whose severities come from HOSTING.md's guidance.
  'site-size-refuse',
  'site-size-confirm',
  'site-size-warn',
  'entry-count',
  'file-size-refuse',
  'file-size-warn',
  // The manifest itself is part of what the checker vouches for.
  'manifest-invalid',
];

test('the shared definition exists and names exactly the rules both sides agree on', () => {
  assert.ok(Array.isArray(artifact.rules), 'rules.json carries a rules array');
  const ids = artifact.rules.map((rule: { id: string }) => rule.id);
  assert.deepEqual(ids, EXPECTED_IDS);
});

test('every rule states its what, why and fix -- a message without a remedy is a defect', () => {
  for (const rule of artifact.rules) {
    for (const field of ['id', 'what', 'why', 'fix'] as const) {
      assert.equal(typeof rule[field], 'string', `${rule.id}: ${field} is a string`);
      assert.ok(rule[field].length > 0, `${rule.id}: ${field} is non-empty`);
    }
    // The fix sentences end with a period: they are sentences, addressed to a person.
    assert.ok(rule.fix.trimEnd().endsWith('.'), `${rule.id}: fix reads as a sentence`);
  }
});

test('ids are stable kebab-case tokens fit to compile against', () => {
  for (const rule of artifact.rules) {
    assert.match(rule.id, /^[a-z][a-z0-9-]*$/, `${rule.id}: kebab-case`);
  }
});
