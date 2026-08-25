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

import { SECURITY_HEADERS } from './proxy.ts';

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

// ---------------------------------------------------------------------------
// 3.1.6's second half: the enforcement matrix. Each rule says HOW reading
// enforces it; these tests hold that claim against the REAL header constants
// the proxy emits -- so a header that drifts fails here even though the Rust
// source still matches itself perfectly.
// ---------------------------------------------------------------------------

const ENFORCEMENT_KINDS = ['csp', 'scan', 'advice', 'publish-check'] as const;

test('every rule declares a known enforcement mechanism', () => {
  for (const rule of artifact.rules) {
    assert.ok(
      (ENFORCEMENT_KINDS as readonly string[]).includes(rule.enforcement),
      `${rule.id}: enforcement must be one of ${ENFORCEMENT_KINDS.join(', ')}`,
    );
    assert.ok(Array.isArray(rule.evidence), `${rule.id}: evidence is an array`);
    assert.ok(Array.isArray(rule.absent), `${rule.id}: absent is an array`);
  }
});

test('csp-enforced rules cite substrings the proxy REALLY emits -- and nothing it does not', () => {
  const headerValue = (name: string): string => {
    const hit = SECURITY_HEADERS.find(([key]) => key === name);
    assert.ok(hit, `SECURITY_HEADERS carries ${name}`);
    return hit[1];
  };
  for (const rule of artifact.rules) {
    if (rule.enforcement !== 'csp') continue;
    assert.ok(rule.evidence.length > 0, `${rule.id}: a csp rule cites its evidence`);
    for (const { header, contains } of rule.evidence) {
      assert.ok(
        headerValue(header).includes(contains),
        `${rule.id}: ${header} must contain "${contains}" -- the rule's read-time enforcement depends on it`,
      );
    }
    for (const { header, omit } of rule.absent) {
      assert.ok(
        !headerValue(header).includes(omit),
        `${rule.id}: ${header} must NOT contain "${omit}" -- its presence would grant what this rule refuses`,
      );
    }
  }
});

test('scan-enforced rules are exactly the ones no header can express', () => {
  // Speculative DNS fires before any policy applies; meta refresh bypasses CSP entirely;
  // nothing in CSP stops a service worker. If the artifact ever marks one of these "csp",
  // or marks a genuinely header-blockable rule "scan", this set drifts and CI fails.
  assert.deepEqual(
    artifact.rules
      .filter((r: { enforcement: string }) => r.enforcement === 'scan')
      .map((r: { id: string }) => r.id),
    ['speculative-link', 'meta-refresh', 'service-worker'],
  );
});
