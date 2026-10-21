/**
 * The scanner, held to the shared definition and to the conformance suite.
 *
 * `registry/src/scan.ts` is a second implementation of three rules whose first implementation is
 * the client's Rust checker. A second copy of a rule is a copy that drifts, and this file is
 * what makes it a checked copy: the rule text is compared against the shared definition, and
 * the detection is compared against the `scan` suite in `conformance/vectors.json`, which the
 * client answers too.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { SCAN_RULES, SPECULATIVE_RELS, scanDocument } from './scan.ts';

const here = fileURLToPath(new URL('.', import.meta.url));
const rules = JSON.parse(readFileSync(`${here}/../../conformance/rules.json`, 'utf8')) as {
  rules: { id: string; what: string; why: string; fix: string; enforcement: string }[];
};
const vectors = JSON.parse(readFileSync(`${here}/../../conformance/vectors.json`, 'utf8')) as {
  scan: { name: string; path: string; content: string; expect: string[] }[];
};

const bytes = (text: string): Uint8Array => new TextEncoder().encode(text);

test('the scan class is exactly the rules this scanner implements', () => {
  // The shared definition says which rules a serving surface owes an enforcement for. A rule
  // added to the scan class without an implementation here fails this test rather than being
  // quietly unenforced.
  const scanClass = rules.rules
    .filter((rule) => rule.enforcement === 'scan')
    .map((rule) => rule.id);
  assert.deepEqual(
    scanClass,
    SCAN_RULES.map((rule) => rule.id),
  );
});

test("every scan rule carries the definition's own text, word for word", () => {
  // A copy of the message text, held to the definition. A refusal that explains a different
  // rule than the one it refuses is a refusal nobody can act on.
  for (const rule of SCAN_RULES) {
    const defined = rules.rules.find((candidate) => candidate.id === rule.id);
    assert.ok(defined, `${rule.id} is in the shared definition`);
    assert.equal(rule.what, defined.what, `${rule.id}: what`);
    assert.equal(rule.why, defined.why, `${rule.id}: why`);
    assert.equal(rule.fix, defined.fix, `${rule.id}: fix`);
  }
});

test('the speculative values are the six the specification names', () => {
  assert.deepEqual(
    [...SPECULATIVE_RELS],
    ['dns-prefetch', 'preconnect', 'prefetch', 'preload', 'prerender', 'modulepreload'],
  );
});

test('every scan vector finds exactly the rules it names', () => {
  assert.ok(vectors.scan.length > 0, 'the suite is not empty');
  for (const vector of vectors.scan) {
    const found = scanDocument(vector.path, bytes(vector.content)).map((finding) => finding.rule);
    assert.deepEqual(found, [...vector.expect], `${vector.name}`);
  }
});

test('a finding names the file, the line, the rule and the remedy', () => {
  // PUBLISHING.md 3.1.1: every diagnostic names the file, the line, what will not work, why, and
  // a concrete fix. A finding without a remedy is a defect in the checker.
  const findings = scanDocument(
    'index.html',
    bytes(
      '<!doctype html>\n<html>\n<head>\n<link rel="preload" href="/app.js">\n</head>\n</html>\n',
    ),
  );
  assert.equal(findings.length, 1);
  const finding = findings[0]!;
  assert.equal(finding.rule, 'speculative-link');
  assert.equal(finding.file, 'index.html');
  assert.equal(finding.line, 4);
  assert.ok(finding.what.length > 0);
  assert.ok(finding.why.length > 0);
  assert.ok(finding.fix.endsWith('.'), 'the fix reads as a sentence');
});

test('a document with no extension is not a document, and carries no obligation', () => {
  // The extension is what selects how the bytes are read, and it is what the client's checker
  // selects too. A path with neither extension is served as bytes, which a browser downloads
  // rather than renders.
  assert.deepEqual(scanDocument('notes.txt', bytes('<link rel="preload" href="/a.js">')), []);
});

test('a script beside a document is scanned as script, not as markup', () => {
  // The service-worker rule lives in the script, not in the page: a page is served and the
  // script beside it is not.
  const findings = scanDocument('app.js', bytes("navigator.serviceWorker.register('/sw.js');"));
  assert.deepEqual(
    findings.map((finding) => finding.rule),
    ['service-worker'],
  );
  assert.equal(findings[0]!.line, 1);
});

test('the scanner reports a violation once, and a clean document not at all', () => {
  assert.deepEqual(scanDocument('index.html', bytes('<p>hello</p>')), []);
  const twice = scanDocument(
    'index.html',
    bytes('<link rel="preload" href="/a.js"><link rel="prefetch" href="/b.js">'),
  );
  assert.equal(twice.length, 2);
});
