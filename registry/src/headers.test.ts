/**
 * The response header set, held to the conformance suite.
 *
 * CONTENT-SECURITY.md section 3 is a table of the headers that accompany a served document, and
 * each row says what it is for. Three of them are canonical blocks in the document itself; the
 * rest are named values.
 *
 * The two serving surfaces of this project sent different sets — the proxy sent all eleven, the
 * client's preview surface sent five, and its own module header claimed the set "from
 * CONTENT-SECURITY.md sections 2-3 verbatim". The suite states the whole set, so neither surface
 * can quietly drop one again: a header that is not sent is as much a divergence as one whose
 * value differs.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { SECURITY_HEADERS } from './proxy.ts';

const here = fileURLToPath(new URL('.', import.meta.url));
const vectors = JSON.parse(readFileSync(`${here}/../../conformance/vectors.json`, 'utf8')) as {
  headers: { name: string; expect: Record<string, string> }[];
};

test('every header vector is answered by exactly the header set it names', () => {
  assert.ok(vectors.headers.length > 0, 'the suite is not empty');
  for (const vector of vectors.headers) {
    const sent = new Map(SECURITY_HEADERS);
    // The whole map, both ways: a header the implementation sends and the suite does not name is
    // as much a divergence as one it does not send.
    assert.deepEqual(
      Object.fromEntries(sent),
      vector.expect,
      `${vector.name}: the header set differs from the suite`,
    );
  }
});

test('the headers a browser refuses without are among them', () => {
  // Stated as themselves rather than as a table dump: the three that changed what a reader's
  // browser did, and the one that stops a cross-origin probe.
  const sent = new Map(SECURITY_HEADERS);
  for (const [name, value] of [
    ['x-content-type-options', 'nosniff'],
    ['x-dns-prefetch-control', 'off'],
    ['cross-origin-resource-policy', 'same-origin'],
    ['cache-control', 'no-store'],
  ] as const) {
    assert.equal(sent.get(name), value, name);
  }
});
