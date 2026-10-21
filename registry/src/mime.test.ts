/**
 * The content-type table, held to the conformance suite.
 *
 * The table is wire-visible on every request: a browser refuses a stylesheet, a font or a module
 * script whose type it does not recognise, and `x-content-type-options: nosniff` means it does
 * not guess. The browsing proxy's table had nine extensions and the client's serving surface had
 * twenty-eight, so a site published with a webfont or a `.mjs` module rendered in one surface and
 * not in the other.
 *
 * The `mime` suite states the table, and this file checks the implementation against it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { contentTypeOf, DEFAULT_CONTENT_TYPE, MIME_TYPES } from './mime.ts';

const here = fileURLToPath(new URL('.', import.meta.url));
const vectors = JSON.parse(readFileSync(`${here}/../../conformance/vectors.json`, 'utf8')) as {
  mime: { name: string; path: string; expect: string }[];
};

test('every mime vector answers with the type it names', () => {
  assert.ok(vectors.mime.length > 0, 'the suite is not empty');
  for (const vector of vectors.mime) {
    assert.equal(contentTypeOf(vector.path), vector.expect, vector.name);
  }
});

test('the table carries no extension the suite does not state', () => {
  // An extension in the table and not in the suite is an extension nobody has pinned, and the
  // suite is the thing that stops the two implementations drifting apart.
  const stated = new Set(
    vectors.mime
      .map((vector) => vector.path.slice(vector.path.lastIndexOf('.') + 1).toLowerCase())
      .filter((extension) => extension !== ''),
  );
  for (const extension of Object.keys(MIME_TYPES)) {
    assert.ok(stated.has(extension), `${extension} is in the table and not in the suite`);
  }
});

test('the types a browser refuses without are not served as bytes', () => {
  // The three that broke a site, stated as themselves rather than as a table dump: a stylesheet,
  // a font and a module script are all refused by a browser served as octet-stream.
  for (const [path, expected] of [
    ['/site.css', 'text/css; charset=utf-8'],
    ['/font.woff2', 'font/woff2'],
    ['/app.mjs', 'text/javascript; charset=utf-8'],
    ['/video.mp4', 'video/mp4'],
    ['/icon.avif', 'image/avif'],
  ] as const) {
    assert.equal(contentTypeOf(path), expected, path);
  }
});

test('a path with no extension, or an unknown one, is served as bytes', () => {
  // The list is closed. Sniffing a type from the bytes is how a resolver serves
  // attacker-chosen content as script, and `nosniff` is on every response.
  assert.equal(contentTypeOf('/LICENSE'), DEFAULT_CONTENT_TYPE);
  assert.equal(contentTypeOf('/assets/file.unknownext'), DEFAULT_CONTENT_TYPE);
  assert.equal(contentTypeOf('/assets/archive.tar.gz'), DEFAULT_CONTENT_TYPE);
});

test('the extension is the one after the last dot, in lower case', () => {
  assert.equal(contentTypeOf('/assets/FILE.CSS'), 'text/css; charset=utf-8');
  assert.equal(contentTypeOf('/assets/app.min.js'), 'text/javascript; charset=utf-8');
  // A dot in a directory name is not an extension: the last dot is what counts.
  assert.equal(contentTypeOf('/v1.2/app'), DEFAULT_CONTENT_TYPE);
});
