/**
 * The path mapping, held to the conformance suite.
 *
 * RESOLUTION.md step 13 is the rule a reader feels: the path they asked for is the page they get,
 * or the site's own 404 page, or its own router's shell. Two serving surfaces in this project
 * implemented it differently — the proxy used the manifest's declared `index` only for the paths
 * written with a trailing slash, and the client's serving surface used it for both — so a site
 * that declared `"index": "home.html"` and published a `/docs/` directory served `/docs/` and
 * 404'd `/docs`, and which one a reader got depended on which surface they were using.
 *
 * The `paths` suite in `conformance/vectors.json` states the mapping, and this file checks the
 * proxy against it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { serveStep13, type ContentPort } from './proxy.ts';
import { ResolutionCache } from './cache.ts';

const here = fileURLToPath(new URL('.', import.meta.url));
const vectors = JSON.parse(readFileSync(`${here}/../../conformance/vectors.json`, 'utf8')) as {
  paths: {
    name: string;
    request: string;
    files: { path: string; content: string }[];
    expect: { status: number; path: string | null };
  }[];
};

/** A content port over a tree of files, as a published site would be. */
function portOver(files: { path: string; content: string }[]): ContentPort {
  const tree = new Map(files.map((file) => [file.path, file.content]));
  return {
    fetch: (_chosen, at) => {
      const path = at.startsWith('/') ? at.slice(1) : at;
      const content = tree.get(path);
      if (content === undefined) return { ok: false, error: 'PATH_NOT_FOUND' };
      return {
        ok: true,
        bytes: new TextEncoder().encode(content),
        contentType: 'text/html; charset=utf-8',
      };
    },
  };
}

test('every path vector answers with the file it names', () => {
  assert.ok(vectors.paths.length > 0, 'the suite is not empty');
  for (const vector of vectors.paths) {
    const cache = new ResolutionCache();
    const answered = serveStep13(portOver(vector.files), 'cid', vector.request, cache);
    if (!answered.ok) {
      assert.equal(
        vector.expect.path,
        null,
        `${vector.name}: nothing answered, and the suite says ${String(vector.expect.path)}`,
      );
      continue;
    }
    // The proxy names the path it fetched with a leading slash; the suite names it the way the
    // tree does.
    const served = answered.path.startsWith('/') ? answered.path.slice(1) : answered.path;
    assert.equal(served, vector.expect.path, `${vector.name}: wrong file answered`);
    assert.equal(answered.status, vector.expect.status, `${vector.name}: wrong status`);
  }
});

test('a directory path answers alike with and without its trailing slash', () => {
  // The divergence this suite exists for, stated as itself rather than as a table lookup: the
  // proxy used to answer `/docs/` from the manifest's index and `/docs` from `index.html`.
  const files = [
    { path: 'home.html', content: 'ROOT-HOME' },
    { path: 'docs/home.html', content: 'DOCS-HOME' },
    { path: '.vayu/manifest.json', content: JSON.stringify({ version: 1, index: 'home.html' }) },
  ];
  const withSlash = serveStep13(portOver(files), 'cid', '/docs/', new ResolutionCache());
  const withoutSlash = serveStep13(portOver(files), 'cid', '/docs', new ResolutionCache());
  assert.ok(withSlash.ok && withoutSlash.ok, 'both forms answer');
  assert.equal(withSlash.path, withoutSlash.path, 'the two forms answer the same file');
  assert.equal(withoutSlash.path, '/docs/home.html');
});

test('a path that is a file is answered by that file', () => {
  const files = [
    { path: 'docs/home.html', content: 'DOCS-HOME' },
    { path: 'docs/index.html', content: 'DOCS-INDEX' },
    { path: '.vayu/manifest.json', content: JSON.stringify({ version: 1, index: 'home.html' }) },
  ];
  const answered = serveStep13(portOver(files), 'cid', '/docs/home.html', new ResolutionCache());
  assert.ok(answered.ok, 'the file answers');
  assert.equal(answered.path, '/docs/home.html');
});

test('a declared index that is not in the tree is discarded', () => {
  // The manifest declares intent; the tree says what exists. A declaration the tree does not
  // support is not an error and not a permission — it is discarded, and the next candidate
  // answers.
  const files = [
    { path: 'index.html', content: 'ROOT-INDEX' },
    { path: '.vayu/manifest.json', content: JSON.stringify({ version: 1, index: 'home.html' }) },
  ];
  const answered = serveStep13(portOver(files), 'cid', '/', new ResolutionCache());
  assert.ok(answered.ok, 'something answers');
  assert.equal(answered.path, '/index.html');
});

test('a miss is a miss, and the site’s own pages answer it', () => {
  const bare = serveStep13(
    portOver([{ path: 'index.html', content: 'ROOT-INDEX' }]),
    'cid',
    '/missing',
    new ResolutionCache(),
  );
  assert.equal(bare.ok, false, 'nothing answers a missing path');

  const withNotFound = serveStep13(
    portOver([
      { path: '404.html', content: 'NOT-FOUND' },
      {
        path: '.vayu/manifest.json',
        content: JSON.stringify({ version: 1, notFound: '404.html' }),
      },
    ]),
    'cid',
    '/missing',
    new ResolutionCache(),
  );
  assert.ok(withNotFound.ok, "the site's own 404 page answers");
  assert.equal(withNotFound.status, 404);
  assert.equal(withNotFound.path, '/404.html');

  const withFallback = serveStep13(
    portOver([
      { path: 'app.html', content: 'FALLBACK' },
      {
        path: '.vayu/manifest.json',
        content: JSON.stringify({ version: 1, fallback: 'app.html' }),
      },
    ]),
    'cid',
    '/missing',
    new ResolutionCache(),
  );
  assert.ok(withFallback.ok, "the site's own router shell answers");
  assert.equal(withFallback.status, 200);
  assert.equal(withFallback.path, '/app.html');
});
