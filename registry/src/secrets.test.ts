/**
 * PRIVACY.md section 7's test, made executable.
 *
 * PRIVACY.md section 7 ends with a requirement, not a wish: "An error message that includes a key
 * is a disclosure. The implementation MUST carry a test that formats every error type with secret
 * material present and asserts none of it appears in the output."
 *
 * The phrase that matters is **with secret material present**. A test that formats an error built
 * from harmless strings asserts nothing about the property: the error would print them, and the
 * test would pass, whether the code was careful or not. The secret has to be in scope while the
 * error is made, and then the output is searched for it.
 *
 * **What this file covers, and what it does not.** It covers the boundaries in this
 * implementation where a secret is actually in scope: the control API's token, and the content
 * cache's key. It does not claim that every string in every message is safe — a message that
 * echoes a publisher's own file path is not a disclosure, and the secret this test searches for is
 * the system's, not the publisher's.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { PinSet, report } from './pins.ts';
import { ResolutionCache } from './cache.ts';

import {
  CONTROL_HEADER,
  TOKEN_BYTES,
  handleControlRequest,
  type ControlPorts,
  type ControlRequest,
} from './control.ts';

/**
 * A secret that is recognisable when it appears.
 *
 * It is a real token's shape — TOKEN_BYTES of base64url — because a check that only recognises a
 * secret of a convenient length would not have caught a leak of the real one. And it is a
 * DIFFERENT secret from the one the API is holding, so a refusal that echoed the token it was
 * issued would be caught too.
 */
const SECRET = randomBytes(TOKEN_BYTES).toString('base64url');
const OTHER = randomBytes(TOKEN_BYTES).toString('base64url');

/** The cache's key, in the place the configuration keeps it. */
const CACHE_KEY = 'cache-key-that-must-never-be-printed';

const ports = (): ControlPorts => {
  let diagnostics = false;
  const pinned = new PinSet((cid) => cid === HELD_CID);
  const cache = new ResolutionCache({});
  return {
    status: () => ({ mode: 'clearnet', uptime: 42, listeners: ['proxy'] }),
    version: () => '0.2.0-test',
    logHead: () => ({ length: 7, root: 'aa'.repeat(32) }),
    config: () => ({
      mode: 'clearnet',
      tokenPath: '/home/reader/.config/vayuweb/token',
      cache: { entries: 512, secretKey: CACHE_KEY },
      cacheSizes: cache.limits,
    }),
    diagnostics: () => diagnostics,
    setDiagnostics: (on: boolean) => {
      diagnostics = on;
    },
    pins: () =>
      pinned
        .list()
        .map((cid) => report(cid, 0, [{ holder: { kind: 'self' }, observedAt: 1 }], 300, 1)),
    resolve: (label, tld) => ({
      outcome: 'error',
      error: 'NAME_NOT_FOUND',
      asked: `${label}/${tld}`,
    }),
    cacheStats: () => ({ negative: 1, positive: 2, manifests: 3, hits: 4, misses: 5 }),
    flushCache: (name) => (name === null ? 6 : 1),
    peers: () => ({ joined: false, peers: 0, detail: 'not joined' }),
    pin: (cid) => pinned.add(cid),
    unpin: (cid) => pinned.remove(cid),
    rotateToken: () => randomBytes(TOKEN_BYTES).toString('base64url'),
    patchCacheSizes: (sizes) => {
      cache.setLimits(sizes);
      return { mode: 'clearnet', cacheSizes: cache.limits };
    },
  };
};

/** Every route the control API answers, with the method that reaches it. */
const ROUTES: ReadonlyArray<readonly [string, string]> = [
  ['GET', '/v1/status'],
  ['GET', '/v1/config'],
  ['GET', '/v1/records/atlasobservatory.vayu'],
  ['GET', '/v1/pins'],
  ['DELETE', '/v1/pins/bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku'],
  ['GET', '/v1/cache/stats'],
  ['DELETE', '/v1/cache'],
  ['DELETE', '/v1/cache/atlasobservatory.vayu'],
  ['GET', '/v1/peers'],
  ['GET', '/v1/evidence'],
  ['GET', '/v1/names'],
  ['POST', '/v1/config'],
  ['GET', '/v1/nothing-here'],
];

const HELD_CID = 'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku';

function request(
  method: string,
  path: string,
  token: string,
  body = new Uint8Array(0),
): ControlRequest {
  return {
    method,
    path,
    headers: new Map([
      [CONTROL_HEADER, '1'],
      ['authorization', `Bearer ${token}`],
    ]),
    body,
  };
}

/** Everything an answer can carry, as one searchable string. */
function rendered(answer: { status: number; body: unknown; headers?: unknown }): string {
  return [
    String(answer.status),
    JSON.stringify(answer.body ?? null),
    JSON.stringify(answer.headers ?? null),
  ].join('\n');
}

test('no refusal the control API produces carries the token that was presented', () => {
  // The token is the secret in scope here: the API holds one, and every request presents another.
  // A refusal that echoed what it was refused for would put a working token into whatever the
  // caller does with the answer -- a log, a screenshot, a support ticket.
  for (const [method, path] of ROUTES) {
    const answered = handleControlRequest(request(method, path, SECRET), ports(), OTHER);
    assert.equal(answered.status, 401, `${method} ${path} must be refused`);
    assert.ok(
      !rendered(answered).includes(SECRET),
      `${method} ${path} echoed the token it refused:\n${rendered(answered)}`,
    );
  }
});

test('a truncated, over-long or absent token is refused without being printed', () => {
  // The same property for the shapes a token can arrive in. The API compares in constant time
  // and answers a wrong length without comparing, so a length mistake must not become a print.
  const presented = [SECRET.slice(0, 10), `${SECRET}extra`, '', 'not base64 at all !!'];
  for (const token of presented) {
    const answered = handleControlRequest(request('GET', '/v1/status', token), ports(), OTHER);
    assert.equal(answered.status, 401);
    assert.ok(
      !rendered(answered).includes(token) || token.length === 0,
      `a refusal echoed the token it refused:\n${rendered(answered)}`,
    );
  }
});

test('the cache key never reaches an answer, on any route that reports configuration', () => {
  // The content-cache key is the other secret this implementation holds. The configuration dump
  // redacts it by field name; the point of this test is that the redaction is not the only thing
  // keeping it out, and that a route nobody thought of does not become a way to read it.
  for (const [method, path] of ROUTES) {
    const answered = handleControlRequest(request(method, path, OTHER), ports(), OTHER);
    assert.ok(
      !rendered(answered).includes(CACHE_KEY),
      `${method} ${path} carried the cache key:\n${rendered(answered)}`,
    );
  }
});

test('a body that carries a secret does not have it echoed back', () => {
  // A caller that puts a secret in a body is doing something wrong, and the answer must not
  // make it worse by reflecting it.
  const answered = handleControlRequest(
    request(
      'POST',
      '/v1/config',
      OTHER,
      new TextEncoder().encode(JSON.stringify({ secretKey: SECRET })),
    ),
    ports(),
    OTHER,
  );
  assert.ok(
    !rendered(answered).includes(SECRET),
    `the answer echoed the body it refused:\n${rendered(answered)}`,
  );
});
