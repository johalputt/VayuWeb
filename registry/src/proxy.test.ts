import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  DEFAULT_CSP,
  DIAGNOSTIC_HEADERS,
  FORBIDDEN_RESPONSE_HEADERS,
  NegativeCache,
  PROXY_LIMITS,
  SECURITY_HEADERS,
  handleRequest,
  normaliseHost,
  requestHost,
  type ProxyRequest,
} from './proxy.ts';
import { RESOLVE_ERRORS, type ResolverPorts } from './resolve.ts';
import type { RegistryRecord } from './record.ts';

const NOW = 1_782_518_400;

/** A resolver that knows one name and nothing else. */
function ports(known: RegistryRecord | null = null): ResolverPorts {
  return {
    lookup: () => known,
    hasVerifiedHead: () => true,
  };
}

function get(target: string, headers: Record<string, string> = {}): ProxyRequest {
  return { method: 'GET', target, headers: new Map(Object.entries(headers)) };
}

/* -------------------------------------------------------------------------- */
/* The policy is the specification's, not a paraphrase of it                   */
/* -------------------------------------------------------------------------- */

test('the emitted CSP is byte-identical to the canonical block in CONTENT-SECURITY.md', () => {
  // A second copy of a security policy is a copy that drifts, and this one is wire-visible: a
  // directive lost in transcription is a relaxation nobody chose. So the specification is read
  // back and compared rather than trusted to have been copied correctly.
  const spec = readFileSync(
    new URL('../../docs/spec/CONTENT-SECURITY.md', import.meta.url),
    'utf8',
  );
  const block = spec.split('<!-- canonical:content-security-policy -->')[1] ?? '';
  const fenced = block.split('```')[1] ?? '';
  const canonical = fenced
    .replace(/^text\n/, '')
    .trim()
    .replace(/^Content-Security-Policy:\s*/, '');

  assert.equal(DEFAULT_CSP, canonical);
});

test('every response carries the full accompanying header set', () => {
  const response = handleRequest(
    get('/', { host: 'atlas.vayu' }),
    ports(),
    new NegativeCache(),
    NOW,
  );
  for (const [name, value] of SECURITY_HEADERS) {
    assert.equal(response.headers.get(name), value, name);
  }
});

test('a refusal carries the same security headers as a success', () => {
  // Otherwise the header set itself distinguishes a VayuWeb refusal from an ordinary failure,
  // which is the fingerprint LOCAL-SURFACE.md 2.4 exists to prevent.
  const refused = handleRequest(
    get('/', { host: 'evil.example' }),
    ports(),
    new NegativeCache(),
    NOW,
  );
  for (const [name, value] of SECURITY_HEADERS) {
    assert.equal(refused.headers.get(name), value, name);
  }
});

test('no response may carry a header that brands the resolver or widens private access', () => {
  const cache = new NegativeCache();
  const responses = [
    handleRequest(get('/', { host: 'atlas.vayu' }), ports(), cache, NOW),
    handleRequest(get('/', { host: 'evil.example' }), ports(), cache, NOW),
    handleRequest(
      { method: 'CONNECT', target: '127.0.0.1:22', headers: new Map() },
      ports(),
      cache,
      NOW,
    ),
  ];
  for (const response of responses) {
    for (const forbidden of FORBIDDEN_RESPONSE_HEADERS) {
      assert.equal(response.headers.has(forbidden), false, forbidden);
    }
  }
});

/* -------------------------------------------------------------------------- */
/* LOCAL-SURFACE.md 2.1 — request shape, and the rebinding defence             */
/* -------------------------------------------------------------------------- */

test('I rebind my own hostname to 127.0.0.1 and reach your proxy', () => {
  // The attack, in the attacker's voice. I control `evil.example`. I set its TTL to one second,
  // answer with a real address once so your browser loads my page, then re-answer with 127.0.0.1.
  // Your browser now sends my page's requests to your loopback interface, believing it is still
  // talking to me, so same-origin policy does not protect you.
  //
  // What it cannot do is change the `Host` header. My page still says `Host: evil.example`,
  // because that is the origin it believes it is talking to — changing it would break the very
  // same-origin belief the attack depends on. So the defence is not to inspect the connection, it
  // is to refuse every host that is not a VayuWeb name, before routing.
  const cache = new NegativeCache();
  for (const host of [
    'evil.example',
    'localhost',
    '127.0.0.1',
    '[::1]',
    '192.168.1.1',
    'atlas.vayu:7654',
    'atlas.vayu.evil.example',
    '',
  ]) {
    const response = handleRequest(get('/', { host }), ports(), cache, NOW);
    // The exact refusal again: a host that is not a VayuWeb name is turned away by the proxy,
    // before routing. A 404 here would mean it HAD been routed and merely not found, which is a
    // different and much weaker property.
    assert.equal(
      response.status,
      RESOLVE_ERRORS.LABEL_INVALID.http,
      `${JSON.stringify(host)} must be refused before routing`,
    );
  }
});

test('a reserved label is refused at the proxy, which is where wpad would be fetched', () => {
  // The registry refusing `wpad.vayu` is necessary and not sufficient. The attack happens in a
  // browser: one configured to discover its proxy automatically fetches `wpad.<domain>/wpad.dat`
  // and runs the JavaScript it finds there to decide where every request goes. That fetch arrives
  // *here*, so this is the surface that has to refuse it — and it does so through the same
  // `labelRejection` the verifier uses, rather than through a second list that could drift.
  const cache = new NegativeCache();
  for (const host of [
    'wpad.vayu',
    'pac.vayu',
    'proxy.vayu',
    'api.vayu',
    'control.vayu',
    'vayu.vayu',
  ]) {
    const response = handleRequest(get('/', { host }), ports(), cache, NOW);
    assert.equal(response.status, RESOLVE_ERRORS.LABEL_INVALID.http, host);
  }
  // And an ordinary name still routes, so the refusal is about the label rather than about
  // everything.
  assert.equal(
    handleRequest(get('/', { host: 'atlas.vayu' }), ports(), cache, NOW).status,
    RESOLVE_ERRORS.NAME_NOT_FOUND.http,
  );
});

test('absolute-form takes its host from the target, never from a disagreeing Host header', () => {
  // A request carrying `http://a.vayu/` with `Host: b.vayu` is one two implementations would route
  // differently, and a proxy that consults whichever is more convenient is a proxy an attacker can
  // aim. The target wins, always.
  assert.equal(requestHost(get('http://atlas.vayu/', { host: 'other.vayu' })), 'atlas.vayu');
  assert.equal(requestHost(get('/page', { host: 'atlas.vayu' })), 'atlas.vayu');
});

test('userinfo in an absolute-form target is refused, not stripped', () => {
  // `http://atlas.vayu@evil.example/` is a host-confusion primitive: a reader sees the VayuWeb
  // name, the parser sees the authority after the `@`. Every reading that is not "refuse" has been
  // an exploit somewhere.
  assert.equal(requestHost(get('http://atlas.vayu@evil.example/')), null);
});

test('a non-http scheme is refused rather than upgraded', () => {
  // An https target would promise a transport guarantee this proxy does not provide, and
  // accepting it would let a page believe it had one.
  assert.equal(requestHost(get('https://atlas.vayu/')), null);
  assert.equal(requestHost(get('ftp://atlas.vayu/')), null);
  assert.equal(requestHost(get('file:///etc/passwd')), null);
});

test('a request target longer than the limit is refused before parsing', () => {
  assert.equal(requestHost(get(`http://atlas.vayu/${'a'.repeat(PROXY_LIMITS.targetBytes)}`)), null);
});

/* -------------------------------------------------------------------------- */
/* LOCAL-SURFACE.md 2.2 — CONNECT                                              */
/* -------------------------------------------------------------------------- */

test('CONNECT is refused for every destination, including VayuWeb ones', () => {
  // Not implemented at all, so there is no destination policy to get wrong. A proxy that will
  // CONNECT anywhere is an open relay and an SSRF pivot into the reader's own network, and the
  // safest implementation of a dangerous verb is none.
  const cache = new NegativeCache();
  for (const destination of [
    'atlas.vayu:443',
    '127.0.0.1:22',
    '169.254.169.254:80',
    '10.0.0.1:6379',
  ]) {
    const response = handleRequest(
      { method: 'CONNECT', target: destination, headers: new Map([['host', 'atlas.vayu']]) },
      ports(),
      cache,
      NOW,
    );
    // The EXACT refusal, not merely "not 200". An earlier version of this test asserted the
    // latter and passed with both method guards deleted, because the request then failed for an
    // unrelated reason — the name did not resolve. A test satisfied by any failure cannot tell
    // you which defence is standing.
    assert.equal(response.status, RESOLVE_ERRORS.BLOCKED_BY_POLICY.http, destination);
  }

  // The cases above are all authority-form targets, which the request-shape rule already refuses
  // for not being one of the two accepted shapes — so they cannot tell you whether the method
  // guard exists. This one can: an origin-form CONNECT with a valid VayuWeb Host passes the shape
  // rule and reaches the method check, so it is refused by that and nothing else.
  const shapedLikeAnOrdinaryRequest = handleRequest(
    { method: 'CONNECT', target: '/', headers: new Map([['host', 'atlas.vayu']]) },
    ports(),
    cache,
    NOW,
  );
  assert.equal(shapedLikeAnOrdinaryRequest.status, RESOLVE_ERRORS.BLOCKED_BY_POLICY.http);
  assert.notEqual(shapedLikeAnOrdinaryRequest.status, RESOLVE_ERRORS.NAME_NOT_FOUND.http);
});

test('methods that could mutate are refused', () => {
  const cache = new NegativeCache();
  for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']) {
    const response = handleRequest(
      { method, target: '/', headers: new Map([['host', 'atlas.vayu']]) },
      ports(),
      cache,
      NOW,
    );
    assert.equal(response.status, RESOLVE_ERRORS.BLOCKED_BY_POLICY.http, method);
    assert.notEqual(
      response.status,
      RESOLVE_ERRORS.NAME_NOT_FOUND.http,
      `${method} must be refused as a method, not because the name happens not to resolve`,
    );
  }
});

/* -------------------------------------------------------------------------- */
/* LOCAL-SURFACE.md 2.4 — the resolver does not announce itself                */
/* -------------------------------------------------------------------------- */

test('diagnostic headers are absent by default', () => {
  // "This person runs VayuWeb" may be the only fact an adversary in a hostile jurisdiction needs.
  // A header branding every response is disclosure, not diagnostics.
  const response = handleRequest(
    get('/', { host: 'atlas.vayu' }),
    ports(),
    new NegativeCache(),
    NOW,
  );
  for (const header of DIAGNOSTIC_HEADERS) {
    assert.equal(response.headers.has(header), false, header);
  }
});

test('a refusal body echoes nothing the caller supplied', () => {
  // Two reasons at once: an echoed name is the response-splitting and header-injection vector,
  // and an echoed VayuWeb error code confirms VayuWeb is running.
  const hostile = 'atlas\r\nX-Injected: 1.vayu';
  const response = handleRequest(get('/', { host: hostile }), ports(), new NegativeCache(), NOW);
  assert.equal(response.body, '');
  for (const [, value] of response.headers) {
    assert.equal(value.includes('X-Injected'), false);
    assert.equal(/[\r\n]/.test(value), false, 'no header value may carry CR or LF');
  }
});

/* -------------------------------------------------------------------------- */
/* LOCAL-SURFACE.md 3.1, 3.2 — validate first, key on the normalised tuple     */
/* -------------------------------------------------------------------------- */

test('the cache key is the normalised tuple, so two spellings are one entry', () => {
  // Keying on the raw Host lets two spellings of one name occupy two entries, which is a
  // cache-poisoning primitive.
  const spellings = ['atlas.vayu', 'ATLAS.VAYU', 'Atlas.Vayu', 'atlas.vayu.'];
  const normalised = spellings.map((h) => normaliseHost(h));
  for (const value of normalised) {
    assert.deepEqual(value, { label: 'atlas', tld: 'vayu' });
  }
});

test('a name is refused rather than repaired', () => {
  for (const host of [
    'atlas .vayu',
    'atlas_.vayu',
    '-atlas.vayu',
    'atlas-.vayu',
    'ab.vayu',
    'atlas.example',
    'atlas.vayu:80',
    'a'.repeat(PROXY_LIMITS.hostBytes + 1),
  ]) {
    assert.equal(normaliseHost(host), null, host);
  }
});

/* -------------------------------------------------------------------------- */
/* LOCAL-SURFACE.md 3.3, 3.4 — nothing unbounded is reachable from a page      */
/* -------------------------------------------------------------------------- */

test('I fill your memory with names nobody will ever ask for twice', () => {
  // The attack: my page requests an endless stream of distinct names. If negative answers are
  // cached "for process lifetime", every one is a permanent entry keyed by bytes I chose, and I
  // exhaust the resolver's memory from a page.
  const cache = new NegativeCache(8, 30);
  for (let i = 0; i < 1_000; i += 1) {
    cache.put(`name${i}.vayu`, NOW);
  }
  assert.equal(cache.size, 8, 'the negative cache must not grow past its bound');
});

test('syntactically invalid names are not cached at all', () => {
  // The grammar check is cheaper than the cache lookup, so caching them buys nothing and hands a
  // page an attacker-keyed insert.
  const cache = new NegativeCache();
  for (let i = 0; i < 100; i += 1) {
    handleRequest(get('/', { host: `bad_${i}.vayu` }), ports(), cache, NOW);
  }
  assert.equal(cache.size, 0);
});

test('a negative answer expires rather than being trusted forever', () => {
  const cache = new NegativeCache(8, 30);
  cache.put('atlas.vayu', NOW);
  assert.equal(cache.has('atlas.vayu', NOW + 29), true);
  assert.equal(cache.has('atlas.vayu', NOW + 30), false, 'the TTL must be finite');
});

test('eviction is by insertion order, so an attacker cannot pin their own entries', () => {
  // LRU would let an attacker keep their entries alive by touching them. There is nothing here
  // worth protecting from eviction, so insertion order is both simpler and less manipulable.
  const cache = new NegativeCache(3, 100);
  cache.put('one.vayu', NOW);
  cache.put('two.vayu', NOW);
  cache.put('three.vayu', NOW);
  assert.equal(cache.has('one.vayu', NOW), true);
  cache.put('four.vayu', NOW);
  assert.equal(cache.has('one.vayu', NOW), false, 'the oldest goes, whatever has been read');
  assert.equal(cache.has('four.vayu', NOW), true);
});
