import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  contentCacheKey,
  DEFAULT_CSP,
  DIAGNOSTIC_HEADERS,
  FORBIDDEN_RESPONSE_HEADERS,
  PROXY_LIMITS,
  SECURITY_HEADERS,
  handleRequest,
  normaliseHost,
  requestHost,
  sourceValueOf,
  type ContentPort,
  type ProxyRequest,
  type ProxyResponse,
} from './proxy.ts';
import { ResolutionCache } from './cache.ts';
import { CID_PARAMETERS, cidBytes, encodeCid, sha256 } from './content.ts';
import { parseRecord } from './record.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH } from './pow.ts';
import type { CborValue } from './cbor.ts';
import {
  MANIFEST_PATH,
  RESOLVE_ERRORS,
  resolveName,
  sourceCandidates,
  type ResolverPorts,
} from './resolve.ts';
import type { RegistryRecord } from './record.ts';

const NOW = 1_782_518_400;

/** A resolver that knows one name and nothing else. */
function ports(known: RegistryRecord | null = null): ResolverPorts {
  return {
    lookup: () => known,
    hasVerifiedHead: () => true,
  };
}

/**
 * The answer these ports give to the resolver's manifest probe.
 *
 * RESOLUTION.md step 13 reads `.vayu/manifest.json` before mapping a directory path, because a
 * declared `index` outranks `index.html` and there is no way to learn that afterwards. That probe
 * is a real fetch — but a test asserting *which sources were tried, in what order* is asking about
 * content, so each port below answers the probe and does not count it. The tests that are about the
 * manifest ask for it on purpose.
 */
const MANIFEST_MISS = { ok: false, error: 'PATH_NOT_FOUND' } as const;

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
    new ResolutionCache(),
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
    new ResolutionCache(),
    NOW,
  );
  for (const [name, value] of SECURITY_HEADERS) {
    assert.equal(refused.headers.get(name), value, name);
  }
});

test('no response may carry a header that brands the resolver or widens private access', () => {
  const cache = new ResolutionCache();
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
  const cache = new ResolutionCache();
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
  const cache = new ResolutionCache();
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
  const cache = new ResolutionCache();
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
  const cache = new ResolutionCache();
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
    new ResolutionCache(),
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
  const response = handleRequest(get('/', { host: hostile }), ports(), new ResolutionCache(), NOW);
  // Byte length, not string equality: a body is bytes now, and empty is the only shape that can
  // echo nothing at all.
  assert.equal(response.body.length, 0);
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
  const cache = new ResolutionCache({ negativeEntries: 8 });
  for (let i = 0; i < 1_000; i += 1) {
    cache.putNegative(`name${i}.vayu`, 'NAME_NOT_FOUND', NOW);
  }
  assert.equal(cache.negativeSize, 8, 'the negative cache must not grow past its bound');
});

test('syntactically invalid names are not cached at all', () => {
  // The grammar check is cheaper than the cache lookup, so caching them buys nothing and hands a
  // page an attacker-keyed insert.
  const cache = new ResolutionCache();
  for (let i = 0; i < 100; i += 1) {
    handleRequest(get('/', { host: `bad_${i}.vayu` }), ports(), cache, NOW);
  }
  assert.equal(cache.negativeSize, 0);
});

test('a negative answer expires rather than being trusted forever', () => {
  const cache = new ResolutionCache({ negativeEntries: 8 });
  cache.putNegative('atlas.vayu', 'NAME_NOT_FOUND', NOW);
  assert.equal(cache.negative('atlas.vayu', NOW + 29), 'NAME_NOT_FOUND');
  assert.equal(cache.negative('atlas.vayu', NOW + 30), null, 'the TTL must be finite');
});

test('eviction is by insertion order, so an attacker cannot pin their own entries', () => {
  // LRU would let an attacker keep their entries alive by touching them. There is nothing here
  // worth protecting from eviction, so insertion order is both simpler and less manipulable.
  const cache = new ResolutionCache({ negativeEntries: 3 });
  for (const name of ['one.vayu', 'two.vayu', 'three.vayu']) {
    cache.putNegative(name, 'NAME_NOT_FOUND', NOW);
  }
  assert.equal(cache.negative('one.vayu', NOW), 'NAME_NOT_FOUND');
  cache.putNegative('four.vayu', 'NAME_NOT_FOUND', NOW);
  assert.equal(cache.negative('one.vayu', NOW), null, 'the oldest goes, whatever has been read');
  assert.equal(cache.negative('four.vayu', NOW), 'NAME_NOT_FOUND');
});

/* -------------------------------------------------------------------------- */
/* AUDIT FINDING: one of the three canonical headers was never emitted          */
/* -------------------------------------------------------------------------- */

test('AUDIT: every canonical header block in CONTENT-SECURITY.md is actually emitted', () => {
  // Conformance item 1: "The three canonical values in sections 2 and 3 are emitted
  // byte-identically on every response." Two were. `Permissions-Policy` — the entire 44-token
  // deny list, every powerful feature the document enumerates as closed — was never sent at all,
  // so every one of those features was permitted by the headers this proxy actually produces.
  //
  // The existing test above pins the CSP by naming its block. A test that names the block it
  // checks cannot notice a block nobody wrote a test for, which is why this one enumerates the
  // `<!-- canonical:... -->` markers instead of listing them.
  const spec = readFileSync(
    new URL('../../docs/spec/CONTENT-SECURITY.md', import.meta.url),
    'utf8',
  );
  const markers = [...spec.matchAll(/<!-- canonical:([a-z-]+) -->\n```text\n([\s\S]*?)\n```/g)];
  assert.ok(markers.length >= 3, `only ${markers.length} canonical blocks found — format changed`);

  const emitted = new Map(SECURITY_HEADERS.map(([n, v]) => [n, v]));
  for (const [, name, block] of markers) {
    const value = block!.replace(new RegExp(`^${name}:\\s*`, 'i'), '').trim();
    assert.ok(emitted.has(name!), `${name} is canonical in the specification and never emitted`);
    assert.equal(emitted.get(name!), value, `${name} differs from its canonical block`);
  }
});

/* -------------------------------------------------------------------------- */
/* Handing a resolved entry to the content layer                               */
/* -------------------------------------------------------------------------- */

/** A live record carrying whatever entries the test needs. */
function live(entries: CborValue[]): RegistryRecord {
  return parseRecord(
    new Map<string | Uint8Array, CborValue>([
      ['version', 1],
      ['suite', 1],
      ['op', 'REGISTER'],
      ['name', 'atlas'],
      ['tld', 'vayu'],
      ['ownerKey', new Uint8Array(32).fill(0x11)],
      ['seq', 0],
      ['notBefore', NOW - 10],
      ['notAfter', NOW + 31_536_000],
      ['records', entries],
      [
        'powProof',
        new Map<string | Uint8Array, CborValue>([
          ['alg', POW_ALGORITHM],
          ['nonce', new Uint8Array(POW_NONCE_LENGTH).fill(7)],
          ['bits', 10],
        ]),
      ],
      ['prevHash', new Uint8Array(32)],
      ['sig', new Uint8Array(64).fill(0xaa)],
    ]),
  );
}

const cborEntry = (type: string, value: CborValue): CborValue =>
  new Map<string | Uint8Array, CborValue>([
    ['type', type],
    ['value', value],
  ]);

const DIGEST = sha256(new TextEncoder().encode('atlas observatory'));
const CID_TEXT = encodeCid({ version: 1, codec: CID_PARAMETERS.codecDagPb, digest: DIGEST });
const CID_BYTES = cidBytes({ version: 1, codec: CID_PARAMETERS.codecDagPb, digest: DIGEST });

/** A well-formed IPNS pointer, which REGISTRY.md types as 1-128 characters of text. */
const POINTER = 'k51qzi5uqu5dabcdefghijklmnopqrstuvwxyz0123456789';

test('AUDIT: a cid entry reaches the content layer as base32, not as String(Uint8Array)', () => {
  // This was `String(outcome.entry.value)`. A `cid` entry is a bstr, so that produced
  // "1,112,18,32,180,…" — the comma-joined DECIMALS of a typed array. It is a string, it is
  // non-empty, and it passes every type check between here and the content port, which can then
  // only ever fail to match it. The symptom was a 502 on a name that resolved perfectly, with
  // nothing wrong recorded anywhere, because by the lights of every function on the path nothing
  // had gone wrong.
  assert.equal(sourceValueOf({ type: 'cid', value: CID_BYTES }), CID_TEXT);
  assert.match(CID_TEXT, /^bafy/);
  // The specific wrong answer, named so a regression cannot be mistaken for a near miss.
  assert.notEqual(sourceValueOf({ type: 'cid', value: CID_BYTES }), String(CID_BYTES));

  // And end to end: the port receives what an addressing layer can compare against.
  const seen: { type: string; value: string }[] = [];
  const content: ContentPort = {
    fetch: (source, path) => {
      // This port says yes to everything, which includes step 13's manifest probe — so the probe
      // is answered separately and not counted. Worth noting what it proves in passing: a content
      // layer that returns bytes for any path hands `parseManifest` "served", which is not JSON
      // and is discarded, so a site cannot be broken by a port that is agreeable.
      if (path === MANIFEST_PATH) return MANIFEST_MISS;
      seen.push(source);
      return { ok: true, bytes: new TextEncoder().encode('served'), contentType: 'text/html' };
    },
  };
  const record = live([cborEntry('cid', CID_BYTES)]);
  const response = handleRequest(
    get('/', { host: 'atlas.vayu' }),
    { lookup: () => record, hasVerifiedHead: () => true },
    new ResolutionCache(),
    NOW,
    { content },
  );
  assert.equal(response.status, 200);
  assert.deepEqual(seen, [{ type: 'cid', value: CID_TEXT }]);
  // The fetched bytes are handed on unchanged — not re-encoded, not decoded and re-encoded.
  assert.deepEqual(response.body, new TextEncoder().encode('served'));
});

test('a malformed cid entry addresses nothing rather than something approximate', () => {
  // A record can carry any bytes; the entry-shape check bounds the LENGTH and says nothing about
  // the contents. A CIDv0, a blake3 multihash or a truncated digest must produce no source at
  // all — rendering one "as best we can" is how a resolver serves a block the record did not
  // name.
  assert.equal(sourceValueOf({ type: 'cid', value: Uint8Array.of(0x00, 0x70) }), null); // v0
  assert.equal(sourceValueOf({ type: 'cid', value: CID_BYTES.subarray(0, 20) }), null); // short
  assert.equal(sourceValueOf({ type: 'cid', value: CID_TEXT }), null); // text in a bstr field

  // A record whose only source is unusable is NO_USABLE_RECORD, not a 200 with an empty body:
  // an empty page is indistinguishable from a site that is genuinely blank.
  const record = live([cborEntry('cid', Uint8Array.of(0x00, 0x70))]);
  const response = handleRequest(
    get('/', { host: 'atlas.vayu' }),
    { lookup: () => record, hasVerifiedHead: () => true },
    new ResolutionCache(),
    NOW,
    { content: { fetch: () => assert.fail('the content port must not be reached') } },
  );
  assert.equal(response.status, RESOLVE_ERRORS.NO_USABLE_RECORD.http);
});

test('each entry type is rendered in its own form, and an unknown one in none', () => {
  assert.equal(sourceValueOf({ type: 'ipns', value: 'k51qzi5uqu5d' }), 'k51qzi5uqu5d');
  assert.equal(sourceValueOf({ type: 'alias', value: 'other.vayu' }), 'other.vayu');
  assert.equal(sourceValueOf({ type: 'peer', value: Uint8Array.of(0xde, 0xad, 0x00) }), 'dead00');
  // Shape mismatches, each the reverse of the type's declared CBOR major type.
  assert.equal(sourceValueOf({ type: 'ipns', value: CID_BYTES }), null);
  assert.equal(sourceValueOf({ type: 'peer', value: 'deadbeef' }), null);
  // `txt` is never a content source (RESOLUTION.md section 9) and neither is a type this version
  // does not know — REGISTRY.md requires both to be stored and replicated, which is not the same
  // as being acted upon.
  assert.equal(sourceValueOf({ type: 'txt', value: 'hello' }), null);
  assert.equal(sourceValueOf({ type: 'dnslink', value: 'example.com' }), null);
});

test('AUDIT: the per-site Trusted Types policy name is constrained before it reaches a header', () => {
  // **A publisher-chosen string spliced into a security header, with no grammar anywhere.**
  //
  // PUBLISHING.md 2.2 declares `csp.trustedTypes: "<policy-name>"`, taken from the site's own
  // `.vayu/manifest.json`, and points at CONTENT-SECURITY.md 2.3 as "authoritative for both".
  // What 2.3 said was one prose row: "Per-site named Trusted Types policy, same scoping and
  // disclosure." No character set, no length, no forbidden values. `<policy-name>` appeared
  // exactly once in the entire corpus.
  //
  // So the publisher, not the resolver, decided what text landed in the `trusted-types`
  // directive. Three consequences, each strictly worse than the relaxation 2.3 authorises:
  //
  //   "*"                      -> unrestricted policy creation, not one named policy
  //   "x; script-src 'unsafe-inline'"  -> arbitrary extra directives appended
  //   "x\r\nSet-Cookie: …"     -> response header splitting outright
  //
  // and every one of them is invisible to the reader-facing disclosure, which announces "a named
  // Trusted Types policy" whatever the name actually did.
  //
  // The corpus already had the governing rule for the only other externally-supplied value that
  // reaches a header — LOCAL-SURFACE.md 3.1, validated "**before** it is echoed, cached, logged,
  // used to construct any header" — and had never extended it to the manifest. Nothing implements
  // the relaxation yet, which is exactly when this is cheapest to close.
  const spec = readFileSync(
    new URL('../../docs/spec/CONTENT-SECURITY.md', import.meta.url),
    'utf8',
  );

  // A grammar, stated where the relaxation is defined rather than left to each implementer.
  assert.match(spec, /tt-policy-name/);
  assert.match(spec, /\[A-Za-z0-9\\-#=_\/@\.%\]\{1,64\}/);
  // The two values that turn "one named policy" into something else.
  assert.match(spec, /MUST NOT be `\*`/);
  assert.match(spec, /`'allow-duplicates'`/);
  // Validated before the header exists, not after — the LOCAL-SURFACE 3.1 discipline.
  assert.match(spec, /before the header is constructed/);
  // And refused rather than repaired, which is what LOCAL-SURFACE 3.2 requires of a bad label.
  assert.match(spec, /trusted-types 'none'/);
  assert.match(spec, /refused, not repaired/);
});

test('AUDIT: a fetched body leaves the handler byte for byte', () => {
  // **Every image and every non-ASCII character served through this proxy was corrupted, and the
  // comment beside the line said the opposite.**
  //
  // `handleRequest` widened the fetched bytes to a latin-1 JS string —
  // `Buffer.from(bytes).toString('binary')` — under a comment reading "the body is a byte string
  // all the way to the socket, and decoding it as text would corrupt every image and every
  // multi-byte character". It is not a byte string all the way to the socket: `writeHttp` in
  // serve.ts narrowed it again with `Buffer.from(body, 'utf8')`. Latin-1 out, UTF-8 back in, so
  // every octet above 0x7f became two. Measured with the fixture below: the 10-byte PNG prefix
  // arrived as 13 bytes, the 19-byte string arrived as 28, and all 256 byte values arrived as 384.
  //
  // The comment was right about the danger and wrong about whether the code avoided it, which is
  // the most expensive kind of comment to have.
  //
  // The browser acceptance test did not catch it because its fixture is pure ASCII — a test that
  // passes for a reason unrelated to what it is testing.
  //
  // This covers the HANDLER half only, and is named for that. The first version of it claimed the
  // socket and never opened one, so re-breaking `writeHttp` alone left it green; the wire half is
  // `AUDIT: a fetched body reaches the wire byte for byte` in serve.test.ts, which binds a
  // listener. Two halves, two tests, each named for the half it actually holds.
  const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xd8]);
  const utf8 = new TextEncoder().encode('café — ünïcode');

  for (const [what, bytes] of [
    ['a PNG header', png],
    ['UTF-8 text', utf8],
    ['every byte value', Uint8Array.from({ length: 256 }, (_, i) => i)],
  ] as const) {
    const record = live([cborEntry('cid', CID_BYTES)]);
    const response = handleRequest(
      get('/', { host: 'atlas.vayu' }),
      { lookup: () => record, hasVerifiedHead: () => true },
      new ResolutionCache(),
      NOW,
      {
        content: {
          fetch: () => ({ ok: true, bytes, contentType: 'application/octet-stream' }),
        },
      },
    );
    assert.equal(response.status, 200, what);
    assert.deepEqual(
      Uint8Array.from(response.body),
      bytes,
      `${what} must survive the proxy unchanged`,
    );
  }
});

/* -------------------------------------------------------------------------- */
/* AUDIT: the fallback three MUSTs describe and nothing implemented            */
/* -------------------------------------------------------------------------- */

/** The arrangement HOSTING.md tells a publisher to use: the living pointer and the snapshot. */
const pointerAndSnapshot = (): RegistryRecord =>
  live([cborEntry('ipns', POINTER), cborEntry('cid', CID_BYTES)]);

/**
 * What {@link POINTER} resolves to, deliberately NOT the snapshot's CID.
 *
 * Step 10 turns a pointer into a CID before step 11 fetches it, so a content layer sees `cid` for
 * both sources and a test asserting on `source.type` can no longer tell them apart. Asserting on
 * the value can — and it is the stronger assertion anyway, because it proves *which* snapshot was
 * asked for and in what order rather than merely that two things were.
 */
const LIVE_CID = encodeCid({
  version: 1,
  codec: CID_PARAMETERS.codecDagPb,
  digest: DIGEST.map((b) => b ^ 0xff),
});

/** A pointer resolver that answers for {@link POINTER} and refuses everything else. */
const pointerResolves = { resolve: (p: string) => (p === POINTER ? LIVE_CID : null) };

test('AUDIT: a record carrying both ipns and cid falls back to the snapshot', () => {
  // **The arrangement the specification recommends returned 502.** Reproduced before the fix:
  // the content port was asked for `ipns`, refused, and the `cid` beside it — the snapshot the
  // publisher supplied for exactly this case — was never asked for at all.
  //
  // RESOLUTION.md states three obligations in one paragraph and none existed:
  //
  //   "If the chosen entry fails, the resolver SHOULD fall back to the next, MUST record the
  //    fallback in the control API's per-request diagnostics, and MUST mark the answer stale."
  //
  // `selectSource` returned one entry and stopped; `Diagnostics.fallbacks` was declared and only
  // ever `[]`. Worse, `SOURCE_ORDER`'s own docstring reasons at length about why `ipns` must be
  // preferred and calls `cid` "the fallback for when the pointer cannot be resolved" — describing
  // a mechanism the module does not contain. A publisher following HOSTING and a resolver
  // following RESOLUTION both conformed, and every reader got a 502.
  const asked: string[] = [];
  const content: ContentPort = {
    fetch: (source, path) => {
      if (path === MANIFEST_PATH) return MANIFEST_MISS;
      asked.push(source.value);
      if (source.value !== CID_TEXT) return { ok: false, error: 'CONTENT_UNAVAILABLE' };
      return {
        ok: true,
        bytes: new TextEncoder().encode('the snapshot'),
        contentType: 'text/html',
      };
    },
  };
  const response = handleRequest(
    get('/', { host: 'atlas.vayu' }),
    { lookup: () => pointerAndSnapshot(), hasVerifiedHead: () => true },
    new ResolutionCache(),
    NOW,
    { content, ipns: pointerResolves, diagnostics: true },
  );

  assert.equal(response.status, 200, 'the snapshot must be served, not a 502');
  assert.deepEqual(Uint8Array.from(response.body), new TextEncoder().encode('the snapshot'));
  // The pointer was tried FIRST and the snapshot second. Serving the snapshot by preferring it
  // would pass the assertions above and reintroduce the defect `SOURCE_ORDER` was reordered to
  // fix: an author republishing weekly into a pointer nobody consults.
  // By VALUE, because after step 10 both sources reach the content layer as a CID. The pointer's
  // CID first, the snapshot's second.
  assert.deepEqual(asked, [LIVE_CID, CID_TEXT]);

  // MUST record the fallback, and MUST mark the answer stale. Both are observable only through
  // the diagnostic headers, which is why this request enables them.
  assert.equal(response.headers.get('x-vayuweb-source'), 'cid');
  assert.equal(response.headers.get('x-vayuweb-fallbacks'), 'ipns');
  assert.equal(response.headers.get('x-vayuweb-stale'), '1');
});

test('AUDIT: recording the fallback does not depend on disclosing it', () => {
  // RESOLUTION.md: "recording is mandatory, disclosing is not". The headers are off by default,
  // so a fallback that were only ever computed while building them would satisfy every test above
  // and record nothing on an ordinary request. Asserted through the resolver rather than the
  // proxy, because that is the layer the control API reads.
  const record = pointerAndSnapshot();
  const outcome = resolveName(
    'atlas.vayu',
    { lookup: () => record, hasVerifiedHead: () => true },
    NOW,
  );
  assert.ok(outcome.ok);
  // The resolver itself still selects one entry — the fallback is a property of the FETCH, and
  // this asserts the shape the proxy needs rather than pre-judging where the loop lives.
  assert.equal(outcome.entry.type, 'ipns');
  assert.deepEqual(
    sourceCandidates(record).map((e) => e.type),
    ['ipns', 'cid'],
  );
});

test('AUDIT: a failing pointer with no snapshot still refuses, and says so once', () => {
  // The fallback must not turn every failure into a 200 by trying until something works. With
  // only a pointer, there is nothing to fall back to and the refusal stands.
  const asked: string[] = [];
  const content: ContentPort = {
    fetch: (source, path) => {
      if (path === MANIFEST_PATH) return MANIFEST_MISS;
      asked.push(source.value);
      return { ok: false, error: 'CONTENT_UNAVAILABLE' };
    },
  };
  const response = handleRequest(
    get('/', { host: 'atlas.vayu' }),
    { lookup: () => live([cborEntry('ipns', POINTER)]), hasVerifiedHead: () => true },
    new ResolutionCache(),
    NOW,
    { content, ipns: pointerResolves },
  );
  assert.equal(response.status, RESOLVE_ERRORS.CONTENT_UNAVAILABLE.http);
  assert.deepEqual(asked, [LIVE_CID], 'one source, one attempt');
});

test('AUDIT: a content failure is cached against the content, because the name is unreachable', () => {
  // Written to prove the two shortest TTLs in RESOLUTION.md's table had a writer, and it failed —
  // which was the finding. Storing them under the NAME is a writer with no reader: step 5 takes a
  // positive record from the cache and goes to step 9, skipping step 6, so a negative entry keyed
  // by `atlas.vayu` is unreachable for exactly as long as `atlas.vayu`'s record is cached. That is
  // every request after the first, which is every request this cache exists for.
  //
  // Keyed by the source, it is reachable — and it is the truer statement anyway. A CID nobody is
  // serving is not being served to any name that points at it.
  const asked: string[] = [];
  const content: ContentPort = {
    fetch: (source, path) => {
      if (path === MANIFEST_PATH) return MANIFEST_MISS;
      asked.push(source.value);
      return { ok: false, error: 'CONTENT_UNAVAILABLE' };
    },
  };
  const cache = new ResolutionCache();
  const registry = {
    lookup: () => live([cborEntry('cid', CID_BYTES)]),
    hasVerifiedHead: () => true,
  };

  const first = handleRequest(get('/', { host: 'atlas.vayu' }), registry, cache, NOW, { content });
  assert.equal(first.status, RESOLVE_ERRORS.CONTENT_UNAVAILABLE.http);
  assert.equal(cache.negative(`content:cid:${CID_TEXT}`, NOW + 9), 'CONTENT_UNAVAILABLE');
  assert.equal(
    cache.negative('atlas.vayu', NOW + 9),
    null,
    'and not under the name, where nothing would ever read it',
  );

  // Within the TTL the content layer is not asked again — which is the whole of what caching a
  // content failure buys, and what a site being offline should not cost every visitor.
  const second = handleRequest(get('/', { host: 'atlas.vayu' }), registry, cache, NOW + 9, {
    content,
  });
  assert.equal(second.status, RESOLVE_ERRORS.CONTENT_UNAVAILABLE.http);
  assert.deepEqual(asked, [CID_TEXT], 'one fetch for two requests');

  // Ten seconds, not thirty: a site coming back online recovers quickly.
  handleRequest(get('/', { host: 'atlas.vayu' }), registry, cache, NOW + 10, { content });
  assert.deepEqual(asked, [CID_TEXT, CID_TEXT], 'and after the TTL it is tried again');
});

/* -------------------------------------------------------------------------- */
/* RESOLUTION.md step 13 / PUBLISHING.md 2.3 — the manifest                    */
/* -------------------------------------------------------------------------- */

/** A site whose tree is exactly the paths given, with a manifest if one is declared. */
function siteWith(files: Record<string, string>): { port: ContentPort; asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    port: {
      fetch: (_source, path) => {
        asked.push(path);
        const body = files[path];
        if (body === undefined) return { ok: false, error: 'PATH_NOT_FOUND' };
        return {
          ok: true,
          bytes: new TextEncoder().encode(body),
          contentType: 'text/html; charset=utf-8',
        };
      },
    },
  };
}

const manifest = (fields: Record<string, unknown>): string =>
  JSON.stringify({ version: 1, ...fields });

function request(port: ContentPort, path: string, cache = new ResolutionCache()): ProxyResponse {
  return handleRequest(
    get(path, { host: 'atlas.vayu' }),
    { lookup: () => live([cborEntry('cid', CID_BYTES)]), hasVerifiedHead: () => true },
    cache,
    NOW,
    { content: port },
  );
}

test('my site 404s on every deep link, and my manifest says what to do about it', () => {
  // PUBLISHING.md 2.3 is a **SHALL** and it names its own symptom in the sentence before: "a site
  // with client-side routing 404s on every deep link unless a fallback exists". Nothing in the
  // shipping resolver read `.vayu/manifest.json` at all — the rule lived in two places, a
  // resolver-side path mapper with no caller and the CLI's content port reimplementing a subset
  // of it inline, and the manifest belonged to neither.
  const site = siteWith({
    '/index.html': 'the app shell',
    '/.vayu/manifest.json': manifest({ fallback: 'index.html' }),
  });

  const deep = request(site.port, '/reports/2026/march');
  assert.equal(deep.status, 200, 'the router gets its chance, which is the whole of the clause');
  assert.equal(new TextDecoder().decode(deep.body), 'the app shell');
});

test('a declared notFound is served, and with 404 rather than 200', () => {
  // The two fields are separate because the STATUS is what separates them. Serving a `notFound`
  // page with 200 would make every broken link look like a page to a search engine, a link
  // checker and the browser's own history — which is what a `notFound` document exists to avoid.
  const site = siteWith({
    '/index.html': 'home',
    '/404.html': 'nothing here',
    '/.vayu/manifest.json': manifest({ notFound: '404.html', fallback: 'index.html' }),
  });

  const missing = request(site.port, '/gone');
  assert.equal(missing.status, 404);
  assert.equal(new TextDecoder().decode(missing.body), 'nothing here');
  assert.equal(
    missing.headers.get('content-type'),
    'text/html; charset=utf-8',
    'a site page carries the site page’s type, not a refusal’s',
  );
});

test('notFound outranks fallback, because the specification orders them', () => {
  const site = siteWith({
    '/404.html': 'nothing here',
    '/index.html': 'home',
    '/.vayu/manifest.json': manifest({ notFound: '404.html', fallback: 'index.html' }),
  });
  assert.equal(request(site.port, '/gone').status, 404);
});

test('a declared index outranks index.html, and is read before the mapping rather than after', () => {
  // "resolving `/` and directory paths to the manifest's `index` when one is declared and to
  // `index.html` otherwise". A resolver that tried `index.html` first and consulted the manifest
  // only on a miss would serve the wrong document for every site that has both — and would look
  // correct in every test where only one exists.
  const site = siteWith({
    '/index.html': 'the wrong one',
    '/home.html': 'the declared one',
    '/.vayu/manifest.json': manifest({ index: 'home.html' }),
  });
  const root = request(site.port, '/');
  assert.equal(root.status, 200);
  assert.equal(new TextDecoder().decode(root.body), 'the declared one');
});

test('a declared file that is not in the tree is discarded rather than reported', () => {
  // Step 13: "a declared file that is not present in the verified tree is discarded rather than
  // reported, because the manifest declares intent and is never evidence about the tree." A
  // manifest is optional, so a typo in one must not be a way to break a site — it falls through to
  // the ordinary answer.
  const site = siteWith({
    '/index.html': 'home',
    '/.vayu/manifest.json': manifest({ index: 'typo.html', notFound: 'also-missing.html' }),
  });
  const root = request(site.port, '/');
  assert.equal(root.status, 200);
  assert.equal(new TextDecoder().decode(root.body), 'home', 'the ordinary mapping still applies');

  const missing = request(site.port, '/gone');
  assert.equal(missing.status, RESOLVE_ERRORS.PATH_NOT_FOUND.http);
});

test('I put ../ in my own manifest and read a file outside my tree', () => {
  // The manifest is inside the tree and covered by the root CID, so it is AUTHENTIC — it is what
  // the publisher signed. That is the whole of what the hash proves. It says nothing about whether
  // the publisher is careless or hostile toward their readers, and these fields become paths this
  // resolver fetches, so each one is validated as though it came from a stranger.
  for (const hostile of ['../secrets', '/etc/passwd', 'a/../../b', '']) {
    const site = siteWith({
      '/index.html': 'home',
      '/.vayu/manifest.json': manifest({ index: hostile, notFound: hostile, fallback: hostile }),
    });
    const root = request(site.port, '/');
    assert.equal(new TextDecoder().decode(root.body), 'home', `index ${hostile}`);
    assert.equal(request(site.port, '/gone').status, RESOLVE_ERRORS.PATH_NOT_FOUND.http, hostile);
    assert.equal(
      site.asked.some((path) => path.includes('..')),
      false,
      `no traversal may reach the content layer: ${JSON.stringify(site.asked)}`,
    );
  }
});

test('the manifest is read once per site, not once per request', () => {
  // A CID addresses its bytes, so a manifest keyed by one cannot go stale — which is what makes
  // remembering it sound and what stops a directory request costing an extra block fetch every
  // time. RESOLUTION.md's caching section calls this the content cache: "immutable, keyed by CID,
  // no expiry."
  const site = siteWith({ '/index.html': 'home' });
  const cache = new ResolutionCache();
  for (let i = 0; i < 5; i += 1) assert.equal(request(site.port, '/', cache).status, 200);

  const probes = site.asked.filter((path) => path === MANIFEST_PATH).length;
  assert.equal(probes, 1, 'five requests, one probe');
  assert.equal(cache.manifestSize, 1, 'and "this site has no manifest" is remembered too');
});

test('a registry append does not forget what a CID contains', () => {
  // `setGeneration` drops the record and negative caches because an append can change what a NAME
  // resolves to. It cannot change what a CID contains, and dropping these with them would make a
  // syncing peer re-fetch every manifest it holds, forever, for no reason.
  const site = siteWith({ '/index.html': 'home' });
  const cache = new ResolutionCache();
  cache.setGeneration(1);
  request(site.port, '/', cache);
  cache.setGeneration(2);
  request(site.port, '/', cache);
  assert.equal(site.asked.filter((path) => path === MANIFEST_PATH).length, 1);
});

test('a manifest is only consulted when the path is missing, never when the site is', () => {
  // A source that is unavailable, a pointer that will not resolve, or bytes that failed their hash
  // are not "this path is not in the tree". Answering any of them with the site's own 404 page
  // would tell a reader the site is fine and their link is wrong, which is the opposite of true.
  const asked: string[] = [];
  const content: ContentPort = {
    fetch: (_source, path) => {
      asked.push(path);
      if (path === MANIFEST_PATH) {
        return {
          ok: true,
          bytes: new TextEncoder().encode(manifest({ notFound: '404.html' })),
          contentType: 'application/json',
        };
      }
      return { ok: false, error: 'CONTENT_UNAVAILABLE' };
    },
  };
  const response = request(content, '/anything');
  assert.equal(response.status, RESOLVE_ERRORS.CONTENT_UNAVAILABLE.http);
  assert.equal(asked.includes('/404.html'), false, 'the site’s 404 page must not be served');
});

/* -------------------------------------------------------------------------- */
/* RESOLUTION.md step 10 — pointer resolution, which had no implementation     */
/* -------------------------------------------------------------------------- */

test('a name carrying only a pointer is told its pointer failed, not that its record is empty', () => {
  // 1421 `NO_USABLE_RECORD` says "this name points at nothing fetchable" and 1505
  // `IPNS_UNRESOLVED` says "this site's pointer could not be resolved". A record carrying an
  // `ipns` entry got the first, and it is false: the record is exactly what HOSTING.md tells
  // publishers to write, and `SOURCE_ORDER` puts that entry FIRST. The publisher reading 1421
  // goes and fixes a record that was never wrong.
  //
  // 1505 had no producer anywhere in the codebase before this — a catalogue entry, a message, an
  // HTTP status and a conformance vector, and no line of code that could ever return it.
  const content: ContentPort = { fetch: () => assert.fail('nothing is fetchable without a CID') };
  const response = handleRequest(
    get('/', { host: 'atlas.vayu' }),
    { lookup: () => live([cborEntry('ipns', POINTER)]), hasVerifiedHead: () => true },
    new ResolutionCache(),
    NOW,
    { content },
  );
  assert.equal(response.status, RESOLVE_ERRORS.IPNS_UNRESOLVED.http);
});

test('a resolved pointer is served, and the header says which snapshot it landed on', () => {
  // `X-VayuWeb-CID` was `type === 'cid' ? value : null`, so a page served through a pointer
  // carried an empty CID header — the one field that tells an operator which snapshot a living
  // pointer resolved to, blank in exactly the case where it is not already in the record.
  const asked: Array<{ type: string; value: string }> = [];
  const content: ContentPort = {
    fetch: (source, path) => {
      if (path === MANIFEST_PATH) return MANIFEST_MISS;
      asked.push({ ...source });
      return { ok: true, bytes: new Uint8Array([1]), contentType: 'text/html; charset=utf-8' };
    },
  };
  const response = handleRequest(
    get('/', { host: 'atlas.vayu' }),
    { lookup: () => live([cborEntry('ipns', POINTER)]), hasVerifiedHead: () => true },
    new ResolutionCache(),
    NOW,
    { content, ipns: { resolve: (p) => (p === POINTER ? CID_TEXT : null) }, diagnostics: true },
  );
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-vayuweb-cid'), CID_TEXT);
  assert.equal(response.headers.get('x-vayuweb-source'), 'ipns', 'the record said ipns');
  assert.deepEqual(
    asked,
    [{ type: 'cid', value: CID_TEXT }],
    'after step 10 there is only a CID, so a content layer never needs to know what a pointer is',
  );
});

test('a pointer that will not resolve falls back to the snapshot the publisher supplied', () => {
  // The arrangement HOSTING.md recommends, working end to end for the first time: a pointer for
  // the living site and a `cid` for "the last snapshot the owner is willing to have served if the
  // pointer cannot be resolved".
  const content: ContentPort = {
    fetch: () => ({ ok: true, bytes: new Uint8Array([2]), contentType: 'text/plain' }),
  };
  const response = handleRequest(
    get('/', { host: 'atlas.vayu' }),
    {
      lookup: () => live([cborEntry('ipns', POINTER), cborEntry('cid', CID_BYTES)]),
      hasVerifiedHead: () => true,
    },
    new ResolutionCache(),
    NOW,
    { content, ipns: { resolve: () => null }, diagnostics: true },
  );
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-vayuweb-source'), 'cid');
  assert.equal(response.headers.get('x-vayuweb-fallbacks'), 'ipns');
  assert.equal(response.headers.get('x-vayuweb-stale'), '1', 'a fallback is not the live answer');
});

test('a pointer that will not resolve is not re-resolved for ten seconds', () => {
  // 1505 is one of the two ten-second codes, and until step 10 existed it was a TTL for an error
  // nothing produced.
  let attempts = 0;
  const content: ContentPort = { fetch: () => ({ ok: false, error: 'CONTENT_UNAVAILABLE' }) };
  const cache = new ResolutionCache();
  const registry = {
    lookup: () => live([cborEntry('ipns', POINTER)]),
    hasVerifiedHead: () => true,
  };
  const ipns = {
    resolve: () => {
      attempts += 1;
      return null;
    },
  };

  handleRequest(get('/', { host: 'atlas.vayu' }), registry, cache, NOW, { content, ipns });
  assert.equal(cache.negative(`content:ipns:${POINTER}`, NOW + 9), 'IPNS_UNRESOLVED');
  handleRequest(get('/', { host: 'atlas.vayu' }), registry, cache, NOW + 9, { content, ipns });
  assert.equal(attempts, 1, 'one resolution attempt for two requests');
  handleRequest(get('/', { host: 'atlas.vayu' }), registry, cache, NOW + 10, { content, ipns });
  assert.equal(attempts, 2, 'and it is tried again once the TTL passes');
});

test('AUDIT: an integrity failure is never cached, against a name or against a CID', () => {
  // The never-cache clause, checked at the key that would make breaking it worst. An integrity
  // failure keyed by CID would let one bad copy take a site down for every reader behind this
  // resolver — and unlike a name key, a CID key is shared by every name pointing at that snapshot.
  //
  // The first version of this test used a 32-byte fixture that is not a decodable CID, so
  // `sourceValueOf` refused it, the content port was never reached, and the refusal was
  // `NO_USABLE_RECORD` — which shares HTTP 502 with `CONTENT_INTEGRITY`. It passed against a
  // deliberately broken resolver. A status assertion is not a code assertion when two codes map to
  // one status, so this one counts the fetches and reads the code.
  let fetches = 0;
  const content: ContentPort = {
    fetch: (_source, path) => {
      if (path === MANIFEST_PATH) return MANIFEST_MISS;
      fetches += 1;
      return { ok: false, error: 'CONTENT_INTEGRITY' };
    },
  };
  const cache = new ResolutionCache();
  const registry = {
    lookup: () => live([cborEntry('cid', CID_BYTES)]),
    hasVerifiedHead: () => true,
  };

  const response = handleRequest(get('/', { host: 'atlas.vayu' }), registry, cache, NOW, {
    content,
  });
  assert.equal(fetches, 1, 'the content layer must actually have been asked');
  assert.equal(response.status, RESOLVE_ERRORS.CONTENT_INTEGRITY.http);
  assert.equal(cache.negativeSize, 0, 'nothing about a bad copy may become sticky');

  // And it stays that way: a second request re-attempts rather than replaying a stored refusal.
  handleRequest(get('/', { host: 'atlas.vayu' }), registry, cache, NOW + 1, { content });
  assert.equal(fetches, 2, 'one bad copy must not take the site down for the TTL');
});

test('AUDIT: the resolver does not fall back across a content-integrity failure', () => {
  // **The one MUST NOT in the paragraph, and the one whose absence is exploitable.**
  //
  // RESOLUTION.md: "It MUST NOT fall back across a CONTENT_INTEGRITY failure, which signals an
  // attack rather than an availability problem." A resolver that falls back on bad bytes hands an
  // attacker a downgrade: corrupt the answer for the source the publisher prefers, and the
  // resolver walks itself down to whichever source the attacker can better influence. The failure
  // that means "someone is lying to you" must not be the trigger for trying somewhere else.
  const asked: string[] = [];
  const content: ContentPort = {
    fetch: (source, path) => {
      if (path === MANIFEST_PATH) return MANIFEST_MISS;
      asked.push(source.value);
      return { ok: false, error: 'CONTENT_INTEGRITY' };
    },
  };
  const response = handleRequest(
    get('/', { host: 'atlas.vayu' }),
    { lookup: () => pointerAndSnapshot(), hasVerifiedHead: () => true },
    new ResolutionCache(),
    NOW,
    { content, ipns: pointerResolves, diagnostics: true },
  );
  assert.equal(response.status, RESOLVE_ERRORS.CONTENT_INTEGRITY.http);
  assert.deepEqual(asked, [LIVE_CID], 'the cid must NOT have been tried after bad bytes');
  // A refusal carries no diagnostic headers at all — not an empty one. LOCAL-SURFACE.md 2.4:
  // a refusal must not be distinguishable in a way that confirms VayuWeb is running, and an
  // `x-vayuweb-*` header on a 502 confirms it by existing. (Asserting the empty string was the
  // first version of this line, and it was asserting that the wrong thing was present.)
  for (const header of DIAGNOSTIC_HEADERS) {
    assert.equal(response.headers.has(header), false, `${header} must not be on a refusal`);
  }
});

test('AUDIT: every diagnostic header RESOLUTION.md enumerates is one the resolver emits', () => {
  // **`x-vayuweb-cid` was declared in `DIAGNOSTIC_HEADERS` and emitted nowhere.** The only test
  // over that list asserted the headers are ABSENT by default — which is true of a header that
  // does not exist, so the list could name anything and stay green. A list that is checked only
  // for absence is a list nothing checks.
  //
  // So this reads the enumeration out of RESOLUTION.md and requires each one to actually appear
  // on a diagnostic response. Same repair the roadmap describes for the Permissions-Policy list:
  // derive from the document rather than restating it, because a restatement drifts silently.
  const spec = readFileSync(new URL('../../docs/spec/RESOLUTION.md', import.meta.url), 'utf8');
  const flat = spec.replace(/\s+/g, ' ');
  const paragraph = /Diagnostic headers — (.*?) — MUST be \*\*off by default\*\*/.exec(flat);
  assert.ok(paragraph, 'RESOLUTION.md must enumerate the diagnostic headers');
  const enumerated = [...paragraph[1]!.matchAll(/`(X-VayuWeb-[A-Za-z-]+)`/g)].map((m) =>
    m[1]!.toLowerCase(),
  );
  assert.ok(enumerated.length >= 6, `only ${enumerated.length} headers enumerated`);

  // The code's own list must be exactly the document's, in both directions.
  assert.deepEqual([...DIAGNOSTIC_HEADERS].sort(), [...enumerated].sort());

  const content: ContentPort = {
    fetch: () => ({ ok: true, bytes: new TextEncoder().encode('page'), contentType: 'text/html' }),
  };
  const response = handleRequest(
    get('/', { host: 'atlas.vayu' }),
    { lookup: () => live([cborEntry('cid', CID_BYTES)]), hasVerifiedHead: () => true },
    new ResolutionCache(),
    NOW,
    { content, diagnostics: true },
  );
  assert.equal(response.status, 200);
  for (const header of enumerated) {
    assert.ok(
      response.headers.has(header),
      `${header} is enumerated in RESOLUTION.md and never emitted`,
    );
  }
  // And the CID one carries the identifier actually served, rendered as a reader would compare it.
  assert.equal(response.headers.get('x-vayuweb-cid'), CID_TEXT);
});

test('MUTATION: the resolver stores a content failure under the key the pin path drops', () => {
  // `pinPorts` invalidates `contentCacheKey('cid', cid)` so that re-pinning a site brings it back
  // on the wire. That only works if the resolver STORES the failure under the same key, and a test
  // that calls `contentCacheKey` on both sides cannot see the difference — mutating the resolver's
  // key to an inline string survived the whole suite. This asserts the storing side.
  const cache = new ResolutionCache();
  const offline: ContentPort = {
    fetch: () => ({ ok: false, error: 'CONTENT_UNAVAILABLE' }),
  };

  const first = request(offline, '/index.html', cache);
  assert.equal(first.status, 504, 'the fixture must actually fail, or this proves nothing');

  const stored = cache.negative(contentCacheKey('cid', CID_TEXT), NOW);
  assert.equal(
    stored,
    'CONTENT_UNAVAILABLE',
    'the failure must be reachable at the key the pin path forgets',
  );

  // And dropping it exactly as `pinPorts` does really does clear the resolver's answer.
  cache.forget(contentCacheKey('cid', CID_TEXT));
  assert.equal(cache.negative(contentCacheKey('cid', CID_TEXT), NOW), null);
});
