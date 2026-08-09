import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { PinSet, report } from './pins.ts';

import {
  CONTROL_HEADER,
  TOKEN_BYTES,
  assertSocketAddress,
  handleControlRequest,
  jsonObject,
  redact,
  tokenMatches,
  type ControlPorts,
  type ControlRequest,
} from './control.ts';

const TOKEN = randomBytes(TOKEN_BYTES).toString('base64url');

const ports = (): ControlPorts => {
  let diagnostics = false;
  const pinned = new PinSet((cid) => cid === HELD_CID);
  return {
    status: () => ({ mode: 'clearnet', uptime: 42, listeners: ['proxy'] }),
    version: () => '0.2.0-test',
    logHead: () => ({ length: 7, root: 'aa'.repeat(32) }),
    config: () => ({
      mode: 'clearnet',
      tokenPath: '/home/reader/.config/vayuweb/token',
      cache: { entries: 512, secretKey: 'hunter2' },
    }),
    diagnostics: () => diagnostics,
    setDiagnostics: (on: boolean) => {
      diagnostics = on;
    },
    pins: () =>
      pinned
        .list()
        .map((cid) => report(cid, 0, [{ holder: { kind: 'self' }, observedAt: 1 }], 300, 1)),
    // Deliberately no `name` field: the router owns that one, and a double that returns it too
    // masks whether the router's echo is the validated name or the bytes that were sent. It did,
    // and a mutation replacing the echo with the raw path went unnoticed because of it.
    resolve: (label, tld) => ({
      outcome: 'error',
      error: 'NAME_NOT_FOUND',
      asked: `${label}/${tld}`,
    }),
    cacheStats: () => ({ negative: 1, positive: 2, manifests: 3, hits: 4, misses: 5 }),
    flushCache: (name) => (name === null ? 6 : 1),
    peers: () => ({ joined: false, peers: 0, detail: 'not joined' }),
    // A real PinSet over a node that holds exactly one CID, because the interesting behaviour is
    // the refusal and a double that accepted everything could not exhibit it.
    pin: (cid) => pinned.add(cid),
    unpin: (cid) => pinned.remove(cid),
  };
};

function request(
  method: string,
  path: string,
  headers: Record<string, string> = {},
  body: Uint8Array = new Uint8Array(0),
): ControlRequest {
  return {
    method,
    path,
    headers: new Map(
      Object.entries({
        [CONTROL_HEADER]: '1',
        authorization: `Bearer ${TOKEN}`,
        ...headers,
      }),
    ),
    body,
  };
}

/** A request carrying `text` as its body, exactly as the transport would hand it over. */
function withBody(method: string, path: string, text: string): ControlRequest {
  return request(method, path, {}, new TextEncoder().encode(text));
}

/* -------------------------------------------------------------------------- */
/* The transport IS the security model                                         */
/* -------------------------------------------------------------------------- */

test('a TCP address is refused at the boundary, not merely discouraged in prose', () => {
  // The sentence "the control API must not listen on TCP" was already written, in
  // LOCAL-SURFACE.md section 1, and five documents went on specifying `127.0.0.1:7653` anyway.
  // A guard that throws is what a sentence could not be.
  for (const address of [
    '127.0.0.1:7653',
    '0.0.0.0:7653',
    'localhost:7653',
    ':7653',
    '7653',
    '[::1]:7653',
  ]) {
    assert.throws(() => assertSocketAddress(address), /never on TCP|must be absolute/, address);
  }
});

test('a socket path or a Windows named pipe is accepted', () => {
  assertSocketAddress('/run/user/1000/vayuweb/vayuweb.sock');
  assertSocketAddress('\\\\.\\pipe\\vayuweb');
});

/* -------------------------------------------------------------------------- */
/* Browser-shaped requests are refused before the token is ever consulted      */
/* -------------------------------------------------------------------------- */

test('an Origin header is disqualifying by itself', () => {
  // A browser attaches Origin to any cross-origin request it makes. Nothing that legitimately
  // speaks to this API has an origin, so its presence is enough — no analysis of the value, which
  // would be a policy to get wrong.
  const response = handleControlRequest(
    request('GET', '/v1/status', { origin: 'http://evil.example' }),
    ports(),
    TOKEN,
  );
  assert.equal(response.status, 403);
});

test('the custom header is required, so a simple cross-origin request cannot be forged', () => {
  const withoutHeader: ControlRequest = {
    method: 'GET',
    path: '/v1/status',
    headers: new Map([['authorization', `Bearer ${TOKEN}`]]),
    body: new Uint8Array(0),
  };
  assert.equal(handleControlRequest(withoutHeader, ports(), TOKEN).status, 403);
});

test('an Upgrade request is refused unconditionally', () => {
  // There is no WebSocket endpoint, so the rejection needs no analysis of what was being upgraded
  // to — and an unconditional refusal cannot be wrong about a protocol nobody has invented yet.
  assert.equal(
    handleControlRequest(request('GET', '/v1/status', { upgrade: 'websocket' }), ports(), TOKEN)
      .status,
    400,
  );
  assert.equal(
    handleControlRequest(request('GET', '/v1/status', { connection: 'Upgrade' }), ports(), TOKEN)
      .status,
    400,
  );
});

test('the browser refusals run BEFORE the token is compared', () => {
  // Order is the point. A page that somehow reached this surface is turned away without its token
  // guess ever being timed, so the timing side-channel a constant-time comparison exists to close
  // is not even reachable from a browser.
  const wrongToken = randomBytes(TOKEN_BYTES).toString('base64url');
  const browserShaped = handleControlRequest(
    request('GET', '/v1/status', {
      origin: 'http://evil.example',
      authorization: `Bearer ${wrongToken}`,
    }),
    ports(),
    TOKEN,
  );
  assert.equal(browserShaped.status, 403, 'refused as a browser, not as a bad token');
});

test('no response ever carries Access-Control-Allow-Origin', () => {
  const responses = [
    handleControlRequest(request('GET', '/v1/status'), ports(), TOKEN),
    handleControlRequest(
      request('GET', '/v1/status', { origin: 'http://evil.example' }),
      ports(),
      TOKEN,
    ),
    handleControlRequest(request('GET', '/v1/nope'), ports(), TOKEN),
  ];
  for (const response of responses) {
    assert.equal(response.headers.has('access-control-allow-origin'), false);
  }
});

/* -------------------------------------------------------------------------- */
/* The token                                                                   */
/* -------------------------------------------------------------------------- */

test('a wrong, absent, truncated or over-long token is refused', () => {
  const control = ports();
  const wrong = randomBytes(TOKEN_BYTES).toString('base64url');
  for (const authorization of [
    '',
    'Bearer ',
    `Bearer ${wrong}`,
    `Bearer ${TOKEN.slice(0, -2)}`,
    `Bearer ${TOKEN}extra`,
    TOKEN,
    `Basic ${TOKEN}`,
  ]) {
    const response = handleControlRequest(
      request('GET', '/v1/status', { authorization }),
      control,
      TOKEN,
    );
    assert.equal(response.status, 401, JSON.stringify(authorization));
  }
});

test('a token of the wrong length is refused without a byte comparison', () => {
  // timingSafeEqual throws on a length mismatch, so a length check must come first — and since the
  // expected token is always TOKEN_BYTES, a wrong length is a wrong token regardless.
  assert.equal(tokenMatches(Buffer.alloc(16).toString('base64url'), TOKEN), false);
  assert.equal(tokenMatches(Buffer.alloc(64).toString('base64url'), TOKEN), false);
  assert.equal(tokenMatches('', TOKEN), false);
  assert.equal(tokenMatches('!!!not base64!!!', TOKEN), false);
});

test('the correct token is accepted', () => {
  assert.equal(tokenMatches(TOKEN, TOKEN), true);
  assert.equal(handleControlRequest(request('GET', '/v1/status'), ports(), TOKEN).status, 200);
});

/* -------------------------------------------------------------------------- */
/* Disclosure                                                                  */
/* -------------------------------------------------------------------------- */

test('the build version reaches only an authenticated caller', () => {
  // A version string is a fingerprint and a vulnerability-matching aid.
  const unauthenticated = handleControlRequest(
    request('GET', '/v1/status', { authorization: 'Bearer wrong' }),
    ports(),
    TOKEN,
  );
  assert.equal(JSON.stringify(unauthenticated.body).includes('0.2.0-test'), false);

  const authenticated = handleControlRequest(request('GET', '/v1/status'), ports(), TOKEN);
  assert.equal(JSON.stringify(authenticated.body).includes('0.2.0-test'), true);
});

test('the config dump redacts every secret-bearing key, including nested ones', () => {
  const response = handleControlRequest(request('GET', '/v1/config'), ports(), TOKEN);
  const dumped = JSON.stringify(response.body);
  assert.equal(dumped.includes('hunter2'), false, 'a nested secret must not survive');
  assert.equal(dumped.includes('/home/reader/.config/vayuweb/token'), false);
  assert.equal(dumped.includes('[redacted]'), true);
  assert.equal(dumped.includes('clearnet'), true, 'non-secret configuration still comes through');
});

test('redaction keys on the name, so an unforeseen secret is redacted by default', () => {
  // The failure mode of over-redaction is an operator looking somewhere else. The failure mode of
  // under-redaction is the token in a log. Substring matching on the key means a field nobody
  // anticipated — `apiToken`, `sessionSecret`, `privateSeed` — is safe without being enumerated.
  const out = redact({
    apiToken: 'a',
    sessionSecret: 'b',
    privateSeed: 'c',
    ownerKeyPath: 'd',
    harmless: 'e',
  });
  assert.deepEqual(out, {
    apiToken: '[redacted]',
    sessionSecret: '[redacted]',
    privateSeed: '[redacted]',
    ownerKeyPath: '[redacted]',
    harmless: 'e',
  });
});

/* -------------------------------------------------------------------------- */
/* Endpoints                                                                   */
/* -------------------------------------------------------------------------- */

test('diagnostics are off until this API turns them on', () => {
  // LOCAL-SURFACE.md 2.4: the headers naming VayuWeb are available "only when explicitly enabled
  // through the control API", which means the control API is the only thing that can enable them.
  const control = ports();
  assert.deepEqual(handleControlRequest(request('GET', '/v1/diagnostics'), control, TOKEN).body, {
    enabled: false,
  });
  handleControlRequest(request('POST', '/v1/diagnostics/on'), control, TOKEN);
  assert.deepEqual(handleControlRequest(request('GET', '/v1/diagnostics'), control, TOKEN).body, {
    enabled: true,
  });
  handleControlRequest(request('POST', '/v1/diagnostics/off'), control, TOKEN);
  assert.deepEqual(handleControlRequest(request('GET', '/v1/diagnostics'), control, TOKEN).body, {
    enabled: false,
  });
});

test('an unknown endpoint is a 404 that still required the token', () => {
  assert.equal(handleControlRequest(request('GET', '/v1/nope'), ports(), TOKEN).status, 404);
  const unauthenticated = handleControlRequest(
    request('GET', '/v1/nope', { authorization: 'Bearer wrong' }),
    ports(),
    TOKEN,
  );
  assert.equal(unauthenticated.status, 401, 'endpoint discovery must not precede authentication');
});

test('health requires the token too', () => {
  // Deliberately not special-cased as an unauthenticated liveness probe. An unauthenticated
  // endpoint on this surface is an oracle for whether the resolver is running, and the socket's
  // existence already answers that for anyone who can see the filesystem.
  assert.equal(handleControlRequest(request('GET', '/v1/health'), ports(), TOKEN).status, 200);
  assert.equal(
    handleControlRequest(request('GET', '/v1/health', { authorization: '' }), ports(), TOKEN)
      .status,
    401,
  );
});

/* -------------------------------------------------------------------------- */
/* GET /v1/pins — the endpoint the honesty module had been waiting for         */
/* -------------------------------------------------------------------------- */

test('the pins endpoint exists at all, which it had not', () => {
  // RESOLUTION.md's endpoint list has carried `GET /v1/pins` since it was written, and `pins.ts` —
  // the module whose entire job is to refuse to overstate availability — was imported by nothing
  // that ships. A module nothing can reach cannot refuse anything.
  const answered = handleControlRequest(request('GET', '/v1/pins'), ports(), TOKEN);
  assert.equal(answered.status, 200);
});

test('a pin nobody was asked about says so, rather than reporting a zero', () => {
  // The whole reason this module exists. `answered: 0` out of `asked: 0` is not "nobody holds it";
  // it is "nobody was asked", and a client handed a bare zero renders the first one.
  const withPin: ControlPorts = {
    ...ports(),
    pins: () => [
      {
        cid: 'bafyexample',
        asked: 0,
        answered: 0,
        peersHolding: 0,
        servicesHolding: 0,
        selfPinned: true,
        observedAt: 1_782_518_400,
        availabilityUnguaranteed: true,
      },
    ],
  };
  const answered = handleControlRequest(request('GET', '/v1/pins'), withPin, TOKEN);
  const body = answered.body as { pins: Array<Record<string, unknown>> };
  assert.equal(body.pins.length, 1);
  const [pin] = body.pins;
  assert.ok(pin);
  assert.match(String(pin['summary']), /no peer has been asked/);
  assert.match(String(pin['summary']), /goes offline the site stops loading/);
  assert.equal(pin['onlyThisNodeHolds'], true, 'and the warning is computed, not left to a client');
  assert.equal(pin['availabilityUnguaranteed'], true);
  // The fields that would let a client render a guarantee are absent by construction, and this
  // asserts the absence rather than trusting the interface to keep it.
  for (const forbidden of ['total', 'percentage', 'durable', 'uptime', 'replicas']) {
    assert.equal(forbidden in pin, false, `a pin report must not carry ${forbidden}`);
  }
});

test('the pins endpoint is behind the token like everything else', () => {
  const unauthenticated = handleControlRequest(
    {
      method: 'GET',
      path: '/v1/pins',
      headers: new Map([[CONTROL_HEADER, '1']]),
      body: new Uint8Array(0),
    },
    ports(),
    TOKEN,
  );
  assert.equal(unauthenticated.status, 401);
});

/* -------------------------------------------------------------------------- */
/* The routes that carry a name — an untrusted string reaching a router        */
/* -------------------------------------------------------------------------- */

test('I put a traversal, an encoded traversal and a control character in the path', () => {
  // The first value a *user* types that reaches this API's routing. Every other endpoint is a
  // constant. LOCAL-SURFACE.md 3.1 imposes the ordering the browsing proxy follows and the reason
  // is unchanged here: validate against the grammar **before** the value is echoed, keyed, logged
  // or passed onward, because a check that runs after any of those ran too late.
  //
  // Decoding happens first and the grammar decides second, deliberately: a percent-encoded
  // traversal checked before decoding is a traversal that was not checked.
  const hostile = [
    '../../../etc/passwd',
    '..%2f..%2fetc%2fpasswd',
    '%2e%2e%2f.vayu',
    'atlas.vayu/../secrets',
    'atlas%00.vayu',
    'atlas.vayu%0d%0aX-Injected:%201',
    'atlas.notaratifiedtld',
    'UPPER_CASE.vayu',
    '.vayu',
    'atlas.',
    '%zz',
    '',
  ];
  for (const name of hostile) {
    const answered = handleControlRequest(request('GET', `/v1/records/${name}`), ports(), TOKEN);
    assert.equal(
      answered.status === 400 || answered.status === 404,
      true,
      `${name} -> ${answered.status}`,
    );
    assert.notEqual(answered.status, 200, `${name} must not resolve`);
  }
});

test('a legitimately encoded name is accepted, which is what decoding is for', () => {
  // Found by a mutation that survived, which showed the comment above this code was crediting the
  // safety to the wrong line. `..%2f..` fails the label grammar exactly as `../..` does — neither
  // `%` nor `/` nor `.` is in it — so decoding is not what stops a traversal. It is what lets an
  // encoded name through, which makes the check MORE permissive, and that is the behaviour a test
  // has to pin because it is the behaviour that would otherwise quietly disappear.
  const encoded = handleControlRequest(
    request('GET', '/v1/records/atlasobservatory%2Evayu'),
    ports(),
    TOKEN,
  );
  assert.equal(encoded.status, 200);
  assert.equal((encoded.body as Record<string, unknown>)['name'], 'atlasobservatory.vayu');
});

test('the answer names the validated name, never the bytes that were sent', () => {
  // Also a surviving mutation: the earlier test asked for a name that was already lowercase and
  // unencoded, so echoing the raw path and echoing the validated name produced the same string.
  // A test that cannot tell the two apart is a test that permits the wrong one.
  const answered = handleControlRequest(
    request('GET', '/v1/records/ATLASOBSERVATORY.VAYU'),
    ports(),
    TOKEN,
  );
  assert.equal(answered.status, 200);
  assert.equal((answered.body as Record<string, unknown>)['name'], 'atlasobservatory.vayu');
});

test('a name that is a name is routed, and its answer names it back exactly once', () => {
  const answered = handleControlRequest(
    request('GET', '/v1/records/atlasobservatory.vayu'),
    ports(),
    TOKEN,
  );
  assert.equal(answered.status, 200);
  const body = answered.body as Record<string, unknown>;
  assert.equal(body['name'], 'atlasobservatory.vayu');
  // Echoed from the VALIDATED parts, not from the request. A router that echoed the raw path
  // would hand back whatever was sent, which is the shape every response-splitting bug has.
  assert.equal(body['error'], 'NAME_NOT_FOUND');
});

test('/v1/cache/stats is a route and not a name', () => {
  // `stats` sits on the same prefix as `DELETE /v1/cache/{name}`. A router that read it as a name
  // would answer a flush for a site called "stats", and a router that read every name as `stats`
  // would answer statistics for a flush.
  const stats = handleControlRequest(request('GET', '/v1/cache/stats'), ports(), TOKEN);
  assert.equal(stats.status, 200);
  assert.deepEqual(stats.body, { negative: 1, positive: 2, manifests: 3, hits: 4, misses: 5 });
  assert.equal(
    'bytes' in (stats.body as object),
    false,
    'nothing measures bytes, so no number is reported for them',
  );

  // And the DELETE on the bare path is the flush-everything route, not a flush of nothing.
  const all = handleControlRequest(request('DELETE', '/v1/cache'), ports(), TOKEN);
  assert.deepEqual(all.body, { flushed: 6 });

  const one = handleControlRequest(
    request('DELETE', '/v1/cache/atlasobservatory.vayu'),
    ports(),
    TOKEN,
  );
  assert.deepEqual(one.body, { flushed: 1 });
});

test('the named routes are behind the token like every other one', () => {
  // Worth its own assertion because these routes are matched BEFORE the exact-path switch, and a
  // match that ran before the token check would be an endpoint anyone could reach.
  for (const path of ['/v1/records/atlasobservatory.vayu', '/v1/cache/atlasobservatory.vayu']) {
    const answered = handleControlRequest(
      {
        method: path.includes('records') ? 'GET' : 'DELETE',
        path,
        headers: new Map([[CONTROL_HEADER, '1']]),
        body: new Uint8Array(0),
      },
      ports(),
      TOKEN,
    );
    assert.equal(answered.status, 401, path);
  }
});

test('a peer count from a process that opens no connection says so', () => {
  // A zero that reads like a measurement is worse than a sentence. This command serves; syncing is
  // a different command, and the answer says which.
  const answered = handleControlRequest(request('GET', '/v1/peers'), ports(), TOKEN);
  assert.equal(answered.status, 200);
  assert.deepEqual(answered.body, { joined: false, peers: 0, detail: 'not joined' });
});

test('a port cannot overwrite the name the router validated', () => {
  // The ordering that let a mutation hide. With `{ name, ...port }` the collaborator is spread
  // last and decides it — and the value a router echoes must be decided where it is validated,
  // not by whatever happens to be spread over it.
  const shouting: ControlPorts = {
    ...ports(),
    resolve: () => ({ name: 'something-else.entirely', outcome: 'ok' }),
  };
  const answered = handleControlRequest(
    request('GET', '/v1/records/atlasobservatory.vayu'),
    shouting,
    TOKEN,
  );
  assert.equal((answered.body as Record<string, unknown>)['name'], 'atlasobservatory.vayu');
});

/* -------------------------------------------------------------------------- */
/* POST /v1/resolve — the first endpoint whose argument is not a path          */
/* -------------------------------------------------------------------------- */

test('a name in a body is validated by the same grammar as a name in a path', () => {
  // Two spellings of one grammar is how the two disagree later, and whoever finds the
  // disagreement finds it through the more permissive one. `parseControlName` is the only
  // implementation; this asserts the body route reaches it rather than reimplementing it.
  for (const bad of [
    '../../etc/passwd',
    '..%2f..%2fetc%2fpasswd',
    'atlasobservatory.notaratifiedtld',
    'atlasobservatory',
    '.vayu',
    'atlasobservatory.',
    'UPPER CASE.vayu',
    'atlas observatory.vayu',
    '%ZZ.vayu',
  ]) {
    const response = handleControlRequest(
      withBody('POST', '/v1/resolve', JSON.stringify({ name: bad })),
      ports(),
      TOKEN,
    );
    assert.equal(response.status, 400, bad);
    assert.deepEqual(response.body, { error: 'bad_name' }, bad);
  }
});

test('a valid name in a body resolves, and the echo is the validated name', () => {
  const response = handleControlRequest(
    withBody('POST', '/v1/resolve', JSON.stringify({ name: 'AtlasObservatory.VAYU' })),
    ports(),
    TOKEN,
  );
  assert.equal(response.status, 200);
  const body = response.body as Record<string, unknown>;
  // Lowercased by the grammar, not echoed as sent — and the port saw the same two components.
  assert.equal(body['name'], 'atlasobservatory.vayu');
  assert.equal(body['asked'], 'atlasobservatory/vayu');
});

test('a body that is not a JSON object is refused, including the ones that nearly work', () => {
  for (const raw of ['', 'not json', '[]', '"atlasobservatory.vayu"', 'null', '42', '{']) {
    const response = handleControlRequest(withBody('POST', '/v1/resolve', raw), ports(), TOKEN);
    assert.equal(response.status, 400, JSON.stringify(raw));
    assert.deepEqual(response.body, { error: 'bad_request' }, JSON.stringify(raw));
  }
});

test('MUTATION: an array is refused by the parser, which is the only place it is visible', () => {
  // The test above cannot see this. `[]`, `"x"` and `null` all read `.name` as undefined and take
  // the missing-field branch, so the handler answers `bad_request` whether or not arrays are
  // rejected — the right answer by accident. Dropping `Array.isArray` survived the whole suite for
  // exactly that reason, and an array's own keys are `"0"`, `"1"`, … so no body can ever make the
  // difference reach the handler. The property belongs to the parser, so it is asserted there.
  const parse = (raw: string) => jsonObject(new TextEncoder().encode(raw));
  assert.equal(parse('[]'), null, 'an array is not an object');
  assert.equal(parse('[{"name":"atlasobservatory.vayu"}]'), null);
  assert.equal(parse('null'), null);
  assert.equal(parse('"atlasobservatory.vayu"'), null);
  assert.equal(parse('42'), null);
  const object = parse('{"name":"atlasobservatory.vayu"}');
  assert.equal(object?.['name'], 'atlasobservatory.vayu', 'and an object is one');
  // Null-prototype on purpose, so a body cannot reach `toString`, `constructor` or anything else
  // it did not put there. Pinned because `deepEqual` is what noticed it, and a property noticed by
  // accident is a property that gets removed by accident.
  assert.equal(Object.getPrototypeOf(object), null, 'the parsed object has no prototype');
});

test('MUTATION: a body that is not valid UTF-8 is refused rather than silently repaired', () => {
  // Dropping `{ fatal: true }` also survived, and this one is not cosmetic: an invalid byte
  // becomes U+FFFD, the body then parses, and a request carrying bytes the client never sent is
  // answered 200. The name is deliberately VALID here — with the decoder repairing, everything
  // downstream succeeds and nothing reports that the body was altered on the way in.
  const repaired = Buffer.from('{"name":"atlasobservatory.vayu","x":"\xff"}', 'latin1');
  assert.equal(jsonObject(repaired), null, 'invalid UTF-8 is not a body');
  const response = handleControlRequest(
    request('POST', '/v1/resolve', {}, repaired),
    ports(),
    TOKEN,
  );
  assert.equal(response.status, 400, 'and the endpoint refuses it rather than answering 200');
  assert.deepEqual(response.body, { error: 'bad_request' });
});

test('a `name` that is not a string is refused rather than coerced', () => {
  for (const raw of ['{"name":null}', '{"name":42}', '{"name":["a.vayu"]}', '{"other":"a.vayu"}']) {
    const response = handleControlRequest(withBody('POST', '/v1/resolve', raw), ports(), TOKEN);
    assert.equal(response.status, 400, raw);
    assert.deepEqual(response.body, { error: 'bad_request' }, raw);
  }
});

test('a body cannot reach a property nobody put there', () => {
  // JSON.parse produces an own `__proto__` key rather than setting a prototype, so a plain
  // property read off the parsed object is not the risk a prototype-chain read would be. The
  // assertion is that the handler still refuses: `name` is absent whatever `__proto__` says.
  const response = handleControlRequest(
    withBody('POST', '/v1/resolve', '{"__proto__":{"name":"atlasobservatory.vayu"}}'),
    ports(),
    TOKEN,
  );
  assert.equal(response.status, 400);
  assert.deepEqual(response.body, { error: 'bad_request' });
});

test('a body is not accepted in place of the token', () => {
  const response = handleControlRequest(
    {
      method: 'POST',
      path: '/v1/resolve',
      headers: new Map([[CONTROL_HEADER, '1']]),
      body: new TextEncoder().encode(JSON.stringify({ name: 'atlasobservatory.vayu' })),
    },
    ports(),
    TOKEN,
  );
  assert.equal(response.status, 401);
});

test('a body on an endpoint that takes none changes nothing about the answer', () => {
  // The transport bounds the body; the handler decides who reads it. An endpoint that ignores one
  // must ignore it completely rather than let it influence the response.
  const plain = handleControlRequest(request('GET', '/v1/status'), ports(), TOKEN);
  const noisy = handleControlRequest(
    withBody('GET', '/v1/status', '{"mode":"tor","version":"9.9.9"}'),
    ports(),
    TOKEN,
  );
  assert.deepEqual(noisy.body, plain.body);
});

/* -------------------------------------------------------------------------- */
/* POST /v1/pin and DELETE /v1/pin/{cid}                                       */
/* -------------------------------------------------------------------------- */

const HELD_CID = 'bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e';
const ABSENT_CID = 'bafkreiaxlvczbcuvhwjrwqmz2s6lrx3zjrxpjnpbcvi3ohbrhkuuwqmxbe';

test('a pin is refused for content this node cannot serve, and says so', () => {
  // The endpoint's whole risk is becoming a register of intentions that reads like a register of
  // holdings. A node with no fetcher cannot make itself hold a stranger's CID, and answering 200
  // would put that fiction into `GET /v1/pins` beside a real one.
  const control = ports();
  const response = handleControlRequest(
    withBody('POST', '/v1/pin', JSON.stringify({ cid: ABSENT_CID })),
    control,
    TOKEN,
  );
  assert.equal(response.status, 409);
  assert.deepEqual(response.body, { error: 'not_held' });
});

test('a pin is taken for content this node holds, and shows up in the pin list', () => {
  const control = ports();
  const taken = handleControlRequest(
    withBody('POST', '/v1/pin', JSON.stringify({ cid: HELD_CID })),
    control,
    TOKEN,
  );
  assert.equal(taken.status, 200);
  assert.deepEqual(taken.body, { cid: HELD_CID, outcome: 'pinned' });

  const listed = handleControlRequest(request('GET', '/v1/pins'), control, TOKEN);
  const body = listed.body as { pins: Array<Record<string, unknown>> };
  assert.equal(body.pins.length, 1);
  assert.equal(body.pins[0]?.['cid'], HELD_CID);
});

test('a CID is validated before it is used for anything at all', () => {
  // LOCAL-SURFACE.md 3.1's ordering, applied to the other kind of value a user types. A CID that
  // is not a CID must never reach a pin set, a log line or an echo.
  const control = ports();
  for (const bad of ['', 'not-a-cid', '../../etc/passwd', 'Qm' + 'a'.repeat(44), 'bafkrei!!!']) {
    const response = handleControlRequest(
      withBody('POST', '/v1/pin', JSON.stringify({ cid: bad })),
      control,
      TOKEN,
    );
    assert.equal(response.status, 400, JSON.stringify(bad));
    assert.deepEqual(response.body, { error: 'bad_cid' }, JSON.stringify(bad));
  }
});

test('unpinning is idempotent and reports which of the two happened', () => {
  const control = ports();
  handleControlRequest(
    withBody('POST', '/v1/pin', JSON.stringify({ cid: HELD_CID })),
    control,
    TOKEN,
  );

  const first = handleControlRequest(request('DELETE', `/v1/pin/${HELD_CID}`), control, TOKEN);
  assert.equal(first.status, 200);
  assert.deepEqual(first.body, { cid: HELD_CID, unpinned: true });

  const again = handleControlRequest(request('DELETE', `/v1/pin/${HELD_CID}`), control, TOKEN);
  assert.equal(again.status, 200, 'DELETE is idempotent; the second is not an error');
  assert.deepEqual(again.body, { cid: HELD_CID, unpinned: false });
});

test('an unpin path carrying something that is not a CID is a 400, not a 404', () => {
  // The truthful distinction between "no such endpoint" and "that is not a CID" — the same one
  // `namedRoute` draws for names.
  const control = ports();
  for (const bad of ['not-a-cid', '..%2f..%2fetc', 'bafkrei!!!']) {
    const response = handleControlRequest(request('DELETE', `/v1/pin/${bad}`), control, TOKEN);
    assert.equal(response.status, 400, bad);
    assert.deepEqual(response.body, { error: 'bad_cid' }, bad);
  }
});

test('the pin routes are behind the token like every other one', () => {
  const control = ports();
  const posted = handleControlRequest(
    {
      method: 'POST',
      path: '/v1/pin',
      headers: new Map([[CONTROL_HEADER, '1']]),
      body: new TextEncoder().encode(JSON.stringify({ cid: HELD_CID })),
    },
    control,
    TOKEN,
  );
  assert.equal(posted.status, 401);
  const deleted = handleControlRequest(
    {
      method: 'DELETE',
      path: `/v1/pin/${HELD_CID}`,
      headers: new Map([[CONTROL_HEADER, '1']]),
      body: new Uint8Array(0),
    },
    control,
    TOKEN,
  );
  assert.equal(deleted.status, 401);
  assert.equal(control.pins().length, 0, 'and neither reached the pin set');
});
