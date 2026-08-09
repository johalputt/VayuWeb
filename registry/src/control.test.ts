import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import {
  CONTROL_HEADER,
  TOKEN_BYTES,
  assertSocketAddress,
  handleControlRequest,
  redact,
  tokenMatches,
  type ControlPorts,
  type ControlRequest,
} from './control.ts';

const TOKEN = randomBytes(TOKEN_BYTES).toString('base64url');

const ports = (): ControlPorts => {
  let diagnostics = false;
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
    pins: () => [],
  };
};

function request(
  method: string,
  path: string,
  headers: Record<string, string> = {},
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
  };
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
    { method: 'GET', path: '/v1/pins', headers: new Map([[CONTROL_HEADER, '1']]) },
    ports(),
    TOKEN,
  );
  assert.equal(unauthenticated.status, 401);
});
