import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  ConnectionCounter,
  SERVE_LIMITS,
  ServeError,
  framing,
  parseHead,
  serveControl,
  serveProxy,
  type Listener,
} from './serve.ts';
import type { ResolverPorts } from './resolve.ts';
import type { ControlPorts } from './control.ts';
import { CID_PARAMETERS, cidBytes, sha256 } from './content.ts';
import { parseRecord } from './record.ts';
import { POW_ALGORITHM, POW_NONCE_LENGTH } from './pow.ts';
import type { CborValue } from './cbor.ts';

/** The code a parse refuses with, or 'accepted'. */
function refusal(run: () => unknown): string {
  try {
    run();
    return 'accepted';
  } catch (error) {
    return error instanceof ServeError ? error.code : `threw:${String(error)}`;
  }
}

const head = (...lines: string[]): string => lines.join('\r\n');

/* -------------------------------------------------------------------------- */
/* The parser, which is where bytes from strangers are first interpreted        */
/* -------------------------------------------------------------------------- */

test('a well-formed head parses into method, target and lowercased headers', () => {
  const parsed = parseHead(head('GET /page HTTP/1.1', 'Host: atlas.vayu', 'X-Thing: v'));
  assert.equal(parsed.method, 'GET');
  assert.equal(parsed.target, '/page');
  assert.equal(parsed.headers.get('host'), 'atlas.vayu');
  assert.equal(parsed.headers.get('x-thing'), 'v');
});

test('obsolete line folding is refused rather than unfolded', () => {
  // RFC 7230 3.2.4 deprecates it, and it is the classic disagreement between two parsers: one
  // unfolds and sees one header, the other does not and sees two. A proxy serving one browser on
  // loopback has no compatibility argument for accepting it.
  //
  // The PROPERTY is what this pins, not the line of code that delivers it. Deleting the explicit
  // fold check does not change any outcome here, and re-mutation is how that was found: a folded
  // line either has no colon, or has one whose name begins with whitespace and therefore is not a
  // token. Both are already refused. The guard is redundant and its comment in `serve.ts` now
  // says so, rather than reading as load-bearing to the next person.
  for (const folded of [' continued', '\tcontinued', ' evil: injected', '\tevil: injected']) {
    assert.equal(
      refusal(() => parseHead(head('GET / HTTP/1.1', 'Host: a.vayu', folded))),
      'MALFORMED_REQUEST',
      JSON.stringify(folded),
    );
  }
});

test('a duplicate header is refused rather than resolved', () => {
  // First-wins and last-wins are both defensible, which is the problem: a header two parsers
  // resolve differently is a request two parsers read differently, and that is the whole shape of
  // request smuggling. Refusing needs no reading of anybody's mind.
  assert.equal(
    refusal(() => parseHead(head('GET / HTTP/1.1', 'Host: a.vayu', 'Host: b.vayu'))),
    'MALFORMED_REQUEST',
  );
});

test('a malformed request line is refused in each of its forms', () => {
  const cases: [string, string][] = [
    ['no version', head('GET /')],
    ['four fields', head('GET / HTTP/1.1 extra')],
    ['unsupported version', head('GET / HTTP/2.0')],
    ['lowercase method', head('get / HTTP/1.1')],
    ['empty target', head('GET  HTTP/1.1')],
    ['empty line', ''],
  ];
  for (const [why, text] of cases) {
    assert.equal(
      refusal(() => parseHead(text)),
      'MALFORMED_REQUEST',
      why,
    );
  }
});

test('a header name that is not a token is refused', () => {
  assert.equal(
    refusal(() => parseHead(head('GET / HTTP/1.1', 'Bad Header: v'))),
    'MALFORMED_REQUEST',
  );
  assert.equal(
    refusal(() => parseHead(head('GET / HTTP/1.1', ': novalue'))),
    'MALFORMED_REQUEST',
  );
});

test('too many header lines is refused, and counted independently of total size', () => {
  const many = ['GET / HTTP/1.1'];
  for (let i = 0; i <= SERVE_LIMITS.headerLines; i += 1) many.push(`x-h${i}: v`);
  assert.equal(
    refusal(() => parseHead(head(...many))),
    'TOO_MANY_HEADERS',
  );
});

test('an over-long target is refused before any routing happens', () => {
  const long = `/${'a'.repeat(4096)}`;
  assert.equal(
    refusal(() => parseHead(head(`GET ${long} HTTP/1.1`))),
    'MALFORMED_REQUEST',
  );
});

/* -------------------------------------------------------------------------- */
/* The listeners                                                               */
/* -------------------------------------------------------------------------- */

/** Speak one request to an address and return the raw response. */
function speak(address: string, request: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = address.includes(':')
      ? connect(Number(address.split(':')[1]), '127.0.0.1')
      : connect(address);
    let out = '';
    socket.setEncoding('utf8');
    socket.on('connect', () => socket.write(request));
    socket.on('data', (chunk: string) => {
      out += chunk;
    });
    socket.on('close', () => resolve(out));
    socket.on('error', reject);
  });
}

const resolverPorts: ResolverPorts = {
  lookup: () => null,
  hasVerifiedHead: () => true,
};

const controlPorts: ControlPorts = {
  status: () => ({ mode: 'clearnet', uptime: 1, listeners: ['127.0.0.1:7654'] }),
  version: () => '0.0.0-test',
  logHead: () => ({ length: 0, root: '00'.repeat(32) }),
  config: () => ({ token: 'secret-value-that-must-not-appear' }),
  diagnostics: () => false,
  setDiagnostics: () => undefined,
  pins: () => [],
  resolve: (label, tld) => ({ outcome: 'error', error: 'NAME_NOT_FOUND', name: `${label}.${tld}` }),
  cacheStats: () => ({ negative: 1, positive: 2, manifests: 3, hits: 4, misses: 5 }),
  flushCache: (name) => (name === null ? 6 : 1),
  peers: () => ({ joined: false, peers: 0, detail: 'not joined' }),
  pin: () => 'not_held' as const,
  unpin: () => false,
  rotateToken: () => randomBytes(32).toString('base64url'),
  patchCacheSizes: (sizes) => ({ cacheSizes: sizes }),
};

async function withListener(make: () => Promise<Listener>, run: (l: Listener) => Promise<void>) {
  const listener = await make();
  try {
    await run(listener);
  } finally {
    await listener.close();
  }
}

test('the proxy binds loopback and answers a real request', async () => {
  await withListener(
    () => serveProxy({ ports: resolverPorts, port: 0, now: () => 1_782_518_400 }),
    async (listener) => {
      assert.ok(listener.address.startsWith('127.0.0.1:'), listener.address);
      const answer = await speak(listener.address, 'GET / HTTP/1.1\r\nHost: atlas.vayu\r\n\r\n');
      assert.match(answer, /^HTTP\/1\.1 \d{3} /);
      // Whatever the outcome, the security headers the specification enumerates are on it. The
      // resolver has no records, so this is a refusal — and a refusal is exactly the response an
      // implementation is most likely to emit bare.
      assert.match(answer, /content-security-policy: /i);
      assert.match(answer, /permissions-policy: /i);
      assert.match(answer, /connection: close/i);
    },
  );
});

test('a head that never ends is refused on size rather than buffered', async () => {
  await withListener(
    () => serveProxy({ ports: resolverPorts, port: 0, now: () => 1_782_518_400 }),
    async (listener) => {
      // No blank line, ever. An unbounded buffer here costs the sender nothing and the resolver
      // everything, which is the cheapest denial of service a loopback listener can offer.
      const flood = `GET / HTTP/1.1\r\nHost: a.vayu\r\nx-pad: ${'a'.repeat(SERVE_LIMITS.headBytes)}\r\n`;
      const answer = await speak(listener.address, flood);
      assert.match(answer, /^HTTP\/1\.1 431 /);
      assert.match(answer, /HEAD_TOO_LARGE/);
    },
  );
});

test('a malformed head is answered with a status rather than a dropped connection', async () => {
  await withListener(
    () => serveProxy({ ports: resolverPorts, port: 0, now: () => 1_782_518_400 }),
    async (listener) => {
      const answer = await speak(listener.address, 'GET /\r\n\r\n');
      assert.match(answer, /^HTTP\/1\.1 400 /);
    },
  );
});

/* -------------------------------------------------------------------------- */
/* AUDIT: the connection cap leaked a slot on every refusal                     */
/* -------------------------------------------------------------------------- */

test('AUDIT: a refused connection consumes no slot at all', () => {
  // Found by attacking `serve.ts` rather than by reading it. The accounting was inline and the
  // refusal path incremented the counter, then returned BEFORE registering the handler that
  // gives the slot back. Every refusal therefore leaked one slot for the lifetime of the
  // process, and an attacker who could cause as many refusals as the cap allows killed the
  // listener permanently: no crash, no log entry, just a resolver answering 503 to its own user
  // forever.
  //
  // The first attempt to reproduce it through real sockets did not land, and that is why this
  // class exists. The client's `connect` event fires before the server's `connection` handler
  // for later sockets, so three concurrent dials never reliably put three connections in flight.
  // A defect that can only be reproduced by racing the operating system is a defect with no
  // regression test.
  const counter = new ConnectionCounter(2);
  assert.equal(counter.admit(), true);
  assert.equal(counter.admit(), true);
  assert.equal(counter.admit(), false, 'the third is over the cap');
  assert.equal(counter.inUse, 2, 'and the refusal took no slot — this is the whole finding');

  // Every refusal, forever, still takes nothing.
  for (let i = 0; i < 1_000; i += 1) assert.equal(counter.admit(), false);
  assert.equal(counter.inUse, 2);

  // And the listener recovers completely once the real connections close.
  counter.release();
  counter.release();
  assert.equal(counter.inUse, 0);
  assert.equal(counter.admit(), true, 'the listener still works after a thousand refusals');
});

test('AUDIT: a double close cannot mint capacity', () => {
  // The mirror of the leak. `close` can fire more than once on a socket, and a counter that
  // decrements below zero hands out slots it does not have — turning the cap into a suggestion
  // for anybody who can get a socket to close twice.
  const counter = new ConnectionCounter(1);
  assert.equal(counter.admit(), true);
  counter.release();
  counter.release();
  counter.release();
  assert.equal(counter.inUse, 0, 'never negative');
  assert.equal(counter.admit(), true);
  assert.equal(counter.admit(), false, 'the cap is still one');
});

test('AUDIT: the listener survives a burst that includes refusals', async () => {
  // The end-to-end half, kept because the unit test above cannot prove the counter is wired in.
  // It does not attempt to force a refusal — that is what made the first version unreliable —
  // it checks that ordinary traffic through the real listener leaves it working.
  await withListener(
    () =>
      serveProxy({ ports: resolverPorts, port: 0, now: () => 1_782_518_400, maxConnections: 2 }),
    async (listener) => {
      for (let i = 0; i < 6; i += 1) {
        const answer = await speak(listener.address, 'GET / HTTP/1.1\r\nHost: a.vayu\r\n\r\n');
        assert.doesNotMatch(answer, /TOO_MANY_CONNECTIONS/, `request ${i} was refused`);
      }
    },
  );
});

/* -------------------------------------------------------------------------- */
/* The control API, which a browser must never reach                           */
/* -------------------------------------------------------------------------- */

test('the control API refuses a TCP address before it binds anything', async () => {
  // The guard is at the boundary rather than in a document, because the document already said it
  // and five specifications went on naming a loopback port anyway. A thrown error and a listening
  // socket are very different outcomes for the same mistake.
  //
  // The retired port number is not written here even as a fixture: `scripts/check-listeners.py`
  // refuses any mention of it, so that it cannot be reintroduced by somebody copying a line that
  // looked authoritative. These addresses are the same shape without being the same number.
  for (const bad of ['127.0.0.1:7000', 'localhost:7000', '0.0.0.0:1', '[::1]:7000']) {
    await assert.rejects(
      async () =>
        serveControl({
          ports: controlPorts,
          path: bad,
          token: () => randomBytes(32).toString('base64url'),
        }),
      /TCP|address|socket/i,
      bad,
    );
  }
});

test('a control token that could never authenticate is refused at bind', async () => {
  // A token that does not decode to 32 bytes can never match, so the resolver binds a control API
  // nobody can reach -- and says nothing, because every request answers 401 exactly as a wrong
  // guess would. That is a misconfiguration indistinguishable from an attack, and the only moment
  // anybody is looking at it is startup.
  //
  // Found by writing these tests with a 64-character token that decodes to 48 bytes, watching
  // every request 401, and having nothing to tell me whether the token or the code was wrong.
  const directory = mkdtempSync(join(tmpdir(), 'vayuweb-control-'));
  for (const bad of ['a'.repeat(64), 'short', '', randomBytes(16).toString('base64url')]) {
    await assert.rejects(
      async () =>
        serveControl({ ports: controlPorts, path: join(directory, 'x.sock'), token: () => bad }),
      /could ever authenticate/,
      JSON.stringify(bad.slice(0, 12)),
    );
  }
});

test('the control socket is 0600 inside a 0700 directory', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'vayuweb-control-'));
  const path = join(directory, 'nested', 'control.sock');
  // The directory is created ALREADY WRONG, which is the only case the explicit chmod exists for.
  // `mkdirSync`'s mode is masked by umask and skipped entirely for a directory that already
  // exists, so a test that lets the resolver create a fresh directory is testing mkdir rather
  // than the tightening -- and it passed with the chmod deleted.
  mkdirSync(join(directory, 'nested'), { recursive: true });
  chmodSync(join(directory, 'nested'), 0o777);
  assert.equal(statSync(join(directory, 'nested')).mode & 0o777, 0o777, 'fixture must start open');
  await withListener(
    () =>
      serveControl({
        ports: controlPorts,
        path,
        token: () => randomBytes(32).toString('base64url'),
      }),
    async () => {
      // A socket anyone on the machine can connect to is a control API anyone on the machine has;
      // a 0600 socket in a world-writable directory is one anybody can replace. Both halves are
      // asserted, because either alone leaves the surface open.
      assert.equal(statSync(path).mode & 0o777, 0o600, 'socket mode');
      assert.equal(statSync(join(directory, 'nested')).mode & 0o777, 0o700, 'directory mode');
    },
  );
});

/**
 * A correctly-formed control request.
 *
 * `x-vayuweb-control` is a fixed marker rather than the credential — a header a browser cannot
 * set cross-origin — and the token travels in `Authorization`. The first version of these tests
 * put the token in the marker header, so every request 403'd. That made the disclosure test below
 * pass while asserting nothing: a 403 body trivially contains no secret. A negative assertion
 * that never reaches the code it is about is the failure mode this repository keeps finding, and
 * `authorised()` exists so the two tests cannot drift apart from the real header contract again.
 */
const authorised = (path: string, token: string, extra = ''): string =>
  `GET ${path} HTTP/1.1\r\nx-vayuweb-control: 1\r\nauthorization: Bearer ${token}\r\n${extra}\r\n`;

test('the control API answers over the socket and refuses a wrong token', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'vayuweb-control-'));
  const path = join(directory, 'control.sock');
  const token = randomBytes(32).toString('base64url');
  await withListener(
    () => serveControl({ ports: controlPorts, path, token: () => token }),
    async (listener) => {
      const good = await speak(listener.address, authorised('/v1/status', token));
      assert.match(good, /^HTTP\/1\.1 200 /);
      // Past the token check, so the version is disclosed here and nowhere else.
      assert.match(good, /0\.0\.0-test/);

      const wrong = await speak(
        listener.address,
        authorised('/v1/status', randomBytes(32).toString('base64url')),
      );
      assert.match(wrong, /^HTTP\/1\.1 401 /, 'a wrong token is unauthorised, not merely not-200');

      // Without the marker header at all: a request a browser could actually make.
      const bare = await speak(
        listener.address,
        `GET /v1/status HTTP/1.1\r\nauthorization: Bearer ${token}\r\n\r\n`,
      );
      assert.match(bare, /^HTTP\/1\.1 403 /);

      // A browser attaches Origin to anything cross-origin it sends. Nothing that legitimately
      // speaks to this API has one, so its presence is disqualifying on its own — and a correct
      // token must not rescue it.
      const withOrigin = await speak(
        listener.address,
        authorised('/v1/status', token, 'origin: http://atlas.vayu\r\n'),
      );
      assert.match(withOrigin, /^HTTP\/1\.1 403 /);
    },
  );
});

test('the control API does not disclose a secret it was handed', async () => {
  // `config()` returns whatever the resolver holds, and a control API that echoes it verbatim
  // publishes the token to anyone who already has the token — which sounds harmless until the
  // response is in a log, a screenshot or a bug report.
  const directory = mkdtempSync(join(tmpdir(), 'vayuweb-control-'));
  const path = join(directory, 'control.sock');
  const token = randomBytes(32).toString('base64url');
  await withListener(
    () => serveControl({ ports: controlPorts, path, token: () => token }),
    async (listener) => {
      const answer = await speak(listener.address, authorised('/v1/config', token));
      // The request must actually SUCCEED, or the assertion below is about a 403 body.
      assert.match(answer, /^HTTP\/1\.1 200 /, 'the disclosure check needs a real response');
      assert.doesNotMatch(answer, /secret-value-that-must-not-appear/);
      assert.match(answer, /REDACTED|\*{3}/i, 'and the key is present but redacted, not dropped');
    },
  );
});

/* -------------------------------------------------------------------------- */
/* AUDIT: the body between the handler and the socket                          */
/* -------------------------------------------------------------------------- */

/**
 * Speak to a listener and keep the answer as BYTES.
 *
 * `speak` above sets the socket encoding to utf8, which is exactly the transformation the test
 * below exists to detect — a body corrupted on the way out would be corrupted a second time on the
 * way in, and the two damages do not cancel. Reading the response as buffers is not a stylistic
 * difference here; it is the only way this assertion can be about the wire.
 */
function speakBytes(address: string, request: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = connect(Number(address.split(':')[1]), '127.0.0.1');
    const chunks: Buffer[] = [];
    socket.on('connect', () => socket.write(request));
    socket.on('data', (chunk: Buffer) => chunks.push(chunk));
    socket.on('close', () => resolve(Buffer.concat(chunks)));
    socket.on('error', reject);
  });
}

/** The bytes after the head terminator — what a browser would actually save to a file. */
function bodyOf(answer: Buffer): Buffer {
  const split = answer.indexOf('\r\n\r\n');
  assert.notEqual(split, -1, 'a response must have a head terminator');
  return answer.subarray(split + 4);
}

const SERVE_NOW = 1_782_518_400;

const SERVED_DIGEST = sha256(new TextEncoder().encode('atlas observatory'));
const SERVED_CID = cidBytes({
  version: 1,
  codec: CID_PARAMETERS.codecDagPb,
  digest: SERVED_DIGEST,
});

/** A resolver holding one live name pointing at one CID. */
function servingPorts(): ResolverPorts {
  const record = parseRecord(
    new Map<string | Uint8Array, CborValue>([
      ['version', 1],
      ['suite', 1],
      ['op', 'REGISTER'],
      ['name', 'atlas'],
      ['tld', 'vayu'],
      ['ownerKey', new Uint8Array(32).fill(0x11)],
      ['seq', 0],
      ['notBefore', SERVE_NOW - 10],
      ['notAfter', SERVE_NOW + 31_536_000],
      [
        'records',
        [
          new Map<string | Uint8Array, CborValue>([
            ['type', 'cid'],
            ['value', SERVED_CID],
          ]),
        ],
      ],
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
  return { lookup: () => record, hasVerifiedHead: () => true };
}

test('AUDIT: a fetched body reaches the wire byte for byte', async () => {
  // **This test exists because a mutation survived the one that was supposed to cover it.**
  //
  // The corruption was a PAIR: `proxy.ts` widened the fetched bytes to a latin-1 string and
  // `writeHttp` narrowed them again as UTF-8, so every octet above 0x7f became two. The audit test
  // in `proxy.test.ts` pins the first half — and only the first half, because it stops at
  // `handleRequest`. Re-encoding the payload inside `writeHttp` afterwards left all 44 tests green
  // while every image served through the real listener was still destroyed.
  //
  // A test named "reaches the socket" that never opens a socket is the same class of defect as the
  // comment that claimed the body was bytes all the way down. This one binds the listener.
  const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
  await withListener(
    () =>
      serveProxy({
        ports: servingPorts(),
        port: 0,
        now: () => SERVE_NOW,
        options: {
          content: {
            fetch: () => ({ ok: true, bytes, contentType: 'application/octet-stream' }),
          },
        },
      }),
    async (listener) => {
      const answer = await speakBytes(
        listener.address,
        'GET / HTTP/1.1\r\nHost: atlas.vayu\r\n\r\n',
      );
      assert.match(answer.subarray(0, 15).toString('latin1'), /^HTTP\/1\.1 200 /);
      const body = bodyOf(answer);
      // Length first: a doubled octet shows here as a size, which is the failure a reader can act
      // on without diffing 256 numbers.
      assert.equal(body.length, bytes.length, 'the body must not grow on the way out');
      assert.deepEqual(Uint8Array.from(body), bytes);
      // And content-length agrees with what was actually written, or a browser truncates or hangs.
      const head = answer.subarray(0, answer.indexOf('\r\n\r\n')).toString('latin1');
      assert.match(head, new RegExp(`content-length: ${bytes.length}\r\n`, 'i'));
    },
  );
});

test('AUDIT: a HEAD response carries the length and none of the body', async () => {
  // **Correct by accident until the content path landed, and wrong the moment it did.**
  //
  // `handleRequest` admits HEAD alongside GET, and the block that fetches content sits below that
  // admission with no method test between them. While the body was always the empty string this
  // was harmless; now a HEAD answer carries the whole entity. RFC 7230 3.3.3 is unambiguous: a
  // response to HEAD never includes a body, and its `content-length` states what a GET would have
  // returned.
  //
  // The consequence is not cosmetic. A client that reads exactly `content-length` bytes gets the
  // body it was promised it would not get, and a client that reads none of them leaves an entity
  // in the connection buffer. Every response here closes the connection, which bounds the damage
  // to one exchange rather than to a smuggled second request — but "the next layer happens to
  // clean up after us" is not a framing rule, and a proxy that answers HEAD with a body is a proxy
  // whose framing cannot be trusted by anything that has to parse it.
  const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
  await withListener(
    () =>
      serveProxy({
        ports: servingPorts(),
        port: 0,
        now: () => SERVE_NOW,
        options: {
          content: {
            fetch: () => ({ ok: true, bytes, contentType: 'application/octet-stream' }),
          },
        },
      }),
    async (listener) => {
      const answer = await speakBytes(
        listener.address,
        'HEAD / HTTP/1.1\r\nHost: atlas.vayu\r\n\r\n',
      );
      const split = answer.indexOf('\r\n\r\n');
      const head = answer.subarray(0, split).toString('latin1');
      assert.match(head, /^HTTP\/1\.1 200 /);
      // The length is the one a GET would have answered with, so a client can size a fetch from a
      // HEAD. Dropping the header instead of the body would be a different bug with the same shape.
      assert.match(head, new RegExp(`content-length: ${bytes.length}\r\n`, 'i'));
      assert.equal(answer.subarray(split + 4).length, 0, 'and not one byte of the entity');

      // The same request as GET still gets the body, or the fix is "answer nothing" wearing a
      // disguise.
      const asGet = await speakBytes(
        listener.address,
        'GET / HTTP/1.1\r\nHost: atlas.vayu\r\n\r\n',
      );
      assert.equal(bodyOf(asGet).length, bytes.length);
    },
  );
});

/* -------------------------------------------------------------------------- */
/* AUDIT: one throw anywhere took the whole resolver down                      */
/* -------------------------------------------------------------------------- */

test('AUDIT: a handler that throws answers 500 and leaves the listener running', async () => {
  // **Measured before this fix: `UNCAUGHT EXCEPTION reached the process`.**
  //
  // `serveConnection` called `respond(parsed)` with nothing around it, and no module in the
  // registry installs an `uncaughtException` handler. So a throw from any injected port — a
  // resolver bug, a corrupt log, a store that cannot read its own file — did not answer 500. It
  // terminated the process, and with it the browsing proxy AND the control API, which are
  // separate listeners in one process. The surface that exists to diagnose a failing resolver
  // died with the resolver.
  //
  // A refusal is a response. A crash is a denial of service that anyone who can provoke one bug
  // gets for free, and the catalogue already had the answer: RESOLUTION.md entry 1500, INTERNAL,
  // 500 — an entry with no producer anywhere in the codebase until now.
  const listener = await serveProxy({
    ports: {
      lookup: () => {
        throw new Error('a port threw, carrying /home/someone/.vayuweb/secret-token-abc');
      },
      hasVerifiedHead: () => true,
    },
    port: 0,
    now: () => SERVE_NOW,
  });
  try {
    const answer = await speak(listener.address, 'GET / HTTP/1.1\r\nHost: atlas.vayu\r\n\r\n');
    assert.match(answer, /^HTTP\/1\.1 500 /);

    // The error's own text never reaches the wire. An exception message is the likeliest place
    // for a path, a token or a record's bytes to be sitting, and LOCAL-SURFACE.md 2.4 forbids a
    // refusal that confirms VayuWeb is running at all.
    assert.doesNotMatch(answer, /secret-token-abc/);
    assert.doesNotMatch(answer, /home\/someone/);
    assert.doesNotMatch(answer, /a port threw/);
    // The body carries nothing at all, which is the general form of the three assertions above:
    // there is no channel for the exception's text rather than a filter over it. (`/Error/` was
    // the first version of this assertion and it was wrong — it matches the standard reason
    // phrase "Internal Server Error", so it failed on a correct response.)
    const body = answer.slice(answer.indexOf('\r\n\r\n') + 4);
    assert.equal(body, '', `a 500 body must be empty, got ${JSON.stringify(body)}`);
    assert.match(answer, /content-length: 0/i);
    // And it is still a proper refusal, not a bare socket close: the security headers are on it.
    assert.match(answer, /content-security-policy: /i);

    // The half that matters most. A 500 for one request is a bug; a listener that stops
    // answering is the outage.
    const second = await speak(listener.address, 'GET / HTTP/1.1\r\nHost: atlas.vayu\r\n\r\n');
    assert.match(second, /^HTTP\/1\.1 500 /, 'the listener must survive the throw');
  } finally {
    await listener.close();
  }
});

test('AUDIT: a control port that throws does not take the control API with it', async () => {
  // The same defect on the other surface, and the more damaging one: the control API is where an
  // operator goes to find out why the resolver is unhappy. A diagnostic surface that dies of the
  // fault it exists to report is worse than none, because its silence reads as "nothing to say".
  const directory = mkdtempSync(join(tmpdir(), 'vayuweb-control-'));
  const path = join(directory, 'control.sock');
  const token = randomBytes(32).toString('base64url');
  const listener = await serveControl({
    ports: {
      ...controlPorts,
      status: () => {
        throw new Error('the log is unreadable at /var/lib/vayuweb/log');
      },
    },
    path,
    token: () => token,
  });
  try {
    const answer = await speak(listener.address, authorised('/v1/status', token));
    assert.match(answer, /^HTTP\/1\.1 500 /);
    assert.doesNotMatch(answer, /var\/lib\/vayuweb/, 'no path from an exception message');
    assert.doesNotMatch(answer, /unreadable/);

    // **The answer is the CONTROL API's, not the backstop's, and the first version of this test
    // could not tell the two apart.** Removing this surface's own catch left every assertion above
    // passing, because `serveConnection`'s backstop answers a bare 500 that satisfies all of them.
    //
    // What the surface's own refusal adds is a body an operator can parse. This is a diagnostic
    // API: the person reading this response is the one whose resolver is failing, and an empty
    // body tells them only that something went wrong somewhere. So the assertion is on the shape
    // the backstop cannot produce.
    const body = answer.slice(answer.indexOf('\r\n\r\n') + 4);
    assert.notEqual(body, '', 'a bare 500 is the backstop answering, not this surface');
    const parsed: unknown = JSON.parse(body);
    assert.deepEqual(parsed, { error: 'internal' });
    // And the reason is a constant. An authenticated caller is still not entitled to a stack
    // trace: this response ends up in support tickets and screenshots.
    assert.equal(JSON.stringify(parsed).includes('vayuweb'), false);

    // Still serving, and the route that does not throw still answers.
    const health = await speak(listener.address, authorised('/v1/health', token));
    assert.match(health, /^HTTP\/1\.1 200 /, 'the control API must survive one bad route');
  } finally {
    await listener.close();
  }
});

test('AUDIT: the backstop, not the callers, is what makes a throw unable to reach the process', () => {
  // The two tests above exercise the two callers. Both would still pass if `serveConnection` had
  // no catch of its own — and then a third listener added later, written the same natural way,
  // would reintroduce the outage. The defect was structural: nothing guaranteed the property. So
  // the property is asserted of the MODULE, against a responder that is neither of the two.
  //
  // Read the source rather than a third listener, because binding one here would be asserting
  // about a fixture rather than about the code that ships.
  const source = readFileSync(new URL('./serve.ts', import.meta.url), 'utf8');
  const body = source.slice(source.indexOf('function serveConnection'));
  // Matched on `respond(<identifier>)` rather than on one spelling of the argument: the property
  // is that the call is inside a try, and a test that fails when a variable is renamed reports a
  // rename as an outage.
  const call = /answer = respond\(\w+\);/.exec(body);
  assert.ok(call, 'serveConnection must call respond() and assign its answer');
  const guarded = new RegExp(
    `try\\s*\\{\\s*${call[0].replace(/[()]/g, '\\$&')}\\s*\\}\\s*catch`,
  ).test(body);
  assert.ok(guarded, 'serveConnection must not call respond() outside a try');
  // And the backstop must not be able to leak the exception either: no reference to the caught
  // value at all, which is stronger than checking what it formats.
  const backstop = body.slice(body.indexOf(call[0]));
  const clause = backstop.slice(0, backstop.indexOf('writeHttp(socket, 500'));
  assert.doesNotMatch(clause, /catch\s*\(/, 'the backstop must not bind the error at all');
});

/* -------------------------------------------------------------------------- */
/* AUDIT: the units of the bound, and the bytes after the head                  */
/* -------------------------------------------------------------------------- */

test('AUDIT: `headBytes` was a bound on code units, so a non-ASCII head was three times it', async () => {
  // The field is named `headBytes` and its comment says "the whole request head — request line
  // plus headers — in bytes". It was compared against a JavaScript string's `length`, which counts
  // UTF-16 code units. Every character from U+0800 to U+FFFF is THREE bytes on the wire and ONE
  // code unit in that string, so a sender could put three times the stated bound through the
  // socket and be accepted — and, worse, the number that governs a request's size would be a
  // number nobody could compute from the request.
  //
  // The consequence is small on its own and structural underneath: a body reader has to count
  // bytes, because `Content-Length` is bytes. A reader built on a buffer measured in code units
  // cannot agree with the header that frames it for any body that is not pure ASCII.
  await withListener(
    () => serveProxy({ ports: resolverPorts, port: 0, now: () => SERVE_NOW }),
    async (listener) => {
      // Under the bound in code units, comfortably over it in bytes.
      const units = SERVE_LIMITS.headBytes - 200;
      const pad = 'ࠀ'.repeat(units);
      assert.ok(
        units < SERVE_LIMITS.headBytes,
        'the padding must be under the bound as characters',
      );
      assert.ok(
        Buffer.byteLength(pad, 'utf8') > SERVE_LIMITS.headBytes,
        'and over it as bytes, or this test proves nothing',
      );
      const answer = await speak(
        listener.address,
        `GET / HTTP/1.1\r\nHost: atlas.vayu\r\nx-pad: ${pad}\r\n\r\n`,
      );
      assert.match(answer, /^HTTP\/1\.1 431 /, 'a head over the byte bound must be refused');
      assert.match(answer, /HEAD_TOO_LARGE/);
    },
  );
});

test('AUDIT: the proxy answered a request whose declared body it never read', async () => {
  // Nothing on the browsing proxy takes a body, and the module said so — then accepted one
  // silently. A request declaring `Content-Length: 11` was answered from its head alone and the
  // eleven bytes were left in the socket buffer, unread and unmentioned.
  //
  // It is NOT a smuggling vulnerability today, and saying so is part of the finding: every
  // response carries `connection: close` and the socket is ended, so no second request is ever
  // parsed off those bytes. What it is, is a framing disagreement between the sender and the
  // server that neither can observe — and a server that answers a request it has not finished
  // reading is one refactor away from the bug the close is currently hiding.
  await withListener(
    () => serveProxy({ ports: resolverPorts, port: 0, now: () => SERVE_NOW }),
    async (listener) => {
      const answer = await speak(
        listener.address,
        'POST / HTTP/1.1\r\nHost: atlas.vayu\r\ncontent-length: 11\r\n\r\nhello there',
      );
      assert.match(answer, /^HTTP\/1\.1 400 /, 'a body on a surface that takes none is refused');
      assert.match(answer, /UNEXPECTED_BODY/);
    },
  );
});

test('AUDIT: chunked framing was accepted and then ignored on both surfaces', async () => {
  // `Transfer-Encoding: chunked` says the body's length is in the body. The parser never looked,
  // so a chunked request was answered as though it had no body at all. One framing, decided by
  // one field, is the only arrangement in which the sender and the server agree; the second
  // framing exists so two parsers can disagree, and this program has no throughput requirement
  // that would pay for it.
  await withListener(
    () => serveProxy({ ports: resolverPorts, port: 0, now: () => SERVE_NOW }),
    async (listener) => {
      const answer = await speak(
        listener.address,
        'POST / HTTP/1.1\r\nHost: atlas.vayu\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n',
      );
      assert.match(answer, /^HTTP\/1\.1 400 /);
      assert.match(answer, /MALFORMED_FRAMING/);
    },
  );
});

/* -------------------------------------------------------------------------- */
/* The bounded body reader                                                     */
/* -------------------------------------------------------------------------- */

test('framing refuses the second length field outright', () => {
  // One framing and no other. Every request-smuggling defect in the literature is two parsers
  // disagreeing about which of two length fields governs; the way not to have that argument is
  // not to accept the second field, including its innocent-looking `identity` spelling.
  for (const value of ['chunked', 'identity', 'gzip, chunked', '']) {
    assert.equal(
      refusal(() => framing(new Map([['transfer-encoding', value]]))),
      'MALFORMED_FRAMING',
      value,
    );
  }
});

test('framing refuses a content-length that is not a plain count of octets', () => {
  // `Number()` accepts most of these. Every acceptance is a value some other parser reads
  // differently, and the whole point of this function is that there is only one reading.
  for (const value of [
    '+5',
    '-1',
    ' 5',
    '5 ',
    '0x5',
    '5, 5',
    '1e3',
    '5.0',
    '',
    'five',
    '1234567890',
  ]) {
    assert.equal(
      refusal(() => framing(new Map([['content-length', value]]))),
      'MALFORMED_FRAMING',
      JSON.stringify(value),
    );
  }
});

test('framing refuses an oversized body from the head alone, before anything is buffered', () => {
  // The ceiling is checked against the number the sender STATED, so a request for a gigabyte
  // costs this process one header line rather than the allocation it asked for.
  assert.equal(
    refusal(() => framing(new Map([['content-length', String(SERVE_LIMITS.bodyBytes + 1)]]))),
    'BODY_TOO_LARGE',
  );
  assert.deepEqual(framing(new Map([['content-length', String(SERVE_LIMITS.bodyBytes)]])), {
    kind: 'fixed',
    length: SERVE_LIMITS.bodyBytes,
  });
});

test('framing reads no body where none is declared, and none where zero is', () => {
  assert.deepEqual(framing(new Map()), { kind: 'none' });
  assert.deepEqual(framing(new Map([['content-length', '0']])), { kind: 'none' });
  assert.deepEqual(framing(new Map([['content-length', '3']])), { kind: 'fixed', length: 3 });
});

/** Speak to a Unix socket and return the raw answer. */
function speakTo(path: string, request: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect(path);
    let out = '';
    socket.setEncoding('utf8');
    socket.on('connect', () => socket.write(request));
    socket.on('data', (chunk: string) => {
      out += chunk;
    });
    socket.on('close', () => resolve(out));
    socket.on('error', reject);
  });
}

/** A control request with a JSON body, framed the way a correct client would frame it. */
function post(path: string, token: string, json: string): string {
  return (
    `POST ${path} HTTP/1.1\r\n` +
    `x-vayuweb-control: 1\r\n` +
    `authorization: Bearer ${token}\r\n` +
    `content-length: ${Buffer.byteLength(json, 'utf8')}\r\n\r\n${json}`
  );
}

async function withControl(run: (address: string, token: string) => Promise<void>): Promise<void> {
  const token = randomBytes(32).toString('base64url');
  const directory = mkdtempSync(join(tmpdir(), 'vayuweb-body-'));
  const listener = await serveControl({
    ports: controlPorts,
    path: join(directory, 'control.sock'),
    token: () => token,
  });
  try {
    await run(listener.address, token);
  } finally {
    await listener.close();
  }
}

test('the control API reads a body and answers from it', async () => {
  await withControl(async (address, token) => {
    const answer = await speakTo(
      address,
      post('/v1/resolve', token, JSON.stringify({ name: 'atlasobservatory.vayu' })),
    );
    assert.match(answer, /^HTTP\/1\.1 200 /, answer);
    assert.match(answer, /"name":"atlasobservatory\.vayu"/);
  });
});

test('a body split across packets is read whole, not answered from the first piece', async () => {
  // The defect this is written against is answering as soon as the head is complete. A sender
  // that writes its head and its body in two writes is the ordinary case, not an attack.
  await withControl(async (address, token) => {
    const json = JSON.stringify({ name: 'atlasobservatory.vayu' });
    const request = post('/v1/resolve', token, json);
    const split = request.length - 5;
    const answer = await new Promise<string>((resolve, reject) => {
      const socket = connect(address);
      let out = '';
      socket.setEncoding('utf8');
      socket.on('connect', () => {
        socket.write(request.slice(0, split));
        setTimeout(() => socket.write(request.slice(split)), 25);
      });
      socket.on('data', (chunk: string) => {
        out += chunk;
      });
      socket.on('close', () => resolve(out));
      socket.on('error', reject);
    });
    assert.match(answer, /^HTTP\/1\.1 200 /, answer);
    assert.match(answer, /"name":"atlasobservatory\.vayu"/);
  });
});

test('a sender that promises bytes and goes quiet is closed by the clock, not held', async () => {
  // The deadline must be armed across the body, not only across the head. A deadline evaluated
  // when the peer next speaks is no deadline at all, because the attack IS the peer not speaking.
  // Asserted on the source rather than by waiting ten seconds: the property is that `finish` —
  // which is what stops the timer — is not reached until the body is complete.
  const source = readFileSync(new URL('./serve.ts', import.meta.url), 'utf8');
  const reader = source.slice(source.indexOf('function serveConnection'));
  const shortRead = reader.indexOf('if (have < wanted) return;');
  const dispatch = reader.indexOf('finish(() => {');
  assert.notEqual(shortRead, -1, 'the reader must have a short-read branch');
  assert.ok(shortRead < dispatch, 'and it must return before the branch that clears the timer');
});

test('more bytes than were declared is a refusal, not a longer body', async () => {
  await withControl(async (address, token) => {
    const json = JSON.stringify({ name: 'atlasobservatory.vayu' });
    const request =
      `POST /v1/resolve HTTP/1.1\r\nx-vayuweb-control: 1\r\n` +
      `authorization: Bearer ${token}\r\n` +
      `content-length: ${Buffer.byteLength(json, 'utf8')}\r\n\r\n${json}` +
      `POST /v1/diagnostics/on HTTP/1.1\r\n\r\n`;
    const answer = await speakTo(address, request);
    assert.match(answer, /^HTTP\/1\.1 400 /, answer);
    assert.match(answer, /UNEXPECTED_BODY/);
  });
});

test('an oversized body is refused with 413 from the head alone', async () => {
  await withControl(async (address, token) => {
    // No body is sent at all. If this were being read rather than refused from the declaration,
    // the connection would sit open until the head deadline instead of answering immediately.
    const answer = await speakTo(
      address,
      `POST /v1/resolve HTTP/1.1\r\nx-vayuweb-control: 1\r\n` +
        `authorization: Bearer ${token}\r\n` +
        `content-length: ${SERVE_LIMITS.bodyBytes + 1}\r\n\r\n`,
    );
    assert.match(answer, /^HTTP\/1\.1 413 /, answer);
    assert.match(answer, /BODY_TOO_LARGE/);
  });
});

test('the body limit is refused before the token is even consulted', async () => {
  // A refusal that costs an allocation is a refusal an unauthenticated caller can spend. The
  // transport bound runs first precisely so an unauthenticated peer cannot make this process
  // allocate anything at all.
  await withControl(async (address) => {
    const answer = await speakTo(
      address,
      `POST /v1/resolve HTTP/1.1\r\nx-vayuweb-control: 1\r\n` +
        `content-length: ${SERVE_LIMITS.bodyBytes + 1}\r\n\r\n`,
    );
    assert.match(answer, /^HTTP\/1\.1 413 /, answer);
  });
});

/* -------------------------------------------------------------------------- */
/* POST /v1/token/rotate — the one endpoint that changes who may call again    */
/* -------------------------------------------------------------------------- */

test('AUDIT: a rotated token takes effect on the very next request, and the old one dies', async () => {
  // The defect this is written against is the one this codebase keeps finding: a mechanism that
  // returns a new value while the thing that checks it keeps comparing against the old. A listener
  // capturing the token once at bind time would answer 200 to `POST /v1/token/rotate`, hand back a
  // fresh token, and then refuse it — leaving the operator holding a credential nothing accepts
  // and a resolver only a restart can recover. Every assertion here is about a SECOND request,
  // because the first one cannot tell the two arrangements apart.
  const first = randomBytes(32).toString('base64url');
  let current = first;
  const directory = mkdtempSync(join(tmpdir(), 'vayuweb-rotate-'));
  const listener = await serveControl({
    ports: {
      ...controlPorts,
      rotateToken: () => {
        current = randomBytes(32).toString('base64url');
        return current;
      },
    },
    path: join(directory, 'control.sock'),
    // Read per request rather than captured, which is the property under test.
    token: () => current,
  });
  try {
    const rotated = await speakTo(listener.address, post('/v1/token/rotate', first, '{}'));
    assert.match(rotated, /^HTTP\/1\.1 200 /, rotated);
    const issued = /"token":"([A-Za-z0-9_-]+)"/.exec(rotated);
    assert.ok(issued, `the response must carry the new token: ${rotated}`);
    const next = issued[1] as string;

    assert.notEqual(next, first, 'a rotation that returns the same token has rotated nothing');
    assert.equal(Buffer.from(next, 'base64url').length, 32, 'and it is a full-length token');

    // The two assertions that matter, both on a later request.
    const withOld = await speakTo(listener.address, authorised('/v1/status', first));
    assert.match(withOld, /^HTTP\/1\.1 401 /, `the old token must stop working: ${withOld}`);
    const withNew = await speakTo(listener.address, authorised('/v1/status', next));
    assert.match(withNew, /^HTTP\/1\.1 200 /, `the new token must work: ${withNew}`);
  } finally {
    await listener.close();
  }
});

test('rotation is behind the token, so a stranger cannot lock the operator out', async () => {
  // Otherwise the endpoint is a denial of service with an authentication step nobody passed:
  // rotate, discard the response, and the operator's token is dead.
  const token = randomBytes(32).toString('base64url');
  const directory = mkdtempSync(join(tmpdir(), 'vayuweb-rotate-auth-'));
  let rotations = 0;
  const listener = await serveControl({
    ports: {
      ...controlPorts,
      rotateToken: () => {
        rotations += 1;
        return token;
      },
    },
    path: join(directory, 'control.sock'),
    token: () => token,
  });
  try {
    const wrong = randomBytes(32).toString('base64url');
    const refused = await speakTo(listener.address, post('/v1/token/rotate', wrong, '{}'));
    assert.match(refused, /^HTTP\/1\.1 401 /);
    assert.equal(rotations, 0, 'and the rotation never happened');
  } finally {
    await listener.close();
  }
});
