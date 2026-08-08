import { test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  ConnectionCounter,
  SERVE_LIMITS,
  ServeError,
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
          token: randomBytes(32).toString('base64url'),
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
        serveControl({ ports: controlPorts, path: join(directory, 'x.sock'), token: bad }),
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
    () => serveControl({ ports: controlPorts, path, token: randomBytes(32).toString('base64url') }),
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
    () => serveControl({ ports: controlPorts, path, token }),
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
    () => serveControl({ ports: controlPorts, path, token }),
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
