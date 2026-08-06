/**
 * The sockets. Everything above this file is a pure function; this is where bytes arrive.
 *
 * docs/spec/LOCAL-SURFACE.md and docs/spec/RESOLUTION.md, "The browsing proxy". The split is
 * deliberate and it is the reason `proxy.ts` and `control.ts` are testable at all: a refusal
 * expressed as `handleRequest(...) -> 403` can be exercised as data, while a refusal expressed as
 * "the socket was never bound" can only be exercised by binding a socket. Every policy decision
 * stays in the handlers. What lives here is the part that cannot be a pure function — listening,
 * reading a request, writing a response, and the file mode on a socket.
 *
 * ## The two surfaces are deliberately of different kinds
 *
 * **The browsing proxy is TCP**, on loopback, because a browser has to reach it.
 *
 * **The control API is a Unix domain socket**, because a browser must never reach it.
 * `assertSocketAddress` already refuses a TCP address, and it is called here before anything is
 * bound rather than trusted to have been called by the caller — LOCAL-SURFACE.md section 1 said
 * this in prose and five documents went on specifying a loopback port anyway, so the guard sits
 * at the boundary where the mistake would otherwise become a listening socket. The retired port
 * number is deliberately not written here: `scripts/check-listeners.py` refuses any mention of
 * it, precisely so that nobody can reintroduce it by copying a comment.
 *
 * ## What this file refuses to do
 *
 * No request body is read on either surface. Nothing in either API takes one, and a body reader
 * is an unbounded allocation controlled by whoever opened the connection. The proxy answers from
 * the request line and headers; the control API's mutating routes carry their argument in the
 * path. A future route that needs a body has to add a bounded reader deliberately, which is the
 * point.
 */

import { createServer as createTcpServer, type Server, type Socket } from 'node:net';
import { chmodSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { dirname } from 'node:path';

import {
  NegativeCache,
  PROXY_LIMITS,
  handleRequest,
  type ProxyOptions,
  type ProxyRequest,
  type ProxyResponse,
} from './proxy.ts';
import {
  TOKEN_BYTES,
  assertSocketAddress,
  handleControlRequest,
  type ControlPorts,
  type ControlRequest,
  type ControlResponse,
} from './control.ts';
import type { ResolverPorts } from './resolve.ts';

/** Bounds on what a connection may do before it has said anything useful. */
export const SERVE_LIMITS = {
  /**
   * The whole request head — request line plus headers — in bytes.
   *
   * Bounded because a connection that never sends a blank line is otherwise an unbounded buffer
   * that costs the sender nothing. 16 KiB is far above any legitimate request to either surface;
   * the proxy's own target and host limits are much tighter still.
   */
  headBytes: 16 * 1024,
  /** Header lines accepted before the head is refused, independent of total size. */
  headerLines: 100,
  /** How long a connection may stay open without completing its head, in milliseconds. */
  headTimeoutMs: 10_000,
  /** Concurrent connections per listener. Beyond this, new sockets are closed immediately. */
  connections: 256,
} as const;

/** Why a connection was refused before any handler saw it. */
export type ServeRejection =
  | 'HEAD_TOO_LARGE'
  | 'TOO_MANY_HEADERS'
  | 'MALFORMED_REQUEST'
  | 'HEAD_TIMEOUT'
  | 'TOO_MANY_CONNECTIONS';

/** A parsed request head. Bodies are never read; see the module comment. */
export interface RequestHead {
  readonly method: string;
  readonly target: string;
  readonly headers: ReadonlyMap<string, string>;
}

export class ServeError extends Error {
  readonly code: ServeRejection;
  constructor(code: ServeRejection, message: string) {
    super(`${code}: ${message}`);
    this.name = 'ServeError';
    this.code = code;
  }
}

/**
 * Parse an HTTP/1.1 request head from the bytes before the blank line.
 *
 * Exported and pure so that every refusal below is testable without a socket — the same reason
 * the handlers are pure. Deliberately strict: this parser serves one browser on loopback and one
 * local control client, so there is no compatibility argument for accepting a malformed head, and
 * every leniency in an HTTP parser is a request-smuggling primitive waiting for a second parser
 * to disagree with it.
 */
export function parseHead(text: string): RequestHead {
  const lines = text.split('\r\n');
  const requestLine = lines[0] ?? '';
  const parts = requestLine.split(' ');
  if (parts.length !== 3) {
    throw new ServeError('MALFORMED_REQUEST', 'a request line is METHOD SP TARGET SP VERSION');
  }
  const [method, target, version] = parts as [string, string, string];
  if (!/^HTTP\/1\.[01]$/.test(version)) {
    throw new ServeError('MALFORMED_REQUEST', `unsupported version ${JSON.stringify(version)}`);
  }
  if (!/^[A-Z]{3,10}$/.test(method)) {
    throw new ServeError('MALFORMED_REQUEST', `unsupported method ${JSON.stringify(method)}`);
  }
  if (target.length === 0 || target.length > PROXY_LIMITS.targetBytes) {
    throw new ServeError('MALFORMED_REQUEST', 'request target is empty or over the limit');
  }

  const headers = new Map<string, string>();
  for (const line of lines.slice(1)) {
    if (line.length === 0) continue;
    if (headers.size >= SERVE_LIMITS.headerLines) {
      throw new ServeError('TOO_MANY_HEADERS', `over ${SERVE_LIMITS.headerLines} header lines`);
    }
    // Leading whitespace is obsolete line folding (RFC 7230 3.2.4), which MUST be rejected: it is
    // the classic disagreement between two parsers, and this one has no reason to accept it.
    //
    // **Redundant, and said so rather than implied.** Deleting this changes no outcome, because a
    // folded line either carries no colon or carries one whose name begins with whitespace and so
    // fails the token check below. It is kept because the refusal deserves to be legible at the
    // point a reader looks for it, and removed silence about that is worth more than one branch.
    // Established by re-mutation: the first version of this comment read as load-bearing.
    if (/^[ \t]/.test(line)) {
      throw new ServeError('MALFORMED_REQUEST', 'obsolete header line folding');
    }
    const colon = line.indexOf(':');
    if (colon <= 0) {
      throw new ServeError('MALFORMED_REQUEST', 'header line without a name');
    }
    const name = line.slice(0, colon).toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) {
      throw new ServeError('MALFORMED_REQUEST', `header name ${JSON.stringify(name)} is not a token`);
    }
    const value = line.slice(colon + 1).trim();
    // Last-wins and first-wins are both defensible, so a duplicate is refused rather than picked
    // between: a header two parsers resolve differently is a request two parsers read differently.
    if (headers.has(name)) {
      throw new ServeError('MALFORMED_REQUEST', `duplicate header ${JSON.stringify(name)}`);
    }
    headers.set(name, value);
  }
  return { method, target, headers };
}

/** Serialise a response head and body. */
function writeHttp(
  socket: Socket,
  status: number,
  headers: ReadonlyMap<string, string>,
  body: string,
): void {
  const payload = Buffer.from(body, 'utf8');
  const lines = [`HTTP/1.1 ${status} ${reason(status)}`];
  for (const [name, value] of headers) lines.push(`${name}: ${value}`);
  lines.push(`content-length: ${payload.length}`);
  // Every response closes the connection. Keep-alive is a state machine whose bugs are
  // request smuggling, and this proxy has no throughput requirement that would pay for it.
  lines.push('connection: close');
  socket.write(`${lines.join('\r\n')}\r\n\r\n`);
  socket.end(payload);
}

function reason(status: number): string {
  const known: Record<number, string> = {
    200: 'OK',
    400: 'Bad Request',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    410: 'Gone',
    413: 'Payload Too Large',
    431: 'Request Header Fields Too Large',
    500: 'Internal Server Error',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
  };
  return known[status] ?? 'Status';
}

/** The status a pre-handler refusal answers with. */
function statusFor(code: ServeRejection): number {
  return code === 'HEAD_TOO_LARGE' || code === 'TOO_MANY_HEADERS' ? 431 : 400;
}

/**
 * Read a request head, then hand it to `respond`.
 *
 * The connection-level bounds live here rather than in either handler because they are properties
 * of a socket and not of a request: a peer that opens a connection and says nothing has not made
 * a request for a handler to refuse.
 */
function serveConnection(
  socket: Socket,
  respond: (head: RequestHead) => { status: number; headers: ReadonlyMap<string, string>; body: string },
): void {
  let buffer = '';
  let done = false;

  const timer = setTimeout(() => {
    if (done) return;
    done = true;
    writeHttp(socket, 400, new Map(), 'HEAD_TIMEOUT');
  }, SERVE_LIMITS.headTimeoutMs);
  // An unref'd timer does not hold the process open, so a listener with an idle connection can
  // still shut down cleanly.
  timer.unref?.();

  const finish = (run: () => void): void => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    run();
  };

  socket.setEncoding('utf8');
  socket.on('data', (chunk: string) => {
    if (done) return;
    buffer += chunk;
    if (buffer.length > SERVE_LIMITS.headBytes) {
      finish(() => writeHttp(socket, 431, new Map(), 'HEAD_TOO_LARGE'));
      return;
    }
    const end = buffer.indexOf('\r\n\r\n');
    if (end === -1) return;
    const head = buffer.slice(0, end);
    finish(() => {
      let parsed: RequestHead;
      try {
        parsed = parseHead(head);
      } catch (error) {
        const code = error instanceof ServeError ? error.code : 'MALFORMED_REQUEST';
        writeHttp(socket, statusFor(code), new Map(), code);
        return;
      }
      const answer = respond(parsed);
      writeHttp(socket, answer.status, answer.headers, answer.body);
    });
  });

  socket.on('error', () => {
    done = true;
    clearTimeout(timer);
    socket.destroy();
  });
}

/** Cap concurrent connections, closing the excess rather than queueing it. */
function withConnectionCap(server: Server): Server {
  let open = 0;
  server.on('connection', (socket: Socket) => {
    open += 1;
    if (open > SERVE_LIMITS.connections) {
      // Refused with a status rather than a silent close, so an operator watching the surface can
      // tell exhaustion apart from a network fault.
      writeHttp(socket, 503, new Map(), 'TOO_MANY_CONNECTIONS');
      return;
    }
    socket.on('close', () => {
      open -= 1;
    });
  });
  return server;
}

/** A bound listener, with the address it actually ended up on. */
export interface Listener {
  readonly address: string;
  close(): Promise<void>;
}

/** Everything the browsing proxy listener needs. */
export interface ProxyServerOptions {
  readonly ports: ResolverPorts;
  /** Defaults to 7654 per RESOLUTION.md. 0 asks the OS for a free port, which the tests use. */
  readonly port?: number;
  readonly options?: ProxyOptions;
  /**
   * Unix seconds, supplied rather than read.
   *
   * Required, not defaulted. A default reaching for the ambient clock would put nondeterminism
   * into the one module whose refusals are otherwise a pure function of their inputs, and
   * `scripts/check-source-hygiene.py` refuses it by name — every clock in this codebase enters
   * through a parameter so that a verdict can be reproduced from its inputs alone. The process
   * boundary in `cli.ts` is where the real clock is allowed to exist.
   */
  readonly now: () => number;
}

/**
 * Bind the browsing proxy.
 *
 * **Loopback only, and not configurable.** RESOLUTION.md binds this to `127.0.0.1`; an address
 * parameter would be a way to publish a reader's resolver to their whole network, and there is no
 * legitimate reason to want one. A caller wanting that has misunderstood what the proxy is.
 */
export function serveProxy(options: ProxyServerOptions): Promise<Listener> {
  const cache = new NegativeCache(PROXY_LIMITS.negativeEntries, PROXY_LIMITS.negativeTtlSeconds);
  const clock = options.now;

  const server = withConnectionCap(
    createTcpServer((socket) => {
      serveConnection(socket, (head) => {
        const request: ProxyRequest = {
          method: head.method,
          target: head.target,
          headers: head.headers,
        };
        const response: ProxyResponse = handleRequest(
          request,
          options.ports,
          cache,
          clock(),
          options.options ?? {},
        );
        return response;
      });
    }),
  );

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port ?? 7654, '127.0.0.1', () => {
      const bound = server.address();
      const address =
        bound !== null && typeof bound === 'object' ? `127.0.0.1:${bound.port}` : '127.0.0.1';
      resolve({
        address,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
          }),
      });
    });
  });
}

/** Everything the control API listener needs. */
export interface ControlServerOptions {
  readonly ports: ControlPorts;
  /** Filesystem path for the socket. Refused if it looks like a TCP address. */
  readonly path: string;
  readonly token: string;
}

/**
 * Bind the control API on a Unix domain socket.
 *
 * Three things happen here that a document cannot do on its own. `assertSocketAddress` runs
 * before the bind, so a TCP address is a thrown error rather than a listening port. The socket
 * gets mode `0600` immediately after binding, because a socket anyone on the machine can connect
 * to is a control API anyone on the machine has. And its directory is created `0700` if missing,
 * since a `0600` socket inside a world-writable directory can be replaced by whoever owns the
 * directory.
 */
export function serveControl(options: ControlServerOptions): Promise<Listener> {
  assertSocketAddress(options.path);

  // A token that cannot decode to TOKEN_BYTES can never match, so a resolver started with one
  // binds a control API nobody can reach -- and says nothing, because every request answers 401
  // exactly as a wrong guess would. Failing at bind turns a silent misconfiguration into a
  // startup error, which is the only moment anybody is looking.
  if (Buffer.from(options.token, 'base64url').length !== TOKEN_BYTES) {
    throw new Error(
      `the control token must be base64url of ${TOKEN_BYTES} bytes; this one decodes to ` +
        `${Buffer.from(options.token, 'base64url').length}, so no caller could ever authenticate`,
    );
  }

  const directory = dirname(options.path);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  // A pre-existing directory keeps its mode from mkdir's point of view, so it is set explicitly.
  chmodSync(directory, 0o700);
  // A stale socket from a crashed run would make bind fail. Removing it is safe because the
  // directory is now known to be 0700 and owned by this user.
  try {
    if (statSync(options.path)) rmSync(options.path, { force: true });
  } catch {
    // Nothing there, which is the ordinary case.
  }

  const server = withConnectionCap(
    createTcpServer((socket) => {
      serveConnection(socket, (head) => {
        const request: ControlRequest = {
          method: head.method,
          path: head.target,
          headers: head.headers,
        };
        const response: ControlResponse = handleControlRequest(request, options.ports, options.token);
        return {
          status: response.status,
          headers: response.headers,
          body: response.body === undefined ? '' : JSON.stringify(response.body),
        };
      });
    }),
  );

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.path, () => {
      // After bind, not before: the file does not exist until listen succeeds. The window between
      // the two is why the directory is 0700 — it is what makes the gap unreachable rather than
      // merely short.
      chmodSync(options.path, 0o600);
      resolve({
        address: options.path,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => {
              rmSync(options.path, { force: true });
              done();
            });
          }),
      });
    });
  });
}
