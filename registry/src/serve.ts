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
 * ## Bodies, and what reading one costs
 *
 * For most of this file's life no request body was read on either surface, on the grounds that a
 * body reader is an unbounded allocation controlled by whoever opened the connection. That was
 * right about the danger and wrong about the conclusion: the danger is the *unbounded* part, and
 * `RESOLUTION.md` specifies four endpoints that carry their argument in a body. The comment here
 * said a future route "has to add a bounded reader deliberately, which is the point" — so this is
 * that reader, added deliberately.
 *
 * What bounds it: one framing and no other ({@link framing} refuses `Transfer-Encoding` outright,
 * so the length is always a number the sender stated before sending anything); a hard ceiling of
 * `SERVE_LIMITS.bodyBytes` checked against that number *before* a single body byte is buffered;
 * a refusal of any byte beyond the stated length rather than an ignore; and the head deadline
 * left armed across the body, so a sender that promises 8 KiB and then goes quiet is closed by
 * the clock rather than held. The proxy passes `acceptsBody: false` and refuses a body outright —
 * nothing on that surface takes one, and a surface that answers a request it has not finished
 * reading is disagreeing with its sender about where the request ended.
 *
 * ## Bytes, not characters
 *
 * The connection buffer is a `Buffer` and every bound in this file is a count of octets. It used
 * to be a string with `setEncoding('utf8')`, which made `SERVE_LIMITS.headBytes` a bound on UTF-16
 * code units — three times looser than its name for any head in the range U+0800..U+FFFF. That
 * was a small looseness on its own and an impossible foundation for a body reader, because
 * `Content-Length` counts octets and a decoded string cannot be counted in them: invalid UTF-8
 * becomes U+FFFD and the byte count is lost for good. The head is decoded `latin1`, one octet to
 * one character, which also makes `parseHead`'s length checks exact rather than approximate.
 */

import { createServer as createTcpServer, type Server, type Socket } from 'node:net';
import { chmodSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { dirname } from 'node:path';

import {
  PROXY_LIMITS,
  handleRequest,
  refusal,
  type ProxyOptions,
  type ProxyRequest,
} from './proxy.ts';
import { ResolutionCache } from './cache.ts';
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
  /**
   * The largest request body accepted, in bytes, on the one surface that takes one.
   *
   * Checked against the sender's declared `Content-Length` *before* any body byte is buffered, so
   * an oversized body costs one header line rather than the allocation it asked for. 8 KiB is
   * three orders of magnitude above every body `RESOLUTION.md` defines — the largest is a name,
   * a CID or a handful of configuration fields — and the generosity is deliberate: a limit that
   * is nowhere near a legitimate request is a limit nobody is tempted to raise.
   */
  bodyBytes: 8 * 1024,
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
  | 'TOO_MANY_CONNECTIONS'
  /** A body arrived on a surface that takes none, or ran past the length its sender declared. */
  | 'UNEXPECTED_BODY'
  /** The declared length is over `SERVE_LIMITS.bodyBytes`. Refused before anything is buffered. */
  | 'BODY_TOO_LARGE'
  /** Chunked encoding, or a `Content-Length` that is not a plain count of octets. */
  | 'MALFORMED_FRAMING';

/** A parsed request, head and body. The body is empty on every surface that takes none. */
export interface RequestHead {
  readonly method: string;
  readonly target: string;
  readonly headers: ReadonlyMap<string, string>;
  /**
   * The request body, or zero bytes.
   *
   * Not optional, and that is a decision rather than an oversight: an optional body is a field a
   * route forgets to check, and the whole reason this reader exists is that a route needs to read
   * one. Zero bytes is the answer for every request that carries none.
   */
  readonly body: Uint8Array;
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
      throw new ServeError(
        'MALFORMED_REQUEST',
        `header name ${JSON.stringify(name)} is not a token`,
      );
    }
    const value = line.slice(colon + 1).trim();
    // Last-wins and first-wins are both defensible, so a duplicate is refused rather than picked
    // between: a header two parsers resolve differently is a request two parsers read differently.
    if (headers.has(name)) {
      throw new ServeError('MALFORMED_REQUEST', `duplicate header ${JSON.stringify(name)}`);
    }
    headers.set(name, value);
  }
  // Head-only, so no body: `serveConnection` re-spreads this with whatever the reader collected.
  // A parser that invented a body would be a parser deciding framing, which is the next function's
  // job and is kept apart from this one so it can be attacked without a socket.
  return { method, target, headers, body: EMPTY_BODY };
}

const EMPTY_BODY = new Uint8Array(0);

/** How long a body is, decided from the head alone. */
export type Framing =
  | { readonly kind: 'none' }
  | { readonly kind: 'fixed'; readonly length: number };

/**
 * Decide a request's framing, or refuse it.
 *
 * **One framing and no other.** `Transfer-Encoding` is refused whatever its value, including
 * `identity`: the whole class of request-smuggling defects is two parsers disagreeing about which
 * of two length fields governs, and the way not to have that argument is not to accept the second
 * field. This program speaks to one browser on loopback and one local control client, so there is
 * no compatibility case on the other side of the trade.
 *
 * `Content-Length` must be a plain count of octets — `^[0-9]{1,9}$` and nothing else. `+5`, `5 `,
 * ` 5`, `0x5`, `5, 5` and `-1` are all refused rather than coerced, because `Number()` accepts
 * most of them and every acceptance is a value some other parser reads differently. (A duplicated
 * header never reaches here: `parseHead` refuses duplicates outright.)
 *
 * The ceiling is checked HERE, against the declared number, rather than while reading — so a
 * sender asking for a gigabyte is answered from its head and costs this process nothing.
 */
export function framing(
  headers: ReadonlyMap<string, string>,
  limit: number = SERVE_LIMITS.bodyBytes,
): Framing {
  if (headers.has('transfer-encoding')) {
    throw new ServeError('MALFORMED_FRAMING', 'transfer-encoding is not accepted; use a length');
  }
  const declared = headers.get('content-length');
  if (declared === undefined) return { kind: 'none' };
  if (!/^[0-9]{1,9}$/.test(declared)) {
    throw new ServeError('MALFORMED_FRAMING', 'content-length must be a plain count of octets');
  }
  const length = Number(declared);
  if (length > limit) {
    throw new ServeError('BODY_TOO_LARGE', `${length} bytes is over the limit of ${limit}`);
  }
  return length === 0 ? { kind: 'none' } : { kind: 'fixed', length };
}

/** Serialise a response head and body. */
/**
 * A short diagnostic code as a body.
 *
 * These are the only bodies this module invents, and every one is ASCII. Encoding them here rather
 * than inside `writeHttp` keeps that function free of any encoding decision at all — which is what
 * the previous arrangement got wrong, by making one at each end and making two different ones.
 */
const asciiBody = (code: string): Uint8Array => Buffer.from(code, 'utf8');

function writeHttp(
  socket: Socket,
  status: number,
  headers: ReadonlyMap<string, string>,
  body: Uint8Array,
  /**
   * Send the head and none of the entity, which is what a response to HEAD is.
   *
   * It belongs here rather than in the handlers because it is a framing rule, not a policy one:
   * `content-length` still states what a GET would have returned, so the two have to be decided
   * together and by whoever writes them. Leaving it to the handler would mean returning an empty
   * body and a length that disagreed with it — the same defect from the other side.
   */
  elideBody = false,
): void {
  // No decode step. The body arrives as the bytes that are going out; it used to arrive as a
  // latin-1 string and get re-encoded as UTF-8, which doubled every octet above 0x7f.
  const payload = Buffer.from(body);
  const lines = [`HTTP/1.1 ${status} ${reason(status)}`];
  for (const [name, value] of headers) lines.push(`${name}: ${value}`);
  lines.push(`content-length: ${payload.length}`);
  // Every response closes the connection. Keep-alive is a state machine whose bugs are
  // request smuggling, and this proxy has no throughput requirement that would pay for it.
  lines.push('connection: close');
  socket.write(`${lines.join('\r\n')}\r\n\r\n`);
  if (elideBody) {
    socket.end();
    return;
  }
  socket.end(payload);
}

function reason(status: number): string {
  const known: Record<number, string> = {
    200: 'OK',
    400: 'Bad Request',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    409: 'Conflict',
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

/** The bytes that end a request head. Named because the reader has to skip exactly this many. */
const HEAD_TERMINATOR = '\r\n\r\n';

/** The status a pre-handler refusal answers with. */
function statusFor(code: ServeRejection): number {
  if (code === 'HEAD_TOO_LARGE' || code === 'TOO_MANY_HEADERS') return 431;
  if (code === 'BODY_TOO_LARGE') return 413;
  return 400;
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
  respond: (head: RequestHead) => {
    status: number;
    headers: ReadonlyMap<string, string>;
    body: Uint8Array;
  },
  /**
   * Whether this surface takes a request body at all.
   *
   * A parameter rather than a property of the request, because it is a property of the SURFACE:
   * the browsing proxy has no route that takes a body and never will, so a body arriving there is
   * refused without any route being consulted. Defaulting to `false` keeps the refusal the thing
   * a caller has to opt out of.
   */
  acceptsBody = false,
): void {
  let buffer: Buffer = Buffer.alloc(0);
  let done = false;
  let headEnd = -1;
  let parsed: RequestHead | null = null;
  let frame: Framing = { kind: 'none' };

  const timer = setTimeout(() => {
    if (done) return;
    done = true;
    writeHttp(socket, 400, new Map(), asciiBody('HEAD_TIMEOUT'));
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

  const refuse = (code: ServeRejection): void => {
    finish(() => writeHttp(socket, statusFor(code), new Map(), asciiBody(code)));
  };

  // No `setEncoding`. The buffer is octets, because every bound in this file is a count of octets
  // and `Content-Length` is one too. See the module comment.
  socket.on('data', (chunk: Buffer) => {
    if (done) return;
    buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);

    if (headEnd === -1) {
      // The head bound applies only until the head is complete. Afterwards the body has its own,
      // already checked against the declared length, and a legitimate body must not be able to
      // push a connection past a limit that was never about it.
      if (buffer.length > SERVE_LIMITS.headBytes) {
        refuse('HEAD_TOO_LARGE');
        return;
      }
      const end = buffer.indexOf(HEAD_TERMINATOR);
      if (end === -1) return;
      headEnd = end;
      try {
        // `latin1`, one octet to one character, so `parseHead`'s length checks count what the
        // sender sent. Any byte above 0x7f survives into a header value and is then refused by the
        // grammar that reads it, which is where a charset decision belongs.
        parsed = parseHead(buffer.subarray(0, end).toString('latin1'));
        frame = framing(parsed.headers);
      } catch (error) {
        refuse(error instanceof ServeError ? error.code : 'MALFORMED_REQUEST');
        return;
      }
      if (!acceptsBody && frame.kind === 'fixed') {
        refuse('UNEXPECTED_BODY');
        return;
      }
    }

    const wanted = frame.kind === 'fixed' ? frame.length : 0;
    const have = buffer.length - (headEnd + HEAD_TERMINATOR.length);
    // More than was declared is not a longer body; it is a second request, or a sender and a
    // server that disagree about where the first one ended. Refused rather than ignored — ignoring
    // it is what let the old code answer a request it had not finished reading.
    if (have > wanted) {
      refuse('UNEXPECTED_BODY');
      return;
    }
    // Fewer means the sender is still speaking, and the head deadline stays armed while it does.
    // A body deadline that only advanced when the peer chose to send would be no deadline: the
    // whole attack is a peer that promised bytes and then went quiet.
    if (have < wanted) return;

    const head = parsed as RequestHead;
    const body = buffer.subarray(headEnd + HEAD_TERMINATOR.length);
    finish(() => {
      const request: RequestHead = { ...head, body };
      // **Nothing used to stand between a handler's throw and the process.**
      //
      // There is no `uncaughtException` handler anywhere in this package, so a throw from any
      // injected port — a resolver bug, a corrupt log, a store that cannot read its own file —
      // did not answer 500. It terminated the process, taking the browsing proxy AND the control
      // API with it, because they are separate listeners inside one process. The surface an
      // operator uses to find out why a resolver is unhappy died of the fault it exists to report.
      //
      // The catch sits HERE rather than in each of the two callers, because the defect was
      // structural: nothing guaranteed the property, so a third listener added later would have
      // reintroduced it by writing the same natural code. Both callers also refuse in their own
      // vocabulary; this is the backstop that makes "no throw reaches the process" true of the
      // module rather than of its current call sites.
      let answer: { status: number; headers: ReadonlyMap<string, string>; body: Uint8Array };
      try {
        answer = respond(request);
      } catch {
        // The error itself is DISCARDED, not logged to the wire. An exception message is the
        // likeliest place in this program for a filesystem path, a token or a record's bytes to
        // be sitting, and LOCAL-SURFACE.md 2.4 forbids a refusal that confirms VayuWeb is even
        // running. RESOLUTION.md's catalogue entry 1500 is a bare 500 for exactly this reason.
        writeHttp(socket, 500, new Map(), new Uint8Array(0), request.method === 'HEAD');
        return;
      }
      // RFC 7230 3.3.3: a response to HEAD never carries an entity, whatever its status. Applied
      // here, once, for both surfaces — the handlers decide what the answer IS and this decides
      // how much of it goes on the wire, which is the split the rest of this file keeps.
      writeHttp(socket, answer.status, answer.headers, answer.body, request.method === 'HEAD');
    });
  });

  socket.on('error', () => {
    done = true;
    clearTimeout(timer);
    socket.destroy();
  });
}

/**
 * The connection accounting, separated from the socket so it can be attacked as data.
 *
 * **This existed inline and leaked a slot on every refusal.** The refusal path incremented the
 * counter and returned before registering the handler that gives the slot back, so an attacker
 * who could cause as many refusals as the cap allows killed the listener permanently — no crash,
 * no log entry, just a resolver that answers 503 to its own user forever. Found by the
 * adversarial pass over this file rather than by reading it.
 *
 * Reproducing it through real sockets turned out to be timing-dependent: the client's `connect`
 * event fires before the server's `connection` handler for later sockets, so three concurrent
 * dials never reliably put three connections in flight. That is the argument for this class
 * existing at all. Accounting is policy, policy belongs where it can be exercised as data, and a
 * defect only reproducible by racing the operating system is a defect with no regression test.
 */
export class ConnectionCounter {
  private open = 0;
  private readonly cap: number;

  constructor(cap: number = SERVE_LIMITS.connections) {
    this.cap = cap;
  }

  /** How many slots are currently held. */
  get inUse(): number {
    return this.open;
  }

  /**
   * Take a slot, or refuse.
   *
   * A refusal takes no slot at all — the counter is incremented only on success. The alternative,
   * increment-then-check-then-return, is what leaked: correct on the accepting path and silently
   * permanent on the other.
   */
  admit(): boolean {
    if (this.open >= this.cap) return false;
    this.open += 1;
    return true;
  }

  /** Give a slot back. Never goes below zero, so a double close cannot mint capacity. */
  release(): void {
    if (this.open > 0) this.open -= 1;
  }
}

/** Cap concurrent connections, closing the excess rather than queueing it. */
function withConnectionCap(server: Server, cap: number = SERVE_LIMITS.connections): Server {
  const counter = new ConnectionCounter(cap);
  server.on('connection', (socket: Socket) => {
    if (!counter.admit()) {
      // Refused with a status rather than a silent close, so an operator watching the surface can
      // tell exhaustion apart from a network fault. No slot was taken, so nothing has to be given
      // back — which is the property the inline version got wrong.
      writeHttp(socket, 503, new Map(), asciiBody('TOO_MANY_CONNECTIONS'));
      return;
    }
    socket.on('close', () => counter.release());
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
  /** Concurrent connections. Defaults to {@link SERVE_LIMITS.connections}; tests lower it. */
  readonly maxConnections?: number;
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
  /**
   * A number that changes whenever the local registry does. `Store.length` is the obvious one.
   *
   * Read once per request and handed to the cache, which drops everything when it moves. Optional
   * because not every embedder has a registry it can count; absent, the cache is exactly what
   * RESOLUTION.md specifies and no less correct, only staler within its stated TTLs.
   */
  readonly generation?: () => number;
  /** The resolution cache, when the caller needs to reach it too — see `DELETE /v1/cache`. */
  readonly cache?: ResolutionCache;
}

/**
 * Bind the browsing proxy.
 *
 * **Loopback only, and not configurable.** RESOLUTION.md binds this to `127.0.0.1`; an address
 * parameter would be a way to publish a reader's resolver to their whole network, and there is no
 * legitimate reason to want one. A caller wanting that has misunderstood what the proxy is.
 */
export function serveProxy(options: ProxyServerOptions): Promise<Listener> {
  // Supplied by the caller when one process serves both surfaces, because `DELETE /v1/cache` on
  // the control API has to reach the cache the proxy is reading. A default is kept so an embedder
  // binding only the proxy does not have to make one.
  const cache = options.cache ?? new ResolutionCache();
  const clock = options.now;

  const server = withConnectionCap(
    createTcpServer((socket) => {
      serveConnection(socket, (head) => {
        const request: ProxyRequest = {
          method: head.method,
          target: head.target,
          headers: head.headers,
        };
        // Caught here as well as in `serveConnection`, and the difference is the answer's SHAPE.
        // The backstop below can only emit a bare 500 — it serves two surfaces and knows neither's
        // vocabulary. This one knows it is the browsing proxy, so its 500 carries the full
        // security-header set that every other proxy response carries. A 500 that is the one
        // response on this surface without a Content-Security-Policy is a response an attacker
        // would rather have than the page.
        try {
          // **The generation, applied per request rather than declared and never called.** The
          // cache's TTLs are a bound on how long a wrong answer may persist; this is what makes
          // the ordinary case shorter than the bound. A registration, an UPDATE, a RENEW, a
          // TRANSFER and a REVOKE are all appends, so a log that has not grown is a registry
          // whose answers cannot have changed — and one that has grown invalidates everything
          // for the price of an integer comparison.
          //
          // Optional because a caller may have no such number, in which case the specification's
          // TTLs stand alone and the cache behaves exactly as RESOLUTION.md describes.
          const generation = options.generation?.();
          if (generation !== undefined) cache.setGeneration(generation);
          return handleRequest(request, options.ports, cache, clock(), options.options ?? {});
        } catch {
          // RESOLUTION.md catalogue entry 1500. The error is discarded rather than reported: an
          // exception message is where a path, a token or a record's bytes would be.
          return refusal('INTERNAL');
        }
      });
    }),
    options.maxConnections ?? SERVE_LIMITS.connections,
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
  /**
   * The token to compare against, read **per request** rather than captured once.
   *
   * A function and not a string, because `POST /v1/token/rotate` changes it while the listener is
   * bound. Capturing the value at bind time would return a fresh token to the caller and then go
   * on refusing it — the shape of defect this codebase has found repeatedly, where a mechanism
   * produces a new value and the thing that checks it keeps reading the old one.
   */
  readonly token: () => string;
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
  const initial = options.token();
  if (Buffer.from(initial, 'base64url').length !== TOKEN_BYTES) {
    throw new Error(
      `the control token must be base64url of ${TOKEN_BYTES} bytes; this one decodes to ` +
        `${Buffer.from(initial, 'base64url').length}, so no caller could ever authenticate`,
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
      serveConnection(
        socket,
        (head) => {
          const request: ControlRequest = {
            method: head.method,
            path: head.target,
            headers: head.headers,
            body: head.body,
          };
          // Caught here as well as in `serveConnection`, for the same reason the proxy catches its
          // own: the backstop can only emit a bare 500. This surface answers JSON, and an operator
          // whose resolver has a failing port is exactly the person parsing this response.
          //
          // The reason is a CONSTANT, not the exception. `handleControlRequest` is reached only past
          // the token check, so the caller is authenticated — but "authenticated" is not "entitled
          // to a stack trace": an internal error's message is where a log path or a record's bytes
          // would be, and this response ends up in support tickets and screenshots.
          let response: ControlResponse;
          try {
            response = handleControlRequest(request, options.ports, options.token());
          } catch {
            response = { status: 500, headers: new Map(), body: { error: 'internal' } };
          }
          return {
            status: response.status,
            headers: response.headers,
            // The control API answers JSON, so the encoding is decided here — at the one place that
            // knows the body is text — rather than being left for the writer to guess at.
            body:
              response.body === undefined
                ? new Uint8Array(0)
                : Buffer.from(JSON.stringify(response.body), 'utf8'),
          };
        },
        // The one surface that takes a body. `RESOLUTION.md` gives four of its endpoints an
        // argument that is not a path component, and `POST /v1/resolve` is the first of them.
        true,
      );
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
