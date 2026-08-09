/**
 * The control API: the resolver's privileged local surface.
 *
 * docs/spec/LOCAL-SURFACE.md section 1 and docs/spec/RESOLUTION.md are authoritative.
 *
 * ## The transport is the security model
 *
 * This API is served over a **Unix domain socket** (a named pipe on Windows), mode `0600`, in a
 * directory owned by the user with mode `0700`. It MUST NOT listen on TCP, on any address,
 * including loopback — and a build offering a TCP control listener is non-conformant even when it
 * is opt-in and even when it is "for development", because a development affordance is an attack
 * surface that ships.
 *
 * The reason is one sentence: **a browser cannot address a Unix domain socket.** No `fetch`, no
 * form, no `img`, no WebSocket, no `XMLHttpRequest` can name one. Moving the privileged surface
 * off TCP therefore deletes DNS rebinding, CSRF including its preflight-free forms, WebSocket
 * `Upgrade` reach and browser port-scanning — permanently, and without a defence that has to stay
 * correct forever.
 *
 * This module cannot bind anything, which is how that rule is enforced here rather than merely
 * stated: {@link handleControlRequest} is a pure function, and {@link assertSocketAddress} exists
 * so a caller that tries to hand it a TCP address fails loudly at the boundary.
 *
 * ## What is still required, and why
 *
 * Everything below is defence in depth against the one failure the socket does not cover: an
 * operator or a future refactor putting an HTTP proxy, a socket-activation shim or a container
 * port-forward in front of it.
 *
 * - A bearer token on every endpoint, compared in constant time. A socket permission is a control
 *   a misconfigured umask can weaken; a token is not.
 * - `Origin` rejected outright, `X-VayuWeb-Control: 1` required, `Upgrade` refused, and
 *   `Access-Control-Allow-Origin` never set for any origin, ever.
 * - `GET /v1/config` redacts the token. `GET /v1/status` discloses no build version to an
 *   unauthenticated caller, because a version string is a fingerprint and a vulnerability-matching
 *   aid.
 */

import { onlyThisNodeHoldsIt, summarise, type AvailabilityReport } from './pins.ts';
import { isRatifiedTld, labelRejection } from './names.ts';
import { decodeCid } from './content.ts';
import type { PinOutcome } from './pins.ts';
import { timingSafeEqual } from 'node:crypto';

/** The header a caller must send. RESOLUTION.md, "The control API". */
export const CONTROL_HEADER = 'x-vayuweb-control';

/** Token length in bytes before base64url encoding. RESOLUTION.md: 32 bytes from the OS CSPRNG. */
export const TOKEN_BYTES = 32;

export interface ControlRequest {
  readonly method: string;
  readonly path: string;
  /** Lowercased header names. */
  readonly headers: ReadonlyMap<string, string>;
  /**
   * The request body, already bounded by the transport, or zero bytes.
   *
   * `serve.ts` refuses anything over `SERVE_LIMITS.bodyBytes` before a byte of it is buffered, so
   * this handler may parse what it is given without a length check of its own. That division is
   * deliberate: a bound belongs where the allocation happens, and a handler that re-checked one it
   * cannot enforce would be stating a guarantee it does not provide.
   */
  readonly body: Uint8Array;
}

export interface ControlResponse {
  readonly status: number;
  readonly headers: ReadonlyMap<string, string>;
  readonly body: unknown;
}

/** What the control API is allowed to read and change. Narrow, so the surface is legible. */
export interface ControlPorts {
  status(): { mode: string; uptime: number; listeners: readonly string[] };
  /** The build version. Only ever disclosed to an authenticated caller. */
  version(): string;
  logHead(): { length: number; root: string };
  config(): Record<string, unknown>;
  /** Whether the proxy is currently emitting diagnostic headers. */
  diagnostics(): boolean;
  setDiagnostics(on: boolean): void;
  /**
   * What this node can honestly say about who is keeping its content alive.
   *
   * Returns the reports rather than a count, because `pins.ts` exists to stop a count being read
   * as a promise — there is no `total` field on an {@link AvailabilityReport} and this port must
   * not become the place one is invented.
   */
  pins(): readonly AvailabilityReport[];
  /**
   * What this resolver currently answers for one **already-validated** name.
   *
   * The validation happens in the router, before the name is used for anything at all — the same
   * ordering LOCAL-SURFACE.md 3.1 imposes on the browsing proxy, for the same reason: a hostile
   * name is the injection vector, and a check that runs after the value has been echoed, keyed or
   * logged is a check that ran too late.
   */
  resolve(label: string, tld: string): unknown;
  /** Entries held and how often they were used. */
  cacheStats(): {
    negative: number;
    positive: number;
    manifests: number;
    hits: number;
    misses: number;
  };
  /** Forget everything, or one validated name. Returns how many entries went. */
  flushCache(name: { label: string; tld: string } | null): number;
  /** Peer count and swarm state. */
  peers(): { joined: boolean; peers: number; detail: string };
  /**
   * Undertake to keep and serve an **already-validated** CID, or say why not.
   *
   * The outcome is `pins.ts`'s, not this module's, because refusing to pin what the node does not
   * hold is an availability decision and that is where availability decisions live.
   */
  pin(cid: string): PinOutcome;
  /** Release a pin. `false` means it was not pinned, which is not an error. */
  unpin(cid: string): boolean;
}

/**
 * Refuse anything that is not a Unix domain socket or a Windows named pipe.
 *
 * A guard at the boundary rather than a sentence in a document, because the sentence was already
 * written and five documents went on specifying a TCP port anyway. A path that parses as an
 * address, or that contains a colon-and-digits, is refused: `127.0.0.1:7653` is not a filesystem
 * path, and a caller passing one has misunderstood the whole design.
 */
export function assertSocketAddress(address: string): void {
  const looksLikeTcp =
    /^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(address) ||
    /^\[?[0-9a-f:]+\]?:\d+$/i.test(address) ||
    /^localhost:\d+$/i.test(address) ||
    /^:\d+$/.test(address) ||
    /^\d+$/.test(address);
  if (looksLikeTcp) {
    throw new Error(
      `the control API must be served on a Unix domain socket or a Windows named pipe, ` +
        `never on TCP: refusing ${JSON.stringify(address)}. LOCAL-SURFACE.md section 1.`,
    );
  }
  const isPipe = address.startsWith('\\\\.\\pipe\\') || address.startsWith('\\\\?\\pipe\\');
  if (!isPipe && !address.startsWith('/') && !address.startsWith('./')) {
    throw new Error(
      `the control API socket path must be absolute or a Windows named pipe: ` +
        `refusing ${JSON.stringify(address)}`,
    );
  }
}

/**
 * Compare a presented token against the expected one without leaking its length or contents.
 *
 * Constant time over fixed-length decoded bytes, per LOCAL-SURFACE.md 1.2. Decoding first matters:
 * comparing the base64url text would leak the length of the *encoding*, and would let two
 * different encodings of one token disagree.
 */
export function tokenMatches(presented: string, expected: string): boolean {
  let a: Buffer;
  let b: Buffer;
  try {
    a = Buffer.from(presented, 'base64url');
    b = Buffer.from(expected, 'base64url');
  } catch {
    return false;
  }
  // A length mismatch cannot be compared in constant time, so it is answered without comparing —
  // and the expected token is always TOKEN_BYTES, so a wrong length is a wrong token regardless.
  if (a.length !== TOKEN_BYTES || b.length !== TOKEN_BYTES) return false;
  return timingSafeEqual(a, b);
}

const DENY_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ['cache-control', 'no-store'],
  ['content-type', 'application/json'],
  // Never an Access-Control-Allow-Origin, for any origin, ever. Stated as an explicit empty
  // absence rather than left to the reader: this is the header whose accidental appearance would
  // undo the whole surface.
];

function deny(status: number, reason: string): ControlResponse {
  return { status, headers: new Map(DENY_HEADERS), body: { error: reason } };
}

function ok(body: unknown): ControlResponse {
  return { status: 200, headers: new Map(DENY_HEADERS), body };
}

/**
 * Handle one control request.
 *
 * Order matters and is the point: the browser-shaped refusals run before authentication, so a
 * page that somehow reached this surface is turned away without its token guess ever being
 * timed, and the unauthenticated `GET /v1/health` runs last rather than being special-cased early
 * where it would bypass them.
 */
export function handleControlRequest(
  request: ControlRequest,
  ports: ControlPorts,
  token: string,
): ControlResponse {
  // 1.3: no WebSocket endpoint exists, so the rejection is unconditional and needs no analysis.
  if (request.headers.has('upgrade') || /upgrade/i.test(request.headers.get('connection') ?? '')) {
    return deny(400, 'upgrade_not_supported');
  }

  // A browser attaches Origin to any cross-origin request it makes. Nothing that legitimately
  // speaks to this API has an origin, so the header's presence is by itself disqualifying.
  if (request.headers.has('origin')) return deny(403, 'forbidden');

  if (request.headers.get(CONTROL_HEADER) !== '1') return deny(403, 'forbidden');

  const authorisation = request.headers.get('authorization') ?? '';
  const presented = authorisation.startsWith('Bearer ') ? authorisation.slice(7) : '';
  if (!tokenMatches(presented, token)) return deny(401, 'unauthorised');

  // Routes carrying a name are matched before the exact-path switch, and the name is validated
  // **before it is used for anything** — not echoed, not used as a cache key, not passed onward
  // until the grammar has accepted it. That is LOCAL-SURFACE.md 3.1's rule; it is written for the
  // browsing proxy and the reason applies here unchanged.
  // Same ordering as the name-carrying routes below, for the same reason: a CID is the other
  // value a user types, and it is validated before it reaches a pin set, an echo or a log line.
  if (request.method === 'DELETE' && request.path.startsWith(PIN_PREFIX)) {
    const cid = parseControlCid(request.path.slice(PIN_PREFIX.length));
    if (cid === null) return deny(400, 'bad_cid');
    return ok({ cid, unpinned: ports.unpin(cid) });
  }

  const named = namedRoute(request.method, request.path);
  if (named !== null) {
    if (named.name === null) return deny(400, 'bad_name');
    switch (named.route) {
      case 'records':
        // The validated name is spread **last**, so a port returning a `name` of its own cannot
        // overwrite it. The other order shipped first and hid a mutation: the test double happened
        // to return `name`, so replacing the router's echo with the raw request path changed
        // nothing observable. A field that can be silently overridden by a collaborator is a field
        // whose value is decided somewhere other than where it is validated.
        return ok({
          ...(ports.resolve(named.name.label, named.name.tld) as object),
          name: `${named.name.label}.${named.name.tld}`,
        });
      case 'cache':
        return ok({ flushed: ports.flushCache(named.name) });
    }
  }

  switch (`${request.method} ${request.path}`) {
    case 'POST /v1/resolve': {
      // The only endpoint on this surface whose argument arrives in a body, and the validation is
      // the SAME function the path-carrying routes use — `parseControlName`. Two spellings of one
      // grammar is how the two disagree later, and this codebase has the habit already: a resolver
      // path mapper and a content port each implemented a subset of one rule, and the part neither
      // implemented went missing without anything looking wrong.
      const fields = jsonObject(request.body);
      if (fields === null) return deny(400, 'bad_request');
      const asked = fields['name'];
      if (typeof asked !== 'string') return deny(400, 'bad_request');
      const name = parseControlName(asked);
      if (name === null) return deny(400, 'bad_name');
      // Spread first, validated name last, for the reason `records` gives above.
      return ok({
        ...(ports.resolve(name.label, name.tld) as object),
        name: `${name.label}.${name.tld}`,
      });
    }
    case 'POST /v1/pin': {
      const fields = jsonObject(request.body);
      if (fields === null) return deny(400, 'bad_request');
      const asked = fields['cid'];
      if (typeof asked !== 'string') return deny(400, 'bad_request');
      const cid = parseControlCid(asked);
      if (cid === null) return deny(400, 'bad_cid');
      const outcome = ports.pin(cid);
      // `not_held` is 409 rather than 404 or 400: the request is well formed and the CID is real,
      // and what is wrong is the state of this node. Answering 200 would put an intention into
      // `GET /v1/pins` beside a holding with nothing distinguishing them, which is the single
      // thing `pins.ts` exists to prevent.
      if (outcome === 'not_held') return deny(409, 'not_held');
      if (outcome === 'full') return deny(409, 'pin_set_full');
      return ok({ cid, outcome });
    }
    case 'GET /v1/health':
      return ok({ ok: true });
    case 'GET /v1/status': {
      const status = ports.status();
      // The version is included only here, past the token check. RESOLUTION.md and
      // LOCAL-SURFACE.md 1.4 both forbid disclosing it to an unauthenticated caller: a version
      // string is a fingerprint and a vulnerability-matching aid.
      return ok({ ...status, version: ports.version() });
    }
    case 'GET /v1/log/head':
      return ok(ports.logHead());
    case 'GET /v1/config':
      return ok(redact(ports.config()));
    case 'GET /v1/pins':
      // RESOLUTION.md's endpoint list has carried `GET /v1/pins` since it was written, and
      // `pins.ts` — the module whose entire job is to refuse to overstate availability — was
      // imported by nothing that ships. A module that cannot be reached cannot refuse anything.
      //
      // The rendered sentence goes over the wire beside the fields, deliberately. `summarise`
      // exists "rather than left to each caller because this is exactly the sentence that gets
      // written optimistically", and a client handed only numbers writes its own.
      return ok({
        pins: ports.pins().map((pin) => ({
          ...pin,
          summary: summarise(pin),
          onlyThisNodeHolds: onlyThisNodeHoldsIt(pin),
        })),
      });
    case 'GET /v1/peers':
      return ok(ports.peers());
    case 'GET /v1/cache/stats':
      return ok(ports.cacheStats());
    case 'DELETE /v1/cache':
      return ok({ flushed: ports.flushCache(null) });
    case 'GET /v1/diagnostics':
      return ok({ enabled: ports.diagnostics() });
    case 'POST /v1/diagnostics/on':
      ports.setDiagnostics(true);
      return ok({ enabled: true });
    case 'POST /v1/diagnostics/off':
      ports.setDiagnostics(false);
      return ok({ enabled: false });
    default:
      return deny(404, 'no_such_endpoint');
  }
}

/**
 * Match the two routes that carry a name, and validate it before anything reads it.
 *
 * Returns `null` when the path is not one of them, and `{ name: null }` when it is one of them
 * carrying something that is not a name — so the caller answers 400 rather than 404, which is the
 * truthful distinction between "no such endpoint" and "that is not a name".
 *
 * **The grammar is what makes this safe, and decoding is not.** An earlier version of this comment
 * said a percent-encoded traversal checked before decoding "is a traversal that was not checked",
 * and that is false: `..%2f..` fails the label grammar exactly as `../..` does, because neither
 * `%` nor `/` nor `.` is in it. Decoding is here so a legitimately encoded name — `atlas%2Dsite`,
 * `atlasobservatory%2Evayu` — is accepted, which makes the check *more* permissive rather than
 * less. Saying otherwise would have credited the safety to the wrong line, and the wrong line is
 * the one somebody removes.
 *
 * `decodeURIComponent` throws on a malformed escape and the throw is caught: a bad escape is a bad
 * name, not a 500.
 */
export function namedRoute(
  method: string,
  path: string,
): { route: 'records' | 'cache'; name: { label: string; tld: string } | null } | null {
  const routes = [
    { prefix: '/v1/records/', method: 'GET', route: 'records' as const },
    { prefix: '/v1/cache/', method: 'DELETE', route: 'cache' as const },
  ];
  for (const candidate of routes) {
    if (method !== candidate.method || !path.startsWith(candidate.prefix)) continue;
    return { route: candidate.route, name: parseControlName(path.slice(candidate.prefix.length)) };
  }
  return null;
}

/**
 * The one place a name reaching the control API is turned into a label and a TLD, or refused.
 *
 * Shared by the path-carrying routes and by `POST /v1/resolve`, deliberately: two implementations
 * of one grammar are two implementations that will disagree, and the disagreement will be found by
 * whoever gets past the more permissive of them.
 *
 * Percent-decoding runs first and it is not what makes this safe — the grammar is. `..%2f..` fails
 * the label rules exactly as `../..` does, because neither `%` nor `/` nor `.` is in them.
 * Decoding is here so a legitimately encoded name (`atlas%2Dsite`, `atlasobservatory%2Evayu`) is
 * accepted, which makes the check *more* permissive rather than less. An earlier version of this
 * comment credited the safety to the decoding, and the line credited with safety is the line
 * somebody removes. `decodeURIComponent` throws on a malformed escape and the throw is caught: a
 * bad escape is a bad name, not a 500.
 */
export function parseControlName(raw: string): { label: string; tld: string } | null {
  if (raw.length === 0) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return null;
  }
  const dot = decoded.lastIndexOf('.');
  if (dot <= 0 || dot === decoded.length - 1) return null;
  const label = decoded.slice(0, dot).toLowerCase();
  const tld = decoded.slice(dot + 1).toLowerCase();
  if (!isRatifiedTld(tld) || labelRejection(label) !== null) return null;
  return { label, tld };
}

const PIN_PREFIX = '/v1/pin/';

/**
 * The one place a CID reaching the control API is validated, or refused.
 *
 * Shared by `POST /v1/pin`, which takes it in a body, and `DELETE /v1/pin/{cid}`, which takes it in
 * a path — deliberately, and for the reason {@link parseControlName} gives about names: two
 * spellings of one grammar are two spellings that disagree later, and the disagreement is found by
 * whoever gets past the more permissive of them.
 *
 * `decodeCid` is the grammar. It refuses anything that is not a base32 CIDv1, which excludes every
 * traversal spelling by construction rather than by a check that has to think of them — `..%2f..`
 * is not base32 and neither is `../..`. Percent-decoding runs first so a legitimately encoded CID
 * is accepted; it is not what makes this safe.
 */
export function parseControlCid(raw: string): string | null {
  if (raw.length === 0) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return null;
  }
  try {
    decodeCid(decoded);
  } catch {
    return null;
  }
  return decoded;
}

/**
 * A JSON object from a request body, or null for anything else.
 *
 * Anything else means: not valid UTF-8, not valid JSON, or valid JSON that is not a plain object —
 * an array, a string, a number, `null`.
 *
 * **Exported so its contract can be asserted directly**, and that is a finding rather than a
 * preference. Two mutations of this function survived a suite that tested it only through
 * `POST /v1/resolve`: dropping `Array.isArray` and dropping `fatal`. The first is invisible
 * through that caller by construction — an array's own keys are `"0"`, `"1"`, … and never `name`,
 * so the handler answers `bad_request` either way — and a property no caller can distinguish is a
 * property that belongs to the function and has to be tested there. The same reasoning `parseHead`
 * and `framing` are exported for.
 *
 * `fatal: true` is the load-bearing one and it is not defensive. Without it an invalid byte
 * becomes U+FFFD and the body parses: `{"name":"atlasobservatory.vayu","x":"\xff"}` is refused
 * with it and answered **200** without it. Silent repair means the bytes acted on are not the
 * bytes sent, which is the disagreement between sender and server this whole surface is arranged
 * to avoid.
 *
 * `Object.hasOwn` guards the read: `JSON.parse` will happily produce an own `__proto__` key, and a
 * plain `in` or a prototype-chain lookup on the result is how a body reaches a property nobody
 * put there.
 */
export function jsonObject(body: Uint8Array): Record<string, unknown> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const source = parsed as Record<string, unknown>;
  const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of Object.keys(source)) {
    if (Object.hasOwn(source, key)) out[key] = source[key];
  }
  return out;
}

/**
 * Redact every secret-bearing value from a configuration dump.
 *
 * Keyed on the name rather than the value, and on a *substring* match, so a key nobody thought of
 * — `apiToken`, `token_path`, `secretKey` — is redacted by default rather than disclosed by
 * default. The failure mode of over-redaction is an operator having to look somewhere else; the
 * failure mode of under-redaction is the token in a log.
 */
export function redact(config: Record<string, unknown>): Record<string, unknown> {
  const secret = /token|secret|password|passphrase|private|seed|key/i;
  const out: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(config)) {
    if (secret.test(name)) {
      out[name] = '[redacted]';
    } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      out[name] = redact(value as Record<string, unknown>);
    } else {
      out[name] = value;
    }
  }
  return out;
}
