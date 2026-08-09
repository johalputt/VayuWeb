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

  switch (`${request.method} ${request.path}`) {
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
