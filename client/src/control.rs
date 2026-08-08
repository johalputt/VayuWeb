//! The client half of the resolver's control API.
//!
//! `docs/spec/LOCAL-SURFACE.md` section 1, and `registry/src/control.ts` is the server it speaks
//! to. This module existed as a claim before it existed as code: `Cargo.toml` described this crate
//! as "identity handling and the control-API client" while the crate held only the first half.
//! A package description is a pushed artifact like any other, and this corpus has spent enough of
//! its time on statements that were true of the intention rather than of the code.
//!
//! ## Why the transport is a Unix socket, restated where it is enforced
//!
//! The server refuses to bind TCP. That refusal is worth nothing if the client offers to speak
//! TCP, because the pair is what an operator configures — so [`ControlEndpoint`] cannot hold a
//! host and a port. There is no variant for one. `assertSocketAddress` on the server side is the
//! mirror of this, and the reason both exist is that LOCAL-SURFACE.md said "Unix socket" in prose
//! and five documents went on specifying a loopback port anyway.
//!
//! A browser cannot address a Unix domain socket: no `fetch`, no form, no `img`, no WebSocket can
//! name one. That single fact deletes DNS rebinding, CSRF and browser port-scanning against this
//! surface permanently, rather than by a defence that has to stay correct forever.
//!
//! ## What this module does not do
//!
//! It does not open the socket. Building the request and parsing the response are decisions with
//! rules — the token goes in one header and nowhere else, `Origin` is never sent, a redacted field
//! is never treated as a value — and those are testable without a filesystem. Connecting is not.
//! The split is the same one `registry/src/control.ts` makes and for the same reason: everything
//! that can be a pure function is one, so the rules are exercised as data rather than as a socket.

use core::fmt;

use crate::secrets::Secret;

/// Where the control API lives.
///
/// **One variant, deliberately.** An `endpoint` that could be a TCP address is an endpoint an
/// operator can point at one, and LOCAL-SURFACE.md 1.1 forbids the surface existing there at all —
/// "a build offering a TCP control listener is non-conformant even when it is opt-in and even when
/// it is 'for development', because a development affordance is an attack surface that ships". The
/// same reasoning binds the client: a client that can speak TCP is half of a TCP control API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlEndpoint {
    /// A Unix domain socket path, or a Windows named pipe.
    Socket(String),
}

impl ControlEndpoint {
    /// Accept a socket path, refusing anything shaped like a network address.
    ///
    /// The check mirrors the server's `assertSocketAddress` rather than trusting it: a caller who
    /// types `127.0.0.1:7653` has misunderstood the design, and finding that out at the boundary
    /// is the difference between an error message and a connection attempt to a listening port
    /// that belongs to something else.
    pub fn socket(path: &str) -> Result<Self, ControlError> {
        if path.is_empty() {
            return Err(ControlError::NotASocketPath {
                given: String::new(),
            });
        }
        let looks_like_tcp = path.starts_with("http://")
            || path.starts_with("https://")
            || path.rsplit_once(':').is_some_and(|(host, port)| {
                !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
            });
        if looks_like_tcp {
            return Err(ControlError::NotASocketPath {
                given: path.to_string(),
            });
        }
        Ok(ControlEndpoint::Socket(path.to_string()))
    }

    /// The path to connect to.
    pub fn path(&self) -> &str {
        match self {
            ControlEndpoint::Socket(path) => path,
        }
    }
}

/// The requests this client knows how to make.
///
/// An enumeration rather than a free-form path, so a caller cannot invent a route and cannot
/// smuggle anything into one. Every value here is a constant: nothing a user typed reaches the
/// request line, which is what makes request splitting unreachable rather than defended against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRequest {
    Health,
    Status,
    LogHead,
    Config,
    Diagnostics,
    DiagnosticsOn,
    DiagnosticsOff,
}

impl ControlRequest {
    /// The method and path, exactly as `handleControlRequest` matches them.
    pub fn route(self) -> (&'static str, &'static str) {
        match self {
            ControlRequest::Health => ("GET", "/v1/health"),
            ControlRequest::Status => ("GET", "/v1/status"),
            ControlRequest::LogHead => ("GET", "/v1/log/head"),
            ControlRequest::Config => ("GET", "/v1/config"),
            ControlRequest::Diagnostics => ("GET", "/v1/diagnostics"),
            ControlRequest::DiagnosticsOn => ("POST", "/v1/diagnostics/on"),
            ControlRequest::DiagnosticsOff => ("POST", "/v1/diagnostics/off"),
        }
    }

    /// Whether this request changes the resolver's state.
    ///
    /// Present so a caller can decide about confirmation prompts without matching on the variant
    /// and getting it wrong when a route is added.
    pub fn is_mutating(self) -> bool {
        matches!(
            self,
            ControlRequest::DiagnosticsOn | ControlRequest::DiagnosticsOff
        )
    }
}

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// The endpoint was not a socket path. See [`ControlEndpoint::socket`].
    NotASocketPath { given: String },
    /// The response was not something this client will parse.
    Malformed { detail: String },
    /// The server answered a status this client will not treat as success.
    Refused { status: u16, reason: String },
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlError::NotASocketPath { given } => write!(
                f,
                "the control API is a Unix domain socket, never a network address; \
                 {given:?} is not a socket path"
            ),
            ControlError::Malformed { detail } => write!(f, "malformed control response: {detail}"),
            ControlError::Refused { status, reason } => {
                write!(f, "control API refused with {status}: {reason}")
            }
        }
    }
}

impl std::error::Error for ControlError {}

/// The header the server requires on every request, per LOCAL-SURFACE.md 1.3.
pub const CONTROL_HEADER: &str = "X-VayuWeb-Control";

/// Build the request head for one call.
///
/// Three rules live here and each has a reason the server states:
///
/// - **The token appears once, in `Authorization`.** Not in the path, not in a query string, not
///   in a second header "for convenience": a token in a URL is a token in a log, in a shell
///   history and in a screenshot.
/// - **`Origin` is never sent.** The server refuses any request carrying one, before it
///   authenticates, because nothing that legitimately speaks to this API has an origin. A client
///   that sent one would be refused; a client that *could* send one is a client an integration
///   might teach to.
/// - **No `Connection: upgrade`, ever.** There is no WebSocket endpoint, so the server rejects the
///   header unconditionally.
///
/// The token is taken by reference from a [`Secret`], so it is never copied into an owned `String`
/// the caller then has to remember to zeroise — `PRIVACY.md` 7.3's "never placed in a
/// garbage-collected string", which Rust satisfies by construction, is only satisfied if the value
/// does not leak into one on the way past.
pub fn request_head(
    endpoint: &ControlEndpoint,
    request: ControlRequest,
    token: &Secret,
) -> Vec<u8> {
    let (method, path) = request.route();
    let _ = endpoint; // The path is the connect target, not part of the head.
                      // Bytes, not a `String`. The token is borrowed straight from the `Secret` into the buffer that
                      // goes on the wire, so it is never converted into an owned string somebody has to remember to
                      // wipe — and `Secret::expose` returns `&[u8]` precisely so that conversion has to be asked for.
    let mut head = Vec::new();
    head.extend_from_slice(method.as_bytes());
    head.push(b' ');
    head.extend_from_slice(path.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\n");
    // A Unix socket has no authority, and HTTP/1.1 requires the header to exist. `localhost` is
    // the conventional filler and the server never reads it.
    head.extend_from_slice(b"host: localhost\r\n");
    head.extend_from_slice(CONTROL_HEADER.as_bytes());
    head.extend_from_slice(b": 1\r\n");
    head.extend_from_slice(b"authorization: Bearer ");
    head.extend_from_slice(token.expose());
    head.extend_from_slice(b"\r\n");
    head.extend_from_slice(b"connection: close\r\n");
    head.extend_from_slice(b"\r\n");
    head
}

/// A parsed control response: the status, and the JSON body as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlResponse {
    pub status: u16,
    pub body: String,
}

/// Parse a response, refusing anything this client will not read as an answer.
///
/// **The body is bytes until it is proved to be text.** The sibling implementation shipped a defect
/// of exactly this shape — a body decoded as latin-1 at one end and re-encoded as UTF-8 at the
/// other, which doubled every octet above `0x7f` — so the decode happens once, here, and fails
/// loudly rather than producing a plausible wrong string.
pub fn parse_response(bytes: &[u8]) -> Result<ControlResponse, ControlError> {
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| ControlError::Malformed {
            detail: "no head terminator".to_string(),
        })?;
    let head = core::str::from_utf8(&bytes[..split]).map_err(|_| ControlError::Malformed {
        detail: "the response head is not UTF-8".to_string(),
    })?;
    let status_line = head.lines().next().unwrap_or_default();
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| ControlError::Malformed {
            detail: format!("no status in {status_line:?}"),
        })?;
    let body = core::str::from_utf8(&bytes[split + 4..]).map_err(|_| ControlError::Malformed {
        detail: "the response body is not UTF-8".to_string(),
    })?;
    Ok(ControlResponse {
        status,
        body: body.to_string(),
    })
}

/// The marker `GET /v1/config` puts where a secret would be.
pub const REDACTED: &str = "[redacted]";

/// Turn a response into a success or the refusal it actually was.
///
/// Exists because "the request completed" and "the request was answered" are different facts, and
/// a client that conflates them hands the caller a 401 body as though it were a status. The server
/// answers a JSON reason on every refusal; that reason is carried through rather than replaced
/// with a generic message, since the operator reading it is the one person entitled to it.
pub fn require_success(response: ControlResponse) -> Result<ControlResponse, ControlError> {
    if (200..300).contains(&response.status) {
        return Ok(response);
    }
    Err(ControlError::Refused {
        status: response.status,
        reason: response.body,
    })
}

/// Whether a value read out of a config dump is the redaction marker rather than a value.
///
/// Exists so a caller cannot accidentally display `[redacted]` to a user as though it were the
/// token, or worse, send it back as one. The server redacts by field NAME on a substring match, so
/// any field a future version adds is redacted by default — and a client that treats the marker as
/// data would turn that safe default into a confusing one.
pub fn is_redacted(value: &str) -> bool {
    value == REDACTED
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::Secret;

    fn token() -> Secret {
        let mut bytes = b"a-token-that-is-long-enough-to-be-real".to_vec();
        Secret::take(&mut bytes)
    }

    /// How many times `needle` occurs in `haystack`. Written out because the failure this guards
    /// against is an EXTRA copy of the token, which a "contains" check cannot see.
    fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
        if needle.is_empty() || haystack.len() < needle.len() {
            return 0;
        }
        haystack
            .windows(needle.len())
            .filter(|window| *window == needle)
            .count()
    }

    #[test]
    fn a_network_address_is_refused_as_an_endpoint() {
        // The server refuses to BIND TCP. That is worth nothing if the client offers to SPEAK it,
        // because the pair is what an operator configures. Every one of these is a thing somebody
        // would plausibly type after reading a document that says "the control API on port 7653",
        // and five documents said exactly that before the guard existed on the other side.
        for given in [
            "127.0.0.1:7653",
            "localhost:7653",
            "http://127.0.0.1:7653",
            "https://example.com:443",
            "[::1]:7653",
            "",
        ] {
            assert_eq!(
                ControlEndpoint::socket(given),
                Err(ControlError::NotASocketPath {
                    given: given.to_string()
                }),
                "{given:?} must not be accepted as a control endpoint"
            );
        }
    }

    #[test]
    fn an_ordinary_socket_path_is_accepted() {
        // And the guard must not be so eager that it refuses the real thing — a check that
        // refuses everything passes the test above and makes the client unusable.
        for given in [
            "/run/user/1000/vayuweb/control.sock",
            "/tmp/vayuweb-test/control.sock",
            r"\\.\pipe\vayuweb-control",
            "./control.sock",
        ] {
            assert_eq!(
                ControlEndpoint::socket(given).map(|e| e.path().to_string()),
                Ok(given.to_string()),
                "{given:?} is a socket path and must be accepted"
            );
        }
    }

    #[test]
    fn the_token_appears_once_and_only_in_authorization() {
        // A token in a path or a query string is a token in a log, a shell history and a
        // screenshot. Counting occurrences rather than checking the header is present: the failure
        // this guards against is an EXTRA copy, which a presence check cannot see.
        let secret = token();
        let endpoint = ControlEndpoint::socket("/run/vayuweb/control.sock").unwrap();
        for request in [
            ControlRequest::Health,
            ControlRequest::Status,
            ControlRequest::LogHead,
            ControlRequest::Config,
            ControlRequest::Diagnostics,
            ControlRequest::DiagnosticsOn,
            ControlRequest::DiagnosticsOff,
        ] {
            let head = request_head(&endpoint, request, &secret);
            assert_eq!(
                occurrences(&head, secret.expose()),
                1,
                "the token does not appear exactly once for {request:?}"
            );
            let text = String::from_utf8(head.clone()).expect("the head is ASCII");
            // The route itself must carry nothing secret. Written as a real comparison after the
            // first attempt at this line was a tautology — `windows(1).any(|_| path.contains(..))`
            // asserts about `path` regardless of the window, which is an assertion that cannot
            // fail. A test that cannot fail is the defect this whole audit keeps finding.
            let (_, path) = request.route();
            assert_eq!(occurrences(path.as_bytes(), secret.expose()), 0);
            assert!(text.contains("authorization: Bearer "));
            // The server refuses these two before it authenticates, so a client that could send
            // either is a client an integration might one day teach to.
            assert!(!text.to_lowercase().contains("origin:"));
            assert!(!text.to_lowercase().contains("upgrade"));
            assert!(text.contains("X-VayuWeb-Control: 1"));
        }
    }

    #[test]
    fn the_request_line_carries_nothing_a_caller_chose() {
        // Every route is a constant, so there is no value to escape and no splitting to defend
        // against. This asserts that property rather than assuming it: a future route taking a
        // parameter would fail here before it reached the wire.
        let endpoint = ControlEndpoint::socket("/run/vayuweb/control.sock").unwrap();
        for request in [ControlRequest::Status, ControlRequest::DiagnosticsOn] {
            let head = request_head(&endpoint, request, &token());
            let text = String::from_utf8(head).expect("the head is ASCII");
            let line = text.lines().next().unwrap();
            assert!(!line.contains('\r'), "no CR inside the request line");
            assert_eq!(line.split(' ').count(), 3, "METHOD SP TARGET SP VERSION");
        }
        // And the socket path — the one caller-supplied string in play — never reaches the head.
        let odd = ControlEndpoint::socket("/tmp/a b\r\nX-Injected: 1/control.sock").unwrap();
        let head = request_head(&odd, ControlRequest::Status, &token());
        let text = String::from_utf8(head).expect("the head is ASCII");
        assert!(!text.contains("X-Injected"));
    }

    #[test]
    fn only_the_two_diagnostics_routes_are_mutating() {
        for request in [
            ControlRequest::Health,
            ControlRequest::Status,
            ControlRequest::LogHead,
            ControlRequest::Config,
            ControlRequest::Diagnostics,
        ] {
            assert!(!request.is_mutating(), "{request:?} reads only");
        }
        assert!(ControlRequest::DiagnosticsOn.is_mutating());
        assert!(ControlRequest::DiagnosticsOff.is_mutating());
    }

    #[test]
    fn a_response_body_is_decoded_once_or_refused() {
        let ok =
            parse_response(b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\n{\"ok\":true}").unwrap();
        assert_eq!(ok.status, 200);
        assert_eq!(ok.body, "{\"ok\":true}");

        // Multi-byte text survives intact. The sibling implementation shipped a body decoded as
        // latin-1 at one end and re-encoded as UTF-8 at the other, which doubled every octet above
        // 0x7f and produced a complete, well-formed, wrong document with no error anywhere.
        let mut accented = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        accented.extend_from_slice("{\"name\":\"caf\u{e9} \u{fc}n\u{ef}code\"}".as_bytes());
        let parsed = parse_response(&accented).unwrap();
        assert_eq!(parsed.body, "{\"name\":\"caf\u{e9} \u{fc}n\u{ef}code\"}");

        // Bytes that are not text are refused rather than replaced. A lossy decode here would
        // hand the caller a plausible string that is not what arrived.
        let mut invalid = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        invalid.extend_from_slice(&[0xff, 0xfe, 0x00]);
        assert!(matches!(
            parse_response(&invalid),
            Err(ControlError::Malformed { .. })
        ));

        for broken in [
            &b"HTTP/1.1 200 OK\r\ncontent-length: 0"[..], // no terminator
            &b"garbage\r\n\r\n"[..],                      // no status
            &b"\r\n\r\n"[..],                             // empty head
        ] {
            assert!(
                matches!(parse_response(broken), Err(ControlError::Malformed { .. })),
                "{broken:?} must be refused"
            );
        }
    }

    #[test]
    fn a_refusal_is_never_returned_as_an_answer() {
        // A 401 body is not a status, and a client that returned it as one would show an operator
        // `{"error":"unauthorised"}` where they expected their resolver's state.
        let ok = ControlResponse {
            status: 200,
            body: "{\"ok\":true}".to_string(),
        };
        assert_eq!(require_success(ok.clone()), Ok(ok));

        for status in [400u16, 401, 403, 404, 500, 503] {
            let refused = ControlResponse {
                status,
                body: "{\"error\":\"unauthorised\"}".to_string(),
            };
            assert_eq!(
                require_success(refused),
                Err(ControlError::Refused {
                    status,
                    reason: "{\"error\":\"unauthorised\"}".to_string(),
                }),
                "{status} must not be reported as success"
            );
        }

        // 204 and 299 are successes, or the boundary is drawn by accident rather than on purpose.
        for status in [200u16, 201, 204, 299] {
            assert!(require_success(ControlResponse {
                status,
                body: String::new()
            })
            .is_ok());
        }
    }

    #[test]
    fn the_redaction_marker_is_never_mistaken_for_a_value() {
        // `GET /v1/config` redacts by field NAME on a substring match, so a field a future version
        // adds is redacted by default. A client that treated the marker as data would turn that
        // safe default into a confusing one — or, worse, send it back as a token.
        assert!(is_redacted(REDACTED));
        assert!(!is_redacted("a-real-token"));
        assert!(!is_redacted(""));
        assert!(!is_redacted("[redacted] "), "not a prefix match");
    }
}
