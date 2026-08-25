//! The loopback preview surface: serve ONE pinned tree over HTTP, locally only.
//!
//! PUBLISHING.md's status line stayed a Draft because nothing served what it publishes. This
//! module is the smallest honest step past that: a preview server that reads a tree back out of
//! a local [`BlockStore`] — through the verified traversal in [`crate::dagnode`] — and answers
//! a browser on `127.0.0.1`. It is NOT the browsing proxy of LOCAL-SURFACE.md section 2: there
//! is no name routing (no records are contacted), no port 7654, no passthrough, no CONNECT, and
//! nothing but one fixed tree behind it. What it does carry over from the implementation of
//! record's `serve.ts`, byte for byte where bytes exist:
//!
//! - the strict request-head parser's rules (bounded head, bounded headers, obsolete folding
//!   refused, token names enforced) — every leniency in an HTTP parser is a smuggling
//!   primitive;
//! - the security-header set from CONTENT-SECURITY.md sections 2–3 verbatim, including
//!   `require-trusted-types-for 'script'` and `trusted-types 'none'`: this surface implements
//!   NO relaxation, because neither implementation does yet;
//! - the deep-link rule of PUBLISHING.md section 2.3: a miss serves `notFound` with 404 when
//!   the manifest declares one, else `fallback` with 200 when declared, else a bare 404;
//! - no identifying headers (LOCAL-SURFACE.md 2.4), no CORS, no `Access-Control-Allow-*`.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::cid::Cid;
use crate::dagnode::{read_path, WalkError, WalkLimits};
use crate::doctor::{self, parse_manifest, Enforcement, Manifest};
use crate::publish::SiteFile;
use crate::store::BlockStore;

/// The default CSP, byte-identical to CONTENT-SECURITY.md section 2 via the implementation of
/// record's `DEFAULT_CSP`.
pub const DEFAULT_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
img-src 'self'; font-src 'self'; media-src 'self'; connect-src 'self'; manifest-src 'self'; \
worker-src 'none'; child-src 'none'; frame-src 'none'; object-src 'none'; \
frame-ancestors 'none'; form-action 'self'; base-uri 'none'; webrtc 'block'; \
require-trusted-types-for 'script'; trusted-types 'none'";

/// The Permissions-Policy deny list, from CONTENT-SECURITY.md section 3 — every powerful feature
/// denied to the document and every nested context. Mirrors `PERMISSIONS_POLICY` exactly.
pub const PERMISSIONS_POLICY: &str = "accelerometer=(), ambient-light-sensor=(), \
attribution-reporting=(), autoplay=(), battery=(), bluetooth=(), browsing-topics=(), camera=(), \
clipboard-read=(), clipboard-write=(), compute-pressure=(), display-capture=(), \
encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), \
identity-credentials-get=(), idle-detection=(), join-ad-interest-group=(), \
language-detector=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), \
otp-credentials=(), payment=(), picture-in-picture=(), private-state-token-issuance=(), \
private-state-token-redemption=(), publickey-credentials-create=(), publickey-credentials-get=(), \
run-ad-auction=(), screen-wake-lock=(), serial=(), shared-storage=(), \
shared-storage-select-url=(), speaker-selection=(), storage-access=(), summarizer=(), \
translator=(), usb=(), web-share=(), window-management=(), xr-spatial-tracking=()";

/// Response headers on EVERY answer, success or refusal. Names are lower-case, matching
/// `SECURITY_HEADERS` byte for byte.
const SECURITY_HEADERS: [(&str, &str); 5] = [
    ("content-security-policy", DEFAULT_CSP),
    ("permissions-policy", PERMISSIONS_POLICY),
    ("referrer-policy", "no-referrer"),
    ("x-content-type-options", "nosniff"),
    ("cross-origin-opener-policy", "same-origin"),
];

/// Bounds copied from `SERVE_LIMITS` where they apply to a request head.
pub const HEAD_BYTES_LIMIT: usize = 16 * 1024;
pub const HEADER_LINES_LIMIT: usize = 100;

/// Why a request was refused before routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    Malformed(&'static str),
    TooLarge,
    MethodNotAllowed,
}

/// One parsed request: method, decoded path segments, and whether a body may follow (it may
/// not — GET and HEAD only).
pub struct Request {
    pub is_head: bool,
    pub segments: Vec<String>,
}

/// Parse and validate the request head from raw bytes. Deliberately strict, per `parseHead`:
/// no folding, no odd methods, no oversized heads, and path traversal refused outright.
pub fn parse_request(head: &[u8]) -> Result<Request, RequestError> {
    if head.len() > HEAD_BYTES_LIMIT {
        return Err(RequestError::TooLarge);
    }
    let text =
        core::str::from_utf8(head).map_err(|_| RequestError::Malformed("head is not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v), None) => (m, t, v),
        _ => {
            return Err(RequestError::Malformed(
                "a request line is METHOD SP TARGET SP VERSION",
            ))
        }
    };
    if !(version == "HTTP/1.0" || version == "HTTP/1.1") {
        return Err(RequestError::Malformed("unsupported version"));
    }
    let is_head = match method {
        "GET" => false,
        "HEAD" => true,
        _ => return Err(RequestError::MethodNotAllowed),
    };
    if target.is_empty() || target.len() > 2048 {
        return Err(RequestError::Malformed(
            "request target is empty or over the limit",
        ));
    }
    let mut header_count = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        header_count += 1;
        if header_count > HEADER_LINES_LIMIT {
            return Err(RequestError::TooLarge);
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(RequestError::Malformed("obsolete header line folding"));
        }
        let Some(colon) = line.find(':') else {
            return Err(RequestError::Malformed("header line without a name"));
        };
        let name = &line[..colon];
        // Header-name token characters, lower-case-insensitive by construction here: we do not
        // need the values, only the shape, so anything outside the token set is refused.
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&b))
        {
            return Err(RequestError::Malformed("header name is not a token"));
        }
    }

    let path = target.split(['?', '#']).next().unwrap_or(target);
    let decoded = percent_decode(path)?;
    let segments: Vec<String> = decoded
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect();
    for segment in &segments {
        if segment == "." || segment == ".." || segment.contains('\\') || segment.contains('\0') {
            return Err(RequestError::Malformed("path segment escapes the tree"));
        }
    }
    Ok(Request { is_head, segments })
}

fn percent_decode(text: &str) -> Result<String, RequestError> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0usize;
    while at < bytes.len() {
        match bytes[at] {
            b'%' => {
                let hex = bytes
                    .get(at + 1..at + 3)
                    .ok_or(RequestError::Malformed("a % escape needs two hex digits"))?;
                let high = (hex[0] as char).to_digit(16);
                let low = (hex[1] as char).to_digit(16);
                match (high, low) {
                    (Some(high), Some(low)) => out.push(((high << 4) | low) as u8),
                    _ => return Err(RequestError::Malformed("invalid % escape")),
                }
                at += 3;
            }
            byte => {
                out.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| RequestError::Malformed("path is not UTF-8"))
}

/// What a route decided to send.
pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

fn mime_of(path: &str) -> &'static str {
    let extension = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match extension.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "txt" | "text" | "log" | "csv" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "mp3" => "audio/mpeg",
        "ogg" | "oga" => "audio/ogg",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        _ => "application/octet-stream",
    }
}

/// Route one request against one pinned tree. The manifest — part of the published tree, read
/// through the same verified traversal — supplies index/notFound/fallback.
///
/// 3.1.6's second half lives here: every HTML document is checked with the PUBLISHER'S OWN
/// checker code before it leaves, and a document violating any [`Enforcement::Scan`] rule is
/// REFUSED rather than served. These are exactly the rules no header can express — speculative
/// DNS fires before any policy applies, meta refresh bypasses CSP entirely, nothing in CSP
/// stops a service worker — so a serving surface that does not scan simply serves them. A
/// checker-passes-resolver-refuses mismatch cannot happen by construction: both sides call the
/// same `doctor::check` over the same bytes. (The header-expressible rules are enforced by the
/// emitted CSP itself; see `Enforcement`.)
pub fn route(
    store: &BlockStore,
    root: &Cid,
    request: &Request,
    limits: &WalkLimits,
) -> Result<Response, WalkError> {
    // The manifest, if present. Its ABSENCE means no routing directives at all: only exact
    // files resolve, which is what a tree without a manifest deserves.
    let manifest: Option<Manifest> =
        match read_path(store, root, &[".vayu", "manifest.json"], limits) {
            Ok(bytes) => match core::str::from_utf8(&bytes) {
                Ok(text) => Some(parse_manifest(text)),
                Err(_) => {
                    return Err(WalkError::BoundExceeded("the manifest is not UTF-8"));
                }
            },
            Err(WalkError::NotFound) => None,
            Err(e) => return Err(e),
        };

    let requested: String = request.segments.join("/");
    let try_file = |segments: &[String]| -> Option<Vec<u8>> {
        read_path(
            store,
            root,
            segments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
            limits,
        )
        .ok()
    };

    let body = try_file(&request.segments);
    if let Some(body) = body {
        let content_type = mime_of(&requested);
        return scan_and_answer(&requested, content_type, body);
    }

    // Not an exact file. If it is a directory, its index document answers instead.
    let index_name = manifest
        .as_ref()
        .and_then(|m| m.index.clone())
        .unwrap_or_else(|| "index.html".to_string());
    let directory_index: Vec<String> = {
        let mut segments = request.segments.clone();
        segments.push(index_name.clone());
        segments
    };
    if let Some(body) = try_file(&directory_index) {
        let index_mime = mime_of(index_name.as_str());
        return scan_and_answer(&directory_index.join("/"), index_mime, body);
    }

    // Deep-link miss: notFound with 404, else fallback with 200, else bare 404.
    if let Some(name) = manifest.as_ref().and_then(|m| m.not_found.clone()) {
        let segments: Vec<String> = vec![name];
        if let Some(body) = try_file(&segments) {
            return Ok(Response {
                status: 404,
                reason: "Not Found",
                content_type: mime_of(segments[0].as_str()),
                body,
            });
        }
    }
    if let Some(name) = manifest.as_ref().and_then(|m| m.fallback.clone()) {
        let segments: Vec<String> = vec![name];
        if let Some(body) = try_file(&segments) {
            return Ok(Response {
                status: 200,
                reason: "OK",
                content_type: mime_of(segments[0].as_str()),
                body,
            });
        }
    }
    Ok(Response {
        status: 404,
        reason: "Not Found",
        content_type: "text/plain; charset=utf-8",
        body: b"not found in this tree\n".to_vec(),
    })
}

/// The last step before anything is served: run the publisher's own checker over the document
/// and refuse it if it violates a rule no header can enforce. Non-HTML passes untouched — the
/// CSP governs how the BROWSER treats those, and scanning binary blobs for HTML rules is
/// nonsense. A refusal carries the rendered findings, because this surface serves the person
/// who published the tree; a mystery refusal is what 3.1.6 exists to prevent.
fn scan_and_answer(
    path: &str,
    content_type: &'static str,
    body: Vec<u8>,
) -> Result<Response, WalkError> {
    if !content_type.starts_with("text/html") {
        return Ok(Response {
            status: 200,
            reason: "OK",
            content_type,
            body,
        });
    }
    let files = [SiteFile {
        path: path.to_string(),
        content: body.clone(),
    }];
    let findings = doctor::check(&files);
    let refused: Vec<_> = findings
        .into_iter()
        .filter(|finding| {
            doctor::RULES
                .iter()
                .any(|rule| rule.id == finding.rule && rule.enforcement == Enforcement::Scan)
        })
        .collect();
    if refused.is_empty() {
        return Ok(Response {
            status: 200,
            reason: "OK",
            content_type,
            body,
        });
    }
    let mut detail = String::from(
        "this document violates rules that headers alone cannot enforce \
         (the browser would render it half-blocked, which is worse than a clear refusal):\n\n",
    );
    for finding in &refused {
        detail.push_str(&finding.render());
        detail.push('\n');
    }
    Ok(Response {
        status: 403,
        reason: "Forbidden",
        content_type: "text/plain; charset=utf-8",
        body: detail.into_bytes(),
    })
}

fn write_response(stream: &mut TcpStream, response: &Response, include_body: bool) {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len(),
    );
    for (name, value) in SECURITY_HEADERS {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("connection: close\r\n\r\n");
    let _ = stream.write_all(head.as_bytes());
    if include_body {
        let _ = stream.write_all(&response.body);
    }
    let _ = stream.flush();
}

fn refuse(stream: &mut TcpStream, error: &RequestError) {
    let (status, reason, text): (u16, &'static str, &[u8]) = match error {
        RequestError::Malformed(_) => (400, "Bad Request", b"malformed request\n"),
        RequestError::TooLarge => (
            431,
            "Request Header Fields Too Large",
            b"request too large\n",
        ),
        RequestError::MethodNotAllowed => {
            (405, "Method Not Allowed", b"only GET and HEAD are served\n")
        }
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        text.len(),
    );
    for (name, value) in SECURITY_HEADERS {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(text);
    let _ = stream.flush();
}

/// Serve requests until `running` goes false. One thread-safe connection at a time keeps the
/// surface honest for what it is: a local preview, not a peer-facing endpoint.
pub fn serve_until(
    listener: TcpListener,
    store: Arc<BlockStore>,
    root: Cid,
    running: Arc<AtomicBool>,
    limits: WalkLimits,
) {
    while running.load(Ordering::SeqCst) {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(_) => {
                // A transient accept failure — descriptor pressure on a loaded machine —
                // must not end the preview: ending it resets every client already waiting
                // in the backlog. Back off briefly and keep serving until told to stop.
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
        };
        // Read up to the blank line, refusing oversized heads. An oversized head is DRAINED
        // (up to a bound) rather than abandoned: a server that stops reading and closes while
        // the client is still writing earns a TCP reset that destroys the refusal itself.
        let mut head = Vec::new();
        let mut buffer = [0u8; 1024];
        let mut oversized = false;
        let mut discarded = 0usize;
        let mut saw_end = false;
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if !oversized {
                        head.extend_from_slice(&buffer[..n]);
                        if head.windows(4).any(|window| window == b"\r\n\r\n") {
                            saw_end = true;
                            break;
                        }
                        if head.len() > HEAD_BYTES_LIMIT {
                            oversized = true;
                        }
                    } else {
                        // Discard until the peer finishes saying what we already refused.
                        discarded += n;
                        if buffer.windows(4).any(|window| window == b"\r\n\r\n")
                            || discarded > 64 * 1024
                        {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        if oversized {
            refuse(&mut stream, &RequestError::TooLarge);
            continue;
        }
        let end = if saw_end {
            head.windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|at| at + 4)
                .unwrap_or(head.len())
        } else {
            head.len()
        };
        match parse_request(&head[..end]) {
            Ok(request) => match route(&store, &root, &request, &limits) {
                Ok(response) => write_response(&mut stream, &response, !request.is_head),
                Err(e) => {
                    let body = format!("{}\n", e);
                    write_response(
                        &mut stream,
                        &Response {
                            status: 500,
                            reason: "Internal Error",
                            content_type: "text/plain; charset=utf-8",
                            body: body.into_bytes(),
                        },
                        true,
                    );
                }
            },
            Err(e) => refuse(&mut stream, &e),
        }
    }
}

/// A running preview server: the address to open plus the switch to turn it off.
pub struct ServingHandle {
    pub addr: SocketAddr,
    running: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl ServingHandle {
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        // Unblocking accept(): connect to ourselves once so the loop wakes and exits.
        let _ = TcpStream::connect(self.addr);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for ServingHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Bind loopback and start serving in a background thread. Port 0 picks a free one, which is
/// what a preview tool should do rather than squatting a named port.
pub fn spawn(
    store: Arc<BlockStore>,
    root: Cid,
    port: u16,
    limits: WalkLimits,
) -> std::io::Result<ServingHandle> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))?;
    let addr = listener.local_addr()?;
    let running = Arc::new(AtomicBool::new(true));
    let thread_running = Arc::clone(&running);
    let join = std::thread::spawn(move || {
        serve_until(listener, store, root, thread_running, limits);
    });
    Ok(ServingHandle {
        addr,
        running,
        join: Some(join),
    })
}
