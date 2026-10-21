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
///
/// **The whole set from CONTENT-SECURITY.md sections 2 and 3, and the six that were missing are
/// not decoration.** This list carried five of the eleven: the Content-Security-Policy, the
/// Permissions-Policy, `Referrer-Policy`, `X-Content-Type-Options` and
/// `Cross-Origin-Opener-Policy`. The six it did not carry are
///
/// - `X-Frame-Options: DENY`, redundant beside `frame-ancestors 'none'` on modern engines and
///   kept for older ones;
/// - `X-DNS-Prefetch-Control: off`, because speculative DNS is **not** covered by CSP and
///   `<link rel="dns-prefetch">` produces a clearnet DNS query — the exact leak this project
///   exists to prevent;
/// - `Cache-Control: no-store`, which removes the HTTP disk cache and so leaves no trail on the
///   reader's disk, at the cost of the offline benefit of content addressing;
/// - `Cross-Origin-Embedder-Policy: require-corp`;
/// - `Cross-Origin-Resource-Policy: same-origin`, which blocks the cross-origin size and timing
///   probes that are active regardless of secure context;
/// - `Origin-Agent-Cluster: ?1`.
///
/// The module's own header claimed "the security-header set from CONTENT-SECURITY.md sections
/// 2-3 verbatim", and the claim was false in six places: a documented fidelity the code did not
/// have, which is the kind of sentence that stops a reader from checking the next one. The set
/// is now the whole set, and the `headers` suite in `conformance/vectors.json` states it, so the
/// two serving surfaces of this project cannot answer a reader's browser differently again.
pub const SECURITY_HEADERS: [(&str, &str); 11] = [
    ("content-security-policy", DEFAULT_CSP),
    ("permissions-policy", PERMISSIONS_POLICY),
    ("referrer-policy", "no-referrer"),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("x-dns-prefetch-control", "off"),
    ("cache-control", "no-store"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-embedder-policy", "require-corp"),
    ("cross-origin-resource-policy", "same-origin"),
    ("origin-agent-cluster", "?1"),
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
    /// The tree-relative path of the file that answered, or `None` when no file did.
    ///
    /// **Which file answered is a fact about the routing, and the routing is what two
    /// implementations of this project have to agree about.** The `paths` suite in
    /// `conformance/vectors.json` states it: a request path, a published tree, and the file that
    /// must answer. Without this field a reader of the response could not tell which file it
    /// was, and the suite could only compare bytes — which is to say, it could not tell a
    /// directory's index from a file that happened to hold the same bytes.
    pub path: Option<String>,
}

/// The content type of a served file, from its extension.
///
/// **The same table the registry's proxy uses, extension for extension and type for type.** The
/// proxy's table had nine extensions where this one had twenty-eight, so a webfont, a module
/// script, an icon and a video were served by the proxy as `application/octet-stream` — which a
/// browser under `nosniff` refuses, so a site published with any of them rendered with none of
/// them. The `mime` suite in `conformance/vectors.json` states the table, and both
/// implementations are checked against it.
pub fn mime_of(path: &str) -> &'static str {
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
    //
    // **The manifest's `index`, for every directory path and not only for the ones written with
    // a trailing slash.** RESOLUTION.md step 13 says "resolving `/` and directory paths to the
    // manifest's `index` when one is declared and to `index.html` otherwise" — a directory path is
    // a directory path whether or not the writer ended it with a slash, and the registry's proxy
    // used to read the trailing slash as the whole of the rule: it asked the tree for
    // `index.html` and never for the declared `home.html`, so a site with a declared index and a
    // subdirectory served its subdirectory on this surface and 404'd on that one.
    //
    // **A declared index that is not in the tree is discarded, and `index.html` answers
    // instead** — the same treatment step 13 gives every other declared file ("a declared file
    // that is not present in the verified tree is discarded rather than reported"), and the same
    // treatment the proxy gives it. The two surfaces used to disagree here as well: this one
    // looked for the declared index and stopped, and the other looked for the declared index and
    // then for `index.html`. The specification's wording admits a second reading, in which the
    // manifest's index is the only file a directory path may answer; the `paths` suite in
    // `conformance/vectors.json` states the reading implemented here, and the editorial panel
    // may change the suite and the code together.
    let index_candidates: Vec<String> = {
        let mut candidates: Vec<String> = Vec::new();
        if let Some(declared) = manifest.as_ref().and_then(|m| m.index.clone()) {
            candidates.push(declared);
        }
        if !candidates.iter().any(|name| name == "index.html") {
            candidates.push("index.html".to_string());
        }
        candidates
    };
    for index_name in index_candidates {
        let directory_index: Vec<String> = {
            let mut segments = request.segments.clone();
            segments.push(index_name.clone());
            segments
        };
        if let Some(body) = try_file(&directory_index) {
            let index_mime = mime_of(index_name.as_str());
            return scan_and_answer(&directory_index.join("/"), index_mime, body);
        }
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
                path: Some(segments[0].clone()),
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
                path: Some(segments[0].clone()),
            });
        }
    }
    Ok(Response {
        status: 404,
        reason: "Not Found",
        content_type: "text/plain; charset=utf-8",
        body: b"not found in this tree\n".to_vec(),
        // No file answered, and the suite asks which one did.
        path: None,
    })
}

/// The last step before anything is served: run the publisher's own checker over the document
/// and refuse it if it violates a rule no header can enforce.
///
/// Two media are scanned, and the reason they are two is that the rules live in two places:
/// the HTML rules (speculative `<link rel>`, `<meta http-equiv="refresh">`) are in the
/// document, and the service-worker rule is in the SCRIPT that registers it — a script
/// served unrefused would register a worker the moment the reader's page loads it, and no
/// header can prevent that.
///
/// Everything else passes untouched: the CSP governs how the BROWSER treats those, and
/// scanning binary blobs for HTML rules is nonsense. A refusal carries the rendered
/// findings, because this surface serves the person who published the tree; a mystery
/// refusal is what 3.1.6 exists to prevent.
fn scan_and_answer(
    path: &str,
    content_type: &'static str,
    body: Vec<u8>,
) -> Result<Response, WalkError> {
    let is_html = content_type.starts_with("text/html");
    let is_script = content_type.starts_with("text/javascript")
        || content_type.starts_with("application/javascript");
    if !is_html && !is_script {
        return Ok(Response {
            status: 200,
            reason: "OK",
            content_type,
            body,
            path: Some(path.to_string()),
        });
    }
    // The path is the doctor's own dispatch key: the rules are written against file
    // extensions, and a script served under a name that hides its extension is not
    // something the publisher's checker would have looked at either.
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
            path: Some(path.to_string()),
        });
    }
    let mut detail = String::from(
        "this document violates rules that headers alone cannot enforce \
         (a page that renders half-blocked, or a script that keeps running after the \
         reader leaves, is worse than a clear refusal):\n\n",
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
        path: Some(path.to_string()),
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
    // The security headers go BEFORE the blank line that ends the head. They were appended
    // after it, which made them the first bytes of the BODY: a browser reads no policy from a
    // body, so every 400, 405 and 431 was served with no policy at all, while the code above
    // said the headers go on EVERY answer, success or refusal.
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: \
         {}\r\n",
        text.len(),
    );
    for (name, value) in SECURITY_HEADERS {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("connection: close\r\n\r\n");
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
                            path: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::{Enforcement, RULES};

    /// The value this server sends for a header name, if it sends one at all.
    fn header_value(name: &str) -> Option<&'static str> {
        SECURITY_HEADERS
            .iter()
            .find(|(header, _)| *header == name)
            .map(|(_, value)| *value)
    }

    /// **The rule table's own claims, checked against the headers THIS server sends.**
    ///
    /// PUBLISHING.md 3.1.6 calls the rule table one shared definition, and the registry-side
    /// test checks the client's rules against the REGISTRY's proxy — so a directive dropped
    /// from the registry's headers fails CI. Nothing checked them against the CLIENT's own
    /// serving surface: the rule table claimed a read-time enforcement the client did not
    /// perform, and the site a user reads through `vayu serve` was looser than the one the
    /// checker had promised. A rule nobody enforces is a wish.
    #[test]
    fn every_header_enforced_rule_is_enforced_by_the_headers_this_server_sends() {
        for rule in RULES {
            if rule.enforcement != Enforcement::Csp {
                continue;
            }
            for (header, contains) in rule.evidence {
                let value = header_value(header)
                    .unwrap_or_else(|| panic!("{}: this server sends no {header}", rule.id));
                assert!(
                    value.contains(contains),
                    "{}: {header} must contain \"{contains}\" -- the rule's read-time \
                     enforcement depends on it",
                    rule.id
                );
            }
            for (header, omit) in rule.evidence_absent {
                let value = header_value(header)
                    .unwrap_or_else(|| panic!("{}: this server sends no {header}", rule.id));
                assert!(
                    !value.contains(omit),
                    "{}: {header} must NOT contain \"{omit}\" -- its presence would grant what \
                     this rule refuses",
                    rule.id
                );
            }
        }
    }

    /// **The policy is the specification's, not a paraphrase of it.**
    ///
    /// The registry's proxy has always been checked against the canonical block in
    /// CONTENT-SECURITY.md; this client only said it was byte-identical to it, in a comment.
    /// A second copy of a security policy is a copy that drifts, and this one is wire-visible:
    /// a directive lost in transcription is a relaxation nobody chose. So the specification is
    /// read back and compared rather than trusted to have been copied correctly.
    #[test]
    fn the_emitted_policy_is_byte_identical_to_the_canonical_block_in_the_specification() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../docs/spec/CONTENT-SECURITY.md"
        );
        let spec = std::fs::read_to_string(path).expect("the specification is in the repository");
        let block = spec
            .split("<!-- canonical:content-security-policy -->")
            .nth(1)
            .expect("the specification carries a canonical block");
        let fenced = block.split("```").nth(1).expect("a fenced block");
        let canonical = fenced
            .trim_start_matches("text\n")
            .trim()
            .trim_start_matches("Content-Security-Policy:")
            .trim();
        assert_eq!(
            DEFAULT_CSP, canonical,
            "the client's policy must be the specification's, byte for byte"
        );
    }
}
