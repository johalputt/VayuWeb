//! The loopback preview surface, exercised over real sockets.
//!
//! The routing rules these tests pin come from PUBLISHING.md section 2.3 (index resolution,
//! notFound-with-404, fallback-with-200) and the header set from CONTENT-SECURITY.md sections
//! 2–3 via the implementation of record's `SECURITY_HEADERS`. What is additionally pinned:
//! the refusals — traversal attempts, oversized heads, non-GET verbs — and that NO response
//! carries CORS or identifying headers.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::sync::Arc;

use vayuweb_client::dagnode::WalkLimits;
use vayuweb_client::publish::{import_site, SiteFile};
use vayuweb_client::serve;
use vayuweb_client::store::BlockStore;

struct Fixture {
    _dir: std::path::PathBuf,
    server: serve::ServingHandle,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.stop();
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

fn serve_tree(tag: &str, files: &[SiteFile]) -> Fixture {
    let dir = std::env::temp_dir().join(format!("vayuweb-serve-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = BlockStore::open(&dir).expect("opens");
    let (blocks, root) = import_site(files).expect("imports");
    store
        .put_all(blocks.into_iter().map(|b| (b.cid.clone(), b.bytes)))
        .expect("pins");
    let server = serve::spawn(Arc::new(store), root, 0, WalkLimits::default()).expect("binds");
    Fixture { _dir: dir, server }
}

fn request(fixture: &Fixture, target: &str, method: &str) -> (u16, String, Vec<u8>) {
    let mut stream = TcpStream::connect(fixture.server.addr).expect("connects");
    write!(stream, "{method} {target} HTTP/1.1\r\nhost: x\r\n\r\n").expect("writes");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("reads");
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("head end")
        + 4;
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, head, raw[head_end..].to_vec())
}

fn site_files() -> Vec<SiteFile> {
    vec![
        SiteFile {
            path: "index.html".into(),
            content: b"<!doctype html><title>home</title>".to_vec(),
        },
        SiteFile {
            path: "style.css".into(),
            content: b"p { color: teal }".to_vec(),
        },
        SiteFile {
            path: ".vayu/manifest.json".into(),
            content: br#"{"version":1,"title":"t"}"#.to_vec(),
        },
    ]
}

fn with_docs_files() -> Vec<SiteFile> {
    vec![
        SiteFile {
            path: "docs/index.html".into(),
            content: b"docs home".to_vec(),
        },
        SiteFile {
            path: ".vayu/manifest.json".into(),
            content: br#"{"version":1}"#.to_vec(),
        },
    ]
}

fn not_found_files() -> Vec<SiteFile> {
    vec![
        SiteFile {
            path: "index.html".into(),
            content: b"home".to_vec(),
        },
        SiteFile {
            path: "404.html".into(),
            content: b"custom not found".to_vec(),
        },
        SiteFile {
            path: ".vayu/manifest.json".into(),
            content: br#"{"version":1,"notFound":"404.html"}"#.to_vec(),
        },
    ]
}

fn fallback_files() -> Vec<SiteFile> {
    vec![
        SiteFile {
            path: "index.html".into(),
            content: b"home".to_vec(),
        },
        SiteFile {
            path: "app-shell.html".into(),
            content: b"shell".to_vec(),
        },
        SiteFile {
            path: ".vayu/manifest.json".into(),
            content: br#"{"version":1,"fallback":"app-shell.html"}"#.to_vec(),
        },
    ]
}

#[test]
fn the_index_document_and_assets_are_served_with_their_types() {
    let fixture = serve_tree("basic", &site_files());
    let (status, head, body) = request(&fixture, "/", "GET");
    assert_eq!(status, 200);
    assert!(
        head.contains("content-type: text/html; charset=utf-8"),
        "{head}"
    );
    assert_eq!(body, b"<!doctype html><title>home</title>");

    let (status, head, body) = request(&fixture, "/style.css", "GET");
    assert_eq!(status, 200);
    assert!(
        head.contains("content-type: text/css; charset=utf-8"),
        "{head}"
    );
    assert_eq!(body, b"p { color: teal }");

    // A nested directory path resolves to its index too.
    let docs = serve_tree("docs", &with_docs_files());
    let (status, _, body) = request(&docs, "/docs/", "GET");
    assert_eq!(status, 200);
    assert_eq!(body, b"docs home");
}

#[test]
fn every_response_carries_the_security_headers_and_nothing_identifying() {
    let fixture = serve_tree("headers", &site_files());
    let (_, head, _) = request(&fixture, "/index.html", "GET");
    for expected in [
        "content-security-policy:",
        "permissions-policy:",
        "referrer-policy: no-referrer",
        "x-content-type-options: nosniff",
        "cross-origin-opener-policy: same-origin",
    ] {
        assert!(head.contains(expected), "missing {expected} in:\n{head}");
    }
    assert!(
        head.contains("require-trusted-types-for 'script'"),
        "the CSP keeps Trusted Types enforcement"
    );
    // No relaxation exists on this surface; the CSP must say `trusted-types 'none'`.
    assert!(head.contains("trusted-types 'none'"), "{head}");
    // LOCAL-SURFACE.md 2.4: no identifying headers. No CORS either.
    for banned in ["x-vayuweb", "access-control-allow"] {
        assert!(!head.to_ascii_lowercase().contains(banned), "{head}");
    }

    // And a REFUSAL carries them too.
    let (_, head, _) = request(&fixture, "/missing.html", "GET");
    assert!(head.contains("x-content-type-options: nosniff"), "{head}");
}

#[test]
fn a_deep_link_miss_follows_the_manifest_routing_rule() {
    // With notFound declared: 404 status carrying that document.
    let nf = serve_tree("notfound", &not_found_files());
    let (status, _, body) = request(&nf, "/deep/link", "GET");
    assert_eq!(status, 404);
    assert_eq!(body, b"custom not found");

    // With only fallback declared: 200 carrying it.
    let fb = serve_tree("fallback", &fallback_files());
    let (status, _, body) = request(&fb, "/router/route/x", "GET");
    assert_eq!(status, 200);
    assert_eq!(body, b"shell");

    // With neither: bare 404.
    let plain = serve_tree("bare404", &site_files());
    let (status, _, _) = request(&plain, "/nope", "GET");
    assert_eq!(status, 404);
}

#[test]
fn refusals_traversal_verbs_and_oversized_heads() {
    let fixture = serve_tree("refusals", &site_files());

    // Dot-dot cannot reach outside the tree — refused as malformed before routing.
    let (status, ..) = request(&fixture, "/..%2f..%2fetc%2fpasswd", "GET");
    assert_eq!(status, 400);

    // POST is not served by a preview surface.
    let (status, ..) = request(&fixture, "/", "POST");
    assert_eq!(status, 405);

    // An oversized head is refused without being buffered forever. The write is allowed to
    // fail with a reset under hostile timing, but the drain-before-refuse discipline means a
    // well-behaved client sees its 431.
    let mut stream = TcpStream::connect(fixture.server.addr).expect("connects");
    let long_header = "x".repeat(serve::HEAD_BYTES_LIMIT + 1024);
    let _ = write!(
        stream,
        "GET / HTTP/1.1\r\nhost: x\r\n{long_header}: y\r\n\r\n"
    );
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    assert!(
        raw.starts_with("HTTP/1.1 431"),
        "{}",
        &raw[..40.min(raw.len())]
    );
}

#[test]
fn head_answers_like_get_without_a_body() {
    let fixture = serve_tree("head", &site_files());
    let mut stream = TcpStream::connect(fixture.server.addr).expect("connects");
    write!(stream, "HEAD /index.html HTTP/1.1\r\nhost: x\r\n\r\n").expect("writes");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("reads");
    let head = String::from_utf8_lossy(&raw).into_owned();
    assert!(head.starts_with("HTTP/1.1 200"));
    assert!(head.contains("content-length: 34"), "{head}");
    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("end") + 4;
    assert_eq!(raw.len(), head_end, "HEAD carries no body bytes");
}

// ---------------------------------------------------------------------------
// 3.1.6's second half: documents violating SCAN-enforced rules are refused,
// because no header can enforce those rules for the browser.
// ---------------------------------------------------------------------------

fn sneaky_files() -> Vec<SiteFile> {
    vec![
        SiteFile {
            path: "index.html".into(),
            content: b"<!doctype html><title>home</title>".to_vec(),
        },
        SiteFile {
            // Speculative loading leaks the reader before any CSP can apply -- a serving
            // surface must refuse the DOCUMENT.
            path: "leaky.html".into(),
            content: b"<!doctype html><head><link rel=\"dns-prefetch\" href=\"https://evil.example\"></head><body>hi</body>".to_vec(),
        },
        SiteFile {
            path: "clean.html".into(),
            content: b"<!doctype html><p>perfectly fine</p>".to_vec(),
        },
        SiteFile {
            path: ".vayu/manifest.json".into(),
            content: br#"{"version":1}"#.to_vec(),
        },
    ]
}

#[test]
fn a_document_violating_a_scan_rule_is_refused_while_clean_ones_still_serve() {
    let fixture = serve_tree("scan", &sneaky_files());

    let (status, head, body) = request(&fixture, "/leaky.html", "GET");
    assert_eq!(status, 403, "{head}");
    let detail = String::from_utf8_lossy(&body);
    assert!(detail.contains("[speculative-link]"), "{detail}");
    assert!(detail.contains("Fix:"), "{detail}");

    // The refusal is per-document, not per-tree: everything else serves normally.
    let (status, ..) = request(&fixture, "/clean.html", "GET");
    assert_eq!(status, 200);
    let (status, ..) = request(&fixture, "/", "GET");
    assert_eq!(status, 200);

    // The security headers ride along on refusals too.
    assert!(
        head.to_ascii_lowercase().contains("x-content-type-options"),
        "{head}"
    );
}

#[test]
fn meta_refresh_is_scan_enforced_and_binary_assets_pass_unscanned() {
    let refresh: Vec<SiteFile> = vec![
        SiteFile {
            path: "redirect.html".into(),
            content: b"<!doctype html><head><meta http-equiv=\"refresh\" content=\"0;url=https://away.example\"></head>".to_vec(),
        },
        SiteFile {
            // A binary file whose bytes happen to contain HTML-looking text must NOT be
            // scanned as if it were a document.
            path: "innocent.bin".into(),
            content: b"<link rel=\"dns-prefetch\" href=\"https://x\">".to_vec(),
        },
        SiteFile {
            path: ".vayu/manifest.json".into(),
            content: br#"{"version":1}"#.to_vec(),
        },
    ];
    let fixture = serve_tree("refresh", &refresh);
    let (status, ..) = request(&fixture, "/redirect.html", "GET");
    assert_eq!(status, 403);
    let (status, ..) = request(&fixture, "/innocent.bin", "GET");
    assert_eq!(status, 200, "non-HTML is not scanned as HTML");
}
