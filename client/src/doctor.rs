//! `vayu doctor` — the publish-time checker. PUBLISHING.md section 3, publish step 1.
//!
//! The design rule is section 0's: **every restriction is paid at publish time, never at read
//! time.** A strict profile that fails silently in a reader's browser gets switched off; one
//! that tells the author exactly what will not render, before they ship, costs them ten minutes
//! once and costs the reader nothing ever. So every finding names the file, the line, what will
//! not work, WHY, and a concrete fix (3.1.1), written for someone who has never heard of a
//! Content-Security-Policy (3.1.2) — "VayuWeb blocks inline styles", never "style-src does not
//! include 'unsafe-inline'".
//!
//! ## What is shared, and what is not yet
//!
//! 3.1.6 requires the checker's rule set and the resolver's read-time enforcement to come from
//! ONE definition, because a checker that passes a site the resolver then refuses converts a
//! clear failure into a mystery. This module is the definition's first half: [`RULES`] states
//! each rule once, and the checks walk it. Read-time enforcement does not exist anywhere yet,
//! so there is nothing to drift FROM; when it exists it consumes this table or generates from
//! it, and until then this module says so rather than claiming a property it cannot have.
//!
//! ## How the scanner errs
//!
//! Tag scanning is deliberate, line-oriented and quote-aware rather than a full HTML parser: it
//! is deterministic, dependency-free, and errs toward REPORTING — a construct it misreads may
//! produce a finding about the wrong construct, never a silently missed violation of a rule it
//! claims to check. No network is touched (3.1.5): files in, findings out.

use crate::publish::SiteFile;

/// HOSTING.md "Size guidance": the ladder a client walks before pinning someone else's disk.
pub const SITE_WARN_BYTES: u64 = 256 * 1024 * 1024;
pub const SITE_CONFIRM_BYTES: u64 = 512 * 1024 * 1024;
pub const SITE_REFUSE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// A single file SHOULD stay under 64 MiB; resolvers reject anything above 256 MiB outright.
pub const FILE_WARN_BYTES: u64 = 64 * 1024 * 1024;
pub const FILE_REFUSE_BYTES: u64 = 256 * 1024 * 1024;
/// A tree SHOULD contain fewer than 10,000 entries.
pub const ENTRY_WARN_COUNT: usize = 10_000;

/// How serious a finding is. `Confirm` exists because HOSTING.md demands explicit confirmation,
/// not refusal, in the 512 MiB..2 GiB band — flattening that to an error would forbid something
/// the specification merely gates behind a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Stops the publish.
    Error,
    /// Publishes only after the operator explicitly confirms.
    Confirm,
    /// Advisory. The publish proceeds.
    Warning,
}

impl Severity {
    fn glyph(self) -> &'static str {
        match self {
            Self::Error => "\u{2717}", // ✗
            Self::Confirm => "!",
            Self::Warning => "\u{26a0}", // ⚠
        }
    }
}

/// One rule, stated once — what, why, and the concrete fix 3.1.1 demands.
pub struct Rule {
    pub id: &'static str,
    /// What will not work, in one line, in plain language.
    pub what: &'static str,
    /// Why VayuWeb restricts it.
    pub why: &'static str,
    /// A concrete fix (a message without a remedy is a defect in the checker).
    pub fix: &'static str,
}

macro_rules! rule {
    ($id:ident, ($text_id:literal, $what:literal, $why:literal, $fix:literal)) => {
        pub const $id: Rule = Rule {
            id: $text_id,
            what: $what,
            why: $why,
            fix: $fix,
        };
    };
}

rule!(INLINE_STYLE, (
    "inline-style",
    "inline <style> or style= attribute",
    "VayuWeb blocks inline styles: an attribute selector plus a url() reads your page one character at a time, and a blocked page renders half-dressed.",
    "move the styles into a .css file in your site folder and reference it with <link rel=\"stylesheet\">."
));
rule!(INLINE_SCRIPT, (
    "inline-script",
    "inline <script>",
    "VayuWeb blocks inline scripts: they are the main way an injected page steals keystrokes, so a blocked one means your page silently does nothing.",
    "move the code into a .js file in your site folder and load it with <script src=\"app.js\">."
));
rule!(REMOTE_SUBRESOURCE, (
    "remote-subresource",
    "a subresource loaded from another server",
    "Remote images, scripts and styles do not load on VayuWeb. Every request to another server tells that server who is reading your page.",
    "save the file into your site folder and reference it relatively."
));
rule!(EXTERNAL_LINK, (
    "external-link",
    "a link that leaves VayuWeb",
    "This works, but the reader is shown that the link goes outside VayuWeb before following it. That is intended.",
    "nothing needed, unless the target has a copy inside your site folder."
));
rule!(DATA_IMAGE, (
    "data-image",
    "a data: image",
    "data: images are blocked along with other inline content, because their bytes cannot be checked against an address the way real files can.",
    "save the image as a file in your site folder and reference it relatively."
));
rule!(BASE_TAG, (
    "base-tag",
    "<base>",
    "<base> rewrites where every relative link on the page points, which is exactly what a tampered page would want. VayuWeb refuses pages that carry one.",
    "remove it and write links the way they should resolve."
));
rule!(IFRAME, (
    "iframe",
    "<iframe>",
    "A frame can host content from anywhere while showing your page's name, so VayuWeb does not render frames at all.",
    "link to the content directly instead of framing it."
));
rule!(FORM_REMOTE_ACTION, (
    "form-remote-action",
    "a form posting to another server",
    "Submitting the form sends your reader's input to another server without VayuWeb being able to say so, and static sites have no server to receive it.",
    "point the action at a same-site handler, or replace the form with a mailto: link."
));
rule!(SPECULATIVE_LINK, (
    "speculative-link",
    "a speculative-loading <link rel>",
    "dns-prefetch, preconnect, prefetch, preload, prerender and modulepreload all contact another server on the speculation that a reader will click. On VayuWeb they do nothing except leak who is reading.",
    "remove the tag; the resource loads when it is used."
));
rule!(META_REFERRER, (
    "meta-referrer",
    "<meta name=\"referrer\">",
    "The referrer policy is part of the browser-security profile VayuWeb sets for the whole reader session; a page cannot change it.",
    "remove the tag."
));
rule!(META_REFRESH, (
    "meta-refresh",
    "<meta http-equiv=\"refresh\">",
    "Auto-redirecting a reader to another address is indistinguishable from open-redirect abuse, so VayuWeb does not honour it.",
    "link to the destination instead, or serve the destination's content directly."
));
rule!(WASM_UNDECLARED, (
    "wasm-undeclared",
    "WebAssembly without a manifest declaration",
    "WebAssembly runs only when your manifest declares csp.wasm: true, and the reader is told that your site uses it. Undeclared, it is blocked and your app will not start.",
    "add \"csp\": { \"wasm\": true } to .vayu/manifest.json, or ship JavaScript instead."
));
rule!(SERVICE_WORKER, (
    "service-worker",
    "service-worker registration",
    "A service worker keeps running after the reader leaves, which VayuWeb promises never to allow. Registration is blocked, so code depending on one misbehaves.",
    "remove the registration; cache nothing beyond the reader's visit."
));
rule!(MISSING_INDEX, (
    "missing-index",
    "no index document",
    "A visitor opening your site's root address has no page to land on.",
    "add the index document, or declare \"index\" in .vayu/manifest.json pointing at your landing page."
));

/// The whole rule set, in one place — the artifact another implementation consumes or generates
/// from, per PUBLISHING.md 3.1.6.
pub const RULES: &[&Rule] = &[
    &INLINE_STYLE,
    &INLINE_SCRIPT,
    &REMOTE_SUBRESOURCE,
    &EXTERNAL_LINK,
    &DATA_IMAGE,
    &BASE_TAG,
    &IFRAME,
    &FORM_REMOTE_ACTION,
    &SPECULATIVE_LINK,
    &META_REFERRER,
    &META_REFRESH,
    &WASM_UNDECLARED,
    &SERVICE_WORKER,
];

/// Size and count thresholds, injectable so tests exercise the ladder without gigabytes of RAM.
pub struct Limits {
    pub site_warn: u64,
    pub site_confirm: u64,
    pub site_refuse: u64,
    pub file_warn: u64,
    pub file_refuse: u64,
    pub entry_warn: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            site_warn: SITE_WARN_BYTES,
            site_confirm: SITE_CONFIRM_BYTES,
            site_refuse: SITE_REFUSE_BYTES,
            file_warn: FILE_WARN_BYTES,
            file_refuse: FILE_REFUSE_BYTES,
            entry_warn: ENTRY_WARN_COUNT,
        }
    }
}

/// One diagnostic, kept structured so a GUI can show it without parsing prose.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub rule: &'static str,
    pub file: String,
    /// 1-based; 0 means the finding is about the tree as a whole.
    pub line: usize,
}

impl Finding {
    /// The rendered form, shaped like PUBLISHING.md section 3's own example.
    pub fn render(&self) -> String {
        let rule = RULES.iter().find(|r| r.id == self.rule);
        let (what, why, fix) = match rule {
            Some(r) => (r.what, r.why, r.fix),
            None => ("", "", ""),
        };
        let location = if self.line == 0 {
            self.file.clone()
        } else {
            format!("{}:{}", self.file, self.line)
        };
        let mut out = format!(
            "  {}  {:<16} {}\n      {}\n      Fix: {}",
            self.severity.glyph(),
            location,
            what,
            why,
            fix
        );
        if !self.rule.is_empty() {
            out.push_str(&format!("\n      [{}]", self.rule));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// A small strict JSON reader, sufficient for the manifest and nothing else.
//
// serde_json is deliberately not a production dependency of this crate — the registry's own
// supply-chain gate counts packages, and a second JSON parser in the dependency tree for six
// fields is not worth one. This reader accepts exactly RFC 8259 JSON, rejects trailing
// garbage, and reports where anything malformed sits.
// ---------------------------------------------------------------------------

/// The subset of JSON values the manifest can contain, arrived at by strict parsing.
#[derive(Debug, Clone, PartialEq)]
enum JValue {
    Null,
    Bool(bool),
    Number,
    Str(String),
    Array(Vec<JValue>),
    Object(Vec<(String, JValue)>),
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn error(&self, what: &str) -> String {
        format!("{what} at byte {}", self.pos)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error(&format!("expected '{}'", b as char)))
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self
                .peek()
                .ok_or_else(|| self.error("unterminated string"))?;
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.peek().ok_or_else(|| self.error("dangling escape"))?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if self.pos + 4 > self.bytes.len() {
                                return Err(self.error("truncated \\u escape"));
                            }
                            let hex = core::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
                                .map_err(|_| self.error("bad \\u escape"))?;
                            let code = u32::from_str_radix(hex, 16)
                                .map_err(|_| self.error("bad \\u escape"))?;
                            self.pos += 4;
                            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(self.error("unknown escape")),
                    }
                }
                _ => {
                    let start = self.pos - 1;
                    let len = utf8_len(b);
                    if start + len > self.bytes.len() {
                        return Err(self.error("truncated character"));
                    }
                    self.pos = start + len;
                    let slice = &self.bytes[start..start + len];
                    out.push_str(core::str::from_utf8(slice).map_err(|_| self.error("bad UTF-8"))?);
                }
            }
        }
    }

    fn value(&mut self, depth: u32) -> Result<JValue, String> {
        if depth == 0 {
            return Err(self.error("nesting too deep"));
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => {
                self.pos += 1;
                let mut members = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(JValue::Object(members));
                }
                loop {
                    self.skip_ws();
                    let key = self.string()?;
                    self.skip_ws();
                    self.expect(b':')?;
                    let item = self.value(depth - 1)?;
                    members.push((key, item));
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(JValue::Object(members));
                        }
                        _ => return Err(self.error("expected ',' or '}'")),
                    }
                }
            }
            Some(b'[') => {
                self.pos += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(JValue::Array(items));
                }
                loop {
                    items.push(self.value(depth - 1)?);
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(JValue::Array(items));
                        }
                        _ => return Err(self.error("expected ',' or ']'")),
                    }
                }
            }
            Some(b'"') => Ok(JValue::Str(self.string()?)),
            Some(b't') => self.literal("true").map(|_| JValue::Bool(true)),
            Some(b'f') => self.literal("false").map(|_| JValue::Bool(false)),
            Some(b'n') => self.literal("null").map(|_| JValue::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.number().map(|_| JValue::Number),
            _ => Err(self.error("expected a JSON value")),
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), String> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(())
        } else {
            Err(self.error("invalid literal"))
        }
    }

    fn number(&mut self) -> Result<(), String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if start == self.pos {
            return Err(self.error("empty number"));
        }
        Ok(())
    }

    /// Parse one complete document: a value, then end of input.
    fn document(&mut self) -> Result<JValue, String> {
        let value = self.value(32)?;
        self.skip_ws();
        if self.pos != self.bytes.len() {
            return Err(self.error("trailing characters"));
        }
        Ok(value)
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

/// The manifest fields the checker reads, extracted from `.vayu/manifest.json`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub present: bool,
    pub index: Option<String>,
    pub not_found: Option<String>,
    pub fallback: Option<String>,
    pub wasm_declared: bool,
    /// Set when the file exists but is not usable JSON — itself a finding.
    pub parse_error: Option<String>,
}

/// Parse a manifest document. A file that exists but does not parse yields `parse_error`; the
/// checker treats intent it cannot read as a stop, not as absence.
pub fn parse_manifest(text: &str) -> Manifest {
    let mut parser = JsonParser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let mut manifest = Manifest {
        present: true,
        ..Default::default()
    };
    let root = match parser.document() {
        Ok(value) => value,
        Err(detail) => {
            manifest.parse_error = Some(format!("the manifest is not valid JSON ({detail})"));
            return manifest;
        }
    };
    let JValue::Object(members) = root else {
        manifest.parse_error = Some("the manifest is a JSON object".to_string());
        return manifest;
    };
    // Duplicate top-level keys are legal-but-ambiguous in raw JSON; last one wins, which the
    // verifier's own reading of manifests also does.
    for (key, value) in members {
        match (key.as_str(), value) {
            ("index", JValue::Str(v)) => manifest.index = Some(v),
            ("notFound", JValue::Str(v)) => manifest.not_found = Some(v),
            ("fallback", JValue::Str(v)) => manifest.fallback = Some(v),
            ("csp", JValue::Object(csp)) => {
                for (name, item) in csp {
                    if name == "wasm" {
                        // Declared means literally true; false or a wrong type widens nothing.
                        manifest.wasm_declared |= item == JValue::Bool(true);
                    }
                }
            }
            _ => {}
        }
    }
    manifest
}

// ---------------------------------------------------------------------------
// The HTML/CSS/JS scanner.
// ---------------------------------------------------------------------------

const SUBRESOURCE_TAGS: &[&str] = &[
    "img", "image", "source", "video", "audio", "track", "embed", "object",
];
const SPECULATIVE_RELS: &[&str] = &[
    "dns-prefetch",
    "preconnect",
    "prefetch",
    "preload",
    "prerender",
    "modulepreload",
];

fn is_remote(url: &str) -> bool {
    (url.len() >= 7 && url[..7].eq_ignore_ascii_case("http://"))
        || (url.len() >= 8 && url[..8].eq_ignore_ascii_case("https://"))
}

fn is_data(url: &str) -> bool {
    url.len() >= 5 && url[..5].eq_ignore_ascii_case("data:")
}

/// Split an attribute region into (name, value) pairs, honouring quotes.
fn attributes(region: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = region.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        let start = i;
        while i < bytes.len()
            && bytes[i] != b'='
            && !(bytes[i] as char).is_whitespace()
            && bytes[i] != b'>'
        {
            i += 1;
        }
        if start == i {
            break;
        }
        let name = region[start..i].to_ascii_lowercase();
        let mut value = String::new();
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                let vstart = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                value = region[vstart..i.min(bytes.len())].to_string();
                i += 1;
            } else {
                let vstart = i;
                while i < bytes.len() && !(bytes[i] as char).is_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                value = region[vstart..i].to_string();
            }
        }
        out.push((name, value));
    }
    out
}

fn attr<'b>(attrs: &'b [(String, String)], name: &str) -> Option<&'b str> {
    attrs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Walk every tag in an HTML document, yielding (tag_name, attribute_region, line_number).
///
/// Quote-aware, so a `>` inside an attribute value does not terminate the tag early; comments
/// and doctypes are skipped whole. Line numbers count from 1 and reflect where the tag OPENS.
pub fn for_each_tag(html: &str, mut visit: impl FnMut(&str, &str, usize)) {
    let bytes = html.as_bytes();
    let mut line = 1usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b'<' => {
                // A comment or doctype runs to its terminator regardless of quotes inside.
                if html[i..].starts_with("<!--") {
                    match html[i..].find("-->") {
                        Some(end) => {
                            line += html[i..i + end].matches('\n').count();
                            i += end + 3;
                        }
                        None => return,
                    }
                    continue;
                }
                let tag_line = line;
                let name_start = i + 1;
                let mut j = name_start;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'-') {
                    j += 1;
                }
                let raw_name = &html[name_start..j];
                let name = raw_name.trim_start_matches('/').to_ascii_lowercase();
                if raw_name.is_empty() || raw_name.starts_with('!') || raw_name.starts_with('?') {
                    // Not an element opening; step past the bracket and keep scanning.
                    i += 1;
                    continue;
                }
                let attrs_start = j;
                let mut quote: Option<u8> = None;
                while j < bytes.len() {
                    match bytes[j] {
                        q if Some(q) == quote => quote = None,
                        b'"' | b'\'' if quote.is_none() => quote = Some(bytes[j]),
                        b'>' if quote.is_none() => break,
                        b'\n' => line += 1,
                        _ => {}
                    }
                    j += 1;
                }
                if j >= bytes.len() {
                    return; // unterminated tag; nothing more to scan
                }
                visit(&name, html[attrs_start..j].trim(), tag_line);
                i = j + 1;
            }
            _ => i += 1,
        }
    }
}

fn finding(severity: Severity, rule: &'static str, file: &str, line: usize) -> Finding {
    Finding {
        severity,
        rule,
        file: file.to_string(),
        line,
    }
}

/// Run the authoring checks over a candidate tree, with the specification's thresholds.
pub fn check(files: &[SiteFile]) -> Vec<Finding> {
    check_with(files, &Limits::default())
}

/// [`check`] with explicit size limits, for tests and for callers serving a different tier.
pub fn check_with(files: &[SiteFile], limits: &Limits) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    // ---- the manifest ------------------------------------------------------
    let manifest_path = ".vayu/manifest.json";
    let manifest = files
        .iter()
        .find(|f| f.path == manifest_path)
        .map(|f| parse_manifest(&String::from_utf8_lossy(&f.content)))
        .unwrap_or_default();
    if manifest.parse_error.is_some() {
        findings.push(finding(
            Severity::Error,
            "manifest-invalid",
            manifest_path,
            0,
        ));
    }

    // ---- tree-level checks --------------------------------------------------
    let index_expected = manifest
        .index
        .clone()
        .unwrap_or_else(|| "index.html".to_string());
    if !files.iter().any(|f| f.path == index_expected) {
        findings.push(finding(
            Severity::Error,
            MISSING_INDEX.id,
            &index_expected,
            0,
        ));
    }

    let total: u64 = files.iter().map(|f| f.content.len() as u64).sum();
    if total > limits.site_refuse {
        findings.push(finding(Severity::Error, "site-size-refuse", "(tree)", 0));
    } else if total > limits.site_confirm {
        findings.push(finding(Severity::Confirm, "site-size-confirm", "(tree)", 0));
    } else if total > limits.site_warn {
        findings.push(finding(Severity::Warning, "site-size-warn", "(tree)", 0));
    }

    if files.len() >= limits.entry_warn {
        findings.push(finding(Severity::Warning, "entry-count", "(tree)", 0));
    }

    // ---- per-file checks -----------------------------------------------------
    for file in files {
        let size = file.content.len() as u64;
        if size > limits.file_refuse {
            findings.push(finding(Severity::Error, "file-size-refuse", &file.path, 0));
        } else if size > limits.file_warn {
            findings.push(finding(Severity::Warning, "file-size-warn", &file.path, 0));
        }

        let lower = file.path.to_ascii_lowercase();
        if lower.ends_with(".html") || lower.ends_with(".htm") {
            scan_html(file, &manifest, &mut findings);
        } else if lower.ends_with(".js") || lower.ends_with(".mjs") {
            let text = String::from_utf8_lossy(&file.content);
            scan_js_text(&file.path, &text, &manifest, &mut findings);
        }
    }

    findings.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    findings
}

fn scan_html(file: &SiteFile, manifest: &Manifest, findings: &mut Vec<Finding>) {
    let text = String::from_utf8_lossy(&file.content);
    for_each_tag(&text, |name, region, line| match name {
        "style" => findings.push(finding(Severity::Error, INLINE_STYLE.id, &file.path, line)),
        "script" => {
            let attrs = attributes(region);
            match attr(&attrs, "src") {
                None => findings.push(finding(Severity::Error, INLINE_SCRIPT.id, &file.path, line)),
                Some(src) if is_remote(src) => findings.push(finding(
                    Severity::Error,
                    REMOTE_SUBRESOURCE.id,
                    &file.path,
                    line,
                )),
                Some(_) => {}
            }
        }
        "link" => {
            let attrs = attributes(region);
            if let Some(rel) = attr(&attrs, "rel").map(str::to_ascii_lowercase) {
                if SPECULATIVE_RELS.contains(&rel.as_str()) {
                    findings.push(finding(
                        Severity::Error,
                        SPECULATIVE_LINK.id,
                        &file.path,
                        line,
                    ));
                }
            }
            if let Some(href) = attr(&attrs, "href") {
                if is_remote(href) {
                    findings.push(finding(
                        Severity::Error,
                        REMOTE_SUBRESOURCE.id,
                        &file.path,
                        line,
                    ));
                }
            }
        }
        "meta" => {
            let attrs = attributes(region);
            if attr(&attrs, "name").map(str::to_ascii_lowercase).as_deref() == Some("referrer") {
                findings.push(finding(Severity::Error, META_REFERRER.id, &file.path, line));
            }
            if attr(&attrs, "http-equiv")
                .map(str::to_ascii_lowercase)
                .as_deref()
                == Some("refresh")
            {
                findings.push(finding(Severity::Error, META_REFRESH.id, &file.path, line));
            }
        }
        "base" => findings.push(finding(Severity::Error, BASE_TAG.id, &file.path, line)),
        "iframe" => findings.push(finding(Severity::Error, IFRAME.id, &file.path, line)),
        "form" => {
            let attrs = attributes(region);
            if let Some(action) = attr(&attrs, "action") {
                if is_remote(action) {
                    findings.push(finding(
                        Severity::Error,
                        FORM_REMOTE_ACTION.id,
                        &file.path,
                        line,
                    ));
                }
            }
        }
        "a" => {
            let attrs = attributes(region);
            if let Some(href) = attr(&attrs, "href") {
                if is_remote(href) {
                    findings.push(finding(
                        Severity::Warning,
                        EXTERNAL_LINK.id,
                        &file.path,
                        line,
                    ));
                }
            }
        }
        other => {
            if SUBRESOURCE_TAGS.contains(&other) {
                let attrs = attributes(region);
                if let Some(url) = attr(&attrs, "src").or_else(|| attr(&attrs, "href")) {
                    if is_remote(url) {
                        findings.push(finding(
                            Severity::Error,
                            REMOTE_SUBRESOURCE.id,
                            &file.path,
                            line,
                        ));
                    } else if is_data(url) {
                        findings.push(finding(Severity::Error, DATA_IMAGE.id, &file.path, line));
                    }
                }
            }
            // An inline style ATTRIBUTE rides with any element.
            if !attributes(region).iter().any(|(k, _)| k == "style") {
                return;
            }
            findings.push(finding(Severity::Error, INLINE_STYLE.id, &file.path, line));
        }
    });
    // WebAssembly and service workers can also appear inside inline scripts; scan the text too.
    scan_js_text(&file.path, &text, manifest, findings);
}

fn scan_js_text(path: &str, text: &str, manifest: &Manifest, findings: &mut Vec<Finding>) {
    if !manifest.wasm_declared && js_uses_wasm(text) {
        findings.push(finding(
            Severity::Error,
            WASM_UNDECLARED.id,
            path,
            line_of_first(text, "WebAssembly"),
        ));
    }
    if js_registers_service_worker(text) {
        findings.push(finding(
            Severity::Error,
            SERVICE_WORKER.id,
            path,
            // Point at the registration call, not at a feature-detection mention earlier.
            line_of_first(text, "serviceWorker.register").max(line_of_first(text, "serviceWorker")),
        ));
    }
}

fn js_uses_wasm(text: &str) -> bool {
    // Any real use goes through this namespace; a comment mentioning WebAssembly produces a
    // finding about itself, which is the direction a checker should err.
    text.contains("WebAssembly.")
}

fn js_registers_service_worker(text: &str) -> bool {
    text.contains("navigator.serviceWorker.register") || text.contains("serviceWorker.register(")
}

fn line_of_first(text: &str, needle: &str) -> usize {
    match text.find(needle) {
        Some(offset) => 1 + text[..offset].matches('\n').count(),
        None => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn html(path: &str, body: &str) -> SiteFile {
        SiteFile {
            path: path.into(),
            content: body.as_bytes().to_vec(),
        }
    }

    fn rules(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|f| f.rule).collect()
    }

    #[test]
    fn a_clean_site_yields_no_findings() {
        let files = vec![
            html("index.html", "<!doctype html><title>t</title><p>hi</p>"),
            html("style.css", "p { color: teal }"),
        ];
        assert!(check(&files).is_empty(), "{:?}", rules(&check(&files)));
    }

    #[test]
    fn inline_style_and_script_are_named_with_their_lines() {
        let body = "<!doctype html>\n<html>\n<style>p{}</style>\n<script>let x</script>\n";
        let findings = check(&[html("index.html", body)]);
        let found = rules(&findings);
        assert!(found.contains(&INLINE_STYLE.id));
        assert!(found.contains(&INLINE_SCRIPT.id));
        let style = findings
            .iter()
            .find(|f| f.rule == INLINE_STYLE.id)
            .expect("style");
        assert_eq!(style.line, 3, "lines come from the document, not the loop");
        let script = findings
            .iter()
            .find(|f| f.rule == INLINE_SCRIPT.id)
            .expect("script");
        assert_eq!(script.line, 4);
    }

    #[test]
    fn a_style_attribute_is_inline_style_too() {
        let body = "<p style=\"color:red\">x</p>";
        let findings = check(&[html("index.html", body)]);
        assert!(rules(&findings).contains(&INLINE_STYLE.id));
    }

    #[test]
    fn a_remote_image_is_an_error_but_a_remote_anchor_is_only_a_warning() {
        let body = concat!(
            "<img src=\"https://cdn.example.com/x.png\">\n",
            "<a href=\"https://example.com\">out there</a>\n"
        );
        let findings = check(&[html("index.html", body)]);
        let image = findings
            .iter()
            .find(|f| f.rule == REMOTE_SUBRESOURCE.id)
            .expect("remote img");
        assert_eq!(image.severity, Severity::Error);
        assert_eq!(image.line, 1);
        let anchor = findings
            .iter()
            .find(|f| f.rule == EXTERNAL_LINK.id)
            .expect("external a");
        assert_eq!(
            anchor.severity,
            Severity::Warning,
            "leaving VayuWeb is allowed, warned"
        );
        assert_eq!(anchor.line, 2);
    }

    #[test]
    fn a_script_loaded_from_the_tree_is_fine_and_from_the_internet_is_not() {
        let local_files = vec![
            html("index.html", "<script src=\"app.js\"></script>"),
            html("app.js", "console.log(1)\n"),
        ];
        assert!(
            check(&local_files).is_empty(),
            "relative scripts are ordinary files in the tree"
        );
        let findings = check(&[html(
            "index.html",
            "<script src=\"https://cdn.example.com/app.js\"></script>",
        )]);
        assert!(rules(&findings).contains(&REMOTE_SUBRESOURCE.id));
    }

    #[test]
    fn data_images_base_iframes_meta_tricks_and_speculation_all_fire() {
        let body = concat!(
            "<img src=\"data:image/png;base64,AAA\">\n",          // 1
            "<base href=\"https://evil.example/\">\n",            // 2
            "<iframe src=\"frame.html\"></iframe>\n",             // 3
            "<meta http-equiv=\"refresh\" content=\"1\">\n",      // 4
            "<meta name=\"referrer\" content=\"no-referrer\">\n", // 5
            "<link rel=\"preconnect\" href=\"https://cdn.example\">\n"  // 6
        );
        let findings = check(&[html("index.html", body)]);
        let found = rules(&findings);
        for wanted in [
            DATA_IMAGE.id,
            BASE_TAG.id,
            IFRAME.id,
            META_REFRESH.id,
            META_REFERRER.id,
            SPECULATIVE_LINK.id,
        ] {
            assert!(found.contains(&wanted), "{wanted} was missed");
        }
        let base = findings
            .iter()
            .find(|f| f.rule == BASE_TAG.id)
            .expect("base");
        assert_eq!(base.line, 2);
    }

    #[test]
    fn a_form_posting_out_is_reported() {
        let body = "<form action=\"https://tracker.example/collect\"><input name=\"q\"></form>";
        let findings = check(&[html("index.html", body)]);
        assert!(rules(&findings).contains(&FORM_REMOTE_ACTION.id));
    }

    #[test]
    fn webassembly_needs_the_manifest_declaration() {
        let js = html(
            "app.js",
            "const mod = await WebAssembly.instantiateStreaming(fetch('m.wasm'));\n",
        );
        let undeclared = check(&[html("index.html", "<!doctype html><p>x</p>"), js.clone()]);
        assert!(rules(&undeclared).contains(&WASM_UNDECLARED.id));

        let declared = check(&[
            html("index.html", "<!doctype html><p>x</p>"),
            html(
                ".vayu/manifest.json",
                "{\"version\":1,\"csp\":{\"wasm\":true}}",
            ),
            js,
        ]);
        assert!(
            !rules(&declared).contains(&WASM_UNDECLARED.id),
            "declared wasm is honoured"
        );
    }

    #[test]
    fn a_nested_wasm_impostor_widens_nothing() {
        // csp.wasm must be read INSIDE the csp object; a "wasm": true somewhere nested must not
        // be mistaken for the declaration.
        let files = vec![
            html("index.html", "<!doctype html><p>x</p>"),
            html("app.js", "WebAssembly.instantiateStreaming(fetch('m'));\n"),
            html(
                ".vayu/manifest.json",
                "{\"version\":1,\"nested\":{\"wasm\":true},\"csp\":{\"wasm\":false}}",
            ),
        ];
        let findings = check(&files);
        assert!(rules(&findings).contains(&WASM_UNDECLARED.id));
    }

    #[test]
    fn service_worker_registration_is_found_wherever_it_hides() {
        let files = vec![
            html("index.html", "<!doctype html><p>x</p>"),
            html(
                "sw-loader.js",
                "if ('serviceWorker' in nav) {\n  navigator.serviceWorker.register('/sw.js')\n}\n",
            ),
        ];
        let findings = check(&files);
        let sw = findings
            .iter()
            .find(|f| f.rule == SERVICE_WORKER.id)
            .expect("sw");
        assert_eq!(sw.line, 2);
    }

    #[test]
    fn a_missing_index_document_stops_everything() {
        let findings = check(&[html("about.html", "<!doctype html><p>me</p>")]);
        let missing = findings
            .iter()
            .find(|f| f.rule == MISSING_INDEX.id)
            .expect("missing");
        assert_eq!(missing.severity, Severity::Error);
        assert_eq!(missing.file, "index.html");

        // Declaring another landing page MOVES the requirement; it does not remove it.
        let moved = check(&[
            html(
                ".vayu/manifest.json",
                "{\"version\":1,\"index\":\"landing.html\"}",
            ),
            html("about.html", "<!doctype html><p>x</p>"),
        ]);
        let landing = moved
            .iter()
            .find(|f| f.rule == MISSING_INDEX.id)
            .expect("still missing");
        assert_eq!(landing.file, "landing.html");
    }

    #[test]
    fn a_broken_manifest_is_a_finding_in_its_own_right() {
        let files = vec![
            html("index.html", "<!doctype html><p>x</p>"),
            html(".vayu/manifest.json", "{\"version\": 1,,"),
        ];
        let findings = check(&files);
        assert!(
            rules(&findings).contains(&"manifest-invalid"),
            "{:?}",
            rules(&findings)
        );
    }

    #[test]
    fn the_size_ladder_walks_exactly_as_hosting_md_says() {
        let tiny = Limits {
            site_warn: 100,
            site_confirm: 200,
            site_refuse: 400,
            file_warn: 50,
            file_refuse: 300,
            entry_warn: 10,
        };
        let base = html("index.html", "<!doctype html><p>pad</p>");

        // Under everything: quiet.
        assert!(check_with(std::slice::from_ref(&base), &tiny)
            .iter()
            .all(|f| !f.rule.starts_with("site-size")));

        // Above the warn line: a warning.
        let medium = SiteFile {
            path: "pad.bin".into(),
            content: vec![0u8; 150],
        };
        let findings = check_with(&[base.clone(), medium], &tiny);
        let warn = findings
            .iter()
            .find(|f| f.rule == "site-size-warn")
            .expect("warn band");
        assert_eq!(warn.severity, Severity::Warning);

        // Above the confirm line: confirmation demanded, not refusal.
        let bigger = SiteFile {
            path: "pad.bin".into(),
            content: vec![0u8; 250],
        };
        let findings = check_with(&[base.clone(), bigger], &tiny);
        let confirm = findings
            .iter()
            .find(|f| f.rule == "site-size-confirm")
            .expect("confirm band");
        assert_eq!(confirm.severity, Severity::Confirm);

        // Past the refuse line: the publish stops.
        let huge = SiteFile {
            path: "pad.bin".into(),
            content: vec![0u8; 500],
        };
        let findings = check_with(&[base, huge], &tiny);
        let refuse = findings
            .iter()
            .find(|f| f.rule == "site-size-refuse")
            .expect("refuse");
        assert_eq!(refuse.severity, Severity::Error);

        // A single oversized file is refused even inside a small site.
        let fat_file = SiteFile {
            path: "big.bin".into(),
            content: vec![0u8; 350],
        };
        let findings = check_with(&[html("index.html", "<p>x</p>"), fat_file], &tiny);
        assert!(rules(&findings).contains(&"file-size-refuse"));

        // Entry-count warnings use the same injection.
        let many: Vec<SiteFile> = (0..12).map(|i| html(&format!("f{i}.txt"), "x")).collect();
        let findings = check_with(&many, &tiny);
        assert!(rules(&findings).contains(&"entry-count"));
    }

    #[test]
    fn findings_render_like_the_specification_example() {
        let findings = check(&[html("index.html", "<style>p{}</style>")]);
        let text = findings[0].render();
        assert!(
            text.starts_with("  \u{2717}"),
            "errors get the ✗ glyph: {text:?}"
        );
        assert!(text.contains("index.html:1"));
        assert!(text.contains("Fix: "), "3.1.1: no finding without a remedy");
        assert!(
            text.contains("[inline-style]"),
            "the rule id is shown for tooling"
        );
    }

    #[test]
    fn every_rule_carries_its_plain_language_prose() {
        // 3.1.4's minimum list walked against the table, so a new rule cannot forget its prose.
        for rule in RULES {
            assert!(!rule.what.is_empty(), "{} has no what", rule.id);
            assert!(!rule.why.is_empty(), "{} has no why", rule.id);
            assert!(
                !rule.fix.is_empty(),
                "{}: a message without a remedy is a defect (3.1.1)",
                rule.id
            );
        }
        let ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        for required in [
            "inline-style",
            "inline-script",
            "remote-subresource",
            "data-image",
            "base-tag",
            "iframe",
            "form-remote-action",
            "speculative-link",
            "meta-referrer",
            "meta-refresh",
            "wasm-undeclared",
            "service-worker",
            "external-link",
        ] {
            assert!(ids.contains(&required), "3.1.4 requires {required}");
        }
    }

    #[test]
    fn quoted_brackets_do_not_confuse_the_tag_scanner() {
        let body = "<p title=\"a>b\" data-x=\"1\">fine</p>\n<img src=\"pic.png\">";
        let findings = check(&[html("index.html", body)]);
        assert!(
            rules(&findings).iter().all(|r| *r != INLINE_STYLE.id),
            "an attribute value containing '>' must not swallow real tags"
        );
    }

    #[test]
    fn comments_are_skipped_whole() {
        let body = "<!-- <style>fake</style> <script>nope</script> -->\n<p>clean</p>";
        let findings = check(&[html("index.html", body)]);
        assert!(
            findings.is_empty(),
            "commented-out violations are not live ones"
        );
    }
}
