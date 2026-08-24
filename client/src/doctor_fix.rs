//! `vayu doctor --fix` — the mechanical half of PUBLISHING.md 3.1.3.
//!
//! The specification's shape for this command is exact: it *"MUST resolve mechanically fixable
//! findings by extracting inline blocks to files in the same tree. It MUST NOT alter document
//! semantics, and MUST show a diff before writing."* So this module never edits in place: it
//! produces a [`FixPlan`] — every rewritten document held side by side with its original, plus
//! each new extracted file — and the caller renders the diffs, gets whatever confirmation a UI
//! owes the user, and only then applies.
//!
//! ## What is mechanically fixable, and what deliberately is not
//!
//! Inline `<style>` and inline `<script>` blocks are fixable by extraction, because moving their
//! bytes verbatim into a `.css`/`.js` file and referencing it preserves both semantics and
//! execution order — the reference sits exactly where the block was. An EMPTY block is removed
//! outright rather than becoming an empty extracted file; removing nothing changes nothing.
//! Everything else the doctor reports — remote subresources, data images, missing index
//! documents, size findings — requires a human decision about where content should live, so the
//! fixer leaves it to the author rather than guessing on their behalf.
//!
//! ## Consistency with the scanner
//!
//! The span scanner here mirrors `for_each_tag`'s quote- and comment-aware walk, because a
//! fixer that disagreed with the checker would rewrite documents around violations the checker
//! sees differently — or worse, "fix" text inside a comment. A test pins the two against each
//! other: after applying a plan, the doctor reports no inline findings.

use crate::publish::SiteFile;

/// One document's proposed rewrite: before and after, plus any new files extraction creates.
#[derive(Debug, Clone)]
pub struct FileEdit {
    pub path: String,
    pub before: String,
    pub after: String,
    /// New files this edit adds to the tree, in creation order: (path, content).
    pub created: Vec<(String, String)>,
}

impl FileEdit {
    /// A minimal unified-style diff: common head and tail trimmed, changed lines shown whole.
    ///
    /// Not a general LCS diff — these documents differ in a handful of contiguous regions, and
    /// trimming common prefix/suffix around them renders exactly what the operator needs to
    /// judge the change without a dependency.
    pub fn render_diff(&self) -> String {
        let mut out = format!("--- {}\n+++ {} (fixed)\n", self.path, self.path);
        let old_lines: Vec<&str> = self.before.lines().collect();
        let new_lines: Vec<&str> = self.after.lines().collect();

        // Trim the shared prefix and suffix so only genuinely changed regions remain.
        let mut start = 0usize;
        while start < old_lines.len()
            && start < new_lines.len()
            && old_lines[start] == new_lines[start]
        {
            start += 1;
        }
        let mut old_end = old_lines.len();
        let mut new_end = new_lines.len();
        while old_end > start && new_end > start && old_lines[old_end - 1] == new_lines[new_end - 1]
        {
            old_end -= 1;
            new_end -= 1;
        }

        let context_before = start.saturating_sub(2);
        let context_after = old_lines.len().saturating_sub(old_end).min(2);
        if context_before > 0 || context_after > 0 || start > 0 {
            for line in &old_lines[context_before..start] {
                out.push_str(&format!("  {line}\n"));
            }
        }
        for line in &old_lines[start..old_end] {
            out.push_str(&format!("- {line}\n"));
        }
        for line in &new_lines[start..new_end] {
            out.push_str(&format!("+ {line}\n"));
        }
        if context_after > 0 {
            for line in &old_lines[old_end..old_end + context_after] {
                out.push_str(&format!("  {line}\n"));
            }
        }
        for (created_path, _) in &self.created {
            out.push_str(&format!(
                "+ new file {created_path} ({} bytes)\n",
                self.created
                    .iter()
                    .find(|(p, _)| p == created_path)
                    .map(|(_, c)| c.len())
                    .unwrap_or_default()
            ));
        }
        out
    }
}

/// The complete proposal for one tree. Nothing has been written until you call [`FixPlan::apply`].
#[derive(Debug, Clone, Default)]
pub struct FixPlan {
    pub edits: Vec<FileEdit>,
}

impl FixPlan {
    /// Whether there is anything mechanical to do at all.
    pub fn is_empty(&self) -> bool {
        self.edits.is_empty()
    }

    /// Render every per-file diff, for display BEFORE applying (3.1.3's "show a diff").
    pub fn render(&self) -> String {
        let mut out = String::new();
        for edit in &self.edits {
            out.push_str(&edit.render_diff());
            out.push('\n');
        }
        out
    }

    /// Produce the fixed tree. The input is consumed read-only: the original files are untouched,
    /// and what comes back is a NEW list containing rewrites plus created files. Applying twice
    /// is a no-op, because the fixed tree has no inline blocks left to extract.
    pub fn apply(&self, files: &[SiteFile]) -> Vec<SiteFile> {
        let mut result: Vec<SiteFile> = files.to_vec();
        for edit in &self.edits {
            if let Some(file) = result.iter_mut().find(|f| f.path == edit.path) {
                file.content = edit.after.as_bytes().to_vec();
            }
            for (path, content) in &edit.created {
                if !result.iter().any(|f| &f.path == path) {
                    result.push(SiteFile {
                        path: path.clone(),
                        content: content.as_bytes().to_vec(),
                    });
                }
            }
        }
        // The tree's iteration order feeds import_site's directory sorting, which is byte-order
        // based and independent of list order; keep insertion order stable regardless.
        result
    }
}

/// Plan the mechanical fixes for a tree: extract inline `<style>` and `<script>` blocks into
/// sibling `.extracted.css` / `.extracted.js` files, referencing them where the blocks stood.
///
/// Documents the doctor finds clean come back untouched; a tree with nothing mechanically
/// fixable yields an empty plan.
pub fn plan(files: &[SiteFile]) -> FixPlan {
    let mut edits = Vec::new();
    for file in files {
        let lower = file.path.to_ascii_lowercase();
        if !(lower.ends_with(".html") || lower.ends_with(".htm")) {
            continue;
        }
        let before = String::from_utf8_lossy(&file.content).into_owned();
        let Some(edit) = rewrite_document(&file.path, &before, files) else {
            continue;
        };
        edits.push(edit);
    }
    FixPlan { edits }
}

/// Re-serialize an attribute region: keep every attribute except the dropped names, then apply
/// additions (replacing same-named ones). Values are re-quoted uniformly; HTML attribute values
/// cannot contain a raw `"` (the scanner's quote handling guarantees the split), so this is lossless.
fn rebuild_attrs(attrs_text: &str, drop: &[&str], add: &[(&str, String)]) -> String {
    let mut pairs: Vec<(String, String)> = crate::doctor::attributes(attrs_text)
        .into_iter()
        .filter(|(name, _)| !drop.contains(&name.as_str()))
        .collect();
    for (name, value) in add {
        pairs.retain(|(existing, _)| existing != name);
        pairs.push(((*name).to_string(), value.clone()));
    }
    pairs
        .iter()
        .map(|(name, value)| {
            if value.is_empty() {
                name.clone()
            } else {
                format!("{name}=\"{value}\"")
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn stem_of(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    match base.rfind('.') {
        Some(dot) if dot > 0 => base[..dot].to_string(),
        _ => base.to_string(),
    }
}

/// Choose an extracted-file name that does not collide with anything already in the tree.
fn free_name(files: &[SiteFile], stem: &str, extension: &str) -> String {
    let mut candidate = format!("{stem}.extracted.{extension}");
    let mut n = 1usize;
    while files.iter().any(|f| f.path == candidate) {
        candidate = format!("{stem}.extracted-{n}.{extension}");
        n += 1;
    }
    candidate
}

/// Rewrite one document, or return None when it holds nothing mechanically fixable.
fn rewrite_document(path: &str, before: &str, all_files: &[SiteFile]) -> Option<FileEdit> {
    let stem = stem_of(path);
    // Names are chosen lazily but ONCE per document, even if several blocks share them: every
    // style block in one page lands in the same extracted stylesheet, in document order.
    let mut css_name: Option<String> = None;
    let mut js_name: Option<String> = None;
    let mut css_body = String::new();
    let mut js_body = String::new();

    struct Span {
        start: usize,
        end: usize,
        replacement: String,
        body: String,
    }
    let mut spans: Vec<Span> = Vec::new();

    for_each_element_span(before, |name, attrs_text, open_start, inner, close_end| {
        // Which kind of block is this, if it is a candidate at all? A script WITH a src is not
        // inline; references are left alone.
        let kind = match name {
            "style" => Some((
                "css",
                rebuild_attrs(
                    attrs_text,
                    &["rel", "href"],
                    &[("rel", "stylesheet".to_string())],
                ),
            )),
            "script" if attr_value(attrs_text, "src").is_none() => {
                Some(("js", rebuild_attrs(attrs_text, &["src"], &[])))
            }
            _ => None,
        };
        let Some((extension, carried)) = kind else {
            return false; // not a candidate: descend into this element's content
        };

        let indent = line_indent(before, open_start);
        match extension {
            "css" => {
                let name = css_name.get_or_insert_with(|| free_name(all_files, &stem, "css"));
                if !css_body.is_empty() {
                    css_body.push('\n');
                }
                css_body.push_str(inner.trim());
                css_body.push('\n');
                spans.push(Span {
                    start: open_start,
                    end: close_end,
                    replacement: format!("{indent}<link {carried} href=\"{name}\">"),
                    body: inner.to_string(),
                });
            }
            _ => {
                let name = js_name.get_or_insert_with(|| free_name(all_files, &stem, "js"));
                if !js_body.is_empty() {
                    js_body.push('\n');
                }
                js_body.push_str(inner.trim());
                js_body.push('\n');
                let src_attr = format!("src=\"{name}\"");
                let attrs = if carried.is_empty() {
                    src_attr
                } else {
                    format!("{carried} {src_attr}")
                };
                spans.push(Span {
                    start: open_start,
                    end: close_end,
                    replacement: format!("{indent}<script {attrs}></script>"),
                    body: inner.to_string(),
                });
            }
        }
        true // the body was CSS or JavaScript, not markup: consume it
    });

    if spans.is_empty() {
        return None;
    }

    // Apply replacements back-to-front so earlier offsets stay valid.
    spans.sort_by_key(|span| std::cmp::Reverse(span.start));
    let mut after = before.to_string();
    for span in &spans {
        // An EMPTY block contributes nothing to any stylesheet; remove it outright rather than
        // manufacturing an empty extracted file. Removing nothing changes nothing.
        if span.body.trim().is_empty() {
            after.replace_range(span.start..span.end, "");
        } else {
            after.replace_range(span.start..span.end, &span.replacement);
        }
    }

    let mut created = Vec::new();
    if let Some(name) = &css_name {
        if !css_body.trim().is_empty() {
            created.push((name.clone(), css_body.clone()));
        }
    }
    if let Some(name) = &js_name {
        if !js_body.trim().is_empty() {
            created.push((name.clone(), js_body.clone()));
        }
    }

    Some(FileEdit {
        path: path.to_string(),
        before: before.to_string(),
        after,
        created,
    })
}

fn line_indent(text: &str, offset: usize) -> String {
    let line_start = text[..offset].rfind('\n').map(|n| n + 1).unwrap_or(0);
    text[line_start..offset]
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect()
}

fn attr_value(attrs_text: &str, wanted: &str) -> Option<String> {
    // Mirror the checker's attribute reader so fixer and doctor agree on what an attribute is.
    for (name, value) in crate::doctor::attributes(attrs_text) {
        if name == wanted {
            return Some(value);
        }
    }
    None
}

/// Walk elements with SPANS: (tag_name, attribute_region, open_tag_start, inner_text, close_end),
/// where the callback returns TRUE to skip the element's content (right for style/script, whose
/// bodies are not markup) or FALSE to keep walking inside it (every wrapper element).
///
/// Quote-aware and comment-aware exactly like the checker's walk. Only paired elements with an
/// explicit closing tag yield spans; unterminated tags end the scan, matching the checker.
pub fn for_each_element_span(
    html: &str,
    mut visit: impl FnMut(&str, &str, usize, &str, usize) -> bool,
) {
    let bytes = html.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        if html[i..].starts_with("<!--") {
            match html[i..].find("-->") {
                Some(end) => i += end + 3,
                None => return,
            }
            continue;
        }
        let name_start = i + 1;
        let mut j = name_start;
        while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'-') {
            j += 1;
        }
        let raw_name = &html[name_start..j];
        if raw_name.is_empty() || raw_name.starts_with('!') || raw_name.starts_with('?') {
            i += 1;
            continue;
        }
        let name = raw_name.to_ascii_lowercase();
        let attrs_start = j;
        let mut quote: Option<u8> = None;
        while j < bytes.len() {
            match bytes[j] {
                q if Some(q) == quote => quote = None,
                b'"' | b'\'' if quote.is_none() => quote = Some(bytes[j]),
                b'>' if quote.is_none() => break,
                _ => {}
            }
            j += 1;
        }
        if j >= bytes.len() {
            return; // unterminated tag
        }
        let attrs_region = html[attrs_start..j].trim();
        let self_closing = attrs_region.ends_with('/');
        let open_end = j + 1;

        // Void and self-closed elements have no inner text and no closing tag to find.
        const VOID: &[&str] = &[
            "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source",
            "track", "wbr",
        ];
        if self_closing || VOID.contains(&name.as_str()) {
            i = open_end;
            continue;
        }

        // Find this element's real closing tag: "</name" then optional whitespace then '>'.
        let mut k = open_end;
        let at = loop {
            let pattern = format!("</{name}");
            match html[k..].find(&pattern) {
                Some(rel) => {
                    let candidate = k + rel;
                    let tail = &html[candidate + pattern.len()..];
                    if tail.starts_with('>') || tail.starts_with([' ', '\t', '\n', '\r']) {
                        break candidate;
                    }
                    k = candidate + 1;
                }
                None => return, // unterminated element; the checker flags it, we cannot fix it
            }
        };
        let after_name = at + 2 + name.len();
        let Some(gt) = html[after_name..].find('>') else {
            return;
        };
        let close_end = after_name + gt + 1;

        let consumed = visit(&name, attrs_region, i, &html[open_end..at], close_end);
        // Consume the content only when the caller claimed it (style/script bodies are not
        // markup); otherwise descend, so candidates inside wrappers are still found.
        i = if consumed { close_end } else { open_end };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::{self, Finding};

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
    fn extracting_inline_blocks_leaves_the_site_clean() {
        let files = vec![html(
            "index.html",
            "<!doctype html>\n<head>\n<style>p { color: teal }</style>\n</head>\n<body>\n<script>console.log('hi')</script>\n</body>",
        )];
        let plan = plan(&files);
        assert!(!plan.is_empty());
        let fixed = plan.apply(&files);
        let findings = doctor::check(&fixed);
        assert!(
            !rules(&findings).contains(&doctor::INLINE_STYLE.id),
            "{:?}",
            rules(&findings)
        );
        assert!(!rules(&findings).contains(&doctor::INLINE_SCRIPT.id));
    }

    #[test]
    fn extracted_content_is_verbatim_and_the_reference_sits_where_the_block_was() {
        let body = "<style>p{color:red}</style><p>x</p>";
        let files = vec![html("page.html", body)];
        let fixed = plan(&files).apply(&files);
        let page = fixed.iter().find(|f| f.path == "page.html").expect("page");
        let text = String::from_utf8_lossy(&page.content);
        assert!(text.contains("<link rel=\"stylesheet\" href=\"page.extracted.css\">"));
        assert!(text.contains("<p>x</p>"));
        let css = fixed
            .iter()
            .find(|f| f.path == "page.extracted.css")
            .expect("css");
        assert_eq!(String::from_utf8_lossy(&css.content).trim(), "p{color:red}");
    }

    #[test]
    fn several_blocks_of_one_kind_land_in_one_extracted_file_in_document_order() {
        let body = concat!(
            "<style>a{}</style>\n",
            "<p>middle</p>\n",
            "<style>b{}</style>\n"
        );
        let files = vec![html("multi.html", body)];
        let fixed = plan(&files).apply(&files);
        let css = fixed
            .iter()
            .find(|f| f.path == "multi.extracted.css")
            .expect("css");
        let text = String::from_utf8_lossy(&css.content);
        assert!(text.starts_with("a{}"), "order is the document's: {text:?}");
        assert!(text.contains("b{}"));
        assert_eq!(
            fixed
                .iter()
                .filter(|f| f.path.ends_with(".extracted.css"))
                .count(),
            1,
            "one stylesheet per page, not one per block"
        );
    }

    #[test]
    fn attributes_that_matter_travel_with_the_extraction() {
        let body = concat!(
            "<style media=\"print\">x{}</style>\n",
            "<script defer>init();</script>\n"
        );
        let files = vec![html("attrs.html", body)];
        let fixed = plan(&files).apply(&files);
        let text = String::from_utf8_lossy(
            &fixed
                .iter()
                .find(|f| f.path == "attrs.html")
                .expect("page")
                .content,
        );
        assert!(
            text.contains("media=\"print\""),
            "media queries must survive: {text:?}"
        );
        assert!(
            text.contains("defer") && text.contains("src=\"attrs.extracted.js\""),
            "execution-hinting attributes must survive: {text:?}"
        );
    }

    #[test]
    fn an_empty_block_is_removed_rather_than_becoming_an_empty_file() {
        let files = vec![
            html("index.html", "<!doctype html><p>home</p>"),
            html("empty.html", "<style>   </style><p>kept</p>"),
        ];
        let outcome = plan(&files);
        // The block is removed (nothing changed nothing), and no empty css file appears.
        let fixed = outcome.apply(&files);
        let text = String::from_utf8_lossy(
            &fixed
                .iter()
                .find(|f| f.path == "empty.html")
                .expect("page")
                .content,
        );
        assert!(
            !text.contains("style"),
            "the empty block went away: {text:?}"
        );
        assert!(fixed.iter().all(|f| !f.path.ends_with(".extracted.css")));
        // And the doctor agrees the site is clean now.
        assert!(
            doctor::check(&fixed).is_empty(),
            "{:?}",
            rules(&doctor::check(&fixed))
        );
    }

    #[test]
    fn a_name_collision_picks_a_deterministic_alternative() {
        let files = vec![
            html("collide.html", "<style>x{}</style>"),
            html("collide.extracted.css", "/* pre-existing */"),
        ];
        let plan = plan(&files);
        let edit = &plan.edits[0];
        assert_eq!(edit.created[0].0, "collide.extracted-1.css");
        // The pre-existing file is untouched by apply.
        let fixed = plan.apply(&files);
        let original = fixed
            .iter()
            .find(|f| f.path == "collide.extracted.css")
            .expect("original kept");
        assert_eq!(
            String::from_utf8_lossy(&original.content),
            "/* pre-existing */"
        );
    }

    #[test]
    fn commented_out_blocks_are_neither_fixed_nor_needed_to_be() {
        let files = vec![
            html("index.html", "<!doctype html><p>home</p>"),
            html("comment.html", "<!-- <style>fake{}</style> --><p>clean</p>"),
        ];
        let outcome = plan(&files);
        assert!(outcome.is_empty(), "a comment is not live markup to fix");
        assert!(doctor::check(&files).is_empty());
    }

    #[test]
    fn scripts_with_a_src_are_left_alone() {
        let files = vec![
            html(
                "index.html",
                "<!doctype html><script src=\"app.js\"></script>",
            ),
            html("app.js", "ok\n"),
        ];
        assert!(plan(&files).is_empty());
        assert!(
            doctor::check(&files).is_empty(),
            "{:?}",
            rules(&doctor::check(&files))
        );
    }

    #[test]
    fn applying_twice_changes_nothing_the_second_time() {
        let files = vec![html("idem.html", "<style>k{}</style>")];
        let first = plan(&files);
        let once = first.apply(&files);
        let second = plan(&once);
        assert!(
            second.is_empty(),
            "the fixed tree has nothing left to extract"
        );
    }

    #[test]
    fn clean_documents_come_back_byte_identical() {
        let files = vec![
            html("index.html", "<!doctype html><p>fine</p>"),
            html("data.bin", "\u{0}\u{1}\u{2}"),
        ];
        let outcome = plan(&files);
        assert!(outcome.is_empty());
        let again = outcome.apply(&files);
        assert_eq!(again.len(), files.len());
        for (before, after) in files.iter().zip(again.iter()) {
            assert_eq!(before.content, after.content);
        }
    }

    #[test]
    fn the_diff_shows_what_will_change_before_anything_is_written() {
        let files = vec![html("diff.html", "<title>t</title>\n<style>p{}</style>")];
        let plan = plan(&files);
        let text = plan.render();
        assert!(text.contains("--- diff.html"), "old side named");
        assert!(
            text.contains("- <style>p{}</style>"),
            "removed lines shown: {text:?}"
        );
        assert!(text.contains("+ "), "added lines shown");
        assert!(
            text.contains("+ new file diff.extracted.css"),
            "created files are announced in the diff: {text:?}"
        );
        // Nothing has been written anywhere: the input files still carry their inline blocks.
        assert_eq!(
            String::from_utf8_lossy(&files[0].content),
            "<title>t</title>\n<style>p{}</style>"
        );
    }
}
