//! `vayu` — the headless command surface for the desktop client's publish path.
//!
//! PUBLISHING.md section 1 opens with `vayu publish ./my-site --name example.vayu`, and until
//! now nothing invoked the library seam. This binary is that verb, headless: it walks a site
//! directory, runs the doctor's authoring checks (step 1), builds and addresses the UnixFS tree
//! (steps 2–3), pins every block to a local store before anything is signed (step 4), and
//! produces the signed record (step 5). Appending to a log (step 6) is the caller's move — this
//! prints or writes the record bytes and stops, because which log belongs to whom is an
//! application decision, not a protocol one.
//!
//! ## What is deliberately plain about key handling
//!
//! `--key-file` reads a hex-encoded seed. That is a TOOL choice for headless use, stated here so
//! nobody mistakes it for the product's answer to key storage: the GUI's OS-keychain placement,
//! zeroisation on lock, and never letting a secret touch disk are Phase 5 requirements this
//! binary neither satisfies nor pretends to. The seed is expanded through
//! [`vayuweb_client::identity::Identity::from_seed`], whose CSPRNG-backed `generate()` remains
//! how production identities are made.
//!
//! Exit codes: 0 success; 1 the doctor found errors or the publish was refused; 2 usage error.

use std::io::Write as _;
use std::sync::Arc;

use vayuweb_client::cid::Cid;
use vayuweb_client::dagnode::WalkLimits;
use vayuweb_client::doctor;
use vayuweb_client::identity::Identity;
use vayuweb_client::publish::SiteFile;
use vayuweb_client::publish_flow::{publish_site, PublishRequest};
use vayuweb_client::record::Predecessor;
use vayuweb_client::serve;
use vayuweb_client::store::BlockStore;

const USAGE: &str = "\
vayu — publish a site into the VayuWeb content path

USAGE:
    vayu doctor <site-dir>
        Run the authoring checks of PUBLISHING.md section 3 over a directory.
        Exit 0 when clean; exit 1 with every finding rendered otherwise.

    vayu publish <site-dir> --name <label>.<tld> [options]
        Check, build, address, pin locally, then sign the pointer — in that order.
        Prints the signed record as hex on stdout.

    Options for publish:
        --name <label>.<tld>    the name to register or update (required)
        --store <dir>           block store directory (default: ./vayu-store)
        --key-file <file>       file holding a hex-encoded identity seed (64 hex chars)
        --prev <file>           previous record bytes; presence makes this an UPDATE
        --out <file>            also write the record bytes here
        --window-count <n>      TLD registration count over the trailing window (default 0)
        --pow-limit <n>         nonce-search ceiling (default 10000000)
        --now <unix-seconds>    override the clock (for reproducible runs)

    vayu serve <store-dir> --root <cid> [options]
        Serve one pinned tree over loopback HTTP for local preview. Prints the URL,
        then Ctrl-C to stop. This is a preview of ONE tree, not the browsing proxy.

    Options for serve:
        --root <cid-text>       the tree to serve (required)
        --port <n>              port to bind (default: 0, an ephemeral free port)

    vayu verify <record.cbor> [options]
        Verify a record RECEIVED from somewhere else, in its exact bytes: framing,
        canonicality, structure, chain discipline against --prev, per-operation
        term rules, signature under the controlling key, transfer countersig-
        nature, proof of work, clock discipline. Prints ACCEPT / REJECT(code) /
        DEFER. Standalone mode cannot know whether a REGISTER's name is taken;
        that check belongs to whoever holds the registry view.

    Options for verify:
        --prev <file>           the predecessor's exact accepted bytes
        --transferor-key <hex>  64 hex chars: a TRANSFER predecessor's transferor key
        --now <unix-seconds>    override the verifier clock
        --window-count <n>      TLD registration count over the trailing window

    vayu pins <store-dir>
        List every block the store holds, classified, with totals.

    vayu help
        Show this text.

Exit codes: 0 success · 1 checks failed or publish refused · 2 usage error.
";

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("doctor") => cmd_doctor(&argv[1..]),
        Some("publish") => cmd_publish(&argv[1..]),
        Some("serve") => cmd_serve(&argv[1..]),
        Some("verify") => cmd_verify(&argv[1..]),
        Some("pins") => cmd_pins(&argv[1..]),
        Some("help") | Some("--help") | Some("-h") => {
            print!("{USAGE}");
            0
        }
        _ => {
            eprint!("{USAGE}");
            2
        }
    }
}

// ---------------------------------------------------------------------------
// vayu verify — the peer's half of record validation.
// ---------------------------------------------------------------------------

fn cmd_verify(argv: &[String]) -> i32 {
    let Some(record_path) = argv.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("vayu verify needs a record file");
        return 2;
    };
    let flags = match Flags::parse(
        &argv[1..],
        &["prev", "transferor-key", "now", "window-count"],
    ) {
        Ok(flags) => flags,
        Err(detail) => {
            eprintln!("vayu verify: {detail}");
            return 2;
        }
    };
    let bytes = match std::fs::read(record_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("vayu verify: cannot read {record_path:?}: {e}");
            return 2;
        }
    };

    let now = match flags.number("now") {
        Ok(Some(now)) => now,
        Ok(None) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default(),
        Err(detail) => {
            eprintln!("vayu verify: {detail}");
            return 2;
        }
    };
    let window_count = match flags.number("window-count") {
        Ok(value) => value.unwrap_or(0),
        Err(detail) => {
            eprintln!("vayu verify: {detail}");
            return 2;
        }
    };

    let previous = match flags.get("prev") {
        Some(path) => {
            let prev_bytes = match std::fs::read(path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("vayu verify: cannot read predecessor {path:?}: {e}");
                    return 2;
                }
            };
            let transferor = match flags.get("transferor-key") {
                Some(text) => match hex_decode(text) {
                    Ok(seed) if seed.len() == 32 => {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&seed);
                        Some(key)
                    }
                    _ => {
                        eprintln!("vayu verify: --transferor-key wants exactly 64 hex chars");
                        return 2;
                    }
                },
                None => None,
            };
            match vayuweb_client::verify::prev_view(&prev_bytes, transferor.as_ref()) {
                Ok(view) => Some(view),
                Err(detail) => {
                    eprintln!("vayu verify: unusable predecessor: {detail}");
                    return 2;
                }
            }
        }
        None => None,
    };

    let verdict = vayuweb_client::verify::verify(&bytes, previous.as_ref(), now, window_count);
    match &verdict {
        vayuweb_client::verify::Verdict::Accept => {
            println!("ACCEPT");
            0
        }
        vayuweb_client::verify::Verdict::Reject { code, detail } => {
            println!("REJECT {code}: {detail}");
            1
        }
        vayuweb_client::verify::Verdict::Defer { detail } => {
            println!("DEFER: {detail}");
            println!("the record is neither good nor bad yet: hold it and retry when the clock catches up.");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// vayu pins — what does this store actually hold?
// ---------------------------------------------------------------------------

fn cmd_pins(argv: &[String]) -> i32 {
    let Some(store_dir) = argv.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("vayu pins needs a store directory");
        return 2;
    };
    if argv.len() > 1 {
        eprintln!("unexpected argument after <store-dir>: {:?}", argv[1]);
        return 2;
    }
    let store = match BlockStore::open(std::path::Path::new(store_dir)) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("vayu pins: cannot open block store {store_dir}: {e}");
            return 2;
        }
    };
    let entries = match std::fs::read_dir(store_dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("vayu pins: cannot list {store_dir}: {e}");
            return 2;
        }
    };

    let limits = WalkLimits::default();
    let mut rows: Vec<(String, u64, String)> = Vec::new();
    let mut total_bytes = 0u64;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(size) = entry.metadata().map(|m| m.len()) else {
            continue;
        };
        let Ok(cid) = Cid::from_text(&name) else {
            // Not a CID-shaped filename: not one of ours (temp files are swept at open).
            continue;
        };
        let kind = match vayuweb_client::dagnode::read_node(&store, &cid, &limits) {
            Ok(vayuweb_client::dagnode::Node::Raw(_)) => "leaf".to_string(),
            Ok(vayuweb_client::dagnode::Node::Directory(links)) => format!("dir({})", links.len()),
            Ok(vayuweb_client::dagnode::Node::File { children, .. }) => {
                format!("file(+{})", children.len())
            }
            Err(e) => format!("unreadable ({e})"),
        };
        total_bytes += size;
        rows.push((name, size, kind));
    }
    rows.sort();
    for (name, size, kind) in &rows {
        println!("{name}  {size:>9} B  {kind}");
    }
    println!(
        "\n{} block(s), {total_bytes} B held in {store_dir}",
        rows.len()
    );
    0
}

// ---------------------------------------------------------------------------
// vayu serve — loopback preview of one pinned tree.
// ---------------------------------------------------------------------------

fn cmd_serve(argv: &[String]) -> i32 {
    let Some(store_dir) = argv.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("vayu serve needs a store directory");
        return 2;
    };
    let flags = match Flags::parse(&argv[1..], &["root", "port"]) {
        Ok(flags) => flags,
        Err(detail) => {
            eprintln!("vayu serve: {detail}");
            return 2;
        }
    };
    let Some(root_text) = flags.get("root") else {
        eprintln!("vayu serve: --root <cid> naming the tree to serve is required");
        return 2;
    };
    let Ok(root) = Cid::from_text(root_text) else {
        eprintln!("vayu serve: {root_text:?} is not a CID this protocol admits");
        return 2;
    };
    let port = match flags.number("port") {
        Ok(Some(port)) if port <= u16::MAX as u64 => port as u16,
        Ok(_) => {
            eprintln!("vayu serve: --port is out of range");
            return 2;
        }
        Err(detail) => {
            eprintln!("vayu serve: {detail}");
            return 2;
        }
    };
    let store = match BlockStore::open(std::path::Path::new(store_dir)) {
        Ok(store) => Arc::new(store),
        Err(e) => {
            eprintln!("vayu serve: cannot open block store {store_dir}: {e}");
            return 2;
        }
    };
    // 3.1.6, enforced at the door: a preview that serves what `vayu publish` would REFUSE is
    // the exact checker-passes-resolver-refuses mismatch the specification calls worse than no
    // checker -- you would be looking at something readers can never see. So the tree is
    // checked with the publisher's own checker before the URL is announced. Warnings print but
    // do not stop; errors stop everything.
    let files = match vayuweb_client::dagnode::collect_files(&store, &root, &WalkLimits::default())
    {
        Ok(files) => files,
        Err(e) => {
            eprintln!("vayu serve: that root is not readable from this store: {e}");
            return 2;
        }
    };
    let findings = vayuweb_client::doctor::check(&files);
    let error_count = findings
        .iter()
        .filter(|f| f.severity == vayuweb_client::doctor::Severity::Error)
        .count();
    if error_count > 0 {
        eprintln!(
            "vayu serve: refusing to serve this tree -- {error_count} finding(s) stop a \
             publish, so serving it would show you a site no reader can get:"
        );
        for finding in &findings {
            eprintln!("{}", finding.render());
        }
        return 1;
    }
    for finding in &findings {
        eprintln!("warning: {}", finding.render().trim_start());
    }
    let root_text_owned = root.to_text();
    let handle = match serve::spawn(store, root, port, WalkLimits::default()) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("vayu serve: cannot bind: {e}");
            return 2;
        }
    };
    println!(
        "serving   http://{}/\nroot      {}\nstop with Ctrl-C",
        handle.addr, root_text_owned
    );
    let _ = std::io::stdout().flush();
    // The default SIGINT/console-ctrl behaviour ends the process, which closes the socket:
    // exactly what a preview server should do. No signal machinery beyond that.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

/// Walk a directory recursively, returning site files with '/'-separated relative paths in
/// deterministic (sorted) order. The manifest at `.vayu/manifest.json` is INCLUDED — it is part
/// of the tree by design. Hidden directories other than `.vayu` are skipped, because editor
/// droppings are not site content; everything else is taken as the publisher wrote it.
fn walk_site(
    root: &std::path::Path,
    exclude: Option<&std::path::Path>,
) -> Result<Vec<SiteFile>, String> {
    let root_canonical = root
        .canonicalize()
        .map_err(|e| format!("{}: {e}", root.display()))?;
    let excluded = exclude
        .map(std::path::Path::canonicalize)
        .transpose()
        .ok()
        .flatten();
    let mut files = Vec::new();
    let mut stack = vec![root_canonical.clone()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if name == ".git" && dir == root_canonical {
                    continue;
                }
                if Some(&path) == excluded.as_ref() {
                    continue;
                }
                if name.starts_with('.') && name != ".vayu" {
                    continue;
                }
                stack.push(path);
            } else if path.is_file() {
                let relative = path
                    .strip_prefix(&root_canonical)
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .replace('\\', "/");
                let content =
                    std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                files.push(SiteFile {
                    path: relative,
                    content,
                });
            }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = text.trim().chars().filter(|c| !c.is_whitespace()).collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err("odd-length hex".to_string());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    for pair in bytes.chunks(2) {
        let high = (pair[0] as char).to_digit(16).ok_or("non-hex character")?;
        let low = (pair[1] as char).to_digit(16).ok_or("non-hex character")?;
        out.push(((high << 4) | low) as u8);
    }
    Ok(out)
}

fn parse_name(value: &str) -> Result<(String, String), String> {
    let (label, tld) = value
        .rsplit_once('.')
        .ok_or_else(|| format!("{value} is not a label.tld"))?;
    Ok((label.to_string(), tld.to_string()))
}

struct Flags {
    values: Vec<(String, Option<String>)>,
}

impl Flags {
    fn parse(argv: &[String], valued: &[&str]) -> Result<Self, String> {
        let mut values = Vec::new();
        let mut i = 0usize;
        while i < argv.len() {
            let arg = &argv[i];
            if let Some(name) = arg.strip_prefix("--") {
                if valued.contains(&name) {
                    let Some(value) = argv.get(i + 1) else {
                        return Err(format!("--{name} needs a value"));
                    };
                    values.push((name.to_string(), Some(value.clone())));
                    i += 2;
                } else {
                    values.push((name.to_string(), None));
                    i += 1;
                }
            } else {
                return Err(format!(
                    "unexpected argument {arg:?} (positional inputs come first)"
                ));
            }
        }
        Ok(Self { values })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| value.as_deref())
    }

    fn number(&self, name: &str) -> Result<Option<u64>, String> {
        match self.get(name) {
            None => Ok(None),
            Some(text) => text
                .parse::<u64>()
                .map(Some)
                .map_err(|_| format!("--{name} wants a number, got {text:?}")),
        }
    }

    fn has(&self, name: &str) -> bool {
        self.values.iter().any(|(key, _)| key == name)
    }
}

fn summary(findings: &[doctor::Finding]) -> String {
    let errors = findings
        .iter()
        .filter(|f| f.severity == doctor::Severity::Error)
        .count();
    let confirms = findings
        .iter()
        .filter(|f| f.severity == doctor::Severity::Confirm)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == doctor::Severity::Warning)
        .count();
    format!("\n{errors} error(s), {confirms} confirmation(s), {warnings} warning(s).")
}

// ---------------------------------------------------------------------------
// vayu doctor
// ---------------------------------------------------------------------------

fn cmd_doctor(argv: &[String]) -> i32 {
    let Some(dir) = argv.first() else {
        eprint!("{USAGE}");
        return 2;
    };
    if argv.len() > 1 {
        eprintln!("unexpected argument after <site-dir>: {:?}", argv[1]);
        return 2;
    }
    let files = match walk_site(std::path::Path::new(dir), None) {
        Ok(files) => files,
        Err(detail) => {
            eprintln!("vayu doctor: {detail}");
            return 2;
        }
    };
    let findings = doctor::check(&files);
    for item in &findings {
        println!("{}", item.render());
    }
    print!("{}", summary(&findings));
    let stopped = findings
        .iter()
        .any(|f| f.severity == doctor::Severity::Error);
    println!(
        "\n{}",
        if stopped {
            "the publish would stop: fix the errors above."
        } else {
            "this site would pass step 1."
        }
    );
    if stopped {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// vayu publish
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
fn cmd_publish(argv: &[String]) -> i32 {
    // First positional is the site directory; everything after may be flags.
    let Some(site_dir) = argv.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("vayu publish needs a site directory");
        eprint!("{USAGE}");
        return 2;
    };
    let flags = match Flags::parse(
        &argv[1..],
        &[
            "name",
            "store",
            "key-file",
            "prev",
            "out",
            "window-count",
            "pow-limit",
            "now",
        ],
    ) {
        Ok(flags) => flags,
        Err(detail) => {
            eprintln!("vayu publish: {detail}");
            return 2;
        }
    };
    if flags.has("help") {
        print!("{USAGE}");
        return 0;
    }
    let Some(name_value) = flags.get("name") else {
        eprintln!("vayu publish: --name <label>.<tld> is required");
        return 2;
    };
    let Ok((label, tld)) = parse_name(name_value) else {
        eprintln!("vayu publish: --name wants <label>.<tld>, got {name_value:?}");
        return 2;
    };

    // Identity. See the module header: --key-file is a tool choice, not the product's answer
    // to key storage.
    let identity = match flags.get("key-file") {
        Some(path) => {
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(e) => {
                    eprintln!("vayu publish: cannot read key file {path:?}: {e}");
                    return 2;
                }
            };
            match hex_decode(&text) {
                Ok(seed) if seed.len() == 32 => match Identity::from_seed(&mut seed.clone()) {
                    Ok(identity) => identity,
                    Err(e) => {
                        eprintln!("vayu publish: the seed did not yield an identity: {e}");
                        return 2;
                    }
                },
                Ok(seed) => {
                    eprintln!(
                        "vayu publish: the seed must be exactly 32 bytes (64 hex chars), got {}",
                        seed.len()
                    );
                    return 2;
                }
                Err(e) => {
                    eprintln!("vayu publish: key file {path:?}: {e}");
                    return 2;
                }
            }
        }
        None => {
            eprintln!(
                "vayu publish: --key-file <hex-seed-file> is required for headless use. \
                 (A generated identity needs the GUI's OS keystore, which does not exist yet.)"
            );
            return 2;
        }
    };

    let site_path = std::path::Path::new(site_dir);
    let store_path = std::path::PathBuf::from(flags.get("store").unwrap_or("vayu-store"));

    // Refusing a store INSIDE the site tree is not fussiness: the store would pin the tree that
    // contains the store, and republishing would then try to pin itself again.
    let store_inside_site = std::fs::canonicalize(&store_path)
        .ok()
        .zip(std::fs::canonicalize(site_path).ok())
        .map(|(store, site)| store.starts_with(&site))
        .unwrap_or(false);
    if store_inside_site {
        eprintln!(
            "vayu publish: the store ({}) must live outside the site directory ({})",
            store_path.display(),
            site_dir
        );
        return 2;
    }

    let predecessor = match flags.get("prev") {
        Some(path) => match std::fs::read(path) {
            Ok(bytes) => match Predecessor::from_bytes(&bytes) {
                Ok(previous) => Some(previous),
                Err(e) => {
                    eprintln!("vayu publish: {path:?} is not a usable previous record: {e}");
                    return 2;
                }
            },
            Err(e) => {
                eprintln!("vayu publish: cannot read {path:?}: {e}");
                return 2;
            }
        },
        None => None,
    };

    let files = match walk_site(site_path, Some(&store_path)) {
        Ok(files) => files,
        Err(detail) => {
            eprintln!("vayu publish: {detail}");
            return 2;
        }
    };

    let store = match BlockStore::open(&store_path) {
        Ok(store) => store,
        Err(e) => {
            eprintln!(
                "vayu publish: cannot open block store {}: {e}",
                store_path.display()
            );
            return 2;
        }
    };

    let now = match flags.number("now") {
        Ok(Some(now)) => now,
        Ok(None) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default(),
        Err(detail) => {
            eprintln!("vayu publish: {detail}");
            return 2;
        }
    };
    let window_count = match flags.number("window-count") {
        Ok(value) => value.unwrap_or(0),
        Err(detail) => {
            eprintln!("vayu publish: {detail}");
            return 2;
        }
    };
    let pow_limit = match flags.number("pow-limit") {
        Ok(value) => value.unwrap_or(10_000_000),
        Err(detail) => {
            eprintln!("vayu publish: {detail}");
            return 2;
        }
    };

    let outcome = publish_site(
        &store,
        PublishRequest {
            identity: &identity,
            label: &label,
            tld: &tld,
            files: &files,
            now,
            predecessor: predecessor.as_ref(),
            window_count,
            pow_limit,
        },
    );

    let published = match outcome {
        Ok(published) => published,
        Err(vayuweb_client::publish_flow::FlowError::Doctor(findings)) => {
            // Step 1 stopped the publish. Render EVERYTHING, because warnings are advice and
            // the operator should see them even amid the errors that stopped them.
            for item in &findings {
                println!("{}", item.render());
            }
            print!("{}", summary(&findings));
            println!("\nnothing was built, pinned or signed: fix the errors above.");
            return 1;
        }
        Err(e) => {
            eprintln!("vayu publish: refused: {e}");
            return 1;
        }
    };

    let record_hex: String = published
        .record
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    if let Some(out) = flags.get("out") {
        if let Err(e) = std::fs::write(out, &published.record) {
            eprintln!("vayu publish: cannot write {out:?}: {e}");
            return 1;
        }
    }

    println!(
        "root     {}\nblocks   {} newly pinned\nrecord   {} bytes{}\n",
        published.root.to_text(),
        published.newly_pinned,
        published.record.len(),
        flags
            .get("out")
            .map(|out| format!("\nwritten  {out}"))
            .unwrap_or_default(),
    );
    println!("{record_hex}");
    let _ = std::io::stdout().flush();
    0
}
