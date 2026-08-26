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

        Renewal is automatic: if the view already holds this name under YOUR key,
        this publish signs an UPDATE (seq + 1) from that chain; once the name has
        lapsed back to the open pool, it registers anew; while someone else holds
        it, publishing refuses. --prev overrides for a hand-carried chain.

    Options for publish:
        --name <label>.<tld>    the name to register or update (required)
        --store <dir>           block store directory (default: ./vayu-store)
        --key-file <file>       file holding a hex-encoded identity seed (64 hex chars)
        --prev <file>           previous record bytes; forces an UPDATE under that chain
        --out <file>            also write the record bytes here
        --window-count <n>      TLD registration count over the trailing window (default 0)
        --pow-limit <n>         nonce-search ceiling (default 10000000)
        --now <unix-seconds>    override the clock (for reproducible runs)
        --view <dir>            registry view appended to AND renews from
                                (default: <store>/view)

    vayu serve <store-dir> (--root <cid> | --name <label>.<tld>) [options]
        Serve one pinned tree over loopback HTTP for local preview. Prints the URL,
        then Ctrl-C to stop. This is a preview of ONE tree, not the browsing proxy.

        With --name, the tree comes from the registry view: the name's current
        accepted record is re-judged as received, must be LIVE at this instant,
        and its cid entry supplies the root. A pointer that does not verify —
        or a lapsed or missing history — refuses to serve. Publish appends to
        the view automatically (default: <store>/view).

    Options for serve:
        --root <cid-text>       the tree to serve (or use --name)
        --name <label>.<tld>    resolve through the view instead of a raw CID
        --view <dir>            the record log (default with --name: <store>/view)
        --now <unix-seconds>    override the verifier clock (with --name)
        --window-count <n>      TLD registration count (with --name)
        --port <n>              port to bind (default: 0, an ephemeral free port)

    vayu verify <record.cbor> [options]
        Verify a record RECEIVED from somewhere else, in its exact bytes: framing,
        canonicality, structure, chain discipline, per-operation term rules,
        signature under the controlling key, transfer countersignature, proof
        of work, clock discipline. Prints ACCEPT / REJECT(code) / DEFER.
        Without --view or --prev the record is judged STANDALONE: no incumbent
        set and no history, so NAME_TAKEN and chain checks cannot run.

    Options for verify:
        --view <dir>            a local record log; predecessor found by replay,
                                NAME_TAKEN answered from the incumbent's lifecycle
        --prev <file>           the predecessor's exact accepted bytes
        --transferor-key <hex>  64 hex chars: a TRANSFER predecessor's transferor key
                                (unneeded with --view: replay resolves it)
        --now <unix-seconds>    override the verifier clock
        --window-count <n>      TLD registration count over the trailing window

    vayu accept <record.cbor> --view <dir> [options]
        Verify against the view (see verify --view) and, on ACCEPT, append the
        record to it. The log is append-only files addressed by their own
        record_hash; state is derived by replay, never indexed.

    Options for accept: --now, --window-count (as for verify).

    vayu names --view <dir>
        List every name this view holds history for, with its lifecycle state:
        LIVE, GRACE, QUARANTINE, FREE, or the revoked freeze.

    vayu export (--view <dir> | --store <dir>) [--out <file>]
        Bundle what one machine holds into one canonical CBOR document. With --view:
        every accepted record's exact bytes. With --store: every pinned block as
        [cidBytes, payload] pairs, sorted by CID. With --out a file; without it, hex
        on stdout. Together the two bundles carry a WHOLE site over any channel.

    vayu import <bundle.cbor> (--view <dir> | --store <dir>) [options]
        Judge each element against its destination and keep only what verifies.
        With --view: records re-judged as received (see vayu verify). With --store:
        every block re-hashed — the payload must match the digest inside its own
        CID before it is pinned, so corruption anywhere refuses that block alone.
        Already-held items skip without re-judgment; refusals print per element.
        Verdicts are data, not tool failures: only broken input or IO exits non-zero.

    vayu pins <store-dir>
        List every block the store holds, classified, with totals.

    vayu transfer <label>.<tld> --store <dir> --key-file <f> --recipient-seed <f> [options]
        Hand the name to another key: both parties co-sign here (the record carries
        sig and coSig). Only while at least the settlement window remains in the term.
        Until settlement ends, resolution refuses the name — it is in flight.

    vayu relinquish <label>.<tld> --store <dir> --key-file <f> [options]
        The owner says they are done. Grace is skipped; quarantine is not.

    vayu revoke <label>.<tld> --store <dir> --key-file <f> [options]
        The deadman switch: resolution stops at once; the name stays frozen for the
        rest of its term and then quarantines, accepting nothing from anyone.

    vayu renew <label>.<tld> --store <dir> --key-file <f> [options]
        Extend the term by one more year, from the old expiry. Only inside the
        renewal window (the last 60 days of the term) and with proof of work like a
        registration. This is how a name outlives its first year; publish's
        automatic UPDATE re-points content but never extends time.

        All four take --now like publish (--renew also --window-count/--pow-limit),
        resolve the predecessor from the view exactly as publish does, refuse if
        another key holds the name, and append their signed record to the view when
        it verifies there.

    vayu alias <label>.<tld> --to <other>.<tld> --key-file <f> [options]
        Point a name at another ratified name: the record's single entry is an
        alias. Resolution follows aliases at most THREE hops (REGISTRY.md) and
        refuses a cycle with ALIAS_LOOP — and every hop's target must itself be
        live and verifying, or nothing resolves.

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
        Some("accept") => cmd_accept(&argv[1..]),
        Some("names") => cmd_names(&argv[1..]),
        Some("export") => cmd_export(&argv[1..]),
        Some("import") => cmd_import(&argv[1..]),
        Some("transfer") => cmd_owner_exit(&argv[1..], OwnerOp::Transfer),
        Some("relinquish") => cmd_owner_exit(&argv[1..], OwnerOp::Relinquish),
        Some("revoke") => cmd_owner_exit(&argv[1..], OwnerOp::Revoke),
        Some("renew") => cmd_owner_exit(&argv[1..], OwnerOp::Renew),
        Some("alias") => cmd_alias(&argv[1..]),
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
        &["view", "prev", "transferor-key", "now", "window-count"],
    ) {
        Ok(flags) => flags,
        Err(detail) => {
            eprintln!("vayu verify: {detail}");
            return 2;
        }
    };
    if flags.has("view") && (flags.has("prev") || flags.has("transferor-key")) {
        eprintln!("vayu verify: --view resolves the predecessor itself; do not combine it with --prev or --transferor-key");
        return 2;
    }
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

    // View mode: predecessor found by replay, NAME_TAKEN answerable. Precedence over
    // single-record mode because the view is strictly more honest about history.
    let verdict = if let Some(view_dir) = flags.get("view") {
        let view = match vayuweb_client::view::View::open(std::path::Path::new(view_dir)) {
            Ok(view) => view,
            Err(detail) => {
                eprintln!("vayu verify: {detail}");
                return 2;
            }
        };
        match view.accept_verdict(&bytes, now, window_count) {
            Ok(verdict) => verdict,
            Err(detail) => {
                eprintln!("vayu verify: {detail}");
                return 2;
            }
        }
    } else {
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
        vayuweb_client::verify::verify(&bytes, previous.as_ref(), now, window_count)
    };

    print_verdict(&verdict)
}

// ---------------------------------------------------------------------------
// vayu accept / vayu names — the local registry view.
// ---------------------------------------------------------------------------

fn cmd_accept(argv: &[String]) -> i32 {
    let Some(record_path) = argv.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("vayu accept needs a record file");
        return 2;
    };
    let flags = match Flags::parse(&argv[1..], &["view", "now", "window-count"]) {
        Ok(flags) => flags,
        Err(detail) => {
            eprintln!("vayu accept: {detail}");
            return 2;
        }
    };
    let Some(view_dir) = flags.get("view") else {
        eprintln!(
            "vayu accept needs --view <dir>: acceptance is meaningless without a log to append to"
        );
        return 2;
    };
    let bytes = match std::fs::read(record_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("vayu accept: cannot read {record_path:?}: {e}");
            return 2;
        }
    };
    let view = match vayuweb_client::view::View::open(std::path::Path::new(view_dir)) {
        Ok(view) => view,
        Err(detail) => {
            eprintln!("vayu accept: {detail}");
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
            eprintln!("vayu accept: {detail}");
            return 2;
        }
    };
    let window_count = match flags.number("window-count") {
        Ok(value) => value.unwrap_or(0),
        Err(detail) => {
            eprintln!("vayu accept: {detail}");
            return 2;
        }
    };

    let before = view.entries().map(|e| e.len()).unwrap_or(0);
    let verdict = match view.accept_verdict(&bytes, now, window_count) {
        Ok(verdict) => verdict,
        Err(detail) => {
            eprintln!("vayu accept: {detail}");
            return 2;
        }
    };
    let code = print_verdict(&verdict);
    if code != 0 {
        // A rejected or deferred record is NOT appended: the log holds only what the view
        // actually accepted, so replay never has to skip a refusal.
        return code;
    }

    if let Err(detail) = view.put(&bytes) {
        eprintln!("vayu accept: verification succeeded but the log refused the write: {detail}");
        return 1;
    }
    let after = view.entries().map(|e| e.len()).unwrap_or(0);
    if after == before {
        println!("already held: identical bytes are already in this view.");
    } else {
        println!("appended to view {view_dir} ({after} record(s) held).");
    }
    0
}

fn cmd_names(argv: &[String]) -> i32 {
    let flags = match Flags::parse(argv, &["view"]) {
        Ok(flags) => flags,
        Err(detail) => {
            eprintln!("vayu names: {detail}");
            return 2;
        }
    };
    let Some(view_dir) = flags.get("view") else {
        eprintln!("vayu names needs --view <dir>");
        return 2;
    };
    let view = match vayuweb_client::view::View::open(std::path::Path::new(view_dir)) {
        Ok(view) => view,
        Err(detail) => {
            eprintln!("vayu names: {detail}");
            return 2;
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let names = match view.all_names() {
        Ok(names) => names,
        Err(detail) => {
            eprintln!("vayu names: {detail}");
            return 2;
        }
    };
    if names.is_empty() {
        if flags.has("json") {
            println!("[]");
        } else {
            println!("this view holds no accepted records yet.");
        }
        return 0;
    }
    if flags.has("json") {
        // Machine-readable inventory for scripts and the future GUI. No string escaping
        // is needed: labels and TLDs are refused at registration unless they match the
        // strict charset, lifecycle states are this file's own fixed words, and hashes
        // and keys print as hex.
        let items: Vec<String> = names
            .iter()
            .map(|(label, tld, tip)| {
                let state = vayuweb_client::verify::lifecycle_state(&tip.prev, now);
                let owner: String = tip
                    .prev
                    .owner_key
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                format!(
                    "{{\"name\": \"{label}.{tld}\", \"state\": \"{state}\", \"seq\": {}, \
                     \"record\": \"{}\", \"owner\": \"{owner}\", \"expires\": {}}}",
                    tip.prev.seq, tip.entry.hash_hex, tip.prev.not_after
                )
            })
            .collect();
        println!("[{}]", items.join(", "));
        return 0;
    }
    for (label, tld, tip) in &names {
        let state = vayuweb_client::verify::lifecycle_state(&tip.prev, now);
        let expiry = tip.prev.not_after;
        println!(
            "{label}.{tld}\n  seq {} · {} · expires {expiry} · {state}",
            tip.prev.seq, tip.entry.hash_hex
        );
    }
    println!("\n{} name(s) in {view_dir}", names.len());
    0
}

// ---------------------------------------------------------------------------
// vayu export / vayu import — exchange over any channel.
//
// Bundles are canonical CBOR documents, so the strict decoder polices the
// envelope too (no bespoke container to get wrong):
//   --view  -> an ARRAY of byte strings: records' EXACT accepted bytes.
//   --store -> an ARRAY of [cidBytes, payload] pairs: every block held,
//              addressed by its own binary CID. The far side re-hashes each
//              payload before pinning, because content addressing is the one
//              integrity check that travels with the bytes.
// ---------------------------------------------------------------------------

fn cmd_export(argv: &[String]) -> i32 {
    let flags = match Flags::parse(argv, &["view", "store", "out"]) {
        Ok(flags) => flags,
        Err(detail) => {
            eprintln!("vayu export: {detail}");
            return 2;
        }
    };
    match (flags.get("view"), flags.get("store")) {
        (Some(_), Some(_)) => {
            eprintln!("vayu export: --view and --store bundle different things; give one");
            return 2;
        }
        (None, None) => {
            eprintln!("vayu export needs --view <dir> (records) or --store <dir> (blocks)");
            return 2;
        }
        _ => {}
    }
    let bundle = if let Some(view_dir) = flags.get("view") {
        let view = match vayuweb_client::view::View::open(std::path::Path::new(view_dir)) {
            Ok(view) => view,
            Err(detail) => {
                eprintln!("vayu export: {detail}");
                return 2;
            }
        };
        let entries = match view.entries() {
            Ok(entries) => entries,
            Err(detail) => {
                eprintln!("vayu export: {detail}");
                return 1;
            }
        };
        let count = entries.len();
        let encoded = vayuweb_client::cbor::encode(&vayuweb_client::cbor::Value::Array(
            entries
                .iter()
                .map(|e| vayuweb_client::cbor::Value::Bytes(e.bytes.clone()))
                .collect(),
        ))
        .expect("an array of byte strings always encodes");
        (encoded, format!("{count} record(s)"))
    } else {
        let store_dir = flags.get("store").expect("checked above");
        match block_bundle(std::path::Path::new(store_dir)) {
            Ok((count, encoded)) => (encoded, format!("{count} block(s)")),
            Err(detail) => {
                eprintln!("vayu export: {detail}");
                return 1;
            }
        }
    };
    let (bundle, what) = bundle;
    match flags.get("out") {
        Some(out) => {
            if let Err(e) = std::fs::write(out, &bundle) {
                eprintln!("vayu export: cannot write {out:?}: {e}");
                return 1;
            }
            println!("{what} -> {out} ({} bytes)", bundle.len());
        }
        None => {
            // No --out: hex on stdout, so the smallest possible exchange is a copy-paste.
            for byte in &bundle {
                print!("{byte:02x}");
            }
            println!();
        }
    }
    0
}

/// Every block a store holds as [cidBytes, payload] pairs in one canonical document,
/// sorted by CID text for reproducible bundles.
fn block_bundle(store_dir: &std::path::Path) -> Result<(usize, Vec<u8>), String> {
    let mut pairs: Vec<(String, Vec<u8>, Vec<u8>)> = Vec::new();
    let entries =
        std::fs::read_dir(store_dir).map_err(|e| format!("cannot list {store_dir:?}: {e}"))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(cid) = Cid::from_text(&name) else {
            continue;
        };
        let payload =
            std::fs::read(entry.path()).map_err(|e| format!("cannot read {name}: {e}"))?;
        pairs.push((name, cid.to_bytes(), payload));
    }
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let count = pairs.len();
    let encoded = vayuweb_client::cbor::encode(&vayuweb_client::cbor::Value::Array(
        pairs
            .into_iter()
            .map(|(_, cid_bytes, payload)| {
                vayuweb_client::cbor::Value::Array(vec![
                    vayuweb_client::cbor::Value::Bytes(cid_bytes),
                    vayuweb_client::cbor::Value::Bytes(payload),
                ])
            })
            .collect(),
    ))
    .expect("an array of arrays of byte strings always encodes");
    Ok((count, encoded))
}

/// Canonical filename for an evidence pair: sorted by record hash, so whichever order
/// the two halves arrive in lands on the same file and a re-report is idempotent.
fn evidence_path(view_dir: &std::path::Path, a: &[u8], b: &[u8]) -> std::path::PathBuf {
    let hash = |bytes: &[u8]| vayuweb_client::domain::record_hash_from_bytes(bytes);
    let (first, second) = if hash(a) <= hash(b) { (a, b) } else { (b, a) };
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    view_dir
        .join("evidence")
        .join(format!("{}-{}.pair", hex(&hash(first)), hex(&hash(second))))
}

/// Persist one verified equivocation pair beside the log that witnessed it.
///
/// REPLICATION.md 6.1 makes evidence worth forwarding BECAUSE anyone can verify it from
/// the two encodings alone — so what gets saved is the exact bytes, in JSON with hex
/// fields, re-verifiable by any implementation without trusting this one.
fn record_evidence(
    view_dir: &std::path::Path,
    a: &[u8],
    b: &[u8],
) -> Result<Option<std::path::PathBuf>, String> {
    let path = evidence_path(view_dir, a, b);
    if path.exists() {
        return Ok(None);
    }
    let parent = path.parent().expect("evidence dir under view");
    std::fs::create_dir_all(parent).map_err(|e| format!("cannot create {parent:?}: {e}"))?;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let document = format!(
        "{{\"rule\": \"REPLICATION.md 6.1\", \"a\": \"{}\", \"b\": \"{}\"}}\n",
        hex(a),
        hex(b)
    );
    std::fs::write(&path, document).map_err(|e| format!("cannot write {path:?}: {e}"))?;
    Ok(Some(path))
}

fn cmd_import(argv: &[String]) -> i32 {
    let Some(bundle_path) = argv.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("vayu import needs a bundle file");
        return 2;
    };
    let flags = match Flags::parse(&argv[1..], &["view", "store", "now", "window-count"]) {
        Ok(flags) => flags,
        Err(detail) => {
            eprintln!("vayu import: {detail}");
            return 2;
        }
    };
    match (flags.get("view"), flags.get("store")) {
        (Some(_), Some(_)) => {
            eprintln!("vayu import: --view and --store fill different homes; give one");
            return 2;
        }
        (None, None) => {
            eprintln!("vayu import needs --view <dir> (records) or --store <dir> (blocks)");
            return 2;
        }
        _ => {}
    }
    let bytes = match std::fs::read(bundle_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("vayu import: cannot read {bundle_path:?}: {e}");
            return 2;
        }
    };
    let records = match vayuweb_client::record::decode_record(&bytes) {
        Ok(vayuweb_client::cbor::Value::Array(records)) => records,
        Ok(_) => {
            eprintln!("vayu import: a bundle is a CBOR array");
            return 2;
        }
        Err(e) => {
            eprintln!("vayu import: that is not a readable bundle: {e}");
            return 2;
        }
    };

    // Blocks mode: content-addressed payloads, each re-hashed before it is pinned.
    if flags.has("store") {
        return import_blocks(
            &records,
            std::path::Path::new(flags.get("store").expect("checked above")),
        );
    }

    let view_dir = flags.get("view").expect("checked above");
    let view = match vayuweb_client::view::View::open(std::path::Path::new(view_dir)) {
        Ok(view) => view,
        Err(detail) => {
            eprintln!("vayu import: {detail}");
            return 2;
        }
    };
    let now = match resolve_now(&flags, "import") {
        Ok(now) => now,
        Err(code) => return code,
    };
    let window_count = match flags.number("window-count") {
        Ok(value) => value.unwrap_or(0),
        Err(detail) => {
            eprintln!("vayu import: {detail}");
            return 2;
        }
    };

    let mut accepted = 0usize;
    let mut held = 0usize;
    let mut refused = 0usize;
    let mut deferred = 0usize;
    let mut evidence = 0usize;

    // A bundle can carry BOTH halves of a fork. Judge every pair before anything is
    // judged singly: two records at one seq by one owner are equivocation evidence no
    // matter what the verifier would later say about either half's validity, and the
    // pair deserves reporting even when both halves expire unaccepted.
    let raw_records: Vec<&vayuweb_client::cbor::Value> = records.iter().collect();
    for (index, a) in raw_records.iter().enumerate() {
        let vayuweb_client::cbor::Value::Bytes(a_bytes) = a else {
            continue;
        };
        for b in &raw_records[index + 1..] {
            let vayuweb_client::cbor::Value::Bytes(b_bytes) = b else {
                continue;
            };
            if vayuweb_client::verify::is_equivocation_evidence(a_bytes, b_bytes) {
                match record_evidence(std::path::Path::new(view_dir), a_bytes, b_bytes) {
                    Ok(Some(path)) => {
                        evidence += 1;
                        println!(
                            "EQUIVOCATION EVIDENCE: this bundle carries both halves of one \
                             owner's fork; saved {path:?}"
                        );
                    }
                    Ok(None) => {}
                    Err(e) => eprintln!("vayu import: could not record evidence: {e}"),
                }
            }
        }
    }

    for record in &records {
        let vayuweb_client::cbor::Value::Bytes(record_bytes) = record else {
            refused += 1;
            println!("REJECT BAD_RECORD: a bundle element must be a byte string");
            continue;
        };
        if view.holds(record_bytes) {
            held += 1;
            continue;
        }
        match view.accept_verdict(record_bytes, now, window_count) {
            Ok(vayuweb_client::verify::Verdict::Accept) => match view.put(record_bytes) {
                Ok(()) => accepted += 1,
                Err(e) => {
                    eprintln!("vayu import: the log refused a verified write: {e}");
                    return 1;
                }
            },
            Ok(verdict) => match verdict {
                vayuweb_client::verify::Verdict::Reject { code, detail } => {
                    refused += 1;
                    println!("REJECT {code}: {detail}");
                    // A refusal at a contested slot may be equivocation against
                    // something already held. Evidence survives the refusal either way.
                    let held_entries = view.entries().unwrap_or_default();
                    for entry in &held_entries {
                        if vayuweb_client::verify::is_equivocation_evidence(
                            &entry.bytes,
                            record_bytes,
                        ) {
                            match record_evidence(
                                std::path::Path::new(view_dir),
                                &entry.bytes,
                                record_bytes,
                            ) {
                                Ok(Some(path)) => {
                                    evidence += 1;
                                    println!(
                                        "EQUIVOCATION EVIDENCE: refused record conflicts with \
                                         held {} under one owner key; saved {path:?}",
                                        entry.hash_hex
                                    );
                                }
                                Ok(None) => {}
                                Err(e) => eprintln!("vayu import: could not record evidence: {e}"),
                            }
                        }
                    }
                }
                vayuweb_client::verify::Verdict::Defer { detail } => {
                    deferred += 1;
                    println!("DEFER: {detail}");
                }
                vayuweb_client::verify::Verdict::Accept => unreachable!(),
            },
            Err(detail) => {
                eprintln!("vayu import: {detail}");
                return 1;
            }
        }
    }
    println!(
        "\n{accepted} accepted · {held} already held · {refused} refused · {deferred} deferred \
         (view: {view_dir})"
    );
    if evidence > 0 {
        println!("{evidence} equivocation pair(s) recorded under {view_dir}/evidence/");
    }
    // Verdicts are data-dependent outcomes, not tool failures: an exchange SHOULD be able to
    // carry records this peer will refuse. Only broken input or IO is an exit 2/1.
    0
}

// ---------------------------------------------------------------------------
// vayu transfer / relinquish / revoke / renew — the owner's operations. One
// shape: resolve the predecessor from the view exactly as publish does, sign
// the op under that chain, judge it as received against the same view, and
// only then append. (renew EXTENDS the term by a year, proof of work
// included; publish's automatic UPDATE only re-points within the term.)
// ---------------------------------------------------------------------------

/// The incumbent rule every signing verb shares: a chain under YOUR key is the
/// predecessor (an UPDATE); a lapsed name registers anew; another key's name refuses.
/// An explicit `--prev` overrides. Lookup-only when the view does not exist yet, so a
/// first-ever operation materializes nothing before it earns it.
fn predecessor_from_view(
    flags: &Flags,
    store_path: &std::path::Path,
    label: &str,
    tld: &str,
    identity: &Identity,
    now: u64,
    verb: &str,
) -> Result<Option<Predecessor>, i32> {
    let view_dir = flags
        .get("view")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| store_path.join("view"));
    let existing = match std::fs::read_dir(&view_dir) {
        Ok(_) => match vayuweb_client::view::View::open(&view_dir) {
            Ok(view) => Some(view),
            Err(detail) => {
                eprintln!("vayu {verb}: {detail}");
                return Err(2);
            }
        },
        Err(_) => None,
    };
    match existing.map(|view| view.chain_tip(label, tld)) {
        Some(Ok(Some(tip))) => {
            if tip.prev.owner_key != *identity.public_key() {
                eprintln!(
                    "vayu {verb}: {label}.{tld} is already held in this view by another key; \
                     a name is not taken over by publishing at it"
                );
                return Err(1);
            }
            match vayuweb_client::verify::lifecycle_state(&tip.prev, now) {
                "FREE" => {
                    println!(
                        "note      {label}.{tld} lapsed back to the open pool; registering anew"
                    );
                    Ok(None)
                }
                _ => match Predecessor::from_bytes(&tip.entry.bytes) {
                    Ok(previous) => {
                        println!("renewal   seq {} -> {}", tip.prev.seq, tip.prev.seq + 1);
                        Ok(Some(previous))
                    }
                    Err(e) => {
                        eprintln!("vayu {verb}: unusable incumbent: {e}");
                        Err(1)
                    }
                },
            }
        }
        Some(Ok(None)) | None => Ok(None),
        Some(Err(detail)) => {
            eprintln!("vayu {verb}: {detail}");
            Err(2)
        }
    }
}

/// `vayu alias <label>.<tld> --to <other>.<tld>` — point a name at another name. The
/// record carries an alias ENTRY; resolution follows it within REGISTRY.md's budget.
fn cmd_alias(argv: &[String]) -> i32 {
    let mut positional = Vec::new();
    for arg in argv {
        if !arg.starts_with("--") {
            positional.push(arg.clone());
        }
    }
    let Some(name_value) = positional.first() else {
        eprintln!("vayu alias: needs <label>.<tld>");
        return 2;
    };
    let flag_args: &[String] = if argv.first().is_some_and(|a| !a.starts_with("--")) {
        &argv[1..]
    } else {
        argv
    };
    let flags = match Flags::parse(
        flag_args,
        &[
            "to",
            "store",
            "key-file",
            "now",
            "view",
            "window-count",
            "pow-limit",
        ],
    ) {
        Ok(flags) => flags,
        Err(detail) => {
            eprintln!("vayu alias: {detail}");
            return 2;
        }
    };
    let (label, tld) = match parse_name(name_value) {
        Ok(parts) => parts,
        Err(_) => {
            eprintln!("vayu alias: wants <label>.<tld>, got {name_value:?}");
            return 2;
        }
    };
    let Some(to_value) = flags.get("to") else {
        eprintln!("vayu alias: --to <label>.<tld> names the target");
        return 2;
    };
    let target = match parse_name(to_value)
        .and_then(|(l, t)| vayuweb_client::record::alias(&l, &t).map_err(|e| e.to_string()))
    {
        Ok(target) => target,
        Err(detail) => {
            eprintln!("vayu alias: --to {to_value:?} is not a name that can be aliased: {detail}");
            return 2;
        }
    };

    let store_path = std::path::PathBuf::from(flags.get("store").unwrap_or("vayu-store"));
    let Some(key_file) = flags.get("key-file") else {
        eprintln!("vayu alias needs --key-file <file>");
        return 2;
    };
    let identity = match read_seed_file(key_file) {
        Ok(identity) => identity,
        Err(code) => return code,
    };
    let now = match resolve_now(&flags, "alias") {
        Ok(now) => now,
        Err(code) => return code,
    };
    let window_count = match flags.number("window-count") {
        Ok(value) => value.unwrap_or(0),
        Err(detail) => {
            eprintln!("vayu alias: {detail}");
            return 2;
        }
    };
    let pow_limit = match flags.number("pow-limit") {
        Ok(value) => value.unwrap_or(10_000_000),
        Err(detail) => {
            eprintln!("vayu alias: {detail}");
            return 2;
        }
    };

    let predecessor =
        match predecessor_from_view(&flags, &store_path, &label, &tld, &identity, now, "alias") {
            Ok(predecessor) => predecessor,
            Err(code) => return code,
        };

    // The whole point of this verb: an entries list whose single entry redirects.
    let entry = vayuweb_client::record::Entry {
        value: vayuweb_client::record::EntryValue::Alias(target.clone()),
        ttl: None,
    };
    let built = match predecessor.as_ref() {
        None => vayuweb_client::record::build_register(
            &identity,
            &label,
            &tld,
            now,
            &[entry],
            window_count,
            None,
            pow_limit,
        ),
        Some(previous) => {
            vayuweb_client::record::build_update(&identity, previous, &label, &tld, now, &[entry])
        }
    };
    let record = match built {
        Ok(record) => record,
        Err(e) => {
            eprintln!("vayu alias: refused: {e}");
            return 1;
        }
    };

    let view_dir = flags
        .get("view")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| store_path.join("view"));
    let view = match vayuweb_client::view::View::open(&view_dir) {
        Ok(view) => view,
        Err(detail) => {
            eprintln!("vayu alias: {detail}");
            return 2;
        }
    };
    match view.accept_verdict(&record, now, window_count) {
        Ok(vayuweb_client::verify::Verdict::Accept) => {}
        Ok(other) => {
            eprintln!("vayu alias: the view refuses this record: {other:?}");
            return 1;
        }
        Err(detail) => {
            eprintln!("vayu alias: {detail}");
            return 2;
        }
    }
    if let Err(e) = view.put(&record) {
        eprintln!("vayu alias: {e}");
        return 1;
    }
    println!(
        "alias     {}.{} -> {}.{} appended",
        label, tld, target.label, target.tld
    );
    0
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OwnerOp {
    Transfer,
    Relinquish,
    Revoke,
    Renew,
}

impl OwnerOp {
    fn verb(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Relinquish => "relinquish",
            Self::Revoke => "revoke",
            Self::Renew => "renew",
        }
    }
}

fn cmd_owner_exit(argv: &[String], op: OwnerOp) -> i32 {
    let mut positional = Vec::new();
    for arg in argv {
        if !arg.starts_with("--") {
            positional.push(arg.clone());
        }
    }
    let Some(name_value) = positional.first() else {
        eprintln!("vayu {}: needs <label>.<tld>", op.verb());
        return 2;
    };
    // Flags::parse knows no positionals; the name was argv's head.
    let flag_args: &[String] = if argv.first().is_some_and(|a| !a.starts_with("--")) {
        &argv[1..]
    } else {
        argv
    };
    let (label, tld) = match parse_name(name_value) {
        Ok(parts) => parts,
        Err(_) => {
            eprintln!(
                "vayu {}: --name wants <label>.<tld>, got {name_value:?}",
                op.verb()
            );
            return 2;
        }
    };
    let flags = match Flags::parse(
        flag_args,
        &["store", "key-file", "recipient-seed", "now", "view"],
    ) {
        Ok(flags) => flags,
        Err(detail) => {
            eprintln!("vayu {}: {detail}", op.verb());
            return 2;
        }
    };
    if op == OwnerOp::Transfer && !flags.has("recipient-seed") {
        eprintln!("vayu transfer: a transfer carries TWO signatures; give --recipient-seed");
        return 2;
    }

    let store_path = std::path::PathBuf::from(flags.get("store").unwrap_or("vayu-store"));
    let view_dir = flags
        .get("view")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| store_path.join("view"));

    // The identity doing the leaving.
    let Some(key_file) = flags.get("key-file") else {
        eprintln!("vayu {} needs --key-file <file>", op.verb());
        return 2;
    };
    let identity = match read_seed_file(key_file) {
        Ok(identity) => identity,
        Err(code) => return code,
    };

    let now = match resolve_now(&flags, op.verb()) {
        Ok(now) => now,
        Err(code) => return code,
    };

    // Predecessor from the view, owner must be us — identical rule to publish.
    let existing = match std::fs::read_dir(&view_dir) {
        Ok(_) => match vayuweb_client::view::View::open(&view_dir) {
            Ok(view) => Some(view),
            Err(detail) => {
                eprintln!("vayu {}: {detail}", op.verb());
                return 2;
            }
        },
        Err(_) => {
            eprintln!(
                "vayu {}: no history at {:?}: nothing to leave",
                op.verb(),
                view_dir
            );
            return 1;
        }
    };
    let view = match existing {
        Some(view) => view,
        None => return 1,
    };
    let tip = match view.chain_tip(&label, &tld) {
        Ok(Some(tip)) => tip,
        Ok(None) => {
            eprintln!(
                "vayu {}: no accepted record for {label}.{tld} in {:?}",
                op.verb(),
                view_dir
            );
            return 1;
        }
        Err(detail) => {
            eprintln!("vayu {}: {detail}", op.verb());
            return 2;
        }
    };
    if tip.prev.owner_key != *identity.public_key() {
        eprintln!(
            "vayu {}: {label}.{tld} is held in this view by another key",
            op.verb()
        );
        return 1;
    }
    let predecessor = match Predecessor::from_bytes(&tip.entry.bytes) {
        Ok(previous) => previous,
        Err(e) => {
            eprintln!("vayu {}: unusable incumbent: {e}", op.verb());
            return 1;
        }
    };

    // Build the op's record under that chain.
    let built = match op {
        OwnerOp::Transfer => {
            let Some(recipient_file) = flags.get("recipient-seed") else {
                unreachable!("checked above");
            };
            let recipient = match read_seed_file(recipient_file) {
                Ok(identity) => identity,
                Err(code) => return code,
            };
            vayuweb_client::record::build_transfer(
                &identity,
                &recipient,
                &predecessor,
                &label,
                &tld,
                now,
            )
        }
        OwnerOp::Relinquish => {
            vayuweb_client::record::build_relinquish(&identity, &predecessor, &label, &tld, now)
        }
        OwnerOp::Revoke => {
            vayuweb_client::record::build_revoke(&identity, &predecessor, &label, &tld, now)
        }
        OwnerOp::Renew => {
            let window_count = match flags.number("window-count") {
                Ok(value) => value.unwrap_or(0),
                Err(detail) => {
                    eprintln!("vayu renew: {detail}");
                    return 2;
                }
            };
            let pow_limit = match flags.number("pow-limit") {
                Ok(value) => value.unwrap_or(10_000_000),
                Err(detail) => {
                    eprintln!("vayu renew: {detail}");
                    return 2;
                }
            };
            vayuweb_client::record::build_renew(
                &identity,
                &predecessor,
                &label,
                &tld,
                now,
                window_count,
                pow_limit,
            )
        }
    };
    let record = match built {
        Ok(record) => record,
        Err(e) => {
            eprintln!("vayu {}: refused: {e}", op.verb());
            return 1;
        }
    };

    // Judge it as received against the same view, then append on Accept. An owner op that
    // cannot re-verify against its own history is a bug in the history, not a warning.
    let window_count_for_verdict = if op == OwnerOp::Renew {
        flags.number("window-count").ok().flatten().unwrap_or(0)
    } else {
        0
    };
    match view.accept_verdict(&record, now, window_count_for_verdict) {
        Ok(vayuweb_client::verify::Verdict::Accept) => {}
        Ok(other) => {
            eprintln!(
                "vayu {}: the view refuses this record: {other:?}",
                op.verb()
            );
            return 1;
        }
        Err(detail) => {
            eprintln!("vayu {}: {detail}", op.verb());
            return 2;
        }
    }
    if let Err(e) = view.put(&record) {
        eprintln!("vayu {}: {e}", op.verb());
        return 1;
    }
    println!(
        "{}    seq {} appended ({label}.{tld})",
        op.verb(),
        tip.prev.seq + 1
    );
    0
}

/// Blocks mode: every element must be [cidBytes, payload]; the payload must hash back to
/// the digest inside its own CID before it is pinned — content addressing is the integrity
/// check that travels with the bytes, so a flipped bit anywhere refuses that one block and
/// nothing else.
fn import_blocks(records: &[vayuweb_client::cbor::Value], store_dir: &std::path::Path) -> i32 {
    let store = match vayuweb_client::store::BlockStore::open(store_dir) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("vayu import: {e}");
            return 2;
        }
    };
    let mut accepted = 0usize;
    let mut held = 0usize;
    let mut refused = 0usize;
    for element in records {
        let vayuweb_client::cbor::Value::Array(pair) = element else {
            refused += 1;
            println!("REJECT BAD_BLOCK: an element must be [cid, bytes]");
            continue;
        };
        let [vayuweb_client::cbor::Value::Bytes(cid_bytes), vayuweb_client::cbor::Value::Bytes(payload)] =
            pair.as_slice()
        else {
            refused += 1;
            println!("REJECT BAD_BLOCK: an element must be two byte strings");
            continue;
        };
        let cid = match Cid::from_bytes(cid_bytes) {
            Ok(cid) => cid,
            Err(e) => {
                refused += 1;
                println!("REJECT BAD_CID: {e}");
                continue;
            }
        };
        if store_dir.join(cid.to_text()).exists() {
            held += 1;
            continue;
        }
        if cid.digest != vayuweb_client::cid::sha256(payload) {
            refused += 1;
            println!(
                "REJECT BAD_DIGEST: {} does not match its own address",
                cid.to_text()
            );
            continue;
        }
        if let Err(e) = store.put_all(std::iter::once((cid, payload.clone()))) {
            eprintln!("vayu import: the store refused a verified write: {e}");
            return 1;
        }
        accepted += 1;
    }
    println!(
        "\n{accepted} accepted · {held} already held · {refused} refused (store: {})",
        store_dir.display()
    );
    // Same policy as records: a corrupt block in a bundle is DATA the peer refuses, not a
    // tool failure; the rest of the bundle still lands.
    0
}

/// One place for the ACCEPT/REJECT/DEFER text and its exit code.
fn print_verdict(verdict: &vayuweb_client::verify::Verdict) -> i32 {
    match verdict {
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
            println!(
                "the record is neither good nor bad yet: hold it and retry when the clock catches up."
            );
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
    let flags = match Flags::parse(
        &argv[1..],
        &["root", "port", "name", "view", "now", "window-count"],
    ) {
        Ok(flags) => flags,
        Err(detail) => {
            eprintln!("vayu serve: {detail}");
            return 2;
        }
    };
    if flags.has("name") && flags.has("root") {
        eprintln!("vayu serve: --name and --root are alternatives, not companions");
        return 2;
    }
    let root = match (flags.get("root"), flags.get("name")) {
        (Some(root_text), None) => match Cid::from_text(root_text) {
            Ok(root) => root,
            Err(_) => {
                eprintln!("vayu serve: {root_text:?} is not a CID this protocol admits");
                return 2;
            }
        },
        (None, Some(name_value)) => {
            let (label, tld) = match parse_name(name_value) {
                Ok(parts) => parts,
                Err(_) => {
                    eprintln!("vayu serve: --name wants <label>.<tld>, got {name_value:?}");
                    return 2;
                }
            };
            let now = match resolve_now(&flags, "serve") {
                Ok(now) => now,
                Err(code) => return code,
            };
            let window_count = match flags.number("window-count") {
                Ok(value) => value.unwrap_or(0),
                Err(detail) => {
                    eprintln!("vayu serve: {detail}");
                    return 2;
                }
            };
            let view_dir = flags
                .get("view")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from(store_dir).join("view"));
            match resolve_name_root(&view_dir, &label, &tld, now, window_count) {
                Ok(root) => {
                    println!(
                        "pointer   {}.{} -> {}\njudged against {}",
                        label,
                        tld,
                        root.to_text(),
                        view_dir.display()
                    );
                    root
                }
                Err(detail) => {
                    eprintln!("vayu serve: refusing to serve by name: {detail}");
                    return 1;
                }
            }
        }
        (None, None) => {
            eprintln!("vayu serve: give either --root <cid> or --name <label>.<tld>");
            return 2;
        }
        (Some(_), Some(_)) => unreachable!(),
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
    // Best-effort announcements: a preview server must not DIE because whoever
    // launched it closed the pipe its stdout was writing to (a harness that stops
    // reading after the URL line, a supervisor rotating logs). Rust's println!
    // panics on a broken pipe; serve's chatter never gets to be lethal.
    let say = |text: &str| {
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(text.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    };
    say(&format!(
        "serving   http://{}/\nroot      {}\nstop with Ctrl-C",
        handle.addr, root_text_owned
    ));
    // The default SIGINT/console-ctrl behaviour ends the process, which closes the socket:
    // exactly what a preview server should do. No signal machinery beyond that.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

/// The verifier clock: `--now` if given, else the system clock.
fn resolve_now(flags: &Flags, verb: &str) -> Result<u64, i32> {
    match flags.number("now") {
        Ok(Some(now)) => Ok(now),
        Ok(None) => Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default()),
        Err(detail) => {
            eprintln!("vayu {verb}: {detail}");
            Err(2)
        }
    }
}

/// Name-based reading, RESOLUTION.md's steps 1-7 against a LOCAL view:
/// name -> current accepted record (replay) -> re-judged as received ->
/// live at this instant -> its entry -> and if that entry ALIASES another
/// name, restart at the target with a budget of three hops (REGISTRY.md),
/// refusing a cycle with ALIAS_LOOP.
///
/// Every gate refuses CLOSED: a pointer that does not verify, a lapsed term,
/// a missing history, or a loop never yields a root.
fn resolve_name_root(
    view_dir: &std::path::Path,
    label: &str,
    tld: &str,
    now: u64,
    window_count: u64,
) -> Result<Cid, String> {
    let view = vayuweb_client::view::View::open(view_dir)?;
    let mut current = (label.to_string(), tld.to_string());
    let mut visited: Vec<(String, String)> = Vec::new();
    let mut hops = 0u32;
    loop {
        let (cur_label, cur_tld) = (&current.0, &current.1);
        let tip = view
            .chain_tip(cur_label, cur_tld)?
            .ok_or_else(|| format!("no accepted record for {cur_label}.{cur_tld}"))?;

        // Re-judge the incumbent's exact bytes before trusting where they point: successor
        // checks against the chain BELOW it, signature and discipline against nothing but
        // the bytes themselves — a tampered held file refuses here.
        match view.judge_held_tip(cur_label, cur_tld, now, window_count)? {
            vayuweb_client::verify::Verdict::Accept => {}
            other => {
                return Err(format!(
                    "the record attesting {cur_label}.{cur_tld} does not verify against this \
                     view: {other:?}"
                ))
            }
        }
        let state = vayuweb_client::verify::lifecycle_state(&tip.prev, now);
        if state != "LIVE" {
            return Err(format!(
                "{cur_label}.{cur_tld} is not LIVE ({state}); only a live name resolves"
            ));
        }

        match view.resolved_pointer(cur_label, cur_tld)? {
            vayuweb_client::view::Pointer::Cid(cid) => return Ok(cid),
            vayuweb_client::view::Pointer::Alias(target) => {
                hops += 1;
                if hops > 3 {
                    // RESOLUTION.md: at most three hops per original request; deeper is a
                    // refusal, not a longer walk.
                    return Err(format!(
                        "ALIAS_LOOP: {label}.{tld}'s alias chain runs deeper than three hops"
                    ));
                }
                let next = (target.label.clone(), target.tld.clone());
                if next == (label.to_string(), tld.to_string()) || visited.contains(&next) {
                    return Err(format!(
                        "ALIAS_LOOP: {cur_label}.{cur_tld} points back along its own chain"
                    ));
                }
                visited.push(current);
                current = next;
            }
        }
    }
}

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

/// Read a hex seed file into an identity — the one key-loading path every verb shares.
/// Errors are already rendered; the code is 2 (usage).
fn read_seed_file(path: &str) -> Result<Identity, i32> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("vayu: cannot read key file {path:?}: {e}");
            return Err(2);
        }
    };
    match hex_decode(&text) {
        Ok(seed) if seed.len() == 32 => match Identity::from_seed(&mut seed.clone()) {
            Ok(identity) => Ok(identity),
            Err(e) => {
                eprintln!("vayu: the seed did not yield an identity: {e}");
                Err(2)
            }
        },
        Ok(seed) => {
            eprintln!(
                "vayu: the seed must be exactly 32 bytes (64 hex chars), got {}",
                seed.len()
            );
            Err(2)
        }
        Err(e) => {
            eprintln!("vayu: key file {path:?}: {e}");
            Err(2)
        }
    }
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
            "view",
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
        Some(path) => match read_seed_file(path) {
            Ok(identity) => identity,
            Err(code) => return code,
        },
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

    // Renewal, automatic: the view this publish appends to is also the history it renews
    // FROM (see predecessor_from_view for the incumbent's rule). An explicit --prev wins.
    let predecessor = if predecessor.is_none() {
        match predecessor_from_view(&flags, &store_path, &label, &tld, &identity, now, "publish") {
            Ok(predecessor) => predecessor,
            Err(code) => return code,
        }
    } else {
        predecessor
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

    // Step 6: hold your own history. The record this command just signed is appended to the
    // local registry view — the same log a stranger's record would be judged against later.
    // A refusal here does NOT undo the publish (the tree is pinned, the signature exists);
    // it is surfaced loudly instead, because serving by name will refuse until it is fixed.
    let view_dir = flags
        .get("view")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| store_path.join("view"));
    match vayuweb_client::view::View::open(&view_dir) {
        Ok(view) => match view.accept_verdict(&published.record, now, window_count) {
            Ok(vayuweb_client::verify::Verdict::Accept) => match view.put(&published.record) {
                Ok(()) => println!("history  {} appended", view_dir.display()),
                Err(e) => eprintln!("warning: the view refused the write: {e}"),
            },
            Ok(verdict) => eprintln!(
                "warning: signed and pinned, but your own view would not hold this record \
                 ({verdict:?}); resolve before relying on serve --name"
            ),
            Err(e) => eprintln!("warning: could not judge against the view: {e}"),
        },
        Err(e) => eprintln!("warning: could not open the registry view: {e}"),
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
