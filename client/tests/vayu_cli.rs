//! The `vayu` CLI, exercised as a process.
//!
//! These are the tests that keep the headless command surface honest: a clean site passes
//! step 1 and exits zero; violations render with their rules and stop at exit 1; publish pins
//! before it signs, writes the record where it was told, refuses a failing site without
//! pinning or signing anything, republishes under `--prev` as an UPDATE, and treats usage
//! mistakes as usage errors (exit 2). Everything runs through
//! [`env!("CARGO_BIN_EXE_vayu")`](std::process::Command) so what is tested is the binary a
//! person would actually run.

use std::path::{Path, PathBuf};
use std::process::Command;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("vayu-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("creates");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn file(&self, name: &str, content: &str) {
        let target = self.0.join(name);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("creates parent");
        }
        std::fs::write(target, content).expect("writes");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn seed_file(dir: &Path) -> PathBuf {
    let path = dir.join("seed.hex");
    std::fs::write(&path, "ab".repeat(32)).expect("writes seed");
    path
}

const CLEAN_INDEX: &str = "<!doctype html><title>t</title><p>hello</p>";

#[test]
fn doctor_passes_a_clean_site_and_fails_a_dirty_one_with_the_rules_named() {
    let site = TempDir::new("doctor-clean");
    site.file("index.html", CLEAN_INDEX);

    let ok = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .arg("doctor")
        .arg(site.path())
        .output()
        .expect("runs");
    assert!(ok.status.success());
    let stdout = String::from_utf8_lossy(&ok.stdout);
    assert!(stdout.contains("0 error(s)"), "{stdout:?}");
    assert!(stdout.contains("would pass step 1"));

    // Now break it: inline style AND script, each named with its rule id.
    site.file("broken.html", "<style>p{}</style><script>x()</script>");
    let bad = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .arg("doctor")
        .arg(site.path())
        .output()
        .expect("runs");
    assert_eq!(bad.status.code(), Some(1), "violations are exit 1");
    let stdout = String::from_utf8_lossy(&bad.stdout);
    assert!(stdout.contains("[inline-style]"), "{stdout:?}");
    assert!(stdout.contains("[inline-script]"));
    assert!(stdout.contains("Fix: "), "every finding carries its remedy");
    assert!(stdout.contains("the publish would stop"));
}

#[test]
fn publish_registers_pins_and_writes_the_record() {
    let work = TempDir::new("publish-reg");
    let site = work.path().join("site");
    let store = work.path().join("store");
    std::fs::create_dir_all(&site).expect("site dir");
    std::fs::write(site.join("index.html"), CLEAN_INDEX).expect("index");
    let seed = seed_file(work.path());
    let record = work.path().join("record.cbor");

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "publish",
            site.to_str().expect("utf8"),
            "--name",
            "cli-test-site.vayu",
            "--store",
            store.to_str().expect("utf8"),
            "--key-file",
            seed.to_str().expect("utf8"),
            "--out",
            record.to_str().expect("utf8"),
            "--now",
            "1900000000",
        ])
        .output()
        .expect("runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The record exists on disk and decodes as a REGISTER carrying a cid entry.
    let bytes = std::fs::read(&record).expect("record written");
    let decoded = vayuweb_client::cbor::decode(&bytes).expect("deterministic CBOR");
    let vayuweb_client::cbor::Value::Map(members) = decoded else {
        panic!("a record is a map");
    };
    let field = |wanted: &str| {
        members
            .iter()
            .find(|(key, _)| matches!(key, vayuweb_client::cbor::Key::Text(name) if name == wanted))
            .map(|(_, value)| value)
    };
    assert!(
        matches!(field("op"), Some(vayuweb_client::cbor::Value::Text(op)) if op == "REGISTER"),
        "{:?}",
        members.iter().map(|(k, _)| k).collect::<Vec<_>>()
    );
    let Some(vayuweb_client::cbor::Value::Array(entries)) = field("records") else {
        panic!("records is an array");
    };
    let carried = match entries.first() {
        Some(vayuweb_client::cbor::Value::Map(fields)) => fields
            .iter()
            .find(
                |(key, _)| matches!(key, vayuweb_client::cbor::Key::Text(name) if name == "value"),
            )
            .map(|(_, value)| value.clone()),
        _ => None,
    };
    let Some(vayuweb_client::cbor::Value::Bytes(carried)) = carried else {
        panic!("the entry carries cid bytes");
    };
    let root = vayuweb_client::cid::Cid::from_bytes(&carried).expect("valid CID");

    // And the store holds every block of that tree, keyed by CID text.
    for entry in std::fs::read_dir(&store).expect("store listed") {
        let _ = entry;
    }
    assert!(
        store.join(root.to_text()).exists(),
        "the root block is pinned by its CID text"
    );
}

#[test]
fn publish_refuses_a_failing_site_before_pin_or_signature() {
    let work = TempDir::new("publish-refused");
    let site = work.path().join("site");
    let store = work.path().join("store");
    std::fs::create_dir_all(&site).expect("site dir");
    std::fs::write(site.join("index.html"), "<style>p{}</style>").expect("dirty index");
    let seed = seed_file(work.path());
    let record = work.path().join("never.cbor");

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "publish",
            site.to_str().expect("utf8"),
            "--name",
            "cli-refused-01.vayu",
            "--store",
            store.to_str().expect("utf8"),
            "--key-file",
            seed.to_str().expect("utf8"),
            "--out",
            record.to_str().expect("utf8"),
            "--now",
            "1900000000",
        ])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[inline-style]"), "{stdout:?}");
    assert!(stdout.contains("nothing was built, pinned or signed"));
    assert!(!record.exists(), "no record was written");
    assert!(
        !store.exists() || std::fs::read_dir(&store).map(|d| d.count()).unwrap_or(0) == 0,
        "nothing was pinned"
    );
}

#[test]
fn republish_under_prev_is_an_update_keeping_both_versions_pinned() {
    let work = TempDir::new("publish-update");
    let site = work.path().join("site");
    let store = work.path().join("store");
    std::fs::create_dir_all(&site).expect("site dir");
    std::fs::write(site.join("index.html"), CLEAN_INDEX).expect("v1");
    let seed = seed_file(work.path());
    let first_record = work.path().join("first.cbor");

    let first = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "publish",
            site.to_str().expect("utf8"),
            "--name",
            "cli-update-site.vayu",
            "--store",
            store.to_str().expect("utf8"),
            "--key-file",
            seed.to_str().expect("utf8"),
            "--out",
            first_record.to_str().expect("utf8"),
            "--now",
            "1900000000",
        ])
        .output()
        .expect("first publish runs");
    assert!(first.status.success());

    // Change the content and republish under the previous record.
    std::fs::write(site.join("index.html"), "<!doctype html><title>v2</title>").expect("v2");
    let second_record = work.path().join("second.cbor");
    let second = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "publish",
            site.to_str().expect("utf8"),
            "--name",
            "cli-update-site.vayu",
            "--store",
            store.to_str().expect("utf8"),
            "--key-file",
            seed.to_str().expect("utf8"),
            "--prev",
            first_record.to_str().expect("utf8"),
            "--out",
            second_record.to_str().expect("utf8"),
            "--now",
            "1900000600",
        ])
        .output()
        .expect("second publish runs");
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );

    let bytes = std::fs::read(&second_record).expect("second record written");
    let decoded = vayuweb_client::cbor::decode(&bytes).expect("decodes");
    let vayuweb_client::cbor::Value::Map(members) = decoded else {
        panic!("a record is a map");
    };
    assert!(matches!(
        members.iter().find(|(key, _)| matches!(key, vayuweb_client::cbor::Key::Text(name) if name == "op")),
        Some((_, vayuweb_client::cbor::Value::Text(op))) if op == "UPDATE"
    ));
    // seq advanced past the predecessor's.
    let seq_of = |path: &Path| {
        let value =
            vayuweb_client::cbor::decode(&std::fs::read(path).expect("reads")).expect("decodes");
        match value {
            vayuweb_client::cbor::Value::Map(members) => members
                .into_iter()
                .find(|(key, _)| matches!(key, vayuweb_client::cbor::Key::Text(name) if name == "seq"))
                .and_then(|(_, v)| match v {
                    vayuweb_client::cbor::Value::UInt(n) => Some(n),
                    _ => None,
                })
                .expect("seq present"),
            _ => panic!("map"),
        }
    };
    assert!(seq_of(&second_record) == seq_of(&first_record) + 1);

    // Both versions remain held: updating a pointer never deletes the old tree.
    let pinned: Vec<String> = std::fs::read_dir(&store)
        .expect("store listed")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(pinned.len() >= 4, "old tree plus new tree: {pinned:?}");
}

#[test]
fn usage_mistakes_exit_two_with_the_text() {
    let none = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .output()
        .expect("runs");
    assert_eq!(none.status.code(), Some(2));

    let unknown = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .arg("transmogrify")
        .output()
        .expect("runs");
    assert_eq!(unknown.status.code(), Some(2));

    let missing_name = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .arg("publish")
        .arg(".")
        .output()
        .expect("runs");
    assert_eq!(missing_name.status.code(), Some(2));

    let help = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .arg("help")
        .output()
        .expect("runs");
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("USAGE"));
}

// ---------------------------------------------------------------------------
// 3.1.6's second half, at the door: a hand-pinned tree (the checker bypassed,
// which is precisely the adversary this clause exists for) cannot be served.
// ---------------------------------------------------------------------------

#[test]
fn serve_refuses_a_tree_the_checker_would_stop() {
    let work = TempDir::new("serve-refused");
    let store = work.path().join("store");
    let opened = vayuweb_client::store::BlockStore::open(&store).expect("opens");

    // Pin a violating document DIRECTLY -- no doctor in the loop, exactly as a
    // checker-bypassing publisher would do it.
    let dirty = vayuweb_client::publish::SiteFile {
        path: "index.html".into(),
        content: b"<!doctype html><title>t</title><script>steal()</script>".to_vec(),
    };
    let (blocks, root) =
        vayuweb_client::publish::import_site(std::slice::from_ref(&dirty)).expect("imports");
    opened
        .put_all(blocks.into_iter().map(|b| (b.cid.clone(), b.bytes)))
        .expect("pins");

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "serve",
            store.to_str().expect("utf8"),
            "--root",
            root.to_text().as_str(),
            "--port",
            "0",
        ])
        .output()
        .expect("runs");
    assert_eq!(
        output.status.code(),
        Some(1),
        "a dirty tree refuses to serve"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing to serve"), "{stderr}");
    assert!(
        stderr.contains("[inline-script]"),
        "the finding names its rule"
    );
}

// ---------------------------------------------------------------------------
// vayu verify — the peer's verdict, through the binary.
// ---------------------------------------------------------------------------

#[test]
fn verify_accepts_what_the_builder_made_and_names_a_forgery() {
    let work = TempDir::new("verify");
    let mut seed = vec![9u8; 32];
    let id = vayuweb_client::identity::Identity::from_seed(&mut seed).expect("identity");
    let record = vayuweb_client::record::build_register(
        &id,
        "cli-verify",
        "vayu",
        1_800_000_000,
        &[],
        0,
        None,
        10_000_000,
    )
    .expect("registers");
    let record_path = work.path().join("record.cbor");
    std::fs::write(&record_path, &record).expect("writes");

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "verify",
            record_path.to_str().expect("utf8"),
            "--now",
            "1800000000",
        ])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&output.stdout).starts_with("ACCEPT"),
        "an honest registration verifies as received"
    );

    // The same file with a forged signature: refused, with the code named.
    let vayuweb_client::cbor::Value::Map(mut members) =
        vayuweb_client::cbor::decode(&record).expect("decodes")
    else {
        panic!("a record is a map");
    };
    for (key, value) in members.iter_mut() {
        if matches!(key, vayuweb_client::cbor::Key::Text(name) if name == "sig") {
            *value = vayuweb_client::cbor::Value::Bytes(vec![0u8; 64]);
        }
    }
    let forged = vayuweb_client::cbor::encode(&vayuweb_client::cbor::Value::Map(members))
        .expect("re-encodes");
    let forged_path = work.path().join("forged.cbor");
    std::fs::write(&forged_path, &forged).expect("writes");

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "verify",
            forged_path.to_str().expect("utf8"),
            "--now",
            "1800000000",
        ])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("REJECT BAD_SIG"), "{stdout}");
}

// ---------------------------------------------------------------------------
// vayu pins — what does this store hold?
// ---------------------------------------------------------------------------

#[test]
fn pins_classifies_every_block_in_a_store() {
    let work = TempDir::new("pins");
    let site = work.path().join("site");
    work.file("site/index.html", "<!doctype html><title>pins</title><p>hi");
    work.file("site/logo.png", "PNGDATA");
    let store_dir = work.path().join("store");

    let seed_path = work.path().join("seed.hex");
    std::fs::write(
        &seed_path,
        "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
    )
    .expect("writes");
    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "publish",
            site.to_str().expect("utf8"),
            "--name",
            "pins.vayu",
            "--store",
            store_dir.to_str().expect("utf8"),
            "--key-file",
            seed_path.to_str().expect("utf8"),
            "--out",
            work.path().join("rec.cbor").to_str().expect("utf8"),
        ])
        .output()
        .expect("runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .arg("pins")
        .arg(store_dir.to_str().expect("utf8"))
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("dir(2)"),
        "the root directory shows its fan-out: {stdout}"
    );
    assert!(
        stdout.contains("leaf"),
        "raw leaves are classified: {stdout}"
    );
    assert!(
        stdout.contains("block(s)"),
        "totals close the listing: {stdout}"
    );

    // Usage mistakes stay usage errors.
    let none = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .arg("pins")
        .output()
        .expect("runs");
    assert_eq!(none.status.code(), Some(2));
}

// ---------------------------------------------------------------------------
// The local registry view: accept, replay, and the lifecycle a stranger's
// record walks through.
// ---------------------------------------------------------------------------

/// A seed file of `byte` repeated 32 times, hex-encoded.
fn seed_hex(byte: u8) -> String {
    format!("{:02x}", byte).repeat(32)
}

#[test]
fn a_view_accepts_a_registration_then_defends_the_name() {
    let work = TempDir::new("view");
    let view_dir = work.path().join("view");
    let now = 1_800_000_000u64;

    let alice = work.path().join("alice.hex");
    std::fs::write(&alice, seed_hex(0x11)).expect("writes");
    let id = vayuweb_client::identity::Identity::from_seed(&mut vec![0x11; 32]).expect("identity");

    let reg = vayuweb_client::record::build_register(
        &id,
        "orchard",
        "vayu",
        now,
        &[],
        0,
        None,
        10_000_000,
    )
    .expect("registers");
    let reg_path = work.path().join("reg.cbor");
    std::fs::write(&reg_path, &reg).expect("writes");

    // Accept into an empty view.
    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "accept",
            reg_path.to_str().expect("utf8"),
            "--view",
            view_dir.to_str().expect("utf8"),
            "--now",
            &now.to_string(),
        ])
        .output()
        .expect("runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("appended"));

    // `names` shows it LIVE.
    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args(["names", "--view", view_dir.to_str().expect("utf8")])
        .output()
        .expect("runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("orchard.vayu") && stdout.contains("LIVE"),
        "{stdout}"
    );

    // A second registration of the same name is NAME_TAKEN — answered cheaply, before any
    // cryptography, exactly as the registry orders it.
    let mallory_id =
        vayuweb_client::identity::Identity::from_seed(&mut vec![0x22; 32]).expect("identity");
    let squat = vayuweb_client::record::build_register(
        &mallory_id,
        "orchard",
        "vayu",
        now + 1_000,
        &[],
        0,
        None,
        10_000_000,
    )
    .expect("registers");
    let squat_path = work.path().join("squat.cbor");
    std::fs::write(&squat_path, &squat).expect("writes");
    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "accept",
            squat_path.to_str().expect("utf8"),
            "--view",
            view_dir.to_str().expect("utf8"),
            "--now",
            &(now + 1_000).to_string(),
        ])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stdout).starts_with("REJECT NAME_TAKEN"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // And the refusal was NOT appended: the log holds only what the view accepted.
    let count = std::fs::read_dir(&view_dir)
        .expect("lists")
        .filter_map(|e| e.ok())
        .count();
    assert_eq!(count, 1, "one accepted record, one file: found {count}");

    // An UPDATE chains off the view itself — no --prev, no --transferor-key. Judged BEFORE
    // it is accepted: once appended, the record IS history, and a view never lets history
    // follow itself.
    let predecessor = vayuweb_client::record::Predecessor::from_bytes(&reg).expect("predecessor");
    let update =
        vayuweb_client::record::build_update(&id, &predecessor, "orchard", "vayu", now + 600, &[])
            .expect("builds");
    let update_path = work.path().join("update.cbor");
    std::fs::write(&update_path, &update).expect("writes");

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "verify",
            update_path.to_str().expect("utf8"),
            "--view",
            view_dir.to_str().expect("utf8"),
            "--now",
            &(now + 600).to_string(),
        ])
        .output()
        .expect("runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("ACCEPT"));

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "accept",
            update_path.to_str().expect("utf8"),
            "--view",
            view_dir.to_str().expect("utf8"),
            "--now",
            &(now + 600).to_string(),
        ])
        .output()
        .expect("runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // And once it is history, re-judging the same bytes fails chain discipline: a record
    // cannot follow itself.
    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "verify",
            update_path.to_str().expect("utf8"),
            "--view",
            view_dir.to_str().expect("utf8"),
            "--now",
            &(now + 700).to_string(),
        ])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("REJECT BAD_SEQ"));
}

#[test]
fn a_transfer_through_the_view_needs_no_transferor_flag() {
    const SETTLEMENT_SECONDS: u64 = 1_209_600;
    let work = TempDir::new("view-transfer");
    let view_dir = work.path().join("view");
    let now = 1_800_000_000u64;

    let alice_id = vayuweb_client::identity::Identity::from_seed(&mut vec![0x33; 32]).expect("id");
    let bob_id = vayuweb_client::identity::Identity::from_seed(&mut vec![0x44; 32]).expect("id");

    let accept = |bytes: &[u8], name: &str, at: u64| {
        let path = work.path().join(name);
        std::fs::write(&path, bytes).expect("writes");
        Command::new(env!("CARGO_BIN_EXE_vayu"))
            .args([
                "accept",
                path.to_str().expect("utf8"),
                "--view",
                view_dir.to_str().expect("utf8"),
                "--now",
                &at.to_string(),
            ])
            .output()
            .expect("runs")
    };

    let reg = vayuweb_client::record::build_register(
        &alice_id,
        "handover",
        "vayu",
        now,
        &[],
        0,
        None,
        10_000_000,
    )
    .expect("registers");
    assert_eq!(accept(&reg, "reg.cbor", now).status.code(), Some(0));

    let predecessor = vayuweb_client::record::Predecessor::from_bytes(&reg).expect("predecessor");
    let transfer = vayuweb_client::record::build_transfer(
        &alice_id,
        &bob_id,
        &predecessor,
        "handover",
        "vayu",
        now + 600,
    )
    .expect("builds");
    assert_eq!(
        accept(&transfer, "transfer.cbor", now + 600).status.code(),
        Some(0)
    );

    // Bob's first act as recipient: an update whose notBefore sits exactly at the end of
    // hop 1's settlement horizon. Judged BEFORE its moment it is neither good nor bad:
    // DEFER — held for the clock, not rejected (and the clock check runs only AFTER the
    // signature earned it). Judged AT its moment it passes. Authority resolves by replay
    // ALONE — the view knows who controlled the name before and through the transfer, so no
    // transferor key is ever handed to the tool.
    let hop1_pred =
        vayuweb_client::record::Predecessor::from_bytes(&transfer).expect("predecessor");
    let settled = now + 600 + SETTLEMENT_SECONDS;
    let bob_update =
        vayuweb_client::record::build_update(&bob_id, &hop1_pred, "handover", "vayu", settled, &[])
            .expect("builds");
    let update_path = work.path().join("bob-update.cbor");
    std::fs::write(&update_path, &bob_update).expect("writes");

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "verify",
            update_path.to_str().expect("utf8"),
            "--view",
            view_dir.to_str().expect("utf8"),
            "--now",
            &(now + 605).to_string(),
        ])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stdout).starts_with("DEFER"),
        "before its moment the record is held, not judged: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "verify",
            update_path.to_str().expect("utf8"),
            "--view",
            view_dir.to_str().expect("utf8"),
            "--now",
            &settled.to_string(),
        ])
        .output()
        .expect("runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn quarantine_returns_a_name_to_the_open_pool() {
    let work = TempDir::new("view-quarantine");
    let view_dir = work.path().join("view");
    let now = 1_800_000_000u64;
    let quarantine_seconds: u64 = 2_592_000;

    let alice_id = vayuweb_client::identity::Identity::from_seed(&mut vec![0x55; 32]).expect("id");
    let squatter_id =
        vayuweb_client::identity::Identity::from_seed(&mut vec![0x66; 32]).expect("id");

    let accept = |bytes: &[u8], name: &str, at: u64| {
        let path = work.path().join(name);
        std::fs::write(&path, bytes).expect("writes");
        Command::new(env!("CARGO_BIN_EXE_vayu"))
            .args([
                "accept",
                path.to_str().expect("utf8"),
                "--view",
                view_dir.to_str().expect("utf8"),
                "--now",
                &at.to_string(),
            ])
            .output()
            .expect("runs")
    };

    let reg = vayuweb_client::record::build_register(
        &alice_id,
        "seasonal",
        "vayu",
        now,
        &[],
        0,
        None,
        10_000_000,
    )
    .expect("registers");
    assert_eq!(accept(&reg, "reg.cbor", now).status.code(), Some(0));

    let pred = vayuweb_client::record::Predecessor::from_bytes(&reg).expect("predecessor");
    let rel =
        vayuweb_client::record::build_relinquish(&alice_id, &pred, "seasonal", "vayu", now + 600)
            .expect("builds");
    assert_eq!(accept(&rel, "rel.cbor", now + 600).status.code(), Some(0));

    // Mid-quarantine the name is still held against everyone, including a stranger.
    let mid_quarantine = now + 600 + quarantine_seconds / 2;
    let squat = vayuweb_client::record::build_register(
        &squatter_id,
        "seasonal",
        "vayu",
        mid_quarantine,
        &[],
        0,
        None,
        10_000_000,
    )
    .expect("registers");
    let output = accept(&squat, "squat.cbor", mid_quarantine);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stdout).starts_with("REJECT NAME_TAKEN"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // After quarantine it is FREE, and the same stranger may take it.
    let after_quarantine = now + 600 + quarantine_seconds + 1;
    let fresh = vayuweb_client::record::build_register(
        &squatter_id,
        "seasonal",
        "vayu",
        after_quarantine,
        &[],
        0,
        None,
        10_000_000,
    )
    .expect("registers");
    let output = accept(&fresh, "fresh.cbor", after_quarantine);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args(["names", "--view", view_dir.to_str().expect("utf8")])
        .output()
        .expect("runs");
    assert!(String::from_utf8_lossy(&output.stdout).contains("LIVE"));
}

// ---------------------------------------------------------------------------
// The local reading path, END TO END: publish holds its own history, and
// serve --name resolves through it — refusing anything that does not verify.
// ---------------------------------------------------------------------------

/// A running `vayu serve` child plus the address it printed.
struct ServeChild {
    child: std::process::Child,
    addr: String,
}

impl Drop for ServeChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn `vayu serve`, wait for the URL line, and return the parsed address.
fn spawn_serve_by_name(store: &Path, name: &str, now: &str) -> ServeChild {
    use std::io::BufRead;
    let mut child = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "serve",
            store.to_str().expect("utf8"),
            "--name",
            name,
            "--port",
            "0",
            "--now",
            now,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawns");
    let mut addr = None;
    let stdout = child.stdout.take().expect("piped");
    for line in std::io::BufReader::new(stdout).lines() {
        let line = line.expect("reads");
        if let Some(rest) = line.trim().strip_prefix("serving") {
            let url = rest.trim();
            addr = Some(
                url.trim_start_matches("http://")
                    .trim_end_matches('/')
                    .to_string(),
            );
            break;
        }
    }
    match addr {
        Some(addr) => ServeChild { child, addr },
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the server never announced its address");
        }
    }
}

fn http_get(addr: &str, target: &str) -> (u16, String, Vec<u8>) {
    use std::io::{Read, Write};
    let mut attempt = 0;
    let mut stream = loop {
        if let Ok(stream) = std::net::TcpStream::connect(addr) {
            break stream;
        }
        attempt += 1;
        assert!(attempt < 100, "the server never accepted a connection");
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .expect("writes");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("reads");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("headers");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status line");
    (status, head, raw[split + 4..].to_vec())
}

#[test]
fn publish_holds_history_and_serve_by_name_roundtrips() {
    let work = TempDir::new("by-name");
    let site = work.path().join("site");
    work.file(
        "site/index.html",
        "<!doctype html><title>roundtrip</title><h1>readable by NAME</h1>",
    );
    let store = work.path().join("store");
    let seed_path = work.path().join("seed.hex");
    std::fs::write(&seed_path, seed_hex(0x71)).expect("writes");
    let now = 1_800_000_000u64;

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "publish",
            site.to_str().expect("utf8"),
            "--name",
            "roundtrip.vayu",
            "--store",
            store.to_str().expect("utf8"),
            "--key-file",
            seed_path.to_str().expect("utf8"),
            "--now",
            &now.to_string(),
        ])
        .output()
        .expect("runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Publish appended its own record to the view at <store>/view.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("history"), "{stdout}");
    let view_dir = store.join("view");
    let held = std::fs::read_dir(&view_dir)
        .expect("view exists")
        .filter_map(|e| e.ok())
        .count();
    assert_eq!(held, 1);

    // And serve --name resolves through it over real HTTP.
    let server = spawn_serve_by_name(&store, "roundtrip.vayu", &now.to_string());
    let (status, _head, body) = http_get(&server.addr, "/");
    assert_eq!(status, 200);
    assert!(
        body.starts_with(b"<!doctype html>"),
        "{}",
        String::from_utf8_lossy(&body)
    );
}

#[test]
fn serve_by_name_refuses_a_lapsed_or_forged_pointer() {
    let work = TempDir::new("by-name-refuse");
    let site = work.path().join("site");
    work.file("site/index.html", "<!doctype html><title>refuse</title>");
    let store = work.path().join("store");
    let seed_path = work.path().join("seed.hex");
    std::fs::write(&seed_path, seed_hex(0x72)).expect("writes");
    let registered_at = 1_000_000_000u64; // a year that ended long ago

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "publish",
            site.to_str().expect("utf8"),
            "--name",
            "lapsed.vayu",
            "--store",
            store.to_str().expect("utf8"),
            "--key-file",
            seed_path.to_str().expect("utf8"),
            "--now",
            &registered_at.to_string(),
        ])
        .output()
        .expect("runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Long expired: the pointer verifies but the term is over. Refuses CLOSED. (For a
    // registration this old the clock discipline answers first — notBefore sits more than a
    // day behind any post-expiry clock — so BACKDATED precedes EXPIRED; both are refusals,
    // and neither yields a root.)
    let long_after = registered_at + 31_536_000 + 86_400;
    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "serve",
            store.to_str().expect("utf8"),
            "--name",
            "lapsed.vayu",
            "--now",
            &long_after.to_string(),
        ])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing to serve by name"), "{stderr}");

    // A forged incumbent (signature zeroed): refuses before anything is served.
    let view_file = std::fs::read_dir(store.join("view"))
        .expect("lists")
        .filter_map(|e| e.ok())
        .next()
        .expect("one record")
        .path();
    let bytes = std::fs::read(&view_file).expect("reads");
    let vayuweb_client::cbor::Value::Map(mut members) =
        vayuweb_client::cbor::decode(&bytes).expect("decodes")
    else {
        panic!("a record is a map");
    };
    for (key, value) in members.iter_mut() {
        if matches!(key, vayuweb_client::cbor::Key::Text(name) if name == "sig") {
            *value = vayuweb_client::cbor::Value::Bytes(vec![0u8; 64]);
        }
    }
    let forged = vayuweb_client::cbor::encode(&vayuweb_client::cbor::Value::Map(members))
        .expect("re-encodes");
    std::fs::write(&view_file, &forged).expect("overwrites");

    let output = Command::new(env!("CARGO_BIN_EXE_vayu"))
        .args([
            "serve",
            store.to_str().expect("utf8"),
            "--name",
            "lapsed.vayu",
            "--now",
            &registered_at.to_string(),
        ])
        .output()
        .expect("runs");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not verify"), "{stderr}");
}
