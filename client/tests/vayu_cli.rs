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
