//! The publish flow, wired together: PUBLISHING.md section 1, steps 1 through 5.
//!
//! Each step existed already — [`doctor::check`] runs the authoring checks, [`import_site`]
//! builds and addresses the tree, [`BlockStore`] pins it, the record builders sign the pointer.
//! What this module adds is the ORDER, because the order is what the specification legislates:
//! step 1 stops the publish on any error finding before anything else runs; and *"Pin locally.
//! The publisher's own node holds the content before anything points at it. Announcing a name
//! that resolves to nothing is the most common self-inflicted failure in content-addressed
//! systems, and step ordering prevents it."* A signed record is an ownership fact peers
//! replicate; if the bytes it points at are not already held when it is produced, the failure is
//! announced rather than prevented.
//!
//! So the flow checks FIRST, pins SECOND, and signs THIRD — structurally: there is no code path
//! that reaches the signer past a failing check or with content the store has not accepted.
//! That is a stronger property than "the caller should do it in this order", which is how step
//! ordering usually gets implemented and later dropped.
//!
//! No command-line or GUI surface calls this yet; it is the library seam such a surface will
//! use.

use crate::cid::Cid;
use crate::doctor::{self, Finding};
use crate::identity::Identity;
use crate::publish::{import_site, PublishError, SiteFile};
use crate::record::{build_register, build_update, BuildError, Entry, EntryValue, Predecessor};
use crate::store::{BlockStore, StoreError};

/// Why the flow stopped. Every variant is a refusal BEFORE a signature exists, except signing
/// itself failing, which cannot produce a half-published site either: the store already holds
/// the blocks, but nothing points at them until the caller chooses to announce the returned
/// record.
#[derive(Debug)]
pub enum FlowError {
    /// Two files claim one path. The lower-level importer would silently keep the last; a
    /// publishing tool must not choose between the user's own files on their behalf.
    DuplicatePath(String),
    /// The authoring checks found at least one ERROR. Warnings and confirmation-gated findings
    /// do not stop the flow; errors do (PUBLISHING.md 3.1: "Any error stops the publish").
    Doctor(Vec<Finding>),
    /// The tree could not be built or addressed.
    Import(PublishError),
    /// Pinning failed. Nothing has been signed, and whatever blocks landed are simply held —
    /// unpointed content is inert.
    Pin(StoreError),
    /// Record construction refused: an invalid name, a renewal outside its window, a settlement
    /// horizon not reached, and so on — each already explained by the builder's error.
    Build(BuildError),
}

impl core::fmt::Display for FlowError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicatePath(path) => write!(
                f,
                "{path:?} appears twice in the file list; a publishing tool must not pick which \
                 one you meant"
            ),
            Self::Doctor(findings) => {
                write!(f, "the authoring checks stopped this publish:")?;
                for item in findings {
                    if item.severity == doctor::Severity::Error {
                        write!(f, "\n{}", item.render())?;
                    }
                }
                Ok(())
            }
            Self::Import(error) => write!(f, "{error}"),
            Self::Pin(error) => write!(f, "{error}"),
            Self::Build(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for FlowError {}

/// Everything a completed publish produces.
pub struct Published {
    /// The root CID the record now points at.
    pub root: Cid,
    /// How many blocks were newly written to the store during this publish.
    pub newly_pinned: usize,
    /// The signed record bytes. Hold them, append them to a log, hand them to peers — but only
    /// now does anything point at `root`.
    pub record: Vec<u8>,
}

/// One publish attempt, stated as a value so the argument list stays honest about what it is:
/// who publishes, what, when, and under what predecessor state.
pub struct PublishRequest<'a> {
    pub identity: &'a Identity,
    pub label: &'a str,
    pub tld: &'a str,
    pub files: &'a [SiteFile],
    pub now: u64,
    /// `Some` is a republish (an UPDATE under this predecessor); `None` is a first registration.
    pub predecessor: Option<&'a Predecessor>,
    /// The TLD's registration count over the trailing window, for the REGISTER's proof of work.
    pub window_count: u64,
    /// Nonce-search ceiling handed to the proof-of-work walk.
    pub pow_limit: u64,
}

/// Publish a site: build, address, pin, then sign the pointer. In that order, structurally.
///
/// With no predecessor this is a first registration (proof of work runs here); with one, it is
/// an UPDATE carrying the new root under the same term. Either way the record returned has been
/// fully built and signed, and every block it references is already verifiably in the store.
pub fn publish_site(
    store: &BlockStore,
    request: PublishRequest<'_>,
) -> Result<Published, FlowError> {
    let PublishRequest {
        identity,
        label,
        tld,
        files,
        now,
        predecessor,
        window_count,
        pow_limit,
    } = request;

    // Input validation at the tool boundary: the importer tolerates duplicate paths the way a
    // map does — last one wins — which is fine for a library and wrong for a tool that would
    // otherwise quietly publish one of the user's files while discarding another.
    let mut seen = std::collections::HashSet::new();
    for file in files {
        if !seen.insert(file.path.clone()) {
            return Err(FlowError::DuplicatePath(file.path.clone()));
        }
    }

    // Step 1: check. Any ERROR finding stops the publish before hashing, pinning or signing;
    // warnings ride along without stopping anything.
    let findings = doctor::check(files);
    if findings
        .iter()
        .any(|item| item.severity == doctor::Severity::Error)
    {
        return Err(FlowError::Doctor(findings));
    }

    // Steps 2 and 3: build the tree and address it.
    let (blocks, root) = import_site(files).map_err(FlowError::Import)?;

    // Step 4: pin locally. Before anything is signed — enforced by control flow, not comment.
    let newly_pinned = store
        .put_all(
            blocks
                .iter()
                .map(|block| (block.cid.clone(), block.bytes.clone())),
        )
        .map_err(FlowError::Pin)?;

    // Step 5: sign the pointer. A cid entry carries the BINARY root — REGISTRY.md: "Binary
    // CIDv1, 1-64 bytes" — thirty-six bytes, not the text rendering.
    let entries = [Entry {
        value: EntryValue::Cid(root.to_bytes()),
        ttl: None,
    }];
    let record = match predecessor {
        None => build_register(
            identity,
            label,
            tld,
            now,
            &entries,
            window_count,
            None,
            pow_limit,
        ),
        Some(previous) => build_update(identity, previous, label, tld, now, &entries),
    }
    .map_err(FlowError::Build)?;

    Ok(Published {
        root,
        newly_pinned,
        record,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{self, Value};
    use crate::record::PredecessorOp;

    fn identity(seed: u8) -> Identity {
        let mut seed = vec![seed; 32];
        Identity::from_seed(&mut seed).expect("test seed")
    }

    fn temp_store(tag: &str) -> (BlockStore, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("vayuweb-flow-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        (BlockStore::open(&path).expect("opens"), path)
    }

    fn sample_files() -> Vec<SiteFile> {
        vec![
            SiteFile {
                path: "index.html".into(),
                content: b"<!doctype html><title>flow</title>hello\n".to_vec(),
            },
            SiteFile {
                path: "docs/a.txt".into(),
                content: b"alpha\n".to_vec(),
            },
        ]
    }

    #[test]
    fn a_first_publish_pins_everything_then_hands_back_a_signed_register() {
        let (store, path) = temp_store("register");
        let who = identity(0xc1);

        let published = publish_site(
            &store,
            PublishRequest {
                identity: &who,
                label: "flow-site-001",
                tld: "vayu",
                files: &sample_files(),
                now: 1_900_000_000,
                predecessor: None,
                window_count: 0,
                pow_limit: 10_000,
            },
        )
        .expect("publishes");

        // The store holds every block of the tree before the record exists to point at them.
        assert!(
            published.newly_pinned >= 3,
            "two raw leaves plus their directories"
        );
        assert!(store.has(&published.root));

        // And the record says exactly that: a REGISTER whose single cid entry decodes to the
        // same root that was pinned.
        let decoded = cbor::decode(&published.record).expect("decodes");
        let Value::Map(record) = decoded else {
            panic!("a record is a map")
        };
        assert!(
            matches!(
                record.iter().find(|(key, _)| matches!(key, crate::cbor::Key::Text(name) if name == "op")),
                Some((_, crate::cbor::Value::Text(op))) if op == "REGISTER"
            ),
            "no predecessor means REGISTER"
        );
        let entry_value = record
            .iter()
            .find(|(key, _)| matches!(key, crate::cbor::Key::Text(name) if name == "records"))
            .and_then(|(_, value)| match value {
                crate::cbor::Value::Array(entries) => entries.first().cloned(),
                _ => None,
            })
            .expect("one entry");
        let crate::cbor::Value::Map(entry) = entry_value else {
            panic!("entry is a map")
        };
        let carried = entry
            .iter()
            .find(|(key, _)| matches!(key, crate::cbor::Key::Text(name) if name == "value"))
            .and_then(|(_, value)| match value {
                crate::cbor::Value::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .expect("cid bytes");
        assert_eq!(Cid::from_bytes(&carried).expect("decodes"), published.root);
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn a_republish_is_an_update_and_the_old_blocks_stay_held() {
        let (store, path) = temp_store("update");
        let who = identity(0xc2);
        let now = 1_900_000_000;

        let first = publish_site(
            &store,
            PublishRequest {
                identity: &who,
                label: "flow-site-002",
                tld: "vayu",
                files: &[SiteFile {
                    path: "index.html".into(),
                    content: b"v1\n".to_vec(),
                }],
                now,
                predecessor: None,
                window_count: 0,
                pow_limit: 10_000,
            },
        )
        .expect("first publish");
        let previous = Predecessor::from_bytes(&first.record).expect("parses");

        let second = publish_site(
            &store,
            PublishRequest {
                identity: &who,
                label: "flow-site-002",
                tld: "vayu",
                files: &[SiteFile {
                    path: "index.html".into(),
                    content: b"v2\n".to_vec(),
                }],
                now: now + 600,
                predecessor: Some(&previous),
                window_count: 0,
                pow_limit: 10_000,
            },
        )
        .expect("second publish");

        assert_ne!(first.root, second.root, "new content, new CID");
        // Both versions remain held: updating a pointer does not delete the old tree, and a
        // reader still holding the old root can still verify it. Unpublishing is a separate,
        // explicit act.
        assert!(store.has(&first.root));
        assert!(store.has(&second.root));

        let decoded = cbor::decode(&second.record).expect("decodes");
        let Value::Map(record) = decoded else {
            panic!("a record is a map")
        };
        assert!(
            matches!(
                record.iter().find(|(key, _)| matches!(key, crate::cbor::Key::Text(name) if name == "op")),
                Some((_, crate::cbor::Value::Text(op))) if op == "UPDATE"
            ),
            "a predecessor means UPDATE"
        );
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn pinning_happens_before_signing_so_a_build_failure_leaves_content_inert_but_held() {
        let (store, path) = temp_store("pin-fail");
        let who = identity(0xc3);

        // The name is invalid, so signing will refuse — but ONLY after the flow has pinned the
        // tree, because that is the order the flow enforces. From outside, this proves the
        // ordering property: content is held even though no record exists, and unpointed content
        // is inert. Nothing was signed, nothing was announced.
        let outcome = publish_site(
            &store,
            PublishRequest {
                identity: &who,
                label: "Bad-Label!",
                tld: "vayu",
                files: &sample_files(),
                now: 1_900_000_000,
                predecessor: None,
                window_count: 0,
                pow_limit: 10_000,
            },
        );
        assert!(matches!(outcome, Err(FlowError::Build(_))));
        assert!(
            store.len().expect("counts") >= 3,
            "the tree was pinned before the signer was ever reached"
        );
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn duplicate_paths_are_refused_before_any_hashing_or_signing() {
        let (store, path) = temp_store("dupes");
        let who = identity(0xc4);
        let files = vec![
            SiteFile {
                path: "index.html".into(),
                content: b"one\n".to_vec(),
            },
            SiteFile {
                path: "index.html".into(),
                content: b"two\n".to_vec(),
            },
        ];
        let outcome = publish_site(
            &store,
            PublishRequest {
                identity: &who,
                label: "dupe-path-site",
                tld: "vayu",
                files: &files,
                now: 1_900_000_000,
                predecessor: None,
                window_count: 0,
                pow_limit: 10_000,
            },
        );
        assert!(matches!(outcome, Err(FlowError::DuplicatePath(ref p)) if p == "index.html"));
        // Nothing was pinned and nothing signed.
        assert!(store.is_empty().expect("counts"));
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn an_update_refuses_to_run_inside_a_transfer_settlement_horizon() {
        let (store, path) = temp_store("settling");
        let recipient = identity(0xc6);
        let now = 1_900_000_000;

        // A live predecessor that is itself a TRANSFER still settling: ownerKey is already the
        // recipient, but the outgoing key keeps control until the horizon passes.
        let settling = Predecessor {
            seq: 2,
            op: PredecessorOp::Transfer,
            not_before: now,
            not_after: now + crate::record::TERM_SECONDS,
            hash: [0x61u8; 32],
            revoked: false,
        };
        let outcome = publish_site(
            &store,
            PublishRequest {
                identity: &recipient,
                label: "settling-site-1",
                tld: "vayu",
                files: &sample_files(),
                now: now + 600,
                predecessor: Some(&settling),
                window_count: 0,
                pow_limit: 10_000,
            },
        );
        assert!(matches!(outcome, Err(FlowError::Build(_))));
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn the_doctor_runs_first_so_a_failing_site_is_never_pinned_or_signed() {
        let (store, path) = temp_store("doctor-first");
        let who = identity(0xc8);
        let files = vec![SiteFile {
            path: "index.html".into(),
            content: b"<style>p{}</style>".to_vec(),
        }];
        let outcome = publish_site(
            &store,
            PublishRequest {
                identity: &who,
                label: "doctor-site-01",
                tld: "vayu",
                files: &files,
                now: 1_900_000_000,
                predecessor: None,
                window_count: 0,
                pow_limit: 10_000,
            },
        );
        // Step 1 stops everything: no hashing, no pinning, and the signer is never reached.
        assert!(matches!(outcome, Err(FlowError::Doctor(_))));
        assert!(store.is_empty().expect("counts"));
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn a_warning_does_not_stop_the_publish_but_an_error_does() {
        let (store, path) = temp_store("warn-ok");
        let who = identity(0xc9);
        let warning_only = vec![SiteFile {
            path: "index.html".into(),
            content: b"<a href=\"https://example.com\">leaves VayuWeb, warned, allowed</a>"
                .to_vec(),
        }];
        let published = publish_site(
            &store,
            PublishRequest {
                identity: &who,
                label: "warn-site-001",
                tld: "vayu",
                files: &warning_only,
                now: 1_900_000_000,
                predecessor: None,
                window_count: 0,
                pow_limit: 10_000,
            },
        )
        .expect("a warning is not an error");
        assert!(store.has(&published.root));
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn an_empty_site_is_refused_by_step_1_for_having_no_index() {
        let (store, path) = temp_store("empty");
        let who = identity(0xc7);
        // An empty tree used to reach the builder and yield the empty-directory root; since the
        // doctor became step 1 it is refused before any hashing — a site nobody can land on has
        // no business getting a signed pointer.
        let outcome = publish_site(
            &store,
            PublishRequest {
                identity: &who,
                label: "empty-site-001",
                tld: "vayu",
                files: &[],
                now: 1_900_000_000,
                predecessor: None,
                window_count: 0,
                pow_limit: 10_000,
            },
        );
        match outcome {
            Err(FlowError::Doctor(findings)) => assert!(
                findings.iter().any(|f| f.rule == "missing-index"),
                "the finding names the rule: {:?}",
                findings.iter().map(|f| f.rule).collect::<Vec<_>>()
            ),
            other => panic!("expected a doctor refusal, got {:?}", other.map(|p| p.root)),
        }
        assert!(store.is_empty().expect("counts"));
        std::fs::remove_dir_all(path).expect("cleanup");
    }
}
