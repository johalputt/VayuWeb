//! The verifier's own linearised log: a local view of the records THIS peer has accepted.
//!
//! The implementation of record defines a `RegistryView` interface and deliberately gives it
//! no permissive default — a view that answered "not taken" and "difficulty zero" would make
//! every caller that forgot to supply one silently accept unproven records. This module is the
//! desktop client's answer, built for one machine's honesty rather than a network's: a
//! directory of accepted records, each stored under its own record_hash, with the current
//! state of every name DERIVED by replay instead of kept in an index that could rot.
//!
//! What replay means here, and why an index is refused: the log is append-only files whose
//! names are content addresses, so "what have I accepted" is always recomputable from bytes —
//! a crash mid-write leaves an unreadable file that replay skips, not a poisoned index.
//! Per name the chain is walked from seq 0 through prevHash links; the tip of the longest
//! contiguous prefix is the current record. A gap (a file lost) truncates at the gap: what is
//! not held is simply not part of this peer's history, which is exactly the honest answer for
//! a local log.
//!
//! The chain also answers a question single-record mode cannot: who SIGNED a transfer. A
//! TRANSFER's authority while settling is its transferor's key — the ownerKey of the record
//! BEFORE it — so a replayed chain supplies `--transferor-key` automatically and a hand-carried
//! hex flag stops being a way to lie to yourself.

use std::path::{Path, PathBuf};

use crate::domain::record_hash_from_bytes;
use crate::verify::{fully_released, peek, verify, Peeked, PrevView, Verdict};

/// One accepted record as the log holds it: exact bytes plus the identity they hash to.
#[derive(Debug, Clone)]
pub struct Entry {
    pub hash_hex: String,
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

/// The tip of one name's chain, plus enough of the chain behind it to know who controlled the
/// name before the tip did.
#[derive(Debug, Clone)]
pub struct Tip {
    pub entry: Entry,
    /// The predecessor view built from the tip's own bytes — with the transferor resolved
    /// from the chain when the tip is a TRANSFER.
    pub prev: PrevView,
}

/// A local directory of accepted records.
#[derive(Debug, Clone)]
pub struct View {
    dir: PathBuf,
}

impl View {
    /// Open (creating if needed) a directory that holds accepted records.
    pub fn open(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create view dir {dir:?}: {e}"))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_for(&self, bytes: &[u8]) -> PathBuf {
        let hash = record_hash_from_bytes(bytes);
        let mut text = String::with_capacity(64 + 5);
        for byte in hash {
            text.push_str(&format!("{byte:02x}"));
        }
        text.push_str(".cbor");
        self.dir.join(text)
    }

    /// Append an accepted record. Idempotent on bytes: the same record hashes to the same
    /// name and re-writing it changes nothing.
    pub fn put(&self, bytes: &[u8]) -> Result<(), String> {
        let path = self.path_for(bytes);
        if path.exists() {
            return Ok(());
        }
        std::fs::write(&path, bytes).map_err(|e| format!("cannot write {path:?}: {e}"))
    }

    /// Whether these exact bytes are already held — an exchange imports a bundle and must
    /// not count what it already has as newly judged.
    pub fn holds(&self, bytes: &[u8]) -> bool {
        self.path_for(bytes).exists()
    }

    /// Every readable record in the log, sorted by hash for determinism. Unreadable files are
    /// skipped, not fatal: a torn final write must not take the whole log down.
    pub fn entries(&self) -> Result<Vec<Entry>, String> {
        let mut out = Vec::new();
        for entry in
            std::fs::read_dir(&self.dir).map_err(|e| format!("cannot list {:?}: {e}", self.dir))?
        {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("cbor") {
                continue;
            }
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            if peek(&bytes).is_err() {
                continue;
            }
            let hash_hex = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            out.push(Entry {
                hash_hex,
                path,
                bytes,
            });
        }
        out.sort_by(|a, b| a.hash_hex.cmp(&b.hash_hex));
        Ok(out)
    }

    /// The current record for a name, by replay: walk from seq 0 through prevHash links and
    /// stop at the first break. `None` when this peer holds no history for the name.
    pub fn chain_tip(&self, label: &str, tld: &str) -> Result<Option<Tip>, String> {
        // Everything this peer holds for the name: sequence number, own content address,
        // claimed predecessor address.
        let all = self.entries()?;
        let mut mine: Vec<(u64, [u8; 32], [u8; 32], &Entry)> = Vec::new();
        for entry in &all {
            let Ok(peeked) = peek(&entry.bytes) else {
                continue;
            };
            if peeked.label != label || peeked.tld != tld {
                continue;
            }
            let prev_hash = match prev_hash_of(&entry.bytes) {
                Ok(hash) => hash,
                Err(_) => continue,
            };
            mine.push((
                peeked.seq,
                record_hash_from_bytes(&entry.bytes),
                prev_hash,
                entry,
            ));
        }
        if mine.is_empty() {
            return Ok(None);
        }
        mine.sort_by_key(|(seq, _, _, _)| *seq);

        // Walk from genesis: a valid history STARTS at seq 0, and every later record carries
        // both the next sequence number and the previous record's content address. First
        // break ends the chain — what follows the break is not part of this peer's history.
        if mine[0].0 != 0 {
            return Ok(None);
        }
        let mut tip_index = 0usize;
        for index in 1..mine.len() {
            let (seq, _, claimed_prev, _) = mine[index];
            let (_, actual_prev, _, _) = mine[index - 1];
            if seq != index as u64 || claimed_prev != actual_prev {
                break;
            }
            tip_index = index;
        }

        // The tip and — when it is a TRANSFER — the record before it, whose ownerKey is the
        // transferor that still controls the name during settlement.
        let tip_entry = mine[tip_index].3.clone();
        let tip_peeked = peek(&tip_entry.bytes)?;
        let signer_key = if tip_peeked.op == "TRANSFER" {
            match tip_index.checked_sub(1) {
                Some(before) => owner_of(&mine[before].3.bytes)?,
                None => return Err("a stored TRANSFER cannot be seq 0".to_string()),
            }
        } else {
            owner_of(&tip_entry.bytes)?
        };
        let op_text = tip_peeked.op;
        let prev = PrevView {
            seq: tip_peeked.seq,
            not_before: tip_peeked.not_before,
            not_after: not_after_of(&tip_entry.bytes)?,
            owner_key: owner_of(&tip_entry.bytes)?,
            signer_key,
            suite: suite_of(&tip_entry.bytes)?,
            hash: mine[tip_index].1,
            revoked: op_text == "REVOKE",
            op_text,
        };
        Ok(Some(Tip {
            entry: tip_entry,
            prev,
        }))
    }

    /// The full verdict for a record AS RECEIVED, against this view: predecessor found by
    /// replay, NAME_TAKEN answered from the incumbent's lifecycle, everything else delegated
    /// to [`verify`] with its order preserved.
    ///
    /// Returns the verdict plus whether an ACCEPT should be appended (true exactly for
    /// [`Verdict::Accept`]).
    pub fn accept_verdict(
        &self,
        bytes: &[u8],
        now: u64,
        window_count: u64,
    ) -> Result<Verdict, String> {
        let Peeked { op, label, tld, .. } = peek(bytes)?;

        // NAME_TAKEN before any cryptography — the ordinary case (registering a plainly-taken
        // name) costs a lookup, not 64 MiB of Argon2id, and says nothing about whether the
        // record would otherwise have been valid. One exception, and it is not a loophole:
        // re-judging the INCUMBENT ITSELF (the bytes this view already accepted) must not
        // answer NAME_TAKEN against its own existence — convergence re-verifies what it holds,
        // exactly as the registry's ignoreIncumbent exists for.
        if op == "REGISTER" {
            if let Some(tip) = self.chain_tip(&label, &tld)? {
                let incoming = crate::domain::record_hash_from_bytes(bytes);
                let incoming_hex: String = incoming.iter().map(|b| format!("{b:02x}")).collect();
                if tip.entry.hash_hex != incoming_hex && !fully_released(&tip.prev, now) {
                    return Ok(Verdict::Reject {
                        code: "NAME_TAKEN",
                        detail: format!(
                            "{label}.{tld} is held ({}); quarantine ends when the name returns \
                             to the open pool",
                            crate::verify::lifecycle_state(&tip.prev, now)
                        ),
                    });
                }
            }
            return Ok(verify(bytes, None, now, window_count));
        }

        let Some(tip) = self.chain_tip(&label, &tld)? else {
            return Ok(Verdict::Reject {
                code: "NO_PREDECESSOR",
                detail: format!("{label}.{tld} has no accepted history in this view"),
            });
        };
        Ok(verify(bytes, Some(&tip.prev), now, window_count))
    }

    /// Every named chain in the log with its current tip, for `vayu names`.
    pub fn all_names(&self) -> Result<Vec<(String, String, Tip)>, String> {
        let mut names: Vec<(String, String)> = Vec::new();
        for entry in self.entries()? {
            if let Ok(Peeked { label, tld, .. }) = peek(&entry.bytes) {
                let key = (label, tld);
                if !names.contains(&key) {
                    names.push(key);
                }
            }
        }
        names.sort();
        let mut out = Vec::new();
        for (label, tld) in names {
            if let Some(tip) = self.chain_tip(&label, &tld)? {
                out.push((label, tld, tip));
            }
        }
        Ok(out)
    }
}

fn field_u64(bytes: &[u8], name: &str) -> Result<u64, String> {
    let value = crate::record::decode_record(bytes).map_err(|e| e.to_string())?;
    match value {
        crate::cbor::Value::Map(members) => members
            .iter()
            .find_map(|(k, v)| match k {
                crate::cbor::Key::Text(text) if text == name => match v {
                    crate::cbor::Value::UInt(n) => Some(*n),
                    _ => None,
                },
                _ => None,
            })
            .ok_or_else(|| format!("no readable {name}")),
        _ => Err("a record is a CBOR map".to_string()),
    }
}

fn owner_of(bytes: &[u8]) -> Result<[u8; 32], String> {
    let value = crate::record::decode_record(bytes).map_err(|e| e.to_string())?;
    let crate::cbor::Value::Map(members) = value else {
        return Err("a record is a CBOR map".to_string());
    };
    let raw = members
        .iter()
        .find_map(|(k, v)| match k {
            crate::cbor::Key::Text(text) if text == "ownerKey" => match v {
                crate::cbor::Value::Bytes(b) if b.len() == 32 => Some(b.clone()),
                _ => None,
            },
            _ => None,
        })
        .ok_or("no readable ownerKey")?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw);
    Ok(key)
}

fn not_after_of(bytes: &[u8]) -> Result<u64, String> {
    field_u64(bytes, "notAfter")
}

/// The predecessor address a record CLAIMS — checked against the actual content address of the
/// record before it during replay.
fn prev_hash_of(bytes: &[u8]) -> Result<[u8; 32], String> {
    let value = crate::record::decode_record(bytes).map_err(|e| e.to_string())?;
    let crate::cbor::Value::Map(members) = value else {
        return Err("a record is a CBOR map".to_string());
    };
    let raw = members
        .iter()
        .find_map(|(k, v)| match k {
            crate::cbor::Key::Text(text) if text == "prevHash" => match v {
                crate::cbor::Value::Bytes(b) if b.len() == 32 => Some(b.clone()),
                _ => None,
            },
            _ => None,
        })
        .ok_or("no readable prevHash")?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&raw);
    Ok(hash)
}

fn suite_of(bytes: &[u8]) -> Result<u8, String> {
    Ok(u8::try_from(field_u64(bytes, "suite").unwrap_or(1)).unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::record::{build_register, build_relinquish, build_update, Predecessor};
    use crate::verify::QUARANTINE_SECONDS;

    const NOW: u64 = 1_800_000_000;
    const LIMIT: u64 = 10_000_000;

    fn identity(byte: u8) -> Identity {
        let mut seed = vec![byte; 32];
        Identity::from_seed(&mut seed).expect("test seed")
    }

    fn temp_view(tag: &str) -> (std::path::PathBuf, View) {
        let dir = std::env::temp_dir().join(format!("vayu-view-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let view = View::open(&dir).expect("opens");
        (dir, view)
    }

    #[test]
    fn replay_walks_the_chain_and_stops_at_the_first_break() {
        let (_dir, view) = temp_view("walk");
        let alice = identity(0xA0);

        let reg =
            build_register(&alice, "river", "vayu", NOW, &[], 0, None, LIMIT).expect("registers");
        let pred = Predecessor::from_bytes(&reg).expect("predecessor");
        let update = build_update(&alice, &pred, "river", "vayu", NOW + 600, &[]).expect("builds");

        view.put(&reg).expect("puts");
        let tip = view
            .chain_tip("river", "vayu")
            .expect("replays")
            .expect("a tip");
        assert_eq!(tip.prev.seq, 0);

        view.put(&update).expect("puts");
        let tip = view
            .chain_tip("river", "vayu")
            .expect("replays")
            .expect("a tip");
        assert_eq!(tip.prev.seq, 1, "the walk followed the prevHash link");

        // An unrelated name is invisible to this chain.
        assert!(view.chain_tip("other", "vayu").expect("replays").is_none());
    }

    #[test]
    fn a_gap_truncates_instead_of_poisoning() {
        let (dir, view) = temp_view("gap");
        let alice = identity(0xA1);

        let reg =
            build_register(&alice, "creek", "vayu", NOW, &[], 0, None, LIMIT).expect("registers");
        let pred = Predecessor::from_bytes(&reg).expect("predecessor");
        let orphan = build_update(&alice, &pred, "creek", "vayu", NOW + 600, &[]).expect("builds");

        // Only the SUCCESSOR is present: without genesis there is no history at all.
        view.put(&orphan).expect("puts");
        assert!(view.chain_tip("creek", "vayu").expect("replays").is_none());

        // With genesis the chain reaches exactly the held prefix.
        view.put(&reg).expect("puts");
        let tip = view
            .chain_tip("creek", "vayu")
            .expect("replays")
            .expect("tip");
        assert_eq!(tip.prev.seq, 1);
        let _ = dir;
    }

    #[test]
    fn name_taken_is_answered_before_quarantine_runs_out_and_freed_after() {
        let (_dir, view) = temp_view("lifecycle");
        let alice = identity(0xA2);
        let stranger = identity(0xA3);

        let reg =
            build_register(&alice, "plot", "vayu", NOW, &[], 0, None, LIMIT).expect("registers");
        let pred = Predecessor::from_bytes(&reg).expect("predecessor");
        let rel = build_relinquish(&alice, &pred, "plot", "vayu", NOW + 600).expect("builds");
        view.put(&reg).expect("puts");
        view.put(&rel).expect("puts");

        let squat = |at: u64| {
            build_register(&stranger, "plot", "vayu", at, &[], 0, None, LIMIT).expect("registers")
        };

        // Mid-quarantine: taken.
        match view
            .accept_verdict(
                &squat(NOW + 600 + QUARANTINE_SECONDS / 2),
                NOW + 600 + QUARANTINE_SECONDS / 2,
                0,
            )
            .expect("verdict")
        {
            Verdict::Reject { code, .. } => assert_eq!(code, "NAME_TAKEN"),
            other => panic!("expected NAME_TAKEN, got {other:?}"),
        }
        // One second before quarantine ends: still taken.
        match view
            .accept_verdict(
                &squat(NOW + 600 + QUARANTINE_SECONDS - 1),
                NOW + 600 + QUARANTINE_SECONDS - 1,
                0,
            )
            .expect("verdict")
        {
            Verdict::Reject { code, .. } => assert_eq!(code, "NAME_TAKEN"),
            other => panic!("expected NAME_TAKEN, got {other:?}"),
        }
        // Quarantine over: FREE, and the stranger's fresh registration verifies clean.
        let after = NOW + 600 + QUARANTINE_SECONDS + 1;
        match view
            .accept_verdict(&squat(after), after, 0)
            .expect("verdict")
        {
            Verdict::Accept => {}
            other => panic!("the name returned to the open pool: {other:?}"),
        }
    }

    #[test]
    fn an_accepted_verdict_is_appendable_and_a_refusal_is_not() {
        let (_dir, view) = temp_view("append");
        let alice = identity(0xA4);

        let reg =
            build_register(&alice, "meadow", "vayu", NOW, &[], 0, None, LIMIT).expect("registers");
        match view.accept_verdict(&reg, NOW, 0).expect("verdict") {
            Verdict::Accept => view.put(&reg).expect("puts"),
            other => panic!("an honest registration accepts: {other:?}"),
        }
        assert_eq!(view.entries().expect("entries").len(), 1);

        // The same bytes again: put is idempotent on content.
        view.put(&reg).expect("puts");
        assert_eq!(view.entries().expect("entries").len(), 1);
    }

    #[test]
    fn a_torn_write_is_skipped_not_fatal() {
        let (_dir, view) = temp_view("torn");
        let alice = identity(0xA5);

        let reg =
            build_register(&alice, "brook", "vayu", NOW, &[], 0, None, LIMIT).expect("registers");
        view.put(&reg).expect("puts");

        // Simulate a crash mid-write: a truncated copy under a plausible name.
        let hash_hex = {
            let hash = record_hash_from_bytes(&reg);
            hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        std::fs::write(
            view.dir().join(format!("{hash_hex}-torn.cbor")),
            &reg[..reg.len() / 2],
        )
        .expect("writes");

        // Replay survives and still finds the good record.
        let tip = view
            .chain_tip("brook", "vayu")
            .expect("replays")
            .expect("tip");
        assert_eq!(tip.prev.seq, 0);
        assert_eq!(
            view.entries().expect("entries").len(),
            1,
            "the torn file is skipped"
        );
    }
}
