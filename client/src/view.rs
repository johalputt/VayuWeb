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

use crate::cid::Cid;
use crate::domain::record_hash_from_bytes;
use crate::record::AliasTarget;
use crate::verify::{fully_released, peek, verify, Peeked, PrevView, Verdict};

/// What a chain currently points at: content, or another ratified name.
pub enum Pointer {
    Cid(Cid),
    Alias(AliasTarget),
}

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

/// One candidate in a name's history: sequence, own content address, the predecessor
/// address it CLAIMS, and the held entry itself.
type Candidate<'a> = (u64, [u8; 32], [u8; 32], &'a Entry);

/// THE chain for a name, chosen deterministically even when the view holds forks.
///
/// REGISTRY.md's convergence rule: where two records claim the same slot — the same
/// sequence number, each a valid link from the record before — the SMALLER record_hash,
/// read as a big-endian unsigned integer, wins. A peer MUST NOT decide by its own log
/// position or arrival order, which is precisely what a stable sort would smuggle in:
/// two peers holding the same forked set in different directory orders must converge
/// on the same tip or they serve different sites from the same evidence.
///
/// The walk starts at seq 0 and the first gap ends the chain — what no link reaches is
/// not part of this history, exactly as before; forks only change WHO wins a slot,
/// never that a link must exist.
fn deterministic_chain<'a>(mine: &mut Vec<Candidate<'a>>) -> Vec<Candidate<'a>> {
    mine.sort_by_key(|(seq, _, _, _)| *seq);
    let mut chain: Vec<Candidate> = Vec::new();
    let mut index = 0usize;
    while index < mine.len() {
        let expected_seq = chain.len() as u64;
        if mine[index].0 != expected_seq {
            break;
        }
        let mut group_end = index;
        while group_end < mine.len() && mine[group_end].0 == expected_seq {
            group_end += 1;
        }
        let prev_hash = chain.last().map(|candidate| candidate.1);
        let mut best: Option<Candidate> = None;
        for candidate in &mine[index..group_end] {
            let linked = match prev_hash {
                // Only slot 0 opens a history; later slots must follow the winner so far.
                None => expected_seq == 0,
                Some(hash) => candidate.2 == hash,
            };
            if !linked {
                continue;
            }
            best = match best {
                None => Some(*candidate),
                Some(current) if candidate.1 < current.1 => Some(*candidate),
                other => other,
            };
        }
        match best {
            Some(chosen) => {
                chain.push(chosen);
                index = group_end;
            }
            None => break,
        }
    }
    chain
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

    /// The current record for a name, by replay: walk from seq 0 through prevHash links,
    /// choosing deterministically at any fork, and stop at the first break. `None` when
    /// this peer holds no history for the name.
    pub fn chain_tip(&self, label: &str, tld: &str) -> Result<Option<Tip>, String> {
        // Everything this peer holds for the name: sequence number, own content address,
        // claimed predecessor address.
        let all = self.entries()?;
        let mut mine: Vec<Candidate> = Vec::new();
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
        let chain = deterministic_chain(&mut mine);
        if chain.is_empty() {
            return Ok(None);
        }
        let tip_index = chain.len() - 1;

        // The tip and — when it is a TRANSFER — the record before it, whose ownerKey is the
        // transferor that still controls the name during settlement.
        let tip_entry = chain[tip_index].3.clone();
        let tip_peeked = peek(&tip_entry.bytes)?;
        let signer_key = if tip_peeked.op == "TRANSFER" {
            match tip_index.checked_sub(1) {
                Some(before) => owner_of(&chain[before].3.bytes)?,
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
            hash: chain[tip_index].1,
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

    /// Re-judge a record this view ALREADY HOLDS as the tip of its chain — the reading
    /// path's gate. The successor checks run against the chain BELOW the tip, never against
    /// the tip itself (a record cannot follow itself); everything else is [`verify`] with
    /// its order preserved, so a tampered held file still refuses on signature or digest.
    pub fn judge_held_tip(
        &self,
        label: &str,
        tld: &str,
        now: u64,
        window_count: u64,
    ) -> Result<Verdict, String> {
        // Replay the walk exactly as chain_tip does — same deterministic fork choice —
        // but keep every link so the parent of the tip is at hand.
        let all = self.entries()?;
        let mut mine: Vec<Candidate> = Vec::new();
        for entry in &all {
            let Ok(peeked) = peek(&entry.bytes) else {
                continue;
            };
            if peeked.label != label || peeked.tld != tld {
                continue;
            }
            let Ok(prev_hash) = prev_hash_of(&entry.bytes) else {
                continue;
            };
            mine.push((
                peeked.seq,
                record_hash_from_bytes(&entry.bytes),
                prev_hash,
                entry,
            ));
        }
        if mine.is_empty() {
            return Ok(Verdict::Reject {
                code: "NO_PREDECESSOR",
                detail: format!("{label}.{tld} has no accepted history in this view"),
            });
        }
        let chain = deterministic_chain(&mut mine);
        if chain.is_empty() {
            return Ok(Verdict::Reject {
                code: "NO_PREDECESSOR",
                detail: format!("{label}.{tld} has no accepted history in this view"),
            });
        }
        let tip_index = chain.len() - 1;

        let tip_bytes = &chain[tip_index].3.bytes;
        let Peeked { op, .. } = peek(tip_bytes)?;
        if op == "REGISTER" {
            return Ok(verify(tip_bytes, None, now, window_count));
        }
        let Some(before) = tip_index.checked_sub(1) else {
            return Ok(Verdict::Reject {
                code: "BAD_SEQ",
                detail: "a non-REGISTER cannot be seq 0".to_string(),
            });
        };
        let signer_key = if op == "TRANSFER" {
            match before.checked_sub(1) {
                Some(settler) => owner_of(&chain[settler].3.bytes)?,
                None => return Err("a stored TRANSFER cannot be seq 0".to_string()),
            }
        } else {
            owner_of(&chain[before].3.bytes)?
        };
        let parent = PrevView {
            seq: peek(&chain[before].3.bytes)?.seq,
            not_before: peek(&chain[before].3.bytes)?.not_before,
            not_after: not_after_of(&chain[before].3.bytes)?,
            owner_key: owner_of(&chain[before].3.bytes)?,
            signer_key,
            suite: suite_of(&chain[before].3.bytes)?,
            hash: chain[before].1,
            revoked: false,
            op_text: peek(&chain[before].3.bytes)?.op,
        };
        Ok(verify(tip_bytes, Some(&parent), now, window_count))
    }

    /// What the chain currently points at: from the tip, scan BACKWARDS to the most recent
    /// record that carries an entry. A RENEW extends time and carries none, so a renewed
    /// name still resolves to whatever was last published; an ALIAS entry names another
    /// ratified name and the RESOLVER follows it within budget.
    pub fn resolved_pointer(&self, label: &str, tld: &str) -> Result<Pointer, String> {
        let all = self.entries()?;
        let mut mine: Vec<Candidate> = Vec::new();
        for entry in &all {
            let Ok(peeked) = peek(&entry.bytes) else {
                continue;
            };
            if peeked.label != label || peeked.tld != tld {
                continue;
            }
            let Ok(prev_hash) = prev_hash_of(&entry.bytes) else {
                continue;
            };
            mine.push((
                peeked.seq,
                record_hash_from_bytes(&entry.bytes),
                prev_hash,
                entry,
            ));
        }
        if mine.is_empty() {
            return Err(format!("{label}.{tld} has no accepted history"));
        }
        // Same deterministic fork choice as chain_tip — the two readers of one log must
        // never disagree about which history is THE history.
        let chain = deterministic_chain(&mut mine);
        if chain.is_empty() {
            return Err(format!("{label}.{tld} has no accepted history"));
        }
        // The most recent record with a SELECTED source decides. A record whose
        // selection is an ipns pointer names content this offline view cannot fetch,
        // and a malformed cid address is content no reader can verify — both refuse
        // CLOSED rather than quietly serving the older record beneath them, which is
        // exactly the frozen-snapshot fork RESOLUTION.md's ordering exists to prevent.
        for candidate in chain.iter().rev() {
            match selected_pointer(&candidate.3.bytes) {
                Some(Selected::Cid(bytes)) => {
                    return match Cid::from_bytes(&bytes) {
                        Ok(cid) => Ok(Pointer::Cid(cid)),
                        Err(_) => Err(format!(
                            "{label}.{tld}'s current record selects a malformed content \
                             address; refusing it rather than serving an older record"
                        )),
                    };
                }
                Some(Selected::Alias(target)) => return Ok(Pointer::Alias(target)),
                Some(Selected::Ipns(text)) => {
                    return Err(format!(
                        "{label}.{tld} currently points at an IPNS pointer ({text}); an \
                         offline view cannot follow it and will not serve an older snapshot \
                         in its place"
                    ))
                }
                None => continue,
            }
        }
        Err(format!(
            "no record in {label}.{tld}'s chain carries a servable entry"
        ))
    }

    /// The cid entry the chain currently points at, when that is content rather than
    /// another name.
    pub fn resolved_root(&self, label: &str, tld: &str) -> Result<Cid, String> {
        match self.resolved_pointer(label, tld)? {
            Pointer::Cid(cid) => Ok(cid),
            Pointer::Alias(_) => Err(format!("{label}.{tld} points at another name, not content")),
        }
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

/// What a record's entries select as the thing to serve. RESOLUTION.md orders the
/// TYPES — `ipns`, then `cid`, then `alias` — and takes the first entry of the
/// selected type; record order decides only within a type, never between them.
/// RENEW and the terminal ops carry no entries at all, and `None` is the honest
/// answer for anything with no selectable source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selected {
    /// A living IPNS pointer. Names content that exists elsewhere; a LOCAL view
    /// cannot follow it and says so rather than silently serving an older `cid`.
    Ipns(String),
    /// Raw content-address bytes. Selection is STRUCTURAL — RESOLUTION.md checks
    /// integrity at fetch time, not selection time — so a malformed address still
    /// wins selection here, and the local server refuses on it rather than quietly
    /// falling back to an older record.
    Cid(Vec<u8>),
    Alias(crate::record::AliasTarget),
}

/// Apply RESOLUTION.md's selection to one record's entries.
pub fn selected_pointer(bytes: &[u8]) -> Option<Selected> {
    let value = crate::record::decode_record(bytes).ok()?;
    let crate::cbor::Value::Map(members) = value else {
        return None;
    };
    let entries = members.iter().find_map(|(k, v)| match k {
        crate::cbor::Key::Text(name) if name == "records" => match v {
            crate::cbor::Value::Array(entries) => Some(entries),
            _ => None,
        },
        _ => None,
    })?;
    // (type, value) pairs in wire order.
    let mut typed: Vec<(&str, &crate::cbor::Value)> = Vec::new();
    for entry in entries {
        let crate::cbor::Value::Map(fields) = entry else {
            continue;
        };
        let kind = fields.iter().find_map(|(k, v)| match k {
            crate::cbor::Key::Text(name) if name == "type" => match v {
                crate::cbor::Value::Text(text) => Some(text.as_str()),
                _ => None,
            },
            _ => None,
        })?;
        let val = fields.iter().find_map(|(k, v)| match k {
            crate::cbor::Key::Text(name) if name == "value" => Some(v),
            _ => None,
        })?;
        typed.push((kind, val));
    }
    for wanted in ["ipns", "cid", "alias"] {
        let Some(val) = typed
            .iter()
            .find(|(kind, _)| *kind == wanted)
            .map(|(_, value)| *value)
        else {
            continue;
        };
        match wanted {
            "ipns" => match val {
                crate::cbor::Value::Text(text) => return Some(Selected::Ipns(text.clone())),
                _ => continue,
            },
            "cid" => match val {
                crate::cbor::Value::Bytes(bytes) => return Some(Selected::Cid(bytes.clone())),
                _ => continue,
            },
            // verify enforces alias-alone, so this branch is reached only when the
            // whole entries list is exactly one alias.
            _ => match val {
                crate::cbor::Value::Text(text) => {
                    let (label, tld) = text.rsplit_once('.')?;
                    return Some(Selected::Alias(crate::record::AliasTarget {
                        label: label.to_string(),
                        tld: tld.to_string(),
                    }));
                }
                _ => continue,
            },
        }
    }
    None
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
    fn a_fork_converges_on_the_smaller_digest_regardless_of_arrival() {
        let alice = identity(0xA5);
        let bob = identity(0xB2);

        // Two independent registrations of the SAME name: a genuine equivocation
        // fork, both records individually valid. REGISTRY.md decides by the smaller
        // record_hash as a big-endian integer — never by who arrived first.
        let a = build_register(&alice, "split", "vayu", NOW, &[], 0, None, LIMIT).expect("a");
        let b = build_register(&bob, "split", "vayu", NOW + 1, &[], 0, None, LIMIT).expect("b");
        let (hash_a, hash_b) = (record_hash_from_bytes(&a), record_hash_from_bytes(&b));
        assert_ne!(hash_a, hash_b, "distinct records must hash apart");
        let (winner_bytes, loser_bytes) = if hash_a < hash_b { (&a, &b) } else { (&b, &a) };

        // Two peers holding the SAME forked set in OPPOSITE arrival orders must
        // converge on the same tip; anything else serves different sites from the
        // same evidence.
        for order in [[loser_bytes, winner_bytes], [winner_bytes, loser_bytes]] {
            let (_dir, view) = temp_view("fork");
            for record in order {
                view.put(record).expect("puts");
            }
            let tip = view
                .chain_tip("split", "vayu")
                .expect("replays")
                .expect("a tip despite the fork");
            assert_eq!(
                tip.prev.hash,
                record_hash_from_bytes(winner_bytes),
                "the smaller digest wins whatever the insertion order"
            );
        }
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
    fn selection_orders_types_and_then_record_order() {
        use crate::record::{AliasTarget, Entry, EntryValue};
        let alice = identity(0xA4);
        let entry = |value| Entry { value, ttl: None };
        let cid_a = entry(EntryValue::Cid({
            let mut bytes = vec![0x01, 0x55, 0x12, 0x20];
            bytes.extend([7u8; 32]);
            bytes
        }));
        let cid_b = entry(EntryValue::Cid(vec![0xEE; 36]));
        let pointer = entry(EntryValue::Ipns("k51qzi5uqu5d".to_string()));
        let note = entry(EntryValue::Txt("v=vayuweb1".to_string()));
        let redirect = entry(EntryValue::Alias(AliasTarget {
            label: "target".to_string(),
            tld: "vayu".to_string(),
        }));
        let build = |entries: &[Entry]| {
            build_register(&alice, "order", "vayu", NOW + 60, entries, 0, None, LIMIT)
                .expect("builds")
        };

        // ipns beats cid regardless of wire order: the living pointer is the point.
        for entries in [
            [cid_a.clone(), pointer.clone()],
            [pointer.clone(), cid_a.clone()],
        ] {
            match selected_pointer(&build(&entries)) {
                Some(Selected::Ipns(text)) => assert_eq!(text, "k51qzi5uqu5d"),
                other => panic!("expected the ipns selection, got {other:?}"),
            }
        }
        // Within one type, record order decides — both ways, so an implementation
        // preferring a particular VALUE cannot pass by accident.
        for (entries, want) in [
            (vec![cid_a.clone(), cid_b.clone()], 7u8),
            (vec![cid_b.clone(), cid_a.clone()], 0xEEu8),
        ] {
            match selected_pointer(&build(&entries)) {
                Some(Selected::Cid(bytes)) => {
                    assert_eq!(bytes[4], want, "first in record order must win");
                }
                other => panic!("expected a cid selection, got {other:?}"),
            }
        }
        // txt is never a source; cid behind it still is.
        match selected_pointer(&build(&[note, cid_a])) {
            Some(Selected::Cid(_)) => {}
            other => panic!("expected cid behind a txt note, got {other:?}"),
        }
        // An alias is selected only when it is alone.
        match selected_pointer(&build(std::slice::from_ref(&redirect))) {
            Some(Selected::Alias(target)) => assert_eq!(target.label, "target"),
            other => panic!("expected the alias, got {other:?}"),
        }
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
