//! The equivocation ledger: where a detection goes so that it survives the process that made it.
//!
//! docs/spec/REPLICATION.md section 6 is authoritative, and 6.3 is a MUST and a SHOULD:
//!
//! > A peer detecting equivocation MUST record it and SHOULD forward the evidence.
//!
//! The client could already DETECT a fork — `vayu import` judges every pair of records in a
//! bundle before it judges anything singly, because two records at one `seq` by one owner are
//! equivocation evidence whatever the verifier would later say about either half's validity. What
//! it could not do was keep the evidence in a form anybody could read, forward, or bound.
//!
//! ## Why the log cannot be the ledger
//!
//! The evidence is a *pair*, and the log can only ever hold one half of it. Equivocation is found
//! when a record arrives that conflicts with one already held: the incumbent is in the log and
//! the newcomer is refused, so the newcomer's bytes go nowhere. Without somewhere else to put it,
//! the refused half is unrecoverable and the detection is gone the moment the function returns.
//!
//! ## What a hostile peer can do to a ledger, which sets every bound below
//!
//! 6.2.4 forbids requiring either record to be **acceptable** — no proof of work, no expiry, no
//! chain position — and it is right to: requiring them would hand an equivocator a one-line
//! evasion. Break your own proof of work in both halves and no report of you can be verified. The
//! consequence is that **minting verifiable evidence costs two signatures and nothing else.** The
//! price is paid here, in three places:
//!
//! - **Identity, not bytes, is the deduplication key.** Two records at one `seq` for one name by
//!   one owner are one fact. Varying `notBefore` by a second mints unlimited distinct *pairs*
//!   about that one fact; keying on the encodings would be an unbounded stream. The key is
//!   `(ownerKey, tld, name, seq)`, and a fact already recorded is a duplicate, not a new entry.
//!
//! - **Two budgets, and one cannot spend the other's.** A report this peer *detected* is
//!   anchored to a record in its own log, and every record in that log cost a proof of work — so
//!   the count is bounded by work somebody did. A report a peer *sent* is bounded by nothing, so
//!   it gets its own smaller budget and can never displace a detection.
//!
//! - **A full budget refuses; it never evicts.** Eviction would let an attacker flush a genuine
//!   report by minting cheap ones after it. Refusing means an attacker can instead deny space to
//!   later genuine third-party reports — the other half of the same trade, stated rather than
//!   hidden.
//!
//! ## And what it is not
//!
//! 6.4: **this protocol does not punish equivocation.** Nothing here is a blocklist, a score or an
//! input to any decision. No name is lost, no key is excluded, and nothing in the resolver or the
//! verifier reads this file. It is a legible record, which Article 38 asks for, and what a reader
//! does with it is not the protocol's business. A mechanism able to act on evidence is a mechanism
//! able to act on manufactured evidence, so this one acts on nothing.

use std::path::{Path, PathBuf};

use crate::verify::{equivocation_key, is_equivocation_evidence};

/// Where a report came from, which is the only thing that distinguishes the two budgets.
///
/// `Detected` is anchored to this peer's own log. `Received` arrived over a wire from a party this
/// peer knows nothing about, and REPLICATION.md is explicit that it knows nothing about them:
/// "there is no trusted peer". Both are verified identically — the origin buys no credibility, only
/// a different bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceOrigin {
    /// Found in this node's own log or bundle.
    Detected,
    /// Sent by a peer.
    Received,
}

impl EvidenceOrigin {
    /// The name this origin is stored under.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::Received => "received",
        }
    }

    /// Parse the stored name, refusing anything else.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "detected" => Some(Self::Detected),
            "received" => Some(Self::Received),
            _ => None,
        }
    }

    /// The budget this origin spends from, as the protocol sets it.
    pub fn limit(self) -> usize {
        match self {
            // Generous, because each detection is anchored to a record in this peer's own log, and
            // every record in that log carried a proof of work somebody paid for. A thousand of
            // them is a thousand solves.
            Self::Detected => DETECTED_LIMIT,
            // An order of magnitude smaller, because this is the number that costs an attacker two
            // signatures each.
            Self::Received => RECEIVED_LIMIT,
        }
    }
}

/// Reports found in this node's own log.
pub const DETECTED_LIMIT: usize = 1_024;
/// Reports sent by a peer.
pub const RECEIVED_LIMIT: usize = 256;

/// One report as the ledger holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pub origin: EvidenceOrigin,
    /// `(ownerKey, tld, name, seq)`. The identity of the fact, not of the pair.
    pub key: String,
    /// The two record encodings, which are the whole of the evidence.
    pub a: Vec<u8>,
    pub b: Vec<u8>,
}

/// What [`EvidenceLedger::record`] did, reported rather than inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// Added to the ledger.
    Recorded,
    /// The fact was already recorded. The same fact, whatever it is encoded as.
    Duplicate,
    /// The pair did not verify, so it names nobody and proves nothing.
    Unverified,
    /// The budget for this origin is spent. Nothing was evicted.
    Full,
}

impl RecordOutcome {
    /// The name this outcome is reported under.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Duplicate => "duplicate",
            Self::Unverified => "unverified",
            Self::Full => "full",
        }
    }
}

/// How many reports a ledger turned away, by reason. Zero is the ordinary state; anything else is
/// news.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Refusals {
    /// Reports that did not verify.
    pub unverified: u64,
    /// Reports refused because their budget was full.
    pub full: u64,
    /// Entries on disk that could not be read back, which includes a truncated tail.
    pub unreadable: u64,
}

/// Why a ledger could not be opened or written.
#[derive(Debug)]
pub enum EvidenceError {
    /// The ledger file could not be read or written.
    Io(String),
    /// The ledger file could not be parsed.
    Malformed(String),
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(detail) => write!(f, "{detail}"),
            Self::Malformed(detail) => write!(f, "malformed evidence ledger: {detail}"),
        }
    }
}

impl std::error::Error for EvidenceError {}

/// A durable, bounded, deduplicating record of the equivocation this peer knows about.
///
/// ## Replay verifies, exactly as the log does
///
/// A file an attacker can append to is not a file whose contents are known-good. Every entry is
/// re-verified on load with the same check a wire report passes, so appending a fabricated pair
/// by hand achieves nothing: it is dropped on the next open and counted in [`Refusals::unreadable`].
///
/// It differs from the log in what it does about a bad entry, and the difference is deliberate. A
/// log entry that no longer verifies makes the whole store unopenable, because the state derived
/// from the log would be wrong and there is no safe way to continue. A ledger entry that does not
/// verify is a lie about somebody else's conduct, and a lie is exactly what a ledger must not
/// carry: it is dropped, counted, and the rest of the ledger stands.
pub struct EvidenceLedger {
    path: PathBuf,
    entries: Vec<LedgerEntry>,
    refusals: Refusals,
    /// The effective budgets, never larger than the protocol's.
    limits: Limits,
}

/// The two budgets, in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub detected: usize,
    pub received: usize,
}

impl Limits {
    /// The protocol's bounds.
    pub fn protocol() -> Self {
        Self {
            detected: DETECTED_LIMIT,
            received: RECEIVED_LIMIT,
        }
    }

    /// A budget for one origin.
    pub fn get(&self, origin: EvidenceOrigin) -> usize {
        match origin {
            EvidenceOrigin::Detected => self.detected,
            EvidenceOrigin::Received => self.received,
        }
    }
}

impl EvidenceLedger {
    /// Open (or create) the ledger belonging to a view.
    ///
    /// The file is one JSON object per line. A line that does not parse, or whose pair does not
    /// verify, is dropped and counted; the file is rewritten on the next write, so a hand-edited
    /// ledger cannot outlive an open.
    pub fn open(dir: &Path) -> Result<Self, EvidenceError> {
        Self::open_with_limits(dir, Limits::protocol())
    }

    /// Open a ledger with tighter budgets.
    ///
    /// **Never looser.** A caller may spend less than the protocol allows — a small budget is a
    /// policy choice, and one that can be tested without minting a thousand pairs — but a budget
    /// above the protocol's would undo the only thing the bound is for. So the request is
    /// clamped, and a caller asking for more gets the protocol's number rather than its own.
    pub fn open_with_limits(dir: &Path, limits: Limits) -> Result<Self, EvidenceError> {
        let limits = Limits {
            detected: limits.detected.min(DETECTED_LIMIT),
            received: limits.received.min(RECEIVED_LIMIT),
        };
        let path = dir.join("ledger.jsonl");
        let mut ledger = Self {
            path,
            entries: Vec::new(),
            refusals: Refusals::default(),
            limits,
        };
        if ledger.path.exists() {
            let text = std::fs::read_to_string(&ledger.path).map_err(|e| {
                EvidenceError::Io(format!("cannot read {}: {e}", ledger.path.display()))
            })?;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Some(entry) = parse_entry(line) else {
                    // A line that does not parse is not a report at all.
                    ledger.refusals.unreadable += 1;
                    continue;
                };
                // **Through the same door a wire report comes in by, budgets and all.** A file is
                // not a privileged source; it is a source whose author had write access to a
                // path. So an entry on disk is verified, deduplicated and charged to a budget
                // exactly as a report from a peer would be, and the outcome is counted.
                let outcome = ledger.admit(&entry.a, &entry.b, entry.origin, false)?;
                if outcome != RecordOutcome::Recorded {
                    ledger.refusals.unreadable += 1;
                }
            }
        }
        // The repair is durable: a hand-edited ledger cannot outlive an open, because the open
        // that noticed writes back what actually verified.
        if ledger.refusals.unreadable > 0 {
            ledger.write()?;
        }
        Ok(ledger)
    }

    /// Where this ledger lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The reports this ledger holds, in the order they were recorded.
    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    /// How many reports this ledger turned away, and why.
    pub fn refusals(&self) -> Refusals {
        self.refusals
    }

    /// Is there nothing to be gained by looking for the other half of this fact?
    ///
    /// True when the fact is already recorded — under EITHER origin, because one fact is one
    /// fact and it is recorded once — or when the budget it would go in is full. It exists so a
    /// caller can answer in a map lookup rather than by scanning the ledger.
    pub fn settled(&self, key: &str, origin: EvidenceOrigin) -> bool {
        self.entries.iter().any(|entry| entry.key == key)
            || self.count(origin) >= self.limits.get(origin)
    }

    /// How many reports this ledger holds against one origin.
    pub fn count(&self, origin: EvidenceOrigin) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.origin == origin)
            .count()
    }

    /// Record a pair, if it is evidence and the ledger has room.
    ///
    /// The pair is verified first, from its own two encodings and nothing else: a report that
    /// must be believed is a report that can be faked.
    pub fn record(
        &mut self,
        a: &[u8],
        b: &[u8],
        origin: EvidenceOrigin,
    ) -> Result<RecordOutcome, EvidenceError> {
        self.admit(a, b, origin, true)
    }

    /// The one door every report comes through — from a peer, or from this ledger's own file.
    ///
    /// Verification first, because everything after it — the identity used for deduplication, the
    /// budget it is charged to, the bytes written to disk — is derived from a pair that has been
    /// checked. A ledger that deduplicated before verifying could be taught to reject a genuine
    /// report by being shown a forged one with the same identity first.
    fn admit(
        &mut self,
        a: &[u8],
        b: &[u8],
        origin: EvidenceOrigin,
        persist: bool,
    ) -> Result<RecordOutcome, EvidenceError> {
        if !is_equivocation_evidence(a, b) {
            self.refusals.unverified += 1;
            return Ok(RecordOutcome::Unverified);
        }
        let key = equivocation_key(a).ok_or_else(|| {
            EvidenceError::Malformed(
                "the pair verified but its identity could not be read".to_string(),
            )
        })?;
        // And a duplicate is a duplicate even when the budget is also spent: the fact is
        // already recorded, and saying "full" instead would report a disk condition where the
        // truth is that this report was never going to be stored.
        if self.entries.iter().any(|entry| entry.key == key) {
            return Ok(RecordOutcome::Duplicate);
        }
        if self.count(origin) >= self.limits.get(origin) {
            self.refusals.full += 1;
            return Ok(RecordOutcome::Full);
        }
        let entry = LedgerEntry {
            origin,
            key,
            a: a.to_vec(),
            b: b.to_vec(),
        };
        if persist {
            self.append(&entry)?;
        }
        self.entries.push(entry);
        Ok(RecordOutcome::Recorded)
    }

    /// Add one entry to the ledger file.
    ///
    /// Appended rather than rewritten: the file grows by one line per report, so recording a
    /// detection costs what the detection costs and not what the whole ledger costs.
    fn append(&self, entry: &LedgerEntry) -> Result<(), EvidenceError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                EvidenceError::Io(format!("cannot create {}: {e}", parent.display()))
            })?;
        }
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| EvidenceError::Io(format!("cannot open {}: {e}", self.path.display())))?;
        writeln!(file, "{}", render_entry(entry))
            .map_err(|e| EvidenceError::Io(format!("cannot write {}: {e}", self.path.display())))
    }

    /// Write the ledger out.
    fn write(&self) -> Result<(), EvidenceError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                EvidenceError::Io(format!("cannot create {}: {e}", parent.display()))
            })?;
        }
        let mut text = String::new();
        for entry in &self.entries {
            text.push_str(&render_entry(entry));
            text.push('\n');
        }
        std::fs::write(&self.path, text)
            .map_err(|e| EvidenceError::Io(format!("cannot write {}: {e}", self.path.display())))
    }
}

/// One ledger line, as a JSON object.
fn render_entry(entry: &LedgerEntry) -> String {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "{{\"origin\": \"{}\", \"key\": \"{}\", \"a\": \"{}\", \"b\": \"{}\"}}",
        entry.origin.as_str(),
        entry.key,
        hex(&entry.a),
        hex(&entry.b)
    )
}

/// Read one ledger line.
///
/// Deliberately hand-parsed rather than pulled from a JSON library: the client has no JSON
/// dependency, and a ledger line is four fields with a fixed shape.
fn parse_entry(line: &str) -> Option<LedgerEntry> {
    let origin = EvidenceOrigin::parse(&field(line, "origin")?)?;
    let key = field(line, "key")?.to_string();
    let a = unhex(&field(line, "a")?)?;
    let b = unhex(&field(line, "b")?)?;
    Some(LedgerEntry { origin, key, a, b })
}

/// The value of one `"name": "value"` field, if the line has it.
fn field(line: &str, name: &str) -> Option<String> {
    let needle = format!("\"{name}\": \"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Decode a hex string into bytes.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let chars: Vec<char> = text.chars().collect();
    for pair in chars.chunks(2) {
        let high = pair[0].to_digit(16)? as u8;
        let low = pair[1].to_digit(16)? as u8;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_round_trips() {
        let entry = LedgerEntry {
            origin: EvidenceOrigin::Detected,
            key: "aa tld name 3".to_string(),
            a: vec![0xde, 0xad],
            b: vec![0xbe, 0xef],
        };
        let parsed = parse_entry(&render_entry(&entry)).expect("parses");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn a_malformed_line_is_refused_rather_than_guessed_at() {
        assert!(parse_entry("not json at all").is_none());
        assert!(parse_entry(
            "{\"origin\": \"invented\", \"key\": \"k\", \"a\": \"\", \"b\": \"\"}"
        )
        .is_none());
        // Odd length is not hex.
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    fn the_two_budgets_are_separate() {
        assert!(EvidenceOrigin::Detected.limit() > EvidenceOrigin::Received.limit());
        assert_eq!(EvidenceOrigin::Detected.limit(), DETECTED_LIMIT);
        assert_eq!(EvidenceOrigin::Received.limit(), RECEIVED_LIMIT);
    }

    /// Two registrations of one name by one key: the textbook fork, and a pair that verifies
    /// from its own bytes alone.
    fn fork(now: u64) -> (Vec<u8>, Vec<u8>) {
        let mut seed = vec![0x37u8; 32];
        let id = crate::identity::Identity::from_seed(&mut seed).expect("an identity");
        let left =
            crate::record::build_register(&id, "split", "vayu", now, &[], 0, None, 10_000_000)
                .expect("registers");
        let right = crate::record::build_register(
            &id,
            "split",
            "vayu",
            now + 1_000,
            &[],
            0,
            None,
            10_000_000,
        )
        .expect("registers");
        (left, right)
    }

    #[test]
    fn a_fact_is_one_entry_whichever_origin_reports_it() {
        // **The origin selects the BUDGET, not the identity.** The same fork can reach a node two
        // ways — a bundle carrying both halves (it arrived) and a refusal against a record the
        // node already holds (it was detected here) — and it is ONE fact. Storing it twice would
        // mean forwarding it twice and counting it twice, and the two entries would disagree
        // about which budget the fact was charged to.
        let dir = std::env::temp_dir().join(format!("vayu-evidence-origin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut ledger = EvidenceLedger::open(&dir).expect("opens");
        let (left, right) = fork(1_800_000_000);
        assert_eq!(
            ledger
                .record(&left, &right, EvidenceOrigin::Received)
                .expect("records"),
            RecordOutcome::Recorded
        );
        // The same fact, from the other door.
        assert_eq!(
            ledger
                .record(&left, &right, EvidenceOrigin::Detected)
                .expect("records"),
            RecordOutcome::Duplicate
        );
        assert_eq!(ledger.entries().len(), 1);
        // And the entry is charged to the budget it arrived under.
        assert_eq!(ledger.count(EvidenceOrigin::Received), 1);
        assert_eq!(ledger.count(EvidenceOrigin::Detected), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_same_fact_is_one_entry_however_it_is_encoded() {
        // Varying a field the evidence does not mention mints a DIFFERENT PAIR about the SAME
        // FACT. Keyed on the encodings that is an unbounded stream; keyed on the fact it is one
        // entry, and the second report is a duplicate.
        let dir = std::env::temp_dir().join(format!("vayu-evidence-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut ledger = EvidenceLedger::open(&dir).expect("opens");
        let (left, right) = fork(1_800_000_000);
        assert_eq!(
            ledger
                .record(&left, &right, EvidenceOrigin::Detected)
                .expect("records"),
            RecordOutcome::Recorded
        );
        // The same two records, in the other order: the same fact.
        assert_eq!(
            ledger
                .record(&right, &left, EvidenceOrigin::Detected)
                .expect("records"),
            RecordOutcome::Duplicate
        );
        assert_eq!(ledger.entries().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_full_budget_refuses_and_never_evicts() {
        // Eviction would let an attacker flush a genuine report by minting cheap ones after it.
        let dir = std::env::temp_dir().join(format!("vayu-evidence-full-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut ledger = EvidenceLedger::open_with_limits(
            &dir,
            Limits {
                detected: 1,
                received: 1,
            },
        )
        .expect("opens");
        let (left, right) = fork(1_800_000_000);
        assert_eq!(
            ledger
                .record(&left, &right, EvidenceOrigin::Detected)
                .expect("records"),
            RecordOutcome::Recorded
        );
        // A different fact, and the budget is spent: refused, and nothing evicted.
        let mut other_seed = vec![0x38u8; 32];
        let other = crate::identity::Identity::from_seed(&mut other_seed).expect("an identity");
        let other_left = crate::record::build_register(
            &other,
            "other",
            "vayu",
            1_800_000_000,
            &[],
            0,
            None,
            10_000_000,
        )
        .expect("registers");
        let other_right = crate::record::build_register(
            &other,
            "other",
            "vayu",
            1_800_001_000,
            &[],
            0,
            None,
            10_000_000,
        )
        .expect("registers");
        assert_eq!(
            ledger
                .record(&other_left, &other_right, EvidenceOrigin::Detected)
                .expect("records"),
            RecordOutcome::Full
        );
        assert_eq!(ledger.entries().len(), 1, "nothing may be evicted");
        assert_eq!(ledger.refusals().full, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_budget_can_be_tighter_but_never_looser() {
        let dir = std::env::temp_dir().join(format!("vayu-evidence-limits-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ledger = EvidenceLedger::open_with_limits(
            &dir,
            Limits {
                detected: DETECTED_LIMIT * 10,
                received: RECEIVED_LIMIT * 10,
            },
        )
        .expect("opens");
        assert_eq!(ledger.limits.detected, DETECTED_LIMIT);
        assert_eq!(ledger.limits.received, RECEIVED_LIMIT);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pair_that_does_not_verify_is_refused_and_counted() {
        let dir = std::env::temp_dir().join(format!("vayu-evidence-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut ledger = EvidenceLedger::open(&dir).expect("opens");
        let (left, _right) = fork(1_800_000_000);
        // The same half twice is not a fork.
        assert_eq!(
            ledger
                .record(&left, &left, EvidenceOrigin::Detected)
                .expect("records"),
            RecordOutcome::Unverified
        );
        assert_eq!(ledger.entries().len(), 0);
        assert_eq!(ledger.refusals().unverified, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
