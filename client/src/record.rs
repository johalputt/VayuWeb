//! Registry record construction: the six operations, assembled and signed.
//!
//! The client-side counterpart of the assembly order in `registry/src/cli.ts`, validated
//! structurally like `registry/src/record.ts`. docs/spec/REGISTRY.md is authoritative for every
//! rule enforced here.
//!
//! ## What this module is, and what it is not
//!
//! This is THE client half of one protocol, not a rival dialect of it. Every byte it emits is
//! checked two ways before it can be called correct: the conformance vectors pin the shared
//! primitives (CBOR, salt derivation, difficulty schedule), and the golden fixtures under
//! `conformance/client-built.json` are fed through the registry's own verifier, which accepts
//! them or this module is broken. What it is NOT is a second implementation of verification —
//! a client that verified like a peer would need the log, and the desktop client's job is to
//! produce records, not to hold the network's state. Phase 6 still asks for an independent
//! implementation by strangers, and this crate does not satisfy it and must not be reported
//! as though it did.
//!
//! ## Why the builder refuses rather than emits-and-hopes
//!
//! A mistyped name or an under-funded proof of work is decidable before any expensive work
//! runs, and a refusal there saves the user an Argon2id solve followed by a rejection their
//! peers were always going to issue. The same philosophy as the CLI's: refuse before the work,
//! never waste the user's CPU on a foregone conclusion.

use crate::cbor::{self, CborError, Key, Value};
use crate::domain::{record_hash_from_bytes, signing_input};
use crate::identity::Identity;
use crate::names::{name_rejection, parse_alias, NameRejection};
use crate::pow::{required_bits, solve, SolveError, POW_ALGORITHM, POW_NONCE_LENGTH};

/// The protocol version implemented. A verifier rejects a major version it lacks.
pub const SUPPORTED_VERSION: u64 = 1;
/// Suite 1: Ed25519 over BLAKE2b-256, the launch suite.
pub const LAUNCH_SUITE: u64 = 1;
/// The suite identifier as it appears in the signing input, one byte wide by construction.
const LAUNCH_SUITE_BYTE: u8 = 1;

/// A registration term is exactly one year. Not "about" a year: an exact equality is checked.
pub const TERM_SECONDS: u64 = 31_536_000;
/// The renewal window opens 60 days before expiry.
pub const RENEWAL_WINDOW_SECONDS: u64 = 5_184_000;
/// Minimum gap between a record and its predecessor.
pub const MIN_INTERVAL_SECONDS: u64 = 300;
/// Grace extends a name's renewability past its expiry, owner only.
pub const GRACE_SECONDS: u64 = 2_592_000;
/// A TRANSFER takes effect fourteen days after its own `notBefore`.
pub const SETTLEMENT_SECONDS: u64 = 1_209_600;

/// Maximum number of entries in `records`.
pub const MAX_RECORD_ENTRIES: usize = 32;
/// Maximum size of a single entry value, bytes for byte strings, UTF-8 length for text.
pub const MAX_ENTRY_VALUE_BYTES: usize = 512;
/// Entry TTL bounds; advisory but validated so peers agree on what is well-formed.
pub const MIN_TTL: u64 = 60;
pub const MAX_TTL: u64 = 86_400;
pub const DEFAULT_TTL: u64 = 3_600;

/// `seq` is capped at 2^32-1.
pub const MAX_SEQ: u64 = 0xffff_ffff;

/// One resolved alias target, kept structured so a malformed target cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasTarget {
    pub label: String,
    pub tld: String,
}

/// An entry value, typed so each known type's shape rule is enforced at construction.
///
/// Unknown entry types exist on the wire and are stored and replicated unchanged but never
/// acted upon; a CLIENT has no reason to emit one, so none can be constructed here. If a VWIP
/// defines a new type, this enumeration gains it deliberately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryValue {
    /// A 32-byte peer key.
    Peer(Box<[u8; 32]>),
    /// An IPNS pointer, 1–128 characters.
    Ipns(String),
    /// A content identifier, 1–64 bytes.
    Cid(Vec<u8>),
    /// A text note, 1–255 UTF-8 bytes, no control characters.
    Txt(String),
    /// A redirect to another ratified name.
    Alias(AliasTarget),
}

/// Why a record could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// Encoding failed. Reaching this from a well-formed builder path is a defect in this
    /// module, not in the caller.
    Encode(CborError),
    /// Salt derivation failed for the same reason.
    Salt(CborError),
    /// The proof-of-work search exhausted its limit.
    PowExhausted,
    /// The label or TLD was refused, with the wire-visible reason.
    InvalidName(NameRejection),
    /// An entry violated its type's shape rule.
    BadEntry(&'static str),
    /// Too many entries for one record.
    TooManyEntries { found: usize },
    /// A successor arrived too soon after its predecessor.
    TooSoon,
    /// A RENEW outside its window: neither live-near-expiry nor within grace.
    OutsideRenewalWindow,
    /// The name is not renewable at all: expired past grace, or revoked.
    NotRenewable,
    /// The predecessor is not live, which every operation except RENEW requires.
    NotLive,
    /// A TRANSFER without enough remaining term to settle in.
    Unsettled,
    /// The predecessor is itself a TRANSFER that has not yet settled: until its horizon
    /// passes, only the passage of time changes anything on the name.
    Settling { settles_at: u64 },
    /// The predecessor bytes could not be understood. The caller handed over something this
    /// module did not build or never verified.
    BadPredecessor(&'static str),
    /// Signing failed. With a well-formed key material state this is unreachable; it exists so
    /// no error path is silently flattened into an encoding lie.
    Signing,
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encode(error) => write!(f, "encoding failed: {error}"),
            Self::Salt(error) => write!(f, "salt derivation failed: {error}"),
            Self::PowExhausted => write!(f, "no nonce satisfied the difficulty"),
            Self::InvalidName(rejection) => {
                write!(f, "{}: name refused ({rejection:?})", rejection.code())
            }
            Self::BadEntry(reason) => write!(f, "BAD_RECORD_ENTRY: {reason}"),
            Self::TooManyEntries { found } => {
                write!(
                    f,
                    "BAD_RECORD_ENTRY: {found} entries exceeds {MAX_RECORD_ENTRIES}"
                )
            }
            Self::TooSoon => write!(f, "TOO_SOON: too close to the predecessor"),
            Self::OutsideRenewalWindow => {
                write!(f, "TOO_EARLY: the renewal window is not open")
            }
            Self::NotRenewable => {
                write!(
                    f,
                    "NAME_TAKEN-shaped refusal: the name accepts no further renewal"
                )
            }
            Self::NotLive => write!(f, "EXPIRED: the predecessor is no longer live"),
            Self::Unsettled => write!(f, "UNSETTLED: not enough term remains to settle"),
            Self::Settling { settles_at } => {
                write!(
                    f,
                    "SETTLING: the preceding transfer settles at {settles_at}"
                )
            }
            Self::BadPredecessor(reason) => write!(f, "BAD_PREDECESSOR: {reason}"),
            Self::Signing => write!(f, "signing failed"),
        }
    }
}

impl std::error::Error for BuildError {}

/// An entry as the client offers it: a value plus an explicit-or-default TTL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub value: EntryValue,
    pub ttl: Option<u64>,
}

impl Entry {
    fn to_map(&self) -> Result<Vec<(Key, Value)>, BuildError> {
        // Shape rules mirror parseRecord exactly, so a record this module builds is one the
        // reference parser admits. Enforced HERE rather than discovered by a peer's rejection:
        // the difference between a form that validates and an error message from the network.
        let (entry_type, value): (&str, Value) = match &self.value {
            EntryValue::Peer(key) => ("peer", Value::Bytes(key.to_vec())),
            EntryValue::Ipns(text) => {
                let chars = text.chars().count();
                if !(1..=128).contains(&chars) || text.len() > MAX_ENTRY_VALUE_BYTES {
                    return Err(BuildError::BadEntry("ipns value must be 1-128 characters"));
                }
                ("ipns", Value::Text(text.clone()))
            }
            EntryValue::Cid(bytes) => {
                if bytes.is_empty() || bytes.len() > 64 {
                    return Err(BuildError::BadEntry("cid value must be 1-64 bytes"));
                }
                ("cid", Value::Bytes(bytes.clone()))
            }
            EntryValue::Txt(text) => {
                let size = text.len();
                if !(1..=255).contains(&size) {
                    return Err(BuildError::BadEntry("txt value must be 1-255 bytes"));
                }
                if text.chars().any(|c| (c as u32) < 0x20) {
                    return Err(BuildError::BadEntry(
                        "txt value must not contain control characters",
                    ));
                }
                ("txt", Value::Text(text.clone()))
            }
            EntryValue::Alias(target) => (
                "alias",
                Value::Text(format!("{}.{}", target.label, target.tld)),
            ),
        };
        Ok(vec![
            (Key::Text("type".into()), Value::Text(entry_type.into())),
            (Key::Text("value".into()), value),
            (
                Key::Text("ttl".into()),
                Value::UInt(self.ttl.unwrap_or(DEFAULT_TTL)),
            ),
        ])
    }
}

fn validate_ttl(ttl: Option<u64>) -> Result<(), BuildError> {
    match ttl {
        None => Ok(()),
        // The range guard is the acceptance condition; the value itself needs no name.
        Some(value) if (MIN_TTL..=MAX_TTL).contains(&value) => Ok(()),
        Some(_) => Err(BuildError::BadEntry("ttl out of range")),
    }
}

/// The facts about a name's current record a successor needs.
///
/// Supplied by the caller because index state is the caller's to know; this module stays a
/// pure function of its arguments, the same discipline the verifier keeps.
#[derive(Debug, Clone)]
pub struct Predecessor {
    pub seq: u64,
    /// The predecessor's operation, kept because one rule reads it: while a TRANSFER is
    /// settling, nothing but the passage of time succeeds on the name.
    pub op: PredecessorOp,
    pub not_before: u64,
    pub not_after: u64,
    /// The hash of the predecessor's exact accepted bytes — `prevHash`, not a re-encoding.
    pub hash: [u8; 32],
    /// Whether the current state came from a REVOKE, after which nothing may succeed.
    pub revoked: bool,
}

/// The six operations, as carried by a record's `op` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredecessorOp {
    Register,
    Renew,
    Update,
    Transfer,
    Relinquish,
    Revoke,
}

impl PredecessorOp {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "REGISTER" => Self::Register,
            "RENEW" => Self::Renew,
            "UPDATE" => Self::Update,
            "TRANSFER" => Self::Transfer,
            "RELINQUISH" => Self::Relinquish,
            "REVOKE" => Self::Revoke,
            _ => return None,
        })
    }
}

impl Predecessor {
    /// Derive the predecessor facts from exact record bytes, the way the CLI does when it
    /// looks the name up in its own log.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BuildError> {
        let value = cbor::decode(bytes)
            .map_err(|_| BuildError::BadPredecessor("bytes are not deterministic CBOR"))?;
        let Value::Map(entries) = value else {
            return Err(BuildError::BadPredecessor("a record is a CBOR map"));
        };

        let mut seq = None;
        let mut not_before = None;
        let mut not_after = None;
        let mut op = None;
        for (key, field) in &entries {
            let Key::Text(name) = key else { continue };
            match name.as_str() {
                "seq" => {
                    if let Value::UInt(v) = field {
                        seq = Some(*v)
                    }
                }
                "notBefore" => {
                    if let Value::UInt(v) = field {
                        not_before = Some(*v)
                    }
                }
                "notAfter" => {
                    if let Value::UInt(v) = field {
                        not_after = Some(*v)
                    }
                }
                "op" => {
                    if let Value::Text(text) = field {
                        op = Some(text.clone())
                    }
                }
                _ => {}
            }
        }
        let op_text = op.ok_or(BuildError::BadPredecessor("op missing"))?;
        Ok(Self {
            seq: seq.ok_or(BuildError::BadPredecessor("seq missing"))?,
            op: PredecessorOp::parse(&op_text)
                .ok_or(BuildError::BadPredecessor("unknown operation"))?,
            not_before: not_before.ok_or(BuildError::BadPredecessor("notBefore missing"))?,
            not_after: not_after.ok_or(BuildError::BadPredecessor("notAfter missing"))?,
            hash: record_hash_from_bytes(bytes),
            revoked: op_text == "REVOKE",
        })
    }
}

fn entries_field(list: &[Entry]) -> Result<Value, BuildError> {
    if list.len() > MAX_RECORD_ENTRIES {
        return Err(BuildError::TooManyEntries { found: list.len() });
    }
    // "At most one alias per record, and an alias MUST NOT coexist with another entry type,
    // because a name is either a pointer or a destination." Enforced here exactly as
    // parseRecord enforces it there: the builder refuses what the verifier would refuse,
    // before any signing key is touched.
    let alias_count = list
        .iter()
        .filter(|entry| matches!(entry.value, EntryValue::Alias(_)))
        .count();
    if alias_count > 1 {
        return Err(BuildError::BadEntry("at most one alias per record"));
    }
    if alias_count == 1 && list.len() > 1 {
        return Err(BuildError::BadEntry(
            "an alias must not coexist with another entry",
        ));
    }
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        validate_ttl(entry.ttl)?;
        out.push(Value::Map(entry.to_map()?));
    }
    Ok(Value::Array(out))
}

#[allow(clippy::too_many_arguments)]
fn skeleton(
    op: &str,
    label: &str,
    tld: &str,
    owner_key: &[u8; 32],
    seq: u64,
    not_before: u64,
    not_after: u64,
    entries: Value,
    pow_proof: Option<(u32, [u8; POW_NONCE_LENGTH])>,
    prev_hash: &[u8; 32],
) -> Vec<(Key, Value)> {
    let proof = match pow_proof {
        Some((bits, nonce)) => Value::Map(vec![
            (Key::Text("alg".into()), Value::Text(POW_ALGORITHM.into())),
            (Key::Text("bits".into()), Value::UInt(bits as u64)),
            (Key::Text("nonce".into()), Value::Bytes(nonce.to_vec())),
        ]),
        None => Value::Null,
    };
    vec![
        (Key::Text("version".into()), Value::UInt(SUPPORTED_VERSION)),
        (Key::Text("suite".into()), Value::UInt(LAUNCH_SUITE)),
        (Key::Text("op".into()), Value::Text(op.into())),
        (Key::Text("name".into()), Value::Text(label.into())),
        (Key::Text("tld".into()), Value::Text(tld.into())),
        (
            Key::Text("ownerKey".into()),
            Value::Bytes(owner_key.to_vec()),
        ),
        (Key::Text("seq".into()), Value::UInt(seq)),
        (Key::Text("notBefore".into()), Value::UInt(not_before)),
        (Key::Text("notAfter".into()), Value::UInt(not_after)),
        (Key::Text("records".into()), entries),
        (Key::Text("powProof".into()), proof),
        (
            Key::Text("prevHash".into()),
            Value::Bytes(prev_hash.to_vec()),
        ),
    ]
}

/// Canonicalise, derive the salt, search, then rebuild the skeleton carrying the winning nonce.
fn finish_pow_and_sign(
    mut record: Vec<(Key, Value)>,
    bits: u32,
    signer: &Identity,
    co_signer: Option<&Identity>,
    limit: u64,
) -> Result<Vec<u8>, BuildError> {
    // Solve against the SKELETON: the salt preimage strips the nonce anyway, so the zeroed
    // placeholder does not perturb the search. Solving before signing mirrors the CLI — a
    // signature is over bytes that already carry their final proof.
    let nonce = solve(&record, bits, limit).map_err(|error| match error {
        SolveError::Exhausted => BuildError::PowExhausted,
        SolveError::Salt(salt_error) => BuildError::Salt(salt_error),
        SolveError::Encode(encode_error) => BuildError::Encode(encode_error),
    })?;

    for (key, value) in record.iter_mut() {
        let Key::Text(name) = key else { continue };
        if name == "powProof" {
            *value = Value::Map(vec![
                (Key::Text("alg".into()), Value::Text(POW_ALGORITHM.into())),
                (Key::Text("bits".into()), Value::UInt(bits as u64)),
                (Key::Text("nonce".into()), Value::Bytes(nonce.to_vec())),
            ]);
        }
    }

    let input = signing_input(
        &cbor::encode(&Value::Map(record.clone())).map_err(BuildError::Encode)?,
        LAUNCH_SUITE_BYTE,
    );
    let signature = signer.sign(&input).map_err(|_| BuildError::Signing)?;
    record.push((Key::Text("sig".into()), Value::Bytes(signature.to_vec())));
    if let Some(co) = co_signer {
        let co_signature = co.sign(&input).map_err(|_| BuildError::Signing)?;
        record.push((
            Key::Text("coSig".into()),
            Value::Bytes(co_signature.to_vec()),
        ));
    }

    cbor::encode(&Value::Map(record)).map_err(BuildError::Encode)
}

/// Sign without proof of work: encode, sign, attach.
fn sign_without_pow(
    record: Vec<(Key, Value)>,
    signer: &Identity,
    co_signer: Option<&Identity>,
) -> Result<Vec<u8>, BuildError> {
    let input = signing_input(
        &cbor::encode(&Value::Map(record.clone())).map_err(BuildError::Encode)?,
        LAUNCH_SUITE_BYTE,
    );
    let signature = signer.sign(&input).map_err(|_| BuildError::Signing)?;
    let mut record = record;
    record.push((Key::Text("sig".into()), Value::Bytes(signature.to_vec())));
    if let Some(co) = co_signer {
        let co_signature = co.sign(&input).map_err(|_| BuildError::Signing)?;
        record.push((
            Key::Text("coSig".into()),
            Value::Bytes(co_signature.to_vec()),
        ));
    }
    cbor::encode(&Value::Map(record)).map_err(BuildError::Encode)
}

fn check_name(label: &str, tld: &str) -> Result<(), BuildError> {
    match name_rejection(label, tld) {
        Some(rejection) => Err(BuildError::InvalidName(rejection)),
        None => Ok(()),
    }
}

fn successor_gap_ok(prev: &Predecessor, now: u64) -> Result<(), BuildError> {
    if now < prev.not_before.saturating_add(MIN_INTERVAL_SECONDS) {
        return Err(BuildError::TooSoon);
    }
    Ok(())
}

/// Build and sign a REGISTER: the name's first record.
///
/// `window_count` is the TLD's registration count over the trailing window, as the CLI reads
/// it from its own log; `bits_override` lets a caller pay MORE than required (over-payment is
/// valid and harmless) but never less, which the verifier would refuse after the work ran.
#[allow(clippy::too_many_arguments)]
pub fn build_register(
    identity: &Identity,
    label: &str,
    tld: &str,
    now: u64,
    entries: &[Entry],
    window_count: u64,
    bits_override: Option<u32>,
    limit: u64,
) -> Result<Vec<u8>, BuildError> {
    check_name(label, tld)?;
    let required = required_bits(label.chars().count(), window_count);
    let bits = bits_override.unwrap_or(required);
    if bits < required {
        return Err(BuildError::BadEntry(
            "claimed difficulty below the requirement",
        ));
    }
    let zero_nonce = [0u8; POW_NONCE_LENGTH];
    let zero_hash = [0u8; 32];
    let record = skeleton(
        "REGISTER",
        label,
        tld,
        identity.public_key(),
        0,
        now,
        now + TERM_SECONDS,
        entries_field(entries)?,
        Some((bits, zero_nonce)),
        &zero_hash,
    );
    finish_pow_and_sign(record, bits, identity, None, limit)
}

/// Shared successor checks. RENEW relaxes liveness to live-or-grace; everything else wants a
/// live predecessor, because there is nothing to update, transfer or release once the term has
/// run out — and past grace the name is nobody's to act on.
///
/// The settling rule comes first among the state checks: while a TRANSFER is inside its
/// fourteen-day horizon the verifier accepts no successor of any kind, so building one would
/// only manufacture a rejection after the signing keys were touched.
fn check_successor_preamble(
    prev: &Predecessor,
    now: u64,
    allow_grace: bool,
) -> Result<(), BuildError> {
    if prev.op == PredecessorOp::Transfer {
        let settles_at = prev.not_before + SETTLEMENT_SECONDS;
        if now < settles_at {
            return Err(BuildError::Settling { settles_at });
        }
    }
    successor_gap_ok(prev, now)?;
    if prev.revoked {
        return Err(BuildError::NotRenewable);
    }
    if now < prev.not_before {
        return Err(BuildError::NotLive);
    }
    let live = now < prev.not_after;
    let grace = now < prev.not_after + GRACE_SECONDS;
    if allow_grace {
        if !grace {
            return Err(BuildError::NotRenewable);
        }
    } else if !live {
        return Err(BuildError::NotLive);
    }
    Ok(())
}

/// Build and sign a RENEW: extends from the existing expiry, never truncating a term.
///
/// Renewing early is how a term grows; the window opens sixty days before expiry so a renewal
/// cannot buy an unbounded future term, and grace exists so a missed renewal is recoverable.
pub fn build_renew(
    identity: &Identity,
    prev: &Predecessor,
    label: &str,
    tld: &str,
    now: u64,
    window_count: u64,
    limit: u64,
) -> Result<Vec<u8>, BuildError> {
    check_name(label, tld)?;
    check_successor_preamble(prev, now, true)?;

    // The window bound sits AFTER the gap check conceptually but is its own refusal: renewing
    // more than sixty days early would extend from prev.notAfter regardless, buying term for
    // one cheap proof. The verifier refuses TOO_EARLY; the builder refuses first.
    if now < prev.not_after.saturating_sub(RENEWAL_WINDOW_SECONDS) {
        return Err(BuildError::OutsideRenewalWindow);
    }

    let bits = required_bits(label.chars().count(), window_count);
    let zero_nonce = [0u8; POW_NONCE_LENGTH];
    let not_after = prev.not_after.max(now) + TERM_SECONDS;
    let record = skeleton(
        "RENEW",
        label,
        tld,
        identity.public_key(),
        prev.seq + 1,
        now,
        not_after,
        Value::Array(Vec::new()),
        Some((bits, zero_nonce)),
        &prev.hash,
    );
    finish_pow_and_sign(record, bits, identity, None, limit)
}

/// Build and sign an UPDATE: new entries, same term, no proof of work.
pub fn build_update(
    identity: &Identity,
    prev: &Predecessor,
    label: &str,
    tld: &str,
    now: u64,
    entries: &[Entry],
) -> Result<Vec<u8>, BuildError> {
    check_name(label, tld)?;
    check_successor_preamble(prev, now, false)?;
    let record = skeleton(
        "UPDATE",
        label,
        tld,
        identity.public_key(),
        prev.seq + 1,
        now,
        prev.not_after,
        entries_field(entries)?,
        None,
        &prev.hash,
    );
    sign_without_pow(record, identity, None)
}

/// Build and sign a TRANSFER: the outgoing owner signs; the incoming owner countersigns.
///
/// The countersignature is what makes transfer-to-a-key-nobody-holds impossible: without it a
/// fat-fingered recipient key would burn the name silently. Fourteen days of settlement delay
/// make an unwanted transfer recoverable by someone who notices in time — which requires term
/// remaining, checked here before anything expensive runs.
pub fn build_transfer(
    transferor: &Identity,
    recipient: &Identity,
    prev: &Predecessor,
    label: &str,
    tld: &str,
    now: u64,
) -> Result<Vec<u8>, BuildError> {
    check_name(label, tld)?;
    check_successor_preamble(prev, now, false)?;
    if prev.not_after - now < SETTLEMENT_SECONDS {
        return Err(BuildError::Unsettled);
    }
    let record = skeleton(
        "TRANSFER",
        label,
        tld,
        recipient.public_key(),
        prev.seq + 1,
        now,
        prev.not_after,
        Value::Array(Vec::new()),
        None,
        &prev.hash,
    );
    sign_without_pow(record, transferor, Some(recipient))
}

/// Build and sign a RELINQUISH: the owner says they are done. Grace is skipped; quarantine is
/// not, whose purpose is front-running rather than protecting the owner.
pub fn build_relinquish(
    identity: &Identity,
    prev: &Predecessor,
    label: &str,
    tld: &str,
    now: u64,
) -> Result<Vec<u8>, BuildError> {
    check_name(label, tld)?;
    check_successor_preamble(prev, now, false)?;
    let record = skeleton(
        "RELINQUISH",
        label,
        tld,
        identity.public_key(),
        prev.seq + 1,
        now,
        now,
        Value::Array(Vec::new()),
        None,
        &prev.hash,
    );
    sign_without_pow(record, identity, None)
}

/// Build and sign a REVOKE: the deadman switch. Resolution stops at once; the name stays
/// frozen for the rest of its term and then quarantines, accepting nothing from anyone.
pub fn build_revoke(
    identity: &Identity,
    prev: &Predecessor,
    label: &str,
    tld: &str,
    now: u64,
) -> Result<Vec<u8>, BuildError> {
    check_name(label, tld)?;
    check_successor_preamble(prev, now, false)?;
    let record = skeleton(
        "REVOKE",
        label,
        tld,
        identity.public_key(),
        prev.seq + 1,
        now,
        prev.not_after,
        Value::Array(Vec::new()),
        None,
        &prev.hash,
    );
    sign_without_pow(record, identity, None)
}

/// Parse a built record back into its fields, for callers that want to display what they just
/// produced. Deliberately minimal: the registry remains the thing that VERIFIES.
pub fn decode_record(bytes: &[u8]) -> Result<crate::cbor::Value, CborError> {
    cbor::decode(bytes)
}

/// Construct an alias target, refusing targets that could never exist.
pub fn alias(label: &str, tld: &str) -> Result<AliasTarget, BuildError> {
    match parse_alias(&format!("{label}.{tld}")) {
        Some(target) => Ok(AliasTarget {
            label: target.label,
            tld: target.tld,
        }),
        None => Err(BuildError::InvalidName(NameRejection::UnknownTld)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;

    fn test_identity(seed_byte: u8) -> Identity {
        let mut seed = vec![seed_byte; 32];
        Identity::from_seed(&mut seed).expect("test seed")
    }

    /// A live predecessor far from any boundary: registered "recently", expiring in a year.
    fn live_predecessor(now: u64) -> Predecessor {
        Predecessor {
            seq: 3,
            op: PredecessorOp::Update,
            not_before: now,
            not_after: now + TERM_SECONDS,
            hash: [0x42u8; 32],
            revoked: false,
        }
    }

    fn field<'a>(record: &'a [(Key, Value)], name: &str) -> &'a Value {
        record
            .iter()
            .find(|(key, _)| matches!(key, Key::Text(text) if text == name))
            .map(|(_, value)| value)
            .expect("field present")
    }

    #[test]
    fn a_register_builds_the_shape_the_specification_names() {
        let identity = test_identity(0xa1);
        let now = T0;
        let bytes = build_register(
            &identity,
            "builder-check-01",
            "vayu",
            now,
            &[Entry {
                value: EntryValue::Txt("v=test".into()),
                ttl: None,
            }],
            0,
            None,
            10_000,
        )
        .expect("builds");

        let decoded = cbor::decode(&bytes).expect("decodes");
        let Value::Map(record) = decoded else {
            panic!("a record is a map");
        };
        assert_eq!(field(&record, "op"), &Value::Text("REGISTER".into()));
        assert_eq!(
            field(&record, "name"),
            &Value::Text("builder-check-01".into())
        );
        assert_eq!(field(&record, "seq"), &Value::UInt(0));
        assert_eq!(field(&record, "notAfter"), &Value::UInt(now + TERM_SECONDS));
        // The proof carries a searched nonce, not the placeholder it was built with.
        let Value::Map(proof) = field(&record, "powProof") else {
            panic!("powProof is a map");
        };
        let Value::Bytes(nonce) = field(proof, "nonce") else {
            panic!("nonce is bytes");
        };
        assert_eq!(nonce.len(), POW_NONCE_LENGTH);
        assert!(nonce.iter().any(|&b| b != 0), "the search moved off zero");
        // The signature is present and is exactly an Ed25519 signature's length.
        assert!(matches!(field(&record, "sig"), Value::Bytes(bytes) if bytes.len() == 64));
    }

    #[test]
    fn building_twice_from_the_same_inputs_gives_identical_bytes() {
        let identity = test_identity(0xa2);
        let first = build_register(
            &identity,
            "builder-determin",
            "vayu",
            T0,
            &[],
            0,
            None,
            10_000,
        )
        .expect("first");
        let second = build_register(
            &identity,
            "builder-determin",
            "vayu",
            T0,
            &[],
            0,
            None,
            10_000,
        )
        .expect("second");
        assert_eq!(
            first, second,
            "Ed25519 signs deterministically and the walk is fixed"
        );
    }

    #[test]
    fn an_alias_is_a_pointer_and_nothing_else() {
        let identity = test_identity(0xa3);
        let prev = live_predecessor(T0);

        // A lone alias builds.
        let lone = build_update(
            &identity,
            &prev,
            "alias-pointer-1",
            "vayu",
            T0 + 600,
            &[Entry {
                value: EntryValue::Alias(alias("some-other-name", "vayu").expect("valid")),
                ttl: None,
            }],
        );
        assert!(lone.is_ok(), "a single alias entry is legal");

        // An alias beside anything else does not, even before signing runs.
        let mixed = build_update(
            &identity,
            &prev,
            "alias-pointer-1",
            "vayu",
            T0 + 600,
            &[
                Entry {
                    value: EntryValue::Txt("v=x".into()),
                    ttl: None,
                },
                Entry {
                    value: EntryValue::Alias(alias("some-other-name", "vayu").expect("valid")),
                    ttl: None,
                },
            ],
        );
        assert!(matches!(mixed, Err(BuildError::BadEntry(message)) if message.contains("coexist")));

        // Two aliases do not, either.
        let doubled = build_update(
            &identity,
            &prev,
            "alias-pointer-1",
            "vayu",
            T0 + 600,
            &[
                Entry {
                    value: EntryValue::Alias(alias("first-pointer-1", "vayu").expect("valid")),
                    ttl: None,
                },
                Entry {
                    value: EntryValue::Alias(alias("second-pointer", "vayu").expect("valid")),
                    ttl: None,
                },
            ],
        );
        assert!(
            matches!(doubled, Err(BuildError::BadEntry(message)) if message.contains("at most one"))
        );
    }

    #[test]
    fn renewal_refuses_too_early_and_extends_from_the_old_expiry() {
        let identity = test_identity(0xa4);
        let registered_at = T0;
        let prev = Predecessor {
            seq: 0,
            op: PredecessorOp::Register,
            not_before: registered_at,
            not_after: registered_at + TERM_SECONDS,
            hash: [0x11u8; 32],
            revoked: false,
        };

        // Sixty days minus one second before expiry: the window is not open yet.
        let too_early = registered_at + TERM_SECONDS - RENEWAL_WINDOW_SECONDS - 1;
        assert_eq!(
            build_renew(
                &identity,
                &prev,
                "renew-boundary",
                "vayu",
                too_early,
                0,
                10_000
            ),
            Err(BuildError::OutsideRenewalWindow)
        );

        // Thirty days before expiry: inside the window, and the term extends from the OLD
        // expiry rather than from now — renewal never truncates a term already paid for.
        let in_window = registered_at + TERM_SECONDS - 2_592_000;
        let renewed = build_renew(
            &identity,
            &prev,
            "renew-boundary",
            "vayu",
            in_window,
            0,
            10_000,
        )
        .expect("in-window renewal builds");
        let decoded = cbor::decode(&renewed).expect("decodes");
        let Value::Map(record) = decoded else {
            panic!("map")
        };
        assert_eq!(
            field(&record, "notAfter"),
            &Value::UInt(prev.not_after + TERM_SECONDS)
        );
    }

    #[test]
    fn a_transfer_needs_term_left_to_settle_in() {
        let transferor = test_identity(0xa5);
        let recipient = test_identity(0xa6);
        let now = T0;

        let short = Predecessor {
            seq: 1,
            op: PredecessorOp::Register,
            not_before: now - MIN_INTERVAL_SECONDS,
            not_after: now + SETTLEMENT_SECONDS - 1,
            hash: [0x21u8; 32],
            revoked: false,
        };
        assert_eq!(
            build_transfer(
                &transferor,
                &recipient,
                &short,
                "settlement-case",
                "vayu",
                now
            ),
            Err(BuildError::Unsettled)
        );

        let enough = Predecessor {
            seq: 1,
            op: PredecessorOp::Register,
            not_before: now - MIN_INTERVAL_SECONDS,
            not_after: now + SETTLEMENT_SECONDS,
            hash: [0x22u8; 32],
            revoked: false,
        };
        let transferred = build_transfer(
            &transferor,
            &recipient,
            &enough,
            "settlement-case",
            "vayu",
            now,
        )
        .expect("settles");
        let decoded = cbor::decode(&transferred).expect("decodes");
        let Value::Map(record) = decoded else {
            panic!("map")
        };
        // ownerKey names the RECIPIENT; both signatures ride along.
        assert_eq!(
            field(&record, "ownerKey"),
            &Value::Bytes(recipient.public_key().to_vec())
        );
        assert!(matches!(field(&record, "sig"), Value::Bytes(_)));
        assert!(matches!(field(&record, "coSig"), Value::Bytes(_)));
    }

    #[test]
    fn successors_respect_the_minimum_gap() {
        let identity = test_identity(0xa7);
        let prev = live_predecessor(T0);
        assert_eq!(
            build_update(
                &identity,
                &prev,
                "gap-respecting",
                "vayu",
                T0 + MIN_INTERVAL_SECONDS - 1,
                &[],
            ),
            Err(BuildError::TooSoon)
        );
        assert!(build_update(
            &identity,
            &prev,
            "gap-respecting",
            "vayu",
            T0 + MIN_INTERVAL_SECONDS,
            &[],
        )
        .is_ok());
    }

    #[test]
    fn nothing_succeeds_while_a_transfer_is_settling() {
        let identity = test_identity(0xa8);
        let transfer_at = T0;
        let prev = Predecessor {
            seq: 2,
            op: PredecessorOp::Transfer,
            not_before: transfer_at,
            not_after: transfer_at + TERM_SECONDS,
            hash: [0x51u8; 32],
            revoked: false,
        };
        // One second before the horizon: refused, and the error names when it lifts.
        let settling = build_update(
            &identity,
            &prev,
            "settling-name-1",
            "vayu",
            transfer_at + SETTLEMENT_SECONDS - 1,
            &[],
        );
        match settling {
            Err(BuildError::Settling { settles_at }) => {
                assert_eq!(settles_at, transfer_at + SETTLEMENT_SECONDS)
            }
            other => panic!("expected Settling, got {other:?}"),
        }
        // At the horizon itself the name is the recipient's to use.
        assert!(build_update(
            &identity,
            &prev,
            "settling-name-1",
            "vayu",
            transfer_at + SETTLEMENT_SECONDS,
            &[],
        )
        .is_ok());
    }

    #[test]
    fn a_revoked_name_accepts_nothing_from_anyone() {
        let identity = test_identity(0xa8);
        let prev = Predecessor {
            seq: 4,
            op: PredecessorOp::Revoke,
            not_before: T0,
            not_after: T0 + TERM_SECONDS,
            hash: [0x31u8; 32],
            revoked: true,
        };
        assert_eq!(
            build_update(&identity, &prev, "revoked-target", "vayu", T0 + 600, &[]),
            Err(BuildError::NotRenewable)
        );
    }

    #[test]
    fn an_expired_name_refuses_updates_but_renews_through_grace() {
        let identity = test_identity(0xa9);
        let expired_at = T0;
        let past_grace = Predecessor {
            seq: 0,
            op: PredecessorOp::Register,
            not_before: expired_at - TERM_SECONDS,
            not_after: expired_at,
            hash: [0x41u8; 32],
            revoked: false,
        };

        // Past grace, nothing succeeds: the name has left its owner's hands entirely.
        let long_after = expired_at + GRACE_SECONDS + 1;
        assert_eq!(
            build_renew(
                &identity,
                &past_grace,
                "grace-boundary",
                "vayu",
                long_after,
                0,
                10_000
            ),
            Err(BuildError::NotRenewable)
        );

        // Inside grace a RENEW still works, starting its new term from NOW — the old expiry
        // is history by then, so extending from it would hand out free time.
        let within_grace = expired_at + GRACE_SECONDS - 1;
        let renewed = build_renew(
            &identity,
            &past_grace,
            "grace-boundary",
            "vayu",
            within_grace,
            0,
            10_000,
        )
        .expect("grace renewal builds");
        let decoded = cbor::decode(&renewed).expect("decodes");
        let Value::Map(record) = decoded else {
            panic!("map")
        };
        assert_eq!(
            field(&record, "notAfter"),
            &Value::UInt(within_grace + TERM_SECONDS)
        );

        // But an UPDATE demands a LIVE predecessor — no content changes after expiry.
        assert_eq!(
            build_update(
                &identity,
                &past_grace,
                "grace-boundary",
                "vayu",
                within_grace,
                &[]
            ),
            Err(BuildError::NotLive)
        );
    }

    const T0: u64 = 1_900_000_000;
}
