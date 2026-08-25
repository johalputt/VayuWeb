//! Verifying a record RECEIVED from somewhere else, in its exact bytes.
//!
//! `record.rs` BUILDS records and refuses what a peer would refuse; this module is the peer.
//! It mirrors the implementation of record's `verify.ts` step for step — same order, same
//! rejection codes, same deliberate placements (a cheap check whose outcome is a REJECTION
//! runs before the expensive Argon2id evaluation; a cheap check whose outcome is a DEFER runs
//! after it, because deferral costs memory and must be earned). The two languages already agree
//! byte for byte on what a record IS (`conformance/client-built.json`); this module closes the
//! loop on what a record MEANS, which is the prerequisite for ever accepting one from anyone.
//!
//! Single-record scope, stated plainly: without a registry view there is no incumbent set, so
//! REGISTER's NAME_TAKEN is not answerable here and is deliberately absent. Everything else —
//! framing, structure, canonicality, chain discipline against an optional predecessor, term
//! rules per operation, signature under the CONTROLLING key, countersignature on transfers,
//! proof of work against the difficulty the name's TLD currently demands, and clock discipline
//! with its defer-not-reject asymmetry — is checked exactly as specified.

use crate::cbor::{self, Key, Value};
use crate::domain::{core_of, encode_core, record_hash_from_bytes, signing_input};
use crate::identity::Identity;
use crate::names;
use crate::pow::{self, POW_NONCE_LENGTH};
use crate::record::{
    decode_record, GRACE_SECONDS, MAX_RECORD_ENTRIES, SETTLEMENT_SECONDS, TERM_SECONDS,
};

/// Framing ceiling for a suite-1 record — `maxRecordBytes` of the launch suite in
/// suites.ts, which is the only suite this crate speaks.
pub const MAX_RECORD_BYTES: usize = 4096;

/// One year, the registration term.
pub const TERM: u64 = TERM_SECONDS;
/// Grace after expiry during which only RENEW is accepted.
pub const GRACE: u64 = GRACE_SECONDS;
/// How long a TRANSFER takes to settle.
pub const SETTLEMENT: u64 = SETTLEMENT_SECONDS;
/// Successor interval minimum.
pub const MIN_INTERVAL: u64 = 300;
/// Clock skew tolerated before a record is HELD rather than judged.
pub const MAX_CLOCK_SKEW: u64 = 300;
/// How far in the past a record's own `notBefore` may sit.
pub const MAX_BACKDATE: u64 = 86_400;
/// Quarantine length after expiry or relinquish.
pub const QUARANTINE_SECONDS: u64 = 2_592_000;

/// What the verifier decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The record is acceptable as received.
    Accept,
    /// The record is refused, with the same codes the implementation of record uses.
    Reject { code: &'static str, detail: String },
    /// The record is neither good nor bad yet: its clock has not caught up. Held, not rejected.
    Defer { detail: String },
}

impl Verdict {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accept)
    }
}

fn reject(code: &'static str, detail: impl Into<String>) -> Verdict {
    Verdict::Reject {
        code,
        detail: detail.into(),
    }
}

// ---------------------------------------------------------------------------
// The predecessor view: everything chain discipline needs about the record a
// successor claims to follow. Parsed from that record's EXACT bytes, because
// prevHash is taken over bytes and a re-encoding is not those bytes.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PrevView {
    pub op_text: String,
    pub seq: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub owner_key: [u8; 32],
    /// The key that signed the predecessor — the transferor on a TRANSFER, else the owner.
    pub signer_key: [u8; 32],
    pub suite: u8,
    pub hash: [u8; 32],
    pub revoked: bool,
}

/// Parse a predecessor view from a previous record's exact accepted bytes. A predecessor that
/// is a TRANSFER needs its TRANSFEROR key supplied — `ownerKey` on a transfer names the
/// RECIPIENT, and until settlement the transferor still controls the name.
pub fn prev_view(bytes: &[u8], transferor_key: Option<&[u8; 32]>) -> Result<PrevView, String> {
    let value = decode_record(bytes).map_err(|e| format!("predecessor does not decode: {e}"))?;
    let Value::Map(members) = value else {
        return Err("a predecessor is a CBOR map".to_string());
    };
    let get = |name: &str| -> Option<&Value> {
        members.iter().find_map(|(k, v)| match k {
            Key::Text(text) if text == name => Some(v),
            _ => None,
        })
    };
    let op_text = match get("op") {
        Some(Value::Text(op)) => op.clone(),
        _ => return Err("predecessor has no op".to_string()),
    };
    let owner_key = key32(get("ownerKey").ok_or("predecessor has no ownerKey")?)?;
    let signer_key = if op_text == "TRANSFER" {
        match transferor_key {
            Some(key) => *key,
            None => {
                return Err(
                    "a TRANSFER predecessor needs its transferor key (--transferor-key): \
                     ownerKey names the recipient, who does not control the name yet"
                        .to_string(),
                )
            }
        }
    } else {
        owner_key
    };
    Ok(PrevView {
        op_text,
        seq: uint(get("seq").ok_or("predecessor has no seq")?)?,
        not_before: uint(get("notBefore").ok_or("predecessor has no notBefore")?)?,
        not_after: uint(get("notAfter").ok_or("predecessor has no notAfter")?)?,
        owner_key,
        signer_key,
        suite: u8::try_from(uint(get("suite").ok_or("predecessor has no suite")?)?)
            .map_err(|_| "predecessor suite out of range".to_string())?,
        hash: record_hash_from_bytes(bytes),
        revoked: false,
    })
}

fn key32(value: &Value) -> Result<[u8; 32], String> {
    match value {
        Value::Bytes(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(bytes);
            Ok(out)
        }
        _ => Err("expected 32-byte key".to_string()),
    }
}

fn uint(value: &Value) -> Result<u64, String> {
    match value {
        Value::UInt(n) => Ok(*n),
        _ => Err("expected an unsigned integer".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Structure: what parseRecord enforces before anything cryptographic runs.
// ---------------------------------------------------------------------------

struct ParsedRecord {
    map: Vec<(Key, Value)>,
    op: String,
    label: String,
    tld: String,
    seq: u64,
    not_before: u64,
    not_after: u64,
    owner_key: [u8; 32],
    sig: Vec<u8>,
    co_sig: Option<Vec<u8>>,
    suite: u8,
    pow_bits: Option<u32>,
    pow_nonce: Option<[u8; POW_NONCE_LENGTH]>,
}

fn field<'a>(members: &'a [(Key, Value)], name: &str) -> Option<&'a Value> {
    members.iter().find_map(|(k, v)| match k {
        Key::Text(text) if text == name => Some(v),
        _ => None,
    })
}

fn parse_record(value: &Value) -> Result<ParsedRecord, Verdict> {
    let Value::Map(members) = value else {
        return Err(reject("NOT_A_MAP", "record must be a CBOR map"));
    };
    let bad = |code: &'static str, detail: &str| reject(code, detail);

    let version = uint(field(members, "version").ok_or(bad("BAD_VERSION", "no version"))?)
        .map_err(|_| bad("BAD_VERSION", "version is not an integer"))?;
    if version != 1 {
        return Err(reject("BAD_VERSION", format!("unknown version {version}")));
    }

    let Value::Text(op) = field(members, "op").ok_or(bad("UNKNOWN_OP", "no op"))? else {
        return Err(reject("UNKNOWN_OP", "op is not text"));
    };
    if !matches!(
        op.as_str(),
        "REGISTER" | "RENEW" | "UPDATE" | "TRANSFER" | "RELINQUISH" | "REVOKE"
    ) {
        return Err(reject("UNKNOWN_OP", format!("unknown operation {op:?}")));
    }

    let Value::Text(label) = field(members, "name").ok_or(bad("BAD_NAME", "no name"))? else {
        return Err(reject("BAD_NAME", "name is not text"));
    };
    let Value::Text(tld) = field(members, "tld").ok_or(bad("BAD_NAME", "no tld"))? else {
        return Err(reject("BAD_NAME", "tld is not text"));
    };
    if let Some(rejection) = names::name_rejection(label, tld) {
        return Err(reject("BAD_NAME", rejection.code()));
    }

    let seq = uint(field(members, "seq").ok_or(bad("BAD_SEQ", "no seq"))?)
        .map_err(|_| bad("BAD_SEQ", "seq is not an integer"))?;
    let not_before = uint(field(members, "notBefore").ok_or(bad("BAD_TERM", "no notBefore"))?)
        .map_err(|_| bad("BAD_TERM", "notBefore is not an integer"))?;
    let not_after = uint(field(members, "notAfter").ok_or(bad("BAD_TERM", "no notAfter"))?)
        .map_err(|_| bad("BAD_TERM", "notAfter is not an integer"))?;

    let owner_key = key32(field(members, "ownerKey").ok_or(bad("BAD_OWNER", "no ownerKey"))?)
        .map_err(|detail| bad("BAD_OWNER", &detail))?;

    let suite = u8::try_from(
        uint(field(members, "suite").ok_or(bad("BAD_SUITE", "no suite"))?)
            .map_err(|_| bad("BAD_SUITE", "suite is not an integer"))?,
    )
    .map_err(|_| bad("BAD_SUITE", "suite out of range"))?;
    if suite != 1 {
        return Err(reject("BAD_SUITE", format!("unknown crypto suite {suite}")));
    }

    // Entries: at most MAX_RECORD_ENTRIES; each well-shaped; an alias never beside another
    // entry, because a name is either a pointer or a destination.
    let mut alias_count = 0usize;
    if let Some(Value::Array(entries)) = field(members, "records") {
        if entries.len() > MAX_RECORD_ENTRIES {
            return Err(reject(
                "TOO_MANY_ENTRIES",
                format!("{} entries exceeds {MAX_RECORD_ENTRIES}", entries.len()),
            ));
        }
        for entry in entries {
            let Value::Map(fields) = entry else {
                return Err(reject("BAD_RECORD_ENTRY", "an entry is a map"));
            };
            let Value::Text(kind) =
                field(fields, "type").ok_or(bad("BAD_RECORD_ENTRY", "entry has no type"))?
            else {
                return Err(reject("BAD_RECORD_ENTRY", "entry type is not text"));
            };
            match kind.as_str() {
                "cid" | "peer" | "ipns" | "txt" | "alias" => {}
                other => {
                    return Err(reject(
                        "BAD_RECORD_ENTRY",
                        format!("unknown entry type {other:?}"),
                    ))
                }
            }
            if kind == "alias" {
                alias_count += 1;
                if alias_count > 1 {
                    return Err(reject("BAD_RECORD_ENTRY", "at most one alias per record"));
                }
                if entries.len() > 1 {
                    return Err(reject(
                        "BAD_RECORD_ENTRY",
                        "an alias MUST NOT coexist with another entry type",
                    ));
                }
            }
            if let Some(ttl) = field(fields, "ttl") {
                let ttl =
                    uint(ttl).map_err(|_| bad("BAD_RECORD_ENTRY", "ttl is not an integer"))?;
                if !(crate::record::MIN_TTL..=crate::record::MAX_TTL).contains(&ttl) {
                    return Err(reject("BAD_RECORD_ENTRY", "ttl outside the agreed bounds"));
                }
            }
        }
    }

    let sig = match field(members, "sig") {
        Some(Value::Bytes(sig)) if sig.len() == 64 => sig.clone(),
        _ => return Err(reject("BAD_SIG", "sig is missing or not 64 bytes")),
    };
    let co_sig = match field(members, "coSig") {
        None | Some(Value::Null) => None,
        Some(Value::Bytes(sig)) if sig.len() == 64 => Some(sig.clone()),
        _ => return Err(reject("BAD_COSIG", "coSig is present but not 64 bytes")),
    };

    let (pow_bits, pow_nonce) = match field(members, "powProof") {
        None | Some(Value::Null) => (None, None),
        Some(Value::Map(proof)) => {
            let bits = uint(field(proof, "bits").ok_or(bad("BAD_POW", "powProof has no bits"))?)
                .map_err(|_| bad("BAD_POW", "bits is not an integer"))?;
            let bits = u32::try_from(bits).map_err(|_| bad("BAD_POW", "bits out of range"))?;
            let Value::Bytes(nonce) =
                field(proof, "nonce").ok_or(bad("BAD_POW", "powProof has no nonce"))?
            else {
                return Err(reject("BAD_POW", "nonce is not bytes"));
            };
            let nonce: [u8; POW_NONCE_LENGTH] = nonce
                .as_slice()
                .try_into()
                .map_err(|_| bad("BAD_POW", "nonce is not the agreed length"))?;
            (Some(bits), Some(nonce))
        }
        _ => return Err(reject("BAD_POW", "powProof is malformed")),
    };

    Ok(ParsedRecord {
        map: members.clone(),
        op: op.clone(),
        label: label.clone(),
        tld: tld.clone(),
        seq,
        not_before,
        not_after,
        owner_key,
        sig,
        co_sig,
        suite,
        pow_bits,
        pow_nonce,
    })
}

// ---------------------------------------------------------------------------
// The verifier proper.
// ---------------------------------------------------------------------------

/// Verify one record's exact bytes against an optional predecessor and the clock.
///
/// `window_count` is the trailing-window registration count for the name's TLD — index state
/// the caller supplies, exactly as the implementation of record's RegistryView does. Zero gives
/// the rate floor.
pub fn verify(bytes: &[u8], previous: Option<&PrevView>, now: u64, window_count: u64) -> Verdict {
    // Framing first: a malleable encoding makes a malleable record_hash, and record_hash is
    // the convergence tie-break.
    if bytes.len() > MAX_RECORD_BYTES {
        return reject(
            "TOO_LARGE",
            format!("{} bytes exceeds {MAX_RECORD_BYTES}", bytes.len()),
        );
    }
    let decoded = match decode_record(bytes) {
        Ok(decoded) => decoded,
        Err(e) => return reject("NON_CANONICAL", format!("undecodable: {e}")),
    };
    // Belt and braces against a decoder that normalises where it should refuse: re-encode and
    // require the bytes back.
    match cbor::encode(&decoded) {
        Ok(reencoded) if reencoded.as_slice() == bytes => {}
        Ok(_) => {
            return reject(
                "NON_CANONICAL",
                "bytes are not the deterministic encoding of their content",
            )
        }
        Err(e) => return reject("NON_CANONICAL", format!("re-encoding failed: {e}")),
    }

    let record = match parse_record(&decoded) {
        Ok(record) => record,
        Err(verdict) => return verdict,
    };

    // The signing input over the core (signature fields removed).
    let core = match core_of(&record.map) {
        Ok(core) => core,
        Err(e) => return reject("NON_CANONICAL", format!("core extraction failed: {e}")),
    };
    let core_cbor = match encode_core(&core) {
        Ok(core_cbor) => core_cbor,
        Err(e) => return reject("NON_CANONICAL", format!("core encoding failed: {e}")),
    };
    let input = signing_input(&core_cbor, record.suite);

    let clock = clock_verdict(record.not_before, now);

    if record.op == "REGISTER" {
        if record.seq != 0 || !is_zero_hash(field(&record.map, "prevHash")) {
            return reject("BAD_CHAIN", "REGISTER must carry seq 0 and a zero prevHash");
        }
        // Deliberately BEFORE signature and proof of work: the ordinary case — registering a
        // plainly-taken name — costs a lookup, not 64 MiB of Argon2id. Standalone mode has no
        // incumbent set, so this check belongs to whoever holds the view; stated here so its
        // absence is a decision on record rather than an oversight.
        if record.not_after - record.not_before != TERM {
            return reject("BAD_TERM", "a registration term is exactly one year");
        }
        if !Identity::verify(&record.owner_key, &input, &record.sig) {
            return reject("BAD_SIG", "signature does not verify under ownerKey");
        }
        if let Some(verdict) = check_pow(&record, window_count) {
            return verdict;
        }
        // Deferral last among REGISTER's checks: it is the one outcome that costs memory, so
        // it must be earned by everything before it.
        if let Some(clock) = clock {
            return clock;
        }
        return Verdict::Accept;
    }

    // Every other operation follows a predecessor.
    let Some(prev) = previous else {
        return reject(
            "NO_PREDECESSOR",
            format!("{}.{} has no accepted history", record.label, record.tld),
        );
    };

    if record.seq != prev.seq + 1 {
        return reject(
            "BAD_SEQ",
            format!("seq {} does not follow {}", record.seq, prev.seq),
        );
    }
    if !prev_hash_matches(&record.map, &prev.hash) {
        return reject("BAD_CHAIN", "prevHash does not match the predecessor");
    }
    if record.not_before < prev.not_before + MIN_INTERVAL {
        return reject(
            "TOO_SOON",
            "notBefore is less than 300s after the predecessor",
        );
    }
    // CRYPTO-AGILITY.md 5.1: a name's suite moves FORWARD only. Checked against the
    // predecessor rather than a high-water mark, because the chain IS the mark.
    if record.suite < prev.suite {
        return reject(
            "SUITE_DOWNGRADE",
            format!(
                "suite {} is below the predecessor's {}; suites move forward only",
                record.suite, prev.suite
            ),
        );
    }
    if prev.revoked {
        return reject(
            "REVOKED",
            "the name has been revoked and accepts no further records",
        );
    }
    if !accepts_successor(prev, now, &record.op) {
        return reject(
            "EXPIRED",
            format!(
                "{}.{} is not live enough for {}",
                record.label, record.tld, record.op
            ),
        );
    }
    // While a TRANSFER settles, only a further TRANSFER is accepted — anything else would
    // complete the handover early and silently.
    let settles_at = (prev.op_text == "TRANSFER").then(|| prev.not_before + SETTLEMENT);
    if let Some(settles_at) = settles_at {
        if record.not_before < settles_at && record.op != "TRANSFER" {
            return reject(
                "UNSETTLED",
                format!(
                    "a transfer of {}.{} settles at {settles_at}; only TRANSFER is accepted until then",
                    record.label, record.tld
                ),
            );
        }
    }
    // Authority comes from the PREDECESSOR'S controlling key — the transferor while settling.
    let authority = controlling_key(prev, record.not_before);
    if !Identity::verify(&authority, &input, &record.sig) {
        return reject(
            "BAD_SIG",
            "signature does not verify under the controlling key",
        );
    }
    // A deferral costs memory, so like REGISTER's it comes only after the signature earned it.
    if let Some(clock) = clock {
        return clock;
    }
    if record.op != "TRANSFER" && record.owner_key != prev.owner_key {
        return reject(
            "BAD_OWNER",
            format!("{} must not change ownerKey", record.op),
        );
    }
    if record.op != "RENEW" && record.pow_bits.is_some() {
        return reject(
            "UNEXPECTED_POW",
            format!("{} must carry powProof null", record.op),
        );
    }

    match record.op.as_str() {
        "UPDATE" => {
            if record.not_after != prev.not_after {
                return reject("BAD_TERM", "UPDATE must not change notAfter");
            }
        }
        "RENEW" => {
            let Some(_bits) = record.pow_bits else {
                return reject("MISSING_POW", "RENEW requires a proof of work");
            };
            if record.not_before
                < prev
                    .not_after
                    .saturating_sub(crate::record::RENEWAL_WINDOW_SECONDS)
            {
                return reject("TOO_SOON", "the renewal window opens 60 days before expiry");
            }
            let base = std::cmp::max(prev.not_after, record.not_before);
            if record.not_after != base + TERM {
                return reject(
                    "BAD_TERM",
                    format!("RENEW must set notAfter to {}", base + TERM),
                );
            }
            if let Some(verdict) = check_pow(&record, window_count) {
                return verdict;
            }
        }
        "TRANSFER" => {
            if record.owner_key == prev.owner_key {
                return reject("BAD_OWNER", "TRANSFER must name a different ownerKey");
            }
            if record.not_after != prev.not_after {
                return reject("BAD_TERM", "TRANSFER must not change notAfter");
            }
            if record.not_after - record.not_before < SETTLEMENT {
                return reject(
                    "UNSETTLED",
                    format!(
                        "a transfer needs {SETTLEMENT}s of term left to settle in; {} remain",
                        record.not_after - record.not_before
                    ),
                );
            }
            let Some(co_sig) = &record.co_sig else {
                return reject(
                    "BAD_COSIG",
                    "coSig does not verify under the incoming ownerKey",
                );
            };
            if !Identity::verify(&record.owner_key, &input, co_sig) {
                return reject(
                    "BAD_COSIG",
                    "coSig does not verify under the incoming ownerKey",
                );
            }
        }
        "RELINQUISH" => {
            if entry_count(&record.map) != 0 {
                return reject("BAD_RECORD_ENTRY", "RELINQUISH must carry no entries");
            }
            if record.not_after != record.not_before {
                return reject("BAD_TERM", "RELINQUISH must expire immediately");
            }
        }
        "REVOKE" => {
            if entry_count(&record.map) != 0 {
                return reject("BAD_RECORD_ENTRY", "REVOKE must carry no entries");
            }
            if record.not_after != prev.not_after {
                return reject("BAD_TERM", "REVOKE must not change notAfter");
            }
        }
        other => return reject("UNKNOWN_OP", format!("unhandled operation: {other}")),
    }

    Verdict::Accept
}

fn clock_verdict(not_before: u64, now: u64) -> Option<Verdict> {
    if not_before > now.saturating_add(MAX_CLOCK_SKEW) {
        return Some(Verdict::Defer {
            detail: format!("notBefore {not_before} is ahead of the verifier clock"),
        });
    }
    if not_before < now.saturating_sub(MAX_BACKDATE) {
        return Some(reject(
            "BACKDATED",
            format!("notBefore {not_before} is more than a day in the past"),
        ));
    }
    None
}

/// The lifecycle question, mirroring `acceptsSuccessor`: LIVE answers every operation, GRACE
/// answers only RENEW, and a revoked name answers nothing.
fn accepts_successor(prev: &PrevView, now: u64, op: &str) -> bool {
    if now < prev.not_before {
        return false;
    }
    // REVOKE stops resolution at once (liveUntil = the act itself); everything else lives to
    // notAfter; RENEW alone may act during grace.
    let live_until = if prev.op_text == "REVOKE" {
        prev.not_before
    } else {
        prev.not_after
    };
    if op == "RENEW" {
        now < prev.not_after.saturating_add(GRACE)
    } else {
        now < live_until
    }
}

/// Authority over a name: the owner — except inside a TRANSFER's settlement horizon, when the
/// transferor's key still speaks for it.
fn controlling_key(prev: &PrevView, at: u64) -> [u8; 32] {
    if prev.op_text == "TRANSFER" && at < prev.not_before + SETTLEMENT {
        prev.signer_key
    } else {
        prev.owner_key
    }
}

fn check_pow(record: &ParsedRecord, window_count: u64) -> Option<Verdict> {
    let (Some(bits), Some(nonce)) = (record.pow_bits, record.pow_nonce) else {
        return Some(reject(
            "MISSING_POW",
            "this operation requires a proof of work",
        ));
    };
    let required = pow::required_bits(record.label.chars().count(), window_count);
    if bits < required {
        return Some(reject(
            "BAD_POW",
            format!("claimed {bits} bits but {required} are currently required"),
        ));
    }
    // Salt from the record's own canonical core; tag over the nonce; leading zero bits with no
    // early exit — the same evaluation the builder ran, re-run distrustfully.
    let core = match core_of(&record.map) {
        Ok(core) => core,
        Err(e) => {
            return Some(reject(
                "NON_CANONICAL",
                format!("core extraction failed: {e}"),
            ))
        }
    };
    let salt = match pow::pow_salt(&core) {
        Ok(salt) => salt,
        Err(e) => return Some(reject("BAD_POW", format!("salt derivation failed: {e}"))),
    };
    let tag = pow::pow_tag(&nonce, &salt);
    if !pow::tag_satisfies(&tag, bits) {
        return Some(reject(
            "BAD_POW",
            "proof of work does not meet the claimed difficulty",
        ));
    }
    None
}

fn is_zero_hash(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bytes(b)) if b.iter().all(|byte| *byte == 0))
}

fn prev_hash_matches(members: &[(Key, Value)], expected: &[u8; 32]) -> bool {
    matches!(field(members, "prevHash"), Some(Value::Bytes(b)) if b.as_slice() == expected)
}

fn entry_count(members: &[(Key, Value)]) -> usize {
    match field(members, "records") {
        Some(Value::Array(entries)) => entries.len(),
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Tests: every acceptance path the builders can reach, and a tamper matrix
// where each class of forgery is refused with ITS OWN code — not merely
// "rejected somewhere".
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::record::{
        build_register, build_relinquish, build_renew, build_revoke, build_transfer, build_update,
        Predecessor,
    };

    const NOW: u64 = 1_800_000_000;
    const LIMIT: u64 = 10_000_000;

    fn identity(seed_byte: u8) -> Identity {
        let mut seed = vec![seed_byte; 32];
        Identity::from_seed(&mut seed).expect("test seed")
    }

    fn registered(id: &Identity, label: &str) -> Vec<u8> {
        build_register(id, label, "vayu", NOW, &[], 0, None, LIMIT).expect("registers")
    }

    fn code(verdict: &Verdict) -> String {
        match verdict {
            Verdict::Accept => "ACCEPT".to_string(),
            Verdict::Reject { code, .. } => format!("REJECT {code}"),
            Verdict::Defer { .. } => "DEFER".to_string(),
        }
    }

    #[test]
    fn a_registration_the_builder_made_verifies_as_received() {
        let id = identity(1);
        let bytes = registered(&id, "alpha");
        assert_eq!(
            verify(&bytes, None, NOW, 0),
            Verdict::Accept,
            "the peer's verdict on an honest registration"
        );
        // And again at a slightly later clock: still accepted. The clock bounds are wide.
        assert!(verify(&bytes, None, NOW + 60, 0).is_accept());
    }

    #[test]
    fn framing_and_canonicality_are_refused_with_their_own_codes() {
        let id = identity(2);
        let bytes = registered(&id, "bravo");

        let oversized = vec![0u8; MAX_RECORD_BYTES + 1];
        assert_eq!(code(&verify(&oversized, None, NOW, 0)), "REJECT TOO_LARGE");

        let trailing = {
            let mut copy = bytes.clone();
            copy.push(0);
            copy
        };
        assert_eq!(
            code(&verify(&trailing, None, NOW, 0)),
            "REJECT NON_CANONICAL",
            "bytes after the record are not the record"
        );

        // A flipped byte inside the name keeps canonical CBOR and the grammar but breaks the
        // signature over content that was never signed.
        let mut malleated = bytes.clone();
        let name_pos = malleated
            .windows(5)
            .position(|w| w == b"bravo")
            .expect("name present");
        malleated[name_pos] ^= 1;
        assert_eq!(code(&verify(&malleated, None, NOW, 0)), "REJECT BAD_SIG");
    }

    /// Decode a record, replace one byte-string field's value, re-encode canonically. The
    /// result is well-formed CBOR whose signature no longer matches its content — the shape
    /// every real forgery takes.
    fn with_field_replaced(bytes: &[u8], field_name: &str, replacement: Vec<u8>) -> Vec<u8> {
        let Value::Map(mut members) = decode_record(bytes).expect("decodes") else {
            panic!("a record is a map");
        };
        for (key, value) in members.iter_mut() {
            if matches!(key, Key::Text(name) if name == field_name) {
                *value = Value::Bytes(replacement.clone());
            }
        }
        cbor::encode(&Value::Map(members)).expect("re-encodes")
    }

    #[test]
    fn a_signature_under_anything_but_the_signing_key_is_refused() {
        let alice = identity(3);
        let bytes = registered(&alice, "charlie");

        // A structurally perfect record whose sig is not the signature of its own core.
        let forged = with_field_replaced(&bytes, "sig", vec![0u8; 64]);
        assert_eq!(code(&verify(&forged, None, NOW, 0)), "REJECT BAD_SIG");
        assert_ne!(forged, bytes, "the replacement really happened");
    }

    #[test]
    fn proof_of_work_is_judged_against_the_difficulty_the_caller_demands() {
        let id = identity(5);
        let bytes = registered(&id, "delta"); // solved at window_count 0: claimed 7 bits

        // Below the rate floor nothing changes: the market is quiet, the claim stands.
        assert!(verify(&bytes, None, NOW, 511).is_accept());
        // Past the floor the requirement climbs; a record valid yesterday is unprovable today.
        assert_eq!(
            code(&verify(&bytes, None, NOW, 4096)),
            "REJECT BAD_POW",
            "difficulty is index state"
        );
        assert!(verify(&bytes, None, NOW, 0).is_accept());
    }

    #[test]
    fn clock_discipline_defers_forward_and_rejects_backward() {
        let id = identity(6);
        let bytes = registered(&id, "echo"); // notBefore == NOW

        // Ahead of the verifier's clock by more than the skew window: HELD, not rejected.
        match verify(&bytes, None, NOW - 3_600, 0) {
            Verdict::Defer { .. } => {}
            other => panic!("expected DEFER, got {:?}", code(&other)),
        }
        // Within skew: fine.
        assert!(verify(&bytes, None, NOW - 120, 0).is_accept());
        // More than a day in the past: rejected as backdated.
        assert_eq!(
            code(&verify(&bytes, None, NOW + MAX_BACKDATE + 1, 0)),
            "REJECT BACKDATED"
        );
    }

    #[test]
    fn chain_discipline_names_each_failure() {
        let alice = identity(7);
        let reg = registered(&alice, "foxtrot");
        let predecessor = Predecessor::from_bytes(&reg).expect("predecessor");

        let entries = Vec::new();
        let update = build_update(
            &alice,
            &predecessor,
            "foxtrot",
            "vayu",
            NOW + 600,
            &entries[..],
        )
        .expect("builds");
        let view = prev_view(&reg, None).expect("prev view");
        assert!(verify(&update, Some(&view), NOW + 600, 0).is_accept());

        // seq not advanced: BAD_SEQ.
        let mut stale_seq = view.clone();
        stale_seq.seq += 5;
        assert_eq!(
            code(&verify(&update, Some(&stale_seq), NOW + 600, 0)),
            "REJECT BAD_SEQ"
        );

        // prevHash pointing elsewhere: BAD_CHAIN.
        let mut wrong_hash = view.clone();
        wrong_hash.hash[0] ^= 1;
        assert_eq!(
            code(&verify(&update, Some(&wrong_hash), NOW + 600, 0)),
            "REJECT BAD_CHAIN"
        );

        // A revoked predecessor accepts nothing: REVOKED.
        let mut revoked_prev = view.clone();
        revoked_prev.revoked = true;
        assert_eq!(
            code(&verify(&update, Some(&revoked_prev), NOW + 600, 0)),
            "REJECT REVOKED"
        );

        // No history at all for a successor: NO_PREDECESSOR.
        assert_eq!(
            code(&verify(&update, None, NOW + 600, 0)),
            "REJECT NO_PREDECESSOR"
        );
    }

    #[test]
    fn an_expired_name_answers_nothing_and_grace_answers_only_a_renewal() {
        let alice = identity(8);
        let reg = registered(&alice, "golf");
        let predecessor = Predecessor::from_bytes(&reg).expect("predecessor");
        let view = prev_view(&reg, None).expect("prev view");

        let entries: Vec<crate::record::Entry> = Vec::new();
        let update = build_update(
            &alice,
            &predecessor,
            "golf",
            "vayu",
            NOW + 600,
            &entries[..],
        )
        .expect("builds");

        // Long after expiry AND grace: nothing succeeds.
        let after_grace = NOW + TERM + GRACE + 1;
        assert_eq!(
            code(&verify(&update, Some(&view), after_grace, 0)),
            "REJECT EXPIRED"
        );

        // Inside grace an UPDATE is refused but a RENEW is exactly what grace exists for.
        let in_grace = NOW + TERM + GRACE / 2;
        assert_eq!(
            code(&verify(&update, Some(&view), in_grace, 0)),
            "REJECT EXPIRED"
        );
        let renew = build_renew(&alice, &predecessor, "golf", "vayu", in_grace, 0, LIMIT)
            .expect("renew inside grace builds");
        assert!(
            verify(&renew, Some(&view), in_grace, 0).is_accept(),
            "grace answers RENEW"
        );
    }

    #[test]
    fn a_transfer_is_signed_by_the_transferor_and_countersigned_by_the_recipient() {
        let alice = identity(9);
        let bob = identity(10);
        let carol = identity(16);
        let reg = registered(&alice, "hotel");
        let reg_view = prev_view(&reg, None).expect("prev view");
        let reg_pred = Predecessor::from_bytes(&reg).expect("predecessor");

        // First hop: alice hands the name to bob.
        let hop1 =
            build_transfer(&alice, &bob, &reg_pred, "hotel", "vayu", NOW + 600).expect("builds");
        assert!(
            verify(&hop1, Some(&reg_view), NOW + 600, 0).is_accept(),
            "an honest transfer settles"
        );

        // Second hop: bob (now controlling) passes it on to carol, once hop1 has settled.
        let hop1_pred = Predecessor::from_bytes(&hop1).expect("predecessor");
        let settled_at = NOW + 600 + SETTLEMENT;
        let hop2 =
            build_transfer(&bob, &carol, &hop1_pred, "hotel", "vayu", settled_at).expect("builds");

        let bob_view = prev_view(&hop1, Some(bob.public_key())).expect("prev view");
        assert!(
            verify(&hop2, Some(&bob_view), settled_at, 0).is_accept(),
            "an honest second hop settles"
        );

        // Authority during settlement belongs to the TRANSFEROR — the pure rule the whole
        // delay rests on.
        let mid_settlement = NOW + 600 + SETTLEMENT / 2;
        assert_eq!(
            controlling_key(&bob_view, mid_settlement),
            *bob.public_key()
        );
        assert_eq!(controlling_key(&bob_view, settled_at), *bob.public_key());

        // A non-transfer successor while a transfer settles is refused outright: the name is
        // in flux, and only another transfer may act on it. Built honestly AFTER hop2's OWN
        // settlement horizon, then checked against a view that claims hop2 is STILL settling.
        let update_pred = Predecessor::from_bytes(&hop2).expect("predecessor");
        let entries: Vec<crate::record::Entry> = Vec::new();
        let after_second_settlement = settled_at + SETTLEMENT;
        let later_update = build_update(
            &carol,
            &update_pred,
            "hotel",
            "vayu",
            after_second_settlement + 600,
            &entries[..],
        )
        .expect("builds");
        let mut still_settling =
            prev_view(&hop2, Some(bob.public_key())).expect("hop2's transferor is bob");
        still_settling.not_before = after_second_settlement + 600 - SETTLEMENT / 2;
        assert_eq!(
            code(&verify(
                &later_update,
                Some(&still_settling),
                after_second_settlement + 600,
                0
            )),
            "REJECT UNSETTLED"
        );

        // A structurally perfect record whose coSig verifies under nothing: BAD_COSIG,
        // distinctly from a broken main signature — transfer-to-a-key-nobody-holds stays
        // impossible.
        let broken_cosig = with_field_replaced(&hop1, "coSig", vec![0u8; 64]);
        assert_eq!(
            code(&verify(&broken_cosig, Some(&reg_view), NOW + 600, 0)),
            "REJECT BAD_COSIG"
        );
    }

    #[test]
    fn suites_move_forward_only() {
        let alice = identity(12);
        let reg = registered(&alice, "india");
        let view = prev_view(&reg, None).expect("prev view");
        let predecessor = Predecessor::from_bytes(&reg).expect("predecessor");
        let entries: Vec<crate::record::Entry> = Vec::new();
        let update = build_update(
            &alice,
            &predecessor,
            "india",
            "vayu",
            NOW + 600,
            &entries[..],
        )
        .expect("builds");

        let mut futuristic = view.clone();
        futuristic.suite = 2;
        assert_eq!(
            code(&verify(&update, Some(&futuristic), NOW + 600, 0)),
            "REJECT SUITE_DOWNGRADE",
            "CRYPTO-AGILITY.md 5.1: the chain IS the high-water mark"
        );
    }

    #[test]
    fn relinquish_and_revoke_follow_their_own_term_rules() {
        let alice = identity(13);
        let reg = registered(&alice, "juliet");
        let predecessor = Predecessor::from_bytes(&reg).expect("predecessor");
        let view = prev_view(&reg, None).expect("prev view");

        let rel =
            build_relinquish(&alice, &predecessor, "juliet", "vayu", NOW + 600).expect("builds");
        assert!(verify(&rel, Some(&view), NOW + 600, 0).is_accept());

        let rev = build_revoke(&alice, &predecessor, "juliet", "vayu", NOW + 600).expect("builds");
        assert!(verify(&rev, Some(&view), NOW + 600, 0).is_accept());
    }

    #[test]
    fn a_predecessor_view_refuses_to_improvise_a_transferors_identity() {
        let alice = identity(14);
        let bob = identity(15);
        let reg = registered(&alice, "kilo");
        let predecessor = Predecessor::from_bytes(&reg).expect("predecessor");
        let transfer =
            build_transfer(&alice, &bob, &predecessor, "kilo", "vayu", NOW + 600).expect("builds");

        // Without the transferor key there is NO correct answer, so refuse rather than guess:
        // defaulting would hand the name over the instant the record was indexed.
        let err = prev_view(&transfer, None).unwrap_err();
        assert!(err.contains("transferor"), "{err}");
        let ok = prev_view(&transfer, Some(alice.public_key()));
        assert!(ok.is_ok());
    }
}
