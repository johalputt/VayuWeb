//! Domain separation, record hashing and signing input.
//!
//! The client-side counterpart of `registry/src/domain.ts`. REGISTRY.md fixes the two inputs
//! byte for byte:
//!
//! ```text
//! signing_input = "VayuWeb-Registry-Record-v1" || 0x00 || uint8(suite) || det_cbor(core)
//! record_hash   = BLAKE2b-256("VayuWeb-Registry-Hash-v1" || 0x00 || det_cbor(full))
//! ```
//!
//! `core` is the record map with `sig` and `coSig` removed; `full` is the complete map. The
//! prefixes are what stop a signature made over one VayuWeb structure being replayed as
//! another, so they are consensus-critical constants: an implementation one byte wrong
//! produces signatures no other implementation accepts, which is a silent fork rather than a
//! visible error. Their lengths are asserted where they are built and pinned again by tests,
//! because a specification prose error about exactly this has happened before — REGISTRY.md
//! once described them as 23 and 21 bytes when the literals are 26 and 24.
//!
//! What proves this port agrees with the reference implementation is again bytes rather than
//! prose: the golden fixtures under `conformance/` are built here, and the registry's verifier
//! recomputes `record_hash` over those same bytes and refuses any disagreement.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use crate::cbor::{self, Key, Value};

/// Domain-separation prefix for the Ed25519 signing input over a registry record.
pub const RECORD_SIGNING_PREFIX: &str = "VayuWeb-Registry-Record-v1";

/// Domain-separation prefix for the BLAKE2b-256 record hash.
pub const RECORD_HASH_PREFIX: &str = "VayuWeb-Registry-Hash-v1";

/// Length of a record hash in bytes. BLAKE2b-256, matching Hypercore's own primitive.
pub const RECORD_HASH_LENGTH: usize = 32;

/// Fields excluded from the signing input, because they carry the signatures themselves.
const SIGNATURE_FIELDS: [&str; 2] = ["sig", "coSig"];

fn ascii_prefix(literal: &str) -> Vec<u8> {
    let bytes = literal.as_bytes();
    for &b in bytes {
        if !(0x20..=0x7e).contains(&b) {
            panic!("domain prefix must be printable ASCII: {literal}");
        }
    }
    bytes.to_vec()
}

fn signing_prefix_bytes() -> Vec<u8> {
    let bytes = ascii_prefix(RECORD_SIGNING_PREFIX);
    assert_eq!(bytes.len(), 26, "signing prefix must be 26 bytes");
    bytes
}

fn hash_prefix_bytes() -> Vec<u8> {
    let bytes = ascii_prefix(RECORD_HASH_PREFIX);
    assert_eq!(bytes.len(), 24, "hash prefix must be 24 bytes");
    bytes
}

/// Concatenate a domain prefix, its 0x00 separator, optional extra bytes, and a body.
fn with_domain(prefix: &[u8], body: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + 1 + extra.len() + body.len());
    out.extend_from_slice(prefix);
    out.push(0x00);
    out.extend_from_slice(extra);
    out.extend_from_slice(body);
    out
}

/// The record map without its signature fields, ready for canonical encoding.
///
/// Removing rather than omitting is the point: a caller that builds `core` separately from
/// `full` can build them differently, which is how a signature ends up over bytes the record
/// no longer matches. One map, stripped twice-verified, is one fact.
pub fn core_of(record: &[(Key, Value)]) -> Result<Vec<(Key, Value)>, cbor::CborError> {
    let mut core = Vec::with_capacity(record.len());
    for (key, value) in record {
        let Key::Text(name) = key else {
            return Err(cbor::CborError::BadMapKey);
        };
        if SIGNATURE_FIELDS.contains(&name.as_str()) {
            continue;
        }
        core.push((key.clone(), value.clone()));
    }
    Ok(core)
}

/// Canonical CBOR of the record map with `sig` and `coSig` removed.
pub fn encode_core(record: &[(Key, Value)]) -> Result<Vec<u8>, cbor::CborError> {
    cbor::encode(&Value::Map(core_of(record)?))
}

/// `signing_input`: what the owner's Ed25519 signature is computed over.
pub fn signing_input(core_cbor: &[u8], suite: u8) -> Vec<u8> {
    with_domain(&signing_prefix_bytes(), core_cbor, &[suite])
}

/// `record_hash`: BLAKE2b-256 over the domain-separated full record bytes.
///
/// BLAKE2b's variable digest length is part of the function's parameterisation, not a
/// truncation of a longer digest — the same reason the reference implementation passes a
/// digest length rather than hashing wide and cutting.
pub fn record_hash_from_bytes(record_bytes: &[u8]) -> [u8; RECORD_HASH_LENGTH] {
    let input = with_domain(&hash_prefix_bytes(), record_bytes, &[]);
    let mut hasher = Blake2bVar::new(RECORD_HASH_LENGTH).expect("32 is a valid BLAKE2b width");
    Update::update(&mut hasher, &input);
    let mut out = [0u8; RECORD_HASH_LENGTH];
    hasher
        .finalize_variable(&mut out)
        .expect("exact output size");
    out
}

/// Constant-time equality for hashes and other fixed-length values.
pub fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn prefixes_are_the_specification_literals_with_the_specification_lengths() {
        // Asserted at build time too; asserted here so a test failure reads as the defect it
        // is rather than a panic inside hashing.
        assert_eq!(RECORD_SIGNING_PREFIX.len(), 26);
        assert_eq!(RECORD_HASH_PREFIX.len(), 24);
        // Neither prefix is a prefix of the other, so no input is well-formed under both
        // domains at once.
        assert!(!RECORD_HASH_PREFIX.starts_with(RECORD_SIGNING_PREFIX));
        assert!(!RECORD_SIGNING_PREFIX.starts_with(RECORD_HASH_PREFIX));
        // And the exact bytes are pinned, because these ARE the wire-visible constants.
        assert_eq!(
            hex(&ascii_prefix(RECORD_SIGNING_PREFIX)),
            "566179755765622d52656769737472792d5265636f72642d7631"
        );
        assert_eq!(
            hex(&ascii_prefix(RECORD_HASH_PREFIX)),
            "566179755765622d52656769737472792d486173682d7631"
        );
    }

    #[test]
    fn signing_input_shape_is_prefix_zero_suite_body() {
        let core = vec![0xde, 0xad, 0xbe, 0xef];
        let input = signing_input(&core, 1);
        assert_eq!(input.len(), 26 + 1 + 1 + core.len());
        assert_eq!(&input[..26], RECORD_SIGNING_PREFIX.as_bytes());
        assert_eq!(input[26], 0x00);
        assert_eq!(input[27], 1);
        assert_eq!(&input[28..], &core);
        // The suite byte is part of the domain: the same core under a different suite is a
        // different signing input.
        assert_ne!(signing_input(&core, 1), signing_input(&core, 2));
    }

    #[test]
    fn core_of_strips_only_signature_fields_and_keeps_everything_else() {
        let record = vec![
            (Key::Text("version".into()), Value::UInt(1)),
            (Key::Text("op".into()), Value::Text("REGISTER".into())),
            (Key::Text("sig".into()), Value::Bytes(vec![0xaa; 64])),
            (Key::Text("coSig".into()), Value::Bytes(vec![0xbb; 64])),
        ];
        let core = core_of(&record).expect("strips");
        assert_eq!(core.len(), 2);
        assert_eq!(core[0].0, Key::Text("version".into()));
        assert_eq!(core[1].0, Key::Text("op".into()));
        // Idempotent: stripping a core changes nothing.
        assert_eq!(core_of(&core).expect("strips"), core);
        // A record whose sig field is absent strips nothing and encodes unchanged.
        let unsigned = vec![(Key::Text("op".into()), Value::Text("RENEW".into()))];
        assert_eq!(
            encode_core(&unsigned).expect("encodes"),
            cbor::encode(&Value::Map(unsigned.clone())).expect("encodes")
        );
    }

    #[test]
    fn record_hash_is_blake2b_256_over_domain_separated_bytes() {
        let bytes = vec![0x01, 0x02, 0x03];
        let hash = record_hash_from_bytes(&bytes);
        assert_eq!(hash.len(), 32);
        // Deterministic, and distinct for distinct inputs including the empty one.
        assert_eq!(hash, record_hash_from_bytes(&bytes));
        assert_ne!(hash, record_hash_from_bytes(&[]));
        assert_ne!(record_hash_from_bytes(&[]), [0u8; 32]);
        // Distinct from the signing input of the same-length prefix: the two domains must not
        // share outputs even by accident, and a 40-byte core makes both sides long enough to
        // compare against the full 32-byte hash.
        let long_core = vec![0x07u8; 40];
        assert_ne!(&hash[..], &signing_input(&long_core, 1)[..32]);
    }

    #[test]
    fn bytes_equal_is_length_safe() {
        assert!(bytes_equal(b"abcd", b"abcd"));
        assert!(!bytes_equal(b"abc", b"abcd"));
        assert!(!bytes_equal(b"abcd", b"abce"));
    }
}
