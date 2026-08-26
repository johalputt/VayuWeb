//! Block-exchange message codecs — VWIP-0005 sections 3 and 5, without the transport.
//!
//! The wire FORMAT is not the rollout gate: these are pure functions over bytes, no
//! sockets, no discovery, no fetching. They exist so that when Phase 4 unblocks, the
//! client already speaks the exact octets the reference implementation does, proven by
//! the same conformance vectors on both sides. Until then nothing here dials anywhere.
//!
//! Every bound lives in [`BX_LIMITS`] with its reasoning, mirroring `blockx.ts` — a
//! limit nobody can enumerate is a limit nobody audits.

use crate::cbor::{self, Key, Value};

/// The block-exchange protocol version this module speaks. VWIP-0005 3.3.
pub const BLOCK_EXCHANGE_VERSION: u64 = 1;

/// Every bound the wire format enforces, in one place so a reviewer can see the whole
/// budget. VWIP-0005 section 5 states each with its reasoning.
pub struct BXLimit;
impl BXLimit {
    /// Whole-message encoding: one maximum block plus CBOR framing and nothing more.
    pub const MESSAGE_BYTES: usize = 1_114_112;
    /// Octets in one block: four times the 262,144-byte chunk size — room for a
    /// directory node at maximum link count, and nothing that could only be an
    /// amplification attempt.
    pub const BLOCK_BYTES: usize = 1_048_576;
    /// Identifiers one BWANT may name. A syncing peer sends many, not one large one.
    pub const WANT_CIDS: usize = 64;
    /// Blocks one BLOCKS may carry. Matches WANT_CIDS but bounds ARRAY ITERATION;
    /// MESSAGE_BYTES bounds volume and binds first.
    pub const BLOCKS_PER_MESSAGE: usize = 64;
    /// REGISTRY.md's cid entry bound, checked before decoding an identifier.
    pub const CID_BYTES: usize = 64;
}

/// Why a message could not be encoded or decoded. The codes ARE the wire contract's
/// refusal vocabulary; conformance vectors name them verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockExchangeError {
    TooLarge(String),
    NonCanonical(String),
    Malformed(String),
    UnknownType(String),
    LimitExceeded(String),
}

impl core::fmt::Display for BlockExchangeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge(d) => write!(f, "TOO_LARGE: {d}"),
            Self::NonCanonical(d) => write!(f, "NON_CANONICAL: {d}"),
            Self::Malformed(d) => write!(f, "MALFORMED: {d}"),
            Self::UnknownType(d) => write!(f, "UNKNOWN_TYPE: {d}"),
            Self::LimitExceeded(d) => write!(f, "LIMIT_EXCEEDED: {d}"),
        }
    }
}

/// One block-exchange message. VWIP-0005 section 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockMessage {
    /// The opening claim: protocol version and the largest message this peer will
    /// accept. `max` is a statement, never a request (3.4).
    BHello { v: u64, max: u64 },
    /// A bounded set of block identifiers, each named at most once (3.6.a).
    BWant { cids: Vec<Vec<u8>> },
    /// Block bytes, verified by the receiver against the identifier that referred
    /// them. Carries no identifiers (3.5) — order is the requester's own.
    Blocks { blks: Vec<Vec<u8>> },
    /// Requested identifiers not being answered. Carries no reason, by design (6.2).
    BDone { cids: Vec<Vec<u8>> },
}

/// The message type as it appears on the wire.
fn type_name(message: &BlockMessage) -> &'static str {
    match message {
        BlockMessage::BHello { .. } => "BHELLO",
        BlockMessage::BWant { .. } => "BWANT",
        BlockMessage::Blocks { .. } => "BLOCKS",
        BlockMessage::BDone { .. } => "BDONE",
    }
}

/// VWIP-0005 3.6.a: an identifier list MUST NOT name the same identifier twice.
///
/// Applied to BDONE as well as BWANT: 6.2 requires a lacking peer and a declining peer
/// to emit the identical message, so the same rule that makes a repeat an amplification
/// demand in a request makes it a signal in an answer.
fn assert_distinct(cids: &[Vec<u8>]) -> Result<(), BlockExchangeError> {
    let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
    for cid in cids {
        if !seen.insert(cid.as_slice()) {
            return Err(BlockExchangeError::Malformed(
                "an identifier is named twice; see 3.6.a".to_string(),
            ));
        }
    }
    Ok(())
}

/// Encode one message, refusing to emit anything a conforming receiver would reject.
///
/// All three sender-side prohibitions are enforced here, because the peer best placed
/// to notice is the one that built the message: a sender that emits something the
/// receiver must refuse has produced a failure that looks like the receiver's fault.
pub fn encode_block_message(message: &BlockMessage) -> Result<Vec<u8>, BlockExchangeError> {
    let mut members: Vec<(Key, Value)> = Vec::new();
    members.push((
        Key::Text("t".to_string()),
        Value::Text(type_name(message).to_string()),
    ));
    match message {
        BlockMessage::BHello { v, max } => {
            // 3.4.a. A declared maximum may only ever be LOWER than the protocol's:
            // lowering harms nobody but the declarer; raising would let a stranger
            // raise the receiver's limit by asking.
            if *max > BXLimit::BLOCK_BYTES as u64 {
                return Err(BlockExchangeError::LimitExceeded(format!(
                    "declared max {max} is above the {}-byte block limit",
                    BXLimit::BLOCK_BYTES
                )));
            }
            members.push((Key::Text("v".to_string()), Value::UInt(*v)));
            members.push((Key::Text("max".to_string()), Value::UInt(*max)));
        }
        BlockMessage::BWant { cids } | BlockMessage::BDone { cids } => {
            assert_distinct(cids)?;
            members.push((
                Key::Text("cids".to_string()),
                Value::Array(cids.iter().map(|cid| Value::Bytes(cid.clone())).collect()),
            ));
        }
        BlockMessage::Blocks { blks } => {
            members.push((
                Key::Text("blks".to_string()),
                Value::Array(blks.iter().map(|b| Value::Bytes(b.clone())).collect()),
            ));
        }
    }
    let bytes = cbor::encode(&Value::Map(members))
        .map_err(|e| BlockExchangeError::Malformed(e.to_string()))?;
    // Checked on the way out as well as the way in.
    if bytes.len() > BXLimit::MESSAGE_BYTES {
        return Err(BlockExchangeError::TooLarge(format!(
            "message is {} bytes, over the {} limit",
            bytes.len(),
            BXLimit::MESSAGE_BYTES
        )));
    }
    Ok(bytes)
}

/// A bounded array of byte strings, checked in the order that costs least: length
/// first, then each element — so an array of a million entries is refused having
/// touched none of them. Reversing those two is how a limit becomes an accounting of
/// work already done.
fn bstr_array(
    members: &[(Key, Value)],
    key: &str,
    limit: usize,
    each: usize,
) -> Result<Vec<Vec<u8>>, BlockExchangeError> {
    let value = members
        .iter()
        .find_map(|(k, v)| match k {
            Key::Text(name) if name == key => Some(v),
            _ => None,
        })
        .ok_or_else(|| BlockExchangeError::Malformed(format!("{key} is required")))?;
    let Value::Array(entries) = value else {
        return Err(BlockExchangeError::Malformed(format!(
            "{key} must be an array"
        )));
    };
    if entries.len() > limit {
        return Err(BlockExchangeError::LimitExceeded(format!(
            "{key} holds {} entries, over the {limit} limit",
            entries.len()
        )));
    }
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let Value::Bytes(bytes) = entry else {
            return Err(BlockExchangeError::Malformed(format!(
                "{key} must hold byte strings"
            )));
        };
        if bytes.len() > each {
            return Err(BlockExchangeError::LimitExceeded(format!(
                "an entry in {key} is {} bytes, over the {each} limit",
                bytes.len()
            )));
        }
        out.push(bytes.clone());
    }
    Ok(out)
}

fn uint_field(members: &[(Key, Value)], key: &str) -> Result<u64, BlockExchangeError> {
    members
        .iter()
        .find_map(|(k, v)| match k {
            Key::Text(name) if name == key => Some(v),
            _ => None,
        })
        .ok_or_else(|| BlockExchangeError::Malformed(format!("{key} is required")))
        .and_then(|v| match v {
            Value::UInt(n) => Ok(*n),
            _ => Err(BlockExchangeError::Malformed(format!(
                "{key} must be an unsigned integer"
            ))),
        })
}

/// Decode one message.
///
/// The whole-message bound is checked against the raw octets before any parsing,
/// because a decoder asked to parse an unbounded input has already lost — VWIP-0005
/// 5.1's rule that nothing is allocated on the basis of an asserted value starts here.
pub fn decode_block_message(bytes: &[u8]) -> Result<BlockMessage, BlockExchangeError> {
    if bytes.len() > BXLimit::MESSAGE_BYTES {
        return Err(BlockExchangeError::TooLarge(format!(
            "message is {} bytes, over the {} limit",
            bytes.len(),
            BXLimit::MESSAGE_BYTES
        )));
    }
    let decoded = cbor::decode(bytes)
        .map_err(|e| BlockExchangeError::NonCanonical(format!("not deterministic CBOR: {e}")))?;
    // Belt and braces, same as records: a decoder that normalises where it should
    // refuse would make the message_hash malleable. Re-encode and require the bytes.
    let reencoded =
        cbor::encode(&decoded).map_err(|e| BlockExchangeError::NonCanonical(e.to_string()))?;
    if reencoded.as_slice() != bytes {
        return Err(BlockExchangeError::NonCanonical(
            "bytes are not the deterministic encoding of their content".to_string(),
        ));
    }
    let Value::Map(members) = decoded else {
        return Err(BlockExchangeError::Malformed(
            "message is not a map".to_string(),
        ));
    };
    let type_text = members
        .iter()
        .find_map(|(k, v)| match k {
            Key::Text(name) if name == "t" => match v {
                Value::Text(text) => Some(text.as_str()),
                _ => None,
            },
            _ => None,
        })
        .ok_or_else(|| BlockExchangeError::Malformed("t must be text".to_string()))?;
    match type_text {
        "BHELLO" => {
            // `max` is read and NOT acted upon here. VWIP-0005 5.1: a peer declaring
            // 2^53 must cost the receiver nothing beyond this message, so nothing
            // downstream may size a buffer from it.
            Ok(BlockMessage::BHello {
                v: uint_field(&members, "v")?,
                max: uint_field(&members, "max")?,
            })
        }
        "BWANT" => Ok(BlockMessage::BWant {
            cids: bstr_array(&members, "cids", BXLimit::WANT_CIDS, BXLimit::CID_BYTES)?,
        }),
        "BDONE" => Ok(BlockMessage::BDone {
            cids: bstr_array(&members, "cids", BXLimit::WANT_CIDS, BXLimit::CID_BYTES)?,
        }),
        "BLOCKS" => Ok(BlockMessage::Blocks {
            blks: bstr_array(
                &members,
                "blks",
                BXLimit::BLOCKS_PER_MESSAGE,
                BXLimit::BLOCK_BYTES,
            )?,
        }),
        other => {
            // Ignored rather than fatal, per VWIP-0005 3.2: refusing to speak to a
            // peer that knows a message you do not is how a protocol becomes
            // unextendable. The caller drops the message; the code distinguishes that
            // from a reason to close the connection.
            Err(BlockExchangeError::UnknownType(format!(
                "unknown message type {other:?}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_roundtrip_preserves_every_message_shape() {
        let messages = vec![
            BlockMessage::BHello {
                v: BLOCK_EXCHANGE_VERSION,
                max: BXLimit::BLOCK_BYTES as u64,
            },
            BlockMessage::BWant {
                cids: vec![vec![1u8; 36], vec![2u8; 64]],
            },
            BlockMessage::Blocks {
                blks: vec![vec![7u8; 262_144], vec![9u8; 1024]],
            },
            BlockMessage::BDone {
                cids: vec![vec![3u8; 36]],
            },
        ];
        for message in &messages {
            let encoded = encode_block_message(message).expect("encodes");
            assert!(encoded.len() <= BXLimit::MESSAGE_BYTES);
            let decoded = decode_block_message(&encoded).expect("decodes");
            assert_eq!(&decoded, message, "roundtrip is exact");
        }
    }

    #[test]
    fn the_sender_refuses_what_the_receiver_must() {
        // 3.4.a: declaring a max above the block limit is forbidden on emit.
        let absurd = BlockMessage::BHello {
            v: BLOCK_EXCHANGE_VERSION,
            max: (1 << 53) - 1,
        };
        assert!(matches!(
            encode_block_message(&absurd),
            Err(BlockExchangeError::LimitExceeded(_))
        ));
        // The same declaration decodes fine — `max` is read and not acted upon.
        let encoded = {
            // Build by hand; the encoder refuses it.
            cbor::encode(&Value::Map(vec![
                (
                    Key::Text("t".to_string()),
                    Value::Text("BHELLO".to_string()),
                ),
                (
                    Key::Text("v".to_string()),
                    Value::UInt(BLOCK_EXCHANGE_VERSION),
                ),
                (Key::Text("max".to_string()), Value::UInt((1 << 53) - 1)),
            ]))
            .expect("encodes")
        };
        assert!(matches!(
            decode_block_message(&encoded),
            Ok(BlockMessage::BHello { .. })
        ));

        // 3.6.a: an identifier named twice is refused on emit.
        let dup = BlockMessage::BWant {
            cids: vec![vec![1u8; 36], vec![1u8; 36]],
        };
        assert!(matches!(
            encode_block_message(&dup),
            Err(BlockExchangeError::Malformed(_))
        ));
        // And on receive, if it somehow arrived anyway.
        let raw = cbor::encode(&Value::Map(vec![
            (Key::Text("t".to_string()), Value::Text("BWANT".to_string())),
            (
                Key::Text("cids".to_string()),
                Value::Array(vec![
                    Value::Bytes(vec![5u8; 36]),
                    Value::Bytes(vec![5u8; 36]),
                ]),
            ),
        ]))
        .expect("encodes");
        // And on receive, if it somehow arrived anyway: the reference decoder ACCEPTS
        // it — 3.6.a binds senders, and a receiver verifies every block against the
        // identifiers IT asked for, so a duplicate demand wastes only the demander's
        // breath. Parity over purity: differing refusals would fork the wire.
        assert!(matches!(
            decode_block_message(&raw),
            Ok(BlockMessage::BWant { .. })
        ));
    }

    #[test]
    fn limits_bind_in_the_order_that_costs_least() {
        // Over the identifier-count limit: refused before any element is inspected.
        let too_many_cids = BlockMessage::BWant {
            cids: (0..(BXLimit::WANT_CIDS + 1))
                .map(|i| vec![i as u8; 36])
                .collect(),
        };
        match encode_block_message(&too_many_cids) {
            // The encoder's distinctness check passes (all distinct), so the refusal
            // must come from the receiver's count limit.
            Ok(bytes) => assert!(matches!(
                decode_block_message(&bytes),
                Err(BlockExchangeError::LimitExceeded(_))
            )),
            Err(e) => panic!("distinct identifiers should reach the wire: {e}"),
        }
        // A non-byte element where bytes belong is MALFORMED, not LIMIT_EXCEEDED:
        // shape first, size second.
        let wrong_shape = cbor::encode(&Value::Map(vec![
            (Key::Text("t".to_string()), Value::Text("BWANT".to_string())),
            (
                Key::Text("cids".to_string()),
                Value::Array(vec![Value::Text("nope".to_string())]),
            ),
        ]))
        .expect("encodes");
        assert!(matches!(
            decode_block_message(&wrong_shape),
            Err(BlockExchangeError::Malformed(_))
        ));
    }
}
