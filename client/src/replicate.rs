//! Replication message codecs — REPLICATION.md sections 3–7, without the session.
//!
//! Same division as `blockx`: pure functions over bytes so that when Phase 4 unblocks,
//! this client already speaks octets proven identical to the reference by the same
//! conformance vectors. The SESSION logic (want ranges answered from a log, verdicts
//! applied through a sink, checkpoint comparison) is deliberately not here yet; these
//! are the shapes everything else will be written against.
//!
//! Five message types carry everything two peers have to agree about: HELLO states the
//! opening claim, WANT asks for a bounded range of the REMOTE log by index, RECORDS
//! carries record encodings the receiver verifies and nobody else vouches for,
//! CHECKPOINT is evidence for a light client to weigh (never an instruction to a
//! session), and EQUIVOCATION names two records at one seq by one owner — verifiable
//! from the pair alone via [`crate::verify::is_equivocation_evidence`].

use crate::cbor::{self, Key, Value};

/// Every bound the replication format enforces. REPLICATION.md section 5.
pub struct RepLimit;
impl RepLimit {
    /// Whole-message encoding bound, checked before decoding: asking the decoder to
    /// chew through a megabyte to discover the message was too big is the denial of
    /// service the limit exists to prevent.
    pub const MESSAGE_BYTES: usize = 65_536;
    /// Records one RECORDS batch may name. An honest reply to a full WANT is routinely
    /// split: this bounds ARRAY ITERATION while MESSAGE_BYTES bounds volume.
    pub const RECORDS_PER_BATCH: usize = 256;
    /// One record encoding's bound (REGISTRY.md's own), enforced at receive time.
    pub const RECORD_BYTES: usize = 4096;
    /// A tree root's exact length. BLAKE2b-256, matching the log's own primitive.
    pub const ROOT_BYTES: usize = 32;
}

/// Why a message could not be encoded or decoded. The codes are the wire contract's
/// refusal vocabulary; conformance vectors name them verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicationError {
    TooLarge(String),
    NonCanonical(String),
    Malformed(String),
    UnknownType(String),
    LimitExceeded(String),
}

impl core::fmt::Display for ReplicationError {
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

/// One replication message. REPLICATION.md sections 3–7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicationMessage {
    /// The opening claim: protocol version, log length, tree root.
    Hello { v: u64, len: u64, root: Vec<u8> },
    /// A bounded range of the remote log, by index.
    Want { from: u64, count: u64 },
    /// Record encodings, verified by the receiver and nobody else.
    Records { from: u64, recs: Vec<Vec<u8>> },
    /// Evidence for a light client to weigh, never an instruction to a session.
    Checkpoint {
        len: u64,
        tree_root: Vec<u8>,
        index_root: Vec<u8>,
        live_names: u64,
    },
    /// Two records at one seq by one owner, verifiable from the pair alone.
    Equivocation { a: Vec<u8>, b: Vec<u8> },
}

/// The message type as it appears on the wire.
fn type_name(message: &ReplicationMessage) -> &'static str {
    match message {
        ReplicationMessage::Hello { .. } => "HELLO",
        ReplicationMessage::Want { .. } => "WANT",
        ReplicationMessage::Records { .. } => "RECORDS",
        ReplicationMessage::Checkpoint { .. } => "CHECKPOINT",
        ReplicationMessage::Equivocation { .. } => "EQUIVOCATION",
    }
}

/// Encode a message as deterministic CBOR.
///
/// Deterministic for the same reason records are: an encoding a peer can vary without
/// changing the content is an encoding two peers can disagree about while both being
/// right. Size is checked on the way out too — the peer best placed to notice is the
/// one that built the message.
pub fn encode_message(message: &ReplicationMessage) -> Result<Vec<u8>, ReplicationError> {
    let mut members: Vec<(Key, Value)> = Vec::new();
    members.push((
        Key::Text("t".to_string()),
        Value::Text(type_name(message).to_string()),
    ));
    match message {
        ReplicationMessage::Hello { v, len, root } => {
            members.push((Key::Text("v".to_string()), Value::UInt(*v)));
            members.push((Key::Text("len".to_string()), Value::UInt(*len)));
            members.push((Key::Text("root".to_string()), Value::Bytes(root.clone())));
        }
        ReplicationMessage::Want { from, count } => {
            members.push((Key::Text("from".to_string()), Value::UInt(*from)));
            members.push((Key::Text("count".to_string()), Value::UInt(*count)));
        }
        ReplicationMessage::Records { from, recs } => {
            members.push((Key::Text("from".to_string()), Value::UInt(*from)));
            members.push((
                Key::Text("recs".to_string()),
                Value::Array(recs.iter().map(|r| Value::Bytes(r.clone())).collect()),
            ));
        }
        ReplicationMessage::Checkpoint {
            len,
            tree_root,
            index_root,
            live_names,
        } => {
            members.push((Key::Text("len".to_string()), Value::UInt(*len)));
            members.push((
                Key::Text("treeRoot".to_string()),
                Value::Bytes(tree_root.clone()),
            ));
            members.push((
                Key::Text("indexRoot".to_string()),
                Value::Bytes(index_root.clone()),
            ));
            members.push((Key::Text("liveNames".to_string()), Value::UInt(*live_names)));
        }
        ReplicationMessage::Equivocation { a, b } => {
            members.push((Key::Text("a".to_string()), Value::Bytes(a.clone())));
            members.push((Key::Text("b".to_string()), Value::Bytes(b.clone())));
        }
    }
    let bytes = cbor::encode(&Value::Map(members))
        .map_err(|e| ReplicationError::Malformed(e.to_string()))?;
    if bytes.len() > RepLimit::MESSAGE_BYTES {
        return Err(ReplicationError::TooLarge(format!(
            "message encodes to {} bytes, over the {} limit",
            bytes.len(),
            RepLimit::MESSAGE_BYTES
        )));
    }
    Ok(bytes)
}

fn uint_field(members: &[(Key, Value)], key: &str) -> Result<u64, ReplicationError> {
    members
        .iter()
        .find_map(|(k, v)| match k {
            Key::Text(name) if name == key => Some(v),
            _ => None,
        })
        .ok_or_else(|| ReplicationError::Malformed(format!("{key} is required")))
        .and_then(|v| match v {
            Value::UInt(n) => Ok(*n),
            _ => Err(ReplicationError::Malformed(format!(
                "{key} must be an unsigned integer"
            ))),
        })
}

/// A byte string, optionally with an exact required length.
fn bstr_field(
    members: &[(Key, Value)],
    key: &str,
    length: Option<usize>,
) -> Result<Vec<u8>, ReplicationError> {
    let value = members
        .iter()
        .find_map(|(k, v)| match k {
            Key::Text(name) if name == key => Some(v),
            _ => None,
        })
        .ok_or_else(|| ReplicationError::Malformed(format!("{key} is required")))?;
    let Value::Bytes(bytes) = value else {
        return Err(ReplicationError::Malformed(format!(
            "{key} must be a byte string"
        )));
    };
    if let Some(length) = length {
        if bytes.len() != length {
            return Err(ReplicationError::Malformed(format!(
                "{key} must be {length} bytes, got {}",
                bytes.len()
            )));
        }
    }
    Ok(bytes.clone())
}

/// Decode a message, enforcing size and shape before anything is believed.
///
/// The whole-message bound runs against the raw octets before parsing; the batch bound
/// runs against the array length before any element is inspected — length first, then
/// each element, because reversing those two is how a limit becomes an accounting of
/// work already done.
pub fn decode_message(bytes: &[u8]) -> Result<ReplicationMessage, ReplicationError> {
    if bytes.len() > RepLimit::MESSAGE_BYTES {
        return Err(ReplicationError::TooLarge(format!(
            "message is {} bytes, over the {} limit",
            bytes.len(),
            RepLimit::MESSAGE_BYTES
        )));
    }
    let decoded = cbor::decode(bytes)
        .map_err(|e| ReplicationError::NonCanonical(format!("not deterministic CBOR: {e}")))?;
    // Belt and braces against a decoder that normalises where it should refuse.
    let reencoded =
        cbor::encode(&decoded).map_err(|e| ReplicationError::NonCanonical(e.to_string()))?;
    if reencoded.as_slice() != bytes {
        return Err(ReplicationError::NonCanonical(
            "bytes are not the deterministic encoding of their content".to_string(),
        ));
    }
    let Value::Map(members) = decoded else {
        return Err(ReplicationError::Malformed(
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
        .ok_or_else(|| ReplicationError::Malformed("t must be text".to_string()))?;
    match type_text {
        "HELLO" => Ok(ReplicationMessage::Hello {
            v: uint_field(&members, "v")?,
            len: uint_field(&members, "len")?,
            root: bstr_field(&members, "root", Some(RepLimit::ROOT_BYTES))?,
        }),
        "WANT" => Ok(ReplicationMessage::Want {
            from: uint_field(&members, "from")?,
            count: uint_field(&members, "count")?,
        }),
        "RECORDS" => {
            let recs_value = members
                .iter()
                .find_map(|(k, v)| match k {
                    Key::Text(name) if name == "recs" => Some(v),
                    _ => None,
                })
                .ok_or_else(|| ReplicationError::Malformed("recs is required".to_string()))?;
            let Value::Array(entries) = recs_value else {
                return Err(ReplicationError::Malformed(
                    "recs must be an array".to_string(),
                ));
            };
            // Length first: a batch of a million entries is refused having touched none.
            if entries.len() > RepLimit::RECORDS_PER_BATCH {
                return Err(ReplicationError::LimitExceeded(format!(
                    "batch of {} exceeds the {} limit",
                    entries.len(),
                    RepLimit::RECORDS_PER_BATCH
                )));
            }
            let mut out = Vec::with_capacity(entries.len());
            for entry in entries {
                let Value::Bytes(bytes) = entry else {
                    return Err(ReplicationError::Malformed(
                        "recs must hold byte strings".to_string(),
                    ));
                };
                out.push(bytes.clone());
            }
            Ok(ReplicationMessage::Records {
                from: uint_field(&members, "from")?,
                recs: out,
            })
        }
        "CHECKPOINT" => Ok(ReplicationMessage::Checkpoint {
            len: uint_field(&members, "len")?,
            tree_root: bstr_field(&members, "treeRoot", Some(RepLimit::ROOT_BYTES))?,
            index_root: bstr_field(&members, "indexRoot", Some(RepLimit::ROOT_BYTES))?,
            live_names: uint_field(&members, "liveNames")?,
        }),
        "EQUIVOCATION" => Ok(ReplicationMessage::Equivocation {
            a: bstr_field(&members, "a", None)?,
            b: bstr_field(&members, "b", None)?,
        }),
        other => Err(ReplicationError::UnknownType(format!(
            "unknown message type {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_roundtrip_preserves_every_message_shape() {
        let messages = vec![
            ReplicationMessage::Hello {
                v: 1,
                len: 7,
                root: vec![9u8; RepLimit::ROOT_BYTES],
            },
            ReplicationMessage::Want {
                from: 0,
                count: 256,
            },
            ReplicationMessage::Records {
                from: 3,
                recs: vec![vec![1u8; 128], vec![2u8; 4096]],
            },
            ReplicationMessage::Checkpoint {
                len: 12,
                tree_root: vec![3u8; RepLimit::ROOT_BYTES],
                index_root: vec![4u8; RepLimit::ROOT_BYTES],
                live_names: 41,
            },
            ReplicationMessage::Equivocation {
                a: vec![5u8; 300],
                b: vec![6u8; 300],
            },
        ];
        for message in &messages {
            let encoded = encode_message(message).expect("encodes");
            assert!(encoded.len() <= RepLimit::MESSAGE_BYTES);
            let decoded = decode_message(&encoded).expect("decodes");
            assert_eq!(&decoded, message, "roundtrip is exact");
        }
    }

    #[test]
    fn the_batch_bound_refuses_before_touching_elements() {
        let mut members: Vec<(Key, Value)> = vec![
            (
                Key::Text("t".to_string()),
                Value::Text("RECORDS".to_string()),
            ),
            (Key::Text("from".to_string()), Value::UInt(0)),
        ];
        let mut recs: Vec<Value> = (0..RepLimit::RECORDS_PER_BATCH)
            .map(|_| Value::Bytes(vec![]))
            .collect();
        recs.push(Value::Text("not even bytes".to_string())); // 257th entry, wrong shape
        members.push((Key::Text("recs".to_string()), Value::Array(recs)));
        let raw = cbor::encode(&Value::Map(members)).expect("encodes");
        // LIMIT_EXCEEDED, NOT MALFORMED: the count binds before any element is read.
        assert!(matches!(
            decode_message(&raw),
            Err(ReplicationError::LimitExceeded(_))
        ));
    }

    #[test]
    fn roots_are_exact_and_unknown_types_are_named() {
        let short_root = cbor::encode(&Value::Map(vec![
            (Key::Text("t".to_string()), Value::Text("HELLO".to_string())),
            (Key::Text("v".to_string()), Value::UInt(1)),
            (Key::Text("len".to_string()), Value::UInt(0)),
            (Key::Text("root".to_string()), Value::Bytes(vec![0u8; 31])),
        ]))
        .expect("encodes");
        assert!(matches!(
            decode_message(&short_root),
            Err(ReplicationError::Malformed(_))
        ));
        let alien = cbor::encode(&Value::Map(vec![(
            Key::Text("t".to_string()),
            Value::Text("GOSSIP".to_string()),
        )]))
        .expect("encodes");
        assert!(matches!(
            decode_message(&alien),
            Err(ReplicationError::UnknownType(_))
        ));
    }
}
