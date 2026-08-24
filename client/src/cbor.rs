//! Deterministic CBOR (RFC 8949 §4.2.1) — encoder and strict decoder.
//!
//! The client-side counterpart of `registry/src/cbor.ts`, which carries the fuller argument.
//! The short version of why this is hand-written rather than a crate: determinism is the
//! property being relied on, and a library that *can* emit canonical output still accepts
//! non-canonical input by default. REGISTRY.md requires that received bytes ARE deterministic
//! CBOR, because two byte strings for one record make `record_hash` malleable and a malleable
//! hash hands an attacker a free grinding surface at the convergence tie-break. So both halves
//! live here: the encoder emits nothing but the deterministic form, and the decoder REJECTS
//! anything that is not already in it rather than accepting leniently and re-encoding.
//!
//! The supported type set is exactly what the record schema uses — unsigned integers, byte
//! strings, text strings, arrays, maps, null — and everything else is refused in both
//! directions. Floats in particular are excluded on purpose: NaN payloads and ±0 give one
//! value several defensible encodings.
//!
//! What pins this port against the reference implementation is not prose but bytes: the
//! `blockExchange` suite of `conformance/vectors.json` carries exact wire encodings generated
//! by the registry, and this module's tests rebuild those messages and require identical hex,
//! plus every rejection shape the profile forbids.

/// Why input could not be decoded as deterministic CBOR, or a value encoded at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    /// A head used a longer form than the value needs — two encodings for one value.
    NonCanonical,
    /// Indefinite-length items (`0x1f` additional info) never have one deterministic form.
    IndefiniteLength,
    /// Additional-information values 28–30 are reserved by RFC 8949.
    ReservedAdditional(u8),
    /// Input ended before the item it promised was complete.
    Truncated,
    /// Bytes remained after a complete top-level item. A record is exactly its bytes.
    TrailingBytes { remaining: usize },
    /// Nesting deeper than [`MAX_DEPTH`].
    DepthExceeded,
    /// A map carried the same key twice. One value with two entries is not a map.
    DuplicateKey,
    /// A map's keys were not in strictly increasing encoded-byte order.
    KeysOutOfOrder,
    /// A map key that is neither text nor bytes; nothing else is in the profile.
    BadMapKey,
    /// A text string whose bytes are not well-formed UTF-8. Refused rather than substituted:
    /// U+FFFD replacement would let two byte strings decode to one text value.
    BadUtf8,
    /// Major type 1 (negative) or 6 (tag): outside the profile entirely.
    UnsupportedMajor(u8),
    /// Major type 7 carrying a float width. Floats are excluded on purpose; see the module
    /// header.
    FloatNotAllowed,
    /// Major type 7 carrying a simple value other than null.
    UnsupportedSimple(u8),
}

impl core::fmt::Display for CborError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonCanonical => write!(f, "NON_CANONICAL: value should use the shorter form"),
            Self::IndefiniteLength => {
                write!(
                    f,
                    "INDEFINITE_LENGTH: indefinite-length items are not deterministic"
                )
            }
            Self::ReservedAdditional(info) => {
                write!(
                    f,
                    "RESERVED_ADDITIONAL: reserved additional information {info}"
                )
            }
            Self::Truncated => write!(f, "TRUNCATED: input ended mid-item"),
            Self::TrailingBytes { remaining } => {
                write!(f, "TRAILING_BYTES: {remaining} unconsumed byte(s)")
            }
            Self::DepthExceeded => write!(f, "DEPTH_EXCEEDED: nesting deeper than {MAX_DEPTH}"),
            Self::DuplicateKey => write!(f, "DUPLICATE_KEY: duplicate map key"),
            Self::KeysOutOfOrder => write!(f, "KEYS_OUT_OF_ORDER: map keys are not sorted"),
            Self::BadMapKey => write!(f, "BAD_MAP_KEY: map keys must be text or byte strings"),
            Self::BadUtf8 => {
                write!(f, "BAD_UTF8: text string is not well-formed UTF-8")
            }
            Self::UnsupportedMajor(major) => {
                write!(
                    f,
                    "UNSUPPORTED_MAJOR: major type {major} is not in the profile"
                )
            }
            Self::FloatNotAllowed => {
                write!(
                    f,
                    "FLOAT_NOT_ALLOWED: floats are not in the deterministic profile"
                )
            }
            Self::UnsupportedSimple(value) => {
                write!(
                    f,
                    "UNSUPPORTED_SIMPLE: simple value {value} is not in the profile"
                )
            }
        }
    }
}

impl std::error::Error for CborError {}

/// Nesting limit on both directions, matching the registry implementation.
///
/// A record schema nests at most four deep; 32 leaves room for forward-compatible shapes while
/// refusing the recursion-depth attack an unbounded decoder offers.
pub const MAX_DEPTH: u32 = 32;

/// A map key. Only text and byte strings are in the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Text(String),
    Bytes(Vec<u8>),
}

/// Values representable in the registry's deterministic CBOR profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    UInt(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Carried in insertion order and sorted by encoded key bytes at encode time; the decoder
    /// returns keys in the order they arrive, which for conforming input IS encoded order.
    Map(Vec<(Key, Value)>),
    Null,
}

const MAJOR_UINT: u8 = 0;
const MAJOR_BSTR: u8 = 2;
const MAJOR_TSTR: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_SIMPLE: u8 = 7;
const SIMPLE_NULL: u8 = 22;

/// Bytewise comparison of two encoded map keys, as unsigned octets.
///
/// RFC 8949 §4.2.1 rule 3 orders map keys by their ENCODED byte sequence, not by the decoded
/// value. Sorting decoded strings by code point would put text keys in a different order than
/// sorting their CBOR encodings, because the encoding carries a length-bearing head byte first.
fn compare_encoded(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let shared = a.len().min(b.len());
    for index in 0..shared {
        if a[index] != b[index] {
            return a[index].cmp(&b[index]);
        }
    }
    a.len().cmp(&b.len())
}

fn head(major: u8, argument: u64, out: &mut Vec<u8>) {
    let base = major << 5;
    if argument < 24 {
        out.push(base | argument as u8);
    } else if argument <= 0xff {
        out.push(base | 24);
        out.push(argument as u8);
    } else if argument <= 0xffff {
        out.push(base | 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= 0xffff_ffff {
        out.push(base | 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(base | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

fn encode_value(value: &Value, out: &mut Vec<u8>, depth: u32) -> Result<(), CborError> {
    if depth > MAX_DEPTH {
        return Err(CborError::DepthExceeded);
    }
    match value {
        Value::Null => out.push((MAJOR_SIMPLE << 5) | SIMPLE_NULL),
        Value::UInt(v) => head(MAJOR_UINT, *v, out),
        Value::Bytes(bytes) => {
            head(MAJOR_BSTR, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            // Rust's String cannot carry a lone surrogate, so the reference encoder's
            // well-formedness refusal has no reachable case here; the length written is the
            // UTF-8 length by construction.
            let bytes = text.as_bytes();
            head(MAJOR_TSTR, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        Value::Array(items) => {
            head(MAJOR_ARRAY, items.len() as u64, out);
            for item in items {
                encode_value(item, out, depth + 1)?;
            }
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, &Value)> = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let mut key_bytes = Vec::new();
                match key {
                    Key::Text(text) => {
                        encode_value(&Value::Text(text.clone()), &mut key_bytes, depth + 1)?
                    }
                    Key::Bytes(bytes) => {
                        encode_value(&Value::Bytes(bytes.clone()), &mut key_bytes, depth + 1)?
                    }
                }
                encoded.push((key_bytes, value));
            }
            // Sort by encoded key bytes. `sort_by` is stable, but stability cannot rescue a
            // duplicate: equal keys stay adjacent either way and the check below fires.
            encoded.sort_by(|a, b| compare_encoded(&a.0, &b.0));
            for pair in encoded.windows(2) {
                if compare_encoded(&pair[0].0, &pair[1].0) == core::cmp::Ordering::Equal {
                    return Err(CborError::DuplicateKey);
                }
            }
            head(MAJOR_MAP, encoded.len() as u64, out);
            for (key_bytes, value) in encoded {
                out.extend_from_slice(&key_bytes);
                encode_value(value, out, depth + 1)?;
            }
        }
    }
    Ok(())
}

/// Encode a value as deterministic CBOR.
pub fn encode(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    encode_value(value, &mut out, 0)?;
    Ok(out)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], CborError> {
        if self.offset + count > self.bytes.len() {
            return Err(CborError::Truncated);
        }
        let slice = &self.bytes[self.offset..self.offset + count];
        self.offset += count;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        Ok(self.take(1)?[0])
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

/// Read a head argument, rejecting any non-shortest encoding.
///
/// This is the check that makes the decoder strict: `0x18 0x05` and `0x05` both mean 5 in
/// general CBOR, but only the second is deterministic. Accepting the first would mean two byte
/// strings decode to one record — exactly what the spec forbids.
fn read_argument(reader: &mut Reader<'_>, additional: u8) -> Result<u64, CborError> {
    match additional {
        0..=23 => Ok(u64::from(additional)),
        24 => {
            let v = reader.byte()?;
            if v < 24 {
                return Err(CborError::NonCanonical);
            }
            Ok(u64::from(v))
        }
        25 => {
            let bytes = reader.take(2)?;
            let v = u16::from_be_bytes([bytes[0], bytes[1]]);
            if v <= 0xff {
                return Err(CborError::NonCanonical);
            }
            Ok(u64::from(v))
        }
        26 => {
            let bytes = reader.take(4)?;
            let v = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if v <= 0xffff {
                return Err(CborError::NonCanonical);
            }
            Ok(u64::from(v))
        }
        27 => {
            let bytes = reader.take(8)?;
            let v = u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            if v <= 0xffff_ffff {
                return Err(CborError::NonCanonical);
            }
            Ok(v)
        }
        31 => Err(CborError::IndefiniteLength),
        reserved => Err(CborError::ReservedAdditional(reserved)),
    }
}

fn decode_value(reader: &mut Reader<'_>, depth: u32) -> Result<Value, CborError> {
    if depth > MAX_DEPTH {
        return Err(CborError::DepthExceeded);
    }
    let initial = reader.byte()?;
    let major = initial >> 5;
    let additional = initial & 0x1f;

    match major {
        MAJOR_UINT => Ok(Value::UInt(read_argument(reader, additional)?)),
        MAJOR_BSTR => {
            let len = read_argument(reader, additional)?;
            if len > reader.remaining() as u64 {
                return Err(CborError::Truncated);
            }
            Ok(Value::Bytes(reader.take(len as usize)?.to_vec()))
        }
        MAJOR_TSTR => {
            let len = read_argument(reader, additional)?;
            if len > reader.remaining() as u64 {
                return Err(CborError::Truncated);
            }
            let raw = reader.take(len as usize)?;
            // Strict UTF-8: malformed bytes are a refusal, never a substitution. Two distinct
            // byte strings must not decode to one text value.
            match std::str::from_utf8(raw) {
                Ok(text) => Ok(Value::Text(text.to_string())),
                Err(_) => Err(CborError::BadUtf8),
            }
        }
        MAJOR_ARRAY => {
            let len = read_argument(reader, additional)?;
            if len > reader.remaining() as u64 {
                // Every element costs at least one byte; more elements than bytes cannot be.
                return Err(CborError::Truncated);
            }
            let mut items = Vec::with_capacity(len.min(1024) as usize);
            for _ in 0..len {
                items.push(decode_value(reader, depth + 1)?);
            }
            Ok(Value::Array(items))
        }
        MAJOR_MAP => {
            let len = read_argument(reader, additional)?;
            // Capacity is capped because `len` is attacker-chosen and unbounded; the loop
            // itself refuses on the first truncation it meets.
            let mut entries: Vec<(Key, Value)> = Vec::with_capacity(len.min(512) as usize);
            let mut previous_key: Option<Vec<u8>> = None;
            for _ in 0..len {
                let key_start = reader.offset;
                let key_value = decode_value(reader, depth + 1)?;
                let key_bytes = reader.bytes[key_start..reader.offset].to_vec();
                let key = match key_value {
                    Value::Text(text) => Key::Text(text),
                    Value::Bytes(bytes) => Key::Bytes(bytes),
                    _ => return Err(CborError::BadMapKey),
                };
                if let Some(previous) = &previous_key {
                    match compare_encoded(previous, &key_bytes) {
                        core::cmp::Ordering::Equal => return Err(CborError::DuplicateKey),
                        core::cmp::Ordering::Greater => return Err(CborError::KeysOutOfOrder),
                        core::cmp::Ordering::Less => {}
                    }
                }
                previous_key = Some(key_bytes);
                let value = decode_value(reader, depth + 1)?;
                entries.push((key, value));
            }
            Ok(Value::Map(entries))
        }
        MAJOR_SIMPLE => {
            if additional == SIMPLE_NULL {
                return Ok(Value::Null);
            }
            if additional == 25 || additional == 26 || additional == 27 {
                return Err(CborError::FloatNotAllowed);
            }
            Err(CborError::UnsupportedSimple(additional))
        }
        other => Err(CborError::UnsupportedMajor(other)),
    }
}

/// Decode deterministic CBOR, rejecting any non-deterministic input.
///
/// Trailing bytes are an error: a record is exactly its bytes, and tolerating a suffix would
/// let two inputs carry one record while hashing differently.
pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
    let mut reader = Reader { bytes, offset: 0 };
    let value = decode_value(&mut reader, 0)?;
    if reader.offset != bytes.len() {
        return Err(CborError::TrailingBytes {
            remaining: bytes.len() - reader.offset,
        });
    }
    Ok(value)
}

/// True when `bytes` is already in deterministic form.
///
/// The registry needs this as a precondition rather than a normalisation step: REGISTRY.md
/// requires that a peer MUST NOT re-serialise a record it did not author, so received bytes
/// are stored and replicated verbatim.
pub fn is_deterministic(bytes: &[u8]) -> bool {
    match decode(bytes) {
        Ok(value) => match encode(&value) {
            Ok(reencoded) => reencoded.as_slice() == bytes,
            Err(_) => false,
        },
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(input: &str) -> Vec<u8> {
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn preferred_head_forms_are_shortest() {
        // RFC 8949 §4.2.1 rule 1, walked across every width boundary. Anything longer for the
        // same value would be a second valid encoding.
        let cases: Vec<(u64, &str)> = vec![
            (0, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65535, "19ffff"),
            (65536, "1a00010000"),
            (4294967295, "1affffffff"),
            (4294967296, "1b0000000100000000"),
        ];
        for (value, expected) in cases {
            let out = encode(&Value::UInt(value)).expect("encodes");
            assert_eq!(hex(&out), expected, "uint {value}");
        }
    }

    #[test]
    fn non_canonical_head_forms_are_refused_on_decode() {
        // `0x18 0x05` means 5, but 5 has a shorter form, so only `0x05` is deterministic.
        assert_eq!(decode(&unhex("1805")), Err(CborError::NonCanonical));
        assert_eq!(decode(&unhex("190005")), Err(CborError::NonCanonical));
        assert_eq!(decode(&unhex("1a00000005")), Err(CborError::NonCanonical));
        assert_eq!(
            decode(&unhex("1b0000000000000005")),
            Err(CborError::NonCanonical)
        );
        // Each shorter-width boundary value must also refuse the next width up.
        assert_eq!(decode(&unhex("1817")), Err(CborError::NonCanonical));
        assert_eq!(decode(&unhex("1900ff")), Err(CborError::NonCanonical));
    }

    #[test]
    fn map_keys_are_ordered_by_encoded_bytes_not_decoded_value() {
        // Encoded-byte order puts "b" FIRST here: its encoding starts 0x61 while "ab"'s
        // starts 0x62, although by code point "ab" < "abc" < "b". Sorting decoded strings and
        // sorting encodings genuinely disagree, which is why RFC 8949 §4.2.1 rule 3 names the
        // encoded form rather than the value.
        let map = Value::Map(vec![
            (Key::Text("ab".into()), Value::UInt(1)),
            (Key::Text("abc".into()), Value::UInt(2)),
            (Key::Text("b".into()), Value::UInt(3)),
        ]);
        let out = encode(&map).expect("encodes");
        assert_eq!(hex(&out), "a3616203626162016361626302");
        assert!(is_deterministic(&out));
    }

    #[test]
    fn a_map_carries_each_key_once_and_in_order() {
        let duplicate = Value::Map(vec![
            (Key::Text("k".into()), Value::UInt(1)),
            (Key::Text("k".into()), Value::UInt(2)),
        ]);
        assert_eq!(encode(&duplicate), Err(CborError::DuplicateKey));

        // The encoder accepts any insertion order — producing canonical output from whatever
        // the caller holds is its job — so unordered input encodes to the same bytes as the
        // ordered form. Order enforcement lives on the decode side, where arriving bytes are
        // already someone else's claim about determinism.
        let unordered = Value::Map(vec![
            (Key::Text("b".into()), Value::UInt(1)),
            (Key::Text("a".into()), Value::UInt(2)),
        ]);
        let canonical = encode(&unordered).expect("encodes");
        assert_eq!(hex(&canonical), "a2616102616201");

        // On decode, arriving order IS checked: sorted keys decode, reversed keys refuse.
        assert!(is_deterministic(&canonical));
        let reversed = unhex("a2616202616101");
        assert_eq!(decode(&reversed), Err(CborError::KeysOutOfOrder));
        let duplicated = unhex("a2616101616102");
        assert_eq!(decode(&duplicated), Err(CborError::DuplicateKey));
    }

    #[test]
    fn what_the_profile_leaves_out_stays_out() {
        // Indefinite length: the framing vectors' own rejection case, `{"a": 1, "b": 2}` in
        // indefinite form.
        assert_eq!(
            decode(&unhex("bf616101616102ff")),
            Err(CborError::IndefiniteLength)
        );

        // Negative integers (major 1) and tags (major 6).
        assert_eq!(decode(&unhex("20")), Err(CborError::UnsupportedMajor(1)));
        assert_eq!(decode(&unhex("c074")), Err(CborError::UnsupportedMajor(6)));

        // Floats at all three widths.
        assert_eq!(decode(&unhex("f90000")), Err(CborError::FloatNotAllowed));
        assert_eq!(
            decode(&unhex("fa00000000")),
            Err(CborError::FloatNotAllowed)
        );
        assert_eq!(
            decode(&unhex("fb0000000000000000")),
            Err(CborError::FloatNotAllowed)
        );

        // Other simple values; null (22) is the one simple value in the profile.
        assert_eq!(decode(&unhex("f4")), Err(CborError::UnsupportedSimple(20)));
        assert_eq!(decode(&unhex("f5")), Err(CborError::UnsupportedSimple(21)));
        assert_eq!(decode(&unhex("f6")), Ok(Value::Null));

        // A non-text, non-bytes map key.
        assert_eq!(decode(&unhex("a10102")), Err(CborError::BadMapKey));
    }

    #[test]
    fn truncation_and_trailing_bytes_are_distinct_refusals() {
        // A declared length running past the end of the input.
        assert_eq!(decode(&unhex("5820")), Err(CborError::Truncated));
        assert_eq!(decode(&unhex("58")), Err(CborError::Truncated));
        assert_eq!(decode(&unhex("637878")), Err(CborError::Truncated));
        // A complete item followed by more bytes: a record is exactly its bytes, so even one
        // unconsumed byte is refused rather than ignored.
        assert_eq!(decode(&unhex("00")).expect("complete"), Value::UInt(0));
        assert_eq!(
            decode(&unhex("0000")),
            Err(CborError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn nesting_is_bounded_in_both_directions() {
        let deep_array = (0..MAX_DEPTH + 1).fold(Value::Null, |inner, _| Value::Array(vec![inner]));
        assert_eq!(encode(&deep_array), Err(CborError::DepthExceeded));
        let deep_bytes = {
            let mut bytes = vec![0x81; MAX_DEPTH as usize + 1]; // array header, one element
            bytes.push(0xf6);
            bytes
        };
        assert_eq!(decode(&deep_bytes), Err(CborError::DepthExceeded));
    }

    #[test]
    fn text_must_be_well_formed_utf8() {
        // U+FFFD substitution would let two byte strings decode to one text value; the
        // reference decoder refuses instead and so does this one.
        assert!(decode(&unhex("62c328")).is_err(), "invalid continuation");
        assert!(
            decode(&unhex("63ed a080".replace(' ', "").as_str())).is_err(),
            "surrogate"
        );
        assert_eq!(
            decode(&unhex("61 78".replace(' ', "").as_str())),
            Ok(Value::Text("x".into()))
        );
    }

    #[test]
    fn blockexchange_vectors_rebuild_byte_for_byte() {
        // conformance/vectors.json, suite `blockExchange`. These hex strings were GENERATED by
        // the registry implementation; rebuilding them here and requiring identity is the
        // interop pin between the two codecs. Kept in step with the artifact by review — the
        // file itself is asserted by the registry's own suites, and a drift shows up as a diff
        // in CI's regenerate-and-require-no-diff job long before it shows up here.
        let bhello = Value::Map(vec![
            (Key::Text("t".into()), Value::Text("BHELLO".into())),
            (Key::Text("v".into()), Value::UInt(1)),
            (Key::Text("max".into()), Value::UInt(1048576)),
        ]);
        assert_eq!(
            hex(&encode(&bhello).expect("encodes")),
            "a36174664248454c4c4f617601636d61781a00100000"
        );

        // max = 2^53 − 1: the largest value JSON can carry exactly, and proof that the u64
        // path does not silently narrow through an f64 somewhere.
        let absurd = Value::Map(vec![
            (Key::Text("t".into()), Value::Text("BHELLO".into())),
            (Key::Text("v".into()), Value::UInt(1)),
            (Key::Text("max".into()), Value::UInt(9007199254740991)),
        ]);
        assert_eq!(
            hex(&encode(&absurd).expect("encodes")),
            "a36174664248454c4c4f617601636d61781b001fffffffffffff"
        );

        // BWANT with one 36-byte identifier: the commonest message on the wire.
        let cid: Vec<u8> =
            unhex("015512201efc3702c902463755b26361db92421394bd86090564b8873ddd6addc9ecedbe");
        let bwant = Value::Map(vec![
            (Key::Text("t".into()), Value::Text("BWANT".into())),
            (
                Key::Text("cids".into()),
                Value::Array(vec![Value::Bytes(cid.clone())]),
            ),
        ]);
        assert_eq!(
            hex(&encode(&bwant).expect("encodes")),
            "a26174654257414e546463696473815824015512201efc3702c902463755b26361db92421394bd86090564b8873ddd6addc9ecedbe"
        );

        // And the round trip back through the decoder agrees about what arrived.
        match decode(&unhex(
            "a26174654257414e546463696473815824015512201efc3702c902463755b26361db92421394bd86090564b8873ddd6addc9ecedbe",
        ))
        .expect("decodes")
        {
            Value::Map(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].0, Key::Text("t".into()));
                assert_eq!(entries[1].0, Key::Text("cids".into()));
                match &entries[1].1 {
                    Value::Array(items) => {
                        assert_eq!(items.len(), 1);
                        assert_eq!(items[0], Value::Bytes(cid));
                    }
                    other => panic!("expected array of cids, got {other:?}"),
                }
            }
            other => panic!("expected map, got {other:?}"),
        }
    }

    #[test]
    fn round_trips_preserve_values_across_the_whole_profile() {
        // Constructed in encoded-key order, where each text key's first byte is
        // (major << 5) | length — 0x64 for "null", 0x66 for "nested", 0x6b for
        // "empty-bytes" — which is why "nested" precedes "empty-bytes" here although no
        // string sort would put it there. Decode returns entries in arrival order and
        // equality compares entry order, so this construction states the canonical form
        // directly rather than leaning on the encoder's sort.
        let value = Value::Map(vec![
            (
                Key::Bytes(vec![0x00, 0xff]),
                Value::Text("binary key".into()),
            ),
            (Key::Text("null".into()), Value::Null),
            (
                Key::Text("nested".into()),
                Value::Array(vec![
                    Value::UInt(0),
                    Value::UInt(u64::MAX),
                    Value::Array(Vec::new()),
                    Value::Map(Vec::new()),
                ]),
            ),
            (Key::Text("empty-bytes".into()), Value::Bytes(Vec::new())),
        ]);
        let out = encode(&value).expect("encodes");
        assert_eq!(decode(&out).expect("decodes"), value);
        assert!(is_deterministic(&out));
    }

    #[test]
    fn decoding_then_encoding_is_the_identity_for_conforming_input() {
        // The property the verifier leans on when it re-encodes to confirm canonicality.
        for hex_case in [
            "a36174664248454c4c4f617601636d61781a00100000",
            "a26174654257414e546463696473815824015512201efc3702c902463755b26361db92421394bd86090564b8873ddd6addc9ecedbe",
            "f6",
            "40",
            "60",
            "80",
            "a0",
        ] {
            let bytes = unhex(hex_case);
            assert!(is_deterministic(&bytes), "{hex_case}");
            let value = decode(&bytes).expect("decodes");
            assert_eq!(encode(&value).expect("re-encodes"), bytes, "{hex_case}");
        }
    }
}
