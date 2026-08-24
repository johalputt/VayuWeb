//! Content identifiers: the addressing scheme a published site is pointed at.
//!
//! The client-side counterpart of `registry/src/content.ts`; HOSTING.md's "Content addressing"
//! section fixes the parameters. Only one shape of CID exists here, on purpose: CIDv1, raw or
//! dag-pb codec, sha2-256. A CIDv0, a base58 rendering, a BLAKE3 multihash or a dag-json codec
//! are all valid CIDs somewhere on the internet, and accepting one would mean a registry record
//! could point at content no conforming resolver addresses the way the specification requires.
//! Refusal is interoperability, not narrow-mindedness.
//!
//! The binary form is what a registry record actually carries: `version || codec ||
//! multihash-code || digest-length || digest`, each an unsigned LEB128 varint. The familiar
//! `bafkrei…` text form is that byte string rendered under multibase base32-lowercase — the
//! derived form, not the stored one.

use sha2::{Digest, Sha256};

/// CIDv1. Version 0 is base58btc dag-pb only and cannot express a raw leaf.
pub const CID_VERSION: u64 = 1;
/// Fixed-size chunker, 256 KiB. Deterministic across implementations, unlike Rabin.
pub const CHUNK_BYTES: usize = 262_144;
/// Maximum links per UnixFS node in the balanced DAG. Stated by the specification; the importer
/// this module ports does not enforce it and neither does this port, which is recorded where the
/// tree is built rather than hidden here.
pub const MAX_LINKS: usize = 174;
/// Raw block codec: a leaf's CID is the hash of the leaf's bytes and nothing else.
pub const CODEC_RAW: u64 = 0x55;
/// dag-pb, for directories and for files that need more than one block.
pub const CODEC_DAG_PB: u64 = 0x70;
/// sha2-256 multihash code, for interoperability with the IPFS network.
pub const MULTIHASH_SHA2_256: u64 = 0x12;
/// sha2-256 digest length in bytes.
pub const DIGEST_BYTES: usize = 32;

/// Why content addressing refused something.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentError {
    /// A CID string that does not decode under the one admitted shape.
    BadCid(&'static str),
    /// A digest whose length is not sha2-256's.
    BadDigest(usize),
}

impl core::fmt::Display for ContentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadCid(reason) => write!(f, "{reason}"),
            Self::BadDigest(found) => {
                write!(f, "a sha2-256 digest is {DIGEST_BYTES} bytes, got {found}")
            }
        }
    }
}

impl std::error::Error for ContentError {}

fn varint(value: u64, out: &mut Vec<u8>) {
    let mut remaining = value;
    loop {
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if remaining == 0 {
            return;
        }
    }
}

fn read_varint(bytes: &[u8], at: &mut usize) -> Result<u64, ContentError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *at >= bytes.len() {
            return Err(ContentError::BadCid("truncated varint"));
        }
        let byte = bytes[*at];
        *at += 1;
        // Shifts beyond 63 would wrap u64; every field here is small, so a long varint is
        // malformed input rather than a large number.
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 63 {
            return Err(ContentError::BadCid("varint is too long"));
        }
    }
}

/// Split bytes into fixed-size chunks; the empty input yields exactly one empty chunk.
///
/// A file of zero bytes is a file, it has a CID, and returning no chunks would make it
/// addressless — the edge case that only shows up when someone publishes a placeholder.
pub fn chunk(bytes: &[u8]) -> Vec<&[u8]> {
    if bytes.is_empty() {
        return vec![&[]];
    }
    bytes.chunks(CHUNK_BYTES).collect()
}

/// sha2-256, the content-side hash.
pub fn sha256(bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut out = [0u8; DIGEST_BYTES];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

/// A decoded CID, in the only shape this specification admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cid {
    pub version: u64,
    pub codec: u64,
    pub digest: [u8; DIGEST_BYTES],
}

impl Cid {
    /// Hash bytes into a raw-codec CID.
    pub fn raw_from_bytes(bytes: &[u8]) -> Self {
        Self {
            version: CID_VERSION,
            codec: CODEC_RAW,
            digest: sha256(bytes),
        }
    }

    /// The binary form a registry record carries.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + DIGEST_BYTES);
        varint(self.version, &mut out);
        varint(self.codec, &mut out);
        varint(MULTIHASH_SHA2_256, &mut out);
        varint(self.digest.len() as u64, &mut out);
        out.extend_from_slice(&self.digest);
        out
    }

    /// Parse the binary form, refusing codecs and hashes this protocol does not use.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContentError> {
        let mut at = 0usize;
        let version = read_varint(bytes, &mut at)?;
        if version != CID_VERSION {
            return Err(ContentError::BadCid("only CIDv1 is used"));
        }
        let codec = read_varint(bytes, &mut at)?;
        if codec != CODEC_RAW && codec != CODEC_DAG_PB {
            return Err(ContentError::BadCid("codec is neither raw nor dag-pb"));
        }
        let multihash = read_varint(bytes, &mut at)?;
        if multihash != MULTIHASH_SHA2_256 {
            return Err(ContentError::BadCid("only sha2-256 is used"));
        }
        let length = read_varint(bytes, &mut at)?;
        if length as usize != DIGEST_BYTES {
            return Err(ContentError::BadCid("a sha2-256 digest is 32 bytes"));
        }
        if bytes.len() - at != DIGEST_BYTES {
            return Err(ContentError::BadCid(
                "digest length disagrees with the bytes present",
            ));
        }
        let mut digest = [0u8; DIGEST_BYTES];
        digest.copy_from_slice(&bytes[at..]);
        Ok(Self {
            version,
            codec,
            digest,
        })
    }

    /// The text form: the binary form rendered under multibase base32, lowercase, unpadded.
    pub fn to_text(&self) -> String {
        format!("b{}", base32_encode(&self.to_bytes()))
    }

    /// Decode the text form, refusing everything but the one admitted rendering.
    pub fn from_text(text: &str) -> Result<Self, ContentError> {
        let encoded = text.strip_prefix('b').ok_or(ContentError::BadCid(
            "the multibase prefix must be lowercase base32 'b'",
        ))?;
        Self::from_bytes(&base32_decode(encoded)?)
    }
}

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, lowercase alphabet, without padding.
///
/// The bit accumulator holds at most 12 bits at a time; the mask keeps the shift well-defined
/// for any input length, including the final partial group.
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut bits: u32 = 0;
    let mut value: u32 = 0;
    for &byte in bytes {
        value = (value << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((value >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[index] as char);
        }
    }
    if bits > 0 {
        let index = ((value << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[index] as char);
    }
    out
}

/// Inverse of [`base32_encode`], rejecting every character outside the alphabet.
pub fn base32_decode(text: &str) -> Result<Vec<u8>, ContentError> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut bits: u32 = 0;
    let mut value: u32 = 0;
    for character in text.bytes() {
        let index = BASE32_ALPHABET
            .iter()
            .position(|&c| c == character)
            .ok_or(ContentError::BadCid("character is not base32"))?;
        value = (value << 5) | index as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((value >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hello_world_leaf_hashes_to_the_reference_cid() {
        // Pinned by registry/src/unixfs.test.ts against the reference IPFS importer: a small
        // file's CID is the sha2-256 of its bytes and nothing else, so this vector also checks
        // with any ordinary hash tool.
        let cid = Cid::raw_from_bytes(b"hello world");
        assert_eq!(
            cid.to_text(),
            "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"
        );
        assert_eq!(cid.to_text().len(), 59);
    }

    #[test]
    fn the_empty_input_is_addressable() {
        let cid = Cid::raw_from_bytes(&[]);
        assert_eq!(
            cid.to_text(),
            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        );
    }

    #[test]
    fn binary_form_round_trips_through_text_and_back() {
        let original = Cid {
            version: CID_VERSION,
            codec: CODEC_DAG_PB,
            digest: [7; 32],
        };
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 36, "four one-byte varints plus the digest");
        assert_eq!(Cid::from_bytes(&bytes).expect("parses"), original);
        assert_eq!(
            Cid::from_text(&original.to_text()).expect("parses"),
            original
        );
    }

    #[test]
    fn decoding_refuses_every_shape_the_specification_does_not_use() {
        use ContentError::BadCid;
        let good = Cid {
            version: 1,
            codec: CODEC_RAW,
            digest: [9; 32],
        }
        .to_bytes();

        // Wrong version.
        let mut wrong = good.clone();
        wrong[0] = 0x00;
        assert!(matches!(Cid::from_bytes(&wrong), Err(BadCid(_))));
        // Wrong codec.
        let mut wrong = good.clone();
        wrong[1] = 0x70 ^ 0x01;
        assert!(matches!(Cid::from_bytes(&wrong), Err(BadCid(_))));
        // Wrong multihash function.
        let mut wrong = good.clone();
        wrong[2] = 0x13;
        assert!(matches!(Cid::from_bytes(&wrong), Err(BadCid(_))));
        // Wrong digest length.
        let mut wrong = good.clone();
        wrong[3] = 0x1f;
        assert!(matches!(Cid::from_bytes(&wrong), Err(BadCid(_))));
        // Truncated.
        assert!(matches!(Cid::from_bytes(&good[..20]), Err(BadCid(_))));
        // Not even the right prefix.
        assert!(matches!(
            Cid::from_text("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"),
            Err(BadCid(_))
        ));
    }

    #[test]
    fn base32_matches_the_reference_renderings_byte_for_byte() {
        // The two known digests above exercise both partial groups: 36 bytes = 57 full groups
        // plus 3 leftover bits, and 32 bytes ends exactly on a group boundary.
        assert_eq!(
            base32_decode(&base32_encode(&(0u8..=200).collect::<Vec<u8>>())).expect("decodes"),
            (0u8..=200).collect::<Vec<u8>>()
        );
        assert!(
            base32_decode("b01").is_err(),
            "digits outside the alphabet are refused"
        );
    }

    #[test]
    fn chunking_splits_at_the_fixed_size_and_keeps_the_empty_file_addressable() {
        assert_eq!(chunk(&[]).len(), 1, "one empty chunk, not none");
        assert_eq!(chunk(&[1, 2, 3]).len(), 1);
        let big = vec![7u8; CHUNK_BYTES + 10];
        let pieces = chunk(&big);
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].len(), CHUNK_BYTES);
        assert_eq!(pieces[1].len(), 10);
    }
}
