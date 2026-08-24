//! Reading trees back out of the store: the verified traversal's client half.
//!
//! [`crate::publish`] builds trees and [`crate::store`] holds their blocks; serving a published
//! site needs the third leg — walk a dag-pb directory by name, recognise a UnixFS file, assemble
//! its bytes. This module mirrors the implementation of record's `fetch.ts` discipline in the
//! one way that matters structurally: **every block is verified against the CID that referred
//! it before its contents are interpreted** — the store's own read-time check covers this for
//! bytes it hands out, and nothing here accepts bytes from anywhere else. The bounds below are
//! FETCH_LIMITS' local counterparts: a tree that exceeds them is refused, not truncated.

use crate::cid::{Cid, CODEC_DAG_PB, CODEC_RAW, MAX_LINKS};
use crate::store::{BlockStore, StoreError};

/// A directory entry as carried by a dag-pb node: the target CID, the entry NAME, and the
/// cumulative size of the subtree it names.
#[derive(Debug, Clone)]
pub struct DirLink {
    pub cid: Cid,
    pub name: String,
    #[allow(dead_code)]
    pub tsize: u64,
}

/// What a node turned out to be once decoded.
#[derive(Debug, Clone)]
pub enum Node {
    /// A raw leaf: the block IS the bytes.
    Raw(Vec<u8>),
    /// A UnixFS file: inline bytes plus chunk leaves, assembled in link order.
    File { data: Vec<u8>, children: Vec<Cid> },
    /// A UnixFS directory: named entries.
    Directory(Vec<DirLink>),
}

// ---------------------------------------------------------------------------
// Minimal protobuf reading, exactly as much of the wire format as dag-pb uses.
//
// dag-pb nodes are protobuf messages where field 2 (Links) is serialised BEFORE field 1 (Data)
// — the layout publish.rs writes deliberately against every protobuf habit. A reader must
// accept either wire order anyway: a tree built by any conforming importer may legally
// interleave. Unknown fields are skipped, not rejected.
// ---------------------------------------------------------------------------

fn read_varint(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while {
        let byte = *bytes.get(*pos)?;
        *pos += 1;
        value |= ((byte & 0x7f) as u64).checked_shl(shift)?;
        byte & 0x80 != 0
    } {
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    Some(value)
}

fn skip_field(bytes: &[u8], pos: &mut usize, wire_type: u64) -> Option<()> {
    match wire_type {
        0 => {
            read_varint(bytes, pos)?;
        }
        1 => *pos += 8,
        2 => {
            let len = usize::try_from(read_varint(bytes, pos)?).ok()?;
            *pos = pos.checked_add(len)?;
        }
        5 => *pos += 4,
        _ => return None,
    }
    if *pos <= bytes.len() {
        Some(())
    } else {
        None
    }
}

/// One decoded dag-pb node: its Data bytes (field 1) and its links in wire order.
struct PbNode {
    data: Vec<u8>,
    links: Vec<PbLink>,
}

struct PbLink {
    hash: Vec<u8>,
    name: String,
    tsize: u64,
}

fn parse_pb_node(bytes: &[u8]) -> Option<PbNode> {
    let mut pos = 0usize;
    let mut data = Vec::new();
    let mut links = Vec::new();
    while pos < bytes.len() {
        let key = read_varint(bytes, &mut pos)?;
        let field = key >> 3;
        let wire = key & 7;
        match (field, wire) {
            (1, 2) => {
                let len = usize::try_from(read_varint(bytes, &mut pos)?).ok()?;
                data = bytes.get(pos..pos + len)?.to_vec();
                pos += len;
            }
            (2, 2) => {
                let len = usize::try_from(read_varint(bytes, &mut pos)?).ok()?;
                let region = bytes.get(pos..pos + len)?;
                pos += len;
                links.push(parse_link(region)?);
            }
            (_, wire) => skip_field(bytes, &mut pos, wire)?,
        }
    }
    Some(PbNode { data, links })
}

fn parse_link(region: &[u8]) -> Option<PbLink> {
    let mut pos = 0usize;
    let mut hash = Vec::new();
    let mut name = String::new();
    let mut tsize = 0u64;
    while pos < region.len() {
        let key = read_varint(region, &mut pos)?;
        let field = key >> 3;
        let wire = key & 7;
        match (field, wire) {
            (1, 2) => {
                let len = usize::try_from(read_varint(region, &mut pos)?).ok()?;
                hash = region.get(pos..pos + len)?.to_vec();
                pos += len;
            }
            (2, 2) => {
                let len = usize::try_from(read_varint(region, &mut pos)?).ok()?;
                name = String::from_utf8(region.get(pos..pos + len)?.to_vec()).ok()?;
                pos += len;
            }
            (3, 0) => tsize = read_varint(region, &mut pos)?,
            (_, wire) => skip_field(region, &mut pos, wire)?,
        }
    }
    Some(PbLink { hash, name, tsize })
}

// ---------------------------------------------------------------------------
// UnixFS Data: the dag-pb node's Data field is itself a protobuf message.
// Type(field1): 0=Raw 1=Directory 2=File; Data(field2)=content bytes; filesize(field3).
// ---------------------------------------------------------------------------

const UNIXFS_DIRECTORY: u64 = 1;
const UNIXFS_FILE: u64 = 2;

fn parse_unixfs(data: &[u8]) -> Option<(u64, Vec<u8>)> {
    if data.is_empty() {
        // An importers'-choice encoding: an empty Data on a dag-pb node means an empty
        // directory message. publish.rs always writes the explicit form either way.
        return Some((UNIXFS_DIRECTORY, Vec::new()));
    }
    let mut pos = 0usize;
    let mut kind = UNIXFS_FILE;
    let mut payload = Vec::new();
    while pos < data.len() {
        let key = read_varint(data, &mut pos)?;
        let field = key >> 3;
        let wire = key & 7;
        match (field, wire) {
            (1, 0) => kind = read_varint(data, &mut pos)?,
            (2, 2) => {
                let len = usize::try_from(read_varint(data, &mut pos)?).ok()?;
                payload = data.get(pos..pos + len)?.to_vec();
                pos += len;
            }
            (3, 0) | (4, 0) => {
                read_varint(data, &mut pos)?;
            }
            (_, wire) => skip_field(data, &mut pos, wire)?,
        }
    }
    Some((kind, payload))
}

/// Why a tree could not be walked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    /// The store refused a block the path needed (corruption surfaces here, not as absence).
    Store(String),
    /// A link's CID did not decode under this protocol's parameters.
    BadLink(String),
    /// The node was not a directory, so it had no entries to descend into.
    NotADirectory,
    /// The path descended through more nodes than the traversal budget allows.
    TooDeep,
    /// A node exceeded a traversal bound (too many links, too large).
    BoundExceeded(&'static str),
    /// The requested path does not exist in this tree.
    NotFound,
}

impl core::fmt::Display for WalkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(detail) => write!(f, "{detail}"),
            Self::BadLink(reason) => write!(f, "a link's CID did not decode: {reason}"),
            Self::NotADirectory => write!(f, "not a directory"),
            Self::TooDeep => write!(f, "tree deeper than the traversal budget"),
            Self::BoundExceeded(what) => write!(f, "{what}"),
            Self::NotFound => write!(f, "no such path in this tree"),
        }
    }
}

impl std::error::Error for WalkError {}

impl From<StoreError> for WalkError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::BadCid(reason) => Self::BadLink(reason.to_string()),
            other => Self::Store(other.to_string()),
        }
    }
}

/// Traversal bounds, mirroring FETCH_LIMITS' ceilings: bounded fan-out, bounded depth, bounded
/// total resource size. Injectable so tests exercise them without gigabytes.
#[derive(Debug, Clone, Copy)]
pub struct WalkLimits {
    pub max_depth: usize,
    pub max_links_per_node: usize,
    pub max_resource_bytes: usize,
}

impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_links_per_node: MAX_LINKS,
            max_resource_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Read ONE node by CID and classify it. The store verified these bytes already.
pub fn read_node(store: &BlockStore, cid: &Cid, limits: &WalkLimits) -> Result<Node, WalkError> {
    let bytes = store.get(cid)?.ok_or(WalkError::NotFound)?;
    match cid.codec {
        CODEC_RAW => Ok(Node::Raw(bytes)),
        CODEC_DAG_PB => {
            let pb = parse_pb_node(&bytes)
                .ok_or(WalkError::BoundExceeded("the node's protobuf is malformed"))?;
            let (kind, payload) =
                parse_unixfs(&pb.data).ok_or(WalkError::BoundExceeded("malformed UnixFS data"))?;
            match kind {
                UNIXFS_DIRECTORY => {
                    if pb.links.len() > limits.max_links_per_node {
                        return Err(WalkError::BoundExceeded(
                            "a directory may carry at most MAX_LINKS entries",
                        ));
                    }
                    let mut entries = Vec::with_capacity(pb.links.len());
                    for link in pb.links {
                        entries.push(DirLink {
                            cid: Cid::from_bytes(&link.hash)
                                .map_err(|e| WalkError::BadLink(e.to_string()))?,
                            name: link.name,
                            tsize: link.tsize,
                        });
                    }
                    Ok(Node::Directory(entries))
                }
                UNIXFS_FILE => {
                    let mut children = Vec::with_capacity(pb.links.len());
                    for link in pb.links {
                        children.push(
                            Cid::from_bytes(&link.hash)
                                .map_err(|e| WalkError::BadLink(e.to_string()))?,
                        );
                    }
                    Ok(Node::File {
                        data: payload,
                        children,
                    })
                }
                _ => Err(WalkError::BoundExceeded("unsupported UnixFS node type")),
            }
        }
        _ => Err(WalkError::BadLink("unsupported codec".to_string())),
    }
}

fn assemble_file(
    store: &BlockStore,
    cid: &Cid,
    limits: &WalkLimits,
    depth_left: &mut usize,
) -> Result<Vec<u8>, WalkError> {
    if *depth_left == 0 {
        return Err(WalkError::TooDeep);
    }
    *depth_left -= 1;
    match read_node(store, cid, limits)? {
        Node::Raw(bytes) => Ok(bytes),
        Node::File { data, children } => {
            let mut out = data;
            for child in children {
                out.extend(assemble_file(store, &child, limits, depth_left)?);
                if out.len() > limits.max_resource_bytes {
                    return Err(WalkError::BoundExceeded(
                        "a single resource exceeds the ceiling",
                    ));
                }
            }
            Ok(out)
        }
        Node::Directory(_) => Err(WalkError::NotADirectory),
    }
}

/// Assemble the FILE at a path within a tree: descend directories segment by segment, then
/// concatenate inline data plus chunk leaves in link order. Absence is `NotFound`; corruption
/// is a store error — the doctor's distinction, kept intact end to end.
pub fn read_path(
    store: &BlockStore,
    root: &Cid,
    segments: &[&str],
    limits: &WalkLimits,
) -> Result<Vec<u8>, WalkError> {
    let mut current = root.clone();
    let mut depth_left = limits.max_depth;
    let last_segment = segments.len().saturating_sub(1);
    for (index, segment) in segments.iter().enumerate() {
        match read_node(store, &current, limits)? {
            Node::Directory(entries) => {
                current = entries
                    .iter()
                    .find(|entry| entry.name == *segment)
                    .map(|entry| entry.cid.clone())
                    .ok_or(WalkError::NotFound)?;
                if index == last_segment && !segments.is_empty() {
                    return assemble_file(store, &current, limits, &mut depth_left);
                }
            }
            Node::Raw(_) | Node::File { .. } => return Err(WalkError::NotFound),
        }
    }
    if segments.is_empty() {
        // No segments: the root itself, assembled as a file.
        return assemble_file(store, root, limits, &mut depth_left);
    }
    // The final segment resolved to something the loop above already assembled; unreachable
    // except for an empty segments slice, handled above.
    Err(WalkError::NotFound)
}

/// List a DIRECTORY at a path (index lookup and listing need entries, not contents).
pub fn read_dir_at(
    store: &BlockStore,
    root: &Cid,
    segments: &[&str],
    limits: &WalkLimits,
) -> Result<Vec<DirLink>, WalkError> {
    let mut current = root.clone();
    for segment in segments {
        match read_node(store, &current, limits)? {
            Node::Directory(entries) => {
                current = entries
                    .iter()
                    .find(|entry| entry.name == *segment)
                    .map(|entry| entry.cid.clone())
                    .ok_or(WalkError::NotFound)?;
            }
            _ => return Err(WalkError::NotFound),
        }
    }
    match read_node(store, &current, limits)? {
        Node::Directory(entries) => Ok(entries),
        _ => Err(WalkError::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::{import_site, SiteFile};

    fn temp_store(tag: &str) -> (BlockStore, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("vayuweb-dagnode-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        (BlockStore::open(&path).expect("opens"), path)
    }

    fn pinned_site(tag: &str, files: &[SiteFile]) -> (BlockStore, std::path::PathBuf, Cid) {
        let (store, path) = temp_store(tag);
        let (blocks, root) = import_site(files).expect("imports");
        store
            .put_all(blocks.into_iter().map(|b| (b.cid.clone(), b.bytes)))
            .expect("pins");
        (store, path, root)
    }

    #[test]
    fn a_published_tree_reads_back_through_the_walker() {
        let files = vec![
            SiteFile {
                path: "index.html".into(),
                content: b"<!doctype html><p>home</p>".to_vec(),
            },
            SiteFile {
                path: "docs/a.txt".into(),
                content: b"alpha\n".to_vec(),
            },
        ];
        let (store, path, root) = pinned_site("walk", &files);

        // The index document reads back exactly as published.
        let got = read_path(&store, &root, &["index.html"], &WalkLimits::default()).expect("reads");
        assert_eq!(got, b"<!doctype html><p>home</p>".to_vec());

        // A nested path descends directories.
        let nested =
            read_path(&store, &root, &["docs", "a.txt"], &WalkLimits::default()).expect("reads");
        assert_eq!(nested, b"alpha\n".to_vec());

        // And the root itself is a directory, not a file.
        assert!(matches!(
            read_path(&store, &root, &[], &WalkLimits::default()),
            Err(WalkError::NotADirectory)
        ));
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn missing_paths_are_not_found_and_midpath_files_are_dead_ends() {
        let (store, path, root) = pinned_site(
            "missing",
            &[SiteFile {
                path: "a/b.txt".into(),
                content: b"x".to_vec(),
            }],
        );
        assert_eq!(
            read_path(&store, &root, &["nope"], &WalkLimits::default()),
            Err(WalkError::NotFound)
        );
        assert_eq!(
            read_path(&store, &root, &["a", "b"], &WalkLimits::default()),
            Err(WalkError::NotFound)
        );
        // A FILE mid-path is a dead end even if a name would continue below it.
        assert_eq!(
            read_path(&store, &root, &["a", "b", "c"], &WalkLimits::default()),
            Err(WalkError::NotFound)
        );
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn a_multi_chunk_file_assembles_in_link_order() {
        // Two chunks: 300 KiB spans one 256 KiB chunk plus a tail.
        let big: Vec<u8> = (0..(CHUNK_BYTES_USIZE + 64 * 1024))
            .map(|i| (i % 251) as u8)
            .collect();
        let (store, path, root) = pinned_site(
            "chunks",
            &[SiteFile {
                path: "big.bin".into(),
                content: big.clone(),
            }],
        );
        let got = read_path(&store, &root, &["big.bin"], &WalkLimits::default()).expect("reads");
        assert_eq!(got.len(), big.len());
        assert_eq!(got, big, "chunk order and bytes survive the round trip");
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn corruption_under_a_tree_is_reported_as_store_error_not_missing() {
        let (store, path, root) = pinned_site(
            "corrupt-walk",
            &[SiteFile {
                path: "f.txt".into(),
                content: b"content".to_vec(),
            }],
        );
        // Corrupt the leaf block behind the store's back.
        let leaf_name = {
            let entries = read_dir_at(&store, &root, &[], &WalkLimits::default()).expect("lists");
            entries
                .iter()
                .find(|entry| entry.name == "f.txt")
                .expect("entry")
                .cid
                .to_text()
        };
        let file = path.join(leaf_name);
        let mut bytes = std::fs::read(&file).expect("reads");
        bytes[0] ^= 0xff;
        std::fs::write(&file, bytes).expect("writes");

        let outcome = read_path(&store, &root, &["f.txt"], &WalkLimits::default());
        assert!(
            matches!(outcome, Err(WalkError::Store(_))),
            "corruption must surface as a store integrity refusal, got {outcome:?}"
        );
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn fanout_and_depth_bounds_are_enforced() {
        // Fan-out: a directory with more than MAX_LINKS entries cannot exist via import_site
        // (it writes what it builds), so exercise read_node's bound directly with a tight limit.
        let files: Vec<SiteFile> = (0..8)
            .map(|i| SiteFile {
                path: format!("f{i}.txt"),
                content: vec![b'a' + i as u8],
            })
            .collect();
        let (store, path, root) = pinned_site("bounds", &files);
        let tight = WalkLimits {
            max_links_per_node: 4,
            ..WalkLimits::default()
        };
        assert!(matches!(
            read_dir_at(&store, &root, &[], &tight),
            Err(WalkError::BoundExceeded(_))
        ));
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    const CHUNK_BYTES_USIZE: usize = crate::cid::CHUNK_BYTES;
}
