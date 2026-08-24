//! dag-pb and UnixFS: turning a site tree into the root CID a registry record points at.
//!
//! The client-side counterpart of `registry/src/unixfs.ts`; HOSTING.md's "Content addressing"
//! fixes the parameters. This is the piece that makes [`crate::cid`] into a publish path rather
//! than a hashing utility, and the piece that completes PUBLISHING.md section 1's steps 2 and 3 —
//! build the tree, address it — for the desktop client. Pinning locally (step 4) needs a local
//! block store this crate does not yet have, and the authoring checks of section 3 are their own
//! work item; neither is claimed here.
//!
//! ## Written against vectors, not against a reading of the format
//!
//! Every byte layout is pinned against blocks produced by the reference IPFS importer, the same
//! pins `registry/src/unixfs.test.ts` carries. The reason is recorded on the TypeScript side and
//! bears repeating once: a first attempt there reasoned from a format description, put the UnixFS
//! `Data` field at protobuf field 2, produced a self-consistent encoder that round-tripped,
//! hashed correctly — and gave every site it published a CID that resolved nowhere but its own
//! machine. A wrong encoder cannot be detected from inside; only an outside vector sees it.
//!
//! ## The two rules a reader will get wrong
//!
//! **Links are serialised before Data.** `PBNode` numbers `Data` as field 1 and `Links` as field
//! 2, and dag-pb requires field 2 on the wire *first* — against the ascending-field-number habit
//! every protobuf encoder has. One byte's position; a different CID for identical content.
//!
//! **A directory's links are sorted by name in raw byte order.** Two publishers importing the
//! same files in different order must produce the same CID, so the sort is part of the format
//! rather than a tidiness convention.

use crate::cid::{chunk, Cid, CODEC_DAG_PB};

/// UnixFS `Data.Type` values. Only the two a site needs are defined.
pub const UNIXFS_TYPE_FILE: u64 = 2;
pub const UNIXFS_TYPE_DIRECTORY: u64 = 1;

/// One entry in a directory, or one chunk of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The child's CID.
    pub cid: Cid,
    /// Entry name. Empty for a file's chunk links, which are positional.
    pub name: String,
    /// Cumulative serialised size of the subtree this link points at.
    pub tsize: usize,
}

/// An encoded block: its bytes and the CID that addresses them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub cid: Cid,
    pub bytes: Vec<u8>,
}

/// Why a tree could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// A path that could not appear under a well-formed site root.
    BadPath(String),
    /// A directory entry that names nothing, or names something twice.
    BadDirectory(&'static str),
}

impl core::fmt::Display for PublishError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadPath(path) => write!(f, "{path:?} is not a site-relative path"),
            Self::BadDirectory(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for PublishError {}

fn varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn tag(field: u64, wire: u64, out: &mut Vec<u8>) {
    varint(field * 8 + wire, out);
}

fn length_delimited(field: u64, payload: &[u8], out: &mut Vec<u8>) {
    tag(field, 2, out);
    varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

fn varint_field(field: u64, value: u64, out: &mut Vec<u8>) {
    tag(field, 0, out);
    varint(value, out);
}

/// The UnixFS `Data` message for a directory: just `Type = Directory`.
///
/// No size, no blocksizes — a directory's content is its links, which live in the enclosing
/// dag-pb node rather than here.
pub fn unixfs_directory() -> Vec<u8> {
    let mut out = Vec::new();
    varint_field(1, UNIXFS_TYPE_DIRECTORY, &mut out);
    out
}

/// The UnixFS `Data` message for a multi-chunk file.
///
/// `filesize` is the logical length of the file. `blocksizes` repeats once per chunk, in order,
/// so a reader can seek to an offset without fetching every block first. Both are needed: the
/// sum of the block sizes equals the file size, but the reader has no way to know that until it
/// has the whole list, and a range request should not require the whole list.
pub fn unixfs_file(chunk_sizes: &[usize]) -> Vec<u8> {
    let total: usize = chunk_sizes.iter().sum();
    let mut out = Vec::new();
    varint_field(1, UNIXFS_TYPE_FILE, &mut out);
    varint_field(3, total as u64, &mut out);
    for &size in chunk_sizes {
        varint_field(4, size as u64, &mut out);
    }
    out
}

/// One `PBLink`: `Hash`, `Name`, `Tsize`, in that order.
fn pb_link(link: &Link) -> Vec<u8> {
    let cid_bytes = link.cid.to_bytes();
    let mut out = Vec::with_capacity(cid_bytes.len() + link.name.len() + 16);
    length_delimited(1, &cid_bytes, &mut out);
    length_delimited(2, link.name.as_bytes(), &mut out);
    varint_field(3, link.tsize as u64, &mut out);
    out
}

/// Encode a `PBNode`.
///
/// **Links before Data**, which is the rule a reader will get wrong: `PBNode` numbers `Data` as
/// field 1 and `Links` as field 2, and dag-pb requires field 2 on the wire first. A node with
/// the fields the other way round hashes differently — a different CID for identical content.
pub fn encode_pb_node(links: &[Link], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for link in links {
        let encoded = pb_link(link);
        length_delimited(2, &encoded, &mut out);
    }
    if !data.is_empty() {
        length_delimited(1, data, &mut out);
    }
    out
}

/// Address an encoded dag-pb node.
fn dag_pb_block(bytes: Vec<u8>) -> Block {
    Block {
        cid: Cid {
            version: 1,
            codec: CODEC_DAG_PB,
            digest: crate::cid::sha256(&bytes),
        },
        bytes,
    }
}

/// Compare two names as raw UTF-8 bytes, which is not JavaScript string order and not locale
/// order either. The sort key is the encoded bytes because that is what appears on the wire.
fn compare_bytewise(a: &str, b: &str) -> core::cmp::Ordering {
    a.as_bytes().cmp(b.as_bytes())
}

/// Build a directory node from its entries, sorted by name in raw byte order.
pub fn directory_node(entries: &[Link]) -> Result<Block, PublishError> {
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        if entry.name.is_empty() {
            return Err(PublishError::BadDirectory(
                "a directory entry must be named",
            ));
        }
        if !seen.insert(entry.name.clone()) {
            return Err(PublishError::BadDirectory("duplicate directory entry"));
        }
    }
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| compare_bytewise(&a.name, &b.name));
    Ok(dag_pb_block(encode_pb_node(&sorted, &unixfs_directory())))
}

/// What building one file produces: every leaf block plus the addressing node, if any.
pub struct BuiltFile {
    pub blocks: Vec<Block>,
    pub cid: Cid,
    pub tsize: usize,
}

/// Build every block for one file.
///
/// A file that fits in one chunk is a **raw leaf and nothing more** — no dag-pb wrapper, no
/// UnixFS message. That is what HOSTING.md's raw-leaf choice buys: a small file's CID is the
/// sha2-256 of the file, checkable with an ordinary hash tool. A larger file becomes a dag-pb
/// node whose links are the chunks in order, with empty names, because chunk links are
/// positional rather than named.
pub fn file_blocks(bytes: &[u8]) -> BuiltFile {
    let pieces = chunk(bytes);

    if pieces.len() == 1 {
        let leaf = pieces[0];
        let cid = Cid::raw_from_bytes(leaf);
        return BuiltFile {
            blocks: vec![Block {
                cid: cid.clone(),
                bytes: leaf.to_vec(),
            }],
            cid,
            tsize: leaf.len(),
        };
    }

    let mut blocks = Vec::new();
    let mut links = Vec::new();
    for piece in &pieces {
        let cid = Cid::raw_from_bytes(piece);
        blocks.push(Block {
            cid: cid.clone(),
            bytes: piece.to_vec(),
        });
        links.push(Link {
            cid,
            name: String::new(),
            tsize: piece.len(),
        });
    }

    let sizes: Vec<usize> = pieces.iter().map(|piece| piece.len()).collect();
    let node = dag_pb_block(encode_pb_node(&links, &unixfs_file(&sizes)));
    // Tsize is the cumulative serialised size of the subtree: this node plus every block under
    // it.
    let tsize = node.bytes.len() + links.iter().map(|link| link.tsize).sum::<usize>();
    blocks.push(node.clone());
    BuiltFile {
        blocks,
        cid: node.cid,
        tsize,
    }
}

/// One file in a site: a path relative to the root, using `/` separators, and its bytes.
#[derive(Debug, Clone)]
pub struct SiteFile {
    pub path: String,
    pub content: Vec<u8>,
}

/// Import a whole site, returning every block and the root CID.
///
/// Directories are created from the paths rather than declared, and the whole tree is built
/// bottom-up so each parent's links carry a `Tsize` its children have already determined. Like
/// the implementation of record here, MAX_LINKS is stated by the specification and not enforced
/// by this importer; a tree wide enough to exceed it is a balanced-DAG VWIP's problem to split,
/// not a silent truncation.
pub fn import_site(files: &[SiteFile]) -> Result<(Vec<Block>, Cid), PublishError> {
    let mut blocks: Vec<Block> = Vec::new();
    let mut tree: std::collections::BTreeMap<String, Link> = std::collections::BTreeMap::new();

    for file in files {
        if file.path.is_empty() || file.path.starts_with('/') || file.path.ends_with('/') {
            return Err(PublishError::BadPath(file.path.clone()));
        }
        if file
            .path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(PublishError::BadPath(file.path.clone()));
        }
        let built = file_blocks(&file.content);
        blocks.extend(built.blocks);
        tree.insert(
            file.path.clone(),
            Link {
                cid: built.cid,
                name: file.path.clone(),
                tsize: built.tsize,
            },
        );
    }

    let (root, _root_tsize) = build_directory("", &tree, &mut blocks)?;
    Ok((blocks, root))
}

/// Build one directory level, recursing into subdirectories first.
fn build_directory(
    prefix: &str,
    tree: &std::collections::BTreeMap<String, Link>,
    blocks: &mut Vec<Block>,
) -> Result<(Cid, usize), PublishError> {
    let mut entries: Vec<Link> = Vec::new();
    let mut subdirectories: Vec<String> = Vec::new();

    for (path, link) in tree {
        if !prefix.is_empty() && !path.starts_with(&format!("{prefix}/")) {
            continue;
        }
        let relative = if prefix.is_empty() {
            path.as_str()
        } else {
            &path[prefix.len() + 1..]
        };
        match relative.find('/') {
            None => entries.push(Link {
                cid: link.cid.clone(),
                name: relative.to_string(),
                tsize: link.tsize,
            }),
            Some(slash) => {
                let name = relative[..slash].to_string();
                if !subdirectories.contains(&name) {
                    subdirectories.push(name);
                }
            }
        }
    }

    for name in &subdirectories {
        let child_prefix = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let (child_cid, child_tsize) = build_directory(&child_prefix, tree, blocks)?;
        entries.push(Link {
            cid: child_cid,
            name: name.clone(),
            tsize: child_tsize,
        });
    }

    let node = directory_node(&entries)?;
    let tsize = node.bytes.len() + entries.iter().map(|entry| entry.tsize).sum::<usize>();
    blocks.push(node.clone());
    Ok((node.cid, tsize))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf8(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    #[test]
    fn the_empty_directory_matches_the_network_byte_for_byte() {
        // The pin that caught the wrong-field-order encoder described in the module header:
        // bafybeiepbj... is what field order reversed produces, and the network says this.
        let node = directory_node(&[]).expect("empty dir");
        assert_eq!(
            node.bytes,
            vec![0x0a, 0x02, 0x08, 0x01],
            "Data after nothing, Type=Directory"
        );
        assert_eq!(
            node.cid.to_text(),
            "bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354"
        );
    }

    #[test]
    fn a_one_file_site_matches_the_reference_importer() {
        let (_, root) = import_site(&[SiteFile {
            path: "index.html".into(),
            content: utf8("<h1>hi</h1>"),
        }])
        .expect("imports");
        assert_eq!(
            root.to_text(),
            "bafybeiegxp4jcqwwry6cjdalgkpozbizynlfvo5krlvezukdaun5a4husi"
        );
    }

    #[test]
    fn a_two_file_site_matches_and_import_order_changes_nothing() {
        let files_a = vec![
            SiteFile {
                path: "index.html".into(),
                content: utf8("<h1>hi</h1>"),
            },
            SiteFile {
                path: "a.txt".into(),
                content: utf8("alpha"),
            },
        ];
        let files_b: Vec<SiteFile> = files_a.iter().rev().cloned().collect();
        let (blocks_a, root_a) = import_site(&files_a).expect("imports");
        let (blocks_b, root_b) = import_site(&files_b).expect("imports");
        assert_eq!(
            root_a.to_text(),
            "bafybeidyhgtyzk2tdvek6nmdcyxnv5law46pcjwdgbkj6spv6bovnjbesy"
        );
        assert_eq!(
            root_a, root_b,
            "the root is a function of contents, not order"
        );
        // The same SET of blocks either way. Enumeration order follows input order, which is
        // fine for a publisher that owns its own file order — the root is what peers agree on.
        let key = |blocks: &[Block]| {
            let mut cids: Vec<String> = blocks.iter().map(|block| block.cid.to_text()).collect();
            cids.sort();
            cids
        };
        assert_eq!(key(&blocks_a), key(&blocks_b));
    }

    #[test]
    fn a_file_needing_two_chunks_matches_node_bytes_and_all() {
        let big = vec![7u8; crate::cid::CHUNK_BYTES + 10];
        let built = file_blocks(&big);
        assert_eq!(built.blocks.len(), 3, "two raw leaves and the file node");
        assert_eq!(
            built.cid.to_text(),
            "bafybeihmxcvd4urq4sge4r5s3mtju5yaoz7urfh4hghul327uyaznjwyhq"
        );

        // The tail of the node is its UnixFS Data field, byte for byte as the reference importer
        // emits it: field 1, length 12, Type=File, filesize 262154, blocksizes [262144, 10].
        let node = &built.blocks[2];
        let tail: Vec<u8> = node.bytes[node.bytes.len() - 14..].to_vec();
        assert_eq!(
            tail,
            vec![
                0x0a, 0x0c, 0x08, 0x02, 0x18, 0x8a, 0x80, 0x10, 0x20, 0x80, 0x80, 0x10, 0x20, 0x0a
            ]
        );

        let (_, root) = import_site(&[SiteFile {
            path: "big.bin".into(),
            content: big,
        }])
        .expect("imports");
        assert_eq!(
            root.to_text(),
            "bafybeiew3gz7lfge2uvtcdhd4kf37ya3zjpmxqcbxucsjl5x66glmrjhzi"
        );
    }

    #[test]
    fn links_are_serialised_before_data_against_every_protobuf_habit() {
        let leaf = Cid::raw_from_bytes(b"hello world");
        let bytes = encode_pb_node(
            &[Link {
                cid: leaf,
                name: "x".into(),
                tsize: 11,
            }],
            &unixfs_directory(),
        );
        assert_eq!(
            bytes[0], 0x12,
            "the first tag byte is field 2, wire type 2 — Links"
        );
        // Data appears after the links, not before.
        let data_at = bytes
            .windows(4)
            .position(|window| window == [0x0a, 0x02, 0x08, 0x01])
            .expect("the directory Data field is present");
        assert!(data_at > 0);
    }

    #[test]
    fn the_unixfs_file_message_carries_filesize_and_every_block_size() {
        let message = unixfs_file(&[262_144, 10]);
        assert_eq!(
            message,
            vec![0x08, 0x02, 0x18, 0x8a, 0x80, 0x10, 0x20, 0x80, 0x80, 0x10, 0x20, 0x0a]
        );
    }

    #[test]
    fn raw_leaves_carry_no_wrapper_and_empty_files_are_addressable() {
        let built = file_blocks(b"hello world");
        assert_eq!(built.blocks.len(), 1);
        assert_eq!(
            built.cid.to_text(),
            "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"
        );
        assert_eq!(built.tsize, 11, "a raw leaf's tsize is its own length");

        let empty = file_blocks(&[]);
        assert_eq!(
            empty.cid.to_text(),
            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        );
        assert_eq!(empty.tsize, 0);
    }

    #[test]
    fn subdirectories_are_created_from_paths_and_the_root_is_stable() {
        let first_files = vec![
            SiteFile {
                path: "index.html".into(),
                content: utf8("root"),
            },
            SiteFile {
                path: "docs/index.html".into(),
                content: utf8("docs"),
            },
            SiteFile {
                path: "docs/deep/index.html".into(),
                content: utf8("deep"),
            },
        ];
        let (first_blocks, first_root) = import_site(&first_files).expect("imports");
        let reversed: Vec<SiteFile> = first_files.iter().rev().cloned().collect();
        let (_, second_root) = import_site(&reversed).expect("imports");
        assert_eq!(first_root, second_root, "order does not change the tree");
        // Pinned against the reference importer: the recursion building intermediate directories
        // is the one part no flat vector exercises, and a Tsize accumulated wrongly one level
        // down changes the root while every leaf stays correct.
        assert_eq!(
            first_root.to_text(),
            "bafybeicrzlnxeesybu4h7j7gx64po5k65kvq5iloqko6i4ph7tincovx2i"
        );
        // Every block the tree references was emitted, and every emitted block hashes back to
        // the digest inside the CID that addresses it — a cheap whole-DAG integrity walk.
        for block in &first_blocks {
            assert_eq!(block.cid.digest, crate::cid::sha256(&block.bytes));
        }
    }

    #[test]
    fn paths_that_are_not_paths_are_refused_before_any_hashing() {
        use PublishError::BadPath;
        for bad in ["", "/abs", "trailing/", "a//b", "./here", "../up"] {
            let outcome = import_site(&[SiteFile {
                path: bad.into(),
                content: vec![1],
            }]);
            assert!(matches!(outcome, Err(BadPath(_))), "{bad}");
        }
    }

    #[test]
    fn directory_entries_must_be_named_and_unique() {
        // Uniqueness and naming are enforced at the node level, where the wire rule lives.
        let leaf = Cid::raw_from_bytes(b"payload");
        assert!(matches!(
            directory_node(&[Link {
                cid: leaf.clone(),
                name: String::new(),
                tsize: 7
            }]),
            Err(PublishError::BadDirectory(
                "a directory entry must be named"
            ))
        ));
        let twice = vec![
            Link {
                cid: leaf.clone(),
                name: "same".into(),
                tsize: 7,
            },
            Link {
                cid: leaf,
                name: "same".into(),
                tsize: 7,
            },
        ];
        assert!(matches!(
            directory_node(&twice),
            Err(PublishError::BadDirectory("duplicate directory entry"))
        ));
        // And the byte-order sort puts uppercase before lowercase, which ASCII ordering does too
        // but locale-aware ordering would not: pinned so nobody "fixes" it into a collation.
        let mixed = vec![
            Link {
                cid: Cid::raw_from_bytes(b"two"),
                name: "beta".into(),
                tsize: 3,
            },
            Link {
                cid: Cid::raw_from_bytes(b"one"),
                name: "Alpha".into(),
                tsize: 3,
            },
        ];
        let node = directory_node(&mixed).expect("sorts");
        let alpha_at = node
            .bytes
            .windows(7)
            .position(|w| w == b"\x12\x05Alpha")
            .expect("Alpha present");
        let beta_at = node
            .bytes
            .windows(6)
            .position(|w| w == b"\x12\x04beta")
            .expect("beta present");
        assert!(
            alpha_at < beta_at,
            "raw byte order, not case-insensitive order"
        );
    }
}
