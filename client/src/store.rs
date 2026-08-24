//! Blocks on disk: the local pin store a publisher's own node holds.
//!
//! PUBLISHING.md section 1, step 4: *"Pin locally. The publisher's own node holds the content
//! before anything points at it. Announcing a name that resolves to nothing is the most common
//! self-inflicted failure in content-addressed systems, and step ordering prevents it."* This
//! module is that step for the desktop client — [`crate::publish`] builds a tree into blocks,
//! and this keeps them somewhere honest until a swarm wants them.
//!
//! ## The one rule that gives the module its shape
//!
//! **Nothing is written before it is verified, and nothing is returned without being verified
//! again.** A block goes in only after its bytes hash to the CID it is filed under, and comes
//! out only after hashing to the CID it was fetched by. The first check means a bug or a hostile
//! caller cannot file rubbish under an address that will later be trusted; the second means disk
//! corruption — or someone editing files in the store — is detected at read time rather than
//! served silently to whoever resolves the name next. To this code they are the same threat:
//! bytes that do not match their address have one disposition, refusal.
//!
//! ## What is deliberately absent
//!
//! No network, no exchange protocol, no eviction policy. Serving blocks to peers is the block
//! exchange VWIP-0005 territory plus a client transport that does not exist yet; evicting pinned
//! content to reclaim space is a product decision with a user-facing surface. Both are easier to
//! add to a store whose contents are provably what their names say than to one that is not.

use crate::cid::{sha256, Cid};

/// One block may weigh at most 1 MiB, matching FETCH_LIMITS.blockBytes in the implementation of
/// record and the block-exchange maximum of VWIP-0005. A larger write is refused, not truncated:
/// truncation would store bytes whose hash cannot match anything, which is a silent defect.
pub const MAX_BLOCK_BYTES: usize = 1024 * 1024;

/// Why a block could not cross the store boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The bytes offered do not hash to the CID they are filed under.
    ContentIntegrity(String),
    /// The block exceeds [`MAX_BLOCK_BYTES`].
    TooLarge { found: usize },
    /// The store directory could not be created or read.
    Io(String),
    /// A CID text form was not decodable under this protocol's parameters.
    BadCid(&'static str),
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ContentIntegrity(cid) => {
                write!(
                    f,
                    "CONTENT_INTEGRITY: bytes offered for {cid} hash to something else"
                )
            }
            Self::TooLarge { found } => {
                write!(
                    f,
                    "block is {found} bytes, over the {MAX_BLOCK_BYTES} limit"
                )
            }
            Self::Io(detail) => write!(f, "{detail}"),
            Self::BadCid(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for StoreError {}

fn io(error: std::io::Error) -> StoreError {
    StoreError::Io(error.to_string())
}

/// Verify that `bytes` hash to `cid`'s digest, in constant time over the digest length.
fn verify(cid: &Cid, bytes: &[u8]) -> bool {
    let digest = sha256(bytes);
    let mut diff = 0u8;
    for (left, right) in digest.iter().zip(cid.digest.iter()) {
        diff |= left ^ right;
    }
    // Lengths are fixed at construction, so zip covers everything; the guard is belt and braces.
    diff == 0 && cid.digest.len() == digest.len()
}

/// A content-addressed block store rooted at a directory.
///
/// Each block is one file named by its CID text — the same rendering everywhere else in the
/// protocol, so a human looking at the directory sees addresses they already know.
pub struct BlockStore {
    root: std::path::PathBuf,
}

impl BlockStore {
    /// Open (creating if needed) the store directory.
    ///
    /// On Unix the directory is created 0700, matching `prepareStoreDirectory` in the
    /// implementation of record; a private store is the point, since published blocks are public
    /// but *your* pin set — which sites you hold — is not. Windows has no mode bits; access
    /// control there inherits from the profile's application directories, which is stated here
    /// rather than pretended away. Stale temporary files from interrupted writes are removed, so
    /// a crash never leaves half a block where a reader can find it.
    pub fn open(path: &std::path::Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(path).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::metadata(path).map_err(io)?.permissions();
            if permissions.mode() & 0o077 != 0 {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                    .map_err(io)?;
            }
        }
        let store = Self {
            root: path.to_path_buf(),
        };
        store.sweep_temporaries()?;
        Ok(store)
    }

    /// Remove leftover `.tmp` writes from an interrupted put. Only our own naming pattern is
    /// touched, and only inside the store directory we were given.
    fn sweep_temporaries(&self) -> Result<(), StoreError> {
        for entry in std::fs::read_dir(&self.root).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name = entry.file_name();
            if name.to_string_lossy().ends_with(".tmp") {
                std::fs::remove_file(entry.path()).map_err(io)?;
            }
        }
        Ok(())
    }

    fn path_for(&self, cid_text: &str) -> std::path::PathBuf {
        self.root.join(cid_text)
    }

    /// File one block, verifying its bytes against its CID first.
    ///
    /// Writing an already-present block again is a no-op that still verifies: idempotence is what
    /// makes republishing a site safe to retry after any failure short of success. `put` takes
    /// the store by shared reference because it mutates the DISK, not the value — the same
    /// reasoning as `std::fs::write`.
    pub fn put(&self, cid: &Cid, bytes: &[u8]) -> Result<(), StoreError> {
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err(StoreError::TooLarge { found: bytes.len() });
        }
        if !verify(cid, bytes) {
            return Err(StoreError::ContentIntegrity(cid.to_text()));
        }
        let target = self.path_for(&cid.to_text());
        if target.exists() {
            return Ok(());
        }
        // Write to a temporary sibling, then rename into place. A rename within one directory is
        // atomic on every filesystem this client targets, so a reader never observes a partial
        // block under a valid CID.
        let mut temp = target.clone();
        temp.set_extension("tmp");
        std::fs::write(&temp, bytes).map_err(io)?;
        std::fs::rename(&temp, &target).map_err(io)?;
        Ok(())
    }

    /// Read one block back, verifying it against its CID on the way out.
    ///
    /// Absence is `Ok(None)` — a normal state for a partially replicated tree. Presence that
    /// fails verification is an ERROR, not None: "this block is corrupt" and "this block does
    /// not exist" demand different responses, and collapsing them hides corruption behind an
    /// availability problem.
    pub fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StoreError> {
        let path = self.path_for(&cid.to_text());
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(io)?;
        if bytes.len() > MAX_BLOCK_BYTES {
            return Err(StoreError::TooLarge { found: bytes.len() });
        }
        if !verify(cid, &bytes) {
            return Err(StoreError::ContentIntegrity(cid.to_text()));
        }
        Ok(Some(bytes))
    }

    /// Whether a verifiable copy is held. Cheap, and lies about nothing: a corrupt block reports
    /// as held, because `has` answers "is it here", not "is it good" — callers about to serve the
    /// bytes must go through [`Self::get`], which is the check that counts.
    pub fn has(&self, cid: &Cid) -> bool {
        self.path_for(&cid.to_text()).exists()
    }

    /// File every block of a built tree, returning how many were newly written.
    pub fn put_all(
        &self,
        blocks: impl IntoIterator<Item = (Cid, Vec<u8>)>,
    ) -> Result<usize, StoreError> {
        let mut written = 0usize;
        for (cid, bytes) in blocks {
            let target = self.path_for(&cid.to_text());
            if !target.exists() {
                self.put(&cid, &bytes)?;
                written += 1;
            }
        }
        Ok(written)
    }

    /// How many blocks are held. Used by tests and by a future UI's storage display; not a
    /// correctness primitive.
    pub fn len(&self) -> Result<usize, StoreError> {
        let count = std::fs::read_dir(&self.root)
            .map_err(io)?
            .filter(|entry| {
                entry
                    .as_ref()
                    .map(|e| !e.file_name().to_string_lossy().ends_with(".tmp"))
                    .unwrap_or(false)
            })
            .count();
        Ok(count)
    }

    /// Whether the store holds nothing at all — the fallible-`len` companion.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::{import_site, SiteFile};

    fn utf8(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    fn temp_store(tag: &str) -> (BlockStore, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("vayuweb-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        (BlockStore::open(&path).expect("opens"), path)
    }

    #[test]
    fn a_built_site_round_trips_through_the_store() {
        let (store, path) = temp_store("roundtrip");
        let (blocks, root) = import_site(&[SiteFile {
            path: "index.html".into(),
            content: utf8("<h1>hi</h1>"),
        }])
        .expect("imports");

        assert_eq!(
            store
                .put_all(blocks.iter().map(|b| (b.cid.clone(), b.bytes.clone())))
                .expect("puts"),
            2
        );
        assert_eq!(store.len().expect("counts"), 2);

        // Every block reads back exactly as written — the raw leaf AND the dag-pb root.
        for block in &blocks {
            let got = store.get(&block.cid).expect("reads").expect("present");
            assert_eq!(got, block.bytes);
            assert!(store.has(&block.cid));
        }
        // The root is the directory node, not the document: resolving a name walks it.
        let root_bytes = store.get(&root).expect("reads").expect("present");
        assert_eq!(
            root_bytes[0], 0x12,
            "a dag-pb node starts with the Links field tag"
        );
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn bytes_that_do_not_hash_to_their_cid_are_never_stored() {
        let (store, path) = temp_store("integrity-in");
        let genuine = Cid::raw_from_bytes(b"genuine content");
        let forged_bytes = b"forged content".to_vec();

        let outcome = store.put(&genuine, &forged_bytes);
        assert!(matches!(outcome, Err(StoreError::ContentIntegrity(_))));
        // And nothing was written: the store holds no lie under a valid-looking name.
        assert!(!store.has(&genuine));
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn a_block_corrupted_on_disk_is_refused_at_read_time_not_served() {
        let (store, path) = temp_store("corruption");
        let original = b"published bytes".to_vec();
        let cid = Cid::raw_from_bytes(&original);
        store.put(&cid, &original).expect("stores");

        // Corrupt the file behind the store's back, the way disk rot or a careless editor would.
        let file = path.join(cid.to_text());
        let mut on_disk = std::fs::read(&file).expect("reads");
        on_disk[0] ^= 0xff;
        std::fs::write(&file, &on_disk).expect("writes");

        // get refuses rather than serving wrong bytes under a right address.
        assert!(matches!(
            store.get(&cid),
            Err(StoreError::ContentIntegrity(_))
        ));
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn absence_and_corruption_are_different_answers() {
        let (store, path) = temp_store("absence");
        let missing = Cid::raw_from_bytes(b"never stored");
        assert!(
            matches!(store.get(&missing), Ok(None)),
            "absence is Ok(None)"
        );
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn oversized_writes_are_refused_whole_not_truncated() {
        let (store, path) = temp_store("oversize");
        let big = vec![0u8; MAX_BLOCK_BYTES + 1];
        let cid = Cid::raw_from_bytes(&big);
        assert!(matches!(
            store.put(&cid, &big),
            Err(StoreError::TooLarge { found }) if found == MAX_BLOCK_BYTES + 1
        ));
        assert!(!store.has(&cid));
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn putting_twice_is_idempotent_and_counts_once() {
        let (store, path) = temp_store("idempotent");
        let (blocks, _) = import_site(&[SiteFile {
            path: "a.txt".into(),
            content: utf8("alpha"),
        }])
        .expect("imports");
        let pairs: Vec<(Cid, Vec<u8>)> = blocks.into_iter().map(|b| (b.cid, b.bytes)).collect();
        let count = pairs.len();

        let first = store.put_all(pairs.clone()).expect("first pass");
        let second = store.put_all(pairs).expect("second pass");
        assert_eq!(first + second, count, "the second pass writes nothing new");
        assert_eq!(store.len().expect("counts"), count);
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn stale_temporaries_from_a_crash_are_swept_on_open() {
        let (store, path) = temp_store("sweep");
        let (blocks, _) = import_site(&[SiteFile {
            path: "b.txt".into(),
            content: utf8("beta"),
        }])
        .expect("imports");
        store
            .put_all(blocks.into_iter().map(|b| (b.cid, b.bytes)))
            .expect("fills");

        // Simulate the crash: a temporary left behind mid-write.
        let junk = path.join("bafkrei-left-behind.tmp");
        std::fs::write(&junk, b"partial").expect("plants junk");

        // Reopening sweeps it and leaves real blocks alone (leaf plus directory node).
        let reopened = BlockStore::open(&path).expect("reopens");
        assert!(!junk.exists(), "the temporary was swept");
        assert_eq!(reopened.len().expect("counts"), 2);
        std::fs::remove_dir_all(path).expect("cleanup");
    }

    #[test]
    fn a_bad_cid_is_refused_before_any_filesystem_work() {
        // The text form is the filename; refusing garbage at decode time keeps arbitrary strings
        // out of the filesystem namespace entirely.
        let (_store, path) = temp_store("badcid");
        assert!(Cid::from_text("not-a-cid").is_err());
        std::fs::remove_dir_all(path).expect("cleanup");
    }
}
