//! PRIVACY.md section 7's test, made executable.
//!
//! PRIVACY.md section 7 ends with a requirement, not a wish: "An error message that includes a
//! key is a disclosure. The implementation MUST carry a test that formats every error type with
//! secret material present and asserts none of it appears in the output."
//!
//! The phrase that matters is **with secret material present**. A test that formats an error
//! built from harmless strings asserts nothing about the property: the error would print them,
//! and the test would pass, whether the code was careful or not. The secret has to be in scope
//! while the error is made, and the output has to be searched for it afterwards.
//!
//! **What this covers, and what it does not.** It covers the boundaries in this crate where a
//! secret is actually in scope: the Ed25519 seed that becomes an identity, the secret handed to
//! the platform keystore, and the key pair that holds the seed. It does not claim that every
//! string in every message is safe — a message that echoes a publisher's own file path is not a
//! disclosure, and the secret this searches for is the system's, not the publisher's.
use std::cell::RefCell;

use vayuweb_client::identity::Identity;
use vayuweb_client::secrets::{store, Keystore, Secret, Sensitivity};

/// A secret whose contents are recognisable when they appear as text.
const MARKER: &[u8] = b"correct horse battery staple";

/// The same secret, at the length a seed must be, so it can be an identity's seed.
const SEED: &[u8] = b"correct horse battery staple!!!!";

/// Assert that a rendering carries neither form a secret can take.
///
/// A leak of raw bytes does not print as text — `{:?}` on a byte slice prints a list of numbers
/// — so a test that searched only for the text would miss the likelier leak of all. Both forms
/// are searched, and the number form is built from the secret itself so it cannot drift from it.
fn assert_carries_no_secret(rendered: &str, secret: &[u8], what: &str) {
    let as_text = String::from_utf8_lossy(secret);
    let as_numbers = format!("{secret:?}");
    assert!(
        !rendered.contains(as_text.as_ref()),
        "{what} printed the secret as text: {rendered}"
    );
    assert!(
        !rendered.contains(&as_numbers),
        "{what} printed the secret as bytes: {rendered}"
    );
}

/** A keystore that is present and refuses everything, recording what it was asked to hold. */
struct RefusingKeystore {
    offered: RefCell<Vec<(String, Vec<u8>)>>,
}

impl RefusingKeystore {
    fn new() -> Self {
        Self {
            offered: RefCell::new(Vec::new()),
        }
    }
}

impl Keystore for RefusingKeystore {
    fn available(&self) -> bool {
        true
    }
    fn set(&self, name: &str, secret: &Secret) -> Result<(), String> {
        // The offer is recorded, the way a real platform records what it was asked to hold, and
        // then it refuses. The error this produces is the only thing that could carry the secret
        // back out.
        self.offered
            .borrow_mut()
            .push((name.to_string(), secret.expose().to_vec()));
        Err("the keyring refused the write".into())
    }
    fn get(&self, _name: &str) -> Result<Option<Secret>, String> {
        Err("the keyring refused the read".into())
    }
    fn delete(&self, _name: &str) -> Result<(), String> {
        Err("the keyring refused the delete".into())
    }
}

#[test]
fn a_seed_of_the_wrong_length_does_not_put_its_bytes_in_the_error() {
    // The seed is the secret in scope: `from_seed` is handed one, and the error it returns is
    // the only thing that could carry it out. The error reports the LENGTH, which is what an
    // operator needs and is not the secret.
    let mut seed = MARKER.to_vec();
    let error = Identity::from_seed(&mut seed).expect_err("a seed of the wrong length is an error");

    let rendered = format!("{error} {error:?}");
    assert_carries_no_secret(&rendered, MARKER, "the identity error");
    assert!(
        rendered.contains(&MARKER.len().to_string()),
        "the error still says how long it was: {rendered}"
    );
}

#[test]
fn a_keystore_refusal_does_not_put_the_secret_in_the_error() {
    // The secret is in scope: `store` is handed one and the platform's refusal is the only thing
    // that could carry it back out.
    let mut bytes = MARKER.to_vec();
    let secret = Secret::take(&mut bytes);
    let keystore = RefusingKeystore::new();

    let error = store(
        &keystore,
        "vayuweb-token",
        &secret,
        Sensitivity::TokenFallback,
        |_| Err("the fallback file could not be written".into()),
    )
    .expect_err("a refusing keystore is an error");

    let rendered = format!("{error} {error:?}");
    assert_carries_no_secret(&rendered, MARKER, "the keystore refusal");
    // The keystore was really asked to hold it, so the secret really was in scope when the error
    // was made. A test where the platform refused before being asked would assert nothing.
    assert_eq!(
        keystore.offered.borrow().len(),
        1,
        "the secret was offered to the keystore before the refusal"
    );
}

#[test]
fn a_key_pair_never_prints_the_seed_it_holds() {
    // The key pair holds the seed, so anything that formats one — a log line, a panic message, a
    // `{:?}` in a test failure — would print the secret with it. The seed's own `Debug` withholds
    // its contents and the key pair's `Debug` never reaches for it; this is the test that says
    // the second of those is still true.
    let mut seed = SEED.to_vec();
    let identity = Identity::from_seed(&mut seed).expect("a 32-byte seed is an identity");

    let rendered = format!("{identity:?}");
    assert_carries_no_secret(&rendered, SEED, "the key pair");
}
