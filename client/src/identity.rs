//! Identity: an Ed25519 key pair, generated here and stored under the rule in [`crate::secrets`].
//!
//! `docs/ROADMAP.md` Phase 5 names this first: "identity generation with the secret key placed in
//! the operating system keychain and never written to a config file or the log". Until now the
//! crate's own package description promised "identity handling" while `ed25519-dalek` and
//! `rand_core` sat in `Cargo.toml` with nothing importing them — and, more to the point,
//! [`Sensitivity::KeystoreOnly`] existed to protect a private key that this crate could not
//! produce. The variant carrying the whole refusal argument had no caller.
//!
//! ## What this is not
//!
//! Signing arbitrary bytes is not building a record. A conforming `REGISTER` is deterministic CBOR
//! over a fixed field set with a domain-separated signing input and a proof of work, and none of
//! that lives here. `crate` is not a second implementation of the protocol and must not be
//! reported as one — `docs/ROADMAP.md` Phase 6 asks for one written by parties with no common
//! employer or funder, and a second language written by the same hands does not satisfy it.
//!
//! ## Where the secret lives, and why not in a `SigningKey`
//!
//! The 32-byte seed is held in a [`Secret`], which is the type every guarantee in this crate hangs
//! off: zeroised on drop at a point `Drop` makes known, never printed by `Debug` or `Display`,
//! never copied into a garbage-collected string. A [`SigningKey`] is reconstructed for each
//! signature and dropped at the end of the call.
//!
//! That is deliberately the more awkward arrangement. Holding a long-lived `SigningKey` would mean
//! two copies of the same secret with two different lifetimes and two different zeroisation
//! stories, and the second one would be the one nobody remembers. The cost is an expansion per
//! signature, which for a desktop client signing a handful of records is not a cost.
//!
//! `ed25519-dalek`'s own `zeroize` feature is enabled so the transient key wipes itself too; the
//! seed's own copy inside it is not this module's to reach into.

use core::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use zeroize::Zeroize;

use crate::secrets::{store, Keystore, Placement, Secret, Sensitivity, StoreError};

/// Bytes in an Ed25519 seed, which is what a secret key is.
pub const SEED_LEN: usize = 32;
/// Bytes in an Ed25519 public key, which is what a record's `ownerKey` field carries.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Bytes in an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Why an identity could not be made or used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// A stored seed was not 32 bytes.
    ///
    /// Named rather than folded into a generic parse error because the two things it distinguishes
    /// are a corrupted keystore entry and a caller handing over the wrong secret entirely, and an
    /// operator can act on the difference.
    BadSeedLength { found: usize },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSeedLength { found } => write!(
                f,
                "an Ed25519 seed is {SEED_LEN} bytes and this one is {found}"
            ),
        }
    }
}

impl std::error::Error for IdentityError {}

/// A key pair: the public half in the clear, the secret half in a [`Secret`].
///
/// Deliberately not `Clone`. A second copy of a private key is a second thing to zeroise and a
/// second place for it to outlive the first, and no caller in a desktop client needs one.
pub struct Identity {
    public: [u8; PUBLIC_KEY_LEN],
    seed: Secret,
}

impl Identity {
    /// A fresh identity from the operating system's CSPRNG.
    ///
    /// `OsRng` and not a seeded generator, and not a "deterministic for testing" mode either. A
    /// key generation path with a switch on it is a key generation path somebody flips, and the
    /// tests below get their determinism from [`Identity::from_seed`] instead — which is the same
    /// coverage without a weakness compiled into the shipping path.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let public = signing.verifying_key().to_bytes();
        let mut bytes = signing.to_bytes().to_vec();
        // `Secret::take` zeroises the caller's copy; the `SigningKey` wipes its own on drop.
        let seed = Secret::take(&mut bytes);
        Self { public, seed }
    }

    /// Rebuild an identity from a stored seed, consuming the caller's copy.
    ///
    /// Takes `&mut Vec<u8>` for the same reason [`Secret::take`] does: a constructor that borrows
    /// a secret and leaves the original with the caller has moved the problem rather than solved
    /// it. The buffer is zeroised **whether or not this succeeds** — a wrong-length secret is
    /// still a secret, and the error path is exactly where a forgotten wipe survives review.
    pub fn from_seed(source: &mut Vec<u8>) -> Result<Self, IdentityError> {
        if source.len() != SEED_LEN {
            let found = source.len();
            source.zeroize();
            return Err(IdentityError::BadSeedLength { found });
        }
        let mut fixed = [0u8; SEED_LEN];
        fixed.copy_from_slice(source);
        source.zeroize();

        let signing = SigningKey::from_bytes(&fixed);
        fixed.zeroize();
        let public = signing.verifying_key().to_bytes();
        let mut bytes = signing.to_bytes().to_vec();
        let seed = Secret::take(&mut bytes);
        Ok(Self { public, seed })
    }

    /// The public key, which is `ownerKey` in a registry record and is not a secret.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }

    /// The seed, for handing to [`store_identity`]. Borrowed, never cloned.
    pub fn seed(&self) -> &Secret {
        &self.seed
    }

    /// Sign a message.
    ///
    /// The message is bytes and this module does not know what they mean. Producing the bytes a
    /// registry record is signed over — deterministic CBOR under a domain-separated input — is the
    /// protocol's business and is not implemented here, so a caller passing the wrong bytes gets a
    /// perfectly valid signature over the wrong thing. Said plainly because a `sign` that looks
    /// like it understands records is how that mistake gets made.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], IdentityError> {
        let mut fixed = [0u8; SEED_LEN];
        let exposed = self.seed.expose();
        if exposed.len() != SEED_LEN {
            return Err(IdentityError::BadSeedLength {
                found: exposed.len(),
            });
        }
        fixed.copy_from_slice(exposed);
        let signing = SigningKey::from_bytes(&fixed);
        fixed.zeroize();
        Ok(signing.sign(message).to_bytes())
    }

    /// Check a signature against this identity's public key, strictly.
    ///
    /// `verify_strict` rather than `verify`, matching the registry's own rule: the permissive
    /// check accepts signatures under small-order and mixed-order public keys, which makes a
    /// signature verifiable under more than one key and turns "who signed this" into a question
    /// with several answers. That is the property every attribution in this protocol rests on.
    pub fn verify(public: &[u8; PUBLIC_KEY_LEN], message: &[u8], signature: &[u8]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(public) else {
            return false;
        };
        let Ok(fixed) = <[u8; SIGNATURE_LEN]>::try_from(signature) else {
            return false;
        };
        key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&fixed))
            .is_ok()
    }
}

impl fmt::Debug for Identity {
    /// Prints the public key's length and nothing about the seed.
    ///
    /// `Secret` already withholds itself, so this is belt and braces — and it is written because a
    /// derived `Debug` on a struct that gains a plain field later is a leak nobody edits a
    /// `#[derive]` to cause.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Identity(public {} bytes, secret withheld)",
            self.public.len()
        )
    }
}

/// Store an identity's secret key, which the keystore or nothing may hold.
///
/// The fallback closure is supplied and can never run: [`Sensitivity::KeystoreOnly`] makes
/// [`store`] return before reaching it. It is written as a refusal rather than as an
/// `unimplemented!()` for the reason `secrets.rs` gives for returning errors instead of panicking —
/// a panic in a desktop client is a crash report, and a crash report is where a secret ends up.
///
/// `PRIVACY.md` 7.4, and the sentence this whole arrangement exists for: "a private key or the
/// content-cache key on a platform without a keystore is a refusal, not a downgrade".
pub fn store_identity(
    keystore: &dyn Keystore,
    name: &str,
    identity: &Identity,
) -> Result<Placement, StoreError> {
    store(
        keystore,
        name,
        identity.seed(),
        Sensitivity::KeystoreOnly,
        |_| Err("a private key has no file fallback; PRIVACY.md 7.4".to_string()),
    )
}

/// Load an identity previously stored under `name`, or `None` if there is none.
pub fn load_identity(keystore: &dyn Keystore, name: &str) -> Result<Option<Identity>, String> {
    let Some(secret) = keystore.get(name)? else {
        return Ok(None);
    };
    let mut bytes = secret.expose().to_vec();
    match Identity::from_seed(&mut bytes) {
        Ok(identity) => Ok(Some(identity)),
        Err(error) => Err(error.to_string()),
    }
}

/// `None` is a real answer, so `load_identity` returning it must be comparable in a test.
impl PartialEq for Identity {
    /// By public key alone. Two identities with one public key have one secret key — Ed25519 makes
    /// that so — and comparing secrets in a derived equality is a timing side channel written by
    /// accident.
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.public {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// A keystore that works, and one that is absent. The distinction `secrets.rs` insists on.
    struct Working {
        held: RefCell<HashMap<String, Vec<u8>>>,
    }

    impl Working {
        fn new() -> Self {
            Self {
                held: RefCell::new(HashMap::new()),
            }
        }
    }

    impl Keystore for Working {
        fn available(&self) -> bool {
            true
        }
        fn set(&self, name: &str, secret: &Secret) -> Result<(), String> {
            self.held
                .borrow_mut()
                .insert(name.to_string(), secret.expose().to_vec());
            Ok(())
        }
        fn get(&self, name: &str) -> Result<Option<Secret>, String> {
            Ok(self.held.borrow().get(name).map(|bytes| {
                let mut copy = bytes.clone();
                Secret::take(&mut copy)
            }))
        }
        fn delete(&self, name: &str) -> Result<(), String> {
            self.held.borrow_mut().remove(name);
            Ok(())
        }
    }

    struct Absent;

    impl Keystore for Absent {
        fn available(&self) -> bool {
            false
        }
        fn set(&self, _: &str, _: &Secret) -> Result<(), String> {
            Err("no keystore".to_string())
        }
        fn get(&self, _: &str) -> Result<Option<Secret>, String> {
            Ok(None)
        }
        fn delete(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn two_identities_are_two_identities() {
        // A generator seeded from a constant produces the same key on every machine that runs it,
        // and every one of those users holds the same name. Cheap to check and catastrophic to get
        // wrong, which is the combination that earns a test.
        let one = Identity::generate();
        let two = Identity::generate();
        assert_ne!(one.public_key(), two.public_key());
        assert_ne!(one.seed().expose(), two.seed().expose());
        assert_eq!(one.seed().len(), SEED_LEN);
    }

    #[test]
    fn a_signature_verifies_under_its_own_key_and_no_other() {
        let mine = Identity::generate();
        let theirs = Identity::generate();
        let message = b"a record's signing input would go here";
        let signature = mine.sign(message).expect("signing must succeed");

        assert!(Identity::verify(mine.public_key(), message, &signature));
        assert!(
            !Identity::verify(theirs.public_key(), message, &signature),
            "a signature that verifies under somebody else's key attributes nothing"
        );
        assert!(
            !Identity::verify(mine.public_key(), b"a different message", &signature),
            "and it must not verify over bytes it was not made from"
        );
    }

    #[test]
    fn a_signature_under_a_small_order_key_is_refused_however_well_formed_it_is() {
        // The reason `verify` is `verify_strict`, in the one case where the difference is not
        // academic. The Ed25519 identity point is a valid public-key encoding, and the pair
        // (R = identity, s = 0) satisfies the permissive verification equation for **every**
        // message: [0]B is the identity, and R + [h]A is the identity too whatever `h` is.
        //
        // So a permissive verifier says yes to a signature nobody made, over bytes nobody chose, by
        // a key nobody holds. In this protocol a public key is an owner and a signature is
        // attribution, which makes that a self-certifying identity — the registry refuses such a
        // key at schema level for the same reason, and a client that accepted one would believe an
        // owner key its holder never had.
        let identity_point = {
            let mut key = [0u8; PUBLIC_KEY_LEN];
            key[0] = 1;
            key
        };
        let mut signature = [0u8; SIGNATURE_LEN];
        signature[0] = 1; // R, encoded as the identity point; s stays zero.

        assert!(
            !Identity::verify(&identity_point, b"any message at all", &signature),
            "a small-order key must not verify anything"
        );
        assert!(
            !Identity::verify(
                &identity_point,
                b"a completely different message",
                &signature
            ),
            "and the same forgery must not work over other bytes either"
        );
    }

    #[test]
    fn a_malformed_signature_or_key_is_false_rather_than_a_panic() {
        // A desktop client verifying attacker-supplied bytes must not abort on them: a panic is a
        // crash report, and `secrets.rs` is arranged around a crash report being where a secret
        // ends up.
        let identity = Identity::generate();
        assert!(!Identity::verify(identity.public_key(), b"m", &[]));
        assert!(!Identity::verify(
            identity.public_key(),
            b"m",
            &[0u8; SIGNATURE_LEN - 1]
        ));
        assert!(!Identity::verify(
            &[0xffu8; PUBLIC_KEY_LEN],
            b"m",
            &[0u8; SIGNATURE_LEN]
        ));
    }

    #[test]
    fn a_seed_round_trips_to_the_same_key_and_the_same_signature() {
        // Ed25519 signing is deterministic, so this pins two things at once: the seed rebuilt the
        // same key pair, and nothing in this module quietly introduced randomness into signing —
        // which would still verify, and would still be wrong.
        let original = Identity::generate();
        let message = b"determinism is a property somebody can remove without failing a test";
        let first = original.sign(message).expect("signing must succeed");

        let mut seed = original.seed().expose().to_vec();
        let restored = Identity::from_seed(&mut seed).expect("32 bytes is a seed");
        assert_eq!(restored.public_key(), original.public_key());
        assert_eq!(
            restored.sign(message).expect("signing must succeed"),
            first,
            "the same seed over the same message is the same signature"
        );
        assert!(
            seed.is_empty() || seed.iter().all(|b| *b == 0),
            "the caller's copy must not survive the call"
        );
    }

    #[test]
    fn a_wrong_length_seed_is_refused_and_still_wiped() {
        // The error path, which is where a forgotten wipe survives review: the happy path gets
        // read every time somebody adds a feature and this one gets read when something breaks.
        let mut short = vec![7u8; SEED_LEN - 1];
        let error = Identity::from_seed(&mut short).expect_err("31 bytes is not a seed");
        assert_eq!(
            error,
            IdentityError::BadSeedLength {
                found: SEED_LEN - 1
            }
        );
        assert!(
            short.iter().all(|b| *b == 0),
            "a wrong-length secret is still a secret"
        );

        let mut long = vec![7u8; SEED_LEN + 1];
        assert!(Identity::from_seed(&mut long).is_err());
        assert!(long.iter().all(|b| *b == 0));
    }

    #[test]
    fn a_machine_with_no_keystore_refuses_the_key_rather_than_writing_it() {
        // **The clause the whole crate is arranged around**, now with a private key to apply it
        // to. `PRIVACY.md` 7.4: "a private key or the content-cache key on a platform without a
        // keystore is a refusal, not a downgrade."
        //
        // The interesting half is that the refusal holds even though a file fallback WOULD have
        // worked — the machine has a writable disk and a caller willing to use it. An
        // implementation that reached for the fallback whenever it was available would pass a test
        // that only checked the error on a machine where writing also failed.
        let identity = Identity::generate();
        let outcome = store_identity(&Absent, "owner", &identity);
        assert_eq!(
            outcome,
            Err(StoreError::NoKeystoreAndNoFallback {
                what: "private key or content-cache key"
            })
        );
    }

    #[test]
    fn a_stored_identity_comes_back_as_the_same_identity() {
        let keystore = Working::new();
        let identity = Identity::generate();
        assert_eq!(
            store_identity(&keystore, "owner", &identity),
            Ok(Placement::Keystore),
            "a working keystore is the ordinary case and must not be the untested one"
        );

        let loaded = load_identity(&keystore, "owner")
            .expect("loading must not error")
            .expect("the identity must be there");
        assert_eq!(loaded.public_key(), identity.public_key());

        let message = b"signed after a round trip through the keystore";
        assert!(Identity::verify(
            identity.public_key(),
            message,
            &loaded.sign(message).expect("signing must succeed")
        ));
    }

    #[test]
    fn a_name_nobody_stored_is_absent_rather_than_an_error() {
        let keystore = Working::new();
        assert_eq!(
            load_identity(&keystore, "never-stored").expect("absence is not an error"),
            None
        );
    }

    #[test]
    fn an_identity_never_prints_its_secret() {
        // `Secret` already withholds itself; this checks the struct around it does too, because a
        // `#[derive(Debug)]` added later would print every field including the one that matters.
        let identity = Identity::generate();
        let printed = format!("{identity:?}");
        assert!(printed.contains("secret withheld"), "{printed}");
        let seed = identity.seed().expose();
        let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!printed.contains(&hex), "the seed must not appear in Debug");
    }
}
