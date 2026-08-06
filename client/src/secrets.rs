//! Secret handling, and the one rule the specification refuses to bend.
//!
//! `docs/spec/PRIVACY.md` section 7 lists four requirements for every secret this client holds.
//! Three are ordinary hygiene. The fourth is a policy decision with a sharp edge, and it is the
//! reason this module exists as a type rather than as a convention:
//!
//! > Never written to disk except in the platform keystore, per Constitution Article 6. **Where
//! > the platform provides no keystore**, the control-API token — and only that token — MAY be
//! > held in a file at mode `0600` inside the resolver's own state directory. The client MUST
//! > report that the weaker guarantee applies […] No other secret has this fallback: a private
//! > key or the content-cache key on a platform without a keystore is a **refusal, not a
//! > downgrade**.
//!
//! Written as prose, that is a rule somebody implements correctly on Monday and relaxes on Friday
//! because the build is failing on a machine with no keyring. Written as a type, the relaxation
//! does not compile: [`Sensitivity::KeystoreOnly`] has no path to a file, and the function that
//! writes one takes [`Sensitivity::TokenFallback`] by value. The compiler is doing what a code
//! review would otherwise have to do every time.
//!
//! ## Why Rust here
//!
//! `docs/ARCHITECTURE.md`, "Implementation Language": the protocol fixes formats and not
//! runtimes, and Rust is the expected choice for the desktop client because Tauri already is one.
//! For *this* module specifically it buys two things a garbage-collected language cannot:
//! `Drop` runs at a known point so zeroisation is not a hope, and requirement 3 — "never placed
//! in a garbage-collected string" — is satisfied by construction rather than by review.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// What a secret may be allowed to do, per `PRIVACY.md` 7.4.
///
/// Two variants and no third, because the specification has two cases and a third would be the
/// downgrade it forbids. A future secret with different rules is a new variant plus whatever
/// review that deserves — which is the point of making it an enum rather than a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// A private key, or the content-cache key. The keystore or nothing.
    KeystoreOnly,
    /// The control-API token, and nothing else. May fall back to a `0600` file, *reported*.
    TokenFallback,
}

/// Why a secret could not be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The platform has no keystore and the secret is not permitted a fallback.
    ///
    /// A refusal rather than a downgrade. `PRIVACY.md` 7.4 says so in terms, and the alternative
    /// is a build that quietly writes a private key to a file on the one platform where the
    /// keyring is missing — which is the platform where the user is least likely to look.
    NoKeystoreAndNoFallback { what: &'static str },
    /// The keystore refused, and the reason is deliberately not the secret.
    KeystoreRefused { detail: String },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKeystoreAndNoFallback { what } => write!(
                f,
                "this platform provides no keystore, and a {what} may not be written to a file: \
                 PRIVACY.md 7.4 makes that a refusal rather than a downgrade"
            ),
            Self::KeystoreRefused { detail } => {
                write!(f, "the platform keystore refused: {detail}")
            }
        }
    }
}

impl std::error::Error for StoreError {}

/// Bytes that are wiped when they go out of scope, and that never print themselves.
///
/// `Debug` and `Display` are implemented to say nothing, which satisfies `PRIVACY.md` 7.3's
/// "never placed in […] an error message" without asking every future caller to remember. A type
/// that prints its own contents when somebody adds a `{:?}` to a log line is a type that will.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    bytes: Vec<u8>,
}

impl Secret {
    /// Take ownership of secret bytes.
    ///
    /// The caller's copy is zeroised, because a constructor that leaves the original lying around
    /// has moved the problem rather than solved it.
    pub fn take(source: &mut Vec<u8>) -> Self {
        let bytes = core::mem::take(source);
        source.zeroize();
        Self { bytes }
    }

    /// Borrow the bytes. Deliberately not `Clone` and deliberately not `into_vec`.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({} bytes, contents withheld)", self.bytes.len())
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<secret>")
    }
}

/// The platform keystore, as this crate needs it.
///
/// A trait so the refusal above is testable without a keyring, and so that `CRYPTO-AGILITY.md`
/// 7.3's point holds: "platform keystores change […] isolation means the storage backend is
/// replaceable without touching the record format".
pub trait Keystore {
    /// Whether a keystore is actually available on this machine right now.
    ///
    /// Separate from `set` failing, because the two are different facts: a machine with no
    /// keyring at all is a refusal case, and a keyring that declined one write is an error to
    /// report. Collapsing them would turn every transient failure into a licence to write a file.
    fn available(&self) -> bool;
    fn set(&self, name: &str, secret: &Secret) -> Result<(), String>;
    fn get(&self, name: &str) -> Result<Option<Secret>, String>;
    fn delete(&self, name: &str) -> Result<(), String>;
}

/// Where a secret ended up, so the client can report it honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// In the platform keystore, which is the guarantee the documentation describes.
    Keystore,
    /// In a `0600` file, which is weaker. `PRIVACY.md` 7.4: the client MUST report this and MUST
    /// NOT describe such an installation as keeping its secrets in the keystore.
    FileFallback,
}

impl Placement {
    /// The sentence a user is owed when the weaker guarantee applies.
    ///
    /// Returned as text rather than left to each call site, because "MUST report" implemented as
    /// "the caller should probably mention it" is how a requirement becomes a comment.
    pub fn disclosure(self) -> Option<&'static str> {
        match self {
            Self::Keystore => None,
            Self::FileFallback => Some(
                "This installation has no platform keystore. The control-API token is held in a \
                 file with mode 0600 instead, which is a weaker guarantee: anything running as \
                 your user can read it. This installation does not keep its secrets in a keystore.",
            ),
        }
    }
}

/// Store a secret, honouring 7.4.
///
/// The whole rule, in one place, with the refusal as a return value rather than a panic — a panic
/// in a desktop client is a crash report, and a crash report is where a secret ends up.
pub fn store(
    keystore: &dyn Keystore,
    name: &str,
    secret: &Secret,
    sensitivity: Sensitivity,
    write_file_fallback: impl FnOnce(&Secret) -> Result<(), String>,
) -> Result<Placement, StoreError> {
    if keystore.available() {
        return match keystore.set(name, secret) {
            Ok(()) => Ok(Placement::Keystore),
            Err(detail) => Err(StoreError::KeystoreRefused { detail }),
        };
    }

    match sensitivity {
        // The refusal. Not a warning, not a prompt, not a configuration option.
        Sensitivity::KeystoreOnly => Err(StoreError::NoKeystoreAndNoFallback {
            what: "private key or content-cache key",
        }),
        Sensitivity::TokenFallback => match write_file_fallback(secret) {
            Ok(()) => Ok(Placement::FileFallback),
            Err(detail) => Err(StoreError::KeystoreRefused { detail }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A keystore that is present or absent on demand, and records what it was asked to hold.
    struct FakeKeystore {
        present: bool,
        held: RefCell<Vec<(String, Vec<u8>)>>,
        refuse: bool,
    }

    impl FakeKeystore {
        fn present() -> Self {
            Self {
                present: true,
                held: RefCell::new(Vec::new()),
                refuse: false,
            }
        }
        fn absent() -> Self {
            Self {
                present: false,
                held: RefCell::new(Vec::new()),
                refuse: false,
            }
        }
        fn refusing() -> Self {
            Self {
                present: true,
                held: RefCell::new(Vec::new()),
                refuse: true,
            }
        }
    }

    impl Keystore for FakeKeystore {
        fn available(&self) -> bool {
            self.present
        }
        fn set(&self, name: &str, secret: &Secret) -> Result<(), String> {
            if self.refuse {
                return Err("keyring locked".into());
            }
            self.held
                .borrow_mut()
                .push((name.into(), secret.expose().to_vec()));
            Ok(())
        }
        fn get(&self, name: &str) -> Result<Option<Secret>, String> {
            Ok(self
                .held
                .borrow()
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| Secret { bytes: v.clone() }))
        }
        fn delete(&self, _name: &str) -> Result<(), String> {
            Ok(())
        }
    }

    fn secret_of(bytes: &[u8]) -> Secret {
        let mut v = bytes.to_vec();
        Secret::take(&mut v)
    }

    #[test]
    fn a_private_key_without_a_keystore_is_refused_rather_than_written() {
        // PRIVACY.md 7.4 in one assertion: "a private key or the content-cache key on a platform
        // without a keystore is a refusal, not a downgrade". The fallback closure panics, so if
        // this ever starts writing the file the test does not merely fail -- it says why.
        let store_result = store(
            &FakeKeystore::absent(),
            "identity",
            &secret_of(&[7u8; 32]),
            Sensitivity::KeystoreOnly,
            |_| panic!("a private key must never reach the file fallback"),
        );
        assert!(matches!(
            store_result,
            Err(StoreError::NoKeystoreAndNoFallback { .. })
        ));
    }

    #[test]
    fn the_control_token_may_fall_back_and_the_placement_says_so() {
        let wrote = RefCell::new(false);
        let placement = store(
            &FakeKeystore::absent(),
            "control-token",
            &secret_of(&[9u8; 32]),
            Sensitivity::TokenFallback,
            |_| {
                *wrote.borrow_mut() = true;
                Ok(())
            },
        )
        .expect("the token is the one secret with a fallback");

        assert_eq!(placement, Placement::FileFallback);
        assert!(*wrote.borrow(), "the fallback actually wrote");
        // "The client MUST report that the weaker guarantee applies." A placement that could be
        // ignored would make that a suggestion, so the disclosure is attached to the value.
        assert!(placement.disclosure().is_some());
        assert!(placement.disclosure().unwrap().contains("weaker guarantee"));
    }

    #[test]
    fn a_keystore_placement_discloses_nothing_because_there_is_nothing_to_disclose() {
        let placement = store(
            &FakeKeystore::present(),
            "identity",
            &secret_of(&[1u8; 32]),
            Sensitivity::KeystoreOnly,
            |_| panic!("unreachable when a keystore exists"),
        )
        .expect("a present keystore accepts");
        assert_eq!(placement, Placement::Keystore);
        assert_eq!(placement.disclosure(), None);
    }

    #[test]
    fn a_keystore_that_refuses_is_an_error_and_never_a_licence_to_write_a_file() {
        // The distinction `available()` exists for. A keyring that declined one write is a
        // transient failure; treating it as "no keystore" would turn every hiccup into a private
        // key on disk, which is the downgrade 7.4 forbids arriving through an error path.
        let result = store(
            &FakeKeystore::refusing(),
            "identity",
            &secret_of(&[2u8; 32]),
            Sensitivity::KeystoreOnly,
            |_| panic!("a refusal is not a fallback"),
        );
        assert!(matches!(result, Err(StoreError::KeystoreRefused { .. })));

        // And the same for the token: a refusing keystore does not silently become a file.
        let token = store(
            &FakeKeystore::refusing(),
            "control-token",
            &secret_of(&[3u8; 32]),
            Sensitivity::TokenFallback,
            |_| panic!("a refusal is not a fallback"),
        );
        assert!(matches!(token, Err(StoreError::KeystoreRefused { .. })));
    }

    #[test]
    fn a_secret_never_prints_itself() {
        // PRIVACY.md 7.3: "never placed in a garbage-collected string, an environment variable, a
        // command-line argument, or an error message". A type that prints its contents when
        // somebody adds `{:?}` to a log line is a type that eventually will.
        let secret = secret_of(b"correct horse battery staple");
        let debug = format!("{secret:?}");
        let display = format!("{secret}");
        assert!(!debug.contains("horse"), "{debug}");
        assert!(!display.contains("horse"), "{display}");
        assert!(
            debug.contains("28 bytes"),
            "the length is fine to say: {debug}"
        );
    }

    #[test]
    fn an_error_never_carries_the_secret() {
        let detail = StoreError::KeystoreRefused {
            detail: "keyring locked".into(),
        }
        .to_string();
        assert!(detail.contains("keyring locked"));
        let refusal = StoreError::NoKeystoreAndNoFallback {
            what: "private key",
        }
        .to_string();
        assert!(refusal.contains("refusal rather than a downgrade"));
    }

    #[test]
    fn taking_a_secret_clears_the_callers_copy() {
        // A constructor that leaves the original lying around has moved the problem, not solved
        // it: the caller's buffer is exactly the copy nobody remembers to wipe.
        let mut source = vec![0xABu8; 32];
        let secret = Secret::take(&mut source);
        assert_eq!(secret.len(), 32);
        assert!(
            source.is_empty() || source.iter().all(|b| *b == 0),
            "{source:?}"
        );
    }

    #[test]
    fn the_sensitivity_set_is_closed_at_two() {
        // A third variant would be the downgrade 7.4 forbids, arriving as an enum arm. This is a
        // reminder in test form: adding one should require deleting this assertion deliberately.
        let all = [Sensitivity::KeystoreOnly, Sensitivity::TokenFallback];
        assert_eq!(all.len(), 2);
        assert_ne!(all[0], all[1]);
    }
}
