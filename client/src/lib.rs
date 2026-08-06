//! The VayuWeb desktop client, in Rust.
//!
//! `docs/ROADMAP.md` Phase 5. `docs/ARCHITECTURE.md`, "Implementation Language": the protocol
//! fixes formats and not runtimes, and Rust is the expected choice here because Tauri already is
//! one — the only question was how much lives below that boundary, and the answer is everything
//! that touches a secret.
//!
//! What this crate is **not** is a second implementation of the protocol. `docs/ROADMAP.md`
//! Phase 6 asks for one written by parties with no common employer or funder; a second language
//! written by the same hands does not satisfy it and must not be reported as though it did.

pub mod secrets;
