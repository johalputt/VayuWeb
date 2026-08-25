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

pub mod cbor;
pub mod cid;
pub mod control;
pub mod dagnode;
pub mod doctor;
pub mod doctor_fix;
pub mod domain;
pub mod identity;
pub mod names;
pub mod namespace_generated;
pub mod pow;
pub mod publish;
pub mod publish_flow;
pub mod record;
pub mod secrets;
pub mod serve;
pub mod store;
pub mod verify;
