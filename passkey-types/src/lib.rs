//! # Passkey Types
//!
//! Rust type definitions for the `webauthn` and `CTAP` specifications.
//!
//! Coming Soon

#[macro_use]
mod utils;

pub mod ctap2;
pub mod webauthn;
// pub mod u2f;

// Re-exports
pub use utils::{
    bytes::{Bytes, NotBase64Encoded},
    crypto, encoding,
};
