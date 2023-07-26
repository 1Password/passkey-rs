//! Utils is a module providing utility functions used by various parts of passkey-rs.
pub(crate) mod bytes;
#[macro_use]
pub(crate) mod repr_enum;
pub(crate) mod serde;
#[macro_use]
pub(crate) mod serde_workaround;

pub mod crypto;
pub mod encoding;
pub mod rand;
