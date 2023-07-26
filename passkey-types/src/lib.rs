//! # Passkey Types
//!
//! [![github]](https://github.com/1Password/passkey-rs/tree/main/passkey-types)
//! [![version]](https://crates.io/crates/passkey-types)
//! [![documentation]](crate)
//!
//! This crate contains the types defined in both the [WebAuthn Level 3] and [CTAP 2.0]
//! specifications for the operations they define. They are each separated in their own modules.
//!
//! ## Webauthn
//!
//! In [this](webauthn) module the type names mirror exactly those in the specifications for ease of
//! navigation. They are defined in a way that allows interoperability with the web types directly
//! as well as the [JSON encoding] for over network communication.
//!
//! ## CTAP 2
//!
//! In [this](ctap2) module, since the method inputs are not given explicit names, the `Request` and
//! `Response` types are defined in separate modules for each operation. These types make use of the
//! same data structures from the [`webauthn`] module. In some cases though, the types have
//! different constraits regarding required and optional fields, in which case it is re-defined in
//! the [`ctap2`] module along with a [`TryFrom`] implementation in either direction.
//!
//! [github]: https://img.shields.io/badge/GitHub-1Password%2Fpasskey--rs%2Fpasskey--types-informational?logo=github&style=flat
//! [version]: https://img.shields.io/crates/v/passkey-types?logo=rust&style=flat
//! [documentation]: https://img.shields.io/docsrs/passkey-types/latest?logo=docs.rs&style=flat
//! [WebAuthn Level 3]: https://w3c.github.io/webauthn/
//! [CTAP 2.0]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
//! [JSON encoding]: https://w3c.github.io/webauthn/#typedefdef-publickeycredentialjson

#[macro_use]
mod utils;

mod passkey;

pub mod ctap2;
pub mod u2f;
pub mod webauthn;

// Re-exports
pub use self::{
    passkey::Passkey,
    utils::{
        bytes::{Bytes, NotBase64Encoded},
        crypto, encoding, rand,
    },
};
