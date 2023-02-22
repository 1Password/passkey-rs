//! The types defined here are a representation of types defined in the [CTAP 2.0] specification along
//! with authenticator specific types from the [WebAuthn Level 3] specification.
//!
//! [CTAP 2.0]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
//! [WebAuthn Level 3]: https://w3c.github.io/webauthn

mod aaguid;
mod attestation_fmt;
mod error;
mod flags;

pub mod get_assertion;
pub mod get_info;
pub mod make_credential;

pub use self::{aaguid::*, attestation_fmt::*, error::*, flags::*};
