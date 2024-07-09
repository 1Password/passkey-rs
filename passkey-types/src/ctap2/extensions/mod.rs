//! Types for the CTAP2 authenticator extensions.
//!
//! <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-defined-extensions>
mod hmac_secret;
pub(super) mod prf;

pub use hmac_secret::{HmacGetSecretInput, HmacSecretSaltOrOutput, TryFromSliceError};
pub use prf::{
    AuthenticatorPrfGetOutputs, AuthenticatorPrfInputs, AuthenticatorPrfMakeOutputs,
    AuthenticatorPrfValues,
};
