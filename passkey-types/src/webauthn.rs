//! Implementation of the types defined in [WebAuthn Level 3]
//!
//! [WebAuthn Level 3]: https://w3c.github.io/webauthn

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::{utils::serde::ignore_unknown, Bytes};

mod assertion;
mod attestation;
mod common;
mod extensions;

// re-export types
pub use self::{assertion::*, attestation::*, common::*, extensions::*};

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::AuthenticatorAssertionResponse {}
    impl Sealed for super::AuthenticatorAttestationResponse {}
}

/// Marker trait for response types
pub trait AuthenticatorResponse: sealed::Sealed {}

impl AuthenticatorResponse for AuthenticatorAssertionResponse {}
impl AuthenticatorResponse for AuthenticatorAttestationResponse {}

/// This is the response from a successful creation or assertion of a credential.
///
/// It is recommended to use the type aliases depending on which response you are expecting:
/// * Credential Creation: [CreatedPublicKeyCredential]
/// * Credential assertion: [AuthenticatedPublicKeyCredential]
///
/// <https://w3c.github.io/webauthn/#iface-pkcredential>
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct PublicKeyCredential<R: AuthenticatorResponse> {
    /// The id contains the credential ID, chosen by the authenticator. This is usually the base64url
    /// encoded data of [Self::raw_id]
    ///
    /// The credential ID is used to look up credentials for use and is therefore expected to be
    /// globally unique with high probability across all credentials of the same type across all
    /// authenticators.
    ///
    /// > NOTE: This API does not constrain the format or length of this identifier, except that it
    /// MUST be sufficient for the authenticator to uniquely select a key.
    pub id: String,

    /// The raw byte containing the credential ID, see [Self::id] for more information.
    pub raw_id: Bytes,

    /// Always [PublicKeyCredentialType]
    #[serde(rename = "type")]
    pub ty: PublicKeyCredentialType,

    /// This contains the authenticator's response to the client's request to either:
    /// * create a public key in which case it is of type [AuthenticatorAttestationResponse] or
    /// * generate an authentication assertion in which case it is of type [AuthenticatorAssertionResponse]
    pub response: R,

    /// This reports the modality of the communication between the client and authenticator.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "ignore_unknown"
    )]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,

    /// This object is a map containing extension identifier → client extension output entries
    /// produced by the extension’s client extension processing.
    #[serde(default)]
    pub client_extension_results: AuthenticatorExtensionsClientOutputs,
}
