use serde::{Deserialize, Serialize};
use typeshare::typeshare;

mod credential_properties;

pub use credential_properties::*;

/// This is a dictionary containing the client extension input values for zero or more
/// [WebAuthn Extensions]. There are currently none supported.
///
/// <https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientinputs>
///
/// [WebAuthn Extensions]: https://w3c.github.io/webauthn/#webauthn-extensions
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct AuthenticationExtensionsClientInputs {
    /// Boolean to indicate that this extension is requested by the relying party.
    ///
    /// See [`CredentialPropertiesOutput`] for more information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
}

/// This is a dictionary containing the client extension output values for zero or more
/// [WebAuthn Extensions].
///
/// <https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientoutputs>
///
/// [WebAuthn Extensions]: https://w3c.github.io/webauthn/#webauthn-extensions
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct AuthenticatorExtensionsClientOutputs {
    /// Contains properties of the given [`PublicKeyCredential`] when it is included.
    ///
    /// See [`CredentialPropertiesOutput`] for more information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<CredentialPropertiesOutput>,
}
