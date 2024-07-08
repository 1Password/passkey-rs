use serde::{Deserialize, Serialize};
use typeshare::typeshare;

mod credential_properties;
mod pseudo_random_function;

pub use credential_properties::*;
pub use pseudo_random_function::*;

/// This is a dictionary containing the client extension input values for zero or more
/// [WebAuthn Extensions]. There are currently none supported.
///
/// <https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientinputs>
///
/// [WebAuthn Extensions]: https://w3c.github.io/webauthn/#webauthn-extensions
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct AuthenticationExtensionsClientInputs {
    /// Boolean to indicate that this extension is requested by the relying party.
    ///
    /// See [`CredentialPropertiesOutput`] for more information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,

    /// Inputs for the pseudo-random function extensions.
    ///
    /// See [`AuthenticationExtensionsPrfInputs`] for more information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<AuthenticationExtensionsPrfInputs>,
}

impl AuthenticationExtensionsClientInputs {
    /// Validates that there is at least one extension field that is `Some`
    /// and that they are in turn not empty. If all fields are `None`
    /// then this returns `None` as well.
    pub fn zip_contents(self) -> Option<Self> {
        let Self { cred_props, prf } = &self;

        let has_cred_props = cred_props.is_some();
        let has_prf = prf.is_some();

        (has_cred_props || has_prf).then_some(self)
    }
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
pub struct AuthenticationExtensionsClientOutputs {
    /// Contains properties of the given [`PublicKeyCredential`] when it is included.
    ///
    /// See [`CredentialPropertiesOutput`] for more information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<CredentialPropertiesOutput>,

    /// Contains the results of evaluating the PRF.
    ///
    /// See [`AuthenticationExtensionsPrfOutputs`] for more information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<AuthenticationExtensionsPrfOutputs>,
}
