use serde::{Deserialize, Serialize};
use typeshare::typeshare;

mod credential_properties;
mod pseudo_random_function;

pub use credential_properties::*;
pub use pseudo_random_function::*;

#[cfg(doc)]
use crate::webauthn::PublicKeyCredential;

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

    /// Inputs for the pseudo-random function extension where the inputs are already hashed
    /// by another client following the `sha256("WebAuthn PRF" || salt)` format.
    ///
    /// This is not an official extension, rather a field that occurs in some cases on Android
    /// as well as the field that MUST be used when mapping from Apple's Authentication Services
    /// [`ASAuthorizationPublicKeyCredentialPRFAssertionInput`].
    ///
    /// This field SHOULD NOT be present alongside the [`Self::prf`] field as that field will take precedence.
    ///
    /// [`ASAuthorizationPublicKeyCredentialPRFAssertionInput`]: https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialprfassertioninput-swift.struct
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf_already_hashed: Option<AuthenticationExtensionsPrfInputs>,
}

impl AuthenticationExtensionsClientInputs {
    /// Validates that there is at least one extension field that is `Some`
    /// and that they are in turn not empty. If all fields are `None`
    /// then this returns `None` as well.
    pub fn zip_contents(self) -> Option<Self> {
        let Self {
            cred_props,
            prf,
            prf_already_hashed,
        } = &self;
        let has_cred_props = cred_props.is_some();

        let has_prf = prf.is_some();
        let has_prf_already_hashed = prf_already_hashed.is_some();

        (has_cred_props || has_prf || has_prf_already_hashed).then_some(self)
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
#[typeshare(swift = "Equatable, Hashable")]
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
