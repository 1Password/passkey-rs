use serde::{Deserialize, Serialize};
use typeshare::typeshare;

#[cfg(doc)]
use crate::webauthn::PublicKeyCredential;

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

/// This client registration extension facilitates reporting certain credential properties known by
/// the client to the requesting WebAuthn [Relying Party] upon creation of a [`PublicKeyCredential`]
/// source as a result of a registration ceremony.
///
/// <https://w3c.github.io/webauthn/#sctn-authenticator-credential-properties-extension>
///
/// [Relying Party]: https://w3c.github.io/webauthn/#relying-party
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct CredentialPropertiesOutput {
    /// This OPTIONAL property, known abstractly as the resident key credential property
    /// (i.e., client-side [discoverable credential] property), is a Boolean value indicating whether
    /// the [`PublicKeyCredential`] returned as a result of a registration ceremony is a client-side
    /// [discoverable credential].
    /// * If `rk` is true, the credential is a [discoverable credential].
    /// * If `rk` is false, the credential is a [server-side credential].
    /// * If `rk` is not present, it is not known whether the credential is a [discoverable credential]
    ///   or a [server-side credential].
    ///
    /// [discoverable credential]: https://w3c.github.io/webauthn/#discoverable-credential
    /// [server-side credential]: https://w3c.github.io/webauthn/#server-side-public-key-credential-source
    #[serde(rename = "rk", default, skip_serializing_if = "Option::is_none")]
    pub discoverable: Option<bool>,

    /// This OPTIONAL property is a human-palatable description of the credential’s managing
    /// authenticator, chosen by the user.
    ///
    /// The client MUST allow the user to choose this value, MAY or MAY not present that choice
    /// during registration ceremonies, and MAY reuse the same value for multiple credentials with
    /// the same managing authenticator across multiple Relying Parties.
    ///
    /// The client MAY query the authenticator, by some unspecified mechanism, for this value.
    /// The authenticator MAY allow the user to configure the response to such a query.
    /// The authenticator vendor MAY provide a default response to such a query. The client MAY
    /// consider a user-configured response chosen by the user, and SHOULD allow the user to
    /// modify a vendor-provided default response.
    ///
    /// If the Relying Party includes an `authenticatorDisplayName` item in credential records, the
    /// Relying Party MAY offer this value, if present, as a default value for the
    /// `authenticatorDisplayName` of the new credential record.
    ///
    /// NOTE: This is still [in proposal](https://github.com/w3c/webauthn/pull/1880), we are
    /// implementing it here to show our backing to this feature
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_display_name: Option<String>,
}
