use serde::{Deserialize, Serialize};
use typeshare::typeshare;

#[cfg(doc)]
use crate::webauthn::PublicKeyCredential;

/// This client registration extension facilitates reporting certain credential properties known by
/// the client to the requesting WebAuthn [Relying Party] upon creation of a [`PublicKeyCredential`]
/// source as a result of a registration ceremony.
///
/// <https://w3c.github.io/webauthn/#sctn-authenticator-credential-properties-extension>
///
/// [Relying Party]: https://w3c.github.io/webauthn/#relying-party
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[typeshare(swift = "Equatable")]
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
}
