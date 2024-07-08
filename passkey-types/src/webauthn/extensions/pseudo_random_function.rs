use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use std::collections::HashMap;

use crate::Bytes;

/// Pseudo-random function values.
///
/// This is used for both PRF inputs and outputs.
///
/// When used as inputs to the PRF evaluation, these values will be included
/// in the calculation of the salts that are sent as parameters in the
/// `hmac-secret` extension process to the authenticator.
///
/// When used as outputs, the fields will contain the results of evaluating
/// the PRF.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
#[typeshare(swift = "Equatable")]
pub struct AuthenticationExtensionsPrfValues {
    /// The first PRF value.
    pub first: Bytes,

    /// The second PRF value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second: Option<Bytes>,
}

/// Inputs for the pseudo-random function extension.
///
/// This client registration extension and authentication extension allows a
/// Relying Party to evaluate outputs from a pseudo-random function (PRF)
/// associated with a credential. The PRFs provided by this extension map from
/// BufferSources of any length to 32-byte BufferSources.
///
/// <https://w3c.github.io/webauthn/#prf-extension>
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct AuthenticationExtensionsPrfInputs {
    /// One or two inputs on which to evaluate PRF. Not all authenticators
    /// support evaluating the PRFs during credential creation so outputs may,
    /// or may not, be provided. If not, then an assertion is needed in order
    /// to obtain the outputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<AuthenticationExtensionsPrfValues>,

    /// A record mapping base64url encoded [credential IDs] to PRF inputs to
    /// evaluate for that credential. Only applicable during assertions when
    /// [allowCredentials] is not empty.
    ///
    /// [credential IDs]: https://w3c.github.io/webauthn/#credential-id
    /// [allowCredentials]: https://w3c.github.io/webauthn/#dom-publickeycredentialrequestoptions-allowcredentials
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval_by_credential: Option<HashMap<String, AuthenticationExtensionsPrfValues>>,
}

/// Outputs from the pseudo-random function extension.
///
/// See [`AuthenticationExtensionsPrfInputs`] for details.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
#[typeshare(swift = "Equatable")]
pub struct AuthenticationExtensionsPrfOutputs {
    /// True if, and only if, the one or two PRFs are available for use with
    /// the created credential. This is only reported during registration and
    /// is not present in the case of authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// The results of evaluating the PRF for the inputs given in `eval` or
    /// `evalByCredential` in [`AuthenticationExtensionsPrfInputs`]. Outputs
    /// may not be available during registration; see comments in `eval`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<AuthenticationExtensionsPrfValues>,
}
