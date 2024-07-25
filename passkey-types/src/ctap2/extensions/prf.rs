//! While this is not an official CTAP extension,
//! it is used on Windows directly and it allows an in-memory authenticator
//! to handle the prf extension in a more efficient manor.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{webauthn, Bytes};

#[cfg(doc)]
use crate::ctap2::{get_assertion, make_credential};

/// This struct is a more opiniated mirror of [`webauthn::AuthenticationExtensionsPrfInputs`].
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthenticatorPrfInputs {
    /// See  [`webauthn::AuthenticationExtensionsPrfInputs::eval`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<AuthenticatorPrfValues>,

    /// See  [`webauthn::AuthenticationExtensionsPrfInputs::eval_by_credential`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval_by_credential: Option<HashMap<Bytes, AuthenticatorPrfValues>>,
}

/// This struct is a more opiniated mirror of [`webauthn::AuthenticationExtensionsPrfValues`].
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthenticatorPrfValues {
    /// This is the already hashed values of [`webauthn::AuthenticationExtensionsPrfValues::first`].
    pub first: [u8; 32],

    /// This is the already hashed values of [`webauthn::AuthenticationExtensionsPrfValues::second`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second: Option<[u8; 32]>,
}

impl From<AuthenticatorPrfValues> for webauthn::AuthenticationExtensionsPrfValues {
    fn from(value: AuthenticatorPrfValues) -> Self {
        Self {
            first: value.first.to_vec().into(),
            second: value.second.map(|b| b.to_vec().into()),
        }
    }
}

/// This struct is a more opiniated mirror of [`webauthn::AuthenticationExtensionsPrfOutputs`]
/// specifically for [`make_credential`].
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthenticatorPrfMakeOutputs {
    /// See [`webauthn::AuthenticationExtensionsPrfOutputs::enabled`].
    pub enabled: bool,

    /// See [`webauthn::AuthenticationExtensionsPrfOutputs::results`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<AuthenticatorPrfValues>,
}

impl From<AuthenticatorPrfMakeOutputs> for webauthn::AuthenticationExtensionsPrfOutputs {
    fn from(value: AuthenticatorPrfMakeOutputs) -> Self {
        Self {
            enabled: Some(value.enabled),
            results: value.results.map(Into::into),
        }
    }
}

/// This struct is a more opiniated mirror of [`webauthn::AuthenticationExtensionsPrfOutputs`]
/// specifically for [`get_assertion`].
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthenticatorPrfGetOutputs {
    /// See [`webauthn::AuthenticationExtensionsPrfOutputs::results`].
    pub results: AuthenticatorPrfValues,
}

impl From<AuthenticatorPrfGetOutputs> for webauthn::AuthenticationExtensionsPrfOutputs {
    fn from(value: AuthenticatorPrfGetOutputs) -> Self {
        Self {
            enabled: None,
            results: Some(value.results.into()),
        }
    }
}
