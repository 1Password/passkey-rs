use std::ops::Not;

use passkey_types::{
    crypto::hmac_sha256,
    ctap2::{
        Ctap2Error, StatusCode, U2FError,
        extensions::{
            AuthenticatorPrfGetOutputs, AuthenticatorPrfInputs, AuthenticatorPrfMakeOutputs,
            AuthenticatorPrfValues, HmacSecretSaltOrOutput,
        },
    },
    rand::random_vec,
};

use crate::Authenticator;

/// Logical module for configuring the [hmac-secret] authenticator extension.
///
/// [hmac-secret]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension
#[derive(Debug)]
pub struct HmacSecretConfig {
    credentials: HmacSecretCredentialSupport,
    /// Extension to retrieve a symmetric secret from the authenticator during registration.
    ///
    /// In the spec this is support for `hmac-secret-mc`
    on_make_credential_support: bool,
}

impl HmacSecretConfig {
    /// Create a new configuration which only supports creating credentials
    /// gated by UV
    pub fn new_with_uv_only() -> Self {
        Self {
            credentials: HmacSecretCredentialSupport::WithUvOnly,
            on_make_credential_support: false,
        }
    }

    /// Create a new configuration which supports creating 2 credentials:
    /// 1. Gated by UV
    /// 2. Not protected by UV, and only needs UP
    pub fn new_without_uv() -> Self {
        Self {
            credentials: HmacSecretCredentialSupport::WithoutUv,
            on_make_credential_support: false,
        }
    }

    /// Enable support for returning the hmac-secret values on credential creation
    pub fn enable_on_make_credential(mut self) -> Self {
        self.on_make_credential_support = true;
        self
    }

    /// Check whether this configuration supports `hmac-secret-mc`,
    /// meaning it supports retrieving the symmetric secret on credential creation.
    pub fn hmac_secret_mc(&self) -> bool {
        self.on_make_credential_support
    }

    fn supports_no_uv(&self) -> bool {
        self.credentials.without_uv()
    }
}

/// Set whether the Hmac Secret generation supports one or two credentials
#[derive(Debug)]
pub enum HmacSecretCredentialSupport {
    /// Only support one credential, which is necessarily backed by User Verification
    WithUvOnly,
    /// Support 2 credentials, where the second one is not protected by User Verification
    WithoutUv,
}

impl HmacSecretCredentialSupport {
    fn without_uv(&self) -> bool {
        match self {
            HmacSecretCredentialSupport::WithUvOnly => false,
            HmacSecretCredentialSupport::WithoutUv => true,
        }
    }
}

impl<S, U> Authenticator<S, U> {
    pub(super) fn make_hmac_secret(
        &self,
        hmac_secret_request: Option<bool>,
    ) -> Option<passkey_types::StoredHmacSecret> {
        let config = self.extensions.hmac_secret.as_ref()?;

        // The spec recommends to still generate and associate credentials regardless of the request
        // but in that case we might be storing things that won't be used. I'd rather wait an see
        // if theres really cases for this.
        if hmac_secret_request.is_some_and(|b| b).not() {
            return None;
        }

        Some(passkey_types::StoredHmacSecret {
            cred_with_uv: random_vec(32),
            cred_without_uv: config.credentials.without_uv().then(|| random_vec(32)),
        })
    }

    pub(super) fn make_prf(
        &self,
        passkey_ext: Option<&passkey_types::StoredHmacSecret>,
        request: AuthenticatorPrfInputs,
        uv: bool,
    ) -> Result<Option<AuthenticatorPrfMakeOutputs>, StatusCode> {
        let Some(ref config) = self.extensions.hmac_secret else {
            return Ok(None);
        };

        let Some(creds) = passkey_ext else {
            return Ok(Some(AuthenticatorPrfMakeOutputs {
                enabled: false,
                results: None,
            }));
        };

        let results = config
            .on_make_credential_support
            .then(|| {
                request.eval.map(|eval| {
                    let request = HmacSecretSaltOrOutput::new(eval.first, eval.second);

                    calculate_hmac_secret(creds, request, config, uv)
                })
            })
            .flatten()
            .transpose()?;

        Ok(Some(AuthenticatorPrfMakeOutputs {
            enabled: true,
            results: results.map(|shared_secrets| AuthenticatorPrfValues {
                first: shared_secrets.first().try_into().unwrap(),
                second: shared_secrets.second().map(|b| b.try_into().unwrap()),
            }),
        }))
    }

    pub(super) fn get_prf(
        &self,
        credential_id: &[u8],
        passkey_ext: Option<&passkey_types::StoredHmacSecret>,
        salts: AuthenticatorPrfInputs,
        uv: bool,
    ) -> Result<Option<AuthenticatorPrfGetOutputs>, StatusCode> {
        let Some(ref config) = self.extensions.hmac_secret else {
            return Ok(None);
        };

        let hmac_creds = passkey_ext.ok_or(U2FError::InvalidParameter)?;

        let Some(request) = select_salts(credential_id, salts) else {
            return Ok(None);
        };

        let results = calculate_hmac_secret(hmac_creds, request, config, uv)?;

        Ok(Some(AuthenticatorPrfGetOutputs {
            results: AuthenticatorPrfValues {
                first: results.first().try_into().unwrap(),
                second: results.second().map(|b| b.try_into().unwrap()),
            },
        }))
    }
}

/// Calculates the Hmac secret output given the stored credentials and given salts.
///
/// ## Process
/// * The authenticator chooses which CredRandom to use for next step based on whether user verification was done or not in above steps.
///   * If uv bit is set to `true` in the response, let CredRandom be [`passkey_types::StoredHmacSecret::cred_with_uv`].
///   * If uv bit is set to `false` in the response, let CredRandom be [`passkey_types::StoredHmacSecret::cred_without_uv`].
/// * If the authenticator cannot find corresponding CredRandom associated with the credential, authenticator ignores this extension and does not add any response from this extension to "extensions" field of the authenticatorGetAssertion response.
/// * The authenticator generates one or two HMAC-SHA-256 values, depending upon whether it received one salt (32 bytes) or two salts (64 bytes):
///   * output1: `HMAC-SHA-256(CredRandom, salt1)`
///   * output2: `HMAC-SHA-256(CredRandom, salt2)`
///
/// <https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-extension>
fn calculate_hmac_secret(
    hmac_creds: &passkey_types::StoredHmacSecret,
    salts: HmacSecretSaltOrOutput,
    config: &HmacSecretConfig,
    uv: bool,
) -> Result<HmacSecretSaltOrOutput, StatusCode> {
    let cred_random = if uv {
        &hmac_creds.cred_with_uv
    } else {
        config
            .supports_no_uv()
            .then_some(hmac_creds.cred_without_uv.as_ref())
            .flatten()
            .ok_or(Ctap2Error::UserVerificationBlocked)?
    };

    let output1 = hmac_sha256(cred_random, salts.first());
    let output2 = salts.second().map(|salt2| hmac_sha256(cred_random, salt2));

    let result = HmacSecretSaltOrOutput::new(output1, output2);

    Ok(result)
}

fn select_salts(
    credential_id: &[u8],
    request: AuthenticatorPrfInputs,
) -> Option<HmacSecretSaltOrOutput> {
    if let Some(eval_by_cred) = request.eval_by_credential {
        let eval = eval_by_cred
            .into_iter()
            .find(|(key, _)| key.as_slice() == credential_id);
        if let Some((_, eval)) = eval {
            return Some(HmacSecretSaltOrOutput::new(eval.first, eval.second));
        }
    }

    let eval = request.eval?;

    Some(HmacSecretSaltOrOutput::new(eval.first, eval.second))
}

#[cfg(test)]
pub mod tests;
