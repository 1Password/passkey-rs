use std::ops::Not;

use passkey_types::{
    crypto::hmac_sha256,
    ctap2::{
        extensions::{
            AuthenticatorPrfGetOutputs, AuthenticatorPrfInputs, AuthenticatorPrfMakeOutputs,
            AuthenticatorPrfValues, HmacSecretSaltOrOutput,
        },
        Ctap2Error, StatusCode, U2FError,
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
}

impl HmacSecretConfig {
    /// Create a new configuration which only supports creating credentials
    /// gated by UV
    pub fn new_with_uv_only() -> Self {
        Self {
            credentials: HmacSecretCredentialSupport::WithUvOnly,
        }
    }

    /// Create a new configuration which supports creating 2 credentials:
    /// 1. Gated by UV
    /// 2. Not protected by UV, and only needs UP
    pub fn new_without_uv() -> Self {
        Self {
            credentials: HmacSecretCredentialSupport::WithoutUv,
        }
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
    ) -> Result<Option<AuthenticatorPrfMakeOutputs>, StatusCode> {
        if self.extensions.hmac_secret.is_none() {
            return Ok(None);
        };

        if passkey_ext.is_none() {
            return Ok(Some(AuthenticatorPrfMakeOutputs {
                enabled: false,
                results: None,
            }));
        };

        Ok(Some(AuthenticatorPrfMakeOutputs {
            enabled: true,
            results: None,
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

fn calculate_hmac_secret(
    hmac_creds: &passkey_types::StoredHmacSecret,
    salts: HmacSecretSaltOrOutput,
    config: &HmacSecretConfig,
    uv: bool,
) -> Result<HmacSecretSaltOrOutput, StatusCode> {
    let cred_random = if uv {
        &hmac_creds.cred_with_uv
    } else {
        hmac_creds
            .cred_without_uv
            .as_ref()
            .ok_or(Ctap2Error::UserVerificationBlocked)?
    };

    let output1 = hmac_sha256(cred_random, salts.first());
    let output2 = salts.second().and_then(|salt2| {
        config
            .supports_no_uv()
            .then(|| hmac_sha256(cred_random, salt2))
    });

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
