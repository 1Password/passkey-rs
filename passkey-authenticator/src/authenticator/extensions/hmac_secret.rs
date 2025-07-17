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

#[cfg(test)]
pub mod tests {
    use passkey_types::{Passkey, ctap2::Aaguid};

    use crate::{Authenticator, MockUserValidationMethod};

    use super::*;

    pub(crate) fn prf_eval_request(eval: Option<Vec<u8>>) -> AuthenticatorPrfInputs {
        let eval = eval
            .and_then(|data| HmacSecretSaltOrOutput::try_from(data.as_slice()).ok())
            .map(|salts| AuthenticatorPrfValues {
                first: salts.first().try_into().unwrap(),
                second: salts.second().map(|b| b.try_into().unwrap()),
            });
        AuthenticatorPrfInputs {
            eval,
            eval_by_credential: None,
        }
    }

    #[test]
    fn hmac_secret_cycle_works() {
        let auth = Authenticator::new(Aaguid::new_empty(), None, MockUserValidationMethod::new())
            .hmac_secret(HmacSecretConfig::new_without_uv());

        let ext = auth
            .make_hmac_secret(Some(true))
            .expect("There should be passkey extensions");
        assert!(ext.cred_without_uv.is_some());

        let passkey = Passkey::mock("sneakernetsend.com".into())
            .hmac_secret(ext)
            .build();

        let request = prf_eval_request(Some(random_vec(64)));

        let res = auth
            .get_prf(
                &passkey.credential_id,
                passkey.extensions.hmac_secret.as_ref(),
                request.clone(),
                true,
            )
            .expect("did not succeed in creating hashes")
            .expect("hmac-secret was not supported when creation was requested")
            .results;
        assert!(res.second.is_some());
        assert_ne!(&res.first, res.second.as_ref().unwrap());

        // Make sure that the same input gives the same output
        let res2 = auth
            .get_prf(
                &passkey.credential_id,
                passkey.extensions.hmac_secret.as_ref(),
                request.clone(),
                true,
            )
            .expect("did not succeed in calling it twice with the same input")
            .expect("hmac-secret was not supported when creation was requested")
            .results;

        assert_eq!(res.first, res2.first);
        assert_eq!(res.second, res2.second);

        // Ensure that a different input changes the output
        let res3 = auth
            .get_prf(
                &passkey.credential_id,
                passkey.extensions.hmac_secret.as_ref(),
                prf_eval_request(Some(random_vec(64))),
                true,
            )
            .expect("Changing input should still succeed")
            .expect("hmac-secret was not supported when creation was requested")
            .results;

        assert_ne!(res.first, res3.first);
        assert_ne!(res.second, res3.second);
        assert!(res3.second.is_some());
        assert_ne!(res3.first, res3.second.unwrap());

        // make sure that if the same input is given but without UV the output is different
        let res4 = auth
            .get_prf(
                &passkey.credential_id,
                passkey.extensions.hmac_secret.as_ref(),
                request,
                false,
            )
            .expect("did not succeed in calling it twice with the same input")
            .expect("hmac-secret was not supported when creation was requested")
            .results;

        assert_ne!(res.first, res4.first);
        assert_ne!(res.second, res4.second);
        assert!(res4.second.is_some());
        assert_ne!(res4.first, res4.second.unwrap());
    }

    #[test]
    fn hmac_secret_cycle_works_with_one_cred() {
        let auth = Authenticator::new(Aaguid::new_empty(), None, MockUserValidationMethod::new())
            .hmac_secret(HmacSecretConfig::new_with_uv_only());

        let ext = auth
            .make_hmac_secret(Some(true))
            .expect("There should be passkey extensions");
        assert!(ext.cred_without_uv.is_none());

        let passkey = Passkey::mock("sneakernetsend.com".into())
            .hmac_secret(ext)
            .build();

        let request = prf_eval_request(Some(random_vec(64)));

        let res = auth
            .get_prf(
                &passkey.credential_id,
                passkey.extensions.hmac_secret.as_ref(),
                request.clone(),
                true,
            )
            .expect("did not succeed in creating hashes")
            .expect("hmac-secret was not supported when creation was requested")
            .results;
        assert!(res.second.is_none());

        let res2 = auth
            .get_prf(
                &passkey.credential_id,
                passkey.extensions.hmac_secret.as_ref(),
                request,
                true,
            )
            .expect("did not succeed in calling it twice with the same input")
            .expect("hmac-secret was not supported when creation was requested")
            .results;

        assert_eq!(res.first, res2.first);
        assert!(res2.second.is_none());

        let res3 = auth
            .get_prf(
                &passkey.credential_id,
                passkey.extensions.hmac_secret.as_ref(),
                prf_eval_request(Some(random_vec(64))),
                true,
            )
            .expect("Changing input should still succeed")
            .expect("hmac-secret was not supported when creation was requested")
            .results;

        assert_ne!(res.first, res3.first);
        assert!(res3.second.is_none());
    }
}
