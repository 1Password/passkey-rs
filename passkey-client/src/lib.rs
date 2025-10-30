//! # Passkey Client
//!
//! [![github]](https://github.com/1Password/passkey-rs/tree/main/passkey-client)
//! [![version]](https://crates.io/crates/passkey-client)
//! [![documentation]](https://docs.rs/passkey-client/)
//!
//! This crate defines a [`Client`] type along with a basic implementation of the [Webauthn]
//! specification. The [`Client`] uses an [`Authenticator`] to perform the actual cryptographic
//! operations, while the Client itself marshals data to and from the structs received from the Relying Party.
//!
//! This crate does not provide any code to perform networking requests to and from Relying Parties.
//!
//! [github]: https://img.shields.io/badge/GitHub-1Password%2Fpasskey--rs%2Fpasskey--client-informational?logo=github&style=flat
//! [version]: https://img.shields.io/crates/v/passkey-client?logo=rust&style=flat
//! [documentation]: https://img.shields.io/docsrs/passkey-client/latest?logo=docs.rs&style=flat
//! [Webauthn]: https://w3c.github.io/webauthn/
mod client_data;
pub use client_data::*;

use std::{borrow::Cow, fmt::Display};

use coset::{Algorithm, iana::EnumI64};
use passkey_authenticator::{Authenticator, CredentialStore, UserValidationMethod};
use passkey_types::{
    Passkey,
    crypto::sha256,
    ctap2, encoding,
    webauthn::{
        self, AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement,
    },
};
use serde::Serialize;
#[cfg(feature = "typeshare")]
use typeshare::typeshare;
use url::Url;

mod extensions;
mod rp_id_verifier;

pub use self::rp_id_verifier::{Fetcher, RelatedOriginResponse, RpIdVerifier};

#[cfg(feature = "android-asset-validation")]
pub use self::rp_id_verifier::android::{UnverifiedAssetLink, ValidationError, valid_fingerprint};

#[cfg(test)]
mod tests;

#[cfg_attr(feature = "typeshare", typeshare)]
#[derive(Debug, serde::Serialize, PartialEq, Eq)]
#[serde(tag = "type", content = "content")]
/// Errors produced by Webauthn Operations.
pub enum WebauthnError {
    /// A credential ID can be a maximum of 1023 bytes.
    CredentialIdTooLong,
    /// The request origin was missing a proper domain part.
    OriginMissingDomain,
    /// The request origin is not a sub-domain of the RP ID.
    OriginRpMissmatch,
    /// The origin of the request does not use HTTPS.
    UnprotectedOrigin,
    /// Origin was set to localhost but allows_insecure_localhost was not set.
    InsecureLocalhostNotAllowed,
    /// No credential was found
    CredentialNotFound,
    /// The RP ID is invalid.
    InvalidRpId,
    /// Internal authenticator error whose value represents a `ctap2::StatusCode`
    AuthenticatorError(u8),
    /// The operation is not supported.
    NotSupportedError,
    /// The string did not match the expected pattern.
    SyntaxError,
    /// The input failed validation
    ValidationError,
    /// The given RpId has possibly rolled out related origins
    RequiresRelatedOriginsSupport,
    /// An error when fetching remote resources
    FetcherError,
    /// A redirect that was not allowed occured
    RedirectError,
    /// Related Origins endpoint contains a number of labels exceeding the max limit
    ExceedsMaxLabelLimit,
}

impl WebauthnError {
    /// Was the error a vendor error?
    pub fn is_vendor_error(&self) -> bool {
        matches!(self, WebauthnError::AuthenticatorError(ctap_error) if ctap2::VendorError::try_from(*ctap_error).is_ok())
    }
}

impl From<ctap2::StatusCode> for WebauthnError {
    fn from(value: ctap2::StatusCode) -> Self {
        match value {
            ctap2::StatusCode::Ctap1(u2f) => WebauthnError::AuthenticatorError(u2f.into()),
            ctap2::StatusCode::Ctap2(ctap2::Ctap2Code::Known(ctap2::Ctap2Error::NoCredentials)) => {
                WebauthnError::CredentialNotFound
            }
            ctap2::StatusCode::Ctap2(ctap2code) => {
                WebauthnError::AuthenticatorError(ctap2code.into())
            }
        }
    }
}

/// The origin of a WebAuthn request.
pub enum Origin<'a> {
    /// A Url, meant for a request in the web browser.
    Web(Cow<'a, Url>),
    /// An android digital asset fingerprint.
    /// Meant for a request coming from an android application.
    #[cfg(feature = "android-asset-validation")]
    Android(UnverifiedAssetLink<'a>),
}

impl From<Url> for Origin<'_> {
    fn from(value: Url) -> Self {
        Origin::Web(Cow::Owned(value))
    }
}

impl<'a> From<&'a Url> for Origin<'a> {
    fn from(value: &'a Url) -> Self {
        Origin::Web(Cow::Borrowed(value))
    }
}

impl Display for Origin<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::Web(url) => write!(f, "{}", url.as_str().trim_end_matches('/')),
            #[cfg(feature = "android-asset-validation")]
            Origin::Android(target_link) => {
                write!(
                    f,
                    "android:apk-key-hash:{}",
                    encoding::base64url(target_link.sha256_cert_fingerprint())
                )
            }
        }
    }
}

/// A `Client` represents a Webauthn client. Users of this struct should supply a
/// [`CredentialStore`], a [`UserValidationMethod`] and, optionally, an implementation of
/// [`public_suffix::EffectiveTLDProvider`].
///
/// The `tld_provider` is used to verify effective Top-Level Domains for request origins presented
/// to the client. Most applications can use the `new()` function, which creates a `Client` with a
/// default provider implementation. Use `new_with_custom_tld_provider()` to provide a custom
/// `EffectiveTLDProvider` if your application needs to interpret eTLDs differently from the Mozilla
/// Public Suffix List.
pub struct Client<S, U, P, F>
where
    S: CredentialStore + Sync,
    U: UserValidationMethod + Sync,
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
{
    authenticator: Authenticator<S, U>,
    rp_id_verifier: RpIdVerifier<P, F>,
}

impl<S, U> Client<S, U, public_suffix::PublicSuffixList, ()>
where
    S: CredentialStore + Sync,
    U: UserValidationMethod + Sync,
    Passkey: TryFrom<<S as CredentialStore>::PasskeyItem>,
{
    /// Create a `Client` with a given `Authenticator` that uses the default
    /// TLD verifier provided by `[public_suffix]`.
    pub fn new(authenticator: Authenticator<S, U>) -> Self {
        Self {
            authenticator,
            rp_id_verifier: RpIdVerifier::new(public_suffix::DEFAULT_PROVIDER, None),
        }
    }
}

impl<S, U, P, F> Client<S, U, P, F>
where
    S: CredentialStore + Sync,
    U: UserValidationMethod<PasskeyItem = <S as CredentialStore>::PasskeyItem> + Sync,
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
    F: Fetcher + Sync,
{
    /// Create a `Client` with a given `Authenticator` and a custom TLD provider
    /// that implements `[public_suffix::EffectiveTLDProvider]`.
    pub fn new_with_custom_tld_provider(
        authenticator: Authenticator<S, U>,
        custom_provider: P,
        fetcher: Option<F>,
    ) -> Self {
        Self {
            authenticator,
            rp_id_verifier: RpIdVerifier::new(custom_provider, fetcher),
        }
    }

    /// Allows the internal [RpIdVerifier] to pass through localhost requests.
    pub fn allows_insecure_localhost(mut self, is_allowed: bool) -> Self {
        self.rp_id_verifier = self.rp_id_verifier.allows_insecure_localhost(is_allowed);
        self
    }

    /// Read access to the Client's `Authenticator`.
    pub fn authenticator(&self) -> &Authenticator<S, U> {
        &self.authenticator
    }

    /// Write access to the Client's `Authenticator`.
    pub fn authenticator_mut(&mut self) -> &mut Authenticator<S, U> {
        &mut self.authenticator
    }

    /// Register a webauthn `request` from the given `origin`.
    ///
    /// Returns either a [`webauthn::CreatedPublicKeyCredential`] on success or some [`WebauthnError`]
    pub async fn register<D: ClientData<E>, E: Serialize + Clone>(
        &mut self,
        origin: impl Into<Origin<'_>>,
        request: webauthn::CredentialCreationOptions,
        client_data: D,
    ) -> Result<webauthn::CreatedPublicKeyCredential, WebauthnError> {
        let origin = origin.into();

        // extract inner value of request as there is nothing else of value directly in CredentialCreationOptions
        let request = request.public_key;
        let auth_info = self.authenticator.get_info().await;

        let pub_key_cred_params = if request.pub_key_cred_params.is_empty() {
            webauthn::PublicKeyCredentialParameters::default_algorithms()
        } else {
            request.pub_key_cred_params
        };
        // TODO: Handle given timeout here, If the value is not within what we consider a reasonable range
        // override to our default
        // let timeout = request
        //     .timeout
        //     .map(|t| t.clamp(MIN_TIMEOUT, MAX_TIMEOUT))
        //     .unwrap_or(MAX_TIMEOUT);

        let rp_id = self
            .rp_id_verifier
            .assert_domain(&origin, request.rp.id.as_deref())
            .await?;

        let collected_client_data = webauthn::CollectedClientData::<E> {
            ty: webauthn::ClientDataType::Create,
            challenge: encoding::base64url(&request.challenge),
            origin: origin.to_string(),
            cross_origin: None,
            extra_data: client_data.extra_client_data(),
            unknown_keys: Default::default(),
        };

        // SAFETY: it is a developer error if serializing this struct fails.
        let client_data_json = serde_json::to_string(&collected_client_data).unwrap();
        let client_data_json_hash = client_data
            .client_data_hash()
            .unwrap_or_else(|| sha256(client_data_json.as_bytes()).to_vec());

        let extension_request = request.extensions.and_then(|e| e.zip_contents());

        let ctap_extensions = self.registration_extension_ctap2_input(
            extension_request.as_ref(),
            auth_info.extensions.as_deref().unwrap_or_default(),
        )?;

        let rk = self.map_rk(&request.authenticator_selection, &auth_info);
        let uv = request.authenticator_selection.map(|s| s.user_verification)
            != Some(UserVerificationRequirement::Discouraged);

        let ctap2_response = self
            .authenticator
            .make_credential(ctap2::make_credential::Request {
                client_data_hash: client_data_json_hash.into(),
                rp: ctap2::make_credential::PublicKeyCredentialRpEntity {
                    id: rp_id.to_owned(),
                    name: Some(request.rp.name),
                },
                user: request.user,
                pub_key_cred_params,
                exclude_list: request.exclude_credentials,
                extensions: ctap_extensions,
                options: ctap2::make_credential::Options { rk, up: true, uv },
                pin_auth: None,
                pin_protocol: None,
            })
            .await
            .map_err(|sc| WebauthnError::AuthenticatorError(sc.into()))?;

        // SAFETY: this unwrap is safe because the ctap2_response was just created in make_credential()
        // above, which currently sets auth_data.attested_credential_data unconditionally.
        // If this fails, it's a programmer error in that the postconditions of make_credential will
        // have changed.
        let credential_id = ctap2_response
            .auth_data
            .attested_credential_data
            .as_ref()
            .unwrap();
        let alg = match credential_id.key.alg.as_ref().unwrap() {
            Algorithm::PrivateUse(val) => *val,
            Algorithm::Assigned(alg) => alg.to_i64(),
            Algorithm::Text(_) => {
                unreachable!()
            }
        };
        let public_key = Some(
            passkey_authenticator::public_key_der_from_cose_key(&credential_id.key)
                .map_err(|e| WebauthnError::AuthenticatorError(e.into()))?,
        );

        let attestation_object = ctap2_response.as_webauthn_bytes();
        let store_info = self.authenticator.store().get_info().await;
        let client_extension_results = self.registration_extension_outputs(
            extension_request.as_ref(),
            store_info,
            rk,
            ctap2_response.unsigned_extension_outputs,
        );

        let response = webauthn::CreatedPublicKeyCredential {
            id: encoding::base64url(credential_id.credential_id()),
            raw_id: credential_id.credential_id().to_vec().into(),
            ty: webauthn::PublicKeyCredentialType::PublicKey,
            response: webauthn::AuthenticatorAttestationResponse {
                client_data_json: Vec::from(client_data_json).into(),
                authenticator_data: ctap2_response.auth_data.to_vec().into(),
                public_key,
                public_key_algorithm: alg,
                attestation_object,
                transports: auth_info.transports,
            },
            authenticator_attachment: Some(self.authenticator().attachment_type()),
            client_extension_results,
        };

        Ok(response)
    }

    /// Authenticate a Webauthn request.
    ///
    /// Returns either an [`webauthn::AuthenticatedPublicKeyCredential`] on success or some [`WebauthnError`].
    pub async fn authenticate<D: ClientData<E>, E: Serialize + Clone>(
        &mut self,
        origin: impl Into<Origin<'_>>,
        request: webauthn::CredentialRequestOptions,
        client_data: D,
    ) -> Result<webauthn::AuthenticatedPublicKeyCredential, WebauthnError> {
        let origin = origin.into();

        // extract inner value of request as there is nothing else of value directly in CredentialRequestOptions
        let request = request.public_key;
        let auth_info = self.authenticator().get_info().await;

        // TODO: Handle given timeout here, If the value is not within what we consider a reasonable range
        // override to our default
        // let timeout = request
        //     .timeout
        //     .map(|t| t.clamp(MIN_TIMEOUT, MAX_TIMEOUT))
        //     .unwrap_or(MAX_TIMEOUT);

        let rp_id = self
            .rp_id_verifier
            .assert_domain(&origin, request.rp_id.as_deref())
            .await?;

        let collected_client_data = webauthn::CollectedClientData::<E> {
            ty: webauthn::ClientDataType::Get,
            challenge: encoding::base64url(&request.challenge),
            origin: origin.to_string(),
            cross_origin: None, //Some(false),
            extra_data: client_data.extra_client_data(),
            unknown_keys: Default::default(),
        };

        // SAFETY: it is a developer error if serializing this struct fails.
        let client_data_json = serde_json::to_string(&collected_client_data).unwrap();
        let client_data_json_hash = client_data
            .client_data_hash()
            .unwrap_or_else(|| sha256(client_data_json.as_bytes()).to_vec());

        let ctap_extensions = self.auth_extension_ctap2_input(
            &request,
            auth_info.extensions.unwrap_or_default().as_slice(),
        )?;
        let rk = false;
        let uv = request.user_verification != UserVerificationRequirement::Discouraged;

        let ctap2_response = self
            .authenticator
            .get_assertion(ctap2::get_assertion::Request {
                rp_id: rp_id.to_owned(),
                client_data_hash: client_data_json_hash.into(),
                allow_list: request.allow_credentials,
                extensions: ctap_extensions,
                options: ctap2::get_assertion::Options { rk, up: true, uv },
                pin_auth: None,
                pin_protocol: None,
            })
            .await
            .map_err(Into::<WebauthnError>::into)?;

        let client_extension_results =
            self.auth_extension_outputs(ctap2_response.unsigned_extension_outputs);

        // SAFETY: This unwrap is safe because ctap2_response was created immedately
        // above and the postcondition of that function is that response.credential
        // will yield a credential. If none was found, we will have already returned
        // a WebauthnError::CredentialNotFound error from map_err in that line.
        let credential_id_bytes = ctap2_response.credential.unwrap().id;
        Ok(webauthn::AuthenticatedPublicKeyCredential {
            id: encoding::base64url(&credential_id_bytes),
            raw_id: credential_id_bytes.to_vec().into(),
            ty: webauthn::PublicKeyCredentialType::PublicKey,
            response: webauthn::AuthenticatorAssertionResponse {
                client_data_json: Vec::from(client_data_json).into(),
                authenticator_data: ctap2_response.auth_data.to_vec().into(),
                signature: ctap2_response.signature,
                user_handle: ctap2_response.user.map(|user| user.id),
                attestation_object: None,
            },
            authenticator_attachment: Some(self.authenticator().attachment_type()),
            client_extension_results,
        })
    }

    fn map_rk(
        &self,
        criteria: &Option<AuthenticatorSelectionCriteria>,
        auth_info: &ctap2::get_info::Response,
    ) -> bool {
        let supports_rk = auth_info.options.as_ref().is_some_and(|o| o.rk);

        match criteria.as_ref().unwrap_or(&Default::default()) {
            // > If pkOptions.authenticatorSelection.residentKey:
            // > is present and set to required
            AuthenticatorSelectionCriteria {
                resident_key: Some(ResidentKeyRequirement::Required),
                ..
            // > Let requireResidentKey be true.
            } => true,

            // > is present and set to preferred
            AuthenticatorSelectionCriteria {
                resident_key: Some(ResidentKeyRequirement::Preferred),
                ..
            // >  And the authenticator is capable of client-side credential storage modality
            //    > Let requireResidentKey be true.
            // >  And the authenticator is not capable of client-side credential storage modality, or if the client cannot determine authenticator capability,
            //    > Let requireResidentKey be false.
            } => supports_rk,

            // > is present and set to discouraged
            AuthenticatorSelectionCriteria {
                resident_key: Some(ResidentKeyRequirement::Discouraged),
                ..
            // > Let requireResidentKey be false.
            } => false,

            // > If pkOptions.authenticatorSelection.residentKey is not present
            AuthenticatorSelectionCriteria {
                resident_key: None,
                require_resident_key,
                ..
            // > Let requireResidentKey be the value of pkOptions.authenticatorSelection.requireResidentKey.
            } => *require_resident_key,
        }
    }
}
