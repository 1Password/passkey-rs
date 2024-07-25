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

use ciborium::{cbor, value::Value};
use coset::{iana::EnumI64, Algorithm};
use passkey_authenticator::{Authenticator, CredentialStore, UserValidationMethod};
use passkey_types::{
    crypto::sha256,
    ctap2, encoding,
    webauthn::{
        self, AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement,
    },
    Passkey,
};
use serde::Serialize;
use typeshare::typeshare;
use url::Url;

mod extensions;
mod quirks;
use quirks::QuirkyRp;

#[cfg(feature = "android-asset-validation")]
mod android;

#[cfg(feature = "android-asset-validation")]
pub use self::android::{valid_fingerprint, UnverifiedAssetLink, ValidationError};

#[cfg(test)]
mod tests;

#[typeshare]
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

/// Returns a decoded [String] if the domain name is punycode otherwise
/// the original string reference [str] is returned.
fn decode_host(host: &str) -> Option<Cow<str>> {
    if host.split('.').any(|s| s.starts_with("xn--")) {
        let (decoded, result) = idna::domain_to_unicode(host);
        result.ok().map(|_| Cow::from(decoded))
    } else {
        Some(Cow::from(host))
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
pub struct Client<S, U, P>
where
    S: CredentialStore + Sync,
    U: UserValidationMethod + Sync,
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
    Passkey: TryFrom<<S as CredentialStore>::PasskeyItem>,
{
    authenticator: Authenticator<S, U>,
    rp_id_verifier: RpIdVerifier<P>,
}

impl<S, U> Client<S, U, public_suffix::PublicSuffixList>
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
            rp_id_verifier: RpIdVerifier::new(public_suffix::DEFAULT_PROVIDER),
        }
    }
}

impl<S, U, P> Client<S, U, P>
where
    S: CredentialStore + Sync,
    U: UserValidationMethod<PasskeyItem = <S as CredentialStore>::PasskeyItem> + Sync,
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
    Passkey: TryFrom<<S as CredentialStore>::PasskeyItem>,
{
    /// Create a `Client` with a given `Authenticator` and a custom TLD provider
    /// that implements `[public_suffix::EffectiveTLDProvider]`.
    pub fn new_with_custom_tld_provider(
        authenticator: Authenticator<S, U>,
        custom_provider: P,
    ) -> Self {
        Self {
            authenticator,
            rp_id_verifier: RpIdVerifier::new(custom_provider),
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
            .assert_domain(&origin, request.rp.id.as_deref())?;

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

        let mut attestation_object = Vec::with_capacity(128);
        // SAFETY: The Results here are from serializing all the internals of `cbor!` into `ciborium::Value`
        // then serializing said value to bytes. The unwraps here are safe because it would otherwise be
        // programmer error.
        // TODO: Create strong attestation type definitions, part of CTAP2
        let attestation_object_value = cbor!({
               // TODO: Follow preference and/or implement AnonCA https://w3c.github.io/webauthn/#anonymization-ca
               "fmt" => "none",
                "attStmt" => {},
                // Explicitly define these fields as bytes since specialization is still fairly far
               "authData" => Value::Bytes(ctap2_response.auth_data.to_vec()),
        })
        .unwrap();
        ciborium::ser::into_writer(&attestation_object_value, &mut attestation_object).unwrap();

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
                attestation_object: attestation_object.into(),
                transports: auth_info.transports,
            },
            authenticator_attachment: Some(self.authenticator().attachment_type()),
            client_extension_results,
        };

        // Sanitize output before sending it back to the RP
        let maybe_quirky_rp = QuirkyRp::from_rp_id(rp_id);
        Ok(maybe_quirky_rp.map_create_credential(response))
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
            .assert_domain(&origin, request.rp_id.as_deref())?;

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

/// Wrapper struct for verifying that a given RpId matches the request's origin.
///
/// While most cases should not use this type directly and instead use [`Client`], there are some
/// cases that warrant the need for checking an RpId in the same way that the client does, but without
/// the rest of pieces that the client needs.
pub struct RpIdVerifier<P> {
    tld_provider: Box<P>,
    allows_insecure_localhost: bool,
}

impl<P> RpIdVerifier<P>
where
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
{
    /// Create a new Verifier with a given TLD provider. Most cases should just use
    /// [`public_suffix::DEFAULT_PROVIDER`].
    pub fn new(tld_provider: P) -> Self {
        Self {
            tld_provider: Box::new(tld_provider),
            allows_insecure_localhost: false,
        }
    }

    /// Allows [`RpIdVerifier::assert_domain`] to pass through requests from `localhost`
    pub fn allows_insecure_localhost(mut self, is_allowed: bool) -> Self {
        self.allows_insecure_localhost = is_allowed;
        self
    }

    /// Parse the given Relying Party Id and verify it against the origin url of the request.
    ///
    /// This follows the steps defined in: <https://html.spec.whatwg.org/multipage/browsers.html#is-a-registrable-domain-suffix-of-or-is-equal-to>
    ///
    /// Returns the effective domain on success or some [`WebauthnError`]
    pub fn assert_domain<'a>(
        &self,
        origin: &'a Origin,
        rp_id: Option<&'a str>,
    ) -> Result<&'a str, WebauthnError> {
        match origin {
            Origin::Web(url) => self.assert_web_rp_id(url, rp_id),
            #[cfg(feature = "android-asset-validation")]
            Origin::Android(unverified) => self.assert_android_rp_id(unverified, rp_id),
        }
    }

    fn assert_web_rp_id<'a>(
        &self,
        origin: &'a Url,
        rp_id: Option<&'a str>,
    ) -> Result<&'a str, WebauthnError> {
        let mut effective_domain = origin.domain().ok_or(WebauthnError::OriginMissingDomain)?;

        if let Some(rp_id) = rp_id {
            if !effective_domain.ends_with(rp_id) {
                return Err(WebauthnError::OriginRpMissmatch);
            }

            effective_domain = rp_id;
        }

        // guard against localhost effective domain, return early
        if effective_domain == "localhost" {
            return if self.allows_insecure_localhost {
                Ok(effective_domain)
            } else {
                Err(WebauthnError::InsecureLocalhostNotAllowed)
            };
        }

        // Make sure origin uses https://
        if !(origin.scheme().eq_ignore_ascii_case("https")) {
            return Err(WebauthnError::UnprotectedOrigin);
        }

        // assert rp_id is not part of the public suffix list and is a registerable domain.
        if decode_host(effective_domain)
            .as_ref()
            .and_then(|s| self.tld_provider.effective_tld_plus_one(s).ok())
            .is_none()
        {
            return Err(WebauthnError::InvalidRpId);
        }

        Ok(effective_domain)
    }

    #[cfg(feature = "android-asset-validation")]
    fn assert_android_rp_id<'a>(
        &self,
        target_link: &'a UnverifiedAssetLink,
        rp_id: Option<&'a str>,
    ) -> Result<&'a str, WebauthnError> {
        let mut effective_rp_id = target_link.host();

        if let Some(rp_id) = rp_id {
            // subset from assert_web_rp_id
            if !effective_rp_id.ends_with(rp_id) {
                return Err(WebauthnError::OriginRpMissmatch);
            }
            effective_rp_id = rp_id;
        }

        if decode_host(effective_rp_id)
            .as_ref()
            .and_then(|s| self.tld_provider.effective_tld_plus_one(s).ok())
            .is_none()
        {
            return Err(WebauthnError::InvalidRpId);
        }

        // TODO: Find an ergonomic and caching friendly way to fetch the remote
        // assetlinks and validate them here.
        // https://github.com/1Password/passkey-rs/issues/13

        Ok(effective_rp_id)
    }
}

#[cfg(test)]
mod test {
    use passkey_authenticator::{Authenticator, MemoryStore, MockUserValidationMethod};
    use passkey_types::{
        ctap2,
        webauthn::{
            AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement,
        },
    };

    use crate::Client;

    #[test]
    fn map_rk_maps_criteria_to_rk_bool() {
        #[derive(Debug)]
        struct TestCase {
            resident_key: Option<ResidentKeyRequirement>,
            require_resident_key: bool,
            expected_rk: bool,
        }

        let test_cases = vec![
            // require_resident_key fallbacks
            TestCase {
                resident_key: None,
                require_resident_key: false,
                expected_rk: false,
            },
            TestCase {
                resident_key: None,
                require_resident_key: true,
                expected_rk: true,
            },
            // resident_key values
            TestCase {
                resident_key: Some(ResidentKeyRequirement::Discouraged),
                require_resident_key: false,
                expected_rk: false,
            },
            TestCase {
                resident_key: Some(ResidentKeyRequirement::Preferred),
                require_resident_key: false,
                expected_rk: true,
            },
            TestCase {
                resident_key: Some(ResidentKeyRequirement::Required),
                require_resident_key: false,
                expected_rk: true,
            },
            // resident_key overrides require_resident_key
            TestCase {
                resident_key: Some(ResidentKeyRequirement::Discouraged),
                require_resident_key: true,
                expected_rk: false,
            },
        ];

        for test_case in test_cases {
            let criteria = AuthenticatorSelectionCriteria {
                resident_key: test_case.resident_key,
                require_resident_key: test_case.require_resident_key,
                user_verification: UserVerificationRequirement::Discouraged,
                authenticator_attachment: None,
            };
            let auth_info = ctap2::get_info::Response {
                versions: vec![],
                extensions: None,
                aaguid: ctap2::Aaguid::new_empty(),
                options: Some(ctap2::get_info::Options {
                    rk: true,
                    uv: Some(true),
                    up: true,
                    plat: true,
                    client_pin: None,
                }),
                max_msg_size: None,
                pin_protocols: None,
                transports: None,
            };
            let client = Client::new(Authenticator::new(
                ctap2::Aaguid::new_empty(),
                MemoryStore::new(),
                MockUserValidationMethod::verified_user(0),
            ));

            let result = client.map_rk(&Some(criteria), &auth_info);

            assert_eq!(result, test_case.expected_rk, "{:?}", test_case);
        }
    }
}
