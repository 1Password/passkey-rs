use coset::{Algorithm, iana::EnumI64};
use passkey_authenticator::public_key_der_from_cose_key;
use passkey_types::{
    ctap2::{AuthenticatorData, Ctap2Error, U2FError},
    encoding,
    webauthn::{
        self, AuthenticationExtensionsClientOutputs, AuthenticatorTransport,
        CredentialPropertiesOutput,
    },
};
use serde::Serialize;

use crate::{ClientData, Origin, RpIdVerifier, WebauthnError};
use windows::Win32::{Foundation::HWND, Networking::WindowsWebServices::{
    WebAuthNAuthenticatorMakeCredential, WebAuthNGetErrorName, WEBAUTHN_CLIENT_DATA, WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS, WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_CTAP_TRANSPORT_BLE, WEBAUTHN_CTAP_TRANSPORT_HYBRID, WEBAUTHN_CTAP_TRANSPORT_INTERNAL, WEBAUTHN_CTAP_TRANSPORT_NFC, WEBAUTHN_CTAP_TRANSPORT_USB, WEBAUTHN_HASH_ALGORITHM_SHA_256, WEBAUTHN_RP_ENTITY_INFORMATION, WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, WEBAUTHN_USER_ENTITY_INFORMATION, WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION
}, UI::WindowsAndMessaging::GetForegroundWindow};
use windows_strings::{HSTRING, PCWSTR};

fn win_api_ctap_transport_mask_to_transports(flags: u32) -> Vec<AuthenticatorTransport> {
    let mut transports = Vec::new();
    if flags & WEBAUTHN_CTAP_TRANSPORT_USB != 0{
        transports.push(AuthenticatorTransport::Usb);
    }
    if flags & WEBAUTHN_CTAP_TRANSPORT_NFC != 0 {
        transports.push(AuthenticatorTransport::Nfc);
    }
    if flags & WEBAUTHN_CTAP_TRANSPORT_BLE != 0 {
        transports.push(AuthenticatorTransport::Ble);
    }
    if flags & WEBAUTHN_CTAP_TRANSPORT_INTERNAL != 0 {
        transports.push(AuthenticatorTransport::Internal);
    }
    if flags & WEBAUTHN_CTAP_TRANSPORT_HYBRID != 0 {
        transports.push(AuthenticatorTransport::Hybrid);
    }
    transports
}

pub struct WindowsClient<P, F> {
    hwnd: HWND,
    rp_id_verifier: RpIdVerifier<P, F>,
}

impl WindowsClient<public_suffix::PublicSuffixList, ()> {
    pub fn new() -> Self {
        Self {
            hwnd: unsafe { GetForegroundWindow() },
            rp_id_verifier: RpIdVerifier::new(public_suffix::DEFAULT_PROVIDER, None),
        }
    }

    pub async fn register<D: ClientData<E>, E: Serialize + Clone>(
        &mut self,
        origin: impl Into<Origin<'_>>,
        request: webauthn::CredentialCreationOptions,
        client_data: D,
    ) -> Result<webauthn::CreatedPublicKeyCredential, WebauthnError> {
        let origin = origin.into();

        // extract inner value of request as there is nothing else of value directly in CredentialCreationOptions
        let mut request = request.public_key;

        // Client-side extension processing: we mirror `Client::registration_extension_outputs`
        // for the parts we can already answer without wiring extension inputs into the Windows
        // call. Right now that's just `credProps` — see the comment on `client_extension_results`
        // below for the rest.
        let cred_props_requested = request
            .extensions
            .as_ref()
            .and_then(|ext| ext.cred_props)
            == Some(true);

        let rp_id = self
            .rp_id_verifier
            .assert_domain(&origin, request.rp.id.as_deref())
            .await?;

        let rp_info = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: PCWSTR::from_raw(HSTRING::from(rp_id).as_ptr()),
            pwszName: PCWSTR::from_raw(HSTRING::from(request.rp.name).as_ptr()),
            pwszIcon: PCWSTR::null(),
        };

        let user_info = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: request.user.id.len() as u32,
            pbId: request.user.id.as_mut_ptr(),
            pwszName: PCWSTR::from_raw(HSTRING::from(request.user.name).as_ptr()),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: PCWSTR::from_raw(HSTRING::from(request.user.display_name).as_ptr()),
        };

        let collected_client_data = webauthn::CollectedClientData::<E> {
            ty: webauthn::ClientDataType::Get,
            challenge: encoding::base64url(&request.challenge),
            origin: origin.to_string(),
            cross_origin: None, //Some(false),
            extra_data: client_data.extra_client_data(),
            unknown_keys: Default::default(),
        };

        let mut client_data_json = serde_json::to_string(&collected_client_data)
            .map_err(|_| WebauthnError::SerializationError)?;

        let client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_data_json.len() as u32,
            pbClientDataJSON: client_data_json.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        let mut credential_params_vec = request.pub_key_cred_params.iter().map(|e| {
            WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
                dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                // TODO: should algorithms that aren't explicitly listed in `webauthn.h` be
                // filtered out?
                lAlg: e.alg as i32,
            }
        }).collect::<Vec<_>>();

        let credential_params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: credential_params_vec.len() as u32,
            pCredentialParameters: credential_params_vec.as_mut_ptr(),
        };

        let make_credential_result = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                self.hwnd,
                &rp_info,
                &user_info,
                &credential_params,
                &client_data,
                None
            )
        };
        match make_credential_result {
            Ok(attestation) => {
                let credential_id: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        (*attestation).pbCredentialId as *const u8,
                        // SAFETY: never fails because usize is always >= 32 bits on Windows
                        (*attestation).cbCredentialId.try_into().unwrap(),
                    )
                };
                let authenticator_data: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        (*attestation).pbAuthenticatorData as *const u8,
                        // SAFETY: never fails because usize is always >= 32 bits on Windows
                        (*attestation).cbAuthenticatorData.try_into().unwrap(),
                    )
                };
                let attestation_object: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        (*attestation).pbAttestationObject as *const u8,
                        // SAFETY: never fails because usize is always >= 32 bits on Windows
                        (*attestation).cbAttestationObject.try_into().unwrap(),
                    )
                };
                let transport_mask = unsafe {
                    (*attestation).dwUsedTransport
                };

                let parsed_auth_data = AuthenticatorData::from_slice(authenticator_data)
                    .map_err(|_| WebauthnError::ValidationError)?;
                let attested = parsed_auth_data
                    .attested_credential_data
                    .as_ref()
                    .ok_or(WebauthnError::ValidationError)?;
                let public_key_algorithm = match attested
                    .key
                    .alg
                    .as_ref()
                    .ok_or(WebauthnError::ValidationError)?
                {
                    Algorithm::PrivateUse(val) => *val,
                    Algorithm::Assigned(alg) => alg.to_i64(),
                    Algorithm::Text(_) => return Err(WebauthnError::ValidationError),
                };
                let public_key = public_key_der_from_cose_key(&attested.key).ok();

                // `credProps` is entirely client-derivable: if the RP asked for it, we report
                // whether the credential ended up discoverable. Windows tells us this directly
                // via `bResidentKey` on the attestation struct, so we don't need to inspect the
                // authenticator data or track the resolved `rk` value the way `Client::register`
                // does with `store_info.discoverability.is_passkey_discoverable(rk)`.
                let cred_props = cred_props_requested.then(|| CredentialPropertiesOutput {
                    discoverable: Some(unsafe { (*attestation).bResidentKey.as_bool() }),
                });

                Ok(webauthn::CreatedPublicKeyCredential {
                    id: unsafe {
                        std::str::from_utf8_unchecked(credential_id)
                    }.to_owned(),
                    raw_id: credential_id.to_vec().into(),
                    ty: webauthn::PublicKeyCredentialType::PublicKey,
                    response: webauthn::AuthenticatorAttestationResponse {
                        client_data_json: Vec::from(client_data_json).into(),
                        authenticator_data: authenticator_data.to_vec().into(),
                        public_key,
                        public_key_algorithm,
                        attestation_object: attestation_object.to_vec().into(),
                        // This should technically only return one transport
                        transports: Some(win_api_ctap_transport_mask_to_transports(transport_mask)),
                    },
                    // Windows WebAuthn API doesn't provide authenticator attachment.
                    authenticator_attachment: None,
                    // Only `credProps` is populated for now — see `Client::registration_extension_outputs`
                    // in lib.rs for the shape we're aiming to mirror.
                    //
                    // TODO: wire up authenticator-driven extensions (prf, credBlob, largeBlob,
                    // credProtect, minPinLength, hmac-secret, …). Doing so requires two pieces
                    // we don't have yet:
                    //
                    //   1. **Inputs.** Right now we pass `None` for `WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS`
                    //      at the WebAuthNAuthenticatorMakeCredential call site above, so Windows
                    //      never sees any extension requests. We'd need to translate
                    //      `request.extensions` (`AuthenticationExtensionsClientInputs`) into a
                    //      `WEBAUTHN_EXTENSIONS` array (plus `WEBAUTHN_HMAC_SECRET_SALT` for PRF
                    //      eval at registration time) and hang it off the options struct.
                    //
                    //   2. **Outputs.** With inputs plumbed, the following fields on the
                    //      returned `WEBAUTHN_CREDENTIAL_ATTESTATION` become meaningful:
                    //        - `bPrfEnabled` + `pHmacSecret` -> `AuthenticationExtensionsPrfOutputs`
                    //          (map first/second salt evaluations from `HmacSecret{First,Second}`).
                    //        - `bLargeBlobSupported`         -> largeBlob client output.
                    //        - `Extensions` array            -> untyped extension outputs
                    //          keyed by `WEBAUTHN_EXTENSIONS_IDENTIFIER_*` (credProtect, credBlob,
                    //          minPinLength). Some of these also surface inside authenticator data
                    //          and can be read there instead.
                    //        - `pbUnsignedExtensionOutputs`  -> CBOR blob of unsigned extension
                    //          outputs, analogous to `ctap2::make_credential::UnsignedExtensionOutputs`
                    //          that lib.rs already knows how to consume.
                    //
                    // Once both directions are in place, this block should look like
                    // `Client::registration_extension_outputs`: match on which extensions the RP
                    // requested and translate the Windows outputs into the corresponding
                    // `AuthenticationExtensionsClientOutputs` fields.
                    client_extension_results: AuthenticationExtensionsClientOutputs {
                        cred_props,
                        prf: None,
                    },
                })
            }
            Err(_) => {
                let err_string = unsafe {
                    // SAFETY: this string is guaranteed to be a valid UTF-16 string with one of the
                    // following values:
                    // "Success", "InvalidStateError", "ConstraintError",
                    // "NotSupportedError", "NotAllowedError", "UnknownError"
                    WebAuthNGetErrorName(make_credential_result.into()).to_string().unwrap()
                };

                Err(match err_string.as_ref() {
                    // NTE_EXISTS: a credential in excludeCredentials already exists on this
                    // authenticator. Closest CTAP2 analogue is CredentialExcluded.
                    "InvalidStateError" => {
                        WebauthnError::AuthenticatorError(Ctap2Error::CredentialExcluded.into())
                    }
                    // (ERROR_)NOT_SUPPORTED / NTE_TOKEN_KEYSET_STORAGE_FULL: the authenticator
                    // couldn't satisfy a requested option (rk, uv, alg, …). Closest CTAP2
                    // analogue is UnsupportedOption.
                    "ConstraintError" => {
                        WebauthnError::AuthenticatorError(Ctap2Error::UnsupportedOption.into())
                    }
                    // NTE_INVALID_PARAMETER: request itself isn't supported.
                    "NotSupportedError" => WebauthnError::NotSupportedError,
                    // Device not found / user cancelled / timeout. There is no shared HRESULT
                    // here so we can't split cancel vs. timeout; map to OperationDenied as the
                    // umbrella "operation was not permitted" case.
                    "NotAllowedError" => {
                        WebauthnError::AuthenticatorError(Ctap2Error::OperationDenied.into())
                    }
                    // Any other HRESULT — surface as an unspecified authenticator error rather
                    // than misclassifying it as "not supported".
                    "UnknownError" => WebauthnError::AuthenticatorError(U2FError::Other.into()),
                    // Unreachable because the Err branch should never return "Success"
                    "Success" => unreachable!(),
                    // Unreachable because the Windows API guarantees these are the only possible
                    // values for the error
                    _ => unreachable!(),
                })
            }
        }
    }
}
