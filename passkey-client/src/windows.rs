use std::time::Duration;

use coset::{Algorithm, iana::EnumI64};
use passkey_authenticator::public_key_der_from_cose_key;
use passkey_types::{
    ctap2::{AuthenticatorData, Ctap2Error, U2FError},
    encoding,
    webauthn::{
        self, AttestationConveyancePreference, AuthenticationExtensionsClientOutputs,
        AuthenticatorAttachment, AuthenticatorTransport, CredentialPropertiesOutput,
        ResidentKeyRequirement, UserVerificationRequirement,
    },
};
use serde::Serialize;

use crate::{ClientData, Origin, RpIdVerifier, WebauthnError};
use windows::Win32::{Foundation::HWND, Networking::WindowsWebServices::{
    WebAuthNAuthenticatorGetAssertion, WebAuthNAuthenticatorMakeCredential, WebAuthNCancelCurrentOperation, WebAuthNFreeAssertion, WebAuthNFreeCredentialAttestation, WebAuthNGetCancellationId, WebAuthNGetErrorName, WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT, WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT, WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION, WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION, WEBAUTHN_CLIENT_DATA, WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS, WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_EX, WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_LIST, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_CTAP_TRANSPORT_BLE, WEBAUTHN_CTAP_TRANSPORT_HYBRID, WEBAUTHN_CTAP_TRANSPORT_INTERNAL, WEBAUTHN_CTAP_TRANSPORT_NFC, WEBAUTHN_CTAP_TRANSPORT_USB, WEBAUTHN_ENTERPRISE_ATTESTATION_NONE, WEBAUTHN_ENTERPRISE_ATTESTATION_VENDOR_FACILITATED, WEBAUTHN_HASH_ALGORITHM_SHA_256, WEBAUTHN_RP_ENTITY_INFORMATION, WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, WEBAUTHN_USER_ENTITY_INFORMATION, WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION, WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED, WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED, WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
}, UI::WindowsAndMessaging::GetForegroundWindow};
use windows_strings::{HSTRING, PCWSTR};

fn win_api_ctap_transport_mask_to_transports(flags: u32) -> Vec<AuthenticatorTransport> {
    let mut transports = Vec::new();
    if flags & WEBAUTHN_CTAP_TRANSPORT_USB != 0 {
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

fn transports_to_win_api_ctap_mask(transports: &[AuthenticatorTransport]) -> u32 {
    let mut mask = 0u32;
    for t in transports {
        mask |= match t {
            AuthenticatorTransport::Usb => WEBAUTHN_CTAP_TRANSPORT_USB,
            AuthenticatorTransport::Nfc => WEBAUTHN_CTAP_TRANSPORT_NFC,
            AuthenticatorTransport::Ble => WEBAUTHN_CTAP_TRANSPORT_BLE,
            AuthenticatorTransport::Internal => WEBAUTHN_CTAP_TRANSPORT_INTERNAL,
            AuthenticatorTransport::Hybrid => WEBAUTHN_CTAP_TRANSPORT_HYBRID,
        };
    }
    mask
}

fn win_attachment(a: Option<AuthenticatorAttachment>) -> u32 {
    match a {
        None => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
        Some(AuthenticatorAttachment::Platform) => WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
        Some(AuthenticatorAttachment::CrossPlatform) => {
            WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM
        }
    }
}

fn win_uv(uv: UserVerificationRequirement) -> u32 {
    match uv {
        UserVerificationRequirement::Required => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        UserVerificationRequirement::Preferred => WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
        UserVerificationRequirement::Discouraged => {
            WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
        }
    }
}

fn win_attestation_conveyance(a: AttestationConveyancePreference) -> u32 {
    match a {
        AttestationConveyancePreference::None => WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        AttestationConveyancePreference::Indirect => {
            WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT
        }
        // Enterprise still requests a direct attestation conveyance preference. The
        // enterprise-specific bit is passed separately via `dwEnterpriseAttestation`.
        AttestationConveyancePreference::Direct | AttestationConveyancePreference::Enterprise => {
            WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
        }
    }
}

fn win_enterprise_attestation(a: AttestationConveyancePreference) -> u32 {
    match a {
        AttestationConveyancePreference::Enterprise => {
            WEBAUTHN_ENTERPRISE_ATTESTATION_VENDOR_FACILITATED
        }
        _ => WEBAUTHN_ENTERPRISE_ATTESTATION_NONE,
    }
}

/// Resolve WebAuthn resident-key requirements into the two BOOLs the Windows
/// options struct exposes. `bPreferResidentKey` overrides `bRequireResidentKey`
/// when both are set, so `Preferred` uses only the "prefer" bit.
fn win_resident_key_bools(sel: Option<&webauthn::AuthenticatorSelectionCriteria>) -> (bool, bool) {
    match sel.and_then(|s| s.resident_key) {
        Some(ResidentKeyRequirement::Required) => (true, false),
        Some(ResidentKeyRequirement::Preferred) => (false, true),
        Some(ResidentKeyRequirement::Discouraged) => (false, false),
        // Fall back to `requireResidentKey` when `residentKey` is absent.
        None => (
            sel.map(|s| s.require_resident_key).unwrap_or(false),
            false,
        ),
    }
}

/// Backing storage for a `WEBAUTHN_CREDENTIAL_LIST` populated from Rust
/// [`webauthn::PublicKeyCredentialDescriptor`]s.
///
/// The FFI structs hold raw pointers into the `Vec`s below, so everything must stay alive together
/// until the Windows API returns. Therefore we keep them in one owning struct.
struct WinCredentialList {
    /// The list handed to Windows. `ppCredentials` points into `_ptrs`.
    list: WEBAUTHN_CREDENTIAL_LIST,
    /// Array of pointers referenced by `list.ppCredentials`.
    _ptrs: Vec<*mut WEBAUTHN_CREDENTIAL_EX>,
    /// The credential entries pointed to by `_ptrs`. `pbId` points into `_id_bufs`.
    _entries: Vec<WEBAUTHN_CREDENTIAL_EX>,
    /// Owned credential ID byte buffers.
    _id_bufs: Vec<Vec<u8>>,
}

impl WinCredentialList {
    fn from_descriptors(descriptors: &[webauthn::PublicKeyCredentialDescriptor]) -> Self {
        let mut id_bufs: Vec<Vec<u8>> = descriptors.iter().map(|d| d.id.to_vec()).collect();

        let mut entries: Vec<WEBAUTHN_CREDENTIAL_EX> = id_bufs
            .iter_mut()
            .zip(descriptors.iter())
            .map(|(id_buf, d)| WEBAUTHN_CREDENTIAL_EX {
                dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
                cbId: id_buf.len() as u32,
                pbId: id_buf.as_mut_ptr(),
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                dwTransports: d
                    .transports
                    .as_deref()
                    .map(transports_to_win_api_ctap_mask)
                    .unwrap_or(0),
            })
            .collect();

        let mut ptrs: Vec<*mut WEBAUTHN_CREDENTIAL_EX> =
            entries.iter_mut().map(|e| e as *mut _).collect();

        let list = WEBAUTHN_CREDENTIAL_LIST {
            cCredentials: ptrs.len() as u32,
            ppCredentials: ptrs.as_mut_ptr(),
        };

        Self {
            list,
            _ptrs: ptrs,
            _entries: entries,
            _id_bufs: id_bufs,
        }
    }

    /// Raw pointer to the `WEBAUTHN_CREDENTIAL_LIST`, or null if the list is empty.
    /// Only valid while `self` is alive.
    fn as_ptr(&mut self) -> *mut WEBAUTHN_CREDENTIAL_LIST {
        if self.list.cCredentials > 0 {
            &mut self.list as *mut _
        } else {
            std::ptr::null_mut()
        }
    }
}

fn win_api_error_to_webauthn_error<T>(res: Result<T, windows::core::Error>) -> WebauthnError {
    let err_string = unsafe {
        // SAFETY: this string is guaranteed to be a valid UTF-16 string with one of the
        // following values:
        // "Success", "InvalidStateError", "ConstraintError",
        // "NotSupportedError", "NotAllowedError", "UnknownError"
        WebAuthNGetErrorName(res.into()).to_string().unwrap()
    };

    // Translate the Windows error messages into WebauthnError analogues (or the closest
    // error that exists).
    match err_string.as_ref() {
        // NTE_EXISTS: a credential in excludeCredentials already exists on this
        // authenticator. Closest CTAP2 analogue is CredentialExcluded.
        "InvalidStateError" => {
            WebauthnError::AuthenticatorError(Ctap2Error::CredentialExcluded.into())
        }
        // (ERROR_)NOT_SUPPORTED / NTE_TOKEN_KEYSET_STORAGE_FULL: the authenticator
        // couldn't satisfy a requested option. Closest CTAP2 analogue is
        // UnsupportedOption.
        "ConstraintError" => {
            WebauthnError::AuthenticatorError(Ctap2Error::UnsupportedOption.into())
        }
        // NTE_INVALID_PARAMETER: request itself isn't supported.
        "NotSupportedError" => WebauthnError::NotSupportedError,
        // Device not found / user cancelled / timeout. Map to OperationDenied as the
        // generic "operation not permitted" case.
        "NotAllowedError" => {
            WebauthnError::AuthenticatorError(Ctap2Error::OperationDenied.into())
        }
        // Any other HRESULT.
        "UnknownError" => WebauthnError::AuthenticatorError(U2FError::Other.into()),
        // Unreachable because the Err branch should never return "Success".
        "Success" => unreachable!(),
        // Unreachable because the Windows API guarantees these are the only possible
        // values for the error.
        _ => unreachable!(),
    }

}

/// A WebAuthn client that uses Windows' webauthn.dll to interface with authenticators.
pub struct WindowsClient<P, F> {
    hwnd: HWND,
    rp_id_verifier: RpIdVerifier<P, F>,
}

impl WindowsClient<public_suffix::PublicSuffixList, ()> {
    /// Create a new `WindowsClient` using the current foreground window as the parent window.
    pub fn new() -> Self {
        Self {
            hwnd: unsafe { GetForegroundWindow() },
            rp_id_verifier: RpIdVerifier::new(public_suffix::DEFAULT_PROVIDER, None),
        }
    }

    /// Register a credential.
    pub async fn register<D: ClientData<E>, E: Serialize + Clone>(
        &mut self,
        origin: impl Into<Origin<'_>>,
        request: webauthn::CredentialCreationOptions,
        client_data: D,
    ) -> Result<webauthn::CreatedPublicKeyCredential, WebauthnError> {
        let origin = origin.into();

        // extract inner value of request as there is nothing else of value directly in CredentialCreationOptions
        let mut request = request.public_key;

        // Extension input processing: for now, we just do credProps.
        let cred_props_requested = request
            .extensions
            .as_ref()
            .and_then(|ext| ext.cred_props)
            == Some(true);

        let rp_id = self
            .rp_id_verifier
            .assert_domain(&origin, request.rp.id.as_deref())
            .await?;

        let rp_id_hstring = HSTRING::from(rp_id);
        let rp_name_hstring = HSTRING::from(request.rp.name);
        let user_name_hstring = HSTRING::from(request.user.name);
        let user_display_name_hstring = HSTRING::from(request.user.display_name);

        let rp_info = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: PCWSTR::from_raw(rp_id_hstring.as_ptr()),
            pwszName: PCWSTR::from_raw(rp_name_hstring.as_ptr()),
            pwszIcon: PCWSTR::null(),
        };

        let user_info = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: request.user.id.len() as u32,
            pbId: request.user.id.as_mut_ptr(),
            pwszName: PCWSTR::from_raw(user_name_hstring.as_ptr()),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: PCWSTR::from_raw(user_display_name_hstring.as_ptr()),
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

        // Translate the Rust request into the Windows options struct. Any parameters not provided
        // in the Rust request are left at their default values.
        let sel = request.authenticator_selection.as_ref();
        let (require_rk, prefer_rk) = win_resident_key_bools(sel);
        let uv = win_uv(
            sel.map(|s| s.user_verification)
                .unwrap_or_default(),
        );
        let mut exclude_list =
            WinCredentialList::from_descriptors(request.exclude_credentials.as_deref().unwrap_or(&[]));

        let make_credential_options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: request.timeout.unwrap_or(0),
            dwAuthenticatorAttachment: win_attachment(sel.and_then(|s| s.authenticator_attachment)),
            bRequireResidentKey: require_rk.into(),
            bPreferResidentKey: prefer_rk.into(),
            dwUserVerificationRequirement: uv,
            dwAttestationConveyancePreference: win_attestation_conveyance(request.attestation),
            dwEnterpriseAttestation: win_enterprise_attestation(request.attestation),
            pExcludeCredentialList: exclude_list.as_ptr(),
            ..Default::default()
        };

        let make_credential_result = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                self.hwnd,
                &rp_info,
                &user_info,
                &credential_params,
                &client_data,
                Some(&make_credential_options as *const _),
            )
        };
        match make_credential_result {
            Ok(attestation) => {
                // Copy every field we care about out of the Windows-owned struct upfront so we can
                // free it before any of the fallible parsing below runs.
                let credential_id_bytes: Vec<u8> = unsafe {
                    std::slice::from_raw_parts(
                        (*attestation).pbCredentialId as *const u8,
                        // SAFETY: never fails because usize is always >= 32 bits on Windows
                        (*attestation).cbCredentialId.try_into().unwrap(),
                    )
                    .to_vec()
                };
                let authenticator_data_bytes: Vec<u8> = unsafe {
                    std::slice::from_raw_parts(
                        (*attestation).pbAuthenticatorData as *const u8,
                        // SAFETY: never fails because usize is always >= 32 bits on Windows
                        (*attestation).cbAuthenticatorData.try_into().unwrap(),
                    )
                    .to_vec()
                };
                let attestation_object_bytes: Vec<u8> = unsafe {
                    std::slice::from_raw_parts(
                        (*attestation).pbAttestationObject as *const u8,
                        // SAFETY: never fails because usize is always >= 32 bits on Windows
                        (*attestation).cbAttestationObject.try_into().unwrap(),
                    )
                    .to_vec()
                };
                let transport_mask = unsafe { (*attestation).dwUsedTransport };
                let is_resident_key = unsafe { (*attestation).bResidentKey.as_bool() };

                // We now own copies of everything we need. Free the attestation allocation before
                // running the parsing steps below, which can early-return via `?`.
                unsafe { WebAuthNFreeCredentialAttestation(Some(attestation as *const _)); }

                let parsed_auth_data = AuthenticatorData::from_slice(&authenticator_data_bytes)
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

                // The client can derive `credProps` by inspecting the `bResidentKey` field on the
                // attestation.
                let cred_props = cred_props_requested.then(|| CredentialPropertiesOutput {
                    discoverable: Some(is_resident_key),
                });

                Ok(webauthn::CreatedPublicKeyCredential {
                    id: encoding::base64url(&credential_id_bytes),
                    raw_id: credential_id_bytes.into(),
                    ty: webauthn::PublicKeyCredentialType::PublicKey,
                    response: webauthn::AuthenticatorAttestationResponse {
                        client_data_json: Vec::from(client_data_json).into(),
                        authenticator_data: authenticator_data_bytes.into(),
                        public_key,
                        public_key_algorithm,
                        attestation_object: attestation_object_bytes.into(),
                        // This should technically only return one transport, since the mask is
                        // guaranteed by the API to only have one bit set.
                        transports: Some(win_api_ctap_transport_mask_to_transports(transport_mask)),
                    },
                    // Windows WebAuthn API doesn't provide authenticator attachment.
                    authenticator_attachment: None,
                    // TODO: Only `credProps` is populated for now. Eventually we aim to mirror
                    // `Client::registration_extension_outputs` in lib.rs.
                    client_extension_results: AuthenticationExtensionsClientOutputs {
                        cred_props,
                        prf: None,
                    },
                })
            }
            Err(_) => Err(win_api_error_to_webauthn_error(make_credential_result))
        }
    }

    /// Get assertion for a credential.
    pub async fn authenticate<D: ClientData<E>, E: Serialize + Clone>(
        &mut self,
        origin: impl Into<Origin<'_>>,
        request: webauthn::CredentialRequestOptions,
        client_data: D,
    ) -> Result<webauthn::AuthenticatedPublicKeyCredential, WebauthnError> {
        let origin = origin.into();

        // extract inner value of request as there is nothing else of value directly in CredentialRequestOptions
        let request = request.public_key;

        let rp_id = self
            .rp_id_verifier
            .assert_domain(&origin, request.rp_id.as_deref())
            .await?;

        let collected_client_data = webauthn::CollectedClientData::<E> {
            ty: webauthn::ClientDataType::Get,
            challenge: encoding::base64url(&request.challenge),
            origin: origin.to_string(),
            cross_origin: None,
            extra_data: client_data.extra_client_data(),
            unknown_keys: Default::default(),
        };

        let mut client_data_json = serde_json::to_string(&collected_client_data)
            .map_err(|_| WebauthnError::SerializationError)?;

        let webauthn_client_data = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_data_json.len() as u32,
            pbClientDataJSON: client_data_json.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        let rp_id_wide = HSTRING::from(rp_id);

        let timeout = request.timeout.unwrap_or(Duration::from_secs(120).as_millis().try_into().unwrap());

        // Translate the Rust request into the Windows options struct.
        let mut allow_list =
            WinCredentialList::from_descriptors(request.allow_credentials.as_deref().unwrap_or(&[]));
        let get_assertion_options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
            dwTimeoutMilliseconds: timeout,
            // Attachment isn't specified in the getAssertion request.
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
            dwUserVerificationRequirement: win_uv(request.user_verification),
            pAllowCredentialList: allow_list.as_ptr(),
            ..Default::default()
        };

        let cancellation_id = {
            // SAFETY: `cancelation_id` is valid to write to and uses the correct type.
            let res = unsafe { WebAuthNGetCancellationId() };
            res.map_err(|_| WebauthnError::ValidationError)?
        };

        // TODO: Test and re-evaluate this in the future.
        // To test: Comment out the `thread::spawn` and see if Windows
        // closes the dialog after 2 minutes.
        // Windows will rarely respect the timeout provided, so we cancel it after our own timeout.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(timeout.into()));
            // SAFETY: `cancelation_id` is valid and can be used.
            unsafe { WebAuthNCancelCurrentOperation(&cancellation_id) }
        });

        let get_assertion_result = unsafe {
            WebAuthNAuthenticatorGetAssertion(
                self.hwnd,
                PCWSTR::from_raw(rp_id_wide.as_ptr()),
                &webauthn_client_data,
                Some(&get_assertion_options as *const _),
            )
        };

        match get_assertion_result {
            Ok(assertion) => {
                // Copy every field we care about out of the Windows-owned struct upfront so we can
                // free it before building the response.
                let credential_id_bytes: Vec<u8> = unsafe {
                    std::slice::from_raw_parts(
                        (*assertion).Credential.pbId as *const u8,
                        // SAFETY: never fails because usize is always >= 32 bits on Windows
                        (*assertion).Credential.cbId.try_into().unwrap(),
                    )
                    .to_vec()
                };
                let authenticator_data_bytes: Vec<u8> = unsafe {
                    std::slice::from_raw_parts(
                        (*assertion).pbAuthenticatorData as *const u8,
                        // SAFETY: never fails because usize is always >= 32 bits on Windows
                        (*assertion).cbAuthenticatorData.try_into().unwrap(),
                    )
                    .to_vec()
                };
                let signature_bytes: Vec<u8> = unsafe {
                    std::slice::from_raw_parts(
                        (*assertion).pbSignature as *const u8,
                        // SAFETY: never fails because usize is always >= 32 bits on Windows
                        (*assertion).cbSignature.try_into().unwrap(),
                    )
                    .to_vec()
                };
                // If `cbUserId` is zero, then `pbUserId` points to an empty string, so return
                // `None` for the `user_handle`.
                let user_id_len = unsafe { (*assertion).cbUserId };
                let user_handle_bytes: Option<Vec<u8>> = (user_id_len > 0).then(|| unsafe {
                    std::slice::from_raw_parts(
                        (*assertion).pbUserId as *const u8,
                        // SAFETY: never fails because usize is always >= 32 bits on Windows
                        user_id_len.try_into().unwrap(),
                    )
                    .to_vec()
                });

                // We now own copies of everything we need. Free the assertion allocation.
                unsafe { WebAuthNFreeAssertion(assertion as *const _); }

                Ok(webauthn::AuthenticatedPublicKeyCredential {
                    id: encoding::base64url(&credential_id_bytes),
                    raw_id: credential_id_bytes.into(),
                    ty: webauthn::PublicKeyCredentialType::PublicKey,
                    response: webauthn::AuthenticatorAssertionResponse {
                        client_data_json: Vec::from(client_data_json).into(),
                        authenticator_data: authenticator_data_bytes.into(),
                        signature: signature_bytes.into(),
                        user_handle: user_handle_bytes.map(Into::into),
                        attestation_object: None,
                    },
                    // Windows WebAuthn API doesn't provide authenticator attachment.
                    authenticator_attachment: None,
                    // TODO: same extension processing logic as `register`
                    client_extension_results: AuthenticationExtensionsClientOutputs::default(),
                })
            }
            Err(_) => Err(win_api_error_to_webauthn_error(get_assertion_result))
        }
    }
}
