//! Windows client for use with hardware authenticators. Uses the webauthn.dll API.

use std::{marker::PhantomData, time::Duration};

use passkey_crypto::{CryptoBackend, PublicKeyT, SecretKeyT, coset::Algorithm, iana::EnumI64};
use passkey_types::{
    Bytes,
    ctap2::{AuthenticatorData, Ctap2Error},
    encoding,
    webauthn::{
        self, AttestationConveyancePreference, AuthenticationExtensionsClientOutputs,
        AuthenticatorAttachment, AuthenticatorTransport, CredentialPropertiesOutput,
        ResidentKeyRequirement, UserVerificationRequirement,
    },
};
use serde::Serialize;

use crate::{ClientData, Fetcher, Origin, RpIdVerifier, WebauthnError};
use windows_sys::Win32::{
    Networking::WindowsWebServices::{
        WEBAUTHN_API_VERSION_1, WEBAUTHN_ASSERTION,
        WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT,
        WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT,
        WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
        WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
        WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
        WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4,
        WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
        WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3, WEBAUTHN_CLIENT_DATA,
        WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_COSE_CREDENTIAL_PARAMETER,
        WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
        WEBAUTHN_CREDENTIAL_ATTESTATION, WEBAUTHN_CREDENTIAL_EX,
        WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_LIST,
        WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_CTAP_TRANSPORT_BLE,
        WEBAUTHN_CTAP_TRANSPORT_INTERNAL, WEBAUTHN_CTAP_TRANSPORT_NFC, WEBAUTHN_CTAP_TRANSPORT_USB,
        WEBAUTHN_HASH_ALGORITHM_SHA_256, WEBAUTHN_RP_ENTITY_INFORMATION,
        WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, WEBAUTHN_USER_ENTITY_INFORMATION,
        WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
        WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
        WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED, WebAuthNAuthenticatorGetAssertion,
        WebAuthNAuthenticatorMakeCredential, WebAuthNCancelCurrentOperation, WebAuthNFreeAssertion,
        WebAuthNFreeCredentialAttestation, WebAuthNGetApiVersionNumber, WebAuthNGetCancellationId,
        WebAuthNGetErrorName,
    },
    UI::WindowsAndMessaging::GetForegroundWindow,
};
use windows_sys::core::{GUID, HRESULT, PCWSTR};

// Check that a high enough WebAuthn API version is supported.
fn check_webauthn_version() -> Result<(), WebauthnError> {
    // SAFETY: this method is always safe to call and has no invariants.
    let supported = unsafe { WebAuthNGetApiVersionNumber() } >= WEBAUTHN_API_VERSION_1;
    if !supported {
        return Err(WebauthnError::NotSupportedError);
    }
    Ok(())
}

/// Encode `s` as a null-terminated UTF-16 buffer suitable for use as a Windows
/// `PCWSTR`.
fn to_utf16_null_terminated(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a null-terminated wide string that Windows returned into an owned `String`.
///
/// # Safety
/// `p` must point to a null-terminated UTF-16 string that stays valid for the
/// duration of the call.
unsafe fn pcwstr_to_string(p: PCWSTR) -> String {
    let mut len = 0usize;
    // SAFETY: caller guarantees the buffer is null-terminated, so we will
    // encounter a 0 before walking off the end of the string.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: due to the previous computation, `p` is valid for `len` u16s.
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

fn get_cancellation_id() -> Result<GUID, WebauthnError> {
    // SAFETY: `GUID` is a plain 16-byte struct that is safe to zero-initialize.
    let mut id: GUID = unsafe { std::mem::zeroed() };
    // SAFETY: `id` is a properly aligned writable `GUID`; the API populates it on success.
    let hr = unsafe { WebAuthNGetCancellationId(&mut id) };
    if hr < 0 {
        return Err(WebauthnError::AuthenticatorError(Ctap2Error::Other.into()));
    }
    Ok(id)
}

// WEBAUTHN_API_VERSION_1 exposes only USB, NFC, BLE, and INTERNAL transports.
// HYBRID was added in WEBAUTHN_API_VERSION_6, so we do not handle it here.
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
            // HYBRID isn't available under WEBAUTHN_API_VERSION_1; skip it in the mask.
            AuthenticatorTransport::Hybrid => 0,
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
        AttestationConveyancePreference::Direct | AttestationConveyancePreference::Enterprise => {
            WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT
        }
    }
}

fn win_require_resident_key(sel: Option<&webauthn::AuthenticatorSelectionCriteria>) -> bool {
    match sel.and_then(|s| s.resident_key) {
        Some(ResidentKeyRequirement::Required) => true,
        Some(ResidentKeyRequirement::Preferred) | Some(ResidentKeyRequirement::Discouraged) => {
            false
        }
        // Fall back to `requireResidentKey` when `residentKey` is absent.
        None => sel.map(|s| s.require_resident_key).unwrap_or(false),
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
                cbId: u32::try_from(id_buf.len()).expect("credential IDs are at most 1023 bytes"),
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
            entries.iter_mut().map(std::ptr::from_mut).collect();

        let list = WEBAUTHN_CREDENTIAL_LIST {
            cCredentials: u32::try_from(ptrs.len())
                .expect("allow/exclude credential list length is bounded by the request payload"),
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
            std::ptr::from_mut(&mut self.list)
        } else {
            std::ptr::null_mut()
        }
    }
}

fn win_api_error_to_webauthn_error(hr: HRESULT) -> WebauthnError {
    // SAFETY: `WebAuthNGetErrorName` returns a static, NUL-terminated UTF-16 string owned by
    // webauthn.dll for the lifetime of the process. `pcwstr_to_string` copies out of it, so no
    // lifetime constraints escape this call. The returned value is guaranteed by the API to be
    // one of: "Success", "InvalidStateError", "ConstraintError", "NotSupportedError",
    // "NotAllowedError", or "UnknownError".
    let err_string = unsafe { pcwstr_to_string(WebAuthNGetErrorName(hr)) };

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
        "NotAllowedError" => WebauthnError::AuthenticatorError(Ctap2Error::OperationDenied.into()),
        // Any other HRESULT.
        "UnknownError" => WebauthnError::AuthenticatorError(Ctap2Error::Other.into()),
        // Successful result.
        "Success" => WebauthnError::AuthenticatorError(Ctap2Error::Ok.into()),
        // Technically unreachable because the Windows API guarantees these are the only possible
        // values for the error. We return Ctap2Error::Other for future compatibility.
        _ => WebauthnError::AuthenticatorError(Ctap2Error::Other.into()),
    }
}

/// A WebAuthn client that uses Windows' webauthn.dll to interface with authenticators.
///
/// The foreground window that the WebAuthn system modal is tied to is queried on every request
/// rather than captured at construction time, so the client works correctly even if the user's
/// active window changes between calls.
pub struct WindowsClient<C, P, F>
where
    C: CryptoBackend,
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
    F: Fetcher + Sync,
{
    rp_id_verifier: RpIdVerifier<P, F>,
    crypto: PhantomData<C>,
}

impl<C: CryptoBackend> Default for WindowsClient<C, public_suffix::PublicSuffixList, ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: CryptoBackend> WindowsClient<C, public_suffix::PublicSuffixList, ()> {
    /// Create a new `WindowsClient`.
    pub fn new() -> Self {
        Self {
            rp_id_verifier: RpIdVerifier::new(public_suffix::DEFAULT_PROVIDER, None),
            crypto: PhantomData,
        }
    }

    /// Register a credential.
    pub async fn register<D: ClientData<E>, E: Serialize + Clone>(
        &mut self,
        origin: impl Into<Origin<'_>>,
        request: webauthn::CredentialCreationOptions,
        client_data: D,
    ) -> Result<webauthn::CreatedPublicKeyCredential, WebauthnError> {
        check_webauthn_version()?;

        let origin = origin.into();

        // extract inner value of request as there is nothing else of value directly in CredentialCreationOptions
        let mut request = request.public_key;

        // Extension input processing: for now, we just do credProps.
        let cred_props_requested =
            request.extensions.as_ref().and_then(|ext| ext.cred_props) == Some(true);

        let rp_id = self
            .rp_id_verifier
            .assert_domain(&origin, request.rp.id.as_deref())
            .await?;

        let rp_id_wide = to_utf16_null_terminated(rp_id);
        let rp_name_wide = to_utf16_null_terminated(&request.rp.name);
        let user_name_wide = to_utf16_null_terminated(&request.user.name);
        let user_display_name_wide = to_utf16_null_terminated(&request.user.display_name);

        let timeout = request.timeout.unwrap_or(
            Duration::from_secs(120)
                .as_millis()
                .try_into()
                .expect("120_000 (120s in ms) fits in u32"),
        );

        let cancellation_id = get_cancellation_id()?;

        let rp_info = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: rp_id_wide.as_ptr(),
            pwszName: rp_name_wide.as_ptr(),
            pwszIcon: std::ptr::null(),
        };

        let user_info = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: u32::try_from(request.user.id.len())
                .expect("WebAuthn spec caps user id at 64 bytes"),
            pbId: request.user.id.as_mut_ptr(),
            pwszName: user_name_wide.as_ptr(),
            pwszIcon: std::ptr::null(),
            pwszDisplayName: user_display_name_wide.as_ptr(),
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
            cbClientDataJSON: u32::try_from(client_data_json.len())
                .expect("serialized client data JSON will never be u32::MAX bytes in practice"),
            pbClientDataJSON: client_data_json.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        let mut credential_params_vec = request
            .pub_key_cred_params
            .iter()
            .map(|e| {
                // TODO: should algorithms that aren't explicitly listed in `webauthn.h` be
                // filtered out?
                WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
                    dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                    pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                    lAlg: i32::try_from(e.alg.to_i64())
                        .expect("IANA-registered COSE algorithm identifiers all fit in i32"),
                }
            })
            .collect::<Vec<_>>();

        let credential_params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: u32::try_from(credential_params_vec.len())
                .expect("pub_key_cred_params list length is bounded by the request payload"),
            pCredentialParameters: credential_params_vec.as_mut_ptr(),
        };

        // Translate the Rust request into the Windows options struct. Any parameters not provided
        // in the Rust request are left at their default values.
        let sel = request.authenticator_selection.as_ref();
        let require_rk = win_require_resident_key(sel);
        let uv = win_uv(sel.map(|s| s.user_verification).unwrap_or_default());
        let mut exclude_list = WinCredentialList::from_descriptors(
            request.exclude_credentials.as_deref().unwrap_or(&[]),
        );

        // V3 is the highest sub-version of this struct available under WEBAUTHN_API_VERSION_1.
        let make_credential_options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3,
            dwTimeoutMilliseconds: request.timeout.unwrap_or(0),
            dwAuthenticatorAttachment: win_attachment(sel.and_then(|s| s.authenticator_attachment)),
            bRequireResidentKey: require_rk.into(),
            dwUserVerificationRequirement: uv,
            dwAttestationConveyancePreference: win_attestation_conveyance(request.attestation),
            pExcludeCredentialList: exclude_list.as_ptr(),
            // Zero-initialize the remaining fields because windows-sys < 0.61 doesn't implement
            // `Default` for this struct.
            // SAFETY: the struct is `#[repr(C)]` and every field is a plain scalar or pointer, so
            // an all-zero bit pattern is a valid initial value.
            ..unsafe { std::mem::zeroed() }
        };

        // TODO: Test and re-evaluate this in the future.
        // To test: Comment out the `thread::spawn` and see if Windows
        // closes the dialog after 2 minutes.
        // Windows will rarely respect the timeout provided, so we cancel it after our own timeout.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(timeout.into()));
            // SAFETY: `cancellation_id` was populated by `get_cancellation_id` above and is valid;
            // `WebAuthNCancelCurrentOperation` only reads from the pointer.
            unsafe { WebAuthNCancelCurrentOperation(&cancellation_id) };
        });

        let mut attestation: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = std::ptr::null_mut();
        // SAFETY: `GetForegroundWindow` is always safe to call; it has no preconditions and
        // returns a null HWND if no foreground window exists (which webauthn.dll rejects with a
        // regular error). All other input pointers passed to
        // `WebAuthNAuthenticatorMakeCredential` reference stack-allocated structs and their
        // owning buffers (`rp_info`, `user_info`, `credential_params`, `client_data`,
        // `make_credential_options`, and everything they transitively reference) that live until
        // after the call returns. The API is documented to only read from them for the duration
        // of the call. The output pointer `attestation` is a properly aligned `*mut *mut _`
        // writable location.
        let hr = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                GetForegroundWindow(),
                &rp_info,
                &user_info,
                &credential_params,
                &client_data,
                &make_credential_options,
                &mut attestation,
            )
        };
        if hr < 0 {
            return Err(win_api_error_to_webauthn_error(hr));
        }

        // Copy every field we care about out of the Windows-owned struct upfront so we can free
        // it before any of the fallible parsing below runs.
        //
        // SAFETY: on success, Windows guarantees `attestation` is a valid, non-null pointer to a
        // `WEBAUTHN_CREDENTIAL_ATTESTATION` whose `pb*` byte buffers are of length `cb*` bytes,
        // and live until we hand the struct back via `WebAuthNFreeCredentialAttestation`.
        let credential_id_bytes: Vec<u8> = unsafe {
            std::slice::from_raw_parts(
                (*attestation).pbCredentialId.cast_const(),
                (*attestation)
                    .cbCredentialId
                    .try_into()
                    .expect("usize is always >= 32 bits on Windows"),
            )
            .to_vec()
        };
        // SAFETY: see the safety comment on `credential_id_bytes` above.
        let authenticator_data_bytes: Vec<u8> = unsafe {
            std::slice::from_raw_parts(
                (*attestation).pbAuthenticatorData.cast_const(),
                (*attestation)
                    .cbAuthenticatorData
                    .try_into()
                    .expect("usize is always >= 32 bits on Windows"),
            )
            .to_vec()
        };
        // SAFETY: see the safety comment on `credential_id_bytes` above.
        let attestation_object_bytes: Vec<u8> = unsafe {
            std::slice::from_raw_parts(
                (*attestation).pbAttestationObject.cast_const(),
                (*attestation)
                    .cbAttestationObject
                    .try_into()
                    .expect("usize is always >= 32 bits on Windows"),
            )
            .to_vec()
        };
        // SAFETY: `attestation` is a valid pointer for the reasons above; the `dwUsedTransport`
        // field is a plain scalar owned by the Windows-allocated struct.
        let transport_mask = unsafe { (*attestation).dwUsedTransport };

        // We now own copies of everything we need. Free the attestation allocation before running
        // the parsing steps below, which can early-return via `?`.
        //
        // SAFETY: `attestation` was produced by `WebAuthNAuthenticatorMakeCredential` above and
        // has not been freed yet, so passing it to `WebAuthNFreeCredentialAttestation` is the
        // documented way to release it. The pointer is not used again after this call.
        unsafe {
            WebAuthNFreeCredentialAttestation(attestation.cast_const());
        }

        let parsed_auth_data =
            AuthenticatorData::from_slice(&authenticator_data_bytes).map_err(|_| {
                WebauthnError::ValidationError {
                    context: "failed to parse authenticator data returned by webauthn.dll",
                }
            })?;
        let attested = parsed_auth_data.attested_credential_data.as_ref().ok_or(
            WebauthnError::ValidationError {
                context: "authenticator data from webauthn.dll is missing attested credential data",
            },
        )?;
        let public_key_algorithm =
            match attested
                .key
                .alg
                .as_ref()
                .ok_or(WebauthnError::ValidationError {
                    context: "COSE key from webauthn.dll is missing algorithm identifier",
                })? {
                Algorithm::PrivateUse(val) => *val,
                Algorithm::Assigned(alg) => alg.to_i64(),
                Algorithm::Text(_) => {
                    return Err(WebauthnError::ValidationError {
                        context: "COSE key from webauthn.dll has non-integer algorithm identifier",
                    });
                }
            };
        let public_key = <C::SecretKey as SecretKeyT>::PublicKey::der_from_cose_key(&attested.key)
            .ok()
            .map(Bytes::from);

        // This should only return one transport, since the mask is guaranteed by the API to only
        // have one bit set.
        let transports = win_api_ctap_transport_mask_to_transports(transport_mask);
        // Derive attachment from the transport: an internal authenticator transport indicates a
        // platform authenticator.
        let attachment = match transports.first() {
            Some(AuthenticatorTransport::Internal) => AuthenticatorAttachment::Platform,
            _ => AuthenticatorAttachment::CrossPlatform,
        };

        let cred_props =
            cred_props_requested.then_some(CredentialPropertiesOutput { discoverable: None });

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
                // This should technically only return one transport, since the mask is guaranteed
                // by the API to only have one bit set.
                transports: Some(win_api_ctap_transport_mask_to_transports(transport_mask)),
            },
            authenticator_attachment: Some(attachment),
            // TODO: Only `credProps` is populated for now. Eventually we aim to mirror
            // `Client::registration_extension_outputs` in lib.rs.
            client_extension_results: AuthenticationExtensionsClientOutputs {
                cred_props,
                prf: None,
            },
        })
    }

    /// Get assertion for a credential.
    pub async fn authenticate<D: ClientData<E>, E: Serialize + Clone>(
        &mut self,
        origin: impl Into<Origin<'_>>,
        request: webauthn::CredentialRequestOptions,
        client_data: D,
    ) -> Result<webauthn::AuthenticatedPublicKeyCredential, WebauthnError> {
        check_webauthn_version()?;

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
            cbClientDataJSON: u32::try_from(client_data_json.len())
                .expect("serialized client data JSON will never be u32::MAX bytes in practice"),
            pbClientDataJSON: client_data_json.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };

        let rp_id_wide = to_utf16_null_terminated(rp_id);

        let timeout = request.timeout.unwrap_or(
            Duration::from_secs(120)
                .as_millis()
                .try_into()
                .expect("120_000 (120s in ms) fits in u32"),
        );

        let cancellation_id = get_cancellation_id()?;

        // Translate the Rust request into the Windows options struct.
        let mut allow_list = WinCredentialList::from_descriptors(
            request.allow_credentials.as_deref().unwrap_or(&[]),
        );
        // V4 is the highest sub-version of this struct available under WEBAUTHN_API_VERSION_1.
        let get_assertion_options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4,
            dwTimeoutMilliseconds: timeout,
            // Attachment isn't specified in the getAssertion request.
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
            dwUserVerificationRequirement: win_uv(request.user_verification),
            pAllowCredentialList: allow_list.as_ptr(),
            // SAFETY: see the matching safety comment on `make_credential_options`.
            ..unsafe { std::mem::zeroed() }
        };

        // TODO: Test and re-evaluate this in the future.
        // To test: Comment out the `thread::spawn` and see if Windows
        // closes the dialog after 2 minutes.
        // Windows will rarely respect the timeout provided, so we cancel it after our own timeout.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(timeout.into()));
            // SAFETY: `cancellation_id` was populated by `get_cancellation_id` above and is valid;
            // `WebAuthNCancelCurrentOperation` only reads from the pointer.
            unsafe { WebAuthNCancelCurrentOperation(&cancellation_id) };
        });

        let mut assertion: *mut WEBAUTHN_ASSERTION = std::ptr::null_mut();
        // SAFETY: `GetForegroundWindow` is always safe to call; it has no preconditions and
        // returns a null HWND if no foreground window exists (which webauthn.dll rejects with a
        // regular error). All other input pointers passed to `WebAuthNAuthenticatorGetAssertion`
        // reference locals (`rp_id_wide`, `webauthn_client_data`, `get_assertion_options`, and
        // the buffers they point into) that live until after the call returns. The API is
        // documented to only read from them for the duration of the call. The output pointer
        // `assertion` is a properly aligned `*mut *mut _` writable location.
        let hr = unsafe {
            WebAuthNAuthenticatorGetAssertion(
                GetForegroundWindow(),
                rp_id_wide.as_ptr(),
                &webauthn_client_data,
                &get_assertion_options,
                &mut assertion,
            )
        };
        if hr < 0 {
            return Err(win_api_error_to_webauthn_error(hr));
        }

        // Copy every field we care about out of the Windows-owned struct upfront so we can free
        // it before building the response.
        //
        // SAFETY: on success, Windows guarantees `assertion` is a valid, non-null pointer to a
        // `WEBAUTHN_ASSERTION` whose `pb*` byte buffers are of length `cb*` bytes, and live until
        // we hand the struct back via `WebAuthNFreeAssertion`.
        let credential_id_bytes: Vec<u8> = unsafe {
            std::slice::from_raw_parts(
                (*assertion).Credential.pbId.cast_const(),
                (*assertion)
                    .Credential
                    .cbId
                    .try_into()
                    .expect("usize is always >= 32 bits on Windows"),
            )
            .to_vec()
        };
        // SAFETY: see the safety comment on `credential_id_bytes` above.
        let authenticator_data_bytes: Vec<u8> = unsafe {
            std::slice::from_raw_parts(
                (*assertion).pbAuthenticatorData.cast_const(),
                (*assertion)
                    .cbAuthenticatorData
                    .try_into()
                    .expect("usize is always >= 32 bits on Windows"),
            )
            .to_vec()
        };
        // SAFETY: see the safety comment on `credential_id_bytes` above.
        let signature_bytes: Vec<u8> = unsafe {
            std::slice::from_raw_parts(
                (*assertion).pbSignature.cast_const(),
                (*assertion)
                    .cbSignature
                    .try_into()
                    .expect("usize is always >= 32 bits on Windows"),
            )
            .to_vec()
        };
        // If `cbUserId` is zero, then `pbUserId` points to an empty string, so return `None` for
        // the `user_handle`.
        //
        // SAFETY: `assertion` is valid for the reasons above; `cbUserId` is a plain scalar owned
        // by the Windows-allocated struct.
        let user_id_len = unsafe { (*assertion).cbUserId };
        let user_handle_bytes: Option<Vec<u8>> = (user_id_len > 0).then(||
            // SAFETY: `pbUserId` points to `cbUserId` valid bytes for the lifetime of the
            // Windows-owned assertion.
            unsafe {
                std::slice::from_raw_parts(
                    (*assertion).pbUserId.cast_const(),
                    user_id_len
                        .try_into()
                        .expect("usize is always >= 32 bits on Windows"),
                )
                .to_vec()
            });

        // We now own copies of everything we need. Free the assertion allocation.
        //
        // SAFETY: `assertion` was produced by `WebAuthNAuthenticatorGetAssertion` above and has
        // not been freed yet, so passing it to `WebAuthNFreeAssertion` is the documented way to
        // release it. The pointer is not used again after this call.
        unsafe {
            WebAuthNFreeAssertion(assertion.cast_const());
        }

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
}
