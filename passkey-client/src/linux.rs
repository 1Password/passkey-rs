//! Multi-device USB HID WebAuthn client for Linux.
//!
//! [`LinuxClient`] wraps a set of [`LinuxAuthenticator`]s, one for each detected FIDO-compatible
//! HID device, and races a WebAuthn ceremony across all of them. Whichever security key the user
//! touches first wins; the rest receive a `CTAPHID_CANCEL` command so their in-flight transactions
//! are cancelled cleanly.
//!
//! Each per-device CTAP request is tailored to that device's capabilities (advertised in its cached
//! `authenticatorGetInfo` response). Algorithms that the device doesn't support are filtered out,
//! resident-key-incapable devices are skipped when an RP requires `rk`, and so on. Only the
//! response from the winning authenticator is returned.
//!
//! ## Usage
//!
//! ```ignore
//! use passkey_client::linux::LinuxClient;
//!
//! let mut client = LinuxClient::open_all().await?;
//! let created = client.register(origin, request, DefaultClientData).await?;
//! ```

use std::future::Future;

use coset::{Algorithm, iana::EnumI64};
use passkey_authenticator::linux::{LinuxAuthenticator, OpenError};
use passkey_authenticator::public_key_der_from_cose_key;
use passkey_types::crypto::{aes_256_cbc, hmac_sha256, sha256};
use passkey_types::ctap2::pin_uv_auth_protocol::PinUvAuthProtocolOne;
use passkey_types::Bytes;
use passkey_types::{
    ctap2, encoding,
    webauthn::{
        self, AuthenticatedPublicKeyCredential, AuthenticatorAssertionResponse,
        AuthenticatorAttachment, AuthenticatorAttestationResponse, ClientDataType,
        CreatedPublicKeyCredential, CredentialCreationOptions, CredentialRequestOptions,
        PublicKeyCredentialParameters, PublicKeyCredentialType,
    },
};
use serde::Serialize;
use tokio::task::JoinSet;

use crate::{
    ClientData, Fetcher, Origin, RpIdVerifier, WebauthnError, build_client_data, ctap_uv_option,
    map_rk,
};

/// Consumer-provided authenticator selection and PIN input prompts.
#[async_trait::async_trait]
pub trait PinPrompt: Send + Sync {
    /// Prompt user to provide User Presence to a particular authenticator to select it for use.
    /// Returning an error aborts the in-flight authenticator-selection race.
    async fn prompt_authenticator_selection(
        &self,
        num_authenticators: usize,
    ) -> Result<(), PinPromptError>;

    /// Prompt user to enter a PIN.
    async fn request_pin(&self, attempts_remaining: u32) -> Result<zeroize::Zeroizing<String>, PinPromptError>;
}

/// Error resulting from a prompt.
pub enum PinPromptError {
    /// PIN request was cancelled by the user.
    Cancelled,

    /// Any other error.
    Other(Box<dyn std::error::Error + Send + Sync>),
}

#[allow(clippy::enum_variant_names)]
enum GetPinUvAuthTokenOp {
    GetPinUvAuthTokenUsingUvWithPermissions,
    GetPinUvAuthTokenUsingPinWithPermissions,
    GetPinToken,
}

/// A WebAuthn client backed by zero or more USB security keys serving as authenticators.
pub struct LinuxClient<P, F>
where
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
    F: Fetcher + Sync,
{
    devices: Vec<LinuxAuthenticator>,
    rp_id_verifier: RpIdVerifier<P, F>,
    uv_when_preferred: bool,
    pin_prompt: Box<dyn PinPrompt>,
    // TODO: support multiple pin protocols
    pin_uv_auth_protocol_state: PinUvAuthProtocolOne,
}

#[derive(Clone)]
struct TokenWithProtocol {
    token: Bytes,
    protocol: u8,
}

fn get_pin_auth_and_protocol(token_with_protocol: Option<TokenWithProtocol>, client_data_hash: &[u8]) -> (Option<Bytes>, Option<u8>) {
        token_with_protocol
            .map(|e| (
                Some(Bytes::from(
                    &hmac_sha256(e.token.as_slice(), client_data_hash)[0..16],
                )),
                Some(e.protocol)
            ))
            .unwrap_or((None, None))
}


impl LinuxClient<public_suffix::PublicSuffixList, ()> {
    /// Build a `LinuxClient` over the supplied authenticators using the default public-suffix list
    /// TLD provider.
    pub fn new(authenticators: Vec<LinuxAuthenticator>, pin_prompt: Box<dyn PinPrompt>) -> Self {
        Self {
            devices: authenticators,
            rp_id_verifier: RpIdVerifier::new(public_suffix::DEFAULT_PROVIDER, None),
            uv_when_preferred: true,
            pin_prompt,
            pin_uv_auth_protocol_state: PinUvAuthProtocolOne::new(),
        }
    }

    /// Enumerate every FIDO-capable USB HID device on the system and open each
    /// one. Devices that fail to open are skipped silently.
    pub async fn open_all(pin_prompt: Box<dyn PinPrompt>) -> Result<Self, OpenError> {
        let infos = LinuxAuthenticator::list_devices()?;
        let mut authenticators = Vec::new();
        for info in infos {
            if let Ok(auth) = LinuxAuthenticator::open(&info.path).await {
                authenticators.push(auth);
            }
        }
        Ok(Self::new(authenticators, pin_prompt))
    }
}

impl<P, F> LinuxClient<P, F>
where
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
    F: Fetcher + Sync,
{
    /// Build a `LinuxClient` with a custom TLD provider and optional fetcher.
    pub fn new_with_custom_tld_provider(
        authenticators: Vec<LinuxAuthenticator>,
        custom_provider: P,
        fetcher: Option<F>,
        pin_prompt: Box<dyn PinPrompt>,
    ) -> Self {
        Self {
            devices: authenticators,
            rp_id_verifier: RpIdVerifier::new(custom_provider, fetcher),
            uv_when_preferred: true,
            pin_prompt,
            pin_uv_auth_protocol_state: PinUvAuthProtocolOne::new(),
        }
    }
}

impl<P, F> LinuxClient<P, F>
where
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
    F: Fetcher + Sync,
{
    /// Mirror of `Client::user_verification_when_preferred`.
    pub fn user_verification_when_preferred(mut self, enabled: bool) -> Self {
        self.uv_when_preferred = enabled;
        self
    }

    /// How many authenticators this client will dispatch to.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Return "valid" devices (devices that can be used for this combination of UV/PIN
    /// configuration). Invalid devices are left in self.devices.
    async fn get_valid_devices(
        &mut self,
        uv: bool,
        rp_id: &str,
    ) -> Result<Vec<(LinuxAuthenticator, Option<TokenWithProtocol>)>, WebauthnError> {
        let mut devices = std::mem::take(&mut self.devices);

        // Determine if any device has been configured to use built-in UV or a PIN.
        let any_device_requires_uv = devices
            .iter()
            .any(|device| 
                device.uv_configured() || device.pin_configured()
            );

        // We need to prompt the user to provide UV if the request requires user verification OR if
        // any device requires UV. In order to do this, we first need them to provide UP to an authenticator
        // to select it.
        let selected_devices = if uv || any_device_requires_uv {
            let mut selected_device = if devices.len() == 1 {
                devices.pop().unwrap()
            } else {
                let candidates = devices.into_iter().map(|e| (e, ())).collect();
                let RaceOutcome {
                    winner,
                    mut errors,
                    losers,
                } = race_request(candidates, |mut auth, _| async move {
                    let result = auth.inner.authenticator_selection().await;
                    (auth, result)
                })
                .await;

                // Put losers back into the devices list
                self.devices.extend(losers);
                if let Some((_, winning_device)) = winner {
                    winning_device
                } else {
                    return Err(WebauthnError::AuthenticatorError(errors.pop().unwrap_or(
                        ctap2::StatusCode::Ctap2(
                                ctap2::Ctap2Code::Known(ctap2::Ctap2Error::UserPresenceRequired)
                        )
                    ).into()));
                }
            };

            let selected_operation = if selected_device.uv_configured() {
                if selected_device.pin_uv_auth_token_supported() {
                    // Use UV
                    Some(GetPinUvAuthTokenOp::GetPinUvAuthTokenUsingUvWithPermissions)
                } else {
                    // Just set uv = true in request
                    // TODO: retry with PIN if we get error code 0x36
                    None
                }
            } else if selected_device.pin_configured() {
                if selected_device.pin_uv_auth_token_supported() {
                    // Use PIN
                    Some(GetPinUvAuthTokenOp::GetPinUvAuthTokenUsingPinWithPermissions)
                } else {
                    Some(GetPinUvAuthTokenOp::GetPinToken)
                }
            } else {
                // Dispatch request with no pinUvAuthToken to selected authenticator
                None
            };

            let token_with_protocol = self.get_auth_token_for_device(&mut selected_device, selected_operation, rp_id).await?;

            vec![(selected_device, token_with_protocol)]
        } else {
            // The request doesn't require UV, and no authenticator device requires UV.
            // Therefore, do the regular authentication flow (race all authenticators).
            devices.into_iter().map(|e| (e, None)).collect()
        };
        Ok(selected_devices)
    }

    // Take a device and an operation and obtain an auth token for that device using the method
    // appropriate to the operation.
    async fn get_auth_token_for_device(
        &self,
        selected_device: &mut LinuxAuthenticator,
        selected_operation: Option<GetPinUvAuthTokenOp>,
        rp_id: &str,
    ) -> Result<Option<TokenWithProtocol>, WebauthnError> {
        let token_and_protocol = match selected_operation {
            None => None,
            Some(op) => {
                // Obtain platform key-agreement key and shared secret.
                let pin_uv_auth_protocol = 1;
                let public_key = selected_device.inner.get_public_key(pin_uv_auth_protocol).await?;
                let (platform_key_agreement_key, shared_secret) = self.pin_uv_auth_protocol_state.encapsulate(&public_key).map_err(ctap2::StatusCode::from)?;
                let permissions = ctap2::client_pin::Permissions::MC | ctap2::client_pin::Permissions::GA;
                let encrypted_token = match op {
                    GetPinUvAuthTokenOp::GetPinUvAuthTokenUsingPinWithPermissions => {
                        let attempts_remaining = selected_device.inner.get_pin_retries(pin_uv_auth_protocol).await?;
                        let pin = self.pin_prompt.request_pin(attempts_remaining).await.map_err(|_| WebauthnError::NotSupportedError)?;
                        let encrypted_pin = aes_256_cbc(
                            shared_secret,
                            [0; 16],
                            &sha256(pin.as_bytes())[0..16]
                        ).into();
                        selected_device.inner.get_pin_uv_auth_token_using_pin(
                            pin_uv_auth_protocol,
                            platform_key_agreement_key,
                            encrypted_pin,
                            permissions,
                            Some(rp_id.to_owned()),
                        ).await?
                    }
                    GetPinUvAuthTokenOp::GetPinUvAuthTokenUsingUvWithPermissions => {
                        selected_device.inner.get_pin_uv_auth_token_using_uv(
                            pin_uv_auth_protocol,
                            platform_key_agreement_key,
                            permissions,
                            Some(rp_id.to_owned()),
                        ).await?
                    }
                    GetPinUvAuthTokenOp::GetPinToken => {
                        // TODO: use getUvRetries here
                        let attempts_remaining = selected_device.inner.get_pin_retries(pin_uv_auth_protocol).await?;
                        let pin = self.pin_prompt.request_pin(attempts_remaining).await.map_err(|_| WebauthnError::NotSupportedError)?;
                        let encrypted_pin = aes_256_cbc(
                            shared_secret,
                            [0; 16],
                            &sha256(pin.as_bytes())[0..16]
                        ).into();
                        selected_device.inner.get_pin_token(
                            pin_uv_auth_protocol,
                            platform_key_agreement_key,
                            encrypted_pin,
                        ).await?
                    }
                };

                // Decrypt the token using the shared secret before returning it.
                let pin_uv_auth_token = Bytes::from(PinUvAuthProtocolOne::decrypt(&shared_secret, encrypted_token.as_slice()));
                Some((pin_uv_auth_token, pin_uv_auth_protocol))
            }
        };
        Ok(token_and_protocol.map(|e| TokenWithProtocol { token: e.0, protocol: e.1 }))
    }

    /// Register a credential by racing every connected security key.
    pub async fn register<D: ClientData<E>, E: Serialize + Clone>(
        &mut self,
        origin: impl Into<Origin<'_>>,
        request: CredentialCreationOptions,
        client_data: D,
    ) -> Result<CreatedPublicKeyCredential, WebauthnError> {
        let origin = origin.into();
        let opts = request.public_key;

        let rp_id = self
            .rp_id_verifier
            .assert_domain(&origin, opts.rp.id.as_deref())
            .await?;
        let rp_id = rp_id.to_owned();

        let (client_data_json, client_data_hash) = build_client_data(
            &client_data,
            ClientDataType::Create,
            &opts.challenge,
            &origin,
        )?;

        let pub_key_cred_params = if opts.pub_key_cred_params.is_empty() {
            PublicKeyCredentialParameters::default_algorithms()
        } else {
            opts.pub_key_cred_params
        };

        let uv_requirement = opts
            .authenticator_selection
            .as_ref()
            .map(|s| s.user_verification)
            .unwrap_or_default();
        let uv = ctap_uv_option(uv_requirement, self.uv_when_preferred);

        // Per-device filter + tailored request build. Owned devices that don't
        // qualify are held aside so we can restore them after the race.
        let selected_devices = self.get_valid_devices(uv, &rp_id).await?;
        let mut candidates: Vec<(LinuxAuthenticator, ctap2::make_credential::Request)> = Vec::new();
        let mut preserved: Vec<LinuxAuthenticator> = Vec::new();
        for (device, token_with_protocol) in selected_devices {
            let info = device.info();

            let rk = map_rk(opts.authenticator_selection.as_ref(), &info);
            if rk && !device.rk_supported() {
                // RP requires a resident key but this device can't store one.
                preserved.push(device);
                continue;
            }
            if uv && !(device.uv_configured() || device.pin_configured()) {
                // RP requires UV but this device has no built-in UV (and we don't implement
                // clientPIN yet, so PIN-only devices can't satisfy `uv`).
                preserved.push(device);
                continue;
            }

            let matched_params = filter_algorithms(&pub_key_cred_params, &info);
            if matched_params.is_empty() {
                // None of the algorithms requested by the RP are supported by this authenticator.
                preserved.push(device);
                continue;
            }


            let (pin_auth, pin_protocol) = get_pin_auth_and_protocol(token_with_protocol, &client_data_hash);
            let request = ctap2::make_credential::Request {
                client_data_hash: client_data_hash.clone().into(),
                rp: ctap2::make_credential::PublicKeyCredentialRpEntity {
                    id: rp_id.clone(),
                    name: Some(opts.rp.name.clone()),
                },
                user: opts.user.clone(),
                pub_key_cred_params: matched_params,
                exclude_list: opts.exclude_credentials.clone(),
                extensions: None,
                options: ctap2::make_credential::Options { rk, up: false, uv },
                pin_auth,
                pin_protocol,
            };
            candidates.push((device, request));
        }

        if candidates.is_empty() {
            self.devices.extend(preserved);
            return Err(WebauthnError::NotSupportedError);
        }

        let RaceOutcome {
            winner,
            errors,
            losers,
        } = race_request(candidates, |mut auth, req| async move {
            let result = auth.inner.make_credential(req).await;
            (auth, result)
        })
        .await;
        self.devices = preserved;
        self.devices.extend(losers);
        let (ctap2_response, winner_auth) = winner.ok_or_else(move || {
            errors
                .into_iter()
                .next_back()
                .map(WebauthnError::from)
                .unwrap_or(WebauthnError::NotSupportedError)
        })?;
        // Report the transports the winning device advertises via `authenticatorGetInfo`, falling
        // back to USB (which every `LinuxAuthenticator` uses) if the device doesn't publish a
        // transports list.
        let transports = winner_auth
            .info()
            .transports
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec![webauthn::AuthenticatorTransport::Usb]);
        self.devices.push(winner_auth);

        let credential_id = ctap2_response
            .auth_data
            .attested_credential_data
            .as_ref()
            .ok_or(WebauthnError::AuthenticatorError(
                ctap2::StatusCode::Ctap1(ctap2::U2FError::Other).into(),
            ))?;
        let alg = match credential_id.key.alg.as_ref() {
            Some(Algorithm::PrivateUse(val)) => *val,
            Some(Algorithm::Assigned(a)) => EnumI64::to_i64(a),
            // In the case that the algorithm is unknown, default to 0 (Reserved)
            _ => 0,
        };
        let public_key = Some(
            public_key_der_from_cose_key(&credential_id.key)
                .map_err(|e| WebauthnError::AuthenticatorError(e.into()))?,
        );
        let attestation_object = ctap2_response.as_webauthn_bytes();

        Ok(CreatedPublicKeyCredential {
            id: encoding::base64url(credential_id.credential_id()),
            raw_id: credential_id.credential_id().to_vec().into(),
            ty: PublicKeyCredentialType::PublicKey,
            response: AuthenticatorAttestationResponse {
                client_data_json: Vec::from(client_data_json).into(),
                authenticator_data: ctap2_response.auth_data.to_vec().into(),
                public_key,
                public_key_algorithm: alg,
                attestation_object,
                transports: Some(transports),
            },
            authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
            client_extension_results: Default::default(),
        })
    }

    /// Get assertion for a credential by racing every connected security key.
    pub async fn authenticate<D: ClientData<E>, E: Serialize + Clone>(
        &mut self,
        origin: impl Into<Origin<'_>>,
        request: CredentialRequestOptions,
        client_data: D,
    ) -> Result<AuthenticatedPublicKeyCredential, WebauthnError> {
        let origin = origin.into();
        let opts = request.public_key;

        let rp_id = self
            .rp_id_verifier
            .assert_domain(&origin, opts.rp_id.as_deref())
            .await?;
        let rp_id = rp_id.to_owned();

        let (client_data_json, client_data_hash) =
            build_client_data(&client_data, ClientDataType::Get, &opts.challenge, &origin)?;

        let uv = ctap_uv_option(opts.user_verification, self.uv_when_preferred);

        let selected_devices = self.get_valid_devices(uv, &rp_id).await?;
        let mut candidates: Vec<(LinuxAuthenticator, ctap2::get_assertion::Request)> = Vec::new();
        let mut preserved: Vec<LinuxAuthenticator> = Vec::new();
        for (device, token_with_protocol) in selected_devices {
            if uv && !(device.uv_configured() || device.pin_configured()) {
                preserved.push(device);
                continue;
            }
            let (pin_auth, pin_protocol) = get_pin_auth_and_protocol(token_with_protocol, &client_data_hash);
            let request = ctap2::get_assertion::Request {
                rp_id: rp_id.clone(),
                client_data_hash: client_data_hash.clone().into(),
                allow_list: opts.allow_credentials.clone(),
                extensions: None,
                options: ctap2::get_assertion::Options { up: true, uv },
                pin_auth,
                pin_protocol,
            };
            candidates.push((device, request));
        }

        if candidates.is_empty() {
            self.devices.extend(preserved);
            return Err(WebauthnError::NotSupportedError);
        }

        let RaceOutcome {
            winner,
            errors,
            losers,
        } = race_request(candidates, |mut auth, req| async move {
            let result = auth.inner.get_assertion(req).await;
            (auth, result)
        })
        .await;
        self.devices = preserved;
        self.devices.extend(losers);
        let (ctap2_response, winner_auth) = winner.ok_or_else(move || {
            // Preserve the earlier behaviour: if every candidate reported
            // "no credentials", surface CredentialNotFound; otherwise surface
            // the most recent non-CredentialNotFound error.
            let mapped: Vec<WebauthnError> = errors.into_iter().map(WebauthnError::from).collect();
            let has_other = mapped
                .iter()
                .any(|e| !matches!(e, WebauthnError::CredentialNotFound));
            if !mapped.is_empty() && !has_other {
                WebauthnError::CredentialNotFound
            } else {
                mapped
                    .into_iter()
                    .rev()
                    .find(|e| !matches!(e, WebauthnError::CredentialNotFound))
                    .unwrap_or(WebauthnError::NotSupportedError)
            }
        })?;
        self.devices.push(winner_auth);

        let credential_id_bytes = match ctap2_response.credential {
            Some(c) => c.id.to_vec(),
            None => return Err(WebauthnError::CredentialNotFound),
        };
        Ok(AuthenticatedPublicKeyCredential {
            id: encoding::base64url(&credential_id_bytes),
            raw_id: credential_id_bytes.into(),
            ty: PublicKeyCredentialType::PublicKey,
            response: AuthenticatorAssertionResponse {
                client_data_json: Vec::from(client_data_json).into(),
                authenticator_data: ctap2_response.auth_data.to_vec().into(),
                signature: ctap2_response.signature,
                user_handle: ctap2_response.user.map(|user| user.id),
                attestation_object: None,
            },
            authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
            client_extension_results: Default::default(),
        })
    }
}

/// Keep only the algorithms the device's `get_info` advertises (if it advertises any). The
/// algorithms field is optional, so if no algorithms are advertised then just return the request
/// unmodified.
fn filter_algorithms(
    requested: &[PublicKeyCredentialParameters],
    info: &ctap2::get_info::Response,
) -> Vec<PublicKeyCredentialParameters> {
    let Some(device_algs) = info.algorithms.as_ref() else {
        return requested.to_vec();
    };

    requested
        .iter()
        .filter(|p| device_algs.iter().any(|d| d.alg == p.alg))
        .copied()
        .collect()
}

/// Result of a [`race_request`] call.
struct RaceOutcome<R> {
    /// The winning response paired with the authenticator that produced it, or `None` if every
    /// candidate returned an error.
    winner: Option<(R, LinuxAuthenticator)>,
    /// Status codes returned by candidates that had already errored by the time a winner emerged
    /// (or by the time the race exhausted its candidates).
    errors: Vec<ctap2::StatusCode>,
    /// Every authenticator that entered the race except the winner.
    losers: Vec<LinuxAuthenticator>,
}

/// Race a CTAP request across all candidates and cancel the losers once a winner has been found.
/// `call` is invoked once per candidate with owned access to the authenticator and its request; the
/// future it returns must hand the authenticator back so the [`LinuxClient`] can keep using it.
async fn race_request<Req, R, C, F>(
    candidates: Vec<(LinuxAuthenticator, Req)>,
    call: C,
) -> RaceOutcome<R>
where
    C: Fn(LinuxAuthenticator, Req) -> F,
    F: Future<Output = (LinuxAuthenticator, Result<R, ctap2::StatusCode>)> + Send + 'static,
    Req: Send + 'static,
    R: Send + 'static,
{
    // Clone each authenticator's cancel sender before moving the
    // authenticator into its task. These clones let us send a `Command::Cancel`
    // to the losers via `LinuxAuthenticator::cancel_tx`.
    let cancel_txs: Vec<_> = candidates
        .iter()
        .map(|(auth, _)| auth.cancel_tx.clone())
        .collect();

    let mut set: JoinSet<(usize, LinuxAuthenticator, Result<R, ctap2::StatusCode>)> =
        JoinSet::new();
    for (idx, (auth, request)) in candidates.into_iter().enumerate() {
        let fut = call(auth, request);
        set.spawn(async move {
            let (auth, result) = fut.await;
            (idx, auth, result)
        });
    }

    let mut winner: Option<(R, LinuxAuthenticator)> = None;
    let mut winner_idx: Option<usize> = None;
    let mut errors: Vec<ctap2::StatusCode> = Vec::new();
    let mut losers: Vec<LinuxAuthenticator> = Vec::with_capacity(cancel_txs.len());
    let mut finished: Vec<usize> = Vec::with_capacity(cancel_txs.len());

    // Wait for task completions until we find a winner or exhaust all the tasks.
    while let Some(join_res) = set.join_next().await {
        let (idx, auth, result) = join_res.expect("race_request task panicked");
        finished.push(idx);
        match result {
            Ok(resp) => {
                winner = Some((resp, auth));
                winner_idx = Some(idx);
                break;
            }
            Err(sc) => {
                errors.push(sc);
                losers.push(auth);
            }
        }
    }

    // Signal the still-running losers to cancel.
    if let Some(win_idx) = winner_idx {
        for (i, tx) in cancel_txs.iter().enumerate() {
            if i != win_idx && !finished.contains(&i) {
                let _ = tx.try_send(());
            }
        }
    }

    // Wait on any remaining tasks so the transactions finish and we get the authenticators back.
    while let Some(join_res) = set.join_next().await {
        let (_idx, auth, _result) = join_res.expect("race_request task panicked");
        losers.push(auth);
    }

    RaceOutcome {
        winner,
        errors,
        losers,
    }
}
