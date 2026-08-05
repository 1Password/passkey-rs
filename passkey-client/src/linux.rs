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

use passkey_authenticator::linux::{LinuxAuthenticator, OpenError};
use passkey_crypto::{
    CryptoBackend, PublicKeyT, SecretKeyT, coset::Algorithm, iana::EnumI64,
    rust_crypto::RustCryptoBackend,
};
use passkey_types::{
    Bytes, ctap2, encoding,
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

/// A WebAuthn client backed by zero or more USB security keys serving as authenticators.
pub struct LinuxClient<P, F>
where
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
    F: Fetcher + Sync,
{
    devices: Vec<LinuxAuthenticator>,
    rp_id_verifier: RpIdVerifier<P, F>,
    uv_when_preferred: bool,
}

impl LinuxClient<public_suffix::PublicSuffixList, ()> {
    /// Build a `LinuxClient` over the supplied authenticators using the default public-suffix list
    /// TLD provider.
    pub fn new(authenticators: Vec<LinuxAuthenticator>) -> Self {
        Self {
            devices: authenticators,
            rp_id_verifier: RpIdVerifier::new(public_suffix::DEFAULT_PROVIDER, None),
            uv_when_preferred: true,
        }
    }

    /// Enumerate every FIDO-capable USB HID device on the system and open each
    /// one. Devices that fail to open are skipped silently.
    pub async fn open_all() -> Result<Self, OpenError> {
        let infos = LinuxAuthenticator::list_devices()?;
        let mut authenticators = Vec::new();
        for info in infos {
            if let Ok(auth) = LinuxAuthenticator::open(&info.path).await {
                authenticators.push(auth);
            }
        }
        Ok(Self::new(authenticators))
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
    ) -> Self {
        Self {
            devices: authenticators,
            rp_id_verifier: RpIdVerifier::new(custom_provider, fetcher),
            uv_when_preferred: true,
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
        let devices = std::mem::take(&mut self.devices);
        let mut candidates: Vec<(LinuxAuthenticator, ctap2::make_credential::Request)> = Vec::new();
        let mut preserved: Vec<LinuxAuthenticator> = Vec::new();
        for device in devices {
            let info = device.info();

            let rk = map_rk(opts.authenticator_selection.as_ref(), &info);
            if rk && !info.options.as_ref().is_some_and(|o| o.rk) {
                // RP requires a resident key but this device can't store one.
                preserved.push(device);
                continue;
            }
            if uv && !device_supports_uv(&info) {
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
                pin_auth: None,
                pin_protocol: None,
            };
            candidates.push((device, request));
        }

        if candidates.is_empty() {
            self.devices = preserved;
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
                ctap2::Ctap2Error::Other.into(),
            ))?;
        let alg = match credential_id.key.alg.as_ref() {
            Some(Algorithm::PrivateUse(val)) => *val,
            Some(Algorithm::Assigned(a)) => EnumI64::to_i64(a),
            // In the case that the algorithm is unknown, default to 0 (Reserved)
            _ => 0,
        };
        // TODO: we handle this conversion through the RustCryptoBackend.
        // We may want to change this in the future.
        let public_key = Some(
            <<RustCryptoBackend as CryptoBackend>::SecretKey as SecretKeyT>::PublicKey::der_from_cose_key(&credential_id.key)
                .map(Into::<Bytes>::into)
                .map_err(|e| WebauthnError::AuthenticatorError(ctap2::Ctap2Error::from(e).into()))?,
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

        let devices = std::mem::take(&mut self.devices);
        let mut candidates: Vec<(LinuxAuthenticator, ctap2::get_assertion::Request)> = Vec::new();
        let mut preserved: Vec<LinuxAuthenticator> = Vec::new();
        for device in devices {
            let info = device.info();
            if uv && !device_supports_uv(&info) {
                preserved.push(device);
                continue;
            }
            let request = ctap2::get_assertion::Request {
                rp_id: rp_id.clone(),
                client_data_hash: client_data_hash.clone().into(),
                allow_list: opts.allow_credentials.clone(),
                extensions: None,
                options: ctap2::get_assertion::Options { up: true, uv },
                pin_auth: None,
                pin_protocol: None,
            };
            candidates.push((device, request));
        }

        if candidates.is_empty() {
            self.devices = preserved;
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

/// Whether the given `get_info::Response` indicates that the device supports a user verification
/// method that's already configured.
fn device_supports_uv(info: &ctap2::get_info::Response) -> bool {
    info.options.as_ref().and_then(|o| o.uv).unwrap_or(false)
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
