//! Linux USB security key authenticator.
//!
//! [`LinuxAuthenticator`] adapts the CTAPHID transport in
//! [`passkey_transports::hidraw`] to the [`Ctap2Api`] trait, so a
//! USB hardware key can be plugged into anything that today drives the in-process
//! [`Authenticator`](crate::Authenticator).
//!
//! ## Usage
//!
//! ```ignore
//! use passkey_authenticator::linux::LinuxAuthenticator;
//!
//! let devices = LinuxAuthenticator::list_devices()?;
//! let mut auth = LinuxAuthenticator::open(&devices[0].path).await?;
//! let info = auth.get_info().await;
//! ```

use std::io;
use std::path::Path;

use passkey_transports::hid::{Command, Message};
use passkey_transports::hidraw::{DeviceInfo, HidDevice, HidrawError, enumerate_fido_devices};
use passkey_types::ctap2::{
    Ctap2ClientPinSubcommand, Ctap2Code, Ctap2Command, Ctap2Error, StatusCode, U2FError,
    client_pin, get_assertion, get_info, make_credential,
};
use passkey_types::{Bytes, webauthn};
use tokio::sync::mpsc;

use crate::Ctap2Api;

// Re-export so callers don't need a direct dep on passkey-transports.
pub use passkey_transports::hidraw::{Capabilities, DeviceInfo as HidDeviceInfo, InitResponse};

/// Errors that can occur while constructing a [`LinuxAuthenticator`].
#[derive(Debug)]
#[non_exhaustive]
pub enum OpenError {
    /// The underlying HIDRAW transport returned an error (open / init / I/O).
    Transport(HidrawError),
    /// `CTAPHID_INIT` succeeded but the device does not advertise CTAP2 (CBOR) support.
    NotCtap2,
    /// The device responded to `authenticatorGetInfo` with a CTAP2 status code.
    GetInfo(StatusCode),
    /// The device's `authenticatorGetInfo` response could not be parsed as CBOR.
    InvalidGetInfo,
}

impl From<HidrawError> for OpenError {
    fn from(e: HidrawError) -> Self {
        Self::Transport(e)
    }
}

impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> Self {
        Self::Transport(HidrawError::from(e))
    }
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Transport(e) => write!(f, "HID transport error: {e}"),
            OpenError::NotCtap2 => f.write_str("device does not advertise CTAP2 support"),
            OpenError::GetInfo(s) => write!(f, "authenticatorGetInfo failed: {s:?}"),
            OpenError::InvalidGetInfo => {
                f.write_str("could not parse authenticatorGetInfo response")
            }
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OpenError::Transport(e) => Some(e),
            _ => None,
        }
    }
}

/// A CTAP2 authenticator backed by a USB security key reached over Linux HIDRAW.
///
/// Construct with [`LinuxAuthenticator::open`]; enumerate candidate devices with
/// [`LinuxAuthenticator::list_devices`].
pub struct LinuxAuthenticator {
    /// Inner authenticator.
    pub inner: LinuxAuthenticatorInner,
    /// Send a message here to cancel the current transaction.
    pub cancel_tx: mpsc::Sender<()>,
}

/// Inner LinuxAuthenticator which interfaces with and contains info about the device.
pub struct LinuxAuthenticatorInner {
    device: HidDevice,
    channel: u32,
    capabilities: Capabilities,
    /// Cached `authenticatorGetInfo` response, stored as raw CBOR.
    ///
    /// The `Ctap2Api::get_info` trait method returns an owned `Box<Response>` and
    /// takes `&self`, so we can't lazily call the device on every invocation
    /// without interior mutability. Caching the bytes lets us hand out fresh
    /// `Response` values cheaply, and avoids requiring `Clone` on the response
    /// type, which lives in `passkey-types`.
    get_info_cbor: CtaphidCborResponse,
    cancel_rx: mpsc::Receiver<()>,
}

impl LinuxAuthenticatorInner {
    /// Determine whether the device supports CTAP 2.1 or greater. If it does, issue an
    /// `authenticatorSelection` command. Otherwise, issue `authenticatorMakeCredential` with a
    /// zero-length `pinUvAuthToken`. Returns when the user provides UP on the device.
    pub async fn authenticator_selection(&mut self) -> Result<(), StatusCode> {
        let info: get_info::Response =
            ciborium::de::from_reader(self.get_info_cbor.get_payload()).unwrap_or_default();
        let authenticator_selection_unsupported = info
            .versions
            .iter()
            .all(|e| *e == get_info::Version::U2F_V2 || *e == get_info::Version::FIDO_2_0);
        if !authenticator_selection_unsupported {
            let response = self
                .send_cbor_with_cancel(Ctap2Command::AuthenticatorSelection, &[])
                .await;
            if matches!(
                response,
                Err(TransactionError::Status(StatusCode::Ctap2(
                    Ctap2Code::Known(Ctap2Error::Ok)
                )))
            ) {
                Ok(())
            } else {
                response.map(|_| ()).map_err(StatusCode::from)
            }
        } else {
            let dummy_request = make_credential::Request {
                client_data_hash: Bytes::from(&[][..]),
                rp: make_credential::PublicKeyCredentialRpEntity {
                    id: String::new(),
                    name: None,
                },
                user: webauthn::PublicKeyCredentialUserEntity {
                    id: Bytes::from(&[][..]),
                    display_name: String::new(),
                    name: String::new(),
                },
                pub_key_cred_params: webauthn::PublicKeyCredentialParameters::default_algorithms(),
                exclude_list: None,
                extensions: None,
                options: make_credential::Options {
                    rk: false,
                    up: false,
                    uv: false,
                },
                pin_auth: Some(Bytes::from(&[][..])),
                pin_protocol: Some(1),
            };
            let mut body = Vec::new();
            ciborium::ser::into_writer(&dummy_request, &mut body)
                .map_err(|_| StatusCode::from(U2FError::Other))?;
            let response = self
                .send_cbor_with_cancel(Ctap2Command::MakeCredential, &body)
                .await;
            if matches!(
                response,
                Err(TransactionError::Status(StatusCode::Ctap2(
                    Ctap2Code::Known(Ctap2Error::PinNotSet | Ctap2Error::PinInvalid)
                )))
            ) {
                Ok(())
            } else {
                response.map(|_| ()).map_err(StatusCode::from)
            }
        }
    }

    /// Issue `authenticatorMakeCredential` against the device.
    pub async fn make_credential(
        &mut self,
        request: make_credential::Request,
    ) -> Result<make_credential::Response, StatusCode> {
        let mut body = Vec::new();
        ciborium::ser::into_writer(&request, &mut body)
            .map_err(|_| StatusCode::from(U2FError::Other))?;
        let response = self
            .send_cbor_with_cancel(Ctap2Command::MakeCredential, &body)
            .await
            .map_err(StatusCode::from)?;
        ciborium::de::from_reader(response.get_payload())
            .map_err(|_| StatusCode::from(Ctap2Error::InvalidCbor))
    }

    /// Issue `authenticatorGetAssertion` against the device.
    pub async fn get_assertion(
        &mut self,
        request: get_assertion::Request,
    ) -> Result<get_assertion::Response, StatusCode> {
        let mut body = Vec::new();
        ciborium::ser::into_writer(&request, &mut body)
            .map_err(|_| StatusCode::from(U2FError::Other))?;
        let response = self
            .send_cbor_with_cancel(Ctap2Command::GetAssertion, &body)
            .await
            .map_err(StatusCode::from)?;
        ciborium::de::from_reader(response.get_payload())
            .map_err(|_| StatusCode::from(Ctap2Error::InvalidCbor))
    }

    /// Fetch public key from device using the given protocol.
    pub async fn get_public_key(&mut self, protocol: u8) -> Result<coset::CoseKey, StatusCode> {
        let request = client_pin::Request {
            pin_uv_auth_protocol: Some(protocol),
            sub_command: Ctap2ClientPinSubcommand::GetKeyAgreement.into(),
            key_agreement: None,
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            rp_id: None,
        };
        let mut body = Vec::new();
        ciborium::ser::into_writer(&request, &mut body)
            .map_err(|_| StatusCode::from(U2FError::Other))?;
        let response = self
            .send_cbor_with_cancel(Ctap2Command::ClientPin, &body)
            .await
            .map_err(StatusCode::from)?;
        let response: client_pin::Response =
            ciborium::de::from_reader(response.get_payload()).unwrap();
        // TODO: remove this expect
        Ok(response.key_agreement.expect("should have a key agreement"))
    }

    /// `getPinToken` subcommand of `clientPin`.
    pub async fn get_pin_token(
        &mut self,
        protocol: u8,
        key_agreement: coset::CoseKey,
        pin_hash_enc: Bytes,
    ) -> Result<Bytes, StatusCode> {
        let request = client_pin::Request {
            pin_uv_auth_protocol: Some(protocol),
            sub_command: Ctap2ClientPinSubcommand::GetPinToken.into(),
            key_agreement: Some(key_agreement),
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: Some(pin_hash_enc),
            permissions: None,
            rp_id: None,
        };
        let mut body = Vec::new();
        ciborium::ser::into_writer(&request, &mut body)
            .map_err(|_| StatusCode::from(U2FError::Other))?;
        let response = self
            .send_cbor_with_cancel(Ctap2Command::ClientPin, &body)
            .await
            .map_err(StatusCode::from)?;
        let response: client_pin::Response =
            ciborium::de::from_reader(response.get_payload()).unwrap_or_default();
        // TODO: remove this expect
        Ok(response
            .pin_uv_auth_token
            .expect("should have a pinUvAuthToken"))
    }

    /// `getPinUvAuthTokenUsingUvWithPermissions` subcommand of `clientPin`.
    pub async fn get_pin_uv_auth_token_using_uv(
        &mut self,
        protocol: u8,
        key_agreement: coset::CoseKey,
        permissions: client_pin::Permissions,
        // rp_id is required for both make_credential and get_assertion, but we leave
        // it as an Option here in case we need to add support for other permissions and don't
        // want to break backwards compatibility.
        rp_id: Option<String>,
    ) -> Result<Bytes, StatusCode> {
        let request = client_pin::Request {
            pin_uv_auth_protocol: Some(protocol),
            sub_command: Ctap2ClientPinSubcommand::GetPinUvAuthTokenUsingUvWithPermissions.into(),
            key_agreement: Some(key_agreement),
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: Some(permissions),
            rp_id,
        };
        let mut body = Vec::new();
        ciborium::ser::into_writer(&request, &mut body)
            .map_err(|_| StatusCode::from(U2FError::Other))?;
        let response = self
            .send_cbor_with_cancel(Ctap2Command::ClientPin, &body)
            .await
            .map_err(StatusCode::from)?;
        let response: client_pin::Response =
            ciborium::de::from_reader(response.get_payload()).unwrap_or_default();
        // TODO: remove this expect
        Ok(response
            .pin_uv_auth_token
            .expect("should have a pinUvAuthToken"))
    }

    /// `getPinUvAuthTokenUsingPinWithPermissions` subcommand of `clientPin`.
    pub async fn get_pin_uv_auth_token_using_pin(
        &mut self,
        protocol: u8,
        key_agreement: coset::CoseKey,
        pin_hash_enc: Bytes,
        permissions: client_pin::Permissions,
        // rp_id is required for both make_credential and get_assertion, but we leave
        // it as an Option here in case we need to add support for other permissions and don't
        // want to break backwards compatibility.
        rp_id: Option<String>,
    ) -> Result<Bytes, StatusCode> {
        let request = client_pin::Request {
            pin_uv_auth_protocol: Some(protocol),
            sub_command: Ctap2ClientPinSubcommand::GetPinUvAuthTokenUsingPinWithPermissions.into(),
            key_agreement: Some(key_agreement),
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: Some(pin_hash_enc),
            permissions: Some(permissions),
            rp_id,
        };
        let mut body = Vec::new();
        ciborium::ser::into_writer(&request, &mut body)
            .map_err(|_| StatusCode::from(U2FError::Other))?;
        let response = self
            .send_cbor_with_cancel(Ctap2Command::ClientPin, &body)
            .await
            .map_err(StatusCode::from)?;
        let response: client_pin::Response =
            ciborium::de::from_reader(response.get_payload()).unwrap_or_default();
        // TODO: remove this expect
        Ok(response
            .pin_uv_auth_token
            .expect("should have a pinUvAuthToken"))
    }

    /// `getPinRetries` subcommand of `clientPin`.
    pub async fn get_pin_retries(&mut self, protocol: u8) -> Result<u32, StatusCode> {
        let request = client_pin::Request {
            pin_uv_auth_protocol: Some(protocol),
            sub_command: Ctap2ClientPinSubcommand::GetPinRetries.into(),
            key_agreement: None,
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            rp_id: None,
        };
        let mut body = Vec::new();
        ciborium::ser::into_writer(&request, &mut body)
            .map_err(|_| StatusCode::from(U2FError::Other))?;
        let response = self
            .send_cbor_with_cancel(Ctap2Command::ClientPin, &body)
            .await
            .map_err(StatusCode::from)?;
        let response: client_pin::Response =
            ciborium::de::from_reader(response.get_payload()).unwrap_or_default();
        // TODO: remove this expect
        Ok(response.pin_retries.expect("Should have pin retries"))
    }

    /// Send a CTAPHID_CBOR request and await its response, forwarding any
    /// signal received on `cancel_rx` to the device as a `CTAPHID_CANCEL`
    /// without cancelling the outstanding `recv`. The pending recv is kept
    /// alive across signals so a response (typically `KeepAliveCancel`) is
    /// always drained before returning.
    async fn send_cbor_with_cancel(
        &mut self,
        command: Ctap2Command,
        body: &[u8],
    ) -> Result<CtaphidCborResponse, TransactionError> {
        // Drop any cancel signals that arrived before this call started so
        // they don't immediately abort the request we're about to send.
        while self.cancel_rx.try_recv().is_ok() {}

        send_cbor(&self.device, self.channel, command, body).await?;

        let device = &self.device;
        let channel = self.channel;
        let cancel_rx = &mut self.cancel_rx;

        let recv_fut = recv_cbor(device, channel);
        tokio::pin!(recv_fut);
        loop {
            tokio::select! {
                result = &mut recv_fut => return result,
                maybe_cancel = cancel_rx.recv() => match maybe_cancel {
                    Some(()) => {
                        let cancel_msg = Message::new(channel, Command::Cancel, &[])
                            .map_err(|_| TransactionError::Hid(HidrawError::MessageTooLarge))?;
                        device.send(&cancel_msg).await.map_err(TransactionError::Hid)?;
                    }
                    None => return (&mut recv_fut).await,
                },
            }
        }
    }
}

impl LinuxAuthenticator {
    /// Enumerate FIDO-capable USB HID devices visible on the system.
    pub fn list_devices() -> io::Result<Vec<DeviceInfo>> {
        enumerate_fido_devices()
    }

    /// Whether builtin UV is configured for this device.
    pub fn uv_configured(&self) -> bool {
        self.info().options.and_then(|o| o.uv).unwrap_or(false)
    }

    /// Whether a PIN is configured for this device.
    pub fn pin_configured(&self) -> bool {
        self.info()
            .options
            .and_then(|o| o.client_pin)
            .unwrap_or(false)
    }

    /// Whether this device supports storing resident keys.
    pub fn rk_supported(&self) -> bool {
        self.info().options.is_some_and(|o| o.rk)
    }

    /// Whether the authenticator supports authenticatorClientPIN's
    /// getPinUvAuthTokenUsingUvWithPermissions subcommand.
    pub fn pin_uv_auth_token_supported(&self) -> bool {
        self.info()
            .options
            .map(|o| o.pin_uv_auth_token == Some(true))
            .unwrap_or(false)
    }

    /// Open a specific `/dev/hidrawN` path, run `CTAPHID_INIT` to obtain a private
    /// channel, and prime the cached `authenticatorGetInfo` response.
    pub async fn open(path: &Path) -> Result<Self, OpenError> {
        let device = HidDevice::open(path)?;
        let init = device.init().await?;
        if !init.capabilities.supports_cbor() {
            return Err(OpenError::NotCtap2);
        }

        // Fetch authenticatorGetInfo so we can cache it and surface any obvious
        // device-side errors before returning to the caller.
        let response_raw =
            send_cbor_without_cancel(&device, init.channel, Ctap2Command::GetInfo, &[]).await?;
        // Validate that it parses.
        let _: get_info::Response = ciborium::de::from_reader(response_raw.get_payload())
            .map_err(|_| OpenError::InvalidGetInfo)?;

        let (tx, rx) = mpsc::channel(1);
        Ok(LinuxAuthenticator {
            inner: LinuxAuthenticatorInner {
                device,
                channel: init.channel,
                capabilities: init.capabilities,
                get_info_cbor: response_raw,
                cancel_rx: rx,
            },
            cancel_tx: tx,
        })
    }

    /// Capabilities reported by the device in its `CTAPHID_INIT` response.
    pub fn capabilities(&self) -> Capabilities {
        self.inner.capabilities
    }

    /// Read and decode the cached `authenticatorGetInfo` response.
    pub fn info(&self) -> get_info::Response {
        ciborium::de::from_reader(self.inner.get_info_cbor.get_payload()).unwrap_or_default()
    }

    // TODO: remove these functions?

    /// Issue `authenticatorMakeCredential` against the device.
    pub async fn make_credential(
        &mut self,
        request: make_credential::Request,
    ) -> Result<make_credential::Response, StatusCode> {
        self.inner.make_credential(request).await
    }

    /// Issue `authenticatorGetAssertion` against the device.
    pub async fn get_assertion(
        &mut self,
        request: get_assertion::Request,
    ) -> Result<get_assertion::Response, StatusCode> {
        self.inner.get_assertion(request).await
    }
}

/// Internal error type for CBOR transactions. Maps cleanly to both [`StatusCode`]
/// (for the [`Ctap2Api`] surface) and [`OpenError`] (for the constructor).
#[derive(Debug)]
enum TransactionError {
    Hid(HidrawError),
    Status(StatusCode),
}

impl From<TransactionError> for OpenError {
    fn from(e: TransactionError) -> Self {
        match e {
            TransactionError::Hid(e) => OpenError::Transport(e),
            TransactionError::Status(s) => OpenError::GetInfo(s),
        }
    }
}

impl From<TransactionError> for StatusCode {
    fn from(e: TransactionError) -> Self {
        match e {
            TransactionError::Status(s) => s,
            // CTAP doesn't have a dedicated "transport failed" status code; surface
            // it as the catch-all CTAP1 `U2FError::Other` (0x7F).
            TransactionError::Hid(_) => StatusCode::from(U2FError::Other),
        }
    }
}

enum CtaphidCborResponseError {
    ResponseEmpty,
    BadStatus(u8),
}

struct CtaphidCborResponse {
    raw: Vec<u8>,
}

impl CtaphidCborResponse {
    fn new(raw: Vec<u8>) -> Result<Self, CtaphidCborResponseError> {
        // Verify that status byte exists and is equal to the success code (0)
        let Some(status) = raw.first() else {
            return Err(CtaphidCborResponseError::ResponseEmpty);
        };
        if *status != u8::from(U2FError::Success) {
            return Err(CtaphidCborResponseError::BadStatus(*status));
        };
        Ok(Self { raw })
    }

    fn get_payload(&self) -> &[u8] {
        // SAFETY: this slice is never out of bounds because we verify in the constructor that `raw`
        // has at least one byte.
        &self.raw[1..]
    }
}

/// Send a CTAPHID_CBOR request.
async fn send_cbor(
    device: &HidDevice,
    channel: u32,
    command: Ctap2Command,
    body: &[u8],
) -> Result<(), TransactionError> {
    let mut payload = Vec::with_capacity(1 + body.len());
    payload.push(command.into());
    payload.extend_from_slice(body);

    let msg = Message::new(channel, Command::Cbor, &payload)
        .map_err(|_| TransactionError::Hid(HidrawError::MessageTooLarge))?;
    device.send(&msg).await.map_err(TransactionError::Hid)?;
    Ok(())
}

/// Await a CTAPHID_CBOR response and return its CBOR body.
async fn recv_cbor(
    device: &HidDevice,
    channel: u32,
) -> Result<CtaphidCborResponse, TransactionError> {
    let response = device.recv(channel).await.map_err(TransactionError::Hid)?;
    if !matches!(response.command, Command::Cbor) {
        return Err(TransactionError::Hid(HidrawError::Protocol(
            "unexpected CTAPHID command in response",
        )));
    }
    let bytes = response.payload;
    let response = match CtaphidCborResponse::new(bytes) {
        Ok(r) => r,
        Err(CtaphidCborResponseError::ResponseEmpty) => {
            return Err(TransactionError::Hid(HidrawError::Protocol(
                "empty CTAPHID_CBOR response",
            )));
        }
        Err(CtaphidCborResponseError::BadStatus(status)) => {
            return Err(TransactionError::Status(StatusCode::from(status)));
        }
    };
    Ok(response)
}

/// Run one CTAPHID_CBOR transaction and return the CBOR body of the response.
///
/// Lifted out of [`LinuxAuthenticator`] so it can also be used during construction
/// before `self` exists.
async fn send_cbor_without_cancel(
    device: &HidDevice,
    channel: u32,
    command: Ctap2Command,
    body: &[u8],
) -> Result<CtaphidCborResponse, TransactionError> {
    send_cbor(device, channel, command, body).await?;
    recv_cbor(device, channel).await
}

#[async_trait::async_trait]
impl Ctap2Api for LinuxAuthenticator {
    async fn get_info(&self) -> Box<get_info::Response> {
        Box::new(self.info())
    }

    async fn make_credential(
        &mut self,
        request: make_credential::Request,
    ) -> Result<make_credential::Response, StatusCode> {
        LinuxAuthenticator::make_credential(self, request).await
    }

    async fn get_assertion(
        &mut self,
        request: get_assertion::Request,
    ) -> Result<get_assertion::Response, StatusCode> {
        LinuxAuthenticator::get_assertion(self, request).await
    }
}
