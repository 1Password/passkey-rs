use crate::ctap2::Flags;
use std::array::TryFromSliceError;

use super::ResponseStatusWords;

/// The authentication Request MUST come with a parameter to determine it's use
#[repr(u8)]
#[derive(Debug)]
pub enum AuthenticationParameter {
    /// If the control byte is set to 0x07 by the FIDO Client, the U2F token is supposed to simply
    /// check whether the provided key handle was originally created by this token, and whether it
    /// was created for the provided application parameter. If so, the U2F token MUST respond with
    /// an authentication response message:error:test-of-user-presence-required (note that despite
    /// the name this signals a success condition). If the key handle was not created by this U2F
    /// token, or if it was created for a different application parameter, the token MUST respond
    /// with an authentication response message:error:bad-key-handle.
    CheckOnly = 0x07,

    /// If the FIDO client sets the control byte to 0x03, then the U2F token is supposed to perform
    /// a real signature and respond with either an authentication response message:success or an
    /// appropriate error response (see below). The signature SHOULD only be provided if user
    /// presence could be validated.
    EnforceUserPresence = 0x03,

    /// If the FIDO client sets the control byte to 0x08, then the U2F token is supposed to perform
    /// a real signature and respond with either an authentication response message:success or an
    /// appropriate error response (see below). The signature MAY be provided without validating
    /// user presence.
    DontEnforceUserPresence = 0x08,
}

impl From<AuthenticationParameter> for u8 {
    #[allow(clippy::as_conversions)]
    fn from(src: AuthenticationParameter) -> Self {
        src as u8
    }
}

impl From<u8> for AuthenticationParameter {
    fn from(src: u8) -> Self {
        match src {
            0x07 => AuthenticationParameter::CheckOnly,
            0x03 => AuthenticationParameter::EnforceUserPresence,
            0x08 => AuthenticationParameter::DontEnforceUserPresence,
            _ => unreachable!("U2F Authentication parameter which is not in the spec"),
        }
    }
}

/// This message is used to initiate a U2F token authentication. The FIDO Client first contacts the
/// relying party to obtain a challenge, and then constructs the authentication request message.
#[derive(Debug)]
pub struct AuthenticationRequest {
    /// During registration, the FIDO Client MAY send authentication request messages to the U2F
    /// token to figure out whether the U2F token has already been registered. In this case, the
    /// FIDO client will use the [`AuthenticationParameter::CheckOnly`] value for the control byte.
    /// In all other cases (i.e., during authentication), the FIDO Client MUST use the
    /// [`AuthenticationParameter::EnforceUserPresence`] or
    /// [`AuthenticationParameter::DontEnforceUserPresence`]
    pub parameter: AuthenticationParameter,
    /// The challenge parameter is the SHA-256 hash of the Client Data, a stringified JSON data
    /// structure that the FIDO Client prepares. Among other things, the Client Data contains the
    /// challenge from the relying party (hence the name of the parameter).
    pub challenge: [u8; 32],
    /// The application parameter is the SHA-256 hash of the UTF-8 encoding of the application
    /// identity of the application requesting the authentication as provided by the relying party.
    pub application: [u8; 32],
    /// This is provided by the relying party, and was obtained by the relying party during registration.
    pub key_handle: Vec<u8>,
}

impl AuthenticationRequest {
    /// Try parsing a data payload into an authentication request with the given parameter taken from
    /// the u2f message frame.
    #[allow(clippy::as_conversions)]
    pub fn try_from(
        data: &[u8],
        parameter: impl Into<AuthenticationParameter>,
    ) -> Result<Self, TryFromSliceError> {
        let (challenge, data) = data.split_at(32);
        let (application, data) = data.split_at(32);
        let (handle_len, data) = data.split_at(1);
        let key_handle = data[..handle_len[0] as usize].to_vec();
        Ok(Self {
            parameter: parameter.into(),
            challenge: challenge.try_into()?,
            application: application.try_into()?,
            key_handle,
        })
    }
}

/// This message is output by the U2F token after processing/signing the [`AuthenticationRequest`]
/// message. Its raw representation is the concatenation of its fields.
pub struct AuthenticationResponse {
    /// Whether user presence was verified or not
    pub user_presence: Flags,
    /// This a counter value that the U2F token increments every time it performs an authentication
    /// operation. It must be transported as big endian representation.
    pub counter: u32,
    /// This is a ECDSA signature (on P-256) over the following byte string.
    /// 1. The application parameter [32 bytes] from the authentication request message.
    /// 2. The above user presence byte [1 byte].
    /// 3. The above counter [4 bytes].
    /// 4. The challenge parameter [32 bytes] from the authentication request message.
    ///
    /// The signature is encoded in ANSI X9.62 format (see [ECDSA-ANSI] in bibliography). The
    /// signature is to be verified by the relying party using the public key obtained during
    /// registration.
    pub signature: Vec<u8>,
}

impl AuthenticationResponse {
    /// Encode the response to its successfull binary representation
    pub fn encode(self) -> Vec<u8> {
        [self.user_presence.into()]
            .into_iter()
            .chain(self.counter.to_be_bytes())
            .chain(self.signature)
            .chain(u16::from(ResponseStatusWords::NoError).to_be_bytes()) // NoError indicates success
            .collect()
    }
}
