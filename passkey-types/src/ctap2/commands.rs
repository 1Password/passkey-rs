use serde::{Deserialize, Serialize};

/// Authenticator commands enumerated by the CTAP 2 specification.
#[repr(u8)]
pub enum Ctap2Command {
    /// CTAP_CMD_MAKE_CREDENTIAL
    MakeCredential = 0x01,
    /// CTAP_CMD_GET_ASSERTION
    GetAssertion = 0x02,
    /// CTAP_CMD_GET_INFO
    GetInfo = 0x04,
    /// CTAP_CMD_CLIENT_PIN
    ClientPin = 0x06,
    /// CTAP_CMD_AUTHENTICATOR_SELECTION
    AuthenticatorSelection = 0x0B,
}

impl From<Ctap2Command> for u8 {
    #[expect(clippy::as_conversions)]
    fn from(value: Ctap2Command) -> Self {
        value as u8
    }
}

/// Possible values for `subCommand` field of `clientPin` request.
#[derive(Clone, Serialize, Deserialize)]
#[serde(into = "u8")]
#[repr(u8)]
pub enum Ctap2ClientPinSubcommand {
    /// getPinRetries
    GetPinRetries = 0x01,
    /// getKeyAgreement
    GetKeyAgreement = 0x02,
    /// getPinToken
    GetPinToken = 0x05,
    /// getPinUvAuthTokenUsingUvWithPermissions
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    /// getUvRetires
    GetUvRetries = 0x07,
    /// getPinUvAuthTokenUsingPinWithPermissions
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

impl From<Ctap2ClientPinSubcommand> for u8 {
    #[expect(clippy::as_conversions)]
    fn from(value: Ctap2ClientPinSubcommand) -> Self {
        value as u8
    }
}
