//! <https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo>
use std::num::NonZeroU128;

use serde::{Deserialize, Serialize};

use crate::{utils::serde::ignore_unknown_opt_vec, webauthn::AuthenticatorTransport};

use super::Aaguid;

serde_workaround! {
    /// An Authenticator's metadata and capabilities.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Response {
        /// List of supported versions.
        /// Supported versions are:
        /// * "FIDO_2_0" for CTAP2 / FIDO2 / Web Authentication authenticators
        /// * "U2F_V2" for CTAP1/U2F authenticators.
        #[serde(rename = 0x01)]
        pub versions: Vec<Version>,

        /// List of supported extensions. (Optional)
        #[serde(rename = 0x02, default, skip_serializing_if = Option::is_none)]
        pub extensions: Option<Vec<Extension>>,

        /// The claimed AAGUID. 16 bytes in length
        #[serde(rename = 0x03)]
        pub aaguid: Aaguid,

        /// List of supported options.
        #[serde(rename = 0x04, default, skip_serializing_if = Option::is_none)]
        pub options: Option<Options>,

        /// Maximum message size supported by the authenticator. By default, authenticators MUST support
        /// messages of at least 1024 bytes.
        ///
        /// This can be passed as a CBOR unsigned number so a u128 is used as the backing value since it
        /// is the maximum a CBOR number can represent.
        #[serde(rename = 0x05, default, skip_serializing_if = Option::is_none)]
        pub max_msg_size: Option<NonZeroU128>,

        /// List of supported PIN Protocol versions.
        ///
        /// If we ever end up with more than 256 pin protocols, an enhancement request should be filed.
        #[serde(rename = 0x06, default, skip_serializing_if = Option::is_none)]
        pub pin_protocols: Option<Vec<u8>>,

        /// List of supported transports. Values are taken from the [`AuthenticatorTransport`] enum.
        /// The list MUST NOT include duplicate values nor be empty if present.
        /// Platforms MUST tolerate unknown values by ignoring them.
        #[serde(
            rename = 0x09,
            default,
            skip_serializing_if = Option::is_none,
            deserialize_with = ignore_unknown_opt_vec
        )]
        pub transports: Option<Vec<AuthenticatorTransport>>,
    }
}

/// All options are in the form of key-value pairs with string IDs and boolean values.
/// When an option is not present, the default is applied.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    /// Platform Device: Indicates that the device is attached to the client and therefore can’t be
    /// removed and used on another client.
    #[serde(default)]
    pub plat: bool,

    /// Resident Key: Indicates that the device is capable of storing keys on the device itself and
    /// therefore can satisfy the authenticatorGetAssertion request with allowList parameter not
    /// specified or empty.
    #[serde(default)]
    pub rk: bool,

    /// Client Pin:
    /// If `Some(true)`, it indicates that the device is capable of accepting a PIN from
    /// the client and PIN has been set.
    ///
    /// If `Some(false)`, it indicates that the device is capable of accepting a PIN from
    /// the client and PIN has not been set yet.
    ///
    /// If `None`, it indicates that the device is not capable of accepting a PIN from the client.
    ///
    /// Client PIN is one of the ways to do user verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_pin: Option<bool>,

    /// User Presence: Indicates that the device is capable of testing user presence.
    #[serde(default = "default_true")]
    pub up: bool,

    /// User Verification: Indicates that the device is capable of verifying the user within itself.
    /// For example, devices with UI, biometrics fall into this category.
    ///
    /// If `Some(true)`, it indicates that the device is capable of user verification
    /// within itself and has been configured.
    ///
    /// If `Some(false)`, it indicates that the device is capable of user verification
    /// within itself and has not been yet configured. For example, a biometric device that has not
    /// yet been configured will return this parameter set to false.
    ///
    /// If `None`, it indicates that the device is not capable of user verification within itself.
    ///
    /// A device that can only do Client PIN will not return the "uv" parameter.
    ///
    /// If a device is capable of verifying the user within itself as well as able to do Client PIN,
    ///  it will return both "uv" and the Client PIN option.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uv: Option<bool>,
}

#[must_use]
#[inline]
const fn default_true() -> bool {
    true
}

impl Default for Options {
    fn default() -> Self {
        Self {
            plat: false,
            rk: false,
            client_pin: None,
            up: true,
            uv: None,
        }
    }
}

/// CTAP versions supported
#[expect(non_camel_case_types)]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Version {
    /// Universal 2nd Factor version 1.2
    U2F_V2,
    /// Client To Authenticator Protocol version 2.0
    FIDO_2_0,
    /// Unknown version catching the value
    #[serde(untagged)]
    Unknown(String),
}

/// CTAP extensions supported by the authenticator
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Extension {
    /// The authenticator supports the [`hmac-secret`] extension
    ///
    /// [`hmac-secret`]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension
    #[serde(rename = "hmac-secret")]
    HmacSecret,
    /// The authenticator supports the [`hmac-secret-mc`] extension.
    ///
    /// TODO: link to the hmac-secret-mc extension in the spec once it's published.
    #[serde(rename = "hmac-secret-mc")]
    HmacSecretMakeCredential,
    /// The authenticator supports the unsigned [`prf`] extension
    ///
    /// [`prf`]: https://w3c.github.io/webauthn/#prf-extension
    #[serde(rename = "prf")]
    Prf,
    /// The authenticator supports an extensions which is currently unsupported by this library.
    #[serde(untagged)]
    Unknown(String),
}

#[cfg(test)]
mod tests;
