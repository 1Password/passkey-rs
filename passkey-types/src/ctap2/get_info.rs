//! <https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo>
use std::{borrow::Cow, num::NonZeroU128};

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
        pub versions: Vec<Cow<'static, str>>,

        /// List of supported extensions. (Optional)
        #[serde(rename = 0x02, default, skip_serializing_if = Option::is_none)]
        pub extensions: Option<Vec<Cow<'static, str>>>,

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
        /// If we ever end up with more than 256 pin protocols, an enhacement request should be filed.
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

#[cfg(test)]
mod tests {
    use ciborium::cbor;

    use super::{Aaguid, AuthenticatorTransport, Options, Response};
    #[test]
    fn serialization_round_trip() {
        let expected = Response {
            versions: vec!["FIDO_2_0".into()],
            extensions: None,
            aaguid: Aaguid::new_empty(),
            options: Some(Options {
                rk: true,
                uv: Some(true),
                ..Default::default()
            }),
            max_msg_size: None,
            pin_protocols: Some(vec![1]),
            transports: Some(vec![
                AuthenticatorTransport::Internal,
                AuthenticatorTransport::Hybrid,
            ]),
        };
        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&expected, &mut serialized)
            .expect("Could not serialize to cbor");

        let deserialized: Response =
            ciborium::de::from_reader(serialized.as_slice()).expect("Could not deserialize");

        assert_eq!(deserialized, expected);
    }

    #[test]
    fn serialization_expected_wire_fmt() {
        let aaguid = Aaguid::new_empty();
        let input = Response {
            versions: vec!["FIDO_2_0".into()],
            extensions: None,
            aaguid,
            options: Some(Options {
                rk: true,
                uv: Some(true),
                plat: false,
                ..Default::default()
            }),
            max_msg_size: None,
            pin_protocols: Some(vec![1]),
            transports: Some(vec![
                AuthenticatorTransport::Internal,
                AuthenticatorTransport::Hybrid,
            ]),
        };
        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&input, &mut serialized).expect("Could not serialize to cbor");

        let deserialized: ciborium::value::Value =
            ciborium::de::from_reader(serialized.as_slice()).expect("Could not deserialize");

        let expected = cbor!({
            0x01 => vec!["FIDO_2_0"],
            // extensions should be skiped
            0x03 => ciborium::value::Value::Bytes([0;16].into()),
            0x04 => {
                "plat" => false,
                "rk" => true,
                "up" => true,
                "uv" => true
                // clientPin should be skipped
            },
            // maxMsgSize should be skipped
            0x06 => vec![1],
            0x09 => vec!["internal", "hybrid"]
        })
        .unwrap();

        assert_eq!(deserialized, expected);
    }

    #[test]
    fn unknown_gets_ignored() {
        let input = cbor!({
            0x01 => vec!["FIDO_2_0"],
            // extensions should be skiped
            0x03 => ciborium::value::Value::Bytes([0;16].into()),
            0x04 => {
                "plat" => false,
                "rk" => true,
                "up" => true,
                "uv" => true
                // clientPin should be skipped
            },
            // maxMsgSize should be skipped
            0x06 => vec![1],
            0x09 => vec!["lora", "hybrid"]
        })
        .unwrap();

        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&input, &mut serialized).expect("Could not serialize to cbor");

        let deserialized: Response =
            ciborium::de::from_reader(serialized.as_slice()).expect("Could not deserialize");

        let expected = Response {
            versions: vec!["FIDO_2_0".into()],
            extensions: None,
            aaguid: Aaguid::new_empty(),
            options: Some(Options {
                rk: true,
                uv: Some(true),
                plat: false,
                ..Default::default()
            }),
            max_msg_size: None,
            pin_protocols: Some(vec![1]),
            transports: Some(vec![AuthenticatorTransport::Hybrid]),
        };

        assert_eq!(expected, deserialized);
    }
}
