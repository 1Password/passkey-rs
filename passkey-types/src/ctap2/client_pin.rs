//! <https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorClientPIN>
use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::Bytes;

serde_workaround! {
    /// Request type for the authenticatorClientPin command.
    pub struct Request {
        /// PIN/UV protocol chosen by the Client.
        #[serde(rename = 0x01; default, skip_serializing_if = Option::is_none)]
        pub pin_uv_auth_protocol: Option<u8>,

        /// TODO: make this just use the subcommand enum
        #[serde(rename = 0x02)]
        pub sub_command: u8,

        /// The platform key-agreement key.
        #[serde(
            rename = 0x03;
            default,
            skip_serializing_if = Option::is_none,
            serialize_with = crate::utils::serde::cose_key::option::serialize,
            deserialize_with = crate::utils::serde::cose_key::option::deserialize
        )]
        pub key_agreement: Option<coset::CoseKey>,

        /// The output of calling authenticate on some context specific to the subcommand.
        #[serde(rename = 0x04; default, skip_serializing_if = Option::is_none)]
        pub pin_uv_auth_param: Option<Bytes>,

        /// An encrypted PIN.
        #[serde(rename = 0x05; default, skip_serializing_if = Option::is_none)]
        pub new_pin_enc: Option<Bytes>,

        /// An encrypted proof-of-knowledge of a PIN.
        #[serde(rename = 0x06; default, skip_serializing_if = Option::is_none)]
        pub pin_hash_enc: Option<Bytes>,

        /// Bitfield of permissions. If present, MUST NOT be 0.
        #[serde(rename = 0x09; default, skip_serializing_if = Option::is_none)]
        pub permissions: Option<Permissions>,

        /// The RP ID to assign as the permissions RP ID.
        #[serde(rename = 0x0A; default, skip_serializing_if = Option::is_none)]
        pub rp_id: Option<String>,
    }
}

serde_workaround! {
    /// authenticatorClientPin response.
    #[derive(Default)]
    pub struct Response {
        /// Result of getPublicKey.
        #[serde(
            rename = 0x01;
            default,
            serialize_with = crate::utils::serde::cose_key::option::serialize,
            deserialize_with = crate::utils::serde::cose_key::option::deserialize
        )]
        pub key_agreement: Option<coset::CoseKey>,

        /// The pinUvAuthToken, encrypted by calling encrypt with the shared secret as the key.
        #[serde(rename = 0x02; default, skip_serializing_if = Option::is_none)]
        pub pin_uv_auth_token: Option<Bytes>,

        /// Number of PIN attempts remaining before lockout.
        #[serde(rename = 0x03; default, skip_serializing_if = Option::is_none)]
        pub pin_retries: Option<u32>,

        /// Present and true if the authenticator requires a power cycle before any future PIN
        /// operation, false if no power cycle needed. If the field is omitted, no information is
        /// given about whether a power cycle is needed or not.
        #[serde(rename = 0x04; default, skip_serializing_if = Option::is_none)]
        pub power_cycle_state: Option<bool>,

        /// Number of uv attempts remaining before lockout.
        #[serde(rename = 0x05; default, skip_serializing_if = Option::is_none)]
        pub uv_retries: Option<u32>,
    }
}

bitflags! {
    /// Permissions field of `authenticatorClientPin` request.
    #[derive(Serialize, Deserialize)]
    pub struct Permissions: u8 {
        /// MakeCredential
        const MC = 0x01;

        /// GetAssertion
        const GA = 0x02;

        /// Credential Management
        const CM = 0x04;

        /// Bio Enrollment
        const BE = 0x08;

        /// Large Blob Write
        const LBW = 0x10;

        /// Authenticator Configuration
        const ACFG = 0x20;

        /// Persistent Credential Management Read Only
        const PCMR = 0x40;
    }
}
