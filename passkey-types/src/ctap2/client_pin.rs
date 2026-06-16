use bitflags::bitflags;
use serde::{Deserialize, Serialize};

use crate::Bytes;

serde_workaround! {
    /// Request type for the authenticatorClientPin command.
    pub struct Request {
        /// PIN/UV protocol chosen by the Client.
        #[serde(rename = 0x01; default, skip_serializing_if = Option::is_none)]
        pub pin_uv_auth_protocol: Option<u8>,

        ///
        #[serde(rename = 0x02)]
        pub sub_command: u8,

        #[serde(
            rename = 0x03;
            default,
            skip_serializing_if = Option::is_none,
            serialize_with = crate::utils::serde::cose_key::option::serialize,
            deserialize_with = crate::utils::serde::cose_key::option::deserialize
        )]
        pub key_agreement: Option<coset::CoseKey>,

        #[serde(rename = 0x04; default, skip_serializing_if = Option::is_none)]
        pub pin_uv_auth_param: Option<Bytes>,

        #[serde(rename = 0x05; default, skip_serializing_if = Option::is_none)]
        pub new_pin_enc: Option<Bytes>,

        #[serde(rename = 0x06; default, skip_serializing_if = Option::is_none)]
        pub pin_hash_enc: Option<Bytes>,

        // TODO: change this from a u8 to a bitfield
        #[serde(rename = 0x09; default, skip_serializing_if = Option::is_none)]
        pub permissions: Option<Permissions>,

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

        #[serde(rename = 0x02; default, skip_serializing_if = Option::is_none)]
        pub pin_uv_auth_token: Option<Bytes>,

        #[serde(rename = 0x03; default, skip_serializing_if = Option::is_none)]
        pub pin_retries: Option<u32>,

        #[serde(rename = 0x04; default, skip_serializing_if = Option::is_none)]
        pub power_cycle_state: Option<bool>,

        #[serde(rename = 0x05; default, skip_serializing_if = Option::is_none)]
        pub uv_retries: Option<u32>,
    }
}

bitflags! {
    #[derive(Serialize, Deserialize)]
    pub struct Permissions: u8 {
        const MC = 0x01;
        const GA = 0x02;
        const CM = 0x04;
        const BE = 0x08;
        const LBW = 0x10;
        const ACFG = 0x20;
        const PCMR = 0x40;
    }
}
