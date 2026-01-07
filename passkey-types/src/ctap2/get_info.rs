//! <https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo>
use std::num::NonZeroU128;

use serde::{Deserialize, Serialize};

use crate::{
    Bytes,
    utils::serde::ignore_unknown_opt_vec,
    webauthn::{AuthenticatorTransport, PublicKeyCredentialParameters},
};

use super::Aaguid;

#[cfg(doc)]
use crate::webauthn;

serde_workaround! {
    /// An Authenticator's metadata and capabilities.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct Response {
        /// List of supported versions.
        /// Supported versions are:
        /// * "FIDO_2_0" for CTAP2 / FIDO2 / Web Authentication authenticators
        /// * "U2F_V2" for CTAP1/U2F authenticators.
        #[serde(rename = 0x01)]
        pub versions: Vec<Version>,

        /// List of supported extensions. (Optional)
        #[serde(rename = 0x02; default, skip_serializing_if = Option::is_none)]
        pub extensions: Option<Vec<Extension>>,

        /// The claimed AAGUID. 16 bytes in length
        #[serde(rename = 0x03)]
        pub aaguid: Aaguid,

        /// List of supported options.
        #[serde(rename = 0x04; default, skip_serializing_if = Option::is_none)]
        pub options: Option<Options>,

        /// Maximum message size supported by the authenticator. By default, authenticators MUST support
        /// messages of at least 1024 bytes.
        ///
        /// This can be passed as a CBOR unsigned number so a u128 is used as the backing value since it
        /// is the maximum a CBOR number can represent.
        #[serde(rename = 0x05; default, skip_serializing_if = Option::is_none)]
        pub max_msg_size: Option<NonZeroU128>,

        /// List of supported PIN Protocol versions.
        ///
        /// If we ever end up with more than 256 pin protocols, an enhancement request should be filed.
        #[serde(rename = 0x06; default, skip_serializing_if = Option::is_none)]
        pub pin_protocols: Option<Vec<u8>>,

        /// List of supported transports. Values are taken from the [`AuthenticatorTransport`] enum.
        /// The list MUST NOT include duplicate values nor be empty if present.
        /// Platforms MUST tolerate unknown values by ignoring them.
        #[serde(
            rename = 0x09;
            default,
            skip_serializing_if = Option::is_none,
            deserialize_with = ignore_unknown_opt_vec
        )]
        pub transports: Option<Vec<AuthenticatorTransport>>,

        /// List of supported algorithms for credential generation, as specified in [webauthn].
        /// The array is ordered from most preferred to least preferred
        /// and MUST NOT include duplicate entries nor be empty if present.
        /// [`PublicKeyCredentialParameters`]' algorithm identifiers are values that
        /// SHOULD be registered in the IANA COSE Algorithms registry [`coset::iana::Algorithm`].
        #[serde(
            rename = 0x0A;
            default,
            skip_serializing_if = Option::is_none,
            deserialize_with = ignore_unknown_opt_vec
        )]
        pub algorithms: Option<Vec<PublicKeyCredentialParameters>>,

        /// The maximum size, in bytes, of the serialized large-blob array that this authenticator can store.
        /// If the authenticatorLargeBlobs command is supported, this MUST be specified.
        /// Otherwise it MUST NOT be. If specified, the value MUST be ≥ 1024.
        /// Thus, 1024 bytes is the least amount of storage an authenticator must make available for
        /// per-credential serialized large-blob arrays if it supports the large, per-credential blobs feature.
        /// This value is not specified and not pertinent if the authenticator implements the largeBlob extension.
        #[serde(
            rename = 0x0B;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub mac_serialized_large_blob_array: Option<u32>,

        /// If this member is:
        /// * present and set to true
        ///     * getPinToken and getPinUvAuthTokenUsingPinWithPermissions will return errors
        ///       until after a successful PIN Change.
        /// * present and set to false, or absent.
        ///     * no PIN Change is required.
        #[serde(
            rename = 0x0C;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub force_pin_change: Option<bool>,

        /// This specifies the current minimum PIN length, in Unicode code points,
        /// the authenticator enforces for ClientPIN.
        /// This is applicable for ClientPIN only:
        /// the minPINLength member MUST be absent if the clientPin option ID is absent;
        /// it MUST be present if the authenticator supports authenticatorClientPIN.
        #[serde(
            rename = 0x0D;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub min_pin_length: Option<u32>,

        /// Indicates the firmware version of the authenticator model identified by AAGUID.
        /// Whenever releasing any code change to the authenticator firmware, authenticator MUST increase the version.
        #[serde(
            rename = 0x0E;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub firmware_version: Option<u32>,

        /// Maximum credBlob length in bytes supported by the authenticator.
        /// Must be present if, and only if, credBlob is included in the supported extensions list.
        /// If present, this value MUST be at least 32 bytes.
        #[serde(
            rename = 0x0F;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub max_cred_blob_length: Option<u32>,

        /// This specifies the max number of RP ID that the authenticator will accept via setMinPINLength subcommand.
        /// The platform MUST NOT send more than this number of RP ID to the setMinPINLength subcommand.
        /// This is in addition to pre-configured list authenticator may have.
        /// If the authenticator does not support adding additional RP IDs, its value is 0.
        /// This MUST ONLY be present if, and only if, the authenticator supports the setMinPINLength subcommand.
        #[serde(
            rename = 0x10;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub max_rpids_for_set_min_pin_length: Option<u32>,

        /// This specifies the preferred number of invocations of the getPinUvAuthTokenUsingUvWithPermissions
        /// subCommand the platform may attempt before falling back to the getPinUvAuthTokenUsingPinWithPermissions
        /// subCommand or displaying an error. MUST be greater than zero.
        /// If the value is 1 then all uvRetries are internal and the platform MUST only invoke the
        /// getPinUvAuthTokenUsingUvWithPermissions subCommand a single time.
        /// If the value is > 1 the authenticator MUST only decrement uvRetries by 1 for each iteration.
        #[serde(
            rename = 0x11;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub preferred_platform_uv_attempts: Option<u32>,

        /// This specifies the user verification modality supported by the authenticator via authenticatorClientPIN’s
        /// getPinUvAuthTokenUsingUvWithPermissions subcommand. This is a hint to help the platform construct user dialogs.
        /// The values are defined in FIDORegistry Section 3.1 User Verification Methods.
        /// Combining multiple bit-flags from the FIDORegistry is allowed.
        /// If clientPin is supported it MUST NOT be included in the bit-flags,
        /// as clientPIN is not a built-in user verification method.
        #[serde(
            rename = 0x12;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub uv_modality: Option<u32>,

        // /// This specifies a list of [authenticator certifications][1].
        // /// The value should be a [`Value::Map`], but there is no way to define this in a consistent way in the type.
        // ///
        // /// [1]: https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-feature-descriptions-certifications
        // #[serde(
        //     rename = 0x13,
        //     default,
        //     skip_serializing_if = Option::is_none
        // )]
        // pub certifications: Option<Value>,

        /// If this member is present it indicates the estimated number of additional discoverable credentials that can be stored.
        /// If this value is zero then platforms SHOULD create non-discoverable credentials if possible.
        #[serde(
            rename = 0x14;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub remaining_discoverable_credentials: Option<u32>,

        /// If present the authenticator supports the authenticatorConfig vendorPrototype subcommand,
        /// and its value is a list of authenticatorConfig vendorCommandId values supported, which MAY be empty.
        #[serde(
            rename = 0x15;
            default,
            skip_serializing_if = Option::is_none,
            deserialize_with = ignore_unknown_opt_vec
        )]
        pub vendor_prototype_config_commands: Option<Vec<u32>>,

        /// List of supported attestation formats.
        /// Authenticators that support multiple attestation formats, not counting "none", MUST set this field.
        /// Otherwise it is optional.
        #[serde(
            rename = 0x16;
            default,
            skip_serializing_if = Option::is_none,
            deserialize_with = ignore_unknown_opt_vec
        )]
        pub attestation_formats: Option<Vec<String>>,

        /// If present the number of internal User Verification operations since the last pin entry including all failed attempts.
        /// This allows the platform to periodically prompt the user for PIN on a biometric device so they don’t forget the PIN.
        /// This is optional platform behavior and the interval is at the discretion of the platform.
        #[serde(
            rename = 0x17;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub uv_count_since_last_pin_entry: Option<u32>,

        /// If present the authenticator requires a 10 second touch for reset.
        #[serde(
            rename = 0x18;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub long_touch_for_reset: Option<bool>,

        /// The value is a byte value containing iv || ct.
        /// Where ct is the AES-128-CBC encryption of (128-bit device identifier) using
        /// HKDF-SHA-256(salt = 32 zero bytes, IKM = persistentPinUvAuthToken, L = 16, info = "encIdentifier").
        /// The encryption iv must be regenerated for each output of getInfo.
        #[serde(
            rename = 0x19;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub enc_identifier: Option<Bytes>,

        /// List of transports that support the reset command.
        /// The list MUST NOT include duplicate values nor be empty if present.
        /// Platforms MUST tolerate unknown values.
        #[serde(
            rename = 0x1A;
            default,
            skip_serializing_if = Option::is_none,
            deserialize_with = ignore_unknown_opt_vec
        )]
        pub transports_for_reset: Option<Vec<AuthenticatorTransport>>,

        /// If present, whether the authenticator is enforcing an additional current PIN complexity policy beyond minPINLength.
        /// PIN complexity policies for authenticators are listed in the FIDO MDS.
        /// The authenticator may have a pre-configured PIN complexity policy value that is applied after a reset.
        #[serde(
            rename = 0x1B;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub pin_complexity_policy: Option<bool>,

        /// If present, a URL that the platform can use to provide the user more information about the enforced PIN policy.
        #[serde(
            rename = 0x1C;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub pin_complexity_policy_url: Option<Bytes>,

        /// This specifies the maximum PIN length, in Unicode code points, the authenticator enforces for ClientPIN.
        /// An authenticator setting this value still MUST restrict the PIN to be represented in 63 or fewer bytes.
        #[serde(
            rename = 0x1D;
            default,
            skip_serializing_if = Option::is_none
        )]
        pub max_pin_length: Option<u32>,
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

    /// If pinUvAuthToken is:
    ///
    /// `Some(true)`, then the authenticator supports authenticatorClientPIN’s getPinUvAuthTokenUsingPinWithPermissions subcommand.
    /// If the uv option id is present and set to true, then the authenticator supports authenticatorClientPIN’s
    /// getPinUvAuthTokenUsingUvWithPermissions subcommand.
    ///
    /// `Some(false)` or `None`, the authenticator does not support authenticatorClientPIN’s getPinUvAuthTokenUsingPinWithPermissions
    /// and getPinUvAuthTokenUsingUvWithPermissions subcommands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_token: Option<bool>,

    /// If this noMcGaPermissionsWithClientPin is:
    ///
    /// `Some(true)`, A pinUvAuthToken obtained via getPinUvAuthTokenUsingPinWithPermissions
    /// (or getPinToken) cannot be used for authenticatorMakeCredential or authenticatorGetAssertion commands,
    /// because it will lack the necessary mc and ga permissions.
    /// In this situation, platforms SHOULD NOT attempt to use getPinUvAuthTokenUsingPinWithPermissions if using
    /// getPinUvAuthTokenUsingUvWithPermissions fails.
    ///
    /// `Some(false)` or `None`, A pinUvAuthToken obtained via getPinUvAuthTokenUsingPinWithPermissions
    /// (or getPinToken) can be used for authenticatorMakeCredential or authenticatorGetAssertion commands.
    ///
    /// Note: noMcGaPermissionsWithClientPin MUST only be present if the [`Self::client_pin`] field is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_mc_ga_permissions_with_client_pin: Option<bool>,

    /// If largeBlobs is:
    /// `Some(true)`, the authenticator supports the authenticatorLargeBlobs command.
    ///
    /// `Some(false)` or `None`, The authenticatorLargeBlobs command is NOT supported.
    ///
    /// This option MUST NOT be set to true if the largeBlob extension is supported instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub large_blobs: Option<bool>,

    /// Enterprise Attestation feature support:
    ///
    /// If ep is `Some(true)`, The authenticator is enterprise attestation capable,
    /// and enterprise attestation is enabled.
    ///
    /// If ep is `Some(false)`, The authenticator is enterprise attestation capable,
    /// and enterprise attestation is disabled.
    ///
    /// If ep is `None`, The Enterprise Attestation feature is NOT supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ep: Option<bool>,

    /// If bioEnroll is:
    ///
    /// `Some(true)`, the authenticator supports the authenticatorBioEnrollment commands,
    ///  and has at least one bio enrollment presently provisioned.
    ///
    /// `Some(false)`, the authenticator supports the authenticatorBioEnrollment commands,
    /// and does not yet have any bio enrollments provisioned.
    ///
    /// `None`, the authenticatorBioEnrollment commands are NOT supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bio_enroll: Option<bool>,

    /// "FIDO_2_1_PRE" Prototype Bio enrollment support:
    ///
    /// If is `Some(true)`, the authenticator supports the Prototype authenticatorBioEnrollment (0x40) commands,
    /// and has at least one bio enrollment presently provisioned.
    ///
    /// If is `Some(false)`, the authenticator supports the Prototype authenticatorBioEnrollment (0x40) commands,
    /// and does not yet have any bio enrollments provisioned.
    ///
    /// If is `None`, the Prototype authenticatorBioEnrollment (0x40) commands are not supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_verification_mgmt_preview: Option<bool>,

    /// getPinUvAuthTokenUsingUvWithPermissions support for requesting the be permission.
    /// This option ID MUST only be present if [`Self::bio_enroll`] is also present.
    ///
    /// If is `Some(true)`, requesting the be permission when invoking getPinUvAuthTokenUsingUvWithPermissions is supported.
    ///
    /// If is `Some(false)` or `None`, requesting the be permission when invoking
    /// getPinUvAuthTokenUsingUvWithPermissions is NOT supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uv_bio_enroll: Option<bool>,

    /// authenticatorConfig command support:
    ///
    /// If is `Some(true)`, the authenticatorConfig command is supported.
    ///
    /// If is `Some(false)` or `None`, the authenticatorConfig command is NOT supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authnr_cfg: Option<bool>,

    /// getPinUvAuthTokenUsingUvWithPermissions support for requesting the acfg permission.
    /// This option ID MUST only be present if [`Self::authnr_cfg`] is also present.
    ///
    /// If is `Some(true)`, requesting the acfg permission when invoking
    /// getPinUvAuthTokenUsingUvWithPermissions is supported.
    ///
    /// If is `Some(false)` or `None`, requesting the acfg permission when invoking
    /// getPinUvAuthTokenUsingUvWithPermissions is NOT supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uv_acfg: Option<bool>,

    /// Credential management support:
    ///
    /// If is `Some(true)`, the authenticatorCredentialManagement command is supported.
    ///
    /// If is `Some(false)` or `None`, the authenticatorCredentialManagement command is NOT supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cred_mgmt: Option<bool>,

    /// Credential management Read Only support:
    ///
    /// If is `Some(true)`, requesting the pcmr permission when invoking
    /// getPinUvAuthTokenUsingUvWithPermissions or getPinUvAuthTokenUsingPinWithPermissions is supported.
    ///
    /// If is `Some(false)` or `None`, requesting the pcmr permission when invoking
    /// getPinUvAuthTokenUsingUvWithPermissions or getPinUvAuthTokenUsingPinWithPermissions is NOT supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_mgmt_preview: Option<bool>,

    /// Support for the Set Minimum PIN Length feature.
    ///
    /// If is `Some(true)`, the setMinPINLength subcommand is supported.
    ///
    /// If is `Some(false)` or `None`, the setMinPINLength subcommand is NOT supported.
    ///
    /// Note: setMinPINLength MUST only be present if the [`Self::client_pin`] option ID is present.
    #[serde(
        rename = "setMinPINLength",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub set_min_pin_length: Option<bool>,

    /// Support for making non-discoverable credentials without requiring User Verification.
    ///
    /// If is `Some(true)`, the authenticator allows creation of non-discoverable credentials
    /// without requiring any form of user verification, if the platform requests this behaviour.
    ///
    /// If is `Some(false)` or `None`, the authenticator requires some form of user verification
    /// for creating non-discoverable credentials, regardless of the parameters the platform supplies
    /// for the authenticatorMakeCredential command.
    ///
    /// Authenticators SHOULD include this option with the value true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub make_cred_uv_not_rqd: Option<bool>,

    /// Support for the Always Require User Verification feature:
    ///
    /// If is `Some(true)`, the authenticator supports the Always Require User Verification feature
    /// and it is enabled.
    ///
    /// If is `Some(false)`, the authenticator supports the Always Require User Verification feature
    /// but it is disabled.
    ///
    /// If is `None`, the authenticator does not support the Always Require User Verification feature.
    ///
    /// Note: If the alwaysUv option ID is present and true the authenticator MUST set the value of
    /// [`Self::make_cred_uv_not_rqd`] to false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub always_uv: Option<bool>,
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
            pin_uv_auth_token: None,
            no_mc_ga_permissions_with_client_pin: None,
            large_blobs: None,
            ep: None,
            bio_enroll: None,
            user_verification_mgmt_preview: None,
            uv_bio_enroll: None,
            authnr_cfg: None,
            uv_acfg: None,
            cred_mgmt: None,
            credential_mgmt_preview: None,
            set_min_pin_length: None,
            make_cred_uv_not_rqd: None,
            always_uv: None,
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
    /// Client To Authenticator Protocol version 2.1
    FIDO_2_1,
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
    /// [`hmac-secret-mc`]: https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#sctn-hmac-secret-make-cred-extension
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
