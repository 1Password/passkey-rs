//! <https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential>

use serde::{Deserialize, Serialize};

use crate::{Bytes, ctap2::AuthenticatorData, webauthn};

#[cfg(doc)]
use {
    crate::webauthn::{
        CollectedClientData, PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    },
    ciborium::value::Value,
};

use super::extensions::{AuthenticatorPrfInputs, AuthenticatorPrfMakeOutputs, HmacGetSecretInput};

serde_workaround! {
    /// While similar in structure to [`PublicKeyCredentialCreationOptions`],
    /// it is not completely identical, namely the presence of the `options` key.
    #[derive(Debug)]
    pub struct Request {
        /// Hash of the ClientData contextual binding specified by host.
        #[serde(rename = 0x01)]
        pub client_data_hash: Bytes,

        /// This [`PublicKeyCredentialRpEntity`] data structure describes a Relying Party with which the
        /// new public key credential will be associated. It contains the Relying party identifier
        /// of type text string, (optionally) a human-friendly RP name of type text string,
        /// and (optionally) a URL of type text string, referencing a RP icon image. The RP name is
        /// to be used by the authenticator when displaying the credential to the user for selection
        /// and usage authorization. The RP name and URL are optional so that the RP can be more
        /// privacy friendly if it chooses to. For example, for authenticators with a display, RP
        /// may not want to display name/icon for single-factor scenarios.
        #[serde(rename = 0x02)]
        pub rp: PublicKeyCredentialRpEntity,

        /// This [`PublicKeyCredentialUserEntity`] data structure describes the user account to
        /// which the new public key credential will be associated at the RP. It contains an
        /// RP-specific user account identifier of type byte array, (optionally) a user name of type
        /// text string, (optionally) a user display name of type text string, and (optionally) a
        /// URL of type text string, referencing a user icon image (of a user avatar, for example).
        /// The authenticator associates the created public key credential with the account
        /// identifier, and MAY also associate any or all of the user name, user display name, and
        /// image data (pointed to by the URL, if any). The user name, display name, and URL are
        /// optional for privacy reasons for single-factor scenarios where only user presence is
        /// required. For example, in certain closed physical environments like factory floors, user
        /// presence only authenticators can satisfy RP’s productivity and security needs. In these
        /// environments, omitting user name, display name and URL makes the credential more privacy
        /// friendly. Although this information is not available without user verification, devices
        /// which support user verification but do not have it configured, can be tricked into
        /// releasing this information by configuring the user verification.
        #[serde(rename = 0x03)]
        pub user: webauthn::PublicKeyCredentialUserEntity,

        /// A sequence of CBOR maps consisting of pairs of PublicKeyCredentialType (a string) and
        /// cryptographic algorithm (a positive or negative integer), where algorithm identifiers
        /// are values that SHOULD be registered in the IANA COSE Algorithms registry
        /// [`coset::iana::Algorithm`]. This sequence is ordered from most preferred (by the RP) to least
        /// preferred.
        #[serde(rename = 0x04)]
        pub pub_key_cred_params: Vec<webauthn::PublicKeyCredentialParameters>,

        /// A sequence of [`PublicKeyCredentialDescriptor`] structures, as specified in [`webauthn`].
        /// The authenticator returns an error if the authenticator already contains one of
        /// the credentials enumerated in this sequence. This allows RPs to limit the creation of
        /// multiple credentials for the same account on a single authenticator.
        #[serde(rename = 0x05, default, skip_serializing_if = Option::is_none)]
        pub exclude_list: Option<Vec<webauthn::PublicKeyCredentialDescriptor>>,

        /// Parameters to influence authenticator operation, as specified in [`webauthn`].
        /// These parameters might be authenticator specific.
        #[serde(rename = 0x06, default, skip_serializing_if = Option::is_none)]
        pub extensions: Option<ExtensionInputs>,

        /// Parameters to influence authenticator operation, see [`Options`] for more details.
        #[serde(rename = 0x07, default)]
        pub options: Options,

        /// First 16 bytes of HMAC-SHA-256 of clientDataHash using pinToken which platform got from
        /// the authenticator: HMAC-SHA-256(pinToken, clientDataHash). (NOT YET SUPPORTED)
        #[serde(rename = 0x08, default, skip_serializing_if = Option::is_none)]
        pub pin_auth: Option<Bytes>,

        /// PIN protocol version chosen by the client
        ///
        /// if ever we hit more than 256 protocol versions, an enhacement request should be filed.
        #[serde(rename = 0x09, default, skip_serializing_if = Option::is_none)]
        pub pin_protocol: Option<u8>,
    }
}

/// This is a copy of [`webauthn::PublicKeyCredentialRpEntity`] but where the `id` is required
/// and the `name` is optional which is the inverse of what is defined in the [WebAuthn]. These are
/// the requirements of the [CTAP2] version of this struct.
///
/// [WebAuthn]: https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity
/// [CTAP2]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    /// The domain of the relying party
    pub id: String,
    /// A human friendly name for the Relying Party
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// This is a copy of [`webauthn::PublicKeyCredentialUserEntity`] with differing optional fields.
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    /// The ID of the user
    pub id: Bytes,
    /// Optional user name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional display name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional URL pointing to a user icon
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

impl From<webauthn::PublicKeyCredentialUserEntity> for PublicKeyCredentialUserEntity {
    fn from(value: webauthn::PublicKeyCredentialUserEntity) -> Self {
        Self {
            id: value.id,
            name: Some(value.name),
            display_name: Some(value.display_name),
            icon_url: None,
        }
    }
}

impl TryFrom<PublicKeyCredentialUserEntity> for webauthn::PublicKeyCredentialUserEntity {
    type Error = &'static str;
    fn try_from(value: PublicKeyCredentialUserEntity) -> Result<Self, Self::Error> {
        match (value.name, value.display_name) {
            (Some(name), Some(display_name)) => Ok(Self {
                id: value.id,
                name,
                display_name,
            }),
            _ => Err(
                "PublicKeyCredentialUserEntity is missing one or more required fields: name, display_name",
            ),
        }
    }
}

/// In the case of a missing `rp_id` on [`webauthn::PublicKeyCredentialRpEntity`] use this to
/// construct a [`PublicKeyCredentialRpEntity`] using a effective domain.
#[non_exhaustive]
#[derive(Debug)]
pub struct MissingRpId {
    /// Human friendly name for the Relying Party, extracted from [`webauthn::PublicKeyCredentialRpEntity::name`].
    pub rp_name: String,
}

impl TryFrom<webauthn::PublicKeyCredentialRpEntity> for PublicKeyCredentialRpEntity {
    type Error = MissingRpId;
    /// Convert the webauthn version of the struct to the CTAP2 version with the effective domain if
    /// the id was not provided.
    fn try_from(value: webauthn::PublicKeyCredentialRpEntity) -> Result<Self, Self::Error> {
        if let Some(id) = value.id {
            Ok(Self {
                id,
                name: Some(value.name),
            })
        } else {
            Err(MissingRpId {
                rp_name: value.name,
            })
        }
    }
}

/// The options that control how an authenticator will behave.
#[derive(Debug, Serialize, Deserialize)]
pub struct Options {
    /// Specifies whether this credential is to be discoverable or not.
    #[serde(default)]
    pub rk: bool,
    /// Instructs the authenticator to require a gesture that verifies the user to complete the request. Examples of such gestures are fingerprint scan or a PIN.
    #[serde(default = "default_true")]
    pub up: bool,
    /// User Verification:
    ///
    /// If the "uv" option is absent, let the "uv" option be treated as being present with the value false.
    #[serde(default)]
    pub uv: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            rk: false,
            up: true,
            uv: false,
        }
    }
}

const fn default_true() -> bool {
    true
}

/// All supported Authenticator extensions inputs during credential creation
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ExtensionInputs {
    /// A boolean value to indicate that this extension is requested by the Relying Party
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension>
    #[serde(
        rename = "hmac-secret",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret: Option<bool>,

    /// The input salts for fetching and deriving a symmetric secret during registration.
    ///
    /// TODO: link to the hmac-secret-mc extension in the spec once it's published.
    #[serde(
        rename = "hmac-secret-mc",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret_mc: Option<HmacGetSecretInput>,

    /// The direct input from a on-system client for the prf extension.
    ///
    /// The output from a request using the `prf` extension will not be signed
    /// and will be un-encrypted.
    /// This input should already be hashed by the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prf: Option<AuthenticatorPrfInputs>,
}

impl ExtensionInputs {
    /// Validates that there is at least one extension field that is `Some`.
    /// If all fields are `None` then this returns `None` as well.
    pub fn zip_contents(self) -> Option<Self> {
        let Self {
            hmac_secret,
            hmac_secret_mc,
            prf,
        } = &self;

        let has_hmac_secret = hmac_secret.is_some();
        let has_hmac_secret_mc = hmac_secret_mc.is_some();
        let has_prf = prf.is_some();

        (has_hmac_secret || has_hmac_secret_mc || has_prf).then_some(self)
    }
}

serde_workaround! {
    /// Upon successful creation of a credential, the authenticator returns an attestation object.
    #[derive(Debug)]
    pub struct Response {
        /// The attestation statement format identifier
        #[serde(rename = 0x01)]
        pub fmt: String,

        /// The authenticator data object
        #[serde(rename = 0x02)]
        pub auth_data: AuthenticatorData,

        /// The attestation statement, whose format is identified by the "fmt" object member.
        /// The client treats it as an opaque object.
        //
        // TODO: Change to a flattened enum when `content, type` serde enums can use numbers as
        // the keys
        #[serde(rename = 0x03)]
        pub att_stmt: ciborium::value::Value,

        /// Indicates whether an enterprise attestation was returned for this credential.
        /// If `ep_att` is absent or present and set to false, then an enterprise attestation was not returned.
        /// If `ep_att` is present and set to true, then an enterprise attestation was returned.
        ///
        /// Enterprise attestation is currently unsupported by this library.
        #[serde(rename = 0x04, default, skip_serializing_if = Option::is_none)]
        pub ep_att: Option<bool>,

        /// Contains the `largeBlobKey` for the credential, if requested with the `largeBlobKey` extension.
        ///
        /// The `largeBlobKey` extension is currently unsupported by this library.
        #[serde(rename = 0x05, default, skip_serializing_if = Option::is_none)]
        pub large_blob_key: Option<Bytes>,

        /// A map, keyed by extension identifiers, to unsigned outputs of extensions, if any.
        /// Authenticators SHOULD omit this field if no processed extensions define unsigned outputs.
        /// Clients MUST treat an empty map the same as an omitted field.
        #[serde(rename = 0x06, default, skip_serializing_if = Option::is_none)]
        pub unsigned_extension_outputs: Option<UnsignedExtensionOutputs>,
    }
}

/// All supported Authenticator extensions outputs during credential creation
///
/// This is to be serialized to [`Value`] in [`AuthenticatorData::extensions`]
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedExtensionOutputs {
    /// A boolean value to indicate that this extension was successfully processed by the extension
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension>
    #[serde(
        rename = "hmac-secret",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret: Option<bool>,

    /// Outputs the symmetric secrets after successfull processing. The output MUST be encrypted.
    ///
    /// TODO: link to the hmac-secret-mc extension in the spec once it's published.
    #[serde(
        rename = "hmac-secret-mc",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret_mc: Option<Bytes>,
}

impl SignedExtensionOutputs {
    /// Validates that there is at least one extension field that is `Some`.
    /// If all fields are `None` then this returns `None` as well.
    pub fn zip_contents(self) -> Option<Self> {
        let Self {
            hmac_secret,
            hmac_secret_mc,
        } = &self;
        let has_hmac_secret = hmac_secret.is_some();
        let has_hmac_secret_mc = hmac_secret_mc.is_some();

        (has_hmac_secret || has_hmac_secret_mc).then_some(self)
    }
}

/// A map, keyed by extension identifiers, to unsigned outputs of extensions, if any.
/// Authenticators SHOULD omit this field if no processed extensions define unsigned outputs.
/// Clients MUST treat an empty map the same as an omitted field.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedExtensionOutputs {
    /// This output is supported in the Webauthn specification and will be used when the authenticator
    /// and the client are in memory or communicating through an internal channel.
    ///
    /// If you are using transports where this needs to pass through a wire, use hmac-secret instead.
    pub prf: Option<AuthenticatorPrfMakeOutputs>,
}

impl UnsignedExtensionOutputs {
    /// Validates that there is at least one extension field that is `Some`.
    /// If all fields are `None` then this returns `None` as well.
    pub fn zip_contents(self) -> Option<Self> {
        let Self { prf } = &self;

        prf.is_some().then_some(self)
    }
}
