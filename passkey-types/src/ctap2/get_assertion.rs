//! <https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion>
use serde::{Deserialize, Serialize};

use crate::{
    ctap2::AuthenticatorData,
    webauthn::{PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity},
    Bytes,
};

pub use crate::ctap2::make_credential::Options;

#[cfg(doc)]
use crate::webauthn::{CollectedClientData, PublicKeyCredentialRequestOptions};

use super::extensions::{AuthenticatorPrfGetOutputs, AuthenticatorPrfInputs, HmacGetSecretInput};

serde_workaround! {
    /// While similar in structure to [`PublicKeyCredentialRequestOptions`],
    /// it is not completely identical, namely the presence of the `options` key.
    #[derive(Debug)]
    pub struct Request {
        /// Relying Party Identifier
        #[serde(rename = 0x01)]
        pub rp_id: String,

        /// Hash of the serialized client data collected by the host.
        /// See [`CollectedClientData`]
        #[serde(rename = 0x02)]
        pub client_data_hash: Bytes,

        /// A sequence of PublicKeyCredentialDescriptor structures, each denoting a credential. If
        /// this parameter is present and has 1 or more entries, the authenticator MUST only
        /// generate an assertion using one of the denoted credentials.
        #[serde(rename = 0x03, default, skip_serializing_if = Option::is_none)]
        pub allow_list: Option<Vec<PublicKeyCredentialDescriptor>>,

        /// Parameters to influence authenticator operation. These parameters might be authenticator
        /// specific.
        #[serde(rename = 0x04, default, skip_serializing_if = Option::is_none)]
        pub extensions: Option<ExtensionInputs>,

        /// Parameters to influence authenticator operation, see [`Options`] for more details.
        #[serde(rename = 0x05, default)]
        pub options: Options,

        /// First 16 bytes of HMAC-SHA-256 of clientDataHash using pinToken which platform got from
        /// the authenticator: HMAC-SHA-256(pinToken, clientDataHash). (NOT YET SUPPORTED)
        #[serde(rename = 0x06, default, skip_serializing_if = Option::is_none)]
        pub pin_auth: Option<Bytes>,

        /// PIN protocol version chosen by the client
        #[serde(rename = 0x07, default, skip_serializing_if = Option::is_none)]
        pub pin_protocol: Option<u8>,
    }
}

/// All supported Authenticator extensions inputs during credential assertion
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ExtensionInputs {
    /// The input salts for fetching and deriving a symmetric secret.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension>
    #[serde(
        rename = "hmac-secret",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret: Option<HmacGetSecretInput>,

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
        let Self { hmac_secret, prf } = &self;

        let has_hmac_secret = hmac_secret.is_some();
        let has_prf = prf.is_some();

        (has_hmac_secret || has_prf).then_some(self)
    }
}

serde_workaround! {
    /// Type returned from `Authenticator::get_assertion` on success.
    #[derive(Debug)]
    pub struct Response {
        /// PublicKeyCredentialDescriptor structure containing the credential identifier whose
        /// private key was used to generate the assertion. May be omitted if the allowList has
        /// exactly one Credential.
        #[serde(rename = 0x01, default, skip_serializing_if = Option::is_none)]
        pub credential: Option<PublicKeyCredentialDescriptor>,

        /// The signed-over contextual bindings made by the authenticator
        #[serde(rename = 0x02)]
        pub auth_data: AuthenticatorData,

        /// The assertion signature produced by the authenticator
        #[serde(rename = 0x03)]
        pub signature: Bytes,

        /// [`PublicKeyCredentialUserEntity`] structure containing the user account information.
        /// User identifiable information (name, DisplayName, icon) MUST not be returned if user
        /// verification is not done by the authenticator.
        ///
        /// ## U2F Devices:
        /// For U2F devices, this parameter is not returned as this user information is not present
        /// for U2F credentials.
        ///
        /// ## FIDO Devices - server resident credentials:
        /// For server resident credentials on FIDO devices, this parameter is optional as server
        /// resident credentials behave same as U2F credentials where they are discovered given the
        /// user information on the RP. Authenticators optionally MAY store user information inside
        /// the credential ID.
        ///
        /// ## FIDO devices - device resident credentials:
        /// For device resident keys on FIDO devices, at least user "id" is mandatory.
        ///
        /// For single account per RP case, authenticator returns "id" field to the platform which
        /// will be returned to the WebAuthn layer.
        ///
        /// For multiple accounts per RP case, where the authenticator does not have a display,
        /// authenticator returns "id" as well as other fields to the platform. Platform will use
        /// this information to show the account selection UX to the user and for the user selected
        /// account, it will ONLY return "id" back to the WebAuthn layer and discard other user details.
        #[serde(rename = 0x04, default, skip_serializing_if = Option::is_none)]
        pub user: Option<PublicKeyCredentialUserEntity>,

        /// Total number of account credentials for the RP. This member is required when more than
        /// one account for the RP and the authenticator does not have a display. Omitted when
        /// returned for the authenticatorGetNextAssertion method.
        ///
        /// It seems unlikely that more than 256 credentials would be needed for any given RP. Please
        /// file an enhancement request if this limit impacts your application.
        #[serde(rename = 0x05, default, skip_serializing_if = Option::is_none)]
        pub number_of_credentials: Option<u8>,

        /// A map, keyed by extension identifiers, to unsigned outputs of extensions, if any.
        /// Authenticators SHOULD omit this field if no processed extensions define unsigned outputs.
        /// Clients MUST treat an empty map the same as an omitted field.
        #[serde(rename = 0x08, default, skip_serializing_if = Option::is_none)]
        pub unsigned_extension_outputs: Option<UnsignedExtensionOutputs>,
    }
}

/// All supported Authenticator extensions outputs during credential assertion
///
/// This is to be serialized to [`Value`] in [`AuthenticatorData::extensions`]
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedExtensionOutputs {
    /// Outputs the symmetric secrets after successfull processing. The output MUST be encrypted.
    ///
    /// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension>
    #[serde(
        rename = "hmac-secret",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret: Option<Bytes>,
}

impl SignedExtensionOutputs {
    /// Validates that there is at least one extension field that is `Some`.
    /// If all fields are `None` then this returns `None` as well.
    pub fn zip_contents(self) -> Option<Self> {
        let Self { hmac_secret } = &self;
        hmac_secret.is_some().then_some(self)
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
    pub prf: Option<AuthenticatorPrfGetOutputs>,
}

impl UnsignedExtensionOutputs {
    /// Validates that there is at least one extension field that is `Some`.
    /// If all fields are `None` then this returns `None` as well.
    pub fn zip_contents(self) -> Option<Self> {
        let Self { prf } = &self;
        prf.is_some().then_some(self)
    }
}
