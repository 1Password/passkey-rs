//! Common types used in both Attestation (registration) and Assertion (authentication).
//!
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::{
    utils::serde::{ignore_unknown, ignore_unknown_opt_vec},
    Bytes,
};

#[cfg(doc)]
use crate::webauthn::{
    AuthenticatorAttestationResponse, PublicKeyCredential, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
};

/// This is a dictionary containing the client extension input values for zero or more
/// [WebAuthn Extensions]. There are currently none supported.
///
/// <https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientinputs>
///
/// [WebAuthn Extensions]: https://w3c.github.io/webauthn/#webauthn-extensions
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct AuthenticationExtensionsClientInputs {}

/// This enumeration defines the valid credential types. It is an extension point; values can be
/// added to it in the future, as more credential types are defined. The values of this enumeration
/// are used for versioning the Authentication Assertion and attestation structures according to the
/// type of the authenticator.
///
/// <https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype>
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[typeshare(serialized_as = "String")]
pub enum PublicKeyCredentialType {
    /// Currently the only type defined is a `PublicKey` meaning the public conterpart of an
    /// asymmetric key pair.
    PublicKey,
    /// This is the default as it will be ignored if the value is unknown during deserialization
    #[default]
    Unknown,
}

/// Identifies a specific public key credential. It is used in [`PublicKeyCredentialCreationOptions::exclude_credentials`]
/// to prevent creating duplicate credentials on the same authenticator, and in [`PublicKeyCredentialRequestOptions::allow_credentials`]
/// to determine if and how the credential can currently be reached by the client. It mirrors some
/// fields of the [`PublicKeyCredential`] object returned by the `create()` and `get()` operations.
///
/// It is recommended to ignore any credential whose type is [`PublicKeyCredentialType::Unknown`]
///
/// <https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptor>
#[derive(Debug, Serialize, Deserialize)]
#[typeshare]
pub struct PublicKeyCredentialDescriptor {
    /// This member contains the type of the public key credential the caller is referring to. The
    /// value SHOULD be a member of [`PublicKeyCredentialType`] but client platforms MUST ignore any
    /// [`PublicKeyCredentialDescriptor`] with an [`PublicKeyCredentialType::Unknown`] type.
    ///
    /// This mirrors the [`PublicKeyCredential::ty`] field.
    #[serde(rename = "type", deserialize_with = "ignore_unknown")]
    pub ty: PublicKeyCredentialType,

    /// This member contains the credential ID of the public key credential the caller is referring to.
    ///
    /// This mirrors the [`PublicKeyCredential::raw_id`] field.
    pub id: Bytes,

    /// This OPTIONAL member contains a hint as to how the client might communicate with the managing
    /// authenticator of the [`PublicKeyCredential`] the caller is referring to. The values SHOULD be
    /// members of [`AuthenticatorTransport`] but client platforms MUST ignore unknown values.
    ///
    /// This mirrors the [`AuthenticatorAttestationResponse::transports`] field of a
    /// [`PublicKeyCredential::response`] structure created by a `create()` operation. When registering
    /// a new credential, the Relying Party SHOULD store the value returned from
    /// [`AuthenticatorAttestationResponse::transports`]. When creating a [`PublicKeyCredentialDescriptor`]
    /// for that credential, the Relying Party SHOULD retrieve that stored value and set it as the
    /// value of the transports member.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "ignore_unknown_opt_vec"
    )]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

impl PublicKeyCredentialDescriptor {
    /// Checks whether [`Self::ty`] is not of value [`PublicKeyCredentialType::Unknown`]. This should
    /// be used for filtering a list of [`PublicKeyCredentialDescriptor`]s that are not of a known type.
    pub fn is_known(&self) -> bool {
        match self.ty {
            PublicKeyCredentialType::PublicKey => true,
            PublicKeyCredentialType::Unknown => false,
        }
    }
}

/// A Relying Party may require [user verification] for some of its operations but not for others,
/// and may use this type to express its needs.
///
/// <https://w3c.github.io/webauthn/#enumdef-userverificationrequirement>
///
/// [user verification]: https://w3c.github.io/webauthn/#user-verification
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
#[typeshare(serialized_as = "String")]
pub enum UserVerificationRequirement {
    /// The Relying Party requires user verification for the operation and will fail the overall
    /// ceremony if the response does not have the UV flag set. The client MUST return an error if
    /// user verification cannot be performed.
    Required,

    /// The Relying Party prefers user verification for the operation if possible, but will not fail
    /// the operation if the response does not have the UV flag set.
    #[default]
    Preferred,

    /// The Relying Party does not want user verification employed during the operation
    /// (e.g., in the interest of minimizing disruption to the user interaction flow).
    Discouraged,
}

/// Authenticators may implement various transports for communicating with clients. This enumeration
/// defines hints as to how clients might communicate with a particular authenticator in order to
/// obtain an assertion for a specific credential. Note that these hints represent the Relying Party's
/// best belief as to how an authenticator may be reached. A Relying Party will typically learn of
/// the supported transports for a [`PublicKeyCredential`] via [`AuthenticatorAttestationResponse::transports`].
///
/// <https://w3c.github.io/webauthn/#enum-transport>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
#[typeshare(serialized_as = "String")]
pub enum AuthenticatorTransport {
    /// Indicates the respective authenticator can be contacted over removable USB.
    Usb,

    /// Indicates the respective authenticator can be contacted over Near Field Communication (NFC).
    Nfc,

    /// Indicates the respective authenticator can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
    Ble,

    /// Indicates the respective authenticator can be contacted using a combination of (often separate)
    /// data-transport and proximity mechanisms. This supports, for example, authentication on a
    /// desktop computer using a smartphone.
    #[serde(alias = "cable")]
    Hybrid,

    /// Indicates the respective authenticator is contacted using a client device-specific transport,
    /// i.e. it is a platform authenticator. These authenticators are not removable from the client
    /// device.
    Internal,
}

/// This enumeration’s values describe authenticators' attachment modalities. Relying Parties use
/// this to express a preferred authenticator attachment modality when passing a
/// [`PublicKeyCredentialCreationOptions`] to create a credential, and clients use this to report the
/// authenticator attachment modality used to complete a registration or authentication ceremony.
///
/// <https://w3c.github.io/webauthn/#enumdef-authenticatorattachment>
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[typeshare(serialized_as = "String")]
pub enum AuthenticatorAttachment {
    /// This value indicates platform attachment which is attached using a client device-specific
    /// transport, called **platform attachment**, and is usually not removable from the client
    /// device. A public key credential bound to a platform authenticator is called a
    /// **platform credential**.
    Platform,

    /// This value indicates cross-platform attachment which is attached using cross-platform transports
    /// called **cross-platform attachment**. Authenticators of this class are removable from, and can
    /// "roam" between, client devices. A public key credential bound to a roaming authenticator is
    /// called a **roaming credential**.
    CrossPlatform,
}
