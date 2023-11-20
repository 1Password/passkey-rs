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

/// This enumeration defines the valid credential types. It is an extension point; values can be
/// added to it in the future, as more credential types are defined. The values of this enumeration
/// are used for versioning the Authentication Assertion and attestation structures according to the
/// type of the authenticator.
///
/// <https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype>
#[derive(Debug, Default, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
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

/// WebAuthn Relying Parties may use this enumeration to communicate hints to the user-agent about
/// how a request may be best completed. These hints are not requirements, and do not bind the
/// user-agent, but may guide it in providing the best experience by using contextual information
/// that the Relying Party has about the request. Hints are provided in order of decreasing preference
/// so, if two hints are contradictory, the first one controls. Hints may also overlap: if a more-specific
/// hint is defined a Relying Party may still wish to send less specific ones for user-agents that may
/// not recognise the more specific one. In this case the most specific hint should be sent before
/// the less-specific ones.
///
/// Hints MAY contradict information contained in [`AuthenticatorTransport`] and [`AuthenticatorAttachment`].
/// When this occurs, the hints take precedence. (Note that transports values are not provided when
/// using discoverable credentials, leaving hints as the only avenue for expressing some aspects of
/// such a request.)
///
/// <https://w3c.github.io/webauthn/#enum-hints>
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[typeshare(serialized_as = "String")]
#[non_exhaustive]
pub enum PublicKeyCredentialHints {
    /// Indicates that the Relying Party believes that users will satisfy this request with a physical
    /// security key. For example, an enterprise Relying Party may set this hint if they have issued
    /// security keys to their employees and will only accept those authenticators for registration
    /// and authentication.
    ///
    /// For compatibility with older user agents, when this hint is used in [`PublicKeyCredentialCreationOptions`],
    /// the authenticatorAttachment SHOULD be set to [`AuthenticatorAttachment::CrossPlatform`].
    SecurityKey,

    /// Indicates that the Relying Party believes that users will satisfy this request with a platform
    /// authenticator attached to the client device.
    ///
    /// For compatibility with older user agents, when this hint is used in [`PublicKeyCredentialCreationOptions`],
    /// the authenticatorAttachment SHOULD be set to [`AuthenticatorAttachment::Platform`].
    ClientDevice,

    /// Indicates that the Relying Party believes that users will satisfy this request with
    /// general-purpose authenticators such as smartphones. For example, a consumer Relying Party
    /// may believe that only a small fraction of their customers possesses dedicated security keys.
    /// This option also implies that the local platform authenticator should not be promoted in the UI.
    ///
    /// For compatibility with older user agents, when this hint is used in [`PublicKeyCredentialCreationOptions`],
    /// the authenticatorAttachment SHOULD be set to [`AuthenticatorAttachment::CrossPlatform`].
    Hybrid,
}
