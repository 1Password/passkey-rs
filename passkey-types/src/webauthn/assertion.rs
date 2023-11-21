//! Types used for public key authentication

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::{
    utils::serde::{ignore_unknown, ignore_unknown_opt_vec, maybe_stringified},
    webauthn::{
        AttestationConveyancePreference, AttestationStatementFormatIdentifiers,
        AuthenticationExtensionsClientInputs, PublicKeyCredential, PublicKeyCredentialDescriptor,
        PublicKeyCredentialHints, UserVerificationRequirement,
    },
    Bytes,
};

#[cfg(doc)]
use crate::{
    ctap2::{AttestedCredentialData, AuthenticatorData},
    webauthn::{
        AuthenticatorAttestationResponse, CollectedClientData, PublicKeyCredentialUserEntity,
    },
};

/// The response to the successful authentication of a [`PublicKeyCredential`]
#[typeshare]
pub type AuthenticatedPublicKeyCredential = PublicKeyCredential<AuthenticatorAssertionResponse>;

/// This type supplies `get()` requests with the data it needs to generate an assertion.
/// Its `challenge` member MUST be present, while its other members are OPTIONAL.
///
/// <https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptions>
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct PublicKeyCredentialRequestOptions {
    /// This member specifies a challenge that the authenticator signs, along with other data, when
    /// producing an authentication assertion. See the [Cryptographic Challenges] security consideration.
    ///
    /// [Cryptographic Challenges]: https://w3c.github.io/webauthn/#sctn-cryptographic-challenges
    pub challenge: Bytes,

    /// This OPTIONAL member specifies a time, in milliseconds, that the Relying Party is willing to
    /// wait for the call to complete. The value is treated as a hint, and MAY be overridden by the
    /// client.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "maybe_stringified"
    )]
    pub timeout: Option<u32>,

    /// This OPTIONAL member specifies the [RP ID] claimed by the [Relying Party]. The client MUST
    /// verify that the Relying Party's origin matches the scope of this RP ID. The authenticator
    /// MUST verify that this RP ID exactly equals the rpId of the credential to be used for the
    /// authentication ceremony.
    ///
    /// If omitted, its value will be the requesting origin's [effective domain].
    ///
    /// [RP ID]: https://w3c.github.io/webauthn/#rp-id
    /// [Relying Party]: https://w3c.github.io/webauthn/#relying-party
    /// [effective domain]: https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-effective-domain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,

    /// This OPTIONAL member is used by the client to find authenticators eligible for this
    /// authentication ceremony. It can be used in two ways:
    ///
    /// * If the user account to authenticate is already identified (e.g. if the user has entered a
    ///   username), then the Relying Party SHOULD use this member to list credential descriptors for
    ///   credential records in the user account. This SHOULD usually include all credential records
    ///   in the user account.
    ///
    ///   The items SHOULD specify [`PublicKeyCredentialDescriptor::transports`] whenever possible.
    ///   This helps the client optimize the user experience for any given situation. Also note that
    ///   the Relying Party does not need to filter the list when requesting user verification — the
    ///   client will automatically ignore non-eligible credentials if [`Self::user_verification`]
    ///   is set to required.
    ///
    ///   See also the [Privacy leak via credential IDs][privacy] privacy consideration.
    ///
    /// * If the user account to authenticate is not already identified, then the Relying Party MAY
    ///   leave this member empty or unspecified. In this case, only discoverable credentials will be
    ///   utilized in this authentication ceremony, and the user account MAY be identified by the
    ///   of the resulting [`AuthenticatorAssertionResponse::user_handle`]. If the available
    ///   authenticators contain more than one discoverable credential scoped to the Relying Party,
    ///   the credentials are displayed by the client platform or authenticator for the user to select
    ///   from.
    ///
    /// If not empty, the client MUST return an error if none of the listed credentials can be used.
    ///
    /// The list is ordered in descending order of preference: the first item in the list is the
    /// most preferred credential, and the last is the least preferred.
    ///
    /// [privacy]: https://w3c.github.io/webauthn/#sctn-credential-id-privacy-leak
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "ignore_unknown_opt_vec"
    )]
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,

    /// This OPTIONAL member specifies the Relying Party's requirements regarding user verification
    /// for the `get()` operation. The value SHOULD be a member of [`UserVerificationRequirement`]
    /// but client platforms MUST ignore unknown values, treating an unknown value as if the member
    /// does not exist and using its default value. Eligible authenticators are filtered to only
    /// those capable of satisfying this requirement.
    ///
    /// See [`UserVerificationRequirement`] for the description of this field's values and semantics.
    #[serde(default, deserialize_with = "ignore_unknown")]
    pub user_verification: UserVerificationRequirement,

    /// This OPTIONAL member contains zero or more elements from [`PublicKeyCredentialHints`]` to
    /// guide the user agent in interacting with the user.
    ///
    /// This field ignores unknown hint values at deserialization.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "ignore_unknown_opt_vec"
    )]
    pub hints: Option<Vec<PublicKeyCredentialHints>>,

    /// The Relying Party MAY use this OPTIONAL member to specify a preference regarding attestation
    /// conveyance. Its value SHOULD be a member of [`AttestationConveyancePreference`]. Client platforms
    /// MUST ignore unknown values, treating an unknown value as if the member does not exist,
    /// therefore acting as the default value.
    ///
    /// The default value is [`AttestationConveyancePreference::None`]
    #[serde(default, deserialize_with = "ignore_unknown")]
    pub attestation: AttestationConveyancePreference,

    /// The Relying Party MAY use this OPTIONAL member to specify a preference regarding the attestation
    /// statement format used by the authenticator. Values SHOULD be taken from the IANA "WebAuthn
    /// Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by
    /// [RFC8809]. Values are ordered from most preferable to least preferable. This parameter is
    /// advisory and the authenticator MAY use an attestation statement not enumerated in this parameter.
    ///
    /// The default value is the empty list, which indicates no preference.
    ///
    /// [IANA-WebAuthn-Registries]: https://www.iana.org/assignments/webauthn/webauthn.xhtml#webauthn-attestation-statement-format-ids
    /// [RFC8809]: https://www.rfc-editor.org/rfc/rfc8809
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "ignore_unknown_opt_vec"
    )]
    pub attestation_formats: Option<Vec<AttestationStatementFormatIdentifiers>>,

    /// The Relying Party MAY use this OPTIONAL member to provide client extension inputs requesting
    /// additional processing by the client and authenticator.
    ///
    /// See [`AuthenticationExtensionsClientInputs`] for the list of currenly supported [WebAuthn Extensions].
    ///
    /// [WebAuthn Extensions]: https://w3c.github.io/webauthn/#webauthn-extensions
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "ignore_unknown"
    )]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// This is the expected input to [`navigator.credentials.get`] when wanting to authenticate using a
/// webauthn credential.
///
/// <https://w3c.github.io/webauthn/#sctn-credentialrequestoptions-extension>
///
/// [`navigator.credentials.get`]: https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct CredentialRequestOptions {
    /// The key defining that this is a request for a webauthn credential.
    pub public_key: PublicKeyCredentialRequestOptions,
}

/// This type represents an authenticator's response to a client’s request for generation of a new
/// authentication assertion given the Relying Party's [challenge](PublicKeyCredentialRequestOptions)
/// and OPTIONAL list of credentials it is aware of. This response contains a cryptographic signature
/// proving possession of the credential private key, and optionally evidence of user consent to a
/// specific transaction.
///
/// <https://w3c.github.io/webauthn/#iface-authenticatorassertionresponse>
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct AuthenticatorAssertionResponse {
    /// This attribute contains the JSON serialization of [`CollectedClientData`] passed to the
    /// authenticator by the client in order to generate this credential. The exact JSON serialization
    /// MUST be preserved, as the hash of the serialized client data has been computed over it.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Bytes,

    /// This attribute contains the authenticator data returned by the authenticator. See [`AuthenticatorData`].
    pub authenticator_data: Bytes,

    /// This attribute contains the raw signature returned from the authenticator.
    pub signature: Bytes,

    /// This attribute contains the user handle returned from the authenticator, or null if the
    /// authenticator did not return a user handle.
    ///
    /// This mirrors the [`PublicKeyCredentialUserEntity::id`] field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<Bytes>,

    /// This OPTIONAL attribute contains an attestation object, if the authenticator supports attestation
    /// in assertions. The attestation object, if present, includes an attestation statement. Unlike
    /// the [`AuthenticatorAttestationResponse::attestation_object`], it does not contain an `authData`
    /// key because the authenticator data is provided directly above in
    /// [`AuthenticatorAssertionResponse::authenticator_data`] structure. For more details on attestation,
    /// see [Attestation in assertions][1].
    ///
    /// [1]: https://w3c.github.io/webauthn/#sctn-attestation-in-assertions
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_object: Option<Bytes>,
}
