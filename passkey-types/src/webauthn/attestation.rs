//! Types specific to public key credential creation
use coset::iana;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;
use typeshare::typeshare;

use crate::{
    utils::serde::{
        i64_to_iana, ignore_unknown, ignore_unknown_opt_vec, ignore_unknown_vec, maybe_stringified,
    },
    webauthn::{
        AuthenticationExtensionsClientInputs, AuthenticatorAttachment, AuthenticatorTransport,
        PublicKeyCredential, PublicKeyCredentialDescriptor, PublicKeyCredentialHints,
        PublicKeyCredentialType, UserVerificationRequirement,
    },
    Bytes,
};

#[cfg(doc)]
use crate::{
    ctap2::{Aaguid, AttestedCredentialData, AuthenticatorData},
    webauthn::AuthenticatorAssertionResponse,
};

/// The response to the successful creation of a PublicKeyCredential
#[typeshare]
pub type CreatedPublicKeyCredential = PublicKeyCredential<AuthenticatorAttestationResponse>;

/// This is the expected input to [`navigator.credentials.create`] when wanting to create a webauthn
/// credential.
///
/// <https://w3c.github.io/webauthn/#sctn-credentialcreationoptions-extension>
///
/// [`navigator.credentials.create`]: https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct CredentialCreationOptions {
    /// The key defining that this is a request for a webauthn credential.
    pub public_key: PublicKeyCredentialCreationOptions,
}

/// This defines the request for creating a [`PublicKeyCredential`].
///
/// <https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions>
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct PublicKeyCredentialCreationOptions {
    /// This member contains a name and an identifier for the [Relying Party] responsible for the request.
    ///
    /// [Relying Party]: https://w3c.github.io/webauthn/#relying-party
    pub rp: PublicKeyCredentialRpEntity,

    /// This member contains names and an identifier for the user account performing the registration.
    ///
    /// The value's [`PublicKeyCredentialUserEntity::id`] can be returned as the [`AuthenticatorAssertionResponse::user_handle`]
    /// in some future authentication ceremonies. It is also used to overwrite existing [discoverable credentials]
    /// that have the same [`PublicKeyCredentialRpEntity::id`] and [`PublicKeyCredentialUserEntity::id`]
    /// on the same authenticator.
    ///
    /// [discoverable credentials]: https://w3c.github.io/webauthn/#discoverable-credential
    pub user: PublicKeyCredentialUserEntity,

    /// This member specifies a challenge that the authenticator signs, along with other data,
    /// when producing an [`AttestedCredentialData`] for the newly created credential.
    ///
    /// See the [Cryptographic Challenges] security consideration.
    ///
    /// [Cryptographic Challenges]: https://w3c.github.io/webauthn/#sctn-cryptographic-challenges
    pub challenge: Bytes,

    /// This member lists the key types and signature algorithms the [Relying Party] supports, ordered
    /// from most preferred to least preferred. The client and authenticator make a best-effort to
    /// create a credential of the most preferred type possible. If none of the listed types can be
    /// created, the `create()` operation MUST fail.
    ///
    /// Relying Parties that wish to support a wide range of authenticators SHOULD include at least
    /// the following [COSEAlgorithmIdentifier] values:
    ///
    /// * [Ed25519][-8]
    /// * [ES256][-7]
    /// * [RS256][-257]
    ///
    /// Additional signature algorithms can be included as needed.
    ///
    /// [Relying Party]: https://w3c.github.io/webauthn/#relying-party
    /// [COSEAlgorithmIdentifier]: https://w3c.github.io/webauthn/#typedefdef-cosealgorithmidentifier
    /// [-8]: coset::iana::Algorithm::EdDSA
    /// [-7]: coset::iana::Algorithm::ES256
    /// [-257]: coset::iana::Algorithm::RS256
    #[serde(deserialize_with = "ignore_unknown_vec")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,

    /// This OPTIONAL member specifies a time, in milliseconds, that the Relying Party is willing to
    /// wait for the call to complete. This is treated as a hint, and MAY be overridden by the client.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "maybe_stringified"
    )]
    pub timeout: Option<u32>,

    /// The Relying Party SHOULD use this OPTIONAL member to list any existing credentials mapped to
    /// this user account (as identified by [`PublicKeyCredentialUserEntity::id`]). This ensures that
    /// the new credential is not created on an authenticator that already contains a credential
    /// mapped to this user account. If it would be, the client is requested to instead guide the
    /// user to use a different authenticator, or return an error if that fails.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "ignore_unknown_opt_vec"
    )]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,

    /// The Relying Party MAY use this OPTIONAL member to specify capabilities and settings that the
    /// authenticator MUST or SHOULD satisfy to participate in the `create()` operation.
    ///
    /// For more information see [`AuthenticatorSelectionCriteria`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,

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
    /// additional processing by the client and authenticator. For example, the Relying Party may
    /// request that the client returns additional information about the credential that was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// This type is used to supply additional Relying Party attributes when creating a new credential.
///
/// <https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[typeshare]
pub struct PublicKeyCredentialRpEntity {
    /// A unique identifier for the [Relying Party] entity, which sets the [RP ID].
    ///
    /// If omitted, its value will be the requesting origin's [effective domain]
    ///
    /// [Relying Party]: https://w3c.github.io/webauthn/#relying-party
    /// [RP ID]: https://w3c.github.io/webauthn/#rp-id
    /// [effective domain]: https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-effective-domain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// A human palatable identifier for the Relying Party, intended only for display. It should
    /// follow the following guidelines.
    ///
    /// * Relying Parties SHOULD perform enforcement, as prescribed in Section 2.3 of [RFC8266] for
    ///   the Nickname Profile of the PRECIS FreeformClass [RFC8264], when setting name's value, or
    ///   displaying the value to the user.
    /// * This string MAY contain language and direction metadata. Relying Parties SHOULD consider
    ///   providing this information. See [Language and Direction Encoding][Lang] about how this
    ///   metadata is encoded.
    /// * Clients SHOULD perform enforcement, as prescribed in Section 2.3 of [RFC8266] for the
    ///   Nickname Profile of the PRECIS FreeformClass [RFC8264], on name's value prior to
    ///   displaying the value to the user or including the value as a parameter of the
    ///   authenticatorMakeCredential operation.
    ///
    /// [RFC8266]: https://www.rfc-editor.org/rfc/rfc8266
    /// [RFC8264]: https://www.rfc-editor.org/rfc/rfc8264
    /// [Lang]: https://w3c.github.io/webauthn/#sctn-strings-langdir
    pub name: String,
}

/// This type is used to supply additional user account attributes when creating a new credential.
///
/// The `name` and `display_name` members should follow the following guidelines:
///
/// * Relying Parties SHOULD perform enforcement, as prescribed in Section 2.3 of [RFC8266] for
///   the Nickname Profile of the PRECIS FreeformClass [RFC8264], when setting name's value, or
///   displaying the value to the user.
/// * This string MAY contain language and direction metadata. Relying Parties SHOULD consider
///   providing this information. See [Language and Direction Encoding][Lang] about how this
///   metadata is encoded.
/// * Clients SHOULD perform enforcement, as prescribed in Section 2.3 of [RFC8266] for the
///   Nickname Profile of the PRECIS FreeformClass [RFC8264], on name's value prior to
///   displaying the value to the user or including the value as a parameter of the
///   authenticatorMakeCredential operation.
///
/// <https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity>
///
/// [RFC8266]: https://www.rfc-editor.org/rfc/rfc8266
/// [RFC8264]: https://www.rfc-editor.org/rfc/rfc8264
/// [Lang]: https://w3c.github.io/webauthn/#sctn-strings-langdir
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct PublicKeyCredentialUserEntity {
    /// The user handle of the user account. A user handle is an opaque byte sequence with a maximum
    /// size of 64 bytes, and is not meant to be displayed to the user.
    ///
    /// To ensure secure operation, authentication and authorization decisions MUST be made on the
    /// basis of this id member, not the [`Self::display_name`] nor [`Self::name`] members.
    ///
    /// The user handle MUST NOT contain personally identifying information about the user, such as
    /// a username or e-mail address; see [User Handle Contents] for details.
    /// The user handle MUST NOT be empty.
    ///
    /// [User Handle Contents]: https://w3c.github.io/webauthn/#sctn-user-handle-privacy
    pub id: Bytes,

    /// A human-palatable name for the user account, intended only for display.
    /// For example:
    ///
    /// * "Alex Müller" or
    /// * "田中倫".
    ///
    /// The Relying Party SHOULD let the user choose this, and SHOULD NOT restrict the choice more
    /// than necessary.
    ///
    /// Authenticators MUST accept and store a 64-byte minimum length for a `display_name` member’s
    /// value. Authenticators MAY truncate a displayName member’s value so that it fits within 64 bytes.
    /// See [String Truncation] about truncation and other considerations.
    ///
    /// [String Truncation]: https://w3c.github.io/webauthn/#sctn-strings-truncation
    pub display_name: String,

    /// A human-palatable identifier for a user account. It is intended only for display,
    /// i.e., aiding the user in determining the difference between user accounts with similar
    /// [`Self::display_name`]s. For example:
    ///
    /// * "alexm",
    /// * "alex.mueller@example.com" or
    /// * "+14255551234"
    ///
    /// Authenticators MUST accept and store a 64-byte minimum length for a `display_name` member’s
    /// value. Authenticators MAY truncate a displayName member’s value so that it fits within 64 bytes.
    /// See [String Truncation] about truncation and other considerations.
    ///
    /// [String Truncation]: https://w3c.github.io/webauthn/#sctn-strings-truncation
    pub name: String,
}

/// This type is used to supply additional parameters when creating a new credential.
///
/// <https://w3c.github.io/webauthn/#dictdef-publickeycredentialparameters>
#[derive(Debug, Serialize, Deserialize)]
#[typeshare]
pub struct PublicKeyCredentialParameters {
    /// This member specifies the type of credential to be created. The value SHOULD be a member of
    /// [`PublicKeyCredentialType`] but client platforms MUST ignore unknown values, ignoring any
    /// [`PublicKeyCredentialParameters`] with an [`PublicKeyCredentialType::Unknown`] type.
    #[serde(rename = "type", deserialize_with = "ignore_unknown")]
    pub ty: PublicKeyCredentialType,

    /// This member specifies the cryptographic signature algorithm with which the newly generated
    /// credential will be used, and thus also the type of asymmetric key pair to be generated,
    /// e.g., RSA or Elliptic Curve.
    ///
    /// > Note: we use `alg` as the latter member name, rather than spelling-out `algorithm`,
    /// >       because it will be serialized into a message to the authenticator, which may be
    /// >       sent over a low-bandwidth link.
    #[serde(with = "i64_to_iana")]
    #[typeshare(serialized_as = "I54")] // because i64 fails for js
    pub alg: iana::Algorithm,
}

/// [Relying Parties] may use this type to specify their requirements regarding authenticator attributes.
///
/// <https://w3c.github.io/webauthn/#dictdef-authenticatorselectioncriteria>
///
/// [Relying Parties]: https://w3c.github.io/webauthn/#webauthn-relying-party
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct AuthenticatorSelectionCriteria {
    /// If this member is present, eligible authenticators are filtered to be only those
    /// authenticators attached with the specified [`AuthenticatorAttachment`] modality. If this
    /// member is absent, then any attachment modality is acceptable. The value SHOULD be a member
    /// of [`AuthenticatorAttachment`] but client platforms MUST ignore unknown values, treating an
    /// unknown value (`None`) as if the member does not exist.
    ///
    /// See also the [`PublicKeyCredential::authenticator_attachment`] member, which can tell what
    /// authenticator attachment modality was used in a successful `create()` or `get()` operation.

    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "ignore_unknown",
        default
    )]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,

    /// Specifies the extent to which the Relying Party desires to create a client-side [discoverable credential].
    /// For historical reasons the naming retains the deprecated “resident” terminology.
    /// The value SHOULD be a member of [`ResidentKeyRequirement`] but client platforms MUST ignore
    /// unknown values, treating an unknown value (`None`) as if the member does not exist. If no
    /// value is given then the effective value is required if [`Self::require_resident_key`] is `true`
    /// or discouraged if it is `false` or absent.
    ///
    /// See [`ResidentKeyRequirement`] for the description of `resident_key`'s values and semantics.
    ///
    /// [discoverable credential]: https://w3c.github.io/webauthn/#client-side-discoverable-credential

    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "ignore_unknown",
        default
    )]
    pub resident_key: Option<ResidentKeyRequirement>,

    /// This member is retained for backwards compatibility with WebAuthn Level 1 and, for historical
    /// reasons, its naming retains the deprecated “resident” terminology for [discoverable credentials].
    /// Relying Parties SHOULD set it to `true` if, and only if, [`Self::resident_key`] is set to required.
    ///
    /// [discoverable credential]: https://w3c.github.io/webauthn/#client-side-discoverable-credential
    #[serde(default)]
    pub require_resident_key: bool,

    /// This member specifies the Relying Party's requirements regarding [user verification] for the
    /// `create()` operation. The value SHOULD be a member of [`UserVerificationRequirement`] but
    /// client platforms MUST ignore unknown values, treating an unknown value as if the member does
    /// not exist.
    ///
    /// See [`UserVerificationRequirement`] for the description of user verification's values and semantics.
    ///
    /// [user verification]: https://w3c.github.io/webauthn/#user-verification
    #[serde(default, deserialize_with = "ignore_unknown")]
    pub user_verification: UserVerificationRequirement,
}

/// This enumeration’s values describe the Relying Party's requirements for client-side
/// [discoverable credentials] (formerly known as resident credentials or resident keys).
///
/// <https://w3c.github.io/webauthn/#enumdef-residentkeyrequirement>
///
/// [discoverable credential]: https://w3c.github.io/webauthn/#client-side-discoverable-credential
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[typeshare(serialized_as = "String")]
pub enum ResidentKeyRequirement {
    /// The Relying Party prefers creating a [server-side credential], but will accept a client-side
    /// discoverable credential. The client and authenticator SHOULD create a server-side credential
    /// if possible.
    ///
    /// > Note: A Relying Party cannot require that a created credential is a server-side credential
    /// >       and the Credential Properties Extension may not return a value for the rk property.
    /// >       Because of this, it may be the case that it does not know if a credential is a
    /// >       server-side credential or not and thus does not know whether creating a second
    /// >       credential with the same user handle will evict the first.
    ///
    /// [server-side credential]: https://w3c.github.io/webauthn/#server-side-credential
    Discouraged,

    /// The Relying Party strongly prefers creating a client-side discoverable credential, but will
    /// accept a server-side credential. The client and authenticator SHOULD create a discoverable
    /// credential if possible. For example, the client SHOULD guide the user through setting up
    /// [user verification] if needed to create a discoverable credential. This takes precedence
    /// over the setting of [`AuthenticatorSelectionCriteria::user_verification`]
    ///
    /// [user verification]: https://w3c.github.io/webauthn/#user-verification
    Preferred,

    /// The Relying Party requires a client-side discoverable credential. The client MUST return an
    /// error if a client-side discoverable credential cannot be created.
    Required,
}

/// Relying Parties may use this enumeration to specify their preference regarding
/// [attestation conveyance] during credential generation.
///
/// <https://w3c.github.io/webauthn/#enumdef-attestationconveyancepreference>
///
/// [attestation conveyance]: https://w3c.github.io/webauthn/#attestation-conveyance
#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[typeshare(serialized_as = "String")]
pub enum AttestationConveyancePreference {
    /// The Relying Party is not interested in authenticator attestation. For example, in order to
    /// potentially avoid having to obtain user consent to relay identifying information to the
    /// Relying Party, or to save a roundtrip to an Attestation CA or Anonymization CA. If the
    /// authenticator generates an attestation statement that is not a self attestation, the client
    /// will replace it with a None attestation statement.
    ///
    /// This is the default, and unknown values fall back to the behavior of this value.
    #[default]
    None,

    /// The Relying Party wants to receive a verifiable attestation statement, but allows the client
    /// to decide how to obtain such an attestation statement. The client MAY replace an
    /// authenticator-generated attestation statement with one generated by an Anonymization CA, in
    /// order to protect the user’s privacy, or to assist Relying Parties with attestation
    /// verification in a heterogeneous ecosystem.
    ///
    /// > Note: There is no guarantee that the Relying Party will obtain a verifiable attestation
    /// >       statement in this case. For example, in the case that the authenticator employs
    /// >       [self attestation] and the client passes the attestation statement through unmodified.
    ///
    /// [self attestation]: https://w3c.github.io/webauthn/#self-attestation
    Indirect,

    /// The Relying Party wants to receive the attestation statement as generated by the authenticator.
    Direct,

    /// The Relying Party wants to receive an attestation statement that may include uniquely
    /// identifying information. This is intended for controlled deployments within an enterprise
    /// where the organization wishes to tie registrations to specific authenticators. User agents
    /// MUST NOT provide such an attestation unless the user agent or authenticator configuration
    /// permits it for the requested RP ID.
    ///
    /// If permitted, the user agent SHOULD signal to the authenticator (at invocation time) that
    /// enterprise attestation is requested, and convey the resulting AAGUID and attestation
    /// statement, unaltered, to the Relying Party.
    Enterprise,
}

/// Attestation statement formats are identified by a string, called an attestation statement format
/// identifier, chosen by the author of the attestation statement format. The values defined below
/// are registed in the [IANA WebAuthn regirsty][1]. See [Attestation Statement Identifiers][2] in
/// the WebAuthn spec for more information.
///
/// [1]: https://www.iana.org/assignments/webauthn/webauthn.xhtml#webauthn-attestation-statement-format-ids
/// [2]: https://w3c.github.io/webauthn/#sctn-attstn-fmt-ids
#[derive(Debug, Default, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[typeshare]
pub enum AttestationStatementFormatIdentifiers {
    /// The `packed` attestation statement format is a WebAuthn-optimized format for attestation.
    /// It uses a very compact but still extensible encoding method. This format is implementable by
    /// authenticators with limited resources (e.g., secure elements).
    Packed,

    /// The TPM attestation statement format returns an attestation statement in the same format as
    /// the packed attestation statement format, although the `rawData` and `signature` fields are
    /// computed differently.
    Tpm,

    /// Platform authenticators on versions "N", and later, may provide this proprietary
    /// `hardware attestation` statement.
    AndroidKey,

    /// Android-based platform authenticators MAY produce an attestation statement based on the
    /// [Android SafetyNet API](https://developer.android.com/training/safetynet/).
    AndroidSafetynet,

    /// Used with FIDO U2F authenticators.
    FidoU2f,

    /// Used with Apple devices' platform authenticators.
    Apple,

    /// Used to replace any authenticator-provided attestation statement when a WebAuthn Relying
    /// Party indicates it does not wish to receive attestation information.
    #[default]
    None,
}

/// The type represents the authenticator's response to a client’s request for the creation of a new
/// [`PublicKeyCredential`]. It contains information about the new credential that can be used to
/// identify it for later use, and metadata that can be used by the [Relying Party] to assess the
/// characteristics of the credential during registration.
///
/// <https://w3c.github.io/webauthn/#iface-authenticatorattestationresponse>
///
/// [Relying Party]: https://w3c.github.io/webauthn/#relying-party
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[typeshare]
pub struct AuthenticatorAttestationResponse {
    /// This attribute contains the JSON serialization of [`CollectedClientData`] passed to the
    /// authenticator by the client in order to generate this credential. The exact JSON serialization
    /// MUST be preserved, as the hash of the serialized client data has been computed over it.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Bytes,

    /// This is the authenticator Data that is contained within Attestation Object.
    pub authenticator_data: Bytes,

    /// This is the DER [SubjectPublicKeyInfo] of the new credential. Or None if it is not available.
    ///
    /// [SubjectPublicKeyInfo]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.7
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<Bytes>,

    /// This is the [CoseAlgorithmIdentifier] of the new credential
    ///
    /// [CoseAlgorithmIdentifier]: https://w3c.github.io/webauthn/#typedefdef-cosealgorithmidentifier
    #[typeshare(serialized_as = "I54")] // because i64 fails for js
    pub public_key_algorithm: i64,

    /// This attribute contains an attestation object, which is opaque to, and cryptographically
    /// protected against tampering by, the client. The attestation object contains both
    /// [`AuthenticatorData`] and an attestation statement. The former contains the [`Aaguid`], a unique
    /// credential ID, and the [`AttestedCredentialData`] of the credential's public key. The contents
    /// of the attestation statement are determined by the attestation statement format used by the
    /// authenticator. It also contains any additional information that the Relying Party's server
    /// requires to validate the attestation statement, as well as to decode and validate the
    /// [`AuthenticatorData`] along with the JSON-compatible serialization of client data.
    pub attestation_object: Bytes,

    /// This field contains a sequence of zero or more unique [`AuthenticatorTransport`] values in
    /// lexicographical order. These values are the transports that the authenticator is believed to
    /// support, or an empty sequence if the information is unavailable. The values SHOULD be
    /// members of [`AuthenticatorTransport`] but Relying Parties SHOULD accept and store unknown values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

/// The client data represents the contextual bindings of both the Relying Party and the client.
/// It is a key-value mapping whose keys are strings. Values can be any type that has a valid
/// encoding in JSON.
///
/// > Note: The [`CollectedClientData`] may be extended in the future. Therefore it’s critical when
/// >       parsing to be tolerant of unknown keys and of any reordering of the keys
///
/// This struct conforms to the JSON byte serialization format expected of `CollectedClientData`,
/// detailed in section [5.8.1.1 Serialization] of the WebAuthn spec. Namely the following
/// requirements:
///
/// * `type`, `challenge`, `origin`, `crossOrigin` must always be present in the serialized format
///   _in that order_.
/// * Any extra parameters must keep the order in which they were used in the signature, hence the
///   use of [`IndexMap`].
///
/// <https://w3c.github.io/webauthn/#dictionary-client-data>
///
/// [5.8.1.1 Serialization]: https://w3c.github.io/webauthn/#clientdatajson-serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectedClientData {
    /// This member contains the value [`ClientDataType::Create`] when creating new credentials, and
    /// [`ClientDataType::Get`] when getting an assertion from an existing credential. The purpose
    /// of this member is to prevent certain types of signature confusion attacks (where an attacker
    ///  substitutes one legitimate signature for another).
    #[serde(rename = "type")]
    pub ty: ClientDataType,

    /// This member contains the base64url encoding of the challenge provided by the Relying Party.
    /// See the [Cryptographic Challenges] security consideration.
    ///
    /// [Cryptographic Challenges]: https://w3c.github.io/webauthn/#sctn-cryptographic-challenges
    pub challenge: String,

    /// This member contains the fully qualified origin of the requester, as provided to the
    /// authenticator by the client, in the syntax defined by [RFC6454].
    ///
    /// [RFC6454]: https://www.rfc-editor.org/rfc/rfc6454
    pub origin: String,

    /// This OPTIONAL member contains the inverse of the sameOriginWithAncestors argument value that
    /// was passed into the internal method
    #[serde(default, serialize_with = "truthiness")]
    pub cross_origin: Option<bool>,

    /// CollectedClientData can be extended in the future, this accounts for unknown keys
    /// Uses an IndexMap to preserve order of keys for JSON byte serialization
    #[serde(flatten)]
    pub unknown_keys: IndexMap<String, serde_json::value::Value>,
}

fn truthiness<S>(cross_origin: &Option<bool>, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    ser.serialize_bool(cross_origin.filter(|b| *b).is_some())
}

/// Used to limit the values of [`CollectedClientData::ty`] and serializes to static strings.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[typeshare]
pub enum ClientDataType {
    /// Serializes to the string `"webauthn.create"`
    #[serde(rename = "webauthn.create")]
    Create,

    /// Serializes to the string `"webauthn.get"`
    #[serde(rename = "webauthn.get")]
    Get,

    /// Serializes to the string `"payment.get"`
    /// This variant is part of the Secure Payment Confirmation specification
    ///
    /// See <https://www.w3.org/TR/secure-payment-confirmation/#client-extension-processing-authentication>
    #[serde(rename = "payment.get")]
    PaymentGet,
}

impl fmt::Display for ClientDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let renamed = serde_json::to_string(self).unwrap();
        write!(f, "{}", renamed.trim_matches('"'))
    }
}

#[cfg(test)]
mod tests {
    use super::CredentialCreationOptions;
    use crate::webauthn::{ClientDataType, CollectedClientData};

    // Normal client data from Chrome assertion
    const CLIENT_DATA_JSON_STRING: &str = r#"{
        "type":"webauthn.get",
        "challenge":"ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg",
        "origin":"http://localhost:4000",
        "crossOrigin":false
    }"#;

    /// This is a Secure Payment Confirmation (SPC) response. SPC assertion responses
    /// extend the `CollectedClientData` struct by adding a "payment" field that
    /// normally does not exist on `CollectedClientData`
    const EXTENDED_CLIENT_DATA_JSON_STRING: &str = r#"{
            "type": "payment.get",
            "challenge": "ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg",
            "origin": "http://localhost:4000",
            "crossOrigin": false,
            "payment": {
                "rpId": "localhost",
                "topOrigin": "http://localhost:4000",
                "payeeOrigin": "https://localhost:4000",
                "total": {
                    "value": "1.01",
                    "currency": "APT"
                },
                "instrument": {
                    "icon": "https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico",
                    "displayName": "Petra test"
                }
            }
        }"#;

    #[test]
    fn ebay_registration() {
        let request = r#"{
            "publicKey": {
                "challenge": [
                    77, 115, 118, 84, 75, 114, 76, 45, 88, 119, 100, 121, 116, 118, 110, 88, 87, 109,
                    65, 77, 98, 100, 120, 77, 67, 119, 70, 103, 112, 70, 98, 122, 83, 81, 110, 74,
                    97, 68, 120, 118, 117, 49, 115, 46, 77, 84, 89, 51, 79, 84, 107, 122, 77, 68, 81,
                    52, 77, 84, 69, 50, 77, 119, 46, 77, 110, 70, 108, 99, 71, 70, 107, 90, 122, 74,
                    48, 99, 109, 69, 46, 120, 117, 120, 86, 77, 108, 97, 90, 100, 78, 70, 112, 54,
                    78, 122, 73, 90, 84, 68, 87, 89, 71, 122, 112, 70, 48, 108, 68, 71, 114, 66, 106,
                    110, 57, 86, 89, 87, 88, 103, 78, 54, 120, 69
                ],
                "rp": {
                    "id": "ebay.ca",
                    "name": "ebay.ca"
                },
                "user": {
                    "id": [50, 113, 101, 112, 97, 100, 103, 50, 116, 114, 97],
                    "name": "R L",
                    "displayName": "R L"
                },
                "pubKeyCredParams": [
                    { "type": "public-key", "alg": -7 },
                    { "type": "public-key", "alg": -35 },
                    { "type": "public-key", "alg": -36 },
                    { "type": "public-key", "alg": -257 },
                    { "type": "public-key", "alg": -258 },
                    { "type": "public-key", "alg": -259 },
                    { "type": "public-key", "alg": -37 },
                    { "type": "public-key", "alg": -38 },
                    { "type": "public-key", "alg": -39 },
                    { "type": "public-key", "alg": -1 }
                ],
                "authenticatorSelection": {
                    "authenticatorAttachment": "platform",
                    "requireResidentKey": false,
                    "userVerification": "preferred"
                },
                "timeout": 60000,
                "attestation": "direct"
            }
        }"#;

        let deserialized = serde_json::from_str::<CredentialCreationOptions>(request)
            .expect("Failed to deserialize");
        // there are 10 in the json but we should be ignoring the `alg: -1`
        assert_eq!(deserialized.public_key.pub_key_cred_params.len(), 9);
    }

    #[test]
    fn webauthn_me_debugger() {
        let request = r#"{
            "publicKey": {
              "rp": {
                "name": "test"
              },
              "user": {
                "id": [
                  208, 3, 44, 155, 74, 109, 149, 31, 234, 107, 36, 243, 249, 29, 32, 48,
                  189, 69, 220, 216, 11, 222, 113, 155, 129, 208, 156, 217, 58, 99, 41,
                  166
                ],
                "name": "test",
                "displayName": "Test User"
              },
              "challenge": [
                21, 69, 217, 214, 15, 130, 240, 139, 91, 76, 136, 60, 96, 131, 25, 110,
                173, 121, 215, 220, 246, 162, 39, 30, 0, 144, 238, 65, 195, 219, 32, 233
              ],
              "pubKeyCredParams": [
                {
                  "type": "public-key",
                  "alg": "-257"
                },
                {
                  "type": "public-key",
                  "alg": "-7"
                }
              ],
              "timeout": "300000"
            }
          }"#;

        let deserialized = serde_json::from_str::<CredentialCreationOptions>(request)
            .expect("Failed to deserialize");
        assert_eq!(deserialized.public_key.timeout, Some(300_000));
        assert_eq!(deserialized.public_key.pub_key_cred_params.len(), 2)
    }

    #[test]
    fn test_client_data_type_to_string() {
        let payment_get = ClientDataType::PaymentGet;
        assert_eq!(payment_get.to_string(), "payment.get");

        let webauthn_get = ClientDataType::Get;
        assert_eq!(webauthn_get.to_string(), "webauthn.get");
    }

    #[test]
    fn test_client_data_serialization() {
        // This is the raw client data json byte buffer returned by a webauthn assertion
        let expected_client_data_bytes = r#"{"type":"webauthn.get","challenge":"ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg","origin":"http://localhost:4000","crossOrigin":false}"#.as_bytes();

        // Deserialize CollectedClientData from JSON string
        let actual_collected_client_data: CollectedClientData =
            serde_json::from_str(CLIENT_DATA_JSON_STRING).unwrap();

        // Check that serde_json byte serialization is also equivalent
        let actual_client_data_bytes = serde_json::to_vec(&actual_collected_client_data).unwrap();
        assert_eq!(
            actual_client_data_bytes.as_slice(),
            expected_client_data_bytes
        )
    }

    #[test]
    fn test_extended_client_data_serialization() {
        // This is the raw client data json byte buffer returned by an SPC webauthn assertion
        let expected_client_data_bytes = r#"{"type":"payment.get","challenge":"ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg","origin":"http://localhost:4000","crossOrigin":false,"payment":{"rpId":"localhost","topOrigin":"http://localhost:4000","payeeOrigin":"https://localhost:4000","total":{"value":"1.01","currency":"APT"},"instrument":{"icon":"https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico","displayName":"Petra test"}}}"#.as_bytes();

        // Deserialize CollectedClientData from JSON string
        let actual_collected_client_data: CollectedClientData =
            serde_json::from_str(EXTENDED_CLIENT_DATA_JSON_STRING).unwrap();

        // Check that serde_json byte serialization is also equivalent
        let actual_client_data_bytes = serde_json::to_vec(&actual_collected_client_data).unwrap();
        assert_eq!(
            actual_client_data_bytes.as_slice(),
            expected_client_data_bytes
        );

        // This is another byte serialization of client data json, different from the ones above
        let expected_client_data_bytes= r#"{"type":"payment.get","challenge":"eUf1aXwdtHKnIYUXkTgHxmWtYQ_U0c3O8Ldmx3PTA_g","origin":"http://localhost:5173","crossOrigin":false,"payment":{"rpId":"localhost","topOrigin":"http://localhost:5173","payeeOrigin":"https://localhost:4000","total":{"value":"1.01","currency":"APT"},"instrument":{"icon":"https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico","displayName":"Petra test"}},"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}"#.as_bytes();

        let collected_client_data_string = r#"
            {
              "type": "payment.get",
              "challenge": "eUf1aXwdtHKnIYUXkTgHxmWtYQ_U0c3O8Ldmx3PTA_g",
              "origin": "http://localhost:5173",
              "crossOrigin": false,
              "payment": {
                "rpId": "localhost",
                "topOrigin": "http://localhost:5173",
                "payeeOrigin": "https://localhost:4000",
                "total": {
                  "value": "1.01",
                  "currency": "APT"
                },
                "instrument": {
                  "icon": "https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico",
                  "displayName": "Petra test"
                }
              },
              "other_keys_can_be_added_here": "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
            }"#;

        // Deserialize CollectedClientData from JSON string
        let actual_collected_client_data: CollectedClientData =
            serde_json::from_str(collected_client_data_string).unwrap();

        // Check that serde_json byte serialization is also equivalent
        let actual_client_data_bytes = serde_json::to_vec(&actual_collected_client_data).unwrap();
        assert_eq!(
            actual_client_data_bytes.as_slice(),
            expected_client_data_bytes
        );
    }

    #[test]
    fn test_extended_client_data_encoding_failure() {
        let expected_client_data: CollectedClientData =
            serde_json::from_str(EXTENDED_CLIENT_DATA_JSON_STRING).unwrap();
        let expected_client_data_bytes = serde_json::to_vec(&expected_client_data).unwrap();

        // This is a sample Secure Payment Confirmation (SPC) client_data response
        // based on the EXTENDED_CLIENT_DATA constant instantiated above
        // The ordering of "rpId" and "topOrigin" is switched
        let bad_client_data_json = r#"{
            "type": "payment.get",
            "challenge": "ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg",
            "origin": "http://localhost:4000",
            "crossOrigin": false,
            "payment": {
                "topOrigin": "http://localhost:4000",
                "rpId": "localhost",
                "payeeOrigin": "https://localhost:4000",
                "total": {
                    "value": "1.01",
                    "currency": "APT"
                },
                "instrument": {
                    "icon": "https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico",
                    "displayName": "Petra test"
                }
            }
        }"#;

        let bad_collected_client_data: CollectedClientData =
            serde_json::from_str(bad_client_data_json).unwrap();
        let bad_client_data_bytes = serde_json::to_vec(&bad_collected_client_data).unwrap();

        // Should not be equal
        assert_ne!(bad_client_data_bytes, expected_client_data_bytes);
    }

    #[test]
    fn test_client_data_cross_origin_serialization() {
        let mut ccd: CollectedClientData = serde_json::from_str(CLIENT_DATA_JSON_STRING).unwrap();

        // Check that serialization of cross_origin with value Some(true) resolves to true
        const CROSS_ORIGIN_TRUE: &str = r#"{"type":"webauthn.get","challenge":"ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg","origin":"http://localhost:4000","crossOrigin":true}"#;
        ccd.cross_origin = Some(true);
        let client_data_json = serde_json::to_string(&ccd).unwrap();
        assert_eq!(client_data_json, CROSS_ORIGIN_TRUE);

        // Check that serialization of cross_origin with value Some(false) resolves to false
        const CROSS_ORIGIN_FALSE: &str = r#"{"type":"webauthn.get","challenge":"ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg","origin":"http://localhost:4000","crossOrigin":false}"#;
        ccd.cross_origin = Some(false);
        let client_data_json = serde_json::to_string(&ccd).unwrap();
        assert_eq!(client_data_json, CROSS_ORIGIN_FALSE);

        // Check that serialization of cross_origin with value None resolves to false
        ccd.cross_origin = None;
        let client_data_json = serde_json::to_string(&ccd).unwrap();
        assert_eq!(client_data_json, CROSS_ORIGIN_FALSE);
    }
}
