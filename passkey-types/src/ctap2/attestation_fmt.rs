use std::{
    io::{Cursor, Read},
    num::TryFromIntError,
};

use ciborium::value::Value;
use coset::{AsCborValue, CborSerializable, CoseKey};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::sha256,
    ctap2::{Aaguid, Flags},
};

use super::{Ctap2Error, get_assertion, make_credential};

/// The authenticator data structure encodes contextual bindings made by the authenticator. These
/// bindings are controlled by the authenticator itself, and derive their trust from the WebAuthn
/// Relying Party's assessment of the security properties of the authenticator. In one extreme case,
/// the authenticator may be embedded in the client, and its bindings may be no more trustworthy
/// than the client data. At the other extreme, the authenticator may be a discrete entity with
/// high-security hardware and software, connected to the client over a secure channel. In both
/// cases, the Relying Party receives the authenticator data in the same format, and uses its
/// knowledge of the authenticator to make trust decisions.
///
/// <https://w3c.github.io/webauthn/#sctn-authenticator-data>
#[derive(Debug, PartialEq)]
pub struct AuthenticatorData {
    /// SHA-256 hash of the RP ID the credential is scoped to.
    rp_id_hash: [u8; 32],

    /// The flags representing the information of this credential. See [Flags] for more information.
    pub flags: Flags,

    /// Signature counter, 32-bit unsigned big-endian integer.
    pub counter: Option<u32>,

    /// An optional [AttestedCredentialData], if present, the [Flags::AT] needs to be set to true.
    /// See [AttestedCredentialData] for more information. Its length depends on the length of the
    /// credential ID and credential public key being attested.
    pub attested_credential_data: Option<AttestedCredentialData>,

    /// Extension-defined authenticator data. This is a CBOR [RFC8949] map with extension identifiers
    /// as keys, and authenticator extension outputs as values. See [WebAuthn Extensions] for details.
    ///
    /// This field uses the generic `Value` rather than a HashMap or the internal map representation for the
    /// following reasons:
    /// 1. `Value` does not implement `Hash` so it can't be used as a key in a `HashMap`
    /// 2. Even if `Vec<(Value, Value)>` is the internal representation of a map in `Value`, it
    ///    serializes to an array rather than a map, so in order to serialize it needs to be cloned
    ///    into a `Value::Map`.
    ///
    /// Instead we just assert that it is a map during deserialization.
    ///
    /// [RFC8949]: https://www.rfc-editor.org/rfc/rfc8949.html
    /// [WebAuthn Extensions]: https://w3c.github.io/webauthn/#sctn-extensions
    pub extensions: Option<Value>,
}

impl AuthenticatorData {
    /// Create a new AuthenticatorData object for an RP ID and an optional counter.
    ///
    /// The flags will be set to their default values.
    pub fn new(rp_id: &str, counter: Option<u32>) -> Self {
        Self {
            rp_id_hash: sha256(rp_id.as_bytes()),
            flags: Flags::default(),
            counter,
            attested_credential_data: None,
            extensions: None,
        }
    }

    /// Add an [`AttestedCredentialData`] to the authenticator data.
    ///
    /// This sets the [`Flags::AT`] value as well.
    pub fn set_attested_credential_data(mut self, acd: AttestedCredentialData) -> Self {
        self.attested_credential_data = Some(acd);
        self.set_flags(Flags::AT)
    }

    /// Set additional [`Flags`] to the authenticator data.
    pub fn set_flags(mut self, flags: Flags) -> Self {
        self.flags |= flags;
        self
    }

    /// Get read access to the RP ID hash
    pub fn rp_id_hash(&self) -> &[u8] {
        &self.rp_id_hash
    }

    /// Set make credential authenticator extensions
    pub fn set_make_credential_extensions(
        mut self,
        extensions: Option<make_credential::SignedExtensionOutputs>,
    ) -> Result<Self, Ctap2Error> {
        let Some(ext) = extensions.and_then(|e| e.zip_contents()) else {
            return Ok(self);
        };

        self.extensions =
            Some(Value::serialized(&ext).map_err(|_| Ctap2Error::CborUnexpectedType)?);

        Ok(self.set_flags(Flags::ED))
    }

    /// Set assertion authenticator extensions
    pub fn set_assertion_extensions(
        mut self,
        extensions: Option<get_assertion::SignedExtensionOutputs>,
    ) -> Result<Self, Ctap2Error> {
        let Some(ext) = extensions.and_then(|e| e.zip_contents()) else {
            return Ok(self);
        };

        self.extensions =
            Some(Value::serialized(&ext).map_err(|_| Ctap2Error::CborUnexpectedType)?);

        Ok(self.set_flags(Flags::ED))
    }
}

impl Serialize for AuthenticatorData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_vec();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for AuthenticatorData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = AuthenticatorData;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Authenticator Data")
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                AuthenticatorData::from_slice(v).map_err(|e| E::custom(e.to_string()))
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

/// Because CoseError does not implement `From` for either `ciborium::de::Error<E>` or `std::io::Error`...
fn io_error<E>(_: E) -> coset::CoseError {
    coset::CoseError::DecodeFailed(ciborium::de::Error::Io(coset::EndOfFile))
}

impl AuthenticatorData {
    /// Decode an Authenticator data from a byte slice
    pub fn from_slice(v: &[u8]) -> coset::Result<Self> {
        // hash len (32 bytes) + flags (1 byte) + counter (4 bytes)
        if v.len() < 37 {
            return Err(io_error(()));
        }

        // SAFETY: split at panics if the param is creater than the length. These are safe due to
        // guard above.
        let (rp_id_hash, v) = v.split_at(32);
        let (flag_byte, v) = v.split_at(1);
        let (counter, v) = v.split_at(4);

        let flags =
            Flags::from_bits(flag_byte[0]).ok_or(coset::CoseError::OutOfRangeIntegerValue)?;
        let mut managed_reader = Cursor::new(v);
        let attested_credential_data = flags
            .contains(Flags::AT)
            .then(|| AttestedCredentialData::from_reader(&mut managed_reader))
            .transpose()?;
        let extensions = flags
            .contains(Flags::ED)
            .then(|| ciborium::de::from_reader(&mut managed_reader).map_err(io_error))
            .transpose()?;

        // SAFETY: These unwraps are safe since these variables are created using `split_at` which
        // creates slices of specific size.
        Ok(AuthenticatorData {
            rp_id_hash: rp_id_hash.try_into().unwrap(),
            flags,
            counter: Some(u32::from_be_bytes(counter.try_into().unwrap())),
            attested_credential_data,
            extensions,
        })
    }

    /// Encode an authenticator data to its byte representation.
    pub fn to_vec(&self) -> Vec<u8> {
        let flags = if self.attested_credential_data.is_some() {
            self.flags | Flags::AT
        } else {
            self.flags
        };

        self.rp_id_hash
            .into_iter()
            .chain(std::iter::once(flags.into()))
            .chain(self.counter.unwrap_or_default().to_be_bytes())
            .chain(
                self.attested_credential_data
                    .clone()
                    .map(AttestedCredentialData::into_iter)
                    .into_iter()
                    .flatten(),
            )
            .chain(
                self.extensions
                    .as_ref()
                    .map(|val| {
                        let mut bytes = Vec::new();
                        ciborium::ser::into_writer(val, &mut bytes).unwrap();
                        bytes
                    })
                    .into_iter()
                    .flatten(),
            )
            .collect()
    }
}

/// Attested credential data is a variable-length byte array added to the authenticator data when
/// generating an attestation object for a credential
///
/// <https://w3c.github.io/webauthn/#attested-credential-data>
#[derive(Debug, Clone, PartialEq)]
pub struct AttestedCredentialData {
    /// The AAGUID of the authenticator.
    pub aaguid: Aaguid,

    /// The credential ID whose length is prepended to the byte array. This is not public as it
    /// should not be modifiable to be longer than a u16.
    credential_id: Vec<u8>,

    /// The credential public key encoded in COSE_Key format, as defined in Section 7 of [RFC9052],
    /// using the CTAP2 canonical CBOR encoding form. The COSE_Key-encoded credential public key
    /// MUST contain the "alg" parameter and MUST NOT contain any other OPTIONAL parameters.
    /// The "alg" parameter MUST contain a [coset::iana::Algorithm] value. The encoded credential
    /// public key MUST also contain any additional REQUIRED parameters stipulated by the relevant
    /// key type specification, i.e. REQUIRED for the key type "kty" and algorithm "alg"
    /// (see Section 2 of [RFC9053]).
    ///
    /// [RFC9052]: https://www.rfc-editor.org/rfc/rfc9052
    /// [RFC9053]: https://www.rfc-editor.org/rfc/rfc9053
    pub key: CoseKey,
}

impl AttestedCredentialData {
    /// Create a new [AttestedCredentialData]
    ///
    /// # Error
    /// Returns an error if the length of `credential_id` cannot be represented by a u16.
    pub fn new(
        aaguid: Aaguid,
        credential_id: Vec<u8>,
        key: CoseKey,
    ) -> Result<Self, TryFromIntError> {
        // assert that the credential id's length can be represented by a u16
        u16::try_from(credential_id.len())?;

        Ok(Self {
            aaguid,
            credential_id,
            key,
        })
    }

    /// Get read access to the credential ID,
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

impl AttestedCredentialData {
    /// Custom implementation rather than IntoIterator because the iterator type is complicated.
    fn into_iter(self) -> impl Iterator<Item = u8> {
        // SAFETY: if this unwrap fails, it is programmer error
        // unfortunately any serialization in Coset does not use serde::Serialize and takes by value ...
        let cose_key = self.key.to_vec().unwrap();
        self.aaguid
            .0
            .into_iter()
            // SAFETY: the length has been asserted to be less than u16::MAX in the constructor.
            .chain(
                u16::try_from(self.credential_id.len())
                    .unwrap()
                    .to_be_bytes(),
            )
            .chain(self.credential_id)
            .chain(cose_key)
    }

    fn from_reader<R: Read>(reader: &mut R) -> coset::Result<Self> {
        let mut aaguid = [0; 16];
        reader.read_exact(&mut aaguid).map_err(io_error)?;
        let aaguid = Aaguid(aaguid);

        let mut cred_len = [0; 2];
        reader.read_exact(&mut cred_len).map_err(io_error)?;
        let cred_len: usize = u16::from_be_bytes(cred_len).into();

        let mut credential_id = vec![0; cred_len];
        reader.read_exact(&mut credential_id).map_err(io_error)?;

        let cose_val = ciborium::de::from_reader(reader).map_err(io_error)?;
        let key = CoseKey::from_cbor_value(cose_val)?;

        Ok(Self {
            aaguid,
            credential_id,
            key,
        })
    }
}

#[cfg(test)]
mod test;
