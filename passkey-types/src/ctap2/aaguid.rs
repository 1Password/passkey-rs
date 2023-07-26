use serde::{Deserialize, Serialize};

/// An Authenticator Attestation GUID is a 128-bit identifier.
///
/// This should be used to indicate the type (e.g. make and model) of an Authenticator. The [spec]
/// recommends this to be identical accross all substantially identical authenticators made by the
/// same manufacturer so that Relying Parties may use it to infer properties of the authenticator.
///
/// For privacy reasons we do not recomend this as it can be used for PII, therefore we provide a
/// way to generate an empty AAGUID where it is only `0`s. This the typical AAGUID used when doing
/// self or no attestation.
///
/// [spec]: https://w3c.github.io/webauthn/#sctn-authenticator-model
/// [RFC4122]: https://www.rfc-editor.org/rfc/rfc4122
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Aaguid(pub [u8; Self::LEN]);

impl Aaguid {
    const LEN: usize = 16;

    /// Generate empty AAGUID
    pub const fn new_empty() -> Self {
        Self([0; 16])
    }
}

impl Default for Aaguid {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl From<[u8; 16]> for Aaguid {
    fn from(inner: [u8; 16]) -> Self {
        Aaguid(inner)
    }
}

impl Serialize for Aaguid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Aaguid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct AaguidVisitior;
        impl<'de> serde::de::Visitor<'de> for AaguidVisitior {
            type Value = Aaguid;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "A byte string of {} bytes long", Aaguid::LEN)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.try_into().map(Aaguid).map_err(|_| {
                    E::custom(format!("Byte string of len {}, is not of len 16", v.len()))
                })
            }
        }
        deserializer.deserialize_bytes(AaguidVisitior)
    }
}

#[cfg(test)]
mod tests {
    use super::Aaguid;

    #[test]
    fn deserialize_byte_str_to_aaguid() {
        let cbor_bytes = [
            0x50, // bytes(16)
            0x02, 0x2b, 0xeb, 0xfd, 0x62, 0x3c, 0xac, 0x25, // data
            0xce, 0xe4, 0xd0, 0x90, 0xb9, 0xf8, 0xb5, 0xaf,
        ];

        let aaguid: Aaguid = ciborium::de::from_reader(cbor_bytes.as_slice())
            .expect("could not deserialize from byte string");
        assert_eq!(
            aaguid,
            Aaguid([
                0x02, 0x2b, 0xeb, 0xfd, 0x62, 0x3c, 0xac, 0x25, 0xce, 0xe4, 0xd0, 0x90, 0xb9, 0xf8,
                0xb5, 0xaf,
            ])
        );
    }

    #[test]
    fn new_empty_truly_zero() {
        assert_eq!(Aaguid::new_empty().0, [0; 16]);
    }

    #[test]
    fn aaguid_serialization_round_trip() {
        let expected = Aaguid::new_empty();
        let mut aaguid_bytes = Vec::with_capacity(17);
        ciborium::ser::into_writer(&expected, &mut aaguid_bytes)
            .expect("could not serialize aaguid");

        let result = ciborium::de::from_reader(aaguid_bytes.as_slice())
            .expect("could not deserialized aaguid");

        assert_eq!(expected, result);
    }
}
