//! Utilities to be used in serde derives for more robust (de)serializations.

use serde::{Deserialize, Deserializer};

/// Many fields in the webauthn spec have the following wording.
///
/// > The values SHOULD be members of `T` but client platforms MUST ignore unknown values.
///
/// This method is a simple way of ignoring unknown values without failing deserialization.
pub fn ignore_unknown<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(match T::deserialize(de) {
        Ok(val) => val,
        Err(_) => T::default(),
    })
}

pub mod i64_to_iana {
    use coset::iana::EnumI64;

    pub fn serialize<S, T>(value: &T, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: EnumI64,
    {
        ser.serialize_i64(value.to_i64())
    }

    pub fn deserialize<'de, D, T>(de: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: EnumI64,
    {
        let value: i64 = serde::Deserialize::deserialize(de)?;

        T::from_i64(value).ok_or_else(|| {
            <D::Error as serde::de::Error>::invalid_value(
                serde::de::Unexpected::Signed(value),
                &"An iana::Algorithm value",
            )
        })
    }
}
