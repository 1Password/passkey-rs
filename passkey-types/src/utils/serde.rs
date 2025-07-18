//! Utilities to be used in serde derives for more robust (de)serializations.

use std::str::FromStr;

use serde::{
    Deserialize, Deserializer,
    de::{Error, Visitor},
};

/// Many fields in the webauthn spec have the following wording.
///
/// > The values SHOULD be members of `T` but client platforms MUST ignore unknown values.
///
/// This method is a simple way of ignoring unknown values without failing deserialization.
pub(crate) fn ignore_unknown<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(T::deserialize(de).unwrap_or_default())
}

#[derive(Debug, Default)]
enum PossiblyUnknown<T> {
    Some(T),
    #[default]
    None,
}

impl<'de, T> Deserialize<'de> for PossiblyUnknown<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match T::deserialize(de) {
            Ok(val) => Self::Some(val),
            Err(_) => Self::None,
        })
    }
}

pub(crate) fn ignore_unknown_opt_vec<'de, D, T>(de: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + std::fmt::Debug,
{
    struct IgnoreUnknown<T>(std::marker::PhantomData<T>);

    impl<'d, T> Visitor<'d> for IgnoreUnknown<T>
    where
        T: Deserialize<'d> + std::fmt::Debug,
    {
        type Value = Option<Vec<T>>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a list of types")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'d>,
        {
            let mut array = Vec::with_capacity(seq.size_hint().unwrap_or_default());
            while let Some(elem) = seq.next_element::<PossiblyUnknown<T>>()? {
                if let PossiblyUnknown::Some(elem) = elem {
                    array.push(elem)
                }
            }
            Ok(Some(array))
        }
        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(None)
        }
    }

    // TODO: This is a temporary workaround until windows sends us the correct type in CredentialDescriptor::transport
    Ok(de
        .deserialize_seq(IgnoreUnknown(std::marker::PhantomData))
        .unwrap_or_default())
    // de.deserialize_seq(IgnoreUnknown(std::marker::PhantomData))
}

pub(crate) fn ignore_unknown_vec<'de, D, T>(de: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + std::fmt::Debug,
{
    ignore_unknown_opt_vec(de)
        .and_then(|opt| opt.ok_or_else(|| D::Error::custom("Expected a list of types")))
}

pub mod i64_to_iana {
    use super::StringOrNum;
    use std::marker::PhantomData;

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
        let value: i64 = de.deserialize_any(StringOrNum(PhantomData))?;

        T::from_i64(value).ok_or_else(|| {
            <D::Error as serde::de::Error>::invalid_value(
                serde::de::Unexpected::Signed(value),
                &"An iana::Algorithm value",
            )
        })
    }
}

struct StringOrNum<T>(pub std::marker::PhantomData<T>);

impl<T> Visitor<'_> for StringOrNum<T>
where
    T: FromStr + TryFrom<i64> + TryFrom<u64>,
{
    type Value = T;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A number or a stringified number")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        match FromStr::from_str(v) {
            Ok(v) => Ok(v),
            _ => {
                if let Ok(v) = f64::from_str(v) {
                    self.visit_f64(v)
                } else {
                    Err(E::custom("Was not a stringified number"))
                }
            }
        }
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_str(&v)
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        TryFrom::try_from(v).map_err(|_| E::custom("out of range"))
    }

    fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_i64(v.into())
    }

    fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_i64(v.into())
    }

    fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_i64(v.into())
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        TryFrom::try_from(v).map_err(|_| E::custom("out of range"))
    }

    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_u64(v.into())
    }

    fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_u64(v.into())
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_u64(v.into())
    }

    fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_f64(v.into())
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        #[expect(clippy::as_conversions)]
        // Ensure the float has an integer representation,
        // or be 0 if it is a non-integer number
        self.visit_i64(if v.is_normal() { v as i64 } else { 0 })
    }
}

pub(crate) fn maybe_stringified_num<'de, D>(de: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    de.deserialize_any(StringOrNum(std::marker::PhantomData))
        .map(Some)
}

struct StringOrBool;

impl Visitor<'_> for StringOrBool {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Expected a boolean or a string encoded boolean")
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_str(&v)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        FromStr::from_str(v).map_err(|_| E::custom("Not a valid boolean representation"))
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(v)
    }
}

pub(crate) fn maybe_stringified_bool<'de, D>(de: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    de.deserialize_any(StringOrBool)
}
#[cfg(test)]
mod tests;
