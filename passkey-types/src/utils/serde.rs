//! Utilities to be used in serde derives for more robust (de)serializations.

use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer,
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
    Ok(match T::deserialize(de) {
        Ok(val) => val,
        Err(_) => T::default(),
    })
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

    de.deserialize_seq(IgnoreUnknown(std::marker::PhantomData))
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

impl<'de, T> Visitor<'de> for StringOrNum<T>
where
    T: std::str::FromStr + TryFrom<i64> + TryFrom<u64>,
{
    type Value = T;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A number or a stringified number")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        std::str::FromStr::from_str(v).map_err(|_| E::custom("Was not a stringified number"))
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
}

pub(crate) fn maybe_stringified<'de, D>(de: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    de.deserialize_any(StringOrNum(std::marker::PhantomData))
        .map(Some)
}
