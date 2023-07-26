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
