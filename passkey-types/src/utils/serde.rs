//! Utilities to be used in serde derives for more robust (de)serializations.

use std::str::FromStr;

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
        if let Ok(v) = FromStr::from_str(v) {
            Ok(v)
        } else if let Ok(v) = f64::from_str(v) {
            self.visit_f64(v)
        } else {
            Err(E::custom("Was not a stringified number"))
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

pub(crate) fn maybe_stringified<'de, D>(de: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    de.deserialize_any(StringOrNum(std::marker::PhantomData))
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn from_float_representations() {
        #[derive(Deserialize)]
        struct FromFloat {
            #[serde(deserialize_with = "maybe_stringified")]
            num: Option<u32>,
        }

        let float_with_0 = r#"{"num": 0.0}"#;
        let result: FromFloat =
            serde_json::from_str(float_with_0).expect("failed to parse from 0.0");
        assert_eq!(result.num, Some(0));

        let float_ends_with_0 = r#"{"num": 1800.0}"#;
        let result: FromFloat =
            serde_json::from_str(float_ends_with_0).expect("failed to parse from 1800.0");
        assert_eq!(result.num, Some(1800));

        let float_ends_with_num = r#"{"num": 1800.1234}"#;
        let result: FromFloat =
            serde_json::from_str(float_ends_with_num).expect("failed to parse from 1800.1234");
        assert_eq!(result.num, Some(1800));

        let sub_zero = r#"{"num": 0.1234}"#;
        let result: FromFloat =
            serde_json::from_str(sub_zero).expect("failed to parse from 0.1234");
        assert_eq!(result.num, Some(0));

        let scientific = r#"{"num": 1.0e-308}"#;
        let result: FromFloat =
            serde_json::from_str(scientific).expect("failed to parse from 1.0e-308");
        assert_eq!(result.num, Some(0));

        // Ignoring these cases because `serde_json` will fail to deserialize these values
        // https://github.com/serde-rs/json/issues/842

        // let nan = r#"{"num": NaN}"#;
        // let result: FromFloat = serde_json::from_str(nan).expect("failed to parse from NaN");
        // assert_eq!(result.num, Some(0));

        // let inf = r#"{"num": Infinity}"#;
        // let result: FromFloat = serde_json::from_str(inf).expect("failed to parse from Infinity");
        // assert_eq!(result.num, Some(0));

        // let neg_inf = r#"{"num": -Infinity}"#;
        // let result: FromFloat =
        //     serde_json::from_str(neg_inf).expect("failed to parse from -Infinity");
        // assert_eq!(result.num, Some(0));

        let float_with_0_str = r#"{"num": "0.0"}"#;
        let result: FromFloat =
            serde_json::from_str(float_with_0_str).expect("failed to parse from stringified 0.0");
        assert_eq!(result.num, Some(0));

        let float_ends_with_0_str = r#"{"num": "1800.0"}"#;
        let result: FromFloat = serde_json::from_str(float_ends_with_0_str)
            .expect("failed to parse from stringified 1800.0");
        assert_eq!(result.num, Some(1800));

        let float_ends_with_num_str = r#"{"num": "1800.1234"}"#;
        let result: FromFloat = serde_json::from_str(float_ends_with_num_str)
            .expect("failed to parse from stringified 1800.1234");
        assert_eq!(result.num, Some(1800));

        let sub_zero_str = r#"{"num": "0.1234"}"#;
        let result: FromFloat =
            serde_json::from_str(sub_zero_str).expect("failed to parse from stringified 0.1234");
        assert_eq!(result.num, Some(0));

        let scientific_str = r#"{"num": "1.0e-308"}"#;
        let result: FromFloat = serde_json::from_str(scientific_str)
            .expect("failed to parse from stringified 1.0e-308");
        assert_eq!(result.num, Some(0));

        let nan_str = r#"{"num": "NaN"}"#;
        let result: FromFloat =
            serde_json::from_str(nan_str).expect("failed to parse from stringified NaN");
        assert_eq!(result.num, Some(0));

        let inf_str = r#"{"num": "Infinity"}"#;
        let result: FromFloat =
            serde_json::from_str(inf_str).expect("failed to parse from stringified Infinity");
        assert_eq!(result.num, Some(0));

        let neg_inf_str = r#"{"num": "-Infinity"}"#;
        let result: FromFloat =
            serde_json::from_str(neg_inf_str).expect("failed to parse from stringified -Infinity");
        assert_eq!(result.num, Some(0));
    }
}
