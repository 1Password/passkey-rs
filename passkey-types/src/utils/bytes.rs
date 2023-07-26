use std::ops::{Deref, DerefMut};

use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use typeshare::typeshare;

use super::encoding;

/// A newtype around `Vec<u8>` which serializes using the transport format's byte representation.
///
/// When feature `serialize_bytes_as_base64_string` is set, this type will be serialized into a
/// `base64url` representation instead. Note that this type should not be used externally when this
/// feature is set, such as in Kotlin, to avoid a serialization errors. In the future, this feature
/// flag can be removed when typeshare supports target/language specific serialization:
/// <https://github.com/1Password/typeshare/issues/63>
///
/// This will use an array of numbers for JSON, and a byte string in CBOR for example.
///
/// It also supports deserializing from `base64` and `base64url` formatted strings.
#[typeshare(transparent)]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[repr(transparent)]
pub struct Bytes(Vec<u8>);

impl Deref for Bytes {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(inner: Vec<u8>) -> Self {
        Bytes(inner)
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(src: Bytes) -> Self {
        src.0
    }
}

impl From<Bytes> for String {
    fn from(src: Bytes) -> Self {
        encoding::base64url(&src)
    }
}

/// The string given for decoding is not `base64url` nor `base64` encoded data.
#[derive(Debug)]
pub struct NotBase64Encoded;

impl TryFrom<&str> for Bytes {
    type Error = NotBase64Encoded;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        encoding::try_from_base64url(value)
            .or_else(|| encoding::try_from_base64(value))
            .ok_or(NotBase64Encoded)
            .map(Self)
    }
}

impl FromIterator<u8> for Bytes {
    fn from_iter<T: IntoIterator<Item = u8>>(iter: T) -> Self {
        Bytes(iter.into_iter().collect())
    }
}

impl IntoIterator for Bytes {
    type Item = u8;

    type IntoIter = std::vec::IntoIter<u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Bytes {
    type Item = &'a u8;

    type IntoIter = std::slice::Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if cfg!(feature = "serialize_bytes_as_base64_string") {
            serializer.serialize_str(&crate::encoding::base64url(&self.0))
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Base64Visitor;

        impl<'de> Visitor<'de> for Base64Visitor {
            type Value = Bytes;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "A vector of bytes or a base46(url) encoded string")
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.try_into().map_err(|_| {
                    E::invalid_value(
                        serde::de::Unexpected::Str(v),
                        &"A base64(url) encoded string",
                    )
                })
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut buf = Vec::with_capacity(seq.size_hint().unwrap_or_default());
                while let Some(byte) = seq.next_element()? {
                    buf.push(byte);
                }
                Ok(Bytes(buf))
            }
        }
        deserializer.deserialize_any(Base64Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    #[test]
    fn deserialize_many_formats_into_base64urlvec() {
        let json = r#"{
            "array": [101,195,212,161,191,112,75,189,152,52,121,17,62,113,114,164],
            "base64url": "ZcPUob9wS72YNHkRPnFypA",
            "base64": "ZcPUob9wS72YNHkRPnFypA=="
        }"#;

        let deserialized: HashMap<&str, Bytes> =
            serde_json::from_str(json).expect("failed to deserialize");

        assert_eq!(deserialized["array"], deserialized["base64url"]);
        assert_eq!(deserialized["base64url"], deserialized["base64"]);
    }

    #[test]
    fn deserialization_should_fail() {
        let json = r#"{
            "array": ["ZcPUob9wS72YNHkRPnFypA","ZcPUob9wS72YNHkRPnFypA=="],
        }"#;

        serde_json::from_str::<HashMap<&str, Bytes>>(json)
            .expect_err("did not give an error as expected.");
    }
}
