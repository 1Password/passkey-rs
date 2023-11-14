/// This is a workaround to deriving [`serde::Deserialize`] and [`serde::Serialize`] but where the
/// field identifiers are serialized as integers rather than strings. This is due to the fact that
/// serde can only serialize struct fields as strings, including when using the `#[serde(rename)]`
/// attribute.
///
/// Issues to keep an eye on for this workaround to no longer be relevant:
/// * rename for enum variants: <https://github.com/serde-rs/serde/pull/2056>
/// * rename for struct fields: <https://github.com/serde-rs/serde/pull/2209>
macro_rules! serde_workaround {
    (
        $(#[$attr:meta])*
        pub struct $name:ident {$(
            $(#[doc=$doc:literal])*
            #[serde(rename = $discriminant:literal$(,$default:ident)?$(,skip_serializing_if = $method:path)?$(,deserialize_with = $de:path)?)]
            $vis:vis $field:ident: $ty:ty,
        )*}
    ) => {
        $(#[$attr])*
        pub struct $name {$(
            $(#[doc=$doc])*
            $vis $field: $ty,
        )*}

        #[doc(hidden)]
        #[allow(unused_imports, dead_code)]
        const _: () = {
            use serde::{de::MapAccess, ser::SerializeMap, Deserialize, Serialize};
            use strum::{EnumString, FromRepr, IntoStaticStr};

            fn struct_len(_instance: &$name) -> usize {
                0 $(+ serde_workaround_struct_len!(_instance.$field $(;$method)?))*
            }


            #[allow(non_camel_case_types)]
            #[derive(FromRepr, IntoStaticStr, EnumString, Clone, Copy)]
            #[strum(serialize_all = "camelCase")]
            #[repr(u8)]
            enum Ident {
                $($field = $discriminant,)*
                #[strum(disabled)]
                Unknown
            }

            impl Serialize for Ident {
                #[allow(clippy::as_conversions)]
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    serializer.serialize_u8(*self as u8)
                }
            }

            impl Serialize for $name {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer
                {
                    let mut serde_state = serde::Serializer::serialize_map(serializer, Some(struct_len(&self)))?;
                    $(
                        serde_serialize_entry!{serde_state; self.$field $(;$method)?}
                    )*
                    serde_state.end()
                }
            }

            struct FieldVisitor;
            impl<'de> serde::de::Visitor<'de> for FieldVisitor {
                type Value = Ident;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("field identifier")
                }
                fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let repr: u8 = value.try_into().map_err(|_| {
                        E::invalid_value(serde::de::Unexpected::Bytes(value.to_ne_bytes().as_slice()), &format!(
                            "Descriminant of value {} too big to be an identifier",
                            value
                        ).as_str())
                    })?;
                    self.visit_u8(repr)
                }
                delegate_visit_to_u8!{
                    visit_u64: u64,
                    visit_u32: u32,
                    visit_u16: u16,
                }
                fn visit_u8<E>(self, value: u8) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(Ident::from_repr(value).unwrap_or(Ident::Unknown))
                }
                fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    Ok(Ident::try_from(value).unwrap_or(Ident::Unknown))
                }
                fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let ident = if let Ok(value) = std::str::from_utf8(value) {
                        Ident::try_from(value).unwrap_or(Ident::Unknown)
                    } else {
                        Ident::Unknown
                    };
                    Ok(ident)
                }
            }
            impl<'de> Deserialize<'de> for Ident {
                #[inline]
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    serde::Deserializer::deserialize_any(deserializer, FieldVisitor)
                }
            }

            struct Visitor;

            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = $name;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str(concat!("struct ", stringify!($name)))
                }

                #[inline]
                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    $(
                        let mut $field: Option<$ty> = None;
                    )*

                    while let Some(key) = map.next_key::<Ident>()? {
                        match key {
                            $(
                                Ident::$field => serde_deserialize_with!(key; $field; map$(; $ty; $de; $name)?),
                            )*
                            Ident::Unknown => {
                                let _ = map.next_value::<serde::de::IgnoredAny>()?;
                            }
                        }
                    }
                    $(
                        let $field = serde_visit_map!($field $(;$default)?);
                    )*
                    Ok($name {
                        $($field,)*
                    })
                }
            }
            impl<'de> Deserialize<'de> for $name {
                #[inline]
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de>,
                {
                    serde::Deserializer::deserialize_map(deserializer, Visitor)
                }
            }
        };
    };
}

macro_rules! serde_workaround_struct_len {
    ($field:expr; $skip_if:path) => {
        if $skip_if(&$field) {
            0
        } else {
            1
        }
    };
    ($field:expr ) => {
        1
    };
}

macro_rules! serde_serialize_entry {
    ($state:ident; $self:ident.$field:ident; $skip_if:path) => {
        if !$skip_if(&$self.$field) {
            serde_serialize_entry!($state; $self.$field)
        }
    };
    ($state:ident; $self:ident.$field:ident) => {
        $state.serialize_entry(&Ident::$field, &$self.$field)?
    };
}

macro_rules! serde_visit_map {
    ($field:ident; default) => {
        $field.unwrap_or_default()
    };
    ($field:ident) => {
        $field.ok_or_else(|| <A::Error as serde::de::Error>::missing_field(Ident::$field.into()))?
    };
}

macro_rules! serde_deserialize_with {
    ($key:ident; $field:ident; $map:ident; $ty:ty; $de_with:path; $name:ident) => {{
        struct __DeserializeWith<'de> {
            value: $ty,
            phantom: ::std::marker::PhantomData<$name>,
            lifetime: ::std::marker::PhantomData<&'de ()>,
        }
        impl<'de> ::serde::Deserialize<'de> for __DeserializeWith<'de> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                $de_with(deserializer).map(|value| __DeserializeWith {
                    value,
                    phantom: ::std::marker::PhantomData,
                    lifetime: ::std::marker::PhantomData,
                })
            }
        }
        $crate::utils::serde_workaround::check_is_already_set($key, &$field, &$map)?;
        $field = Some($map.next_value::<__DeserializeWith<'de>>()?.value);
    }};
    ($key:ident; $field:ident; $map:ident) => {
        $crate::utils::serde_workaround::set_if_none($key, &mut $field, &mut $map)?
    };
}

macro_rules! delegate_visit_to_u8 {
    ($($fn:ident: $int:ty,)+) => {
        $(
            fn $fn<E>(self, value: $int) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let repr: u8 = value.try_into().map_err(|_| {
                    E::invalid_value(serde::de::Unexpected::Unsigned(value.into()), &format!(
                        "Descriminant of value {} too big to be an identifier",
                        value
                    ).as_str())
                })?;
                self.visit_u8(repr)
            }
        )*
    };
}

pub(crate) fn set_if_none<'de, E, K, T, M>(
    key: K,
    val: &mut Option<T>,
    map: &mut M,
) -> Result<(), E>
where
    E: serde::de::Error,
    K: Into<&'static str>,
    T: serde::Deserialize<'de>,
    M: serde::de::MapAccess<'de, Error = E>,
{
    check_is_already_set(key, val, map)?;
    *val = Some(map.next_value()?);
    Ok(())
}

pub(crate) fn check_is_already_set<'de, E, K, T, M>(
    key: K,
    val: &Option<T>,
    _map: &M,
) -> Result<(), E>
where
    E: serde::de::Error,
    K: Into<&'static str>,
    M: serde::de::MapAccess<'de, Error = E>,
{
    if val.is_some() {
        return Err(E::duplicate_field(key.into()));
    }
    Ok(())
}
