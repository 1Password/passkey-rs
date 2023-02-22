use std::fmt::Display;

/// Error converting an integer code into an enum variant. The integer is not within the range of values
/// in the known error type.
#[derive(Debug)]
pub struct CodeOutOfRange<I>(pub I);

impl<I: Display> Display for CodeOutOfRange<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Value {} is out of range", self.0)
    }
}

/// Generate an enum with associated values, plus conversion methods
macro_rules! repr_enum {
    ( $(#[$attr:meta])* $enum_name:ident: $repr:ident {$($(#[$fattr:meta])* $name:ident: $val:expr,)* } ) => {
        #[allow(non_camel_case_types)]
        $(#[$attr])*
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
        #[non_exhaustive]
        #[repr($repr)]
        pub enum $enum_name {
            $($(#[$fattr])* $name = $val,)*
        }
        impl TryFrom<$repr> for $enum_name {
            type Error = $crate::utils::repr_enum::CodeOutOfRange<$repr>;

            fn try_from(value: $repr) -> Result<Self, Self::Error> {
                Ok(match value {
                    $($val => Self::$name,)*
                    _ => return Err($crate::utils::repr_enum::CodeOutOfRange(value))
                })
            }
        }
        impl From<$enum_name> for $repr {
            #[allow(clippy::as_conversions)]
            fn from(src: $enum_name) -> Self {
                src as $repr
            }
        }
    }
}
