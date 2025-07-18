use crate::Bytes;

#[cfg(doc)]
use serde::{Deserialize, Serialize};

serde_workaround! {
    /// Object holding the initial salts for creating the secret.
    #[derive(Debug, Clone)]
    pub struct HmacGetSecretInput {
        /// Should be of form [`coset::CoseKey`] but that doesn't implement [`Serialize`] or [`Deserialize`].
        #[serde(rename=0x01)]
        pub key_agreement: ciborium::value::Value,

        /// The salts encrypted using the shared secret key from the pin UV exchange
        #[serde(rename= 0x02)]
        pub salt_enc: Bytes,

        /// The HMAC of the salts using the shared secret key
        #[serde(rename=0x03)]
        pub salt_auth: Bytes,

        /// The Pin Authentication protocol used in the derivation of the shared secret.
        #[serde(rename=0x04, default, skip_serializing_if= Option::is_none)]
        pub pin_uv_auth_protocol: Option<u8>,
    }
}

/// The salts (`salt1` and `salt2`) or the outputs (`output1` and `output2`) depending on whether
/// this is in the input request, or in the response.
#[derive(Debug, Clone)]
pub struct HmacSecretSaltOrOutput {
    salts: [u8; 64],

    has_salt2: bool,
}

impl From<[u8; 32]> for HmacSecretSaltOrOutput {
    fn from(value: [u8; 32]) -> Self {
        let mut salts = [0; 64];
        salts[..32].copy_from_slice(&value);
        Self {
            salts,
            has_salt2: false,
        }
    }
}

impl From<[u8; 64]> for HmacSecretSaltOrOutput {
    fn from(salts: [u8; 64]) -> Self {
        Self {
            salts,
            has_salt2: true,
        }
    }
}

/// An error occurred when converting an badly sized slice to [`HmacSecretSaltOrOutput`]
#[derive(Debug)]
pub struct TryFromSliceError;

impl From<std::array::TryFromSliceError> for TryFromSliceError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        TryFromSliceError
    }
}

impl TryFrom<&[u8]> for HmacSecretSaltOrOutput {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() == 64 {
            let salts: [u8; 64] = value.try_into()?;
            Ok(salts.into())
        } else if value.len() == 32 {
            let salts: [u8; 32] = value.try_into()?;
            Ok(salts.into())
        } else {
            Err(TryFromSliceError)
        }
    }
}

impl HmacSecretSaltOrOutput {
    /// Create a new [`HmacSecretSaltOrOutput`] from sized arrays which is infallible
    pub fn new(salt1: [u8; 32], salt2: Option<[u8; 32]>) -> Self {
        let mut salts = [0; 64];
        let has_salt2 = salt2.is_some();
        let (one, two) = salts.split_at_mut(32);
        one.copy_from_slice(&salt1);

        if let Some(salt2) = salt2 {
            two.copy_from_slice(&salt2);
        }

        Self { salts, has_salt2 }
    }

    /// Try creating a new [`HmacSecretSaltOrOutput`] from byte slices. Returns an error if any of the given slices are
    /// not exactly 32 bytes long.
    pub fn try_new(salt1: &[u8], salt2: Option<&[u8]>) -> Result<Self, TryFromSliceError> {
        Ok(Self::new(
            salt1.try_into()?,
            salt2.map(|s| s.try_into()).transpose()?,
        ))
    }

    /// Get the first value along with the second concatenated if present.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        if self.has_salt2 {
            &self.salts
        } else {
            &self.salts[..32]
        }
    }

    /// Get access to `salt1` or `output1` as a slice
    #[inline]
    pub fn first(&self) -> &[u8] {
        &self.salts[..32]
    }

    /// Get access to `salt2` or `output2` as a slice
    #[inline]
    pub fn second(&self) -> Option<&[u8]> {
        self.has_salt2.then_some(&self.salts[32..])
    }
}

#[cfg(test)]
mod tests;
