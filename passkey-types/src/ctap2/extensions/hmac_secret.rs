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
mod tests {
    use ciborium::{cbor, value::Value};
    use coset::AsCborValue;

    use crate::rand::random_vec;

    use super::*;

    const GOOD_SALT1: [u8; 32] = [
        130, 250, 15, 242, 237, 2, 78, 230, 76, 63, 184, 229, 40, 172, 4, 60, 75, 182, 244, 15,
        109, 248, 177, 205, 235, 65, 32, 16, 183, 12, 145, 39,
    ];
    const GOOD_SALT2: [u8; 32] = [
        188, 232, 220, 195, 110, 115, 163, 139, 67, 124, 35, 10, 117, 252, 33, 207, 48, 16, 59, 32,
        69, 95, 121, 238, 217, 110, 160, 25, 20, 97, 164, 140,
    ];
    const GOOD_SALT1_AND_2: [u8; 64] = [
        130, 250, 15, 242, 237, 2, 78, 230, 76, 63, 184, 229, 40, 172, 4, 60, 75, 182, 244, 15,
        109, 248, 177, 205, 235, 65, 32, 16, 183, 12, 145, 39, 188, 232, 220, 195, 110, 115, 163,
        139, 67, 124, 35, 10, 117, 252, 33, 207, 48, 16, 59, 32, 69, 95, 121, 238, 217, 110, 160,
        25, 20, 97, 164, 140,
    ];
    #[test]
    fn from_32_byte_array() {
        let salt = HmacSecretSaltOrOutput::from(GOOD_SALT1);
        assert_eq!(&GOOD_SALT1, salt.first());
        assert!(!salt.has_salt2);
        assert!(salt.second().is_none());
        assert_eq!(salt.as_slice(), &GOOD_SALT1);

        let salt = HmacSecretSaltOrOutput::new(GOOD_SALT1, None);
        assert_eq!(&GOOD_SALT1, salt.first());
        assert!(!salt.has_salt2);
        assert!(salt.second().is_none());
        assert_eq!(salt.as_slice(), &GOOD_SALT1);
    }

    #[test]
    fn from_64_byte_array() {
        let salt = HmacSecretSaltOrOutput::from(GOOD_SALT1_AND_2);
        assert_eq!(&GOOD_SALT1, salt.first());
        assert!(salt.has_salt2);
        assert_eq!(salt.second(), Some(GOOD_SALT2.as_slice()));
        assert_eq!(salt.as_slice(), &GOOD_SALT1_AND_2);

        let salt = HmacSecretSaltOrOutput::new(GOOD_SALT1, Some(GOOD_SALT2));
        assert_eq!(&GOOD_SALT1, salt.first());
        assert!(salt.has_salt2);
        assert_eq!(salt.second(), Some(GOOD_SALT2.as_slice()));
        assert_eq!(salt.as_slice(), &GOOD_SALT1_AND_2);
    }

    #[test]
    fn from_32_byte_slice() {
        let salt = HmacSecretSaltOrOutput::try_from(GOOD_SALT1.as_slice())
            .expect("Failed to parse slice of one salt");
        assert_eq!(&GOOD_SALT1, salt.first());
        assert!(!salt.has_salt2);
        assert!(salt.second().is_none());
        assert_eq!(salt.as_slice(), &GOOD_SALT1);

        let salt = HmacSecretSaltOrOutput::try_new(GOOD_SALT1.as_slice(), None)
            .expect("Failed to parse slice of one salt");
        assert_eq!(&GOOD_SALT1, salt.first());
        assert!(!salt.has_salt2);
        assert!(salt.second().is_none());
        assert_eq!(salt.as_slice(), &GOOD_SALT1);
    }

    #[test]
    fn from_64_byte_slice() {
        let salt = HmacSecretSaltOrOutput::try_from(GOOD_SALT1_AND_2.as_slice())
            .expect("Failed to parse slice of both salts");
        assert_eq!(&GOOD_SALT1, salt.first());
        assert!(salt.has_salt2);
        assert_eq!(salt.second(), Some(GOOD_SALT2.as_slice()));
        assert_eq!(salt.as_slice(), &GOOD_SALT1_AND_2);

        let salt =
            HmacSecretSaltOrOutput::try_new(GOOD_SALT1.as_slice(), Some(GOOD_SALT2.as_slice()))
                .expect("Failed to parse slice of both salts");
        assert_eq!(&GOOD_SALT1, salt.first());
        assert!(salt.has_salt2);
        assert_eq!(salt.second(), Some(GOOD_SALT2.as_slice()));
        assert_eq!(salt.as_slice(), &GOOD_SALT1_AND_2);
    }

    #[test]
    fn from_incorrectly_sized_byte_slice() {
        let too_short = random_vec(31);
        let between = random_vec(33);
        let too_long = random_vec(65);

        HmacSecretSaltOrOutput::try_from(too_short.as_slice())
            .expect_err("Failed to detect salt1 is too short");
        HmacSecretSaltOrOutput::try_from(between.as_slice())
            .expect_err("Failed to detect salt2 is too short");
        HmacSecretSaltOrOutput::try_from(too_long.as_slice())
            .expect_err("Failed to detect both salts are too long");

        HmacSecretSaltOrOutput::try_new(&too_short, None)
            .expect_err("Failed to detect salt1 is too short");
        HmacSecretSaltOrOutput::try_new(&between, None)
            .expect_err("Failed to detect salt1 is too long");

        HmacSecretSaltOrOutput::try_new(&too_short, Some(&too_short))
            .expect_err("Failed to detect both salts are too short");
        HmacSecretSaltOrOutput::try_new(&between, Some(&between))
            .expect_err("Failed to detect both salts are too long");

        HmacSecretSaltOrOutput::try_new(&too_short, Some(&between))
            .expect_err("Failed to detect salt1 is short and salt2 is long");
        HmacSecretSaltOrOutput::try_new(&between, Some(&too_short))
            .expect_err("Failed to detect salt1 is long and salt2 is short");

        let correct = random_vec(32);

        HmacSecretSaltOrOutput::try_new(&correct, Some(&too_short))
            .expect_err("Failed to detect salt1 is good but salt2 is short");
        HmacSecretSaltOrOutput::try_new(&correct, Some(&between))
            .expect_err("Failed to detect salt1 is good but salt2 is long");
        HmacSecretSaltOrOutput::try_new(&too_short, Some(&correct))
            .expect_err("Failed to detect salt1 is short but salt2 is good");
        HmacSecretSaltOrOutput::try_new(&between, Some(&correct))
            .expect_err("Failed to detect salt1 is long but salt2 is good");
    }

    #[test]
    fn from_correct_cbor() {
        let key = coset::CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            random_vec(32),
            random_vec(32),
        )
        .build()
        .to_cbor_value()
        .unwrap();
        let remote_one_salt = cbor!({
            0x01 => key,
            0x02 => Value::Bytes(GOOD_SALT1.to_vec()),
            // should be a HMAC other salt with the key
            0x03 => Value::Bytes(random_vec(32))
        })
        .unwrap();
        let remote_two_salts = cbor!({
            0x01 => key,
            0x02 => Value::Bytes(GOOD_SALT1_AND_2.to_vec()),
            // should be a HMAC other salt with the key
            0x03 => Value::Bytes(random_vec(32))
        })
        .unwrap();

        let remote: HmacGetSecretInput = remote_one_salt
            .deserialized()
            .expect("Failed to deserialize remote with one salt");
        // should be encrypted but lets ignore that for now
        let salts = HmacSecretSaltOrOutput::try_from(remote.salt_enc.as_slice())
            .expect("The salts are most likely encrypted");
        assert_eq!(&GOOD_SALT1, salts.first());
        assert!(!salts.has_salt2);
        assert!(salts.second().is_none());
        assert_eq!(salts.as_slice(), &GOOD_SALT1);

        let remote: HmacGetSecretInput = remote_two_salts
            .deserialized()
            .expect("Failed to deserialize remote with two salts");
        // should be encrypted but lets ignore that for now
        let salts = HmacSecretSaltOrOutput::try_from(remote.salt_enc.as_slice())
            .expect("The salts are most likely encrypted");
        assert_eq!(&GOOD_SALT1, salts.first());
        assert!(salts.has_salt2);
        assert_eq!(salts.second(), Some(GOOD_SALT2.as_slice()));
        assert_eq!(salts.as_slice(), &GOOD_SALT1_AND_2);
    }

    #[test]
    fn cbor_round_trip_one_salt() {
        let key = coset::CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            random_vec(32),
            random_vec(32),
        )
        .build()
        .to_cbor_value()
        .unwrap();
        let one_salt = HmacGetSecretInput {
            key_agreement: key,
            salt_enc: Bytes::from(GOOD_SALT1.as_slice()),
            salt_auth: random_vec(32).into(),
            pin_uv_auth_protocol: None,
        };
        let mut buf = Vec::with_capacity(128);
        ciborium::ser::into_writer(&one_salt, &mut buf).unwrap();

        let Value::Map(map) = ciborium::de::from_reader(buf.as_slice()).unwrap() else {
            panic!("Could not deserialize to a map")
        };
        assert_eq!(
            32,
            map.into_iter()
                .find(|(i, _)| i.as_integer() == Some(0x02.into()))
                .map(|(_, val)| val.as_bytes().unwrap().len())
                .unwrap()
        );
        let expect_one_salt: HmacGetSecretInput =
            ciborium::de::from_reader(buf.as_slice()).unwrap();

        assert_eq!(expect_one_salt.key_agreement, one_salt.key_agreement);
        assert_eq!(expect_one_salt.salt_enc, one_salt.salt_enc);
        assert_eq!(expect_one_salt.salt_auth, one_salt.salt_auth);
        assert_eq!(
            expect_one_salt.pin_uv_auth_protocol,
            one_salt.pin_uv_auth_protocol
        );
    }
    #[test]
    fn cbor_round_trip_both_salts() {
        let key = coset::CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            random_vec(32),
            random_vec(32),
        )
        .build()
        .to_cbor_value()
        .unwrap();
        let one_salt = HmacGetSecretInput {
            key_agreement: key,
            salt_enc: Bytes::from(GOOD_SALT1_AND_2.as_slice()),
            salt_auth: random_vec(32).into(),
            pin_uv_auth_protocol: None,
        };
        let mut buf = Vec::with_capacity(128);
        ciborium::ser::into_writer(&one_salt, &mut buf).unwrap();

        let Value::Map(map) = ciborium::de::from_reader(buf.as_slice()).unwrap() else {
            panic!("Could not deserialize to a map")
        };
        assert_eq!(
            64,
            map.into_iter()
                .find(|(i, _)| i.as_integer() == Some(0x02.into()))
                .map(|(_, val)| val.as_bytes().unwrap().len())
                .unwrap()
        );
        let expect_one_salt: HmacGetSecretInput =
            ciborium::de::from_reader(buf.as_slice()).unwrap();

        assert_eq!(expect_one_salt.key_agreement, one_salt.key_agreement);
        assert_eq!(expect_one_salt.salt_enc, one_salt.salt_enc);
        assert_eq!(expect_one_salt.salt_auth, one_salt.salt_auth);
        assert_eq!(
            expect_one_salt.pin_uv_auth_protocol,
            one_salt.pin_uv_auth_protocol
        );
    }
}
