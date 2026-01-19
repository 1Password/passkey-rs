use coset::{CoseKey, CoseKeyBuilder, iana};

use crate::{CryptoBackend, PublicKeyT, SecretKeyT, SignatureT};

pub struct RustCryptoBackend;

impl CryptoBackend for RustCryptoBackend {
    type Rng = ::rand::rngs::ThreadRng;

    type SecretKey = p256::SecretKey;

    fn generate_key(&self, algorithm: iana::Algorithm) -> Result<Self::SecretKey, crate::Error> {
        let mut rng = ::rand::thread_rng();
        match algorithm {
            iana::Algorithm::ES256 | iana::Algorithm::PS256 => {
                Ok(p256::SecretKey::random(&mut rng))
            }
            _ => Err("Algorithm is unsupported".to_string().into()),
        }
    }
}

impl SecretKeyT for p256::SecretKey {
    type Signature = p256::ecdsa::Signature;

    type PublicKey = p256::PublicKey;

    fn to_cose_key(&self) -> CoseKey {
        let public_key = p256::ecdsa::SigningKey::from(self)
            .verifying_key()
            .to_encoded_point(false);
        // SAFETY: These unwraps are safe because the public_key above is not compressed (false
        // parameter) therefore x and y are guaranteed to contain values.
        #[allow(deprecated)]
        let x = public_key.x().unwrap().as_slice().to_vec();
        #[allow(deprecated)]
        let y = public_key.y().unwrap().as_slice().to_vec();
        CoseKeyBuilder::new_ec2_priv_key(iana::EllipticCurve::P_256, x, y, self.to_bytes().to_vec())
            .algorithm(iana::Algorithm::ES256)
            .build()
    }

    fn public_key(&self) -> Self::PublicKey {
        self.public_key()
    }
}

impl PublicKeyT for p256::PublicKey {
    type Signature = p256::ecdsa::Signature;

    fn to_cose_key(&self) -> CoseKey {
        let encoded_public_key = p256::ecdsa::VerifyingKey::from(self).to_encoded_point(false);

        // SAFETY: These unwraps are safe because the public_key above is not compressed (false
        // parameter) therefore x and y are guarateed to contain values.
        #[allow(deprecated)]
        let x = encoded_public_key.x().unwrap().as_slice().to_vec();
        #[allow(deprecated)]
        let y = encoded_public_key.y().unwrap().as_slice().to_vec();
        CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
            .algorithm(iana::Algorithm::ES256)
            .build()
    }
}

impl SignatureT for p256::ecdsa::Signature {}
