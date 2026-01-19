use coset::iana;

use crate::{CryptoBackend, PublicKeyT, SecretKeyT, SignatureT};

pub struct RustCryptoBackend {}

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
}

impl PublicKeyT for p256::PublicKey {
    type Signature = p256::ecdsa::Signature;
}

impl SignatureT for p256::ecdsa::Signature {}
