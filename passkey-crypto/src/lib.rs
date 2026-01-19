//!

use coset::{CoseKey, iana};

pub mod rng;

#[cfg(feature = "rust-crypto")]
pub mod rust_crypto;

pub trait CryptoBackend {
    type Rng: rng::RngBackend;
    type SecretKey: SecretKeyT;

    fn generate_key(&self, algorithm: iana::Algorithm) -> Result<Self::SecretKey, Error>;
    // fn parse_private_cose_key(cose_key: CoseKey) -> Self::PrivateKey;
}

pub trait SecretKeyT {
    type Signature: SignatureT;
    type PublicKey: PublicKeyT<Signature = Self::Signature>;
    // fn sign(&mut self, target: &[u8]) -> Self::Signature;
    // fn public_key(&self) -> Self::PublicKey;
    fn to_cose_key(&self) -> CoseKey;
}

pub trait PublicKeyT {
    type Signature: SignatureT;
    // fn verify(&self, target: &[u8], signature: &Self::Signature) -> Result<(), Error>;
    // fn to_cose_key(&self) -> CoseKey;
}

pub trait SignatureT {
    // fn to_bytes(&self) -> Vec<u8>;
}

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
