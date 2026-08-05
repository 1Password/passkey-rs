//! Swappable crypto backends for passkey operations.

// TODO: remove this
#![allow(missing_docs)]

// TODO: investigate rolling our own IANA listings and COSE keys
pub use coset::{self, CoseKey, iana};

pub mod rng;

#[cfg(feature = "rust-crypto")]
pub mod rust_crypto;

pub trait CryptoBackend {
    type Rng: rng::RngBackend;
    type SecretKey: SecretKeyT;

    fn enumerate_algorithms(&self) -> Vec<iana::Algorithm>;

    fn generate_key(&self, algorithm: iana::Algorithm) -> Result<Self::SecretKey, Error>;
}

pub trait SecretKeyT {
    type PublicKey: PublicKeyT;
    fn from_cose_key(cose_key: &CoseKey) -> Result<Self, CoseKeyConversionError>
    where
        Self: Sized;
    fn sign(&mut self, target: &[u8]) -> Vec<u8>;
    fn public_key(&self) -> Self::PublicKey;
    fn to_cose_key(&self) -> CoseKey;
}

// TODO: is this conformant with CTAP2? Do we need to expose other error variants?
#[derive(Debug)]
pub enum CoseKeyConversionError {
    UnsupportedAlgorithm,
    InvalidCredential,
    Other(Box<dyn std::error::Error>),
}

pub trait PublicKeyT {
    fn verify(&self, target: &[u8], signature: &[u8]) -> Result<(), Error>;
    fn bytes_from_cose_key(cose_key: &CoseKey) -> Result<Vec<u8>, CoseKeyConversionError>;
    fn to_cose_key(&self) -> CoseKey;
}

pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
