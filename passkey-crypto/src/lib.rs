//! Swappable crypto backends for passkey operations.

// TODO: investigate rolling our own IANA listings and COSE keys
pub use coset::{self, CoseKey, iana};

pub mod hash;
pub mod rng;

/// [CryptoBackend] implementation that uses the crates from the [RustCrypto
/// project](https://github.com/rustcrypto).
#[cfg(feature = "rust-crypto")]
pub mod rust_crypto;

/// [CryptoBackend] implementation backed by the [aws-lc-rs](https://github.com/aws/aws-lc-rs)
/// crate.
#[cfg(feature = "aws-lc-rs")]
pub mod aws_lc_rs;

#[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
mod cose;

/// The [CryptoBackend] to use when a downstream crate has not picked one explicitly.
///
/// Resolves to AwsLcRsBackend when the `aws-lc-rs` feature is enabled, otherwise RustCryptoBackend
/// when only the `rust-crypto` feature is enabled. If both features are enabled, aws-lc-rs wins.
#[cfg(feature = "aws-lc-rs")]
pub type AvailableBackend = aws_lc_rs::AwsLcRsBackend;

/// The [CryptoBackend] to use when a downstream crate has not picked one explicitly.
///
/// Resolves to AwsLcRsBackend when the `aws-lc-rs` feature is enabled, otherwise RustCryptoBackend
/// when only the `rust-crypto` feature is enabled. If both features are enabled, aws-lc-rs wins.
#[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
pub type AvailableBackend = rust_crypto::RustCryptoBackend;

/// The [rng::RngBackend] provided by the [AvailableBackend].
#[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
pub type AvailableRng = <AvailableBackend as CryptoBackend>::Rng;

/// The [hash::Sha256Backend] provided by the [AvailableBackend].
#[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
pub type AvailableSha2 = <AvailableBackend as CryptoBackend>::Sha256;

/// The signing-algorithm secret key type provided by the [AvailableBackend].
#[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
pub type AvailableSecretKey = <AvailableBackend as CryptoBackend>::SecretKey;

/// The signing-algorithm public key type provided by the [AvailableBackend].
#[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
pub type AvailablePublicKey = <AvailableSecretKey as SecretKeyT>::PublicKey;

#[cfg(all(test, feature = "aws-lc-rs", feature = "rust-crypto"))]
mod tests;

/// Trait to capture cryptographic operations necessary in the other passkey-* crates.
pub trait CryptoBackend {
    /// RNG implementation.
    type Rng: rng::RngBackend;

    /// The Sha256 implementation
    type Sha256: hash::Sha256Backend;

    /// Signature algorithm's secret key.
    type SecretKey: SecretKeyT;

    /// Construct a new instance of this backend.
    fn new() -> Self;

    /// List the signing algorithms supported by this [CryptoBackend].
    fn enumerate_algorithms(&self) -> Vec<iana::Algorithm>;

    /// Gemerate a secret key with the provided algorithm.
    fn generate_key(&self, algorithm: iana::Algorithm) -> Result<Self::SecretKey, Error>;
}

/// Operations for a secret key.
pub trait SecretKeyT {
    /// The public key type associated with this secret key.
    type PublicKey: PublicKeyT;
    /// Parse a secret key from the provided COSE-encoded key.
    fn from_cose_key(cose_key: &CoseKey) -> Result<Self, CoseKeyConversionError>
    where
        Self: Sized;
    /// Sign a message using the signing algorithm associated with this key.
    fn sign(&mut self, target: &[u8]) -> Vec<u8>;
    /// Obtain the corresponding public key.
    fn public_key(&self) -> Self::PublicKey;
    /// Encode this key as a COSE key.
    fn to_cose_key(&self) -> CoseKey;
}

/// Errors that can arise when converting from a COSE key.
// TODO: is this conformant with CTAP2? Do we need to expose other error variants?
#[derive(Debug)]
pub enum CoseKeyConversionError {
    /// The algorithm specified in the COSE key is not supported by the [CryptoBackend].
    UnsupportedAlgorithm,
    /// Some parameter of the credential is invalid.
    InvalidCredential,
    /// Any other error.
    Other(Box<dyn std::error::Error>),
}

/// Operations for a public key.
pub trait PublicKeyT {
    /// Verify the cryptographic signature of the given message using this public key.
    fn verify(&self, target: &[u8], signature: &[u8]) -> Result<(), Error>;
    /// Convert a COSE-encoded public key to a byte array in ASN.1 DER format.
    fn der_from_cose_key(cose_key: &CoseKey) -> Result<Vec<u8>, CoseKeyConversionError>;
    /// Encode this key as a COSE key.
    fn to_cose_key(&self) -> CoseKey;
}

/// Catch-all error type for generic operations.
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
