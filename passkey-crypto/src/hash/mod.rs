//! Trait abstraction for hashing and hmac operations

/// A generic Sha256 trait for various implementations
pub trait Sha256Backend {
    /// SHA256 hash provided bytes
    fn sha256(bytes: &[u8]) -> [u8; 32];

    /// HMAC SHA256 byte given a provided key
    fn hmac_sha256(key: &[u8], bytes: &[u8]) -> [u8; 32];
}
