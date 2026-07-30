//! Trait abstraction for hashing and hmac operations

pub trait Sha256Backend {
    fn sha256(bytes: &[u8]) -> [u8; 32];
    fn hmac_sha256(key: &[u8], bytes: &[u8]) -> [u8; 32];
}
