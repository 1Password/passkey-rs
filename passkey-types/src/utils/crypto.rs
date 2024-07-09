//! Collection of common cryptography primitives used in serialization of types.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Compute the SHA-256 of the given `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    // SAFETY: sha256 always gives a 32 byte array
    Sha256::digest(data).into()
}

/// Compute the HMAC of the given data with the given key
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac can take key of any size");
    mac.update(data);

    mac.finalize().into_bytes().into()
}
