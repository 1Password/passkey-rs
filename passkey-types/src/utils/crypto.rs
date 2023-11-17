//! Collection of common cryptography primitives used in serialization of types.

use sha2::{Digest, Sha256};

/// Compute the SHA-256 of the given `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    // SAFETY: sha256 always gives a 32 byte array
    Sha256::digest(data).into()
}
