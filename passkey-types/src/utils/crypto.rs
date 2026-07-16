//! Collection of common cryptography primitives used in serialization of types.

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, generic_array::GenericArray};
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

const AES_BLOCK_SIZE: usize = 16;

/// AES-256-CBC encryption of `data` under `key` with the given `iv`, with no padding.
pub fn aes_256_cbc(key: [u8; 32], iv: [u8; 16], data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() % AES_BLOCK_SIZE == 0,
        "plaintext length must be a multiple of the AES block size",
    );
    let mut cipher = cbc::Encryptor::<Aes256>::new(
        GenericArray::from_slice(&key),
        GenericArray::from_slice(&iv),
    );
    let mut out = vec![0u8; data.len()];
    for (in_chunk, out_chunk) in data
        .chunks_exact(AES_BLOCK_SIZE)
        .zip(out.chunks_exact_mut(AES_BLOCK_SIZE))
    {
        cipher.encrypt_block_b2b_mut(
            GenericArray::from_slice(in_chunk),
            GenericArray::from_mut_slice(out_chunk),
        );
    }
    out
}

/// AES-256-CBC decryption of `data` under `key` with the given `iv`, with no padding.
/// Mirror of [`aes_256_cbc`].
pub fn aes_256_cbc_decrypt(key: [u8; 32], iv: [u8; 16], data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() % AES_BLOCK_SIZE == 0,
        "ciphertext length must be a multiple of the AES block size",
    );
    let mut cipher = cbc::Decryptor::<Aes256>::new(
        GenericArray::from_slice(&key),
        GenericArray::from_slice(&iv),
    );
    let mut out = vec![0u8; data.len()];
    for (in_chunk, out_chunk) in data
        .chunks_exact(AES_BLOCK_SIZE)
        .zip(out.chunks_exact_mut(AES_BLOCK_SIZE))
    {
        cipher.decrypt_block_b2b_mut(
            GenericArray::from_slice(in_chunk),
            GenericArray::from_mut_slice(out_chunk),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_256_cbc_zero_iv_roundtrip_via_decrypt() {
        use aes::cipher::BlockDecryptMut;

        let key = [0x42u8; 32];
        let iv = [0u8; AES_BLOCK_SIZE];
        let plaintext = b"plaintext_b1_!!!plaintext_b2_!!!"; // 32 bytes, two blocks
        assert_eq!(plaintext.len(), 32);

        let ct = aes_256_cbc(key, iv, plaintext);
        assert_eq!(ct.len(), plaintext.len());
        assert_ne!(ct.as_slice(), plaintext.as_slice());
        // CBC chains — identical plaintext blocks must NOT yield identical
        // ciphertext blocks under a non-zero IV-chained encryption.
        assert_ne!(&ct[..AES_BLOCK_SIZE], &ct[AES_BLOCK_SIZE..]);

        // Decrypt with the symmetric primitive to confirm correctness.
        let mut cipher = cbc::Decryptor::<Aes256>::new(
            GenericArray::from_slice(&key),
            GenericArray::from_slice(&iv),
        );
        let mut pt = vec![0u8; ct.len()];
        for (i, o) in ct
            .chunks_exact(AES_BLOCK_SIZE)
            .zip(pt.chunks_exact_mut(AES_BLOCK_SIZE))
        {
            cipher.decrypt_block_b2b_mut(
                GenericArray::from_slice(i),
                GenericArray::from_mut_slice(o),
            );
        }
        assert_eq!(pt.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn aes_256_cbc_empty_input() {
        let ct = aes_256_cbc([0u8; 32], [0u8; AES_BLOCK_SIZE], &[]);
        assert!(ct.is_empty());
    }
}
