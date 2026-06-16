//! Client-side implementation of the PIN/UV Auth Protocols defined in CTAP2.
//! Currently only implements Protocol One.

use coset::{
    CoseKey, CoseKeyBuilder, Label, RegisteredLabel,
    iana::{Algorithm, Ec2KeyParameter, EllipticCurve, EnumI64, KeyType},
};
use p256::{
    EncodedPoint, PublicKey, SecretKey,
    ecdh::diffie_hellman,
    elliptic_curve::{
        generic_array::GenericArray,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use rand::rngs::OsRng;

use crate::{
    ctap2::Ctap2Error,
    utils::crypto::{aes_256_cbc_decrypt, sha256},
};

/// Client-side state for PIN/UV Auth Protocol One. Holds the client's ephemeral P-256 key agreement
/// key.
pub struct PinUvAuthProtocolOne {
    key_agreement: SecretKey,
}

impl PinUvAuthProtocolOne {
    /// Create a new protocol instance with a freshly generated key agreement keypair.
    pub fn new() -> Self {
        Self {
            key_agreement: SecretKey::random(&mut OsRng),
        }
    }

    /// Replace the key agreement keypair with a fresh one.
    pub fn regenerate(&mut self) {
        self.key_agreement = SecretKey::random(&mut OsRng);
    }

    /// COSE_Key encoding of `xB`.
    ///
    /// Headers per spec: `kty=EC2(2)`, `alg=-25` ("not the algorithm actually used"),
    /// `crv=P-256(1)`, `x` and `y` as 32-byte big-endian coordinates.
    pub fn get_public_key(&self) -> CoseKey {
        let point = self.key_agreement.public_key().to_encoded_point(false);
        // SAFETY: an uncompressed P-256 point always carries both coordinates.
        let x = point.x().unwrap().as_slice().to_vec();
        let y = point.y().unwrap().as_slice().to_vec();
        CoseKeyBuilder::new_ec2_pub_key(EllipticCurve::P_256, x, y)
            .algorithm(Algorithm::ECDH_ES_HKDF_256)
            .build()
    }

    /// Returns the client's own public key plus the derived shared secret to
    /// send to/use with the authenticator whose public key is `peer`.
    pub fn encapsulate(&self, peer: &CoseKey) -> Result<(CoseKey, [u8; 32]), Ctap2Error> {
        let shared_secret = self.ecdh(peer)?;
        Ok((self.get_public_key(), shared_secret))
    }

    /// AES-256-CBC-Decrypt with a zero IV and no padding.
    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
        aes_256_cbc_decrypt(*key, [0; 16], ciphertext)
    }

    /// 1. Parse `peer` as a P-256 point `Y`; reject if not on the curve.
    /// 2. Compute `xY` with the local private key.
    /// 3. `Z` = 32-byte big-endian encoding of the x-coordinate of `xY`.
    /// 4. Return `kdf(Z) = SHA-256(Z)`.
    fn ecdh(&self, peer: &CoseKey) -> Result<[u8; 32], Ctap2Error> {
        let peer_public = cose_to_p256_public(peer)?;
        // `SharedSecret::raw_secret_bytes()` is exactly Z - the BE x-coord of xY.
        let shared = diffie_hellman(
            self.key_agreement.to_nonzero_scalar(),
            peer_public.as_affine(),
        );
        Ok(sha256(shared.raw_secret_bytes().as_slice()))
    }
}

impl Default for PinUvAuthProtocolOne {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse the COSE_Key shape required by get_public_key into a `p256::PublicKey`. The `alg` header
/// is intentionally ignored: the spec mandates writing `-25` there but explicitly notes it is not
/// the algorithm actually in use.
fn cose_to_p256_public(key: &CoseKey) -> Result<PublicKey, Ctap2Error> {
    if !matches!(key.kty, RegisteredLabel::Assigned(KeyType::EC2)) {
        return Err(Ctap2Error::InvalidCredential);
    }

    let (mut crv, mut x, mut y) = (None, None, None);
    for (label, value) in &key.params {
        let Label::Int(i) = label else { continue };
        match Ec2KeyParameter::from_i64(*i) {
            Some(Ec2KeyParameter::Crv) => {
                crv = value.as_integer().and_then(|n| i128::from(n).try_into().ok());
            }
            Some(Ec2KeyParameter::X) => x = value.as_bytes(),
            Some(Ec2KeyParameter::Y) => y = value.as_bytes(),
            _ => {}
        }
    }

    if crv != Some(EllipticCurve::P_256.to_i64()) {
        return Err(Ctap2Error::InvalidCredential);
    }
    let (Some(x), Some(y)) = (x, y) else {
        return Err(Ctap2Error::CborUnexpectedType);
    };

    let point = EncodedPoint::from_affine_coordinates(
        GenericArray::from_slice(x),
        GenericArray::from_slice(y),
        false,
    );
    Option::<PublicKey>::from(PublicKey::from_encoded_point(&point))
        .ok_or(Ctap2Error::InvalidCredential)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_and_decapsulate_agree() {
        // Two independent instances stand in for client and authenticator.
        let client = PinUvAuthProtocolOne::new();
        let authenticator = PinUvAuthProtocolOne::new();

        let (client_public, client_shared) = client
            .encapsulate(&authenticator.get_public_key())
            .expect("encapsulate succeeds for a valid peer");

        // Authenticator-side derivation of the same secret via ecdh(clientPublic).
        let auth_shared = authenticator
            .ecdh(&client_public)
            .expect("ecdh succeeds for a valid peer");

        assert_eq!(client_shared, auth_shared);
    }

    #[test]
    fn rejects_non_ec2_key() {
        let proto = PinUvAuthProtocolOne::new();
        let bogus = CoseKeyBuilder::new_symmetric_key(vec![0; 32]).build();
        assert!(proto.encapsulate(&bogus).is_err());
    }
}
