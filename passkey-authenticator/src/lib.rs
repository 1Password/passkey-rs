//! # Passkey Authenticator
//!
//! [![github]](https://github.com/1Password/passkey-rs/tree/main/passkey-authenticator)
//! [![version]](https://crates.io/crates/passkey-authenticator)
//! [![documentation]](https://docs.rs/passkey-authenticator/)
//!
//! This crate defines an [`Authenticator`] type along with a basic implementation of the [CTAP 2.0]
//! specification. The [`Authenticator`] struct is designed in such a way that storage and user
//! interaction are defined through traits, allowing only the parts that vary between vendors,
//! but keeping the specification compliant implementation regardless of vendor. This is why the
//! [`Ctap2Api`] trait is sealed, to prevent external implementations.
//!
//! ## Why RustCrypto?
//!
//! For targeting WASM, yes there are other cryptographic libraries out there that allow targeting
//! WASM, but none of them are as easy to compile to wasm than the pure rust implementations of the
//! [RustCrypto] libraries. Now this does come with limitations, so there are plans to provide a
//! similar backing trait to "plug-in" the desired cryptography from a vendor. Work is ongoing for this.
//!
//! [github]: https://img.shields.io/badge/GitHub-1Password%2Fpasskey--rs%2Fpasskey--authenticator-informational?logo=github&style=flat
//! [version]: https://img.shields.io/crates/v/passkey-authenticator?logo=rust&style=flat
//! [documentation]: https://img.shields.io/docsrs/passkey-authenticator/latest?logo=docs.rs&style=flat
//! [CTAP 2.0]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
//! [RustCrypto]: https://github.com/RustCrypto

mod authenticator;
mod credential_store;
mod ctap2;
mod u2f;
mod user_validation;

use coset::{
    iana::{self, Algorithm, EnumI64},
    CoseKey, CoseKeyBuilder,
};
use p256::{
    ecdsa::SigningKey,
    elliptic_curve::{generic_array::GenericArray, sec1::FromEncodedPoint},
    pkcs8::EncodePublicKey,
    EncodedPoint, PublicKey, SecretKey,
};
use passkey_types::{ctap2::Ctap2Error, Bytes};

pub use self::{
    authenticator::Authenticator,
    credential_store::{CredentialStore, MemoryStore},
    ctap2::Ctap2Api,
    u2f::U2fApi,
    user_validation::UserValidationMethod,
};

#[cfg(feature = "testable")]
pub use self::user_validation::MockUserValidationMethod;

/// Extract a cryptographic secret key from a [`CoseKey`].
// possible candidate for a `passkey-crypto` crate?
fn private_key_from_cose_key(key: &CoseKey) -> Result<SecretKey, Ctap2Error> {
    if !matches!(
        key.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(
            iana::Algorithm::ES256
        ))
    ) {
        return Err(Ctap2Error::UnsupportedAlgorithm);
    }
    if !matches!(
        key.kty,
        coset::RegisteredLabel::Assigned(iana::KeyType::EC2)
    ) {
        return Err(Ctap2Error::InvalidCredential);
    }

    key.params
        .iter()
        .find_map(|(k, v)| {
            if let coset::Label::Int(i) = k {
                iana::Ec2KeyParameter::from_i64(*i)
                    .filter(|p| p == &iana::Ec2KeyParameter::D)
                    .and_then(|_| v.as_bytes())
                    .and_then(|b| SecretKey::from_slice(b).ok())
            } else {
                None
            }
        })
        .ok_or(Ctap2Error::InvalidCredential)
}

/// Convert a Cose Key to a X.509 SubjectPublicKeyInfo formatted byte array.
///
/// This should be used by the client when creating the [Easy Credential Data Accessors][ez]
///
/// [ez]: https://w3c.github.io/webauthn/#sctn-public-key-easy
pub fn public_key_der_from_cose_key(key: &CoseKey) -> Result<Bytes, Ctap2Error> {
    if !matches!(
        key.alg,
        Some(coset::RegisteredLabelWithPrivate::Assigned(
            iana::Algorithm::ES256
        ))
    ) {
        return Err(Ctap2Error::UnsupportedAlgorithm);
    }
    if !matches!(
        key.kty,
        coset::RegisteredLabel::Assigned(iana::KeyType::EC2)
    ) {
        return Err(Ctap2Error::InvalidCredential);
    }

    let (mut x, mut y) = (None, None);
    for (key, value) in &key.params {
        if let coset::Label::Int(i) = key {
            let key = iana::Ec2KeyParameter::from_i64(*i).ok_or(Ctap2Error::InvalidCbor)?;
            match key {
                iana::Ec2KeyParameter::X => {
                    if value.as_bytes().and_then(|v| x.replace(v)).is_some() {
                        log::warn!("Cose key has multiple entries for X coordinate");
                    }
                }
                iana::Ec2KeyParameter::Y => {
                    if value.as_bytes().and_then(|v| y.replace(v)).is_some() {
                        log::warn!("Cose key has multiple entries for Y coordinate");
                    }
                }
                _ => (),
            }
        }
    }
    let (Some(x), Some(y)) = (x, y) else {
        return Err(Ctap2Error::CborUnexpectedType);
    };

    let point = EncodedPoint::from_affine_coordinates(
        GenericArray::from_slice(x.as_slice()),
        GenericArray::from_slice(y.as_slice()),
        false,
    );
    let Some(pub_key): Option<PublicKey> = PublicKey::from_encoded_point(&point).into() else {
        return Err(Ctap2Error::InvalidCredential);
    };
    pub_key
        .to_public_key_der()
        .map_err(|_| Ctap2Error::InvalidCredential)
        .map(|pk| pk.as_ref().to_vec().into())
}

pub(crate) struct CoseKeyPair {
    public: CoseKey,
    private: CoseKey,
}

impl CoseKeyPair {
    fn from_secret_key(private_key: &SecretKey, algorithm: Algorithm) -> Self {
        let public_key = SigningKey::from(private_key)
            .verifying_key()
            .to_encoded_point(false);
        // SAFETY: These unwraps are safe because the public_key above is not compressed (false
        // parameter) therefore x and y are guarateed to contain values.
        let x = public_key.x().unwrap().as_slice().to_vec();
        let y = public_key.y().unwrap().as_slice().to_vec();
        let private = CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_256,
            x.clone(),
            y.clone(),
            private_key.to_bytes().to_vec(),
        )
        .algorithm(algorithm)
        .build();
        let public = CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
            .algorithm(algorithm)
            .build();

        Self { public, private }
    }
}

#[cfg(test)]
mod tests {
    use coset::iana;
    use p256::{
        ecdsa::{
            signature::{Signer, Verifier},
            SigningKey,
        },
        SecretKey,
    };
    use passkey_types::{ctap2::AuthenticatorData, rand::random_vec};

    use super::{private_key_from_cose_key, CoseKeyPair};

    #[test]
    fn private_key_cose_round_trip_sanity_check() {
        let private_key = {
            let mut rng = rand::thread_rng();
            SecretKey::random(&mut rng)
        };
        let CoseKeyPair {
            private: private_cose,
            ..
        } = CoseKeyPair::from_secret_key(&private_key, iana::Algorithm::ES256);
        let public_signing_key = SigningKey::from(&private_key);
        let public_key = public_signing_key.verifying_key();

        let auth_data = AuthenticatorData::new("future.1password.com", None);
        let mut signature_target = auth_data.to_vec();
        signature_target.extend(random_vec(32));

        let secret_key = private_key_from_cose_key(&private_cose).expect("to get a private key");

        let private_key = SigningKey::from(secret_key);
        let signature: p256::ecdsa::Signature = private_key.sign(&signature_target);

        public_key
            .verify(&signature_target, &signature)
            .expect("failed to verify signature")
    }
}
