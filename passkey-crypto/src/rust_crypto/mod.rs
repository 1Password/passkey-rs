use coset::{
    CoseKey, CoseKeyBuilder,
    cbor::Value,
    iana::{self, EnumI64},
};

use crate::{CoseKeyConversionError, CryptoBackend, PublicKeyT, SecretKeyT, hash::Sha256Backend};
use ed25519_dalek::{Signer, ed25519::SignatureEncoding};
use hmac::{Hmac, KeyInit, Mac};
use p256::{
    Sec1Point,
    elliptic_curve::{Generate, array::Array},
    pkcs8::EncodePublicKey,
};
use sha2::{Digest, Sha256};
use signature::Verifier;

pub enum RustCryptoSecretKey {
    P256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

pub enum RustCryptoPublicKey {
    P256(p256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PublicKeyT for RustCryptoPublicKey {
    fn verify(&self, target: &[u8], signature: &[u8]) -> Result<(), crate::Error> {
        match self {
            Self::P256(public_key) => {
                let signature = p256::ecdsa::Signature::from_slice(signature)?;
                public_key.verify(target, &signature)?;
            }
            Self::Ed25519(public_key) => {
                let signature = ed25519_dalek::ed25519::Signature::from_slice(signature)?;
                public_key.verify(target, &signature)?;
            }
        }
        Ok(())
    }

    fn bytes_from_cose_key(cose_key: &CoseKey) -> Result<Vec<u8>, CoseKeyConversionError> {
        let Some(coset::RegisteredLabelWithPrivate::Assigned(alg)) = cose_key.alg else {
            return Err(CoseKeyConversionError::UnsupportedAlgorithm);
        };
        if !matches!(alg, iana::Algorithm::ES256 | iana::Algorithm::Ed25519) {
            return Err(CoseKeyConversionError::UnsupportedAlgorithm);
        }
        match alg {
            iana::Algorithm::ES256 => {
                if !matches!(
                    cose_key.kty,
                    coset::RegisteredLabel::Assigned(iana::KeyType::EC2)
                ) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                let (mut x, mut y) = (None, None);
                for (key, value) in &cose_key.params {
                    if let coset::Label::Int(i) = key {
                        let key = iana::Ec2KeyParameter::from_i64(*i)
                            .ok_or(CoseKeyConversionError::InvalidCredential)?;
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
                    return Err(CoseKeyConversionError::InvalidCredential);
                };
                let point = Sec1Point::from_affine_coordinates(
                    &Array::try_from(x.as_slice())
                        .map_err(|_| CoseKeyConversionError::InvalidCredential)?,
                    &Array::try_from(y.as_slice())
                        .map_err(|_| CoseKeyConversionError::InvalidCredential)?,
                    false,
                );
                let Ok(pub_key) = p256::ecdsa::VerifyingKey::from_sec1_point(&point) else {
                    return Err(CoseKeyConversionError::InvalidCredential);
                };
                pub_key
                    .to_public_key_der()
                    .map_err(|_| CoseKeyConversionError::InvalidCredential)
                    .map(|pk| pk.as_ref().to_vec())
            }
            iana::Algorithm::Ed25519 => {
                if !matches!(
                    cose_key.kty,
                    coset::RegisteredLabel::Assigned(iana::KeyType::OKP)
                ) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                let mut x = None;
                for (key, value) in &cose_key.params {
                    if let coset::Label::Int(i) = key {
                        let key = iana::Ec2KeyParameter::from_i64(*i)
                            .ok_or(CoseKeyConversionError::InvalidCredential)?;
                        if key == iana::Ec2KeyParameter::X
                            && value.as_bytes().and_then(|v| x.replace(v)).is_some()
                        {
                            log::warn!("Cose key has multiple entries for X coordinate");
                        }
                    }
                }
                let Some(x) = x else {
                    return Err(CoseKeyConversionError::InvalidCredential);
                };
                Ok(x.to_owned())
            }
            _ => Err(CoseKeyConversionError::UnsupportedAlgorithm),
        }
    }

    fn to_cose_key(&self) -> CoseKey {
        match self {
            Self::P256(public_key) => {
                let encoded_public_key = public_key.to_sec1_point(false);

                // SAFETY: These unwraps are safe because the public_key above is not compressed (false
                // parameter) therefore x and y are guarateed to contain values.
                #[allow(deprecated)]
                let x = encoded_public_key.x().unwrap().as_slice().to_vec();
                #[allow(deprecated)]
                let y = encoded_public_key.y().unwrap().as_slice().to_vec();
                CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
                    .algorithm(iana::Algorithm::ES256)
                    .build()
            }
            Self::Ed25519(public_key) => CoseKeyBuilder::new_okp_key()
                .algorithm(iana::Algorithm::Ed25519)
                .param(
                    iana::OkpKeyParameter::Crv.to_i64(),
                    Value::from(iana::EllipticCurve::Ed25519.to_i64()),
                )
                .param(
                    iana::OkpKeyParameter::X.to_i64(),
                    Value::from(public_key.to_bytes().as_slice()),
                )
                .build(),
        }
    }
}

impl SecretKeyT for RustCryptoSecretKey {
    type PublicKey = RustCryptoPublicKey;

    fn from_cose_key(cose_key: &CoseKey) -> Result<Self, CoseKeyConversionError>
    where
        Self: Sized,
    {
        let Some(coset::RegisteredLabelWithPrivate::Assigned(alg)) = cose_key.alg else {
            return Err(CoseKeyConversionError::UnsupportedAlgorithm);
        };
        if !matches!(alg, iana::Algorithm::ES256 | iana::Algorithm::Ed25519) {
            return Err(CoseKeyConversionError::UnsupportedAlgorithm);
        }
        let bytes = cose_key
            .params
            .iter()
            .find_map(|(k, v)| {
                if let coset::Label::Int(i) = k {
                    iana::Ec2KeyParameter::from_i64(*i)
                        .filter(|p| p == &iana::Ec2KeyParameter::D)
                        .and_then(|_| v.as_bytes())
                } else {
                    None
                }
            })
            .ok_or(CoseKeyConversionError::InvalidCredential)?;
        match alg {
            iana::Algorithm::ES256 => {
                if !matches!(
                    cose_key.kty,
                    coset::RegisteredLabel::Assigned(iana::KeyType::EC2)
                ) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                Ok(Self::P256(
                    p256::ecdsa::SigningKey::from_slice(bytes)
                        .map_err(|_| CoseKeyConversionError::InvalidCredential)?,
                ))
            }
            iana::Algorithm::Ed25519 => {
                if !matches!(
                    cose_key.kty,
                    coset::RegisteredLabel::Assigned(iana::KeyType::OKP)
                ) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                Ok(Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| CoseKeyConversionError::InvalidCredential)?,
                )))
            }
            _ => Err(CoseKeyConversionError::UnsupportedAlgorithm),
        }
    }

    fn sign(&mut self, target: &[u8]) -> Vec<u8> {
        match self {
            Self::P256(secret_key) => {
                let signature: p256::ecdsa::Signature = secret_key.sign(target);
                signature.to_der().to_vec()
            }
            Self::Ed25519(secret_key) => secret_key.sign(target).to_vec(),
        }
    }

    fn public_key(&self) -> Self::PublicKey {
        match self {
            Self::P256(secret_key) => RustCryptoPublicKey::P256(*secret_key.verifying_key()),
            Self::Ed25519(secret_key) => RustCryptoPublicKey::Ed25519(secret_key.verifying_key()),
        }
    }

    fn to_cose_key(&self) -> CoseKey {
        match self {
            Self::P256(secret_key) => {
                let public_key = secret_key.verifying_key().to_sec1_point(false);
                // SAFETY: These unwraps are safe because the public_key above is not compressed (false
                // parameter) therefore x and y are guaranteed to contain values.
                #[allow(deprecated)]
                let x = public_key.x().unwrap().as_slice().to_vec();
                #[allow(deprecated)]
                let y = public_key.y().unwrap().as_slice().to_vec();
                CoseKeyBuilder::new_ec2_priv_key(
                    iana::EllipticCurve::P_256,
                    x,
                    y,
                    secret_key.to_bytes().to_vec(),
                )
                .algorithm(iana::Algorithm::ES256)
                .build()
            }
            Self::Ed25519(secret_key) => CoseKeyBuilder::new_okp_key()
                .algorithm(iana::Algorithm::Ed25519)
                .param(
                    iana::OkpKeyParameter::Crv.to_i64(),
                    Value::from(iana::EllipticCurve::Ed25519.to_i64()),
                )
                .param(
                    iana::OkpKeyParameter::X.to_i64(),
                    Value::from(secret_key.verifying_key().to_bytes().as_slice()),
                )
                .param(
                    iana::OkpKeyParameter::D.to_i64(),
                    Value::from(&secret_key.to_bytes()[..]),
                )
                .build(),
        }
    }
}

pub struct RustCryptoSha2;

impl Sha256Backend for RustCryptoSha2 {
    /// Compute the SHA-256 of the given `data`.
    fn sha256(data: &[u8]) -> [u8; 32] {
        // SAFETY: sha256 always gives a 32 byte array
        Sha256::digest(data).into()
    }

    /// Compute the HMAC of the given data with the given key
    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac can take key of any size");
        mac.update(data);

        mac.finalize().into_bytes().into()
    }
}

pub struct RustCryptoBackend;

impl CryptoBackend for RustCryptoBackend {
    type Rng = ::rand::rngs::ThreadRng;
    type Sha256 = RustCryptoSha2;
    type SecretKey = RustCryptoSecretKey;

    fn enumerate_algorithms(&self) -> Vec<iana::Algorithm> {
        vec![
            iana::Algorithm::ES256,
            iana::Algorithm::PS256,
            iana::Algorithm::EdDSA,
            iana::Algorithm::Ed25519,
        ]
    }

    fn generate_key(&self, algorithm: iana::Algorithm) -> Result<Self::SecretKey, crate::Error> {
        match algorithm {
            iana::Algorithm::ES256 | iana::Algorithm::PS256 => Ok(RustCryptoSecretKey::P256(
                p256::ecdsa::SigningKey::generate(),
            )),
            iana::Algorithm::EdDSA | iana::Algorithm::Ed25519 => {
                let mut rng = ::rand::rng();
                Ok(RustCryptoSecretKey::Ed25519(
                    ed25519_dalek::SigningKey::generate(&mut rng),
                ))
            }
            _ => Err("Algorithm is unsupported".to_string().into()),
        }
    }
}

pub type RustCryptoRng = <RustCryptoBackend as CryptoBackend>::Rng;
