use coset::{
    CoseKey, CoseKeyBuilder, MlDsaVariant,
    cbor::Value,
    iana::{self, EnumI64},
};

use crate::{CoseKeyConversionError, CryptoBackend, PublicKeyT, SecretKeyT};
use ed25519_dalek::{Signer, ed25519::SignatureEncoding};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use p256::{
    Sec1Point,
    elliptic_curve::{Generate, array::Array},
    pkcs8::EncodePublicKey,
};
use signature::{Keypair, Verifier};

pub enum RustCryptoSecretKey {
    P256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
    MlDsa44(ml_dsa::SigningKey<MlDsa44>),
    MlDsa65(ml_dsa::SigningKey<MlDsa65>),
    MlDsa87(ml_dsa::SigningKey<MlDsa87>),
}

pub enum RustCryptoPublicKey {
    P256(p256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
    MlDsa44(ml_dsa::VerifyingKey<MlDsa44>),
    MlDsa65(ml_dsa::VerifyingKey<MlDsa65>),
    MlDsa87(ml_dsa::VerifyingKey<MlDsa87>),
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
            Self::MlDsa44(public_key) => {
                let signature = ml_dsa::Signature::<MlDsa44>::try_from(signature)?;
                public_key.verify(target, &signature)?;
            }
            Self::MlDsa65(public_key) => {
                let signature = ml_dsa::Signature::<MlDsa65>::try_from(signature)?;
                public_key.verify(target, &signature)?;
            }
            Self::MlDsa87(public_key) => {
                let signature = ml_dsa::Signature::<MlDsa87>::try_from(signature)?;
                public_key.verify(target, &signature)?;
            }
        }
        Ok(())
    }

    fn bytes_from_cose_key(cose_key: &CoseKey) -> Result<Vec<u8>, CoseKeyConversionError> {
        let Some(coset::RegisteredLabelWithPrivate::Assigned(alg)) = cose_key.alg else {
            return Err(CoseKeyConversionError::UnsupportedAlgorithm);
        };
        if !matches!(
            alg,
            iana::Algorithm::ES256
                | iana::Algorithm::Ed25519
                | iana::Algorithm::ML_DSA_44
                | iana::Algorithm::ML_DSA_65
                | iana::Algorithm::ML_DSA_87
        ) {
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
                let mut x_bytes = None;
                for (key, value) in &cose_key.params {
                    if let coset::Label::Int(i) = key {
                        let key = iana::Ec2KeyParameter::from_i64(*i)
                            .ok_or(CoseKeyConversionError::InvalidCredential)?;
                        if key == iana::Ec2KeyParameter::X
                            && value.as_bytes().and_then(|v| x_bytes.replace(v)).is_some()
                        {
                            log::warn!("Cose key has multiple entries for X coordinate");
                        }
                    }
                }
                x_bytes
                    .map(|v| v.to_owned())
                    .ok_or(CoseKeyConversionError::InvalidCredential)
            }
            iana::Algorithm::ML_DSA_44
            | iana::Algorithm::ML_DSA_65
            | iana::Algorithm::ML_DSA_87 => {
                if !matches!(
                    cose_key.kty,
                    coset::RegisteredLabel::Assigned(iana::KeyType::AKP)
                ) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                let mut pub_bytes = None;
                for (key, value) in &cose_key.params {
                    if let coset::Label::Int(i) = key {
                        if *i == iana::AkpKeyParameter::Pub.to_i64()
                            && value
                                .as_bytes()
                                .and_then(|v| pub_bytes.replace(v))
                                .is_some()
                        {
                            log::warn!("AKP key has multiple entries for Pub parameter");
                        }
                    }
                }
                pub_bytes
                    .map(|v| v.to_owned())
                    .ok_or(CoseKeyConversionError::InvalidCredential)
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
            Self::MlDsa44(public_key) => CoseKeyBuilder::new_mldsa_pub_key(
                MlDsaVariant::MlDsa44,
                public_key.encode().to_vec(),
            )
            .build(),
            Self::MlDsa65(public_key) => CoseKeyBuilder::new_mldsa_pub_key(
                MlDsaVariant::MlDsa65,
                public_key.encode().to_vec(),
            )
            .build(),
            Self::MlDsa87(public_key) => CoseKeyBuilder::new_mldsa_pub_key(
                MlDsaVariant::MlDsa87,
                public_key.encode().to_vec(),
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
        match alg {
            iana::Algorithm::ES256 => {
                if !matches!(
                    cose_key.kty,
                    coset::RegisteredLabel::Assigned(iana::KeyType::EC2)
                ) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                let bytes = find_int_param(cose_key, iana::Ec2KeyParameter::D.to_i64())
                    .ok_or(CoseKeyConversionError::InvalidCredential)?;
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
                let bytes = find_int_param(cose_key, iana::OkpKeyParameter::D.to_i64())
                    .ok_or(CoseKeyConversionError::InvalidCredential)?;
                Ok(Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| CoseKeyConversionError::InvalidCredential)?,
                )))
            }
            iana::Algorithm::ML_DSA_44 => Ok(Self::MlDsa44(ml_dsa::SigningKey::from_seed(
                &mldsa_seed_from_cose_key(cose_key)?,
            ))),
            iana::Algorithm::ML_DSA_65 => Ok(Self::MlDsa65(ml_dsa::SigningKey::from_seed(
                &mldsa_seed_from_cose_key(cose_key)?,
            ))),
            iana::Algorithm::ML_DSA_87 => Ok(Self::MlDsa87(ml_dsa::SigningKey::from_seed(
                &mldsa_seed_from_cose_key(cose_key)?,
            ))),
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
            Self::MlDsa44(secret_key) => {
                let signature: ml_dsa::Signature<MlDsa44> = secret_key.sign(target);
                signature.to_vec()
            }
            Self::MlDsa65(secret_key) => {
                let signature: ml_dsa::Signature<MlDsa65> = secret_key.sign(target);
                signature.to_vec()
            }
            Self::MlDsa87(secret_key) => {
                let signature: ml_dsa::Signature<MlDsa87> = secret_key.sign(target);
                signature.to_vec()
            }
        }
    }

    fn public_key(&self) -> Self::PublicKey {
        match self {
            Self::P256(secret_key) => RustCryptoPublicKey::P256(*secret_key.verifying_key()),
            Self::Ed25519(secret_key) => RustCryptoPublicKey::Ed25519(secret_key.verifying_key()),
            Self::MlDsa44(secret_key) => RustCryptoPublicKey::MlDsa44(secret_key.verifying_key()),
            Self::MlDsa65(secret_key) => RustCryptoPublicKey::MlDsa65(secret_key.verifying_key()),
            Self::MlDsa87(secret_key) => RustCryptoPublicKey::MlDsa87(secret_key.verifying_key()),
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
            Self::MlDsa44(secret_key) => mldsa_priv_cose_key(
                MlDsaVariant::MlDsa44,
                secret_key.verifying_key().encode().to_vec(),
                secret_key.as_seed().to_vec(),
            ),
            Self::MlDsa65(secret_key) => mldsa_priv_cose_key(
                MlDsaVariant::MlDsa65,
                secret_key.verifying_key().encode().to_vec(),
                secret_key.as_seed().to_vec(),
            ),
            Self::MlDsa87(secret_key) => mldsa_priv_cose_key(
                MlDsaVariant::MlDsa87,
                secret_key.verifying_key().encode().to_vec(),
                secret_key.as_seed().to_vec(),
            ),
        }
    }
}

pub struct RustCryptoBackend;

impl CryptoBackend for RustCryptoBackend {
    type Rng = ::rand::rngs::ThreadRng;

    type SecretKey = RustCryptoSecretKey;

    fn enumerate_algorithms(&self) -> Vec<iana::Algorithm> {
        vec![
            iana::Algorithm::ES256,
            iana::Algorithm::PS256,
            iana::Algorithm::EdDSA,
            iana::Algorithm::Ed25519,
            iana::Algorithm::ML_DSA_44,
            iana::Algorithm::ML_DSA_65,
            iana::Algorithm::ML_DSA_87,
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
            iana::Algorithm::ML_DSA_44 => Ok(RustCryptoSecretKey::MlDsa44(ml_dsa::SigningKey::<
                MlDsa44,
            >::generate(
            ))),
            iana::Algorithm::ML_DSA_65 => Ok(RustCryptoSecretKey::MlDsa65(ml_dsa::SigningKey::<
                MlDsa65,
            >::generate(
            ))),
            iana::Algorithm::ML_DSA_87 => Ok(RustCryptoSecretKey::MlDsa87(ml_dsa::SigningKey::<
                MlDsa87,
            >::generate(
            ))),
            _ => Err("Algorithm is unsupported".to_string().into()),
        }
    }
}

pub type RustCryptoRng = <RustCryptoBackend as CryptoBackend>::Rng;

fn find_int_param(cose_key: &CoseKey, label: i64) -> Option<&Vec<u8>> {
    cose_key.params.iter().find_map(|(k, v)| {
        if let coset::Label::Int(i) = k {
            if *i == label { v.as_bytes() } else { None }
        } else {
            None
        }
    })
}

fn mldsa_seed_from_cose_key(cose_key: &CoseKey) -> Result<ml_dsa::Seed, CoseKeyConversionError> {
    if !matches!(
        cose_key.kty,
        coset::RegisteredLabel::Assigned(iana::KeyType::AKP)
    ) {
        return Err(CoseKeyConversionError::InvalidCredential);
    }
    let bytes = find_int_param(cose_key, iana::AkpKeyParameter::Priv.to_i64())
        .ok_or(CoseKeyConversionError::InvalidCredential)?;
    ml_dsa::Seed::try_from(bytes.as_slice()).map_err(|_| CoseKeyConversionError::InvalidCredential)
}

fn mldsa_priv_cose_key(variant: MlDsaVariant, pub_bytes: Vec<u8>, priv_bytes: Vec<u8>) -> CoseKey {
    CoseKeyBuilder::new_mldsa_pub_key(variant, pub_bytes)
        .param(
            iana::AkpKeyParameter::Priv.to_i64(),
            Value::Bytes(priv_bytes),
        )
        .build()
}
