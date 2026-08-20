use coset::{
    CoseKey, CoseKeyBuilder, MlDsaVariant,
    cbor::Value,
    iana::{self, EnumI64},
};

use crate::{
    CoseKeyConversionError, CryptoBackend, PublicKeyT, SecretKeyT,
    cose::{
        ML_DSA_SEED_LEN, extract_akp_priv, extract_akp_pub, extract_okp_d, extract_okp_x,
        extract_p256_d, extract_p256_xy, find_ec2_crv, find_okp_crv,
    },
    hash::Sha256Backend,
};
use ed25519_dalek::{Signer, ed25519::SignatureEncoding};
use hmac::{Hmac, KeyInit, Mac};
use ml_dsa::pkcs8::{der::AnyRef, spki::AssociatedAlgorithmIdentifier};
use ml_dsa::{
    MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed as MlDsaSeed, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey, signature::Keypair,
};
use p256::{Sec1Point, elliptic_curve::Generate, pkcs8::EncodePublicKey};
use sha2::{Digest, Sha256};
use signature::Verifier;

/// Secret key backed by the RustCrypto crates.
pub struct RustCryptoSecretKey(RustCryptoSecretKeyInner);

enum RustCryptoSecretKeyInner {
    // Secret key that uses the P256 ECDSA algorithm.
    P256(p256::ecdsa::SigningKey),
    // Secret key that uses the Ed25519 EdDSA algorithm
    Ed25519(ed25519_dalek::SigningKey),
    // Secret key that uses ML-DSA-44.
    MlDsa44(MlDsaSigningKey<MlDsa44>),
    // Secret key that uses ML-DSA-65.
    MlDsa65(MlDsaSigningKey<MlDsa65>),
    // Secret key that uses ML-DSA-87.
    MlDsa87(MlDsaSigningKey<MlDsa87>),
}

/// Public key backed by the RustCrypto crates.
pub struct RustCryptoPublicKey(RustCryptoPublicKeyInner);

enum RustCryptoPublicKeyInner {
    // Public key that uses the P256 ECDSA algorithm.
    P256(p256::ecdsa::VerifyingKey),
    // Public key that uses the Ed25519 EdDSA algorithm
    Ed25519(ed25519_dalek::VerifyingKey),
    // Public key that uses ML-DSA-44.
    MlDsa44(MlDsaVerifyingKey<MlDsa44>),
    // Public key that uses ML-DSA-65.
    MlDsa65(MlDsaVerifyingKey<MlDsa65>),
    // Public key that uses ML-DSA-87.
    MlDsa87(MlDsaVerifyingKey<MlDsa87>),
}

impl PublicKeyT for RustCryptoPublicKey {
    fn verify(&self, target: &[u8], signature: &[u8]) -> Result<(), crate::Error> {
        match &self.0 {
            RustCryptoPublicKeyInner::P256(public_key) => {
                let signature = p256::ecdsa::Signature::from_der(signature)?;
                public_key.verify(target, &signature)?;
            }
            RustCryptoPublicKeyInner::Ed25519(public_key) => {
                let signature = ed25519_dalek::ed25519::Signature::from_slice(signature)?;
                public_key.verify(target, &signature)?;
            }
            RustCryptoPublicKeyInner::MlDsa44(public_key) => {
                verify_ml_dsa(public_key, target, signature)?;
            }
            RustCryptoPublicKeyInner::MlDsa65(public_key) => {
                verify_ml_dsa(public_key, target, signature)?;
            }
            RustCryptoPublicKeyInner::MlDsa87(public_key) => {
                verify_ml_dsa(public_key, target, signature)?;
            }
        }
        Ok(())
    }

    fn der_from_cose_key(cose_key: &CoseKey) -> Result<Vec<u8>, CoseKeyConversionError> {
        let Some(coset::RegisteredLabelWithPrivate::Assigned(alg)) = cose_key.alg else {
            return Err(CoseKeyConversionError::UnsupportedAlgorithm);
        };
        match alg {
            iana::Algorithm::ES256 | iana::Algorithm::ESP256 => {
                if !matches!(
                    cose_key.kty,
                    coset::RegisteredLabel::Assigned(iana::KeyType::EC2)
                ) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                if find_ec2_crv(cose_key)? != Some(iana::EllipticCurve::P_256.to_i64()) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                let (x, y) = extract_p256_xy(cose_key)?;
                let point = Sec1Point::from_affine_coordinates((&x).into(), (&y).into(), false);
                let Ok(pub_key) = p256::ecdsa::VerifyingKey::from_sec1_point(&point) else {
                    return Err(CoseKeyConversionError::InvalidCredential);
                };
                pub_key
                    .to_public_key_der()
                    .map_err(|_| CoseKeyConversionError::InvalidCredential)
                    .map(|pk| pk.as_ref().to_vec())
            }
            iana::Algorithm::EdDSA | iana::Algorithm::Ed25519 => {
                if !matches!(
                    cose_key.kty,
                    coset::RegisteredLabel::Assigned(iana::KeyType::OKP)
                ) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                if find_okp_crv(cose_key)? != Some(iana::EllipticCurve::Ed25519.to_i64()) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                let x = extract_okp_x(cose_key)?;
                let public_key = ed25519_dalek::VerifyingKey::from_bytes(&x)
                    .map_err(|_| CoseKeyConversionError::InvalidCredential)?;

                public_key
                    .to_public_key_der()
                    .map_err(|_| CoseKeyConversionError::InvalidCredential)
                    .map(|pk| pk.as_ref().to_vec())
            }
            iana::Algorithm::ML_DSA_44 => ml_dsa_der_from_cose_key::<MlDsa44>(cose_key),
            iana::Algorithm::ML_DSA_65 => ml_dsa_der_from_cose_key::<MlDsa65>(cose_key),
            iana::Algorithm::ML_DSA_87 => ml_dsa_der_from_cose_key::<MlDsa87>(cose_key),
            _ => Err(CoseKeyConversionError::UnsupportedAlgorithm),
        }
    }

    fn to_cose_key(&self) -> CoseKey {
        match &self.0 {
            RustCryptoPublicKeyInner::P256(public_key) => {
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
            RustCryptoPublicKeyInner::Ed25519(public_key) => CoseKeyBuilder::new_okp_key()
                .algorithm(iana::Algorithm::EdDSA)
                .param(
                    iana::OkpKeyParameter::Crv.to_i64(),
                    Value::from(iana::EllipticCurve::Ed25519.to_i64()),
                )
                .param(
                    iana::OkpKeyParameter::X.to_i64(),
                    Value::from(public_key.to_bytes().as_slice()),
                )
                .build(),
            RustCryptoPublicKeyInner::MlDsa44(public_key) => {
                ml_dsa_public_to_cose_key(public_key, MlDsaVariant::MlDsa44)
            }
            RustCryptoPublicKeyInner::MlDsa65(public_key) => {
                ml_dsa_public_to_cose_key(public_key, MlDsaVariant::MlDsa65)
            }
            RustCryptoPublicKeyInner::MlDsa87(public_key) => {
                ml_dsa_public_to_cose_key(public_key, MlDsaVariant::MlDsa87)
            }
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
            iana::Algorithm::ES256 | iana::Algorithm::ESP256 => {
                if !matches!(
                    cose_key.kty,
                    coset::RegisteredLabel::Assigned(iana::KeyType::EC2)
                ) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                if find_ec2_crv(cose_key)? != Some(iana::EllipticCurve::P_256.to_i64()) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                let d = extract_p256_d(cose_key)?;
                Ok(Self(RustCryptoSecretKeyInner::P256(
                    p256::ecdsa::SigningKey::from_slice(d.as_slice())
                        .map_err(|_| CoseKeyConversionError::InvalidCredential)?,
                )))
            }
            iana::Algorithm::EdDSA | iana::Algorithm::Ed25519 => {
                if !matches!(
                    cose_key.kty,
                    coset::RegisteredLabel::Assigned(iana::KeyType::OKP)
                ) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                if find_okp_crv(cose_key)? != Some(iana::EllipticCurve::Ed25519.to_i64()) {
                    return Err(CoseKeyConversionError::InvalidCredential);
                }
                let seed = extract_okp_d(cose_key)?;
                Ok(Self(RustCryptoSecretKeyInner::Ed25519(
                    ed25519_dalek::SigningKey::from_bytes(&seed),
                )))
            }
            iana::Algorithm::ML_DSA_44 => Ok(Self(RustCryptoSecretKeyInner::MlDsa44(
                ml_dsa_secret_from_cose_key(cose_key)?,
            ))),
            iana::Algorithm::ML_DSA_65 => Ok(Self(RustCryptoSecretKeyInner::MlDsa65(
                ml_dsa_secret_from_cose_key(cose_key)?,
            ))),
            iana::Algorithm::ML_DSA_87 => Ok(Self(RustCryptoSecretKeyInner::MlDsa87(
                ml_dsa_secret_from_cose_key(cose_key)?,
            ))),
            _ => Err(CoseKeyConversionError::UnsupportedAlgorithm),
        }
    }

    fn sign(&mut self, target: &[u8]) -> Vec<u8> {
        match &self.0 {
            RustCryptoSecretKeyInner::P256(secret_key) => {
                let signature: p256::ecdsa::Signature = secret_key.sign(target);
                signature.to_der().to_vec()
            }
            RustCryptoSecretKeyInner::Ed25519(secret_key) => secret_key.sign(target).to_vec(),
            RustCryptoSecretKeyInner::MlDsa44(secret_key) => ml_dsa_sign(secret_key, target),
            RustCryptoSecretKeyInner::MlDsa65(secret_key) => ml_dsa_sign(secret_key, target),
            RustCryptoSecretKeyInner::MlDsa87(secret_key) => ml_dsa_sign(secret_key, target),
        }
    }

    fn public_key(&self) -> Self::PublicKey {
        match &self.0 {
            RustCryptoSecretKeyInner::P256(secret_key) => {
                RustCryptoPublicKey(RustCryptoPublicKeyInner::P256(*secret_key.verifying_key()))
            }
            RustCryptoSecretKeyInner::Ed25519(secret_key) => RustCryptoPublicKey(
                RustCryptoPublicKeyInner::Ed25519(secret_key.verifying_key()),
            ),
            RustCryptoSecretKeyInner::MlDsa44(secret_key) => RustCryptoPublicKey(
                RustCryptoPublicKeyInner::MlDsa44(secret_key.verifying_key()),
            ),
            RustCryptoSecretKeyInner::MlDsa65(secret_key) => RustCryptoPublicKey(
                RustCryptoPublicKeyInner::MlDsa65(secret_key.verifying_key()),
            ),
            RustCryptoSecretKeyInner::MlDsa87(secret_key) => RustCryptoPublicKey(
                RustCryptoPublicKeyInner::MlDsa87(secret_key.verifying_key()),
            ),
        }
    }

    fn to_cose_key(&self) -> CoseKey {
        match &self.0 {
            RustCryptoSecretKeyInner::P256(secret_key) => {
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
            RustCryptoSecretKeyInner::Ed25519(secret_key) => CoseKeyBuilder::new_okp_key()
                .algorithm(iana::Algorithm::EdDSA)
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
            RustCryptoSecretKeyInner::MlDsa44(secret_key) => {
                ml_dsa_secret_to_cose_key(secret_key, MlDsaVariant::MlDsa44)
            }
            RustCryptoSecretKeyInner::MlDsa65(secret_key) => {
                ml_dsa_secret_to_cose_key(secret_key, MlDsaVariant::MlDsa65)
            }
            RustCryptoSecretKeyInner::MlDsa87(secret_key) => {
                ml_dsa_secret_to_cose_key(secret_key, MlDsaVariant::MlDsa87)
            }
        }
    }
}

/// [Sha256Backend] backed by RustCrypto
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

/// [CryptoBackend] backed by RustCrypto.
pub struct RustCryptoBackend;

impl CryptoBackend for RustCryptoBackend {
    type Rng = crate::rng::rand::RandRng;

    type Sha256 = RustCryptoSha2;

    type SecretKey = RustCryptoSecretKey;

    fn enumerate_algorithms(&self) -> Vec<iana::Algorithm> {
        vec![
            iana::Algorithm::ES256,
            iana::Algorithm::ESP256,
            iana::Algorithm::EdDSA,
            iana::Algorithm::Ed25519,
            iana::Algorithm::ML_DSA_44,
            iana::Algorithm::ML_DSA_65,
            iana::Algorithm::ML_DSA_87,
        ]
    }

    fn generate_key(&self, algorithm: iana::Algorithm) -> Result<Self::SecretKey, crate::Error> {
        match algorithm {
            iana::Algorithm::ES256 | iana::Algorithm::ESP256 => Ok(RustCryptoSecretKey(
                RustCryptoSecretKeyInner::P256(p256::ecdsa::SigningKey::generate()),
            )),
            iana::Algorithm::EdDSA | iana::Algorithm::Ed25519 => {
                let mut rng = ::rand::rng();
                Ok(RustCryptoSecretKey(RustCryptoSecretKeyInner::Ed25519(
                    ed25519_dalek::SigningKey::generate(&mut rng),
                )))
            }
            iana::Algorithm::ML_DSA_44 => Ok(RustCryptoSecretKey(
                RustCryptoSecretKeyInner::MlDsa44(ml_dsa_generate()),
            )),
            iana::Algorithm::ML_DSA_65 => Ok(RustCryptoSecretKey(
                RustCryptoSecretKeyInner::MlDsa65(ml_dsa_generate()),
            )),
            iana::Algorithm::ML_DSA_87 => Ok(RustCryptoSecretKey(
                RustCryptoSecretKeyInner::MlDsa87(ml_dsa_generate()),
            )),
            _ => Err("Algorithm is unsupported".to_string().into()),
        }
    }
}

/// Re-export of the [crate::rng::RngBackend] provided by this backend.
pub type RustCryptoRng = <RustCryptoBackend as CryptoBackend>::Rng;

fn verify_ml_dsa<P: MlDsaParams>(
    public_key: &MlDsaVerifyingKey<P>,
    target: &[u8],
    signature: &[u8],
) -> Result<(), crate::Error> {
    let signature = MlDsaSignature::<P>::try_from(signature)?;
    public_key.verify(target, &signature)?;
    Ok(())
}

fn ml_dsa_sign<P: MlDsaParams>(secret_key: &MlDsaSigningKey<P>, target: &[u8]) -> Vec<u8> {
    let signature: MlDsaSignature<P> = secret_key.sign(target);
    signature.encode().as_slice().to_vec()
}

fn ml_dsa_generate<P: MlDsaParams>() -> MlDsaSigningKey<P> {
    MlDsaSigningKey::<P>::generate()
}

fn ml_dsa_secret_from_cose_key<P: MlDsaParams>(
    cose_key: &CoseKey,
) -> Result<MlDsaSigningKey<P>, CoseKeyConversionError> {
    if !matches!(
        cose_key.kty,
        coset::RegisteredLabel::Assigned(iana::KeyType::AKP)
    ) {
        return Err(CoseKeyConversionError::InvalidCredential);
    }
    let seed = extract_akp_priv(cose_key)?;
    let seed_bytes: [u8; ML_DSA_SEED_LEN] = *seed;
    Ok(MlDsaSigningKey::<P>::from_seed(&MlDsaSeed::from(
        seed_bytes,
    )))
}

fn ml_dsa_der_from_cose_key<P>(cose_key: &CoseKey) -> Result<Vec<u8>, CoseKeyConversionError>
where
    P: MlDsaParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    if !matches!(
        cose_key.kty,
        coset::RegisteredLabel::Assigned(iana::KeyType::AKP)
    ) {
        return Err(CoseKeyConversionError::InvalidCredential);
    }
    let pub_bytes = extract_akp_pub(cose_key)?;
    let encoded = ml_dsa::EncodedVerifyingKey::<P>::try_from(pub_bytes.as_slice())
        .map_err(|_| CoseKeyConversionError::InvalidCredential)?;
    let verifying_key = MlDsaVerifyingKey::<P>::decode(&encoded);
    verifying_key
        .to_public_key_der()
        .map_err(|_| CoseKeyConversionError::InvalidCredential)
        .map(|pk| pk.as_ref().to_vec())
}

fn ml_dsa_public_to_cose_key<P: MlDsaParams>(
    public_key: &MlDsaVerifyingKey<P>,
    variant: MlDsaVariant,
) -> CoseKey {
    CoseKeyBuilder::new_mldsa_pub_key(variant, public_key.encode().as_slice().to_vec()).build()
}

fn ml_dsa_secret_to_cose_key<P: MlDsaParams>(
    secret_key: &MlDsaSigningKey<P>,
    variant: MlDsaVariant,
) -> CoseKey {
    let verifying_key = secret_key.verifying_key();
    CoseKeyBuilder::new_mldsa_pub_key(variant, verifying_key.encode().as_slice().to_vec())
        .param(
            iana::AkpKeyParameter::Priv.to_i64(),
            Value::from(secret_key.to_seed().as_slice()),
        )
        .build()
}
