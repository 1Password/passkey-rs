use coset::{
    CoseKey, CoseKeyBuilder,
    cbor::Value,
    iana::{self, EnumI64},
};

use std::ops::RangeInclusive;

use crate::{
    CoseKeyConversionError, CryptoBackend, PublicKeyT, SecretKeyT,
    cose::{
        ED25519_KEY_LEN, P256_UNCOMPRESSED_LEN, extract_okp_d, extract_okp_x, extract_p256_d,
        extract_p256_xy, find_ec2_crv, find_okp_crv, find_okp_x, p256_uncompressed,
        split_p256_uncompressed,
    },
    hash::Sha256Backend,
    rng::RngBackend,
};
use aws_lc_rs::{
    digest,
    encoding::{AsBigEndian, AsDer},
    hmac,
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ED25519, EcdsaKeyPair,
        Ed25519KeyPair, KeyPair, ParsedPublicKey, UnparsedPublicKey,
    },
};

/// Secret key backed by aws-lc-rs.
pub struct AwsLcRsSecretKey(AwsLcRsSecretKeyInner);

enum AwsLcRsSecretKeyInner {
    // Secret key that uses the P-256 ECDSA algorithm.
    P256(EcdsaKeyPair),
    // Secret key that uses the Ed25519 EdDSA algorithm.
    Ed25519(Ed25519KeyPair),
}

/// Public key backed by aws-lc-rs.
pub struct AwsLcRsPublicKey(AwsLcRsPublicKeyInner);

enum AwsLcRsPublicKeyInner {
    // Uncompressed SEC1 encoding: 0x04 || X || Y (65 bytes).
    P256([u8; P256_UNCOMPRESSED_LEN]),
    // Raw 32-byte Ed25519 public key.
    Ed25519([u8; ED25519_KEY_LEN]),
}

impl PublicKeyT for AwsLcRsPublicKey {
    fn verify(&self, target: &[u8], signature: &[u8]) -> Result<(), crate::Error> {
        match &self.0 {
            AwsLcRsPublicKeyInner::P256(bytes) => {
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, bytes.as_slice())
                    .verify(target, signature)?;
            }
            AwsLcRsPublicKeyInner::Ed25519(bytes) => {
                UnparsedPublicKey::new(&ED25519, bytes.as_slice()).verify(target, signature)?;
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
                let uncompressed = p256_uncompressed(&x, &y);
                let parsed = ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, uncompressed.as_slice())
                    .map_err(|_| CoseKeyConversionError::InvalidCredential)?;
                let der = parsed
                    .as_der()
                    .map_err(|_| CoseKeyConversionError::InvalidCredential)?;
                Ok(der.as_ref().to_vec())
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
                let parsed = ParsedPublicKey::new(&ED25519, x.as_slice())
                    .map_err(|_| CoseKeyConversionError::InvalidCredential)?;
                let der = parsed
                    .as_der()
                    .map_err(|_| CoseKeyConversionError::InvalidCredential)?;
                Ok(der.as_ref().to_vec())
            }
            _ => Err(CoseKeyConversionError::UnsupportedAlgorithm),
        }
    }

    fn to_cose_key(&self) -> CoseKey {
        match &self.0 {
            AwsLcRsPublicKeyInner::P256(bytes) => {
                let (x, y) = split_p256_uncompressed(bytes);
                CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
                    .algorithm(iana::Algorithm::ES256)
                    .build()
            }
            AwsLcRsPublicKeyInner::Ed25519(bytes) => CoseKeyBuilder::new_okp_key()
                .algorithm(iana::Algorithm::EdDSA)
                .param(
                    iana::OkpKeyParameter::Crv.to_i64(),
                    Value::from(iana::EllipticCurve::Ed25519.to_i64()),
                )
                .param(
                    iana::OkpKeyParameter::X.to_i64(),
                    Value::from(bytes.as_slice()),
                )
                .build(),
        }
    }
}

impl SecretKeyT for AwsLcRsSecretKey {
    type PublicKey = AwsLcRsPublicKey;

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
                let (x, y) = extract_p256_xy(cose_key)?;
                let d = extract_p256_d(cose_key)?;
                let uncompressed = p256_uncompressed(&x, &y);
                // aws-lc-rs verifies that D and (X, Y) belong to the same key pair
                // as part of `from_private_key_and_public_key`.
                let key_pair = EcdsaKeyPair::from_private_key_and_public_key(
                    &ECDSA_P256_SHA256_ASN1_SIGNING,
                    d.as_slice(),
                    &uncompressed,
                )
                .map_err(|_| CoseKeyConversionError::InvalidCredential)?;
                Ok(Self(AwsLcRsSecretKeyInner::P256(key_pair)))
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
                // When the COSE key carries the public key alongside the seed, use
                // aws-lc-rs' consistency-checked constructor so a mismatched X is rejected.
                let key_pair = match find_okp_x(cose_key)? {
                    Some(public_key) => {
                        Ed25519KeyPair::from_seed_and_public_key(seed.as_slice(), &public_key)
                    }
                    None => Ed25519KeyPair::from_seed_unchecked(seed.as_slice()),
                }
                .map_err(|_| CoseKeyConversionError::InvalidCredential)?;
                Ok(Self(AwsLcRsSecretKeyInner::Ed25519(key_pair)))
            }
            _ => Err(CoseKeyConversionError::UnsupportedAlgorithm),
        }
    }

    fn sign(&mut self, target: &[u8]) -> Vec<u8> {
        match &self.0 {
            AwsLcRsSecretKeyInner::P256(key_pair) => {
                let rng = SystemRandom::new();
                let signature = key_pair
                    .sign(&rng, target)
                    .expect("aws-lc-rs ECDSA P-256 signing failed");
                signature.as_ref().to_vec()
            }
            AwsLcRsSecretKeyInner::Ed25519(key_pair) => key_pair.sign(target).as_ref().to_vec(),
        }
    }

    fn public_key(&self) -> Self::PublicKey {
        match &self.0 {
            AwsLcRsSecretKeyInner::P256(key_pair) => {
                let mut bytes = [0u8; P256_UNCOMPRESSED_LEN];
                bytes.copy_from_slice(key_pair.public_key().as_ref());
                AwsLcRsPublicKey(AwsLcRsPublicKeyInner::P256(bytes))
            }
            AwsLcRsSecretKeyInner::Ed25519(key_pair) => {
                let mut bytes = [0u8; ED25519_KEY_LEN];
                bytes.copy_from_slice(key_pair.public_key().as_ref());
                AwsLcRsPublicKey(AwsLcRsPublicKeyInner::Ed25519(bytes))
            }
        }
    }

    fn to_cose_key(&self) -> CoseKey {
        match &self.0 {
            AwsLcRsSecretKeyInner::P256(key_pair) => {
                let (x, y) = split_p256_uncompressed(
                    key_pair
                        .public_key()
                        .as_ref()
                        .try_into()
                        .expect("aws-lc-rs P-256 public key is 65 bytes"),
                );
                let d = key_pair
                    .private_key()
                    .as_be_bytes()
                    .expect("aws-lc-rs failed to marshal a P-256 private scalar");
                CoseKeyBuilder::new_ec2_priv_key(
                    iana::EllipticCurve::P_256,
                    x.to_vec(),
                    y.to_vec(),
                    d.as_ref().to_vec(),
                )
                .algorithm(iana::Algorithm::ES256)
                .build()
            }
            AwsLcRsSecretKeyInner::Ed25519(key_pair) => {
                let seed = key_pair
                    .seed()
                    .and_then(|s| s.as_be_bytes())
                    .expect("aws-lc-rs failed to marshal an Ed25519 seed");
                CoseKeyBuilder::new_okp_key()
                    .algorithm(iana::Algorithm::EdDSA)
                    .param(
                        iana::OkpKeyParameter::Crv.to_i64(),
                        Value::from(iana::EllipticCurve::Ed25519.to_i64()),
                    )
                    .param(
                        iana::OkpKeyParameter::X.to_i64(),
                        Value::from(key_pair.public_key().as_ref()),
                    )
                    .param(
                        iana::OkpKeyParameter::D.to_i64(),
                        Value::from(seed.as_ref()),
                    )
                    .build()
            }
        }
    }
}

/// [Sha256Backend] backed by aws-lc-rs.
pub struct AwsLcRsSha2;

impl Sha256Backend for AwsLcRsSha2 {
    fn sha256(data: &[u8]) -> [u8; 32] {
        let out = digest::digest(&digest::SHA256, data);
        out.as_ref().try_into().expect("SHA-256 output is 32 bytes")
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&key, data);
        tag.as_ref()
            .try_into()
            .expect("HMAC-SHA-256 tag is 32 bytes")
    }
}

/// [RngBackend] backed by [`aws_lc_rs::rand`].
pub struct AwsLcRsRng;

impl RngBackend for AwsLcRsRng {
    fn random_vec(len: usize) -> Vec<u8> {
        let mut data = vec![0u8; len];
        aws_lc_rs::rand::fill(&mut data).expect("aws-lc-rs RNG failure");
        data
    }

    fn random_array<const N: usize>() -> [u8; N] {
        let mut bytes = [0u8; N];
        aws_lc_rs::rand::fill(&mut bytes).expect("aws-lc-rs RNG failure");
        bytes
    }

    fn from_range(range: RangeInclusive<u8>) -> u8 {
        let low = *range.start();
        let high = *range.end();
        if low >= high {
            return low;
        }
        // span is in 2..=256 here (low < high, so at least 2 possibilities).
        let span: u16 = u16::from(high - low) + 1;
        // Largest multiple of `span` that fits in a byte: reject samples above it
        // so the modulus doesn't bias the low residues.
        let cutoff: u16 = 256 - (256 % span);
        loop {
            let mut buf = [0u8; 1];
            aws_lc_rs::rand::fill(&mut buf).expect("aws-lc-rs RNG failure");
            let sample = u16::from(buf[0]);
            if sample < cutoff {
                let offset =
                    u8::try_from(sample % span).expect("sample % span is < 256 by construction");
                return low + offset;
            }
        }
    }
}

/// [CryptoBackend] backed by aws-lc-rs.
pub struct AwsLcRsBackend;

impl CryptoBackend for AwsLcRsBackend {
    type Rng = AwsLcRsRng;

    type Sha256 = AwsLcRsSha2;

    type SecretKey = AwsLcRsSecretKey;

    fn enumerate_algorithms(&self) -> Vec<iana::Algorithm> {
        vec![
            iana::Algorithm::ES256,
            iana::Algorithm::ESP256,
            iana::Algorithm::EdDSA,
            iana::Algorithm::Ed25519,
        ]
    }

    fn generate_key(&self, algorithm: iana::Algorithm) -> Result<Self::SecretKey, crate::Error> {
        match algorithm {
            iana::Algorithm::ES256 | iana::Algorithm::ESP256 => {
                let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)?;
                Ok(AwsLcRsSecretKey(AwsLcRsSecretKeyInner::P256(key_pair)))
            }
            iana::Algorithm::EdDSA | iana::Algorithm::Ed25519 => {
                let key_pair = Ed25519KeyPair::generate()?;
                Ok(AwsLcRsSecretKey(AwsLcRsSecretKeyInner::Ed25519(key_pair)))
            }
            _ => Err("Algorithm is unsupported".to_string().into()),
        }
    }
}
