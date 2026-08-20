//! Tests for compatibility between the RustCryptoBackend and the AwsLcRsBackend. Non-deterministic
//! methods like the Rng methods and generate_key are not tested.

use coset::{
    CoseKey, CoseKeyBuilder, MlDsaVariant,
    cbor::Value,
    iana::{self, EnumI64},
};

use crate::{
    PublicKeyT, SecretKeyT,
    aws_lc_rs::{AwsLcRsPublicKey, AwsLcRsSecretKey, AwsLcRsSha2},
    hash::Sha256Backend,
    rust_crypto::{RustCryptoPublicKey, RustCryptoSecretKey, RustCryptoSha2},
};

const TEST_MESSAGES: &[&[u8]] = &[b"", b"\x72", b"passkey-rs", &[0x5a; 512]];

// RFC 6979 §A.2.5 P-256 test key.
const P256_D: [u8; 32] = [
    0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
    0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
];
const P256_X: [u8; 32] = [
    0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
    0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
];
const P256_Y: [u8; 32] = [
    0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
    0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
];

// RFC 8032 §7.1 test 2 Ed25519 keypair.
const ED25519_SEED: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];
const ED25519_PUB: [u8; 32] = [
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];

fn p256_pub_cose() -> CoseKey {
    CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, P256_X.to_vec(), P256_Y.to_vec())
        .algorithm(iana::Algorithm::ES256)
        .build()
}

fn p256_priv_cose() -> CoseKey {
    CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_256,
        P256_X.to_vec(),
        P256_Y.to_vec(),
        P256_D.to_vec(),
    )
    .algorithm(iana::Algorithm::ES256)
    .build()
}

fn ed25519_pub_cose() -> CoseKey {
    CoseKeyBuilder::new_okp_key()
        .algorithm(iana::Algorithm::EdDSA)
        .param(
            iana::OkpKeyParameter::Crv.to_i64(),
            Value::from(iana::EllipticCurve::Ed25519.to_i64()),
        )
        .param(
            iana::OkpKeyParameter::X.to_i64(),
            Value::from(ED25519_PUB.as_slice()),
        )
        .build()
}

fn ed25519_priv_cose() -> CoseKey {
    CoseKeyBuilder::new_okp_key()
        .algorithm(iana::Algorithm::EdDSA)
        .param(
            iana::OkpKeyParameter::Crv.to_i64(),
            Value::from(iana::EllipticCurve::Ed25519.to_i64()),
        )
        .param(
            iana::OkpKeyParameter::X.to_i64(),
            Value::from(ED25519_PUB.as_slice()),
        )
        .param(
            iana::OkpKeyParameter::D.to_i64(),
            Value::from(ED25519_SEED.as_slice()),
        )
        .build()
}

#[test]
fn sha256_matches() {
    let inputs: &[&[u8]] = &[
        b"",
        b"abc",
        b"The quick brown fox jumps over the lazy dog",
        &[0xa5; 1024],
    ];
    for input in inputs {
        assert_eq!(AwsLcRsSha2::sha256(input), RustCryptoSha2::sha256(input));
    }
}

#[test]
fn hmac_sha256_matches() {
    let cases: &[(&[u8], &[u8])] = &[
        (b"", b""),
        (b"key", b"The quick brown fox jumps over the lazy dog"),
        // RFC 4231 test case 1.
        (&[0x0b; 20], b"Hi There"),
        (&[0xaa; 131], &[0xdd; 250]),
    ];
    for (key, data) in cases {
        assert_eq!(
            AwsLcRsSha2::hmac_sha256(key, data),
            RustCryptoSha2::hmac_sha256(key, data),
        );
    }
}

#[test]
fn p256_public_der_from_cose_matches() {
    let cose = p256_pub_cose();
    let aws = AwsLcRsPublicKey::der_from_cose_key(&cose).unwrap();
    let rc = RustCryptoPublicKey::der_from_cose_key(&cose).unwrap();
    assert_eq!(aws, rc);
}

#[test]
fn ed25519_public_der_from_cose_matches() {
    let cose = ed25519_pub_cose();
    let aws = AwsLcRsPublicKey::der_from_cose_key(&cose).unwrap();
    let rc = RustCryptoPublicKey::der_from_cose_key(&cose).unwrap();
    assert_eq!(aws, rc);
}

#[test]
fn p256_secret_public_key_matches() {
    let cose = p256_priv_cose();
    let aws_sec = AwsLcRsSecretKey::from_cose_key(&cose).unwrap();
    let rc_sec = RustCryptoSecretKey::from_cose_key(&cose).unwrap();
    assert_eq!(
        aws_sec.public_key().to_cose_key(),
        rc_sec.public_key().to_cose_key(),
    );
}

#[test]
fn ed25519_secret_public_key_matches() {
    let cose = ed25519_priv_cose();
    let aws_sec = AwsLcRsSecretKey::from_cose_key(&cose).unwrap();
    let rc_sec = RustCryptoSecretKey::from_cose_key(&cose).unwrap();
    assert_eq!(
        aws_sec.public_key().to_cose_key(),
        rc_sec.public_key().to_cose_key(),
    );
}

#[test]
fn p256_secret_to_cose_matches() {
    let cose = p256_priv_cose();
    let aws_sec = AwsLcRsSecretKey::from_cose_key(&cose).unwrap();
    let rc_sec = RustCryptoSecretKey::from_cose_key(&cose).unwrap();
    assert_eq!(aws_sec.to_cose_key(), rc_sec.to_cose_key());
}

#[test]
fn ed25519_secret_to_cose_matches() {
    let cose = ed25519_priv_cose();
    let aws_sec = AwsLcRsSecretKey::from_cose_key(&cose).unwrap();
    let rc_sec = RustCryptoSecretKey::from_cose_key(&cose).unwrap();
    assert_eq!(aws_sec.to_cose_key(), rc_sec.to_cose_key());
}

#[test]
fn ed25519_sign_matches() {
    // Ed25519 signatures are deterministic per RFC 8032, so both backends must
    // produce identical signatures for a given key + message.
    let cose = ed25519_priv_cose();
    let mut aws_sec = AwsLcRsSecretKey::from_cose_key(&cose).unwrap();
    let mut rc_sec = RustCryptoSecretKey::from_cose_key(&cose).unwrap();
    for msg in TEST_MESSAGES {
        assert_eq!(aws_sec.sign(msg), rc_sec.sign(msg));
    }
}

// Cross-backend sign/verify tests: sign with one backend and verify with the
// other.

#[test]
fn p256_sign_rust_crypto_verify_aws_lc_rs() {
    let cose = p256_priv_cose();
    let mut rc_sec = RustCryptoSecretKey::from_cose_key(&cose).unwrap();
    let aws_pub = AwsLcRsSecretKey::from_cose_key(&cose).unwrap().public_key();
    for msg in TEST_MESSAGES {
        let sig = rc_sec.sign(msg);
        aws_pub
            .verify(msg, &sig)
            .expect("aws-lc-rs must verify a RustCrypto P-256 signature");
    }
}

#[test]
fn p256_sign_aws_lc_rs_verify_rust_crypto() {
    let cose = p256_priv_cose();
    let mut aws_sec = AwsLcRsSecretKey::from_cose_key(&cose).unwrap();
    let rc_pub = RustCryptoSecretKey::from_cose_key(&cose)
        .unwrap()
        .public_key();
    for msg in TEST_MESSAGES {
        let sig = aws_sec.sign(msg);
        rc_pub
            .verify(msg, &sig)
            .expect("RustCrypto must verify an aws-lc-rs P-256 signature");
    }
}

#[test]
fn ed25519_sign_rust_crypto_verify_aws_lc_rs() {
    let cose = ed25519_priv_cose();
    let mut rc_sec = RustCryptoSecretKey::from_cose_key(&cose).unwrap();
    let aws_pub = AwsLcRsSecretKey::from_cose_key(&cose).unwrap().public_key();
    for msg in TEST_MESSAGES {
        let sig = rc_sec.sign(msg);
        aws_pub
            .verify(msg, &sig)
            .expect("aws-lc-rs must verify a RustCrypto Ed25519 signature");
    }
}

#[test]
fn ed25519_sign_aws_lc_rs_verify_rust_crypto() {
    let cose = ed25519_priv_cose();
    let mut aws_sec = AwsLcRsSecretKey::from_cose_key(&cose).unwrap();
    let rc_pub = RustCryptoSecretKey::from_cose_key(&cose)
        .unwrap()
        .public_key();
    for msg in TEST_MESSAGES {
        let sig = aws_sec.sign(msg);
        rc_pub
            .verify(msg, &sig)
            .expect("RustCrypto must verify an aws-lc-rs Ed25519 signature");
    }
}

// ML-DSA tests.
const ML_DSA_SEED_44: [u8; 32] = [0x11; 32];
const ML_DSA_SEED_65: [u8; 32] = [0x22; 32];
const ML_DSA_SEED_87: [u8; 32] = [0x33; 32];

fn ml_dsa_priv_cose(variant: MlDsaVariant, seed: &[u8]) -> CoseKey {
    // Derive the raw public key with the RustCrypto backend so we can put it in the COSE key
    // alongside the seed.
    let priv_cose_no_pub = CoseKeyBuilder::new_mldsa_pub_key(variant, Vec::new())
        .param(
            iana::AkpKeyParameter::Priv.to_i64(),
            Value::from(seed.to_vec()),
        )
        .build();
    let secret =
        RustCryptoSecretKey::from_cose_key(&priv_cose_no_pub).expect("valid ml-dsa seed");
    secret.to_cose_key()
}

fn ml_dsa_pub_cose(variant: MlDsaVariant, seed: &[u8]) -> CoseKey {
    let priv_cose = ml_dsa_priv_cose(variant, seed);
    RustCryptoSecretKey::from_cose_key(&priv_cose)
        .unwrap()
        .public_key()
        .to_cose_key()
}

fn ml_dsa_der_matches(variant: MlDsaVariant, seed: &[u8]) {
    let cose = ml_dsa_pub_cose(variant, seed);
    let aws = AwsLcRsPublicKey::der_from_cose_key(&cose).unwrap();
    let rc = RustCryptoPublicKey::der_from_cose_key(&cose).unwrap();
    assert_eq!(aws, rc, "ML-DSA {:?} DER mismatch", variant);
}

#[test]
fn ml_dsa_public_der_from_cose_matches() {
    ml_dsa_der_matches(MlDsaVariant::MlDsa44, &ML_DSA_SEED_44);
    ml_dsa_der_matches(MlDsaVariant::MlDsa65, &ML_DSA_SEED_65);
    ml_dsa_der_matches(MlDsaVariant::MlDsa87, &ML_DSA_SEED_87);
}

fn ml_dsa_public_key_matches(variant: MlDsaVariant, seed: &[u8]) {
    let cose = ml_dsa_priv_cose(variant, seed);
    let aws_sec = AwsLcRsSecretKey::from_cose_key(&cose).unwrap();
    let rc_sec = RustCryptoSecretKey::from_cose_key(&cose).unwrap();
    assert_eq!(
        aws_sec.public_key().to_cose_key(),
        rc_sec.public_key().to_cose_key(),
        "ML-DSA {:?} public key mismatch",
        variant,
    );
}

#[test]
fn ml_dsa_secret_public_key_matches() {
    ml_dsa_public_key_matches(MlDsaVariant::MlDsa44, &ML_DSA_SEED_44);
    ml_dsa_public_key_matches(MlDsaVariant::MlDsa65, &ML_DSA_SEED_65);
    ml_dsa_public_key_matches(MlDsaVariant::MlDsa87, &ML_DSA_SEED_87);
}

fn ml_dsa_secret_cose_matches(variant: MlDsaVariant, seed: &[u8]) {
    let cose = ml_dsa_priv_cose(variant, seed);
    let aws_sec = AwsLcRsSecretKey::from_cose_key(&cose).unwrap();
    let rc_sec = RustCryptoSecretKey::from_cose_key(&cose).unwrap();
    assert_eq!(
        aws_sec.to_cose_key(),
        rc_sec.to_cose_key(),
        "ML-DSA {:?} secret COSE mismatch",
        variant,
    );
}

#[test]
fn ml_dsa_secret_to_cose_matches() {
    ml_dsa_secret_cose_matches(MlDsaVariant::MlDsa44, &ML_DSA_SEED_44);
    ml_dsa_secret_cose_matches(MlDsaVariant::MlDsa65, &ML_DSA_SEED_65);
    ml_dsa_secret_cose_matches(MlDsaVariant::MlDsa87, &ML_DSA_SEED_87);
}

fn ml_dsa_cross_verify(variant: MlDsaVariant, seed: &[u8]) {
    let cose = ml_dsa_priv_cose(variant, seed);
    let mut rc_sec = RustCryptoSecretKey::from_cose_key(&cose).unwrap();
    let mut aws_sec = AwsLcRsSecretKey::from_cose_key(&cose).unwrap();
    let aws_pub = aws_sec.public_key();
    let rc_pub = rc_sec.public_key();

    for msg in TEST_MESSAGES {
        let rc_sig = rc_sec.sign(msg);
        aws_pub
            .verify(msg, &rc_sig)
            .expect("aws-lc-rs must verify a RustCrypto ML-DSA signature");

        let aws_sig = aws_sec.sign(msg);
        rc_pub
            .verify(msg, &aws_sig)
            .expect("RustCrypto must verify an aws-lc-rs ML-DSA signature");
    }
}

#[test]
fn ml_dsa_cross_backend_sign_verify() {
    ml_dsa_cross_verify(MlDsaVariant::MlDsa44, &ML_DSA_SEED_44);
    ml_dsa_cross_verify(MlDsaVariant::MlDsa65, &ML_DSA_SEED_65);
    ml_dsa_cross_verify(MlDsaVariant::MlDsa87, &ML_DSA_SEED_87);
}
