use coset::iana;
use p256::ecdsa::{
    SigningKey,
    signature::{Signer, Verifier},
};
use passkey_crypto::{
    CryptoBackend, SecretKeyT,
    rng::{Rng, RngBackend},
    rust_crypto::RustCryptoBackend,
};
use passkey_types::ctap2::AuthenticatorData;

use super::private_key_from_cose_key;

#[test]
fn private_key_cose_round_trip_sanity_check() {
    let private_key = RustCryptoBackend
        .generate_key(iana::Algorithm::ES256)
        .expect("Backend does not support ES256");
    let private_cose = private_key.to_cose_key();
    let public_signing_key = SigningKey::from(&private_key);
    let public_key = public_signing_key.verifying_key();

    let auth_data = AuthenticatorData::new("future.1password.com", None);
    let mut signature_target = auth_data.to_vec();
    signature_target.extend(Rng::random_vec(32));

    let secret_key = private_key_from_cose_key(&private_cose).expect("to get a private key");

    let private_key = SigningKey::from(secret_key);
    let signature: p256::ecdsa::Signature = private_key.sign(&signature_target);

    public_key
        .verify(&signature_target, &signature)
        .expect("failed to verify signature")
}
