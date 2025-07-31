use coset::iana;
use p256::{
    SecretKey,
    ecdsa::{
        SigningKey,
        signature::{Signer, Verifier},
    },
};
use passkey_types::{ctap2::AuthenticatorData, rand::random_vec};

use super::{CoseKeyPair, private_key_from_cose_key};

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
