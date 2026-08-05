use passkey_crypto::{
    iana,
    CryptoBackend, PublicKeyT, SecretKeyT,
    rng::RngBackend,
    rust_crypto::{RustCryptoBackend, RustCryptoRng},
};
use passkey_types::ctap2::AuthenticatorData;

#[test]
fn private_key_cose_round_trip_sanity_check() {
    let original_private_key = RustCryptoBackend
        .generate_key(iana::Algorithm::ES256)
        .expect("Backend does not support ES256");
    let private_cose = original_private_key.to_cose_key();
    let public_key = original_private_key.public_key();

    let auth_data = AuthenticatorData::new("future.1password.com", None);
    let mut signature_target = auth_data.to_vec();
    signature_target.extend(RustCryptoRng::random_vec(32));

    let mut reconstructed_private_key =
        <RustCryptoBackend as CryptoBackend>::SecretKey::from_cose_key(&private_cose)
            .expect("to get a private key");

    let signature = reconstructed_private_key.sign(&signature_target);

    // TODO: this currently fails because private_key.sign() performs DER encoding for P256
    // signatures. Should we have a separate "sign_with_der" method?
    public_key
        .verify(&signature_target, &signature)
        .expect("failed to verify signature")
}
