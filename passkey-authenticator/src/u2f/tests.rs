use super::{AuthenticationRequest, Authenticator, RegisterRequest};
use crate::{u2f::U2fApi, user_validation::MockUserValidationMethod};
use generic_array::GenericArray;
use p256::{
    EncodedPoint,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
};
use passkey_types::{ctap2::Aaguid, *};

#[tokio::test]
async fn test_save_u2f_passkey() {
    let credstore: Option<Passkey> = None;
    let mut authenticator = Authenticator::new(
        Aaguid::new_empty(),
        credstore,
        MockUserValidationMethod::verified_user(0),
    );

    let challenge: [u8; 32] = ::rand::random();
    let application: [u8; 32] = ::rand::random();

    // Create a U2F request
    let reg_request = RegisterRequest {
        challenge,
        application,
    };

    let handle: [u8; 16] = ::rand::random();

    // Register the request and assert that it worked.
    let store_result = authenticator.register(reg_request, &handle[..]).await;
    assert!(store_result.is_ok());
    let response = store_result.unwrap();
    let public_key = response.public_key;

    // Now generate an authentication challenge using the original application
    let challenge: [u8; 32] = ::rand::random();
    let auth_req = AuthenticationRequest {
        parameter: u2f::AuthenticationParameter::CheckOnly,
        application,
        challenge,
        key_handle: handle.to_vec(),
    };

    // Try to authenticate.
    let counter = 181;
    let auth_result = authenticator
        .authenticate(auth_req, counter, ctap2::Flags::UV)
        .await;
    assert!(auth_result.is_ok());
    let auth_result = auth_result.unwrap();
    assert_eq!(auth_result.counter, counter);
    assert_eq!(auth_result.user_presence, ctap2::Flags::UV);

    // Now can we verify the signature from the Authenticator using the
    // public key we received above?

    // Recover the VerifyingKey from the uncompressed X, Y points for the public key
    let ep = EncodedPoint::from_affine_coordinates(
        &GenericArray::clone_from_slice(&public_key.x),
        &GenericArray::clone_from_slice(&public_key.y),
        false,
    );
    let verifying_key = VerifyingKey::from_encoded_point(&ep).unwrap();
    let sig = Signature::from_der(&auth_result.signature).unwrap();

    // Generate the expected challenge message that
    // the authenticator should have signed.
    // See docs for AuthenticationResponse for explanation.
    let signature_target = application
        .into_iter()
        .chain(std::iter::once(auth_result.user_presence.into()))
        .chain(auth_result.counter.to_be_bytes())
        .chain(challenge)
        .collect::<Vec<u8>>();

    // Verify that the given signature is correct for the given message.
    assert!(verifying_key.verify(&signature_target, &sig).is_ok());
}
