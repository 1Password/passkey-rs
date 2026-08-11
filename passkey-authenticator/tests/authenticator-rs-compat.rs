//! Tests for compatibility sanity checks with Authenticator-rs

use authenticator::MakeCredentialsResult;
use coset::iana;
use passkey_authenticator::{Authenticator, UiHint, UserCheck, UserValidationMethod};
use passkey_types::{
    Passkey,
    ctap2::{Ctap2Error, make_credential},
    rand, webauthn,
};

struct MockUV;

#[async_trait::async_trait]
impl UserValidationMethod for MockUV {
    type PasskeyItem = Passkey;

    async fn check_user<'a>(
        &self,
        _hint: UiHint<'a, Self::PasskeyItem>,
        presence: bool,
        verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        Ok(UserCheck {
            presence,
            verification,
        })
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

#[tokio::test]
async fn ensure_attestation_object_compatibility() {
    let mut auth = Authenticator::new([0; 16].into(), None::<Passkey>, MockUV);
    let cred_response = auth
        .make_credential(make_credential::Request {
            client_data_hash: rand::random_vec(32).into(),
            rp: make_credential::PublicKeyCredentialRpEntity {
                id: "webauth.io".to_string(),
                name: Some("webauthn.io".to_string()),
            },
            user: webauthn::PublicKeyCredentialUserEntity {
                id: rand::random_vec(16).into(),
                name: "wendy".to_string(),
                display_name: "wendy".to_string(),
            },
            pub_key_cred_params: vec![webauthn::PublicKeyCredentialParameters {
                ty: webauthn::PublicKeyCredentialType::PublicKey,
                alg: iana::Algorithm::ES256,
            }],
            exclude_list: None,
            extensions: None,
            options: make_credential::Options {
                rk: true,
                up: true,
                uv: false,
            },
            pin_auth: None,
            pin_protocol: None,
        })
        .await
        .expect("Creation failed");

    // Encode response as we do
    let mut attestation_obj = Vec::with_capacity(256);
    ciborium::into_writer(&cred_response, &mut attestation_obj).expect("Failed to serialize");

    // Decode response as Authenticator-rs does
    let make_cred_response: MakeCredentialsResult =
        serde_cbor::from_slice(attestation_obj.as_slice())
            .expect("Failed to deserialize for authenticator-rs");

    // Ensure that our public keys are correctly parseable as x.509 format.
    let auth_data = make_cred_response.att_obj.auth_data;
    let cose_key = auth_data.credential_data.unwrap().credential_public_key;
    let public_key = cose_key
        .der_spki()
        .expect("ensure our public key parses correctly");
    assert!(!public_key.is_empty());
}
