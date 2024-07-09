use std::collections::HashMap;

use passkey_authenticator::extensions::HmacSecretConfig;

use super::*;

#[tokio::test]
async fn registration_without_eval() {
    let auth = Authenticator::new(
        ctap2::Aaguid::new_empty(),
        MemoryStore::new(),
        uv_mock_with_creation(1),
    )
    .hmac_secret(HmacSecretConfig::new_without_uv());

    let mut client = Client::new(auth);

    let origin = Url::parse("https://future.1password.com").unwrap();
    let options = webauthn::CredentialCreationOptions {
        public_key: webauthn::PublicKeyCredentialCreationOptions {
            extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval: None,
                    eval_by_credential: None,
                }),
                ..Default::default()
            }),
            ..good_credential_creation_options()
        },
    };
    let cred = client
        .register(&origin, options, None)
        .await
        .expect("failed to register with options and prf ext");

    let prf_out = cred
        .client_extension_results
        .prf
        .expect("client extension results should contain PRF output");

    assert!(prf_out.enabled.expect("PRF should be enabled"));
    assert!(prf_out.results.is_none());
}

fn uv_mock_user_check_skip(times: usize) -> MockUserValidationMethod {
    let mut user_mock = MockUserValidationMethod::new();
    user_mock
        .expect_is_verification_enabled()
        .returning(|| Some(true));
    user_mock
        .expect_check_user()
        .with(
            mockall::predicate::always(),
            mockall::predicate::eq(true),
            mockall::predicate::eq(true),
        )
        .returning(|_, _, _| {
            Ok(UserCheck {
                presence: true,
                verification: true,
            })
        })
        .times(times - 1);
    user_mock.expect_is_presence_enabled().returning(|| true);
    user_mock
}

#[tokio::test]
async fn registration_with_eval_by_credential() {
    let auth = Authenticator::new(
        ctap2::Aaguid::new_empty(),
        MemoryStore::new(),
        uv_mock_user_check_skip(1),
    )
    .hmac_secret(HmacSecretConfig::new_without_uv());
    let mut client = Client::new(auth);

    let origin = Url::parse("https://future.1password.com").unwrap();
    let options = webauthn::CredentialCreationOptions {
        public_key: webauthn::PublicKeyCredentialCreationOptions {
            extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval: None,
                    eval_by_credential: Some(HashMap::new()),
                }),
                ..Default::default()
            }),
            ..good_credential_creation_options()
        },
    };
    let registration_res = client.register(&origin, options, None).await;

    assert!(matches!(
        registration_res,
        Err(WebauthnError::NotSupportedError)
    ));
}
