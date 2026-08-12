use passkey_crypto::rng::RngBackend;
use passkey_crypto::rust_crypto::{RustCryptoBackend, RustCryptoRng};
use passkey_types::{
    Passkey, StoredHmacSecret,
    ctap2::{
        Aaguid, Ctap2Error,
        get_assertion::{ExtensionInputs, Options, Request},
    },
};

use crate::{
    Authenticator, MockUserValidationMethod,
    extensions::{self, prf_eval_request},
    user_validation::MockUiHint,
};

fn create_passkey(hmac_secret: Option<Vec<u8>>) -> Passkey {
    let builder = Passkey::mock("example.com".into(), RustCryptoBackend);

    if let Some(hs) = hmac_secret {
        builder.hmac_secret(StoredHmacSecret {
            cred_with_uv: hs,
            cred_without_uv: None,
        })
    } else {
        builder
    }
    .build()
}

fn good_request() -> Request {
    Request {
        rp_id: "example.com".into(),
        client_data_hash: vec![0; 32].into(),
        allow_list: None,
        extensions: None,
        pin_auth: None,
        pin_protocol: None,
        options: Options { up: true, uv: true },
    }
}

#[tokio::test]
async fn get_assertion_returns_no_credentials_found() {
    // Arrange
    let request = good_request();
    let store = None;
    let mut authenticator = Authenticator::new(
        Aaguid::new_empty(),
        store,
        MockUserValidationMethod::verified_user_with_hint(1, MockUiHint::InformNoCredentialsFound),
        RustCryptoBackend,
    );

    // Act
    let response = authenticator.get_assertion(request).await;

    // Assert
    assert_eq!(response.unwrap_err(), Ctap2Error::NoCredentials.into(),);
}

#[tokio::test]
async fn get_assertion_increments_signature_counter_when_counter_is_some() {
    // Arrange
    let request = good_request();
    let passkey = Passkey {
        counter: Some(9000),
        ..create_passkey(None)
    };
    let store = Some(passkey.clone());
    let mut authenticator = Authenticator::new(
        Aaguid::new_empty(),
        store,
        MockUserValidationMethod::verified_user_with_hint(
            1,
            MockUiHint::RequestExistingCredential(passkey),
        ),
        RustCryptoBackend,
    );

    // Act
    let response = authenticator.get_assertion(request).await.unwrap();

    // Assert
    assert_eq!(response.auth_data.counter.unwrap(), 9001);
    assert_eq!(
        authenticator
            .store()
            .as_ref()
            .and_then(|c| c.counter)
            .unwrap(),
        9001
    );
}

#[tokio::test]
async fn unsupported_extension_with_request_gives_no_ext_output() {
    let shared_store = Some(create_passkey(None));
    let user_mock = MockUserValidationMethod::verified_user(1);

    let mut authenticator = Authenticator::new(
        Aaguid::new_empty(),
        shared_store.clone(),
        user_mock,
        RustCryptoBackend,
    );

    let request = Request {
        extensions: Some(ExtensionInputs {
            prf: Some(prf_eval_request(Some(RustCryptoRng::random_vec(32)))),
            ..Default::default()
        }),
        ..good_request()
    };

    let res = authenticator
        .get_assertion(request)
        .await
        .expect("error happened while trying to authenticate a credential");

    assert!(res.auth_data.extensions.is_none());
    assert!(res.unsigned_extension_outputs.is_none());
}

#[tokio::test]
async fn unsupported_extension_with_empty_request_gives_no_ext_output() {
    let shared_store = Some(create_passkey(None));
    let user_mock = MockUserValidationMethod::verified_user(1);

    let mut authenticator = Authenticator::new(
        Aaguid::new_empty(),
        shared_store.clone(),
        user_mock,
        RustCryptoBackend,
    );

    let request = Request {
        extensions: Some(ExtensionInputs::default()),
        ..good_request()
    };

    let res = authenticator
        .get_assertion(request)
        .await
        .expect("error happened while trying to authenticate a credential");

    assert!(res.auth_data.extensions.is_none());
    assert!(res.unsigned_extension_outputs.is_none());
}

#[tokio::test]
async fn supported_extension_with_empty_request_gives_no_ext_output() {
    let shared_store = Some(create_passkey(Some(RustCryptoRng::random_vec(32))));
    let user_mock = MockUserValidationMethod::verified_user(1);

    let mut authenticator = Authenticator::new(
        Aaguid::new_empty(),
        shared_store.clone(),
        user_mock,
        RustCryptoBackend,
    )
    .hmac_secret(extensions::HmacSecretConfig::new_with_uv_only());

    let request = Request {
        extensions: Some(ExtensionInputs::default()),
        ..good_request()
    };

    let res = authenticator
        .get_assertion(request)
        .await
        .expect("error happened while trying to authenticate a credential");

    assert!(res.auth_data.extensions.is_none());
    assert!(res.unsigned_extension_outputs.is_none());
}

#[tokio::test]
async fn supported_extension_without_extension_request_gives_no_ext_output() {
    let shared_store = Some(create_passkey(Some(RustCryptoRng::random_vec(32))));
    let user_mock = MockUserValidationMethod::verified_user(1);

    let mut authenticator = Authenticator::new(
        Aaguid::new_empty(),
        shared_store.clone(),
        user_mock,
        RustCryptoBackend,
    )
    .hmac_secret(extensions::HmacSecretConfig::new_with_uv_only());

    let request = good_request();

    let res = authenticator
        .get_assertion(request)
        .await
        .expect("error happened while trying to authenticate a credential");

    assert!(res.auth_data.extensions.is_none());
    assert!(res.unsigned_extension_outputs.is_none());
}

#[tokio::test]
async fn supported_extension_with_request_gives_output() {
    let shared_store = Some(create_passkey(Some(RustCryptoRng::random_vec(32))));
    let user_mock = MockUserValidationMethod::verified_user(1);

    let mut authenticator = Authenticator::new(
        Aaguid::new_empty(),
        shared_store.clone(),
        user_mock,
        RustCryptoBackend,
    )
    .hmac_secret(extensions::HmacSecretConfig::new_with_uv_only());

    let request = Request {
        extensions: Some(ExtensionInputs {
            prf: Some(prf_eval_request(Some(RustCryptoRng::random_vec(32)))),
            ..Default::default()
        }),
        ..good_request()
    };

    let res = authenticator
        .get_assertion(request)
        .await
        .expect("error happened while trying to authenticate a credential");

    assert!(res.auth_data.extensions.is_none());
    assert!(res.unsigned_extension_outputs.is_some());
    assert!(res.unsigned_extension_outputs.unwrap().prf.is_some());
}
