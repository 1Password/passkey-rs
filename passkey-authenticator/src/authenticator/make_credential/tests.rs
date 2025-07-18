use std::sync::Arc;

use coset::iana;
use passkey_types::{
    Bytes,
    ctap2::{
        Aaguid,
        extensions::{AuthenticatorPrfInputs, AuthenticatorPrfValues},
        make_credential::{
            ExtensionInputs, Options, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
        },
    },
    rand::random_vec,
    webauthn,
};

use tokio::sync::Mutex;

use super::*;
use crate::{
    MemoryStore,
    credential_store::{DiscoverabilitySupport, StoreInfo},
    extensions,
    user_validation::MockUserValidationMethod,
};

fn good_request() -> Request {
    Request {
        client_data_hash: random_vec(32).into(),
        rp: PublicKeyCredentialRpEntity {
            id: "future.1password.com".into(),
            name: Some("1password".into()),
        },
        user: webauthn::PublicKeyCredentialUserEntity {
            id: random_vec(16).into(),
            display_name: "wendy".into(),
            name: "Appleseed".into(),
        },
        pub_key_cred_params: vec![webauthn::PublicKeyCredentialParameters {
            ty: webauthn::PublicKeyCredentialType::PublicKey,
            alg: iana::Algorithm::ES256,
        }],
        exclude_list: None,
        extensions: None,
        options: Options {
            rk: true,
            up: true,
            uv: true,
        },
        pin_auth: None,
        pin_protocol: None,
    }
}

#[tokio::test]
async fn assert_storage_on_success() {
    let shared_store = Arc::new(Mutex::new(MemoryStore::new()));
    let user_mock = MockUserValidationMethod::verified_user(1);

    let mut authenticator =
        Authenticator::new(Aaguid::new_empty(), shared_store.clone(), user_mock);

    let request = good_request();

    authenticator
        .make_credential(request)
        .await
        .expect("error happened while trying to make a new credential");

    let store = shared_store.lock().await;

    assert_eq!(store.len(), 1);
}

#[tokio::test]
async fn assert_excluded_credentials() {
    let cred_id: Bytes = random_vec(16).into();
    let response = Request {
        exclude_list: Some(vec![webauthn::PublicKeyCredentialDescriptor {
            ty: webauthn::PublicKeyCredentialType::PublicKey,
            id: cred_id.clone(),
            transports: Some(vec![webauthn::AuthenticatorTransport::Usb]),
        }]),
        ..good_request()
    };
    let passkey = Passkey {
        // contents of key doesn't matter, only the id
        key: Default::default(),
        rp_id: "".into(),
        credential_id: cred_id.clone(),
        user_handle: Some(response.user.id.clone()),
        counter: None,
        extensions: Default::default(),
    };
    let shared_store = Arc::new(Mutex::new(MemoryStore::new()));
    let user_mock = MockUserValidationMethod::verified_user(1);

    shared_store.lock().await.insert(cred_id.into(), passkey);

    let mut authenticator =
        Authenticator::new(Aaguid::new_empty(), shared_store.clone(), user_mock);

    let err = authenticator
        .make_credential(response)
        .await
        .expect_err("make credential succeeded even though store contains excluded id");

    assert_eq!(err, Ctap2Error::CredentialExcluded.into());
    assert_eq!(shared_store.lock().await.len(), 1);
}

#[tokio::test]
async fn assert_unsupported_algorithm() {
    let user_mock = MockUserValidationMethod::verified_user(1);
    let mut authenticator = Authenticator::new(Aaguid::new_empty(), MemoryStore::new(), user_mock);

    let request = Request {
        pub_key_cred_params: vec![webauthn::PublicKeyCredentialParameters {
            ty: webauthn::PublicKeyCredentialType::PublicKey,
            alg: iana::Algorithm::RSAES_OAEP_SHA_256,
        }],
        ..good_request()
    };

    let err = authenticator
        .make_credential(request)
        .await
        .expect_err("Succeeded with an unsupported algorithm");

    assert_eq!(err, Ctap2Error::UnsupportedAlgorithm.into());
}

#[tokio::test]
async fn make_credential_counter_is_some_0_when_counters_are_enabled() {
    // Arrange
    let shared_store = Arc::new(Mutex::new(None));
    let user_mock = MockUserValidationMethod::verified_user(1);
    let request = good_request();
    let mut authenticator =
        Authenticator::new(Aaguid::new_empty(), shared_store.clone(), user_mock);
    authenticator.set_make_credentials_with_signature_counter(true);

    // Act
    authenticator.make_credential(request).await.unwrap();

    // Assert
    let store = shared_store.lock().await;
    assert_eq!(store.as_ref().and_then(|c| c.counter).unwrap(), 0);
}

#[tokio::test]
async fn unsupported_extension_with_request_gives_no_ext_output() {
    let shared_store = Arc::new(Mutex::new(MemoryStore::new()));
    let user_mock = MockUserValidationMethod::verified_user(1);

    let mut authenticator =
        Authenticator::new(Aaguid::new_empty(), shared_store.clone(), user_mock);

    let request = Request {
        extensions: Some(ExtensionInputs {
            prf: Some(AuthenticatorPrfInputs {
                eval: None,
                eval_by_credential: None,
            }),
            ..Default::default()
        }),
        ..good_request()
    };

    let res = authenticator
        .make_credential(request)
        .await
        .expect("error happened while trying to make a new credential");

    assert!(res.auth_data.extensions.is_none());
    assert!(res.unsigned_extension_outputs.is_none());
}

#[tokio::test]
async fn unsupported_extension_with_empty_request_gives_no_ext_output() {
    let shared_store = Arc::new(Mutex::new(MemoryStore::new()));
    let user_mock = MockUserValidationMethod::verified_user(1);
    let mut authenticator =
        Authenticator::new(Aaguid::new_empty(), shared_store.clone(), user_mock);

    let request = Request {
        extensions: Some(ExtensionInputs::default()),
        ..good_request()
    };

    let res = authenticator
        .make_credential(request)
        .await
        .expect("error happened while trying to make a new credential");

    assert!(res.auth_data.extensions.is_none());
    assert!(res.unsigned_extension_outputs.is_none());
}

#[tokio::test]
async fn supported_extension_with_empty_request_gives_no_ext_output() {
    let shared_store = Arc::new(Mutex::new(MemoryStore::new()));
    let user_mock = MockUserValidationMethod::verified_user(1);

    let mut authenticator =
        Authenticator::new(Aaguid::new_empty(), shared_store.clone(), user_mock)
            .hmac_secret(extensions::HmacSecretConfig::new_with_uv_only());

    let request = Request {
        extensions: Some(ExtensionInputs::default()),
        ..good_request()
    };

    let res = authenticator
        .make_credential(request)
        .await
        .expect("error happened while trying to make a new credential");

    assert!(res.auth_data.extensions.is_none());
    assert!(res.unsigned_extension_outputs.is_none());
}

#[tokio::test]
async fn supported_extension_without_extension_request_gives_no_ext_output() {
    let shared_store = Arc::new(Mutex::new(MemoryStore::new()));
    let user_mock = MockUserValidationMethod::verified_user(1);

    let mut authenticator =
        Authenticator::new(Aaguid::new_empty(), shared_store.clone(), user_mock)
            .hmac_secret(extensions::HmacSecretConfig::new_with_uv_only());

    let request = good_request();

    let res = authenticator
        .make_credential(request)
        .await
        .expect("error happened while trying to make a new credential");

    assert!(res.auth_data.extensions.is_none());
    assert!(res.unsigned_extension_outputs.is_none());
}

#[tokio::test]
async fn supported_extension_with_request_gives_output() {
    let shared_store = Arc::new(Mutex::new(MemoryStore::new()));
    let user_mock = MockUserValidationMethod::verified_user(1);

    let mut authenticator =
        Authenticator::new(Aaguid::new_empty(), shared_store.clone(), user_mock)
            .hmac_secret(extensions::HmacSecretConfig::new_with_uv_only());

    let request = Request {
        extensions: Some(ExtensionInputs {
            prf: Some(AuthenticatorPrfInputs {
                eval: None,
                eval_by_credential: None,
            }),
            ..Default::default()
        }),
        ..good_request()
    };

    let res = authenticator
        .make_credential(request)
        .await
        .expect("error happened while trying to make a new credential");

    assert!(res.auth_data.extensions.is_none());
    assert!(res.unsigned_extension_outputs.is_some());
    let exts = res.unsigned_extension_outputs.unwrap();
    assert!(exts.prf.is_some());
    let prf = exts.prf.unwrap();
    assert!(prf.enabled);
    assert!(prf.results.is_none())
}

#[tokio::test]
async fn hmac_secret_mc_happy_path() {
    let shared_store = Arc::new(Mutex::new(MemoryStore::new()));
    let user_mock = MockUserValidationMethod::verified_user(1);

    let mut authenticator =
        Authenticator::new(Aaguid::new_empty(), shared_store.clone(), user_mock).hmac_secret(
            extensions::HmacSecretConfig::new_with_uv_only().enable_on_make_credential(),
        );

    let request = Request {
        extensions: Some(ExtensionInputs {
            prf: Some(AuthenticatorPrfInputs {
                eval: Some(AuthenticatorPrfValues {
                    first: random_vec(32).try_into().unwrap(),
                    second: Some(random_vec(32).try_into().unwrap()),
                }),
                eval_by_credential: None,
            }),
            ..Default::default()
        }),
        ..good_request()
    };

    let res = authenticator
        .make_credential(request)
        .await
        .expect("error happened while trying to make a new credential");

    assert!(res.auth_data.extensions.is_none());

    assert!(res.unsigned_extension_outputs.is_some());
    let exts = res.unsigned_extension_outputs.unwrap();

    assert!(exts.prf.is_some());
    let prf = exts.prf.unwrap();

    assert!(prf.enabled);
    assert!(prf.results.is_some());
    let values = prf.results.unwrap();

    assert!(!values.first.is_empty());
    // We expect this to be None because the authenticator requires UV.
    // When calculating hmac secrets, it will skip the second input if
    // the authenticator does not support "no UV".
    assert!(values.second.is_none());
}

#[tokio::test]
async fn hmac_secret_mc_without_hmac_secret_support() {
    let shared_store = Arc::new(Mutex::new(MemoryStore::new()));
    let user_mock = MockUserValidationMethod::verified_user(1);

    let mut authenticator =
        Authenticator::new(Aaguid::new_empty(), shared_store.clone(), user_mock)
            //support on make credential is not set.
            .hmac_secret(extensions::HmacSecretConfig::new_with_uv_only());

    let request = Request {
        extensions: Some(ExtensionInputs {
            prf: Some(AuthenticatorPrfInputs {
                eval: Some(AuthenticatorPrfValues {
                    first: random_vec(32).try_into().unwrap(),
                    second: None,
                }),
                eval_by_credential: None,
            }),
            ..Default::default()
        }),
        ..good_request()
    };

    let res = authenticator
        .make_credential(request)
        .await
        .expect("error happened while trying to make a new credential");

    assert!(res.auth_data.extensions.is_none());
    assert!(res.unsigned_extension_outputs.is_some());
    let exts = res.unsigned_extension_outputs.unwrap();
    assert!(exts.prf.is_some());
    let prf = exts.prf.unwrap();
    assert!(prf.enabled);
    assert!(prf.results.is_none())
}

#[tokio::test]
async fn make_credential_returns_err_when_rk_is_requested_but_not_supported() {
    struct StoreWithoutDiscoverableSupport;
    #[async_trait::async_trait]
    impl CredentialStore for StoreWithoutDiscoverableSupport {
        type PasskeyItem = Passkey;

        async fn find_credentials(
            &self,
            _id: Option<&[webauthn::PublicKeyCredentialDescriptor]>,
            _rp_id: &str,
        ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
            #![allow(clippy::unimplemented)]
            unimplemented!("The test should not call find_credentials")
        }

        async fn save_credential(
            &mut self,
            _cred: Passkey,
            _user: PublicKeyCredentialUserEntity,
            _rp: PublicKeyCredentialRpEntity,
            _options: Options,
        ) -> Result<(), StatusCode> {
            #![allow(clippy::unimplemented)]
            unimplemented!("The test should not call save_credential")
        }

        async fn update_credential(&mut self, _cred: Passkey) -> Result<(), StatusCode> {
            #![allow(clippy::unimplemented)]
            unimplemented!("The test should not call update_credential")
        }

        async fn get_info(&self) -> StoreInfo {
            StoreInfo {
                discoverability: DiscoverabilitySupport::OnlyNonDiscoverable,
            }
        }
    }

    // Arrange
    let store = StoreWithoutDiscoverableSupport;
    let user_mock = MockUserValidationMethod::verified_user(1);
    let request = good_request();
    let mut authenticator = Authenticator::new(Aaguid::new_empty(), store, user_mock);
    authenticator.set_make_credentials_with_signature_counter(true);

    // Act
    let err = authenticator
        .make_credential(request)
        .await
        .expect_err("Succeeded with unsupported rk");

    // Assert
    assert_eq!(err, Ctap2Error::UnsupportedOption.into());
}
