use std::collections::HashMap;

use passkey_authenticator::extensions::HmacSecretConfig;
use passkey_types::{
    crypto::hmac_sha256,
    ctap2::{AuthenticatorData, Flags},
};

use super::*;

fn good_credential_creation_options_with_prf(
    eval: Option<webauthn::AuthenticationExtensionsPrfValues>,
) -> webauthn::CredentialCreationOptions {
    webauthn::CredentialCreationOptions {
        public_key: webauthn::PublicKeyCredentialCreationOptions {
            extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval,
                    eval_by_credential: None,
                }),
                ..Default::default()
            }),
            ..good_credential_creation_options()
        },
    }
}

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

#[tokio::test]
async fn registration_with_single_input_eval() {
    let auth = Authenticator::new(
        ctap2::Aaguid::new_empty(),
        MemoryStore::new(),
        uv_mock_with_creation(1),
    )
    .hmac_secret(HmacSecretConfig::new_without_uv().enable_on_make_credential());
    let mut client = Client::new(auth);

    let first = vec![
        101, 195, 212, 161, 191, 112, 75, 189, 152, 52, 121, 17, 62, 113, 114, 164,
    ];

    let origin = Url::parse("https://future.1password.com").unwrap();
    let options = webauthn::CredentialCreationOptions {
        public_key: webauthn::PublicKeyCredentialCreationOptions {
            extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval: Some(webauthn::AuthenticationExtensionsPrfValues {
                        first: Bytes::from(first),
                        second: None,
                    }),
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
    // CTAP2's new extension hmac-secret-mc allows us to evaluate PRF inputs
    // at creation time. This is implemented by our in-memory authenticator.
    assert!(prf_out.results.is_some());
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrfValuesConfig {
    None,
    One,
    Two,
}

impl PrfValuesConfig {
    fn build(&self) -> Option<webauthn::AuthenticationExtensionsPrfValues> {
        match self {
            PrfValuesConfig::None => None,
            PrfValuesConfig::One => Some(webauthn::AuthenticationExtensionsPrfValues {
                first: Bytes::from(random_vec(128)),
                second: None,
            }),
            PrfValuesConfig::Two => Some(webauthn::AuthenticationExtensionsPrfValues {
                first: Bytes::from(random_vec(128)),
                second: Some(Bytes::from(random_vec(128))),
            }),
        }
    }
}

#[cfg(test)]
macro_rules! valid_authentication_with_prf {
    ( $($test_name:ident: $eval:expr, $eval_by_cred:expr),+ ) => {
        $(
            #[tokio::test]
            async fn $test_name() {
                let auth = Authenticator::new(
                    ctap2::Aaguid::new_empty(),
                    MemoryStore::new(),
                    uv_mock_with_creation(2),
                )
                .hmac_secret(HmacSecretConfig::new_without_uv());
                let mut client = Client::new(auth);

                let origin = Url::parse("https://future.1password.com").unwrap();
                let eval = $eval.build();
                let eval_by_cred = $eval_by_cred.build();
                let options = good_credential_creation_options_with_prf(eval.clone().or_else(|| eval_by_cred.clone()));

                let cred = client
                    .register(&origin, options, None)
                    .await
                    .expect("failed to register with options");

                let auth_data = AuthenticatorData::from_slice(&cred.response.authenticator_data)
                    .expect("could not deserialize authenticator data");
                assert!(!auth_data.flags.contains(Flags::ED));

                let cred_id = cred.raw_id;

                let make_prf = cred
                    .client_extension_results
                    .prf;

                // prf should still be initialized if the dictionary key is present but has no value
                assert!(make_prf.is_some());
                assert_eq!(make_prf.unwrap().enabled, Some(true));

                let eval_by_credential = match eval_by_cred {
                    None => None,
                    Some(val) => Some(
                        [(String::from(cred_id.clone()), val)]
                            .into_iter()
                            .collect()
                    ),
                };

                let auth_options = webauthn::CredentialRequestOptions {
                    public_key: webauthn::PublicKeyCredentialRequestOptions {
                        extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                            prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                                eval,
                                eval_by_credential,
                            }),
                            ..Default::default()
                        }),
                        ..good_credential_request_options(cred_id)
                    }
                };

                let auth_res = client
                    .authenticate(&origin, auth_options, None)
                    .await
                    .expect("failed to authenticate with PRF input");

                let auth_data = AuthenticatorData::from_slice(&auth_res.response.authenticator_data)
                    .expect("could not deserialize authenticator data");
                assert!(!auth_data.flags.contains(Flags::ED));

                let prf_out = auth_res
                    .client_extension_results
                    .prf;

                // Base case: if no credentials were provided nor a fallback eval was given,
                // the PRF extension after authentication should be None.
                // NOTE: the [W3C spec](https://w3c.github.io/webauthn/#prf-extension) does not
                // explicitly say what must happen in this case, except that it should have
                // initialized the prf extension output to an empty directory at some point.
                // Instead of returning a Some(empty PRF outputs), our implementation sets
                // the prf field in client_extension_results to None directly.
                if $eval == PrfValuesConfig::None && $eval_by_cred == PrfValuesConfig::None {
                    assert!(prf_out.is_none());
                    return;
                }

                let prf_out = prf_out.expect("client extension results should contain PRF output");

                // Should only be present during registration
                assert!(prf_out.enabled.is_none());

                // Otherwise, there must at least be a single result.
                let prf_res = prf_out.results.expect("PRF output should contain results");

                // A PRF output must be non-empty
                assert!(!prf_res.first.is_empty());

                // If the input eval contains two values, we also expect the output from the
                // PRF extension to contain a second, non-empty result.
                match ($eval, $eval_by_cred) {
                    (PrfValuesConfig::Two, PrfValuesConfig::None) | (_, PrfValuesConfig::Two) => {
                        let second = prf_res.second.expect("PRF results should contain second result value");
                        assert!(!second.is_empty());
                    },
                    _ => {}
                }
            }
        )*
    };
}

valid_authentication_with_prf! {
    auth_empty_evals: PrfValuesConfig::None, PrfValuesConfig::None,
    auth_two_inputs_eval_by_credential: PrfValuesConfig::None, PrfValuesConfig::Two,
    auth_single_input_eval: PrfValuesConfig::One, PrfValuesConfig::None,
    auth_both_eval_and_eval_by_credential: PrfValuesConfig::One, PrfValuesConfig::Two
}

#[tokio::test]
async fn auth_empty_allow_credentials() {
    let auth = Authenticator::new(
        ctap2::Aaguid::new_empty(),
        MemoryStore::new(),
        uv_mock_user_check_skip(2),
    )
    .hmac_secret(HmacSecretConfig::new_without_uv());
    let mut client = Client::new(auth);

    let origin = Url::parse("https://future.1password.com").unwrap();
    let eval_by_cred = webauthn::AuthenticationExtensionsPrfValues {
        first: Bytes::from(random_vec(128)),
        second: None,
    };
    let options = good_credential_creation_options_with_prf(Some(eval_by_cred.clone()));

    let cred = client
        .register(&origin, options, None)
        .await
        .expect("failed to register with options");

    let cred_id = cred.raw_id;

    let auth_options = webauthn::CredentialRequestOptions {
        public_key: webauthn::PublicKeyCredentialRequestOptions {
            allow_credentials: None,
            extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval: None,
                    eval_by_credential: Some(
                        [(String::from(cred_id.clone()), eval_by_cred)]
                            .into_iter()
                            .collect(),
                    ),
                }),
                ..Default::default()
            }),
            ..good_credential_request_options(cred_id)
        },
    };

    let auth_res = client.authenticate(&origin, auth_options, None).await;

    // See https://w3c.github.io/webauthn/#prf-extension
    //   - Client extension processing (authentication)
    //     - (1)
    assert!(matches!(auth_res, Err(WebauthnError::NotSupportedError)));
}

#[cfg(test)]
macro_rules! invalid_eval_by_credential_in_authentication {
    ( $($test_name:ident: $key:expr ),+ ) => {
        $(
            #[tokio::test]
            async fn $test_name() {
                let auth = Authenticator::new(
                    ctap2::Aaguid::new_empty(),
                    MemoryStore::new(),
                    uv_mock_user_check_skip(2),
                )
                .hmac_secret(HmacSecretConfig::new_without_uv());
                let mut client = Client::new(auth);

                let eval_by_cred = webauthn::AuthenticationExtensionsPrfValues {
                    first: Bytes::from(random_vec(128)),
                    second: None,
                };

                let origin = Url::parse("https://future.1password.com").unwrap();
                let options = good_credential_creation_options_with_prf(Some(eval_by_cred.clone()));

                let cred = client
                    .register(&origin, options, None)
                    .await
                    .expect("failed to register with options");

                let cred_id = cred.raw_id;

                let auth_options = webauthn::CredentialRequestOptions {
                    public_key: webauthn::PublicKeyCredentialRequestOptions {
                        extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                            prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                                eval: None,
                                eval_by_credential: Some(
                                    [(
                                        $key,
                                        eval_by_cred
                                    )]
                                    .into_iter()
                                    .collect(),
                                ),
                            }),
                            ..Default::default()
                        }),
                        ..good_credential_request_options(cred_id)
                    },
                };

                let auth_res = client.authenticate(&origin, auth_options, None).await;

                // See https://w3c.github.io/webauthn/#prf-extension
                //   - Client extension processing (authentication)
                //     - (2)
                assert!(matches!(auth_res, Err(WebauthnError::SyntaxError)));
            }
        )*
    };
}

invalid_eval_by_credential_in_authentication! {
    auth_empty_key_in_eval_by_credential: String::from(""),
    auth_invalid_base64url_key_in_eval_by_credential: String::from("xyz"),
    auth_no_matching_credential_id_in_allow_credentials: String::from(Bytes::from(random_vec(64)))
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SameInputs {
    Yes,
    No,
}

#[cfg(test)]
macro_rules! compare_auth_calls {
    ( $($test_name:ident: $same_inputs:expr),+ ) => {
        $(
            #[tokio::test]
            async fn $test_name() {
                let auth = Authenticator::new(
                    ctap2::Aaguid::new_empty(),
                    MemoryStore::new(),
                    uv_mock_with_creation(3),
                )
                .hmac_secret(HmacSecretConfig::new_without_uv());
                let mut client = Client::new(auth);

                let mut first = Bytes::from(random_vec(128));
                let mut second = Some(Bytes::from(random_vec(128)));

                let eval_by_cred = webauthn::AuthenticationExtensionsPrfValues {
                    first: first.clone(),
                    second: second.clone(),
                };

                let origin = Url::parse("https://future.1password.com").unwrap();
                let options = good_credential_creation_options_with_prf(Some(eval_by_cred.clone()));

                let cred = client
                    .register(&origin, options, None)
                    .await
                    .expect("failed to register with options");

                let cred_id = cred.raw_id;


                let auth_options = webauthn::CredentialRequestOptions {
                    public_key: webauthn::PublicKeyCredentialRequestOptions {
                        extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                            prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                                eval: None,
                                eval_by_credential: Some(
                                    [(
                                        String::from(cred_id.clone()),
                                        eval_by_cred
                                    )]
                                    .into_iter()
                                    .collect(),
                                ),
                            }),
                            ..Default::default()
                        }),
                        ..good_credential_request_options(cred_id.clone())
                    },
                };

                let auth_res_a = client
                    .authenticate(&origin, auth_options, None)
                    .await
                    .expect("failed to authenticate with PRF input");

                if $same_inputs == SameInputs::No {
                    first = Bytes::from(random_vec(128));
                    second = Some(Bytes::from(random_vec(128)));
                }

                let auth_options = webauthn::CredentialRequestOptions {
                    public_key: webauthn::PublicKeyCredentialRequestOptions {
                        extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                            prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                                eval: None,
                                eval_by_credential: Some(
                                    [(
                                        String::from(cred_id.clone()),
                                        webauthn::AuthenticationExtensionsPrfValues { first, second },
                                    )]
                                    .into_iter()
                                    .collect(),
                                ),
                            }),
                            ..Default::default()
                        }),
                        ..good_credential_request_options(cred_id)
                    },
                };

                let auth_res_b = client
                    .authenticate(&origin, auth_options, None)
                    .await
                    .expect("failed to authenticate with PRF input");

                let prf_results_a = auth_res_a
                    .client_extension_results
                    .prf
                    .expect("client extension results should contain PRF output")
                    .results
                    .expect("PRF output should contain results");
                let prf_results_b = auth_res_b
                    .client_extension_results
                    .prf
                    .expect("client extension results should contain PRF output")
                    .results
                    .expect("PRF output should contain results");

                match $same_inputs {
                    SameInputs::Yes => {
                        assert_eq!(prf_results_a.first, prf_results_b.first);
                        assert_eq!(prf_results_a.second, prf_results_b.second);
                    },
                    SameInputs::No => {
                        assert_ne!(prf_results_a.first, prf_results_b.first);
                        assert_ne!(prf_results_a.second, prf_results_b.second);
                    }
                }
            }
        )+
    }
}

compare_auth_calls! {
    auth_same_inputs_should_give_same_outputs: SameInputs::Yes,
    auth_different_inputs_should_give_different_outputs: SameInputs::No
}

#[tokio::test]
async fn registration_and_authentication_with_unsupported_authenticator_ignores_prf() {
    let auth = Authenticator::new(
        ctap2::Aaguid::new_empty(),
        MemoryStore::new(),
        uv_mock_with_creation(2),
    );
    let mut client = Client::new(auth);

    let origin = Url::parse("https://future.1password.com").unwrap();
    let eval = PrfValuesConfig::Two.build();
    let options = good_credential_creation_options_with_prf(eval.clone());

    let cred = client
        .register(&origin, options, None)
        .await
        .expect("failed to register with options");
    assert!(cred.client_extension_results.prf.is_none());
    let auth_data = AuthenticatorData::from_slice(&cred.response.authenticator_data)
        .expect("could not decode Authenticator Data");
    assert!(auth_data.extensions.is_none());
    assert!(!auth_data.flags.contains(Flags::ED));

    let auth_options = webauthn::CredentialRequestOptions {
        public_key: webauthn::PublicKeyCredentialRequestOptions {
            extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval,
                    eval_by_credential: None,
                }),
                ..Default::default()
            }),
            ..good_credential_request_options(cred.raw_id)
        },
    };

    let auth_res = client
        .authenticate(&origin, auth_options, None)
        .await
        .expect("failed to authenticate with PRF input");

    assert!(auth_res.client_extension_results.prf.is_none());
    let auth_data = AuthenticatorData::from_slice(&auth_res.response.authenticator_data)
        .expect("could not decode Authenticator Data");
    assert!(auth_data.extensions.is_none());
    assert!(!auth_data.flags.contains(Flags::ED));
}

#[tokio::test]
async fn empty_extension_and_no_hmac_secret_support() {
    let auth = Authenticator::new(
        ctap2::Aaguid::new_empty(),
        MemoryStore::new(),
        uv_mock_with_creation(2),
    );
    let mut client = Client::new(auth);

    let origin = Url::parse("https://future.1password.com").unwrap();
    let options = webauthn::CredentialCreationOptions {
        public_key: webauthn::PublicKeyCredentialCreationOptions {
            extensions: Some(Default::default()),
            ..good_credential_creation_options()
        },
    };

    let cred = client
        .register(&origin, options, None)
        .await
        .expect("failed to register with options");
    assert!(cred.client_extension_results.prf.is_none());
    let auth_data = AuthenticatorData::from_slice(&cred.response.authenticator_data)
        .expect("could not decode Authenticator Data");
    assert!(auth_data.extensions.is_none());
    assert!(!auth_data.flags.contains(Flags::ED));

    let auth_options = webauthn::CredentialRequestOptions {
        public_key: webauthn::PublicKeyCredentialRequestOptions {
            extensions: Some(Default::default()),
            ..good_credential_request_options(cred.raw_id)
        },
    };

    let auth_res = client
        .authenticate(&origin, auth_options, None)
        .await
        .expect("failed to authenticate");

    assert!(auth_res.client_extension_results.prf.is_none());
    let auth_data = AuthenticatorData::from_slice(&auth_res.response.authenticator_data)
        .expect("could not decode Authenticator Data");
    assert!(auth_data.extensions.is_none());
    assert!(!auth_data.flags.contains(Flags::ED));
}

#[tokio::test]
async fn empty_extension_with_hmac_secret_support() {
    let auth = Authenticator::new(
        ctap2::Aaguid::new_empty(),
        MemoryStore::new(),
        uv_mock_with_creation(2),
    )
    .hmac_secret(HmacSecretConfig::new_without_uv());
    let mut client = Client::new(auth);

    let origin = Url::parse("https://future.1password.com").unwrap();
    let options = webauthn::CredentialCreationOptions {
        public_key: webauthn::PublicKeyCredentialCreationOptions {
            extensions: Some(Default::default()),
            ..good_credential_creation_options()
        },
    };

    let cred = client
        .register(&origin, options, None)
        .await
        .expect("failed to register with options");
    assert!(cred.client_extension_results.prf.is_none());
    let auth_data = AuthenticatorData::from_slice(&cred.response.authenticator_data)
        .expect("could not decode Authenticator Data");
    assert!(auth_data.extensions.is_none());
    assert!(!auth_data.flags.contains(Flags::ED));

    let auth_options = webauthn::CredentialRequestOptions {
        public_key: webauthn::PublicKeyCredentialRequestOptions {
            extensions: Some(Default::default()),
            ..good_credential_request_options(cred.raw_id)
        },
    };
    let auth_res = client
        .authenticate(&origin, auth_options, None)
        .await
        .expect("failed to authenticate");

    assert!(auth_res.client_extension_results.prf.is_none());
    let auth_data = AuthenticatorData::from_slice(&auth_res.response.authenticator_data)
        .expect("could not decode Authenticator Data");
    assert!(auth_data.extensions.is_none());
    assert!(!auth_data.flags.contains(Flags::ED));
}

// When evalByCredential contains credential ID not registered with the authenticator,
// it should never use those values as input to the salts sent to the authenicator's
// hmac-secret extension.
#[tokio::test]
async fn two_eval_by_credential_entries() {
    let auth = Authenticator::new(
        ctap2::Aaguid::new_empty(),
        MemoryStore::new(),
        uv_mock_with_creation(3),
    )
    .hmac_secret(HmacSecretConfig::new_without_uv());
    let mut client = Client::new(auth);

    let eval_values = webauthn::AuthenticationExtensionsPrfValues {
        first: Bytes::from(random_vec(128)),
        second: Some(Bytes::from(random_vec(128))),
    };

    let origin = Url::parse("https://future.1password.com").unwrap();
    let options = good_credential_creation_options_with_prf(Some(eval_values.clone()));

    let cred = client
        .register(&origin, options, None)
        .await
        .expect("failed to register with options");

    let cred_id = cred.raw_id;

    let auth_options = webauthn::CredentialRequestOptions {
        public_key: webauthn::PublicKeyCredentialRequestOptions {
            extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval: None,
                    eval_by_credential: Some(
                        [(String::from(cred_id.clone()), eval_values.clone())]
                            .into_iter()
                            .collect(),
                    ),
                }),
                ..Default::default()
            }),
            ..good_credential_request_options(cred_id.clone())
        },
    };

    let auth_res_control = client
        .authenticate(&origin, auth_options, None)
        .await
        .expect("failed to authenticate with PRF input");

    let eval_values_2 = webauthn::AuthenticationExtensionsPrfValues {
        first: Bytes::from(random_vec(128)),
        second: Some(Bytes::from(random_vec(128))),
    };

    let mut cred_id_2 = cred_id.clone();
    cred_id_2.reverse();

    // Include an entry referencing a credential ID that does not exist
    // on the authenticator. The implementation should always pick the
    // eval input from the credential ID it has registered.
    let auth_options = webauthn::CredentialRequestOptions {
        public_key: webauthn::PublicKeyCredentialRequestOptions {
            allow_credentials: Some(vec![
                webauthn::PublicKeyCredentialDescriptor {
                    ty: webauthn::PublicKeyCredentialType::PublicKey,
                    id: cred_id_2.clone(),
                    transports: None,
                },
                webauthn::PublicKeyCredentialDescriptor {
                    ty: webauthn::PublicKeyCredentialType::PublicKey,
                    id: cred_id.clone(),
                    transports: None,
                },
            ]),
            extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval: None,
                    eval_by_credential: Some(
                        [
                            (String::from(cred_id_2.clone()), eval_values_2),
                            (String::from(cred_id.clone()), eval_values),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                }),
                ..Default::default()
            }),
            ..good_credential_request_options(cred_id.clone())
        },
    };

    let auth_res_treatment = client
        .authenticate(&origin, auth_options, None)
        .await
        .expect("failed to authenticate with PRF input");

    let treatment_prf_res = auth_res_treatment
        .client_extension_results
        .prf
        .expect("should have PRF extension results")
        .results
        .expect("should have PRF extension outputs");

    let control_prf_res = auth_res_control
        .client_extension_results
        .prf
        .expect("should have PRF extension results")
        .results
        .expect("should have PRF extension outputs");

    assert_eq!(treatment_prf_res.first, control_prf_res.first);
    assert_eq!(treatment_prf_res.second, control_prf_res.second);
}

#[tokio::test]
async fn prf_already_hashed_does_not_hash_again() {
    let salt = [2; 32];

    let hashed_salt = sha256(&[b"WebAuthn PRF".as_slice(), &[0x00], salt.as_slice()].concat());

    let origin = Url::parse("https://future.1password.com").unwrap();

    let auth = Authenticator::new(ctap2::Aaguid::new_empty(), None, uv_mock_with_creation(2))
        .hmac_secret(HmacSecretConfig::new_without_uv().enable_on_make_credential());
    let mut client = Client::new(auth);
    let create_request = webauthn::CredentialCreationOptions {
        public_key: webauthn::PublicKeyCredentialCreationOptions {
            extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                prf_already_hashed: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval: Some(webauthn::AuthenticationExtensionsPrfValues {
                        first: hashed_salt.as_slice().into(),
                        second: None,
                    }),
                    eval_by_credential: None,
                }),
                ..Default::default()
            }),
            ..good_credential_creation_options()
        },
    };
    let created = client
        .register(&origin, create_request, None)
        .await
        .expect("could not register a new passkey with PRF already hashed");

    let passkey = client
        .authenticator
        .store()
        .clone()
        .expect("no passkey was stored after its creation");

    let hmac_secret = passkey
        .extensions
        .hmac_secret
        .as_ref()
        .expect("no HMAC secret was created with PRF already hashed")
        .cred_with_uv
        .clone();

    let expected_output = hmac_sha256(&hmac_secret, &hashed_salt);

    let prf_results = created
        .client_extension_results
        .prf
        .expect("no PRF was returned")
        .results
        .expect("no results were returned with make credential support");
    assert_eq!(prf_results.first.as_slice(), expected_output.as_slice());

    let request = webauthn::CredentialRequestOptions {
        public_key: webauthn::PublicKeyCredentialRequestOptions {
            allow_credentials: None,
            extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                prf_already_hashed: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval: Some(webauthn::AuthenticationExtensionsPrfValues {
                        first: hashed_salt.as_slice().into(),
                        second: None,
                    }),
                    eval_by_credential: None,
                }),
                ..Default::default()
            }),
            ..good_credential_request_options(vec![])
        },
    };

    let response = client
        .authenticate(&origin, request, None)
        .await
        .expect("could not authenticate with PRF already hashed");

    let prf = response
        .client_extension_results
        .prf
        .expect("no PRF output was provided");

    let prf_results = prf
        .results
        .expect("no PRF results were included in the output");

    assert_eq!(prf_results.first.as_slice(), expected_output.as_slice());
}

#[tokio::test]
async fn prf_takes_precedence_over_prf_already_hashed() {
    let salt = [2; 32];

    let hashed_salt = sha256(&[b"WebAuthn PRF".as_slice(), &[0x00], salt.as_slice()].concat());

    let origin = Url::parse("https://future.1password.com").unwrap();

    let auth = Authenticator::new(ctap2::Aaguid::new_empty(), None, uv_mock_with_creation(2))
        .hmac_secret(HmacSecretConfig::new_without_uv().enable_on_make_credential());
    let mut client = Client::new(auth);
    let create_request = webauthn::CredentialCreationOptions {
        public_key: webauthn::PublicKeyCredentialCreationOptions {
            extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                prf_already_hashed: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval: Some(webauthn::AuthenticationExtensionsPrfValues {
                        first: hashed_salt.as_slice().into(),
                        second: None,
                    }),
                    eval_by_credential: None,
                }),
                ..Default::default()
            }),
            ..good_credential_creation_options()
        },
    };
    let created = client
        .register(&origin, create_request, None)
        .await
        .expect("could not register a new passkey with PRF already hashed");

    let passkey = client
        .authenticator
        .store()
        .clone()
        .expect("no passkey was stored after its creation");

    let hmac_secret = passkey
        .extensions
        .hmac_secret
        .as_ref()
        .expect("no HMAC secret was created with PRF already hashed")
        .cred_with_uv
        .clone();

    let expected_output = hmac_sha256(&hmac_secret, &hashed_salt);

    let prf_results = created
        .client_extension_results
        .prf
        .expect("no PRF was returned")
        .results
        .expect("no results were returned with make credential support");
    assert_eq!(prf_results.first.as_slice(), expected_output.as_slice());

    let request = webauthn::CredentialRequestOptions {
        public_key: webauthn::PublicKeyCredentialRequestOptions {
            allow_credentials: None,
            extensions: Some(webauthn::AuthenticationExtensionsClientInputs {
                prf: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval: Some(webauthn::AuthenticationExtensionsPrfValues {
                        first: salt.as_slice().into(),
                        second: None,
                    }),
                    eval_by_credential: None,
                }),
                prf_already_hashed: Some(webauthn::AuthenticationExtensionsPrfInputs {
                    eval: Some(webauthn::AuthenticationExtensionsPrfValues {
                        // Input nonsense here so if it is selected it fails
                        first: [3; 32].as_slice().into(),
                        second: None,
                    }),
                    eval_by_credential: None,
                }),
                ..Default::default()
            }),
            ..good_credential_request_options(vec![])
        },
    };

    let response = client
        .authenticate(&origin, request, None)
        .await
        .expect("could not authenticate with PRF already hashed");

    let prf = response
        .client_extension_results
        .prf
        .expect("no PRF output was provided");

    let prf_results = prf
        .results
        .expect("no PRF results were included in the output");

    assert_eq!(prf_results.first.as_slice(), expected_output.as_slice());
}
