//! Sample App for Passkeys
use passkey::{
    authenticator::{Authenticator, UserValidationMethod},
    client::{Client, WebauthnError},
    types::{crypto::sha256, ctap2::*, rand::random_vec, webauthn::*, Bytes, Passkey},
};

use coset::iana;
use url::Url;

// MyUserValidationMethod is a stub impl of the UserValidationMethod trait, used later.
struct MyUserValidationMethod {}
#[async_trait::async_trait]
impl UserValidationMethod for MyUserValidationMethod {
    async fn check_user_presence(&self) -> bool {
        true
    }

    async fn check_user_verification(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }
}

// Example of how to set up, register and authenticate with a `Client`.
async fn client_setup(
    challenge_bytes_from_rp: Bytes,
    parameters_from_rp: PublicKeyCredentialParameters,
    origin: &Url,
    user_entity: PublicKeyCredentialUserEntity,
) -> Result<(CreatedPublicKeyCredential, AuthenticatedPublicKeyCredential), WebauthnError> {
    // First create an Authenticator for the Client to use.
    let my_aaguid = Aaguid::new_empty();
    let user_validation_method = MyUserValidationMethod {};
    // Create the CredentialStore for the Authenticator.
    // Option<Passkey> is the simplest possible implementation of CredentialStore
    let store: Option<Passkey> = None;
    let my_authenticator = Authenticator::new(my_aaguid, store, user_validation_method);

    // Create the Client
    // If you are creating credentials, you need to declare the Client as mut
    let mut my_client = Client::new(my_authenticator);

    // The following values, provided as parameters to this function would usually be
    // retrieved from a Relying Party according to the context of the application.
    let request = CredentialCreationOptions {
        public_key: PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                id: None, // Leaving the ID as None means use the effective domain
                name: origin.domain().unwrap().into(),
            },
            user: user_entity,
            challenge: challenge_bytes_from_rp,
            pub_key_cred_params: vec![parameters_from_rp],
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: None,
            attestation: AttestationConveyancePreference::None,
            extensions: None,
        },
    };

    // Now create the credential.
    let my_webauthn_credential = my_client.register(origin, request, None).await?;

    // Let's try and authenticate.
    // Create a challenge that would usually come from the RP.
    let challenge_bytes_from_rp: Bytes = random_vec(32).into();
    // Now try and authenticate
    let credential_request = CredentialRequestOptions {
        public_key: PublicKeyCredentialRequestOptions {
            challenge: challenge_bytes_from_rp,
            timeout: None,
            rp_id: Some(String::from(origin.domain().unwrap())),
            allow_credentials: None,
            user_verification: UserVerificationRequirement::default(),
            extensions: None,
        },
    };

    let authenticated_cred = my_client
        .authenticate(origin, credential_request, None)
        .await?;

    Ok((my_webauthn_credential, authenticated_cred))
}

async fn authenticator_setup(
    user_entity: PublicKeyCredentialUserEntity,
    client_data_hash: Bytes,
    algorithms_from_rp: PublicKeyCredentialParameters,
    rp_id: String,
) -> Result<get_assertion::Response, StatusCode> {
    let store: Option<Passkey> = None;
    let user_validation_method = MyUserValidationMethod {};
    let my_aaguid = Aaguid::new_empty();

    let mut my_authenticator = Authenticator::new(my_aaguid, store, user_validation_method);

    let reg_request = make_credential::Request {
        client_data_hash: client_data_hash.clone(),
        rp: make_credential::PublicKeyCredentialRpEntity {
            id: rp_id.clone(),
            name: None,
        },
        user: user_entity,
        pub_key_cred_params: vec![algorithms_from_rp],
        exclude_list: None,
        extensions: None,
        options: make_credential::Options::default(),
        pin_auth: None,
        pin_protocol: None,
    };

    let credential: make_credential::Response =
        my_authenticator.make_credential(reg_request).await?;

    ctap2_creation_success(credential);

    let auth_request = get_assertion::Request {
        rp_id,
        client_data_hash,
        allow_list: None,
        extensions: None,
        options: make_credential::Options::default(),
        pin_auth: None,
        pin_protocol: None,
    };

    let response = my_authenticator.get_assertion(auth_request).await?;

    Ok(response)
}

fn ctap2_creation_success(credential: make_credential::Response) {
    println!(
        "CTAP2 credential creation succeeded:\n\n{:?}\n\n",
        credential
    );
}

fn ctap2_auth_success(credential: get_assertion::Response) {
    println!(
        "CTAP2 credential authentication succeeded:\n\n{:?}\n\n",
        credential
    );
}

fn ctap2_credential_not_found() {
    println!("CTAP2 error: Credential not found.");
}

fn ctap2_other_error(code: StatusCode) {
    println!("CTAP2 error: Other Status Code: {:?}", code);
}

#[tokio::main]
async fn main() -> Result<(), WebauthnError> {
    let rp_url = Url::parse("https://future.1password.com").expect("Should Parse");
    let user_entity = PublicKeyCredentialUserEntity {
        id: random_vec(32).into(),
        display_name: "Johnny Passkey".into(),
        name: "jpasskey@example.org".into(),
    };

    // Set up a client, create and authenticate a credential, then report results.
    let (created_cred, authed_cred) = client_setup(
        random_vec(32).into(), // challenge_bytes_from_rp
        PublicKeyCredentialParameters {
            ty: PublicKeyCredentialType::PublicKey,
            alg: iana::Algorithm::ES256,
        },
        &rp_url, // origin
        user_entity.clone(),
    )
    .await?;

    println!("Webauthn credential created:\n\n{:?}\n\n", created_cred);
    println!("Webauthn credential auth'ed:\n\n{:?}\n\n", authed_cred);

    // Generate the client_data_hash from the created_cred response
    let client_data_hash = sha256(&created_cred.response.client_data_json).to_vec();

    // Authenticator Version
    let authenticator_result = authenticator_setup(
        user_entity,
        client_data_hash.into(),
        PublicKeyCredentialParameters {
            ty: PublicKeyCredentialType::PublicKey,
            alg: iana::Algorithm::ES256,
        },
        rp_url
            .domain()
            .expect("Our example should unwrap.")
            .to_string(), // tld_from_rp
    )
    .await;

    match authenticator_result {
        Ok(authresponse) => {
            ctap2_auth_success(authresponse);
        }
        Err(StatusCode::Ctap2(Ctap2Code::Known(Ctap2Error::NoCredentials))) => {
            ctap2_credential_not_found()
        }
        Err(status_code) => ctap2_other_error(status_code),
    };

    Ok(())
}
