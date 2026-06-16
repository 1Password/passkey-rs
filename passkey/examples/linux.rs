//! Sample App for Linux Client
use std::io::{Write, stdin, stdout};

use passkey::{
    client::{WebauthnError, linux::LinuxClient},
    types::{Bytes, rand::random_vec, webauthn::*},
};

use coset::iana;
use passkey_client::{
    DefaultClientData,
    linux::{PinPrompt, PinPromptError},
};
use url::Url;
use zeroize::Zeroizing;

struct MyPinPrompt;

#[async_trait::async_trait]
impl PinPrompt for MyPinPrompt {
    async fn prompt_authenticator_selection(
        &self,
        num_authenticators: usize,
    ) -> Result<(), PinPromptError> {
        println!(
            "Touch one of the {} attached authenticator devices to select it.",
            num_authenticators
        );
        Ok(())
    }
    async fn request_pin(
        &self,
        attempts_remaining: u32,
    ) -> Result<Zeroizing<String>, PinPromptError> {
        print!("Enter PIN ({} attempts remaining): ", attempts_remaining);
        stdout()
            .flush()
            .map_err(|e| PinPromptError::Other(Box::new(e)))?;
        let mut buf = String::new();
        stdin()
            .read_line(&mut buf)
            .map_err(|e| PinPromptError::Other(Box::new(e)))?;
        Ok(Zeroizing::new(buf.trim_ascii().into()))
    }
}

// Example of how to set up, register and authenticate with a `Client`.
async fn client_setup(
    challenge_bytes_from_rp: Bytes,
    parameters_from_rp: PublicKeyCredentialParameters,
    origin: &Url,
    user_entity: PublicKeyCredentialUserEntity,
) -> Result<(CreatedPublicKeyCredential, AuthenticatedPublicKeyCredential), WebauthnError> {
    // Create the Client
    let my_client = LinuxClient::open_all(Box::new(MyPinPrompt))
        .await
        .unwrap()
        .user_verification_when_preferred(false);

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
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                resident_key: Some(ResidentKeyRequirement::Required),
                ..Default::default()
            }),
            hints: None,
            attestation: AttestationConveyancePreference::None,
            attestation_formats: None,
            extensions: None,
        },
    };

    // Now create the credential.
    println!("Attempting credential creation");
    let my_webauthn_credential = my_client
        .register(origin, request, DefaultClientData)
        .await?;

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
            hints: None,
            attestation: AttestationConveyancePreference::None,
            attestation_formats: None,
            extensions: None,
        },
    };

    println!("Attempting authentication");
    let authenticated_cred = my_client
        .authenticate(origin, credential_request, DefaultClientData)
        .await?;

    Ok((my_webauthn_credential, authenticated_cred))
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

    println!("Webauthn credential created:\n\n{created_cred:?}\n\n");
    println!("Webauthn credential auth'ed:\n\n{authed_cred:?}\n\n");

    Ok(())
}
