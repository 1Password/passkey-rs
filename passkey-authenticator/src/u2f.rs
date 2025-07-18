//! Follows U2F 1.2 <https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html>

use crate::{Authenticator, CoseKeyPair, CredentialStore, UserValidationMethod};
use coset::iana;
use p256::{
    SecretKey,
    ecdsa::{SigningKey, signature::Signer},
};
use passkey_types::{
    Bytes, Passkey,
    ctap2::{Flags, U2FError},
    u2f::{
        AuthenticationRequest, AuthenticationResponse, PublicKey, RegisterRequest, RegisterResponse,
    },
};
mod sealed {
    use crate::{Authenticator, CredentialStore, UserValidationMethod};

    pub trait Sealed {}
    impl<S: CredentialStore, U: UserValidationMethod> Sealed for Authenticator<S, U> {}
}

/// Provides the U2F Authenticator API
#[async_trait::async_trait]
pub trait U2fApi: sealed::Sealed {
    /// from: RegisterRequest::register() (u2f/register.rs)
    async fn register(
        &mut self,
        request: RegisterRequest,
        handle: &[u8],
    ) -> Result<RegisterResponse, U2FError>;

    /// from AuthenticationRequest::authenticate() (u2f/authenticate.rs)
    async fn authenticate(
        &self,
        request: AuthenticationRequest,
        counter: u32,
        user_presence: Flags,
    ) -> Result<AuthenticationResponse, U2FError>;
}

#[async_trait::async_trait]
impl<S: CredentialStore + Sync + Send, U: UserValidationMethod + Sync + Send> U2fApi
    for Authenticator<S, U>
{
    /// Apply a register request and create a credential and respond with the public key of said credential.
    async fn register(
        &mut self,
        request: RegisterRequest,
        handle: &[u8],
    ) -> Result<RegisterResponse, U2FError> {
        // Create Keypair on P256 curve
        let private_key = {
            let mut rng = rand::thread_rng();
            SecretKey::random(&mut rng)
        };

        // SAFETY: Can only fail if key is malformed
        let CoseKeyPair { public: _, private } =
            CoseKeyPair::from_secret_key(&private_key, iana::Algorithm::ES256);
        let signing_key = SigningKey::from(private_key);
        let public_key = signing_key.verifying_key();
        let pub_key_encoded = public_key.to_encoded_point(false);

        // SAFETY: These unwraps are safe due to the encoding not having any compression (false above)
        // this makes sure that both x and y points are present in the encoded and are of 32 bytes
        // in size.
        let public_key = PublicKey {
            x: pub_key_encoded.x().unwrap().as_slice().try_into().unwrap(),
            y: pub_key_encoded.y().unwrap().as_slice().try_into().unwrap(),
        };

        // create signature, see [`RegisterResponse::signature`]'s documentation for more information
        let signature_target = [0x00] // 1. reserved byte
            .into_iter()
            .chain(request.application) // 2. application parameter
            .chain(request.challenge) // 3. challenge parameter
            .chain(handle.iter().copied()) // 4. Key handle
            .chain(public_key.encode()) // 5. public key
            .collect::<Vec<u8>>();
        let signature_singleton: p256::ecdsa::Signature = signing_key.sign(&signature_target);
        let signature = signature_singleton.to_vec();

        let attestation_certificate = Vec::new();

        let response = RegisterResponse {
            public_key,
            key_handle: handle.into(),
            attestation_certificate,
            signature,
        };

        let (passkey, user, rp) =
            Passkey::wrap_u2f_registration_request(&request, &response, handle, &private);

        // U2F registration does not use rk, uv, or up
        let options = passkey_types::ctap2::get_assertion::Options {
            rk: false,
            uv: false,
            up: false,
        };
        let result = self
            .store_mut()
            .save_credential(passkey, user, rp, options)
            .await;

        match result {
            Ok(_) => Ok(response),
            _ => Err(U2FError::Other),
        }
    }

    /// Apply an authentication request with the appropriate response
    async fn authenticate(
        &self,
        request: AuthenticationRequest,
        counter: u32,
        user_presence: Flags,
    ) -> Result<AuthenticationResponse, U2FError> {
        // Turn the Authentication Request into a PublicKeyCredentialDescriptor and
        // an rp_id in order to find the secret key in our store

        let pk_descriptor = passkey_types::webauthn::PublicKeyCredentialDescriptor {
            ty: passkey_types::webauthn::PublicKeyCredentialType::PublicKey,
            id: request.key_handle.into(),
            transports: None,
        };
        let id_bytes: Bytes = request.application.to_vec().into();
        let maybe_credential = self
            .store()
            .find_credentials(Some(&[pk_descriptor]), String::from(id_bytes).as_str())
            .await
            .map_err(|_| U2FError::Other);

        let credential: Passkey = maybe_credential?
            .into_iter()
            .next()
            .ok_or(U2FError::Other)?
            .try_into()
            .map_err(|_| U2FError::Other)?;

        let secret_key =
            super::private_key_from_cose_key(&credential.key).map_err(|_| U2FError::Other)?;
        let signing_key = SigningKey::from(secret_key);

        // The following signature_target is specified in the U2F Raw Message Formats spec:
        // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#authentication-response-message-success
        // [A signature] is [an] ECDSA signature (on P-256) over the following byte string:
        let signature_target = request
            .application // 1. The application parameter [32 bytes] from the authentication request message.
            .into_iter()
            .chain(std::iter::once(user_presence.into())) // 2. The ... user presence byte [1 byte].
            .chain(counter.to_be_bytes()) // 3. The ... counter [4 bytes].
            .chain(request.challenge) // 4. The challenge parameter [32 bytes] from the authentication request message.
            .collect::<Vec<u8>>();

        let signature: p256::ecdsa::Signature = signing_key.sign(&signature_target);
        let signature_bytes = signature.to_der().as_bytes().to_vec();

        Ok(AuthenticationResponse {
            user_presence,
            counter,
            signature: signature_bytes,
        })
    }
}

#[cfg(test)]
mod tests;
