//! Ctap 2.0 Authenticator API
//!
//! This module defines the [`Ctap2Api`] trait which is sealed to the [`Authenticator`] type and a
//! future `RemoteAuthenticator` type wich will implement the different transports.
//!
//! <https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticator-api>

use passkey_types::ctap2::{get_assertion, get_info, make_credential, StatusCode};

use crate::{Authenticator, CredentialStore, UserValidationMethod};

mod sealed {
    use crate::{Authenticator, CredentialStore, UserValidationMethod};

    pub trait Sealed {}

    impl<S: CredentialStore, U: UserValidationMethod> Sealed for Authenticator<S, U> {}
}

/// Methods defined as being required for a [CTAP 2.0] compliant authenticator to implement.
///
/// This trait is sealed to prevent missuse and to prevent incorrect implementations in the wild.
/// If you need to define an authenticator please use the [`Authenticator`] struct which provides
/// the necessary generics to customize storage and UI interactions.
///
/// These methods are provided as traits in order to have a remotely connected authenticators through
/// the different transports defined in [CTAP 2.0].
///
/// [CTAP 2.0]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
#[async_trait::async_trait]
pub trait Ctap2Api: sealed::Sealed {
    /// Request to get the information of the authenticator and see what it supports.
    async fn get_info(&self) -> get_info::Response;

    /// Request to create and save a new credential in the authenticator.
    async fn make_credential(
        &mut self,
        request: make_credential::Request,
    ) -> Result<make_credential::Response, StatusCode>;

    /// Request to assert a user's existing credential that might exist in the authenticator.
    async fn get_assertion(
        &self,
        request: get_assertion::Request,
    ) -> Result<get_assertion::Response, StatusCode>;
}

#[async_trait::async_trait]
impl<S, U> Ctap2Api for Authenticator<S, U>
where
    S: CredentialStore + Sync + Send,
    U: UserValidationMethod + Sync + Send,
{
    async fn get_info(&self) -> get_info::Response {
        self.get_info()
    }

    async fn make_credential(
        &mut self,
        request: make_credential::Request,
    ) -> Result<make_credential::Response, StatusCode> {
        self.make_credential(request).await
    }

    async fn get_assertion(
        &self,
        request: get_assertion::Request,
    ) -> Result<get_assertion::Response, StatusCode> {
        self.get_assertion(request).await
    }
}
