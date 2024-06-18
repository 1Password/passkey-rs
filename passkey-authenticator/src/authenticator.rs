use coset::iana;
use passkey_types::{
    ctap2::{Aaguid, Ctap2Error, Flags},
    webauthn,
};

use crate::{CredentialStore, UserValidationMethod};

mod get_assertion;
mod get_info;
mod make_credential;

/// A virtual authenticator with all the necessary state and information.
pub struct Authenticator<S, U> {
    /// The authenticator's AAGUID
    aaguid: Aaguid,
    /// Provides credential storage capabilities
    store: S,
    /// Current supported algorithms by the authenticator
    algs: Vec<iana::Algorithm>,
    /// Current supported transports that this authenticator can use to communicate.
    ///
    /// Default values are [`AuthenticatorTransport::Internal`] and [`AuthenticatorTransport::Hybrid`].
    transports: Vec<webauthn::AuthenticatorTransport>,
    /// Provider of user verification factor.
    user_validation: U,

    /// The display name given when a [`webauthn::CredentialPropertiesOutput`] is requested
    display_name: Option<String>,

    /// Value to control whether the authenticator will save new credentials with a signature counter.
    /// The default value is `false`.
    ///
    /// NOTE: Using a counter with a credential that will sync is not recommended and can cause friction
    /// with the distributed nature of synced keys. It can also cause issues with backup and restore functionality.
    make_credentials_with_signature_counter: bool,
}

impl<S, U> Authenticator<S, U>
where
    S: CredentialStore,
    U: UserValidationMethod,
{
    /// Create an authenticator with a known aaguid, a backing storage and a User verification system.
    pub fn new(aaguid: Aaguid, store: S, user: U) -> Self {
        Self {
            aaguid,
            store,
            // TODO: Change this to a method on the cryptographic backend
            algs: vec![iana::Algorithm::ES256],
            transports: vec![
                webauthn::AuthenticatorTransport::Internal,
                webauthn::AuthenticatorTransport::Hybrid,
            ],
            user_validation: user,
            display_name: None,
            make_credentials_with_signature_counter: false,
        }
    }

    /// Set the authenticator's display name which will be returned if [`webauthn::CredentialPropertiesOutput`] is requested.
    pub fn set_display_name(&mut self, name: String) {
        self.display_name = Some(name);
    }

    /// Get a reference to the authenticators display name to return in [`webauthn::CredentialPropertiesOutput`].
    pub fn display_name(&self) -> Option<&String> {
        self.display_name.as_ref()
    }

    /// Set whether the authenticator should save new credentials with a signature counter.
    ///
    /// NOTE: Using a counter with a credential that will sync is not recommended and can cause friction
    /// with the distributed nature of synced keys. It can also cause issues with backup and restore functionality.
    pub fn set_make_credentials_with_signature_counter(&mut self, value: bool) {
        self.make_credentials_with_signature_counter = value;
    }

    /// Get whether the authenticator will save new credentials with a signature counter.
    pub fn make_credentials_with_signature_counter(&self) -> bool {
        self.make_credentials_with_signature_counter
    }

    /// Access the [`CredentialStore`] to look into what is stored.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Exclusively access the [`CredentialStore`] to look into what is stored and modify it if needed.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Access the authenticator's [`Aaguid`]
    pub fn aaguid(&self) -> &Aaguid {
        &self.aaguid
    }

    /// Return the current attachment type for this authenticator.
    pub fn attachment_type(&self) -> webauthn::AuthenticatorAttachment {
        // TODO: Make this variable depending on the transport.
        webauthn::AuthenticatorAttachment::Platform
    }

    /// Validate `params` with the following steps
    ///     1. For each element of `params`:
    ///         1-2: Handled during deserialization
    ///         3. If the element specifies an algorithm that is supported by the authenticator, and
    ///            no algorithm has yet been chosen by this loop, then let the algorithm specified by
    ///            the current element be the chosen algorithm.
    ///     2. If the loop completes and no algorithm was chosen then return [`Ctap2Error::UnsupportedAlgorithm`].
    /// Note: This loop chooses the first occurrence of an algorithm identifier supported by this
    ///       authenticator but always iterates over every element of `params` to validate them.
    pub fn choose_algorithm(
        &self,
        params: &[webauthn::PublicKeyCredentialParameters],
    ) -> Result<iana::Algorithm, Ctap2Error> {
        params
            .iter()
            .find(|param| self.algs.contains(&param.alg))
            .map(|param| param.alg)
            .ok_or(Ctap2Error::UnsupportedAlgorithm)
    }

    /// Builder method for overwriting the authenticator's supported transports.
    pub fn transports(self, transports: Vec<webauthn::AuthenticatorTransport>) -> Self {
        Self { transports, ..self }
    }

    /// Collect user consent if required. This step MUST happen before the following steps due
    ///    to privacy reasons (i.e., authenticator cannot disclose existence of a credential
    ///    until the user interacted with the device):
    ///     1. If the "uv" option was specified and set to true:
    ///         1. If device doesn’t support user-identifiable gestures, return the
    ///            CTAP2_ERR_UNSUPPORTED_OPTION error.
    ///         2. Collect a user-identifiable gesture. If gesture validation fails, return the
    ///            CTAP2_ERR_OPERATION_DENIED error.
    ///     2. If the "up" option was specified and set to true, collect the user’s consent.
    ///         1. If no consent is obtained and a timeout occurs, return the
    ///            CTAP2_ERR_OPERATION_DENIED error.
    async fn check_user(
        &self,
        options: &passkey_types::ctap2::make_credential::Options,
        credential: Option<<U as UserValidationMethod>::PasskeyItem>,
    ) -> Result<Flags, Ctap2Error> {
        if options.uv && self.user_validation.is_verification_enabled() != Some(true) {
            return Err(Ctap2Error::UnsupportedOption);
        };

        let check_result = self
            .user_validation
            .check_user(credential, options.up, options.uv)
            .await?;

        if options.up && !check_result.presence {
            return Err(Ctap2Error::OperationDenied);
        }

        if options.uv && !check_result.verification {
            return Err(Ctap2Error::OperationDenied);
        }

        let mut flags = Flags::empty();
        if check_result.presence {
            flags |= Flags::UP;
        }

        if check_result.verification {
            flags |= Flags::UV;
        }

        Ok(flags)
    }
}

#[cfg(test)]
mod tests {
    use passkey_types::ctap2::{Aaguid, Flags};

    use crate::{Authenticator, MockUserValidationMethod, UserCheck};

    #[tokio::test]
    async fn check_user_does_not_check_up_or_uv_when_not_requested() {
        // Arrange & Assert
        let mut user_mock = MockUserValidationMethod::new();
        user_mock
            .expect_check_user()
            .with(
                mockall::predicate::always(),
                mockall::predicate::eq(false),
                mockall::predicate::eq(false),
            )
            .returning(|_, _, _| {
                Ok(UserCheck {
                    presence: false,
                    verification: false,
                })
            })
            .once();

        // Arrange
        let store = None;
        let authenticator = Authenticator::new(Aaguid::new_empty(), store, user_mock);
        let options = passkey_types::ctap2::make_credential::Options {
            up: false,
            uv: false,
            ..Default::default()
        };

        // Act
        let result = authenticator.check_user(&options, None).await.unwrap();

        // Assert
        assert_eq!(result, Flags::empty());
    }

    #[tokio::test]
    async fn check_user_checks_up_when_requested() {
        // Arrange & Assert
        let mut user_mock = MockUserValidationMethod::new();
        user_mock
            .expect_check_user()
            .with(
                mockall::predicate::always(),
                mockall::predicate::eq(true),
                mockall::predicate::eq(false),
            )
            .returning(|_, _, _| {
                Ok(UserCheck {
                    presence: true,
                    verification: false,
                })
            })
            .once();

        // Arrange
        let store = None;
        let authenticator = Authenticator::new(Aaguid::new_empty(), store, user_mock);
        let options = passkey_types::ctap2::make_credential::Options {
            up: true,
            uv: false,
            ..Default::default()
        };

        // Act
        let result = authenticator.check_user(&options, None).await.unwrap();

        // Assert
        assert_eq!(result, Flags::UP);
    }

    #[tokio::test]
    async fn check_user_checks_uv_when_requested() {
        // Arrange & Assert
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
            .once();

        // Arrange
        let store = None;
        let authenticator = Authenticator::new(Aaguid::new_empty(), store, user_mock);
        let options = passkey_types::ctap2::make_credential::Options {
            up: true,
            uv: true,
            ..Default::default()
        };

        // Act
        let result = authenticator.check_user(&options, None).await.unwrap();

        // Assert
        assert_eq!(result, Flags::UP | Flags::UV);
    }

    #[tokio::test]
    async fn check_user_returns_operation_denied_when_up_was_requested_but_not_returned() {
        // Arrange & Assert
        let mut user_mock = MockUserValidationMethod::new();
        user_mock
            .expect_check_user()
            .with(
                mockall::predicate::always(),
                mockall::predicate::eq(true),
                mockall::predicate::eq(false),
            )
            .returning(|_, _, _| {
                Ok(UserCheck {
                    presence: false,
                    verification: false,
                })
            })
            .once();

        // Arrange
        let store = None;
        let authenticator = Authenticator::new(Aaguid::new_empty(), store, user_mock);
        let options = passkey_types::ctap2::make_credential::Options {
            up: true,
            uv: false,
            ..Default::default()
        };

        // Act
        let result = authenticator.check_user(&options, None).await;

        // Assert
        assert_eq!(
            result,
            Err(passkey_types::ctap2::Ctap2Error::OperationDenied)
        );
    }

    #[tokio::test]
    async fn check_user_returns_operation_denied_when_uv_was_requested_but_not_returned() {
        // Arrange & Assert
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
                    verification: false,
                })
            })
            .once();

        // Arrange
        let store = None;
        let authenticator = Authenticator::new(Aaguid::new_empty(), store, user_mock);
        let options = passkey_types::ctap2::make_credential::Options {
            up: true,
            uv: true,
            ..Default::default()
        };

        // Act
        let result = authenticator.check_user(&options, None).await;

        // Assert
        assert_eq!(
            result,
            Err(passkey_types::ctap2::Ctap2Error::OperationDenied)
        );
    }

    #[tokio::test]
    async fn check_user_returns_unsupported_option_when_uv_was_requested_but_is_not_supported() {
        // Arrange & Assert
        let mut user_mock = MockUserValidationMethod::new();
        user_mock
            .expect_is_verification_enabled()
            .returning(|| None);

        // Arrange
        let store = None;
        let authenticator = Authenticator::new(Aaguid::new_empty(), store, user_mock);
        let options = passkey_types::ctap2::make_credential::Options {
            up: true,
            uv: true,
            ..Default::default()
        };

        // Act
        let result = authenticator.check_user(&options, None).await;

        // Assert
        assert_eq!(
            result,
            Err(passkey_types::ctap2::Ctap2Error::UnsupportedOption)
        );
    }

    #[tokio::test]
    async fn check_user_returns_up_and_uv_flags_when_neither_up_or_uv_was_requested_but_performed_anyways(
    ) {
        // Arrange & Assert
        let mut user_mock = MockUserValidationMethod::new();
        user_mock
            .expect_is_verification_enabled()
            .returning(|| Some(true));
        user_mock
            .expect_check_user()
            .with(
                mockall::predicate::always(),
                mockall::predicate::eq(false),
                mockall::predicate::eq(false),
            )
            .returning(|_, _, _| {
                Ok(UserCheck {
                    presence: true,
                    verification: true,
                })
            })
            .once();

        // Arrange
        let store = None;
        let authenticator = Authenticator::new(Aaguid::new_empty(), store, user_mock);
        let options = passkey_types::ctap2::make_credential::Options {
            up: false,
            uv: false,
            ..Default::default()
        };

        // Act
        let result = authenticator.check_user(&options, None).await.unwrap();

        // Assert
        assert_eq!(result, Flags::UP | Flags::UV);
    }
}
