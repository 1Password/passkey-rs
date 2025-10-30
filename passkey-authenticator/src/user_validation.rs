use passkey_types::{
    Passkey,
    ctap2::{
        Ctap2Error,
        make_credential::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity},
    },
};

#[cfg(doc)]
use crate::Authenticator;

/// Additional information that can be displayed to the user if the authenticator has a display.
#[derive(Debug, Clone, PartialEq)]
pub enum UiHint<'a, P> {
    /// Inform the user that the operation cannot be completed because the user already has a credential registered.
    InformExcludedCredentialFound(&'a P),

    /// Inform the user that the operation cannot be completed because the user has no matching credentials registered.
    InformNoCredentialsFound,

    /// Request permission to save the credential in this object.
    RequestNewCredential(
        &'a PublicKeyCredentialUserEntity,
        &'a PublicKeyCredentialRpEntity,
    ),

    /// Request permission to use the existing credential in this object.
    RequestExistingCredential(&'a P),
}

/// The result of a user validation check.
#[derive(Clone, Copy, PartialEq)]
pub struct UserCheck {
    /// Indicates whether the user was present.
    pub presence: bool,

    /// Indicates whether the user was verified.
    pub verification: bool,
}

/// Pluggable trait for the [`Authenticator`] to do user interaction and verification.
#[cfg_attr(any(test, feature = "testable"), mockall::automock(type PasskeyItem = Passkey;))]
#[async_trait::async_trait]
pub trait UserValidationMethod {
    /// The type of the passkey item that can be used to display additional information about the operation to the user.
    type PasskeyItem: TryInto<Passkey> + Send + Sync;

    /// Check for the user's presence and obtain consent for the operation. The operation may
    /// also require the user to be verified.
    ///
    /// * `hint` - Can be used to display additional information about the operation to the user.
    /// * `presence` - Indicates whether the user's presence is required.
    /// * `verification` - Indicates whether the user should be verified.
    async fn check_user<'a>(
        &self,
        hint: UiHint<'a, Self::PasskeyItem>,
        presence: bool,
        verification: bool,
    ) -> Result<UserCheck, Ctap2Error>;

    /// Indicates whether this type is capable of testing user presence.
    fn is_presence_enabled(&self) -> bool;

    /// Indicates that this type is capable of verifying the user within itself.
    /// For example, devices with UI, biometrics fall into this category.
    ///
    /// If `Some(true)`, it indicates that the device is capable of user verification
    /// within itself and has been configured.
    ///
    /// If Some(false), it indicates that the device is capable of user verification
    /// within itself and has not been yet configured. For example, a biometric device that has not
    /// yet been configured will return this parameter set to false.
    ///
    /// If `None`, it indicates that the device is not capable of user verification within itself.
    ///
    /// A device that can only do Client PIN will set this to `None`.
    ///
    /// If a device is capable of verifying the user within itself as well as able to do Client PIN,
    ///  it will return both `Some` and the Client PIN option.
    fn is_verification_enabled(&self) -> Option<bool>;
}

/// A version of the [`UiHint`] that uses a [`Passkey`] as the passkey item, is not tied to any specific lifetime,
/// and does not verify new passkey items which contain new random data that the tests cannot know about beforehand.
#[cfg(any(test, feature = "testable"))]
#[derive(Debug, Clone)]
pub enum MockUiHint {
    InformExcludedCredentialFound(Passkey),
    InformNoCredentialsFound,
    RequestNewCredential(PublicKeyCredentialUserEntity, PublicKeyCredentialRpEntity),
    RequestExistingCredential(Passkey),
}

#[cfg(any(test, feature = "testable"))]
impl MockUserValidationMethod {
    /// Sets up the mock for returning true for the verification.
    pub fn verified_user(times: usize) -> Self {
        let mut user_mock = MockUserValidationMethod::new();
        user_mock.expect_is_presence_enabled().returning(|| true);
        user_mock
            .expect_is_verification_enabled()
            .returning(|| Some(true))
            .times(..);
        user_mock.expect_is_presence_enabled().returning(|| true);
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
            .times(times);
        user_mock
    }

    /// Sets up the mock for returning true for the verification.
    pub fn verified_user_with_hint(times: usize, expected_hint: MockUiHint) -> Self {
        let mut user_mock = MockUserValidationMethod::new();
        user_mock
            .expect_is_verification_enabled()
            .returning(|| Some(true))
            .times(..);
        user_mock
            .expect_is_presence_enabled()
            .returning(|| true)
            .times(..);
        user_mock
            .expect_check_user()
            .withf(move |actual_hint, presence, verification| {
                *presence
                    && *verification
                    && match &expected_hint {
                        MockUiHint::InformExcludedCredentialFound(p) => {
                            actual_hint == &UiHint::InformExcludedCredentialFound(p)
                        }
                        MockUiHint::InformNoCredentialsFound => {
                            matches!(actual_hint, UiHint::InformNoCredentialsFound)
                        }
                        MockUiHint::RequestNewCredential(user, rp) => {
                            actual_hint == &UiHint::RequestNewCredential(user, rp)
                        }
                        MockUiHint::RequestExistingCredential(p) => {
                            actual_hint == &UiHint::RequestExistingCredential(p)
                        }
                    }
            })
            .returning(|_, _, _| {
                Ok(UserCheck {
                    presence: true,
                    verification: true,
                })
            })
            .times(times);
        user_mock
    }
}
