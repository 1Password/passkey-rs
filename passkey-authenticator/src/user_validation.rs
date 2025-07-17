use passkey_types::{Passkey, ctap2::Ctap2Error};

#[cfg(doc)]
use crate::Authenticator;

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
    /// * `crdential` - Can be used to display additional information about the operation to the user.
    /// * `presence` - Indicates whether the user's presence is required.
    /// * `verification` - Indicates whether the user should be verified.
    async fn check_user<'a>(
        &self,
        credential: Option<&'a Self::PasskeyItem>,
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
    pub fn verified_user_with_credential(times: usize, credential: Passkey) -> Self {
        let mut user_mock = MockUserValidationMethod::new();
        user_mock
            .expect_is_verification_enabled()
            .returning(|| Some(true));
        user_mock
            .expect_check_user()
            .withf(move |cred, up, uv| cred == &Some(&credential) && *up && *uv)
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
