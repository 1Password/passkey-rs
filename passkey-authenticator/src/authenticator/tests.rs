use passkey_types::ctap2::{Aaguid, Flags};

use crate::{
    Authenticator, CredentialIdLength, MockUserValidationMethod, UserCheck, user_validation::UiHint,
};

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
    let result = authenticator
        .check_user(UiHint::InformNoCredentialsFound, &options)
        .await
        .unwrap();

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
    let result = authenticator
        .check_user(UiHint::InformNoCredentialsFound, &options)
        .await
        .unwrap();

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
    let result = authenticator
        .check_user(UiHint::InformNoCredentialsFound, &options)
        .await
        .unwrap();

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
    let result = authenticator
        .check_user(UiHint::InformNoCredentialsFound, &options)
        .await;

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
    let result = authenticator
        .check_user(UiHint::InformNoCredentialsFound, &options)
        .await;

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
    let result = authenticator
        .check_user(UiHint::InformNoCredentialsFound, &options)
        .await;

    // Assert
    assert_eq!(
        result,
        Err(passkey_types::ctap2::Ctap2Error::UnsupportedOption)
    );
}

#[tokio::test]
async fn check_user_returns_up_and_uv_flags_when_neither_up_or_uv_was_requested_but_performed_anyways()
 {
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
    let result = authenticator
        .check_user(UiHint::InformNoCredentialsFound, &options)
        .await
        .unwrap();

    // Assert
    assert_eq!(result, Flags::UP | Flags::UV);
}

#[test]
fn credential_id_lengths_validate() {
    for num in 0..u8::MAX {
        let length = CredentialIdLength::from(num);
        if !(16..=64).contains(&num) {
            if num < 16 {
                // Lower values should be rounded up.
                assert_eq!(length.0, CredentialIdLength::DEFAULT.0);
            } else {
                // Higher values should be clamped
                assert_eq!(length.0, 64);
            }
        }
    }

    assert_eq!(
        CredentialIdLength::DEFAULT.0,
        CredentialIdLength::default().0
    );
}

#[test]
fn credential_id_generation() {
    let mut rng = rand::thread_rng();
    let valid_range = 0..=64;
    for _ in 0..=100 {
        let length = CredentialIdLength::randomized(&mut rng).0;
        assert!(valid_range.contains(&length));
    }
}
