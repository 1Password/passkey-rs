//! # Passkey-RS by 1Password
//!
//! [![github]](https://github.com/1Password/passkey-rs/tree/main/passkey/)
//! [![version]](https://crates.io/crates/passkey/)
//! [![documentation]](https://docs.rs/passkey/)
//!
//! The `passkey-rs` library is a collection of Rust libraries to enable developers to use Passkeys in Rust code through a comprehensive implementation of both the [Webauthn Level 3][webauthn-3] and [CTAP2][ctap-2] standards. It is comprised of five sub-libraries:
//!
//! - `passkey-client` - a library, usable as [`client`], which implements the [Webauthn Level 3 standard][webauthn-3] for authentication to websites.
//! - `passkey-authenticator` - a library, usable as [`authenticator`], which implements the [CTAP2][ctap-2] standard.
//! - `passkey-transports` - a library, usable as [`transports`], which implements the [CTAP HID protocol][ctap-hid].
//! - `passkey-types` - type definitions, usable as [`types`] for the `-client` and `-authenticator` libraries.
//! - `public-suffix` - a library which efficiently determines the effictive Top-Level Domain of a given URL, based on the [Mozilla Public Suffix List][public-suffix].
//!
//! In understanding how to use this library, developers should read the [Webauthn Level 3][webauthn-3] and [CTAP2][ctap-2] standards. Much of the type naming in these libraries refer directly to the terms used in these standards and being familiar with their terminology will greatly aid your understanding of how to use these libraries.
//!
//! Examples in this documentation shows certain values being assumed to come from the website (Relying Party). It is not within the scope of these libraries to manage the details of the interaction with the Relying Party. How these values and the authentication results are communicated with the Relying Party is an implementation detail for users of these crates.
//!
//! ## Basic Concepts
//!
//! Conceptually, working with Passkeys involves receiving requests for registration of new credentials, storing those credentials, and performing authentication with existing credentials. Two standards are involved here: [Webauthn][webauthn-3] is the protocol by which a website (a "Relying Party") communicates with your application. The [Client-to-Authenticator Protocol (CTAP2)][ctap-2] is the protocol by which your application communicates with an authenticator - which can be software or a hardware device such as a FIDO2 USB key.
//!
//! This library provides Rust types to implement both protocols, as well as a software [`Authenticator`](authenticator::Authenticator) which can be used in place of the USB keys that many will be familiar with.
//!
//! You can think of these libraries as a chain that interacts with Relying Parties in the following way:
//!
//! RelyingParty <-> [`Client`](client::Client) <-> [Authenticator](`authenticator::Authenticator`) <-> [CredentialStore](`authenticator::CredentialStore`)
//!
//! The [`Client`](client::Client) type marshals and unmarshals options and data from the Relying Party. It provides the following API for registration and authentication:
//!
//! - [`register()`](client::Client::register()) - Register a webauthn credential.
//! - [`authenticate()`](client::Client::authenticate()) - Authenticate a webauthn request.
//!
//! The [`Client`](client::Client) does not itself perform cryptographic operations. Instead it depends on an internal [Authenticator](`passkey-authenticator::Authenticator`) for these operations.
//!
//! The [`Authenticator`](`passkey-authenticator::Authenticator`) type provides a virtual authenticator which can create new credentials and authenticate users using the following functions:
//!
//! - [`make_credential()`](authenticator::Authenticator::make_credential()) - creates a credential.
//! - [`get_assertion()`](authenticator::Authenticator::get_assertion()) - generates the cryptograhic proof of user authentication
//!
//! The [`Authenticator`](`authenticator::Authenticator`) does not store credentials itself, but relies on a generic type which implements the [`CredentialStore`](authenticator::CredentialStore) trait. This trait provides the API for storing and retrieving Passkey structures:
//!
//! - [`save_credential()`](authenticator::CredentialStore::save_credential()) - stores a credential created in [`make_credential()`](authenticator::Authenticator::make_credential())
//! - [`find_credentials()`](authenticator::CredentialStore::find_credentials()) - searches the [`CredentialStore`](authenticator::CredentialStore)'s internal storage for credentials which might be used for an authentication.
//!
//! The [`authenticator`] library provides a range of implementations of [`authenticator::CredentialStore`] but users of the library can provide their own.
//!
//! A runnable demonstration binary is provided in `passkey/examples/usage.rs`.
//!
//! [github]: https://img.shields.io/badge/GitHub-1Password%2Fpasskey--rs%2Fpasskey-informational?logo=github&style=flat
//! [version]: https://img.shields.io/crates/v/passkey?logo=rust&style=flat
//! [documentation]: https://img.shields.io/docsrs/passkey/latest?logo=docs.rs&style=flat
//! [webauthn-3]: https://www.w3.org/TR/webauthn-3/
//! [ctap-2]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
//! [public-suffix]: https://publicsuffix.org/
//! [ctap-hid]: https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#usb
//!
//! ### Example: Using the Client type for Webauthn Operations
//!
//! The highest-level type in these libraries is the `passkey-client::Client`. This is the type you will primarily use to implement Webauthn authentication in your application.
//!
//! The following example demonstrates how to create a `Client` and use it to create a credential. Doing this from scratch involves creating an `Authenticator` and a `CredentialStore`, then providing those to the `Client`.
//!
//! In this example, we are going to manually create a `CredentialCreationOptions` struct with hypothetical values named `*_from_rp` to indicate that these are values that would usually be supplied by the Relying Party. For simplicity, most of the `CredentialCreationOptions` are being set to `None` here.
//! ```
//! use passkey::{
//!     authenticator::{Authenticator, UserValidationMethod, UserCheck},
//!     client::{Client, WebauthnError},
//!     types::{ctap2::*, rand::random_vec, crypto::sha256, webauthn::*, Bytes, Passkey},
//! };
//!
//! use coset::iana;
//! use url::Url;
//! #
//! # // MyUserValidationMethod is a stub impl of the UserValidationMethod trait, used later.
//! # struct MyUserValidationMethod {}
//! # #[async_trait::async_trait]
//! # impl UserValidationMethod for MyUserValidationMethod {
//! #     type PasskeyItem = Passkey;
//! #
//! #     async fn check_user(
//! #         &self,
//! #         _credential: Option<Self::PasskeyItem>,
//! #         presence: bool,
//! #         verification: bool,
//! #     ) -> Result<UserCheck, Ctap2Error> {
//! #         Ok(UserCheck { presence: true, verification: true })
//! #     }
//! #
//! #     fn is_verification_enabled(&self) -> Option<bool> {
//! #         Some(true)
//! #     }
//! #
//! #     fn is_presence_enabled(&self) -> bool {
//! #         true
//! #     }
//! # }
//!
//! // Example of how to set up, register and authenticate with a `Client`.
//! # tokio_test::block_on(async {
//! let challenge_bytes_from_rp: Bytes = random_vec(32).into();
//! let parameters_from_rp = PublicKeyCredentialParameters {
//!     ty: PublicKeyCredentialType::PublicKey,
//!     alg: iana::Algorithm::ES256,
//! };
//! let origin = Url::parse("https://future.1password.com").expect("Should parse");
//! let user_entity = PublicKeyCredentialUserEntity {
//!     id: random_vec(32).into(),
//!     display_name: "Johnny Passkey".into(),
//!     name: "jpasskey@example.org".into(),
//! };
//! // First create an Authenticator for the Client to use.
//! let my_aaguid = Aaguid::new_empty();
//! let user_validation_method = MyUserValidationMethod {};
//! // Create the CredentialStore for the Authenticator.
//! // Option<Passkey> is the simplest possible implementation of CredentialStore
//! let store: Option<Passkey> = None;
//! let my_authenticator = Authenticator::new(my_aaguid, store, user_validation_method);
//!
//! // Create the Client
//! // If you are creating credentials, you need to declare the Client as mut
//! let mut my_client = Client::new(my_authenticator);
//!
//! // The following values, provided as parameters to this function would usually be
//! // retrieved from a Relying Party according to the context of the application.
//! let request = CredentialCreationOptions {
//!     public_key: PublicKeyCredentialCreationOptions {
//!         rp: PublicKeyCredentialRpEntity {
//!             id: None, // Leaving the ID as None means use the effective domain
//!             name: origin.domain().unwrap().into(),
//!         },
//!         user: user_entity,
//!         challenge: challenge_bytes_from_rp,
//!         pub_key_cred_params: vec![parameters_from_rp],
//!         timeout: None,
//!         exclude_credentials: None,
//!         authenticator_selection: None,
//!         hints: None,
//!         attestation: AttestationConveyancePreference::None,
//!         attestation_formats: None,
//!         extensions: None,
//!     },
//! };
//!
//! // Now create the credential.
//! let my_webauthn_credential = my_client.register(&origin, request, None).await.unwrap();
//!
//! // Let's try and authenticate.
//! // Create a challenge that would usually come from the RP.
//! let challenge_bytes_from_rp: Bytes = random_vec(32).into();
//! // Now try and authenticate
//! let credential_request = CredentialRequestOptions {
//!     public_key: PublicKeyCredentialRequestOptions {
//!         challenge: challenge_bytes_from_rp,
//!         timeout: None,
//!         rp_id: Some(String::from(origin.domain().unwrap())),
//!         allow_credentials: None,
//!         user_verification: UserVerificationRequirement::default(),
//!         hints: None,
//!         attestation: AttestationConveyancePreference::None,
//!         attestation_formats: None,
//!         extensions: None,
//!     },
//! };
//!
//! let authenticated_cred = my_client
//!     .authenticate(&origin, credential_request, None)
//!     .await
//!     .unwrap();
//! # })
//! ```
//! ### Example: Using the Authenticator for CTAP2 Operations
//!
//! The following code provides a basic example of how to create and use an `Authenticator` by itself to generate a credential and store it.
//!
//! ```
//! # use passkey::{
//! #     authenticator::{Authenticator, UserValidationMethod, UserCheck},
//! #     client::{Client, WebauthnError},
//! #     types::{ctap2::*, rand::random_vec, crypto::sha256, webauthn::*, Bytes, Passkey},
//! # };
//! #
//! # use coset::iana;
//! # use url::Url;
//! #
//! # // MyUserValidationMethod is a stub impl of the UserValidationMethod trait, used later.
//! # struct MyUserValidationMethod {}
//! # #[async_trait::async_trait]
//! # impl UserValidationMethod for MyUserValidationMethod {
//! #     type PasskeyItem = Passkey;
//! #
//! #     async fn check_user(
//! #         &self,
//! #         _credential: Option<Self::PasskeyItem>,
//! #         presence: bool,
//! #         verification: bool,
//! #     ) -> Result<UserCheck, Ctap2Error> {
//! #         Ok(UserCheck { presence: true, verification: true })
//! #     }
//! #
//! #     fn is_verification_enabled(&self) -> Option<bool> {
//! #         Some(true)
//! #     }
//! #
//! #     fn is_presence_enabled(&self) -> bool {
//! #         true
//! #     }
//! # }
//! #
//! # tokio_test::block_on(async {
//! // Note: this isn't really how you generate `client_data_hash` but it simplifies the example.
//! // See usage.rs for actual technique.
//! let client_data_hash: Bytes = random_vec(32).into();
//! let user_entity = PublicKeyCredentialUserEntity {
//!     id: random_vec(32).into(),
//!     display_name: "Johnny Passkey".into(),
//!     name: "jpasskey@example.org".into(),
//! };
//! let algorithms_from_rp = PublicKeyCredentialParameters {
//!     ty: PublicKeyCredentialType::PublicKey,
//!     alg: iana::Algorithm::ES256,
//! };
//! let rp_id: String = "future.1password.com".into();
//! let store: Option<Passkey> = None;
//! let user_validation_method = MyUserValidationMethod {};
//! let my_aaguid = Aaguid::new_empty();
//!
//! let mut my_authenticator = Authenticator::new(my_aaguid, store, user_validation_method);
//!
//! let reg_request = make_credential::Request {
//!     client_data_hash: client_data_hash.clone(),
//!     rp: make_credential::PublicKeyCredentialRpEntity {
//!         id: rp_id.clone(),
//!         name: None,
//!     },
//!     user: user_entity,
//!     pub_key_cred_params: vec![algorithms_from_rp],
//!     exclude_list: None,
//!     extensions: None,
//!     options: make_credential::Options::default(),
//!     pin_auth: None,
//!     pin_protocol: None,
//! };
//!
//! let credential: make_credential::Response =
//!     my_authenticator.make_credential(reg_request).await.unwrap();
//!
//! // Now try and authenticate with the credential.
//! let auth_request = get_assertion::Request {
//!     rp_id,
//!     client_data_hash,
//!     allow_list: None,
//!     extensions: None,
//!     options: make_credential::Options::default(),
//!     pin_auth: None,
//!     pin_protocol: None,
//! };
//!
//! let response = my_authenticator.get_assertion(auth_request).await.unwrap();
//! # })
//! ```

pub use passkey_authenticator as authenticator;
pub use passkey_client as client;
pub use passkey_transports as transports;
pub use passkey_types as types;
