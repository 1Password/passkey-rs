# Passkey-rs by 1Password

[![github]](https://github.com/1Password/passkey-rs/tree/main/passkey/)
[![version]](https://crates.io/crates/passkey/)
[![documentation]](https://docs.rs/passkey/)

The `passkey-rs` library is a collection of Rust libraries to enable developers to use Passkeys in Rust code through a comprehensive implementation of both the [Webauthn Level 3][webauthn-3] and [CTAP2][ctap-2] standards. It is comprised of five sub-libraries:

- `passkey-client` - a library, usable as `client`, which implements the [Webauthn Level 3 standard][webauthn-3] for authentication to websites.
- `passkey-authenticator` - a library, usable as `authenticator`, which implements the [CTAP2][ctap-2] standard.
- `passkey-transports` - a library, usable as `transports`, which implements the [CTAP HID protocol][ctap-hid].
- `passkey-types` - type definitions, usable as `types` for the `-client` and `-authenticator` libraries.
- `public-suffix` - a library which efficiently determines the effictive Top-Level Domain of a given URL, based on the [Mozilla Public Suffix List][public-suffix].

In understanding how to use this library, developers should read the [Webauthn Level 3][webauthn-3] and [CTAP2][ctap-2] standards. Much of the type naming in these libraries refer directly to the terms used in these standards and being familiar with their terminology will greatly aid your understanding of how to use these libraries.

Examples in this documentation shows certain values being assumed to come from the website (Relying Party). It is not within the scope of these libraries to manage the details of the interaction with the Relying Party. How these values and the authentication results are communicated with the Relying Party is an implementation detail for users of these crates.

# Basic Concepts

Conceptually, working with Passkeys involves receiving requests for registration of new credentials, storing those credentials, and performing authentication with existing credentials. Two standards are involved here: [Webauthn][webauthn-3] is the protocol by which a website (a "Relying Party") communicates with your application. The [Client-to-Authenticator Protocol (CTAP2)][ctap-2] is the protocol by which your application communicates with an authenticator - which can be software or a hardware device such as a FIDO2 USB key.

This library provides Rust types to implement both protocols, as well as a software `Authenticator` which can be used in place of the USB keys that many will be familiar with.

You can think of these libraries as a chain that interacts with Relying Parties in the following way:

RelyingParty <-> `Client` <-> `Authenticator` <-> `CredentialStore`

The `Client` type marshals and unmarshals options and data from the Relying Party. It provides the following API for registration and authentication:

- `register()` - Register a webauthn credential.
- `authenticate()` - Authenticate a webauthn request.

The `Client` does not itself perform cryptographic operations. Instead it depends on an internal `Authenticator` for these operations.

The `Authenticator` type provides a virtual authenticator which can create new credentials and authenticate users using the following functions:

- `make_credential()` - creates a credential.
- `get_assertion()` - generates the cryptograhic proof of user authentication

The `Authenticator` does not store credentials itself, but relies on a generic type which implements the `CredentialStore` trait. This trait provides the API for storing and retrieving Passkey structures:

- `save_credential()` - stores a credential created in `make_credential()`
- `find_credentials()` - searches the `CredentialStore`'s internal storage for credentials which might be used for an authentication.

The `authenticator` library provides a range of implementations of `authenticator::CredentialStore` but users of the library can provide their own.

A runnable demonstration binary is provided in `passkey/examples/usage.rs`.
## Example: Using the Client type for Webauthn Operations

The highest-level type in these libraries is the `passkey-client::Client`. This is the type you will primarily use to implement Webauthn authentication in your application.

The following example demonstrates how to create a `Client` and use it to create a credential. Doing this from scratch involves creating an `Authenticator` and a `CredentialStore`, then providing those to the `Client`.

In this example, we are going to manually create a `CredentialCreationOptions` struct with hypothetical values named `*_from_rp` to indicate that these are values that would usually be supplied by the Relying Party. For simplicity, most of the `CredentialCreationOptions` are being set to `None` here.

```rust
use passkey::{
    authenticator::{Authenticator, UserValidationMethod},
    client::{Client, WebauthnError},
    types::{ctap2::*, webauthn::*, Bytes, Passkey},
};
use url::Url;

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
            name: name_from_rp.clone(),
        },
        user: PublicKeyCredentialUserEntity {
            id: user_handle_from_rp,
            display_name: display_name_from_rp,
            name: name_from_rp,
        },
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
let my_webauthn_credential: CreatedPublicKeyCredential = my_client.register(origin, request).await?;

```

The above example shows how a Webauthn credential can be created. Now, we can go ahead and try to authenticate the user.

```rust
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

let authenticated_cred: AuthenticatedPublicKeyCredential = my_client
    .authenticate(origin, credential_request, None)
    .await?;
```

## Example: Using the Authenticator for CTAP2 Operations

The following code provides a basic example of how to create and use an `Authenticator` by itself to generate a credential and store it.

```rust
// Option<Passkey> is the simplest possible implementation of CredentialStore
let store: Option<Passkey> = None;
let user_validation_method = MyUserValidationMethod {};
let my_aaguid = Aaguid::new_empty();

let mut my_authenticator = Authenticator::new(my_aaguid, store, user_validation_method);

let reg_request = make_credential::Request {
    client_data_hash: client_data_hash_from_rp.clone(),
    rp: make_credential::PublicKeyCredentialRpEntity {
        id: tld_from_rp.clone(),
        name: None,
    },
    user: PublicKeyCredentialUserEntity {
        id: user_handle_from_rp,
        display_name: display_name_from_rp,
        name: name_from_rp,
    },
    pub_key_cred_params: vec![algorithms_from_rp],
    exclude_list: None,
    extensions: None,
    options: make_credential::Options::default(),
    pin_auth: None,
    pin_protocol: None,
};

let credential: make_credential::Response =
    my_authenticator.make_credential(reg_request).await?;
```

The credential is stored within the `Authenticator`'s `CredentialStore` as part of the creation process. Now, we can use this credential directly to perform an authentication:

```rust
let auth_request = get_assertion::Request {
    rp_id: tld_from_rp,
    client_data_hash: client_data_hash_from_rp,
    allow_list: None,
    extensions: None,
    options: make_credential::Options::default(),
    pin_auth: None,
    pin_protocol: None,
};

let response = my_authenticator.get_assertion(auth_request).await?;
```

## Crates in Detail

### Passkey-Types

`Passkey-types` provides the type definitions for the other crates. It may be initially confusing to realise that there are sometimes two variants of what is seemingly the same type. For example, we have a `webauthn::PublicKeyCredentialRpEntity` and a `ctap2::PublicKeyCredentialRpEntity`. This is because the different protocols have different requirements for which fields must be present and which are optional. In cases where the CTAP2 structures are the same as those in Webauthn, the CTAP2 libraries use the Webauthn types.

### Public-Suffix

The `Public-Suffix` crate provides an efficient library for determining the effective top-level domain or 'public suffix' for a given URL. Most crate users will not need to work with this library directly. It is used internally by the `passkey-client::Client` type.

However, depending on the context, it may be necessary for some applications to take an alternative interpretation of certain top-level domains. To do this, users can reimplement the public-suffix list in this crate or provide an alternative implementation. Next, users should implement the `public-suffix::EffectiveTLDProvider` trait and provide that implementation to `Client::new_with_custom_tld_provider()`. An example of how to do this is provided in the `validate_domain_with_private_list_provider()` test in `passkey_client::tests`. See, also, the README in `public-suffix` for more information on how to generate a custom TLD list according to the needs of your application.

## Current Limitations

- `Client::authenticate()` and `Client::register()` do not respect timeout values set in `CredentialRequestOptions`.
- The `Client` always reports its [Authenticator Attachment Modality](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-attachment-modality) as "Platform"
- `Client` only supports the "internal" type of [AuthenticatorTransport](https://www.w3.org/TR/webauthn-3/#enum-transport)
- The `Authenticator` currently only supports the ECDSA w/SHA-256 algorithm.

## Contributing and feedback

`passkey-rs` is an [open source project](https://github.com/1Password/passkey-rs).

🐛 If you find an issue you'd like to report, or otherwise have feedback, please [file a new Issue](https://github.com/1Password/passkey-rs/issues/new).

🧑‍💻 If you'd like to contribute to the code please start by filing or commenting on an [Issue](https://github.com/1Password/passkey-rs/issues) so we can track the work.

## Credits

Made with ❤️ and ☕ by the [1Password](https://1password.com/) team.

### Get a free 1Password account for your open source project

Does your team need a secure way to manage passwords and other credentials for your open source project? Head on over to our [other repository](https://github.com/1Password/1password-teams-open-source) to get a 1Password Teams account on us:

✨[1Password for Open Source Projects](https://github.com/1Password/1password-teams-open-source)

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>

[github]: https://img.shields.io/badge/GitHub-1Password%2Fpasskey--rs%2Fpasskey-informational?logo=github&style=flat
[version]: https://img.shields.io/crates/v/passkey?logo=rust&style=flat
[documentation]: https://img.shields.io/docsrs/passkey/latest?logo=docs.rs&style=flat
[webauthn-3]: https://www.w3.org/TR/webauthn-3/
[ctap-2]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
[public-suffix]: https://publicsuffix.org/
[ctap-hid]: https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#usb
