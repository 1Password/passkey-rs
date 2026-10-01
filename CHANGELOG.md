# Changelog

## Unreleased

### passkey-crypto v0.1.1

- Remove the `wasm_js` feature automatically being enabled for wasm builds.
  Enable the `js` feature if you need it in your dependency tree. ([#126](https://github.com/1Password/passkey-rs/pull/126))

## Passkey v0.6.0

* Re-export `passkey-crypto` as `passkey::crypto` ([#91](https://github.com/1Password/passkey-rs/pull/91))
* Add `linux` feature flag enabling the Linux HIDRAW authenticator and client ([#99](https://github.com/1Password/passkey-rs/pull/99))
* Add `windows` feature flag enabling the Windows WebAuthn client ([#111](https://github.com/1Password/passkey-rs/pull/111))
* Add `rust-crypto` and `aws-lc-rs` feature flags to select the crypto backend ([#117](https://github.com/1Password/passkey-rs/pull/117))

### passkey-authenticator 0.6.0

- ⚠ BREAKING: Added new generic parameter to Authenticator for the crypto backend ([#91](https://github.com/1Password/passkey-rs/pull/91))
  - Which the `Authenticator::new` constructor now has a new crypto backend parameter.
- ⚠ BREAKING: Replace the `private_key_from_cose_key` and `public_key_der_from_cose_key` functions with methods on `passkey-crypto` traits ([#91](https://github.com/1Password/passkey-rs/pull/91))
- ⚠ BREAKING: `CoseKeyPair::from_secret_key` now takes a generic `SecretKeyT` and no longer takes an `Algorithm` ([#91](https://github.com/1Password/passkey-rs/pull/91))
- ⚠ BREAKING: `CredentialIdLength::randomized` now uses a generic `RngBackend` instead of taking a `rand::Rng` ([#91](https://github.com/1Password/passkey-rs/pull/91))
- Add `linux` module with a `LinuxAuthenticator` for USB CTAP2 hardware authenticators ([#99](https://github.com/1Password/passkey-rs/pull/99))
- ⚠ BREAKING: Remove U2F support ([#105](https://github.com/1Password/passkey-rs/pull/105))
- Add a builder method on Authenticator to set supported algorithms ([#116](https://github.com/1Password/passkey-rs/pull/116))

### passkey-client v0.6.0

- ⚠ BREAKING: Added new generic parameter to Client for the crypto backend ([#91](https://github.com/1Password/passkey-rs/pull/91))
- Fix RP ID validation to require dot boundary ([#92](https://github.com/1Password/passkey-rs/pull/92))
- ⚠ BREAKING: `WebauthnError` is now `#[non_exhaustive]` and has a new `TimeoutError` variant ([#94](https://github.com/1Password/passkey-rs/pull/94))
- `Client::register` and `Client::authenticate` now respect request timeouts when the `tokio` feature is enabled ([#94](https://github.com/1Password/passkey-rs/pull/94))
- Add `Client::user_verification_when_preferred` builder to control `uv` when the RP asks for `Preferred` ([#96](https://github.com/1Password/passkey-rs/pull/96))
- Add `linux` module with a client for external hardware authenticators ([#99](https://github.com/1Password/passkey-rs/pull/99))
- Client now verifies credential ID length during credential registration ([#100](https://github.com/1Password/passkey-rs/pull/100))
- An empty client data hash now falls back to hashing the client data JSON ([#107](https://github.com/1Password/passkey-rs/pull/107))
- ⚠ BREAKING: `WebauthnError::ValidationError` is now a struct variant with a `context` field ([#111](https://github.com/1Password/passkey-rs/pull/111))
- Add `windows` module with a `WindowsClient` backed by the Windows WebAuthn API ([#111](https://github.com/1Password/passkey-rs/pull/111))

### passkey-crypto v0.1.0

A new crate! This crate houses the swappable cryptographic backends for different libraries should you
wish/need to use a different set of libraries than the default RustCrypto libraries. As always PRs are
accepted to add new backends should you wish to not use plenty of newtypes to get around the orphan
rules.

- New `RngBackend` trait which replaces the pre-existing `passkey-types::rand::random_vec` function.
  Use this new method as `passkey-crypto::rng::Rng::random_vec`.
- Supports 2 cryptography backends: 
  - RustCrypto ecosystem as the default choice
  - Awc-lc-rs as an alternative choice
- Adds support for Ed25519 and ML-DSA passkeys

### passkey-transports v0.2.0

- Add a Linux-only `hidraw` module for talking to USB CTAP2 authenticators ([#99](https://github.com/1Password/passkey-rs/pull/99))
- ⚠ BREAKING: Remove `hid::Command::Msg` variant as that is U2F only and U2F support is now being removed.
  ([#105](https://github.com/1Password/passkey-rs/pull/105))

### passkey-types v0.6.0

- ⚠ BREAKING: The `passkey-types::rand` module no longer exists and is instead replaced by `passkey-crypto::rng` ([#91](https://github.com/1Password/passkey-rs/pull/91))
- `Ctap2Error` and `StatusCode` now implement `From<CoseKeyConversionError>` ([#91](https://github.com/1Password/passkey-rs/pull/91))
- ⚠ BREAKING: Remove the `CoseKey` re-export, which now comes from `passkey-crypto` ([#91](https://github.com/1Password/passkey-rs/pull/91))
- ⚠ BREAKING: `Passkey::mock` now takes a `CryptoBackend`, and `PasskeyBuilder` is now generic over it ([#91](https://github.com/1Password/passkey-rs/pull/91), [#121](https://github.com/1Password/passkey-rs/pull/121))
- `PublicKeyCredentialParameters` now accepts a stringified `alg` and skips unknown algorithms without failing ([#96](https://github.com/1Password/passkey-rs/pull/96))
- `CredentialExtensions` now derives `Debug` ([#96](https://github.com/1Password/passkey-rs/pull/96))
- ⚠ BREAKING: `get_assertion::Options` is now its own type without `rk`, instead of re-exporting `make_credential::Options` ([#99](https://github.com/1Password/passkey-rs/pull/99))
- ⚠ BREAKING: `get_assertion::Response::user` now uses `ctap2::make_credential::PublicKeyCredentialUserEntity`, whose fields are optional ([#99](https://github.com/1Password/passkey-rs/pull/99))
- ⚠ BREAKING: The CTAP2 `PublicKeyCredentialUserEntity` now serializes as camelCase, with `icon_url` renamed to `icon` on the wire ([#99](https://github.com/1Password/passkey-rs/pull/99))
- Add a `Ctap2Command` enum ([#99](https://github.com/1Password/passkey-rs/pull/99))
- `PublicKeyCredentialDescriptor` now derives `Clone` ([#99](https://github.com/1Password/passkey-rs/pull/99))
- `make_credential::Options::up` is no longer serialized when false ([#99](https://github.com/1Password/passkey-rs/pull/99))
- ⚠ BREAKING: Remove U2F support ([#105](https://github.com/1Password/passkey-rs/pull/105))
- ⚠ BREAKING: Migrate `U2FError` variant into `Ctap2Error`, rename `Ctap2Code` to `StatusCode` ([#105](https://github.com/1Password/passkey-rs/pull/105))
  and finaly remove the old `StatusCode`. ([#105](https://github.com/1Password/passkey-rs/pull/105))
- ⚠ BREAKING: Remove the `crypto` module (`sha256`/`hmac_sha256`) in favour of `passkey-crypto::hash::Sha256Backend` ([#109](https://github.com/1Password/passkey-rs/pull/109))
- ⚠ BREAKING: `AuthenticatorData::new` now takes a `CryptoBackend` argument ([#109](https://github.com/1Password/passkey-rs/pull/109))

## Passkey v0.5.0

- Migrate project to Rust 2024 edition

### passkey-authenticator v0.5.0

- Ignore the deprecated `rk` option in requests (#67)
- ⚠ BREAKING: Add `user_handle` as an optional parameter in `CredentialStore::find_credentials`
  to allow filtering on `user_handle`. (#67)
- Stop returning an error when we find credentials in the `exclude_credentials` list.
  This allows for updating/replacing credentials should the user so wish. (#67)
- Fix hmac-secret logic around the second salt (#67)
- ⚠ BREAKING: Fix Ctap2Api trait to correctly call the concrete method to prevent recursion (#67)
- ⚠ BREAKING: The `UserValidationMethod` trait has been updated to use `UiHint`
  to give the implementation more information about the request, which can be used
  to decide whether additional validations are needed. To reflect this, the
  `UserValidationMethod` trait now also returns which validations were performed. (#76)
- ⚠ BREAKING: Change the `CredentialStore` and `UserValidationMethod` associated type constraint
  to a new `PasskeyAccessor` trait instead of the `TryInto<Passkey>`, making it possible to use a
  custom passkey representation type that goes throughout the entire flow without losing any
  additional information through a conversion. (#87)
- ⚠ BREAKING: The `Ctap2Api::get_info` method now returns a boxed response due to the size of
  the response. (#88)


### passkey-client v0.5.0

- ⚠ BREAKING: Add support for RelatedOrigins to the RpIdVerifier through a generic fetcher (#67)

### passkey-types v0.5.0

- Make output types Hashable in Swift code gen (#67)
- Support stringified booleans in webauthn requests (#67)
- Be more tolerant to failed deserialization of optional vectors (#67)
- ⚠ BREAKING: Add `username` and `user_display_name` to the `Passkey` type and its mock builder. (#87)
- Update CTAP2 types to ignore unknown values during deserialization,
  just like their WebAuthn equivalents. (#88)
- ⚠ BREAKING: Update `ctap2::get_info::Response` to have all the fields from ctap 2.2 (#88)

## Passkey v0.4.0
### passkey-authenticator v0.4.0

- Added: support for controlling generated credential's ID length to Authenticator ([#49](https://github.com/1Password/passkey-rs/pull/49))
- ⚠ BREAKING: Removal of `Authenticator::set_display_name` and `Authenticator::display_name` methods ([#51](https://github.com/1Password/passkey-rs/pull/51))

### passkey-client v0.4.0
- ⚠ BREAKING: Update android asset link verification ([#51](https://github.com/1Password/passkey-rs/pull/51))
  - Change `asset_link_url` parameter in `UnverifiedAssetLink::new` to be required rather than optional.
  - Remove internal string in `ValidationError::InvalidAssetLinkUrl` variant.
- Remove special casing of responses for specific RPs ([#51](https://github.com/1Password/passkey-rs/pull/51))
- Added `RpIdValidator::is_valid_rp_id` to verify that an rp_id is valid to be used as such ([#51](https://github.com/1Password/passkey-rs/pull/51))

### passkey-types v0.4.0
- ⚠ BREAKING: Removal of `CredentialPropertiesOutput::authenticator_display_name` ([#51](https://github.com/1Password/passkey-rs/pull/51))


## Passkey v0.3.0
### passkey-authenticator v0.3.0

- Added: support for signature counters
	- ⚠ BREAKING: Add `update_credential` function to `CredentialStore` ([#23](https://github.com/1Password/passkey-rs/pull/23)).
	- Add `make_credentials_with_signature_counter` to `Authenticator`.
- ⚠ BREAKING: Merge functions in `UserValidationMethod` ([#24](https://github.com/1Password/passkey-rs/pull/24))
	- Removed: `UserValidationMethod::check_user_presence`
	- Removed: `UserValidationMethod::check_user_verification`
	- Added: `UserValidationMethod::check_user`. This function now performs both user presence and user verification checks.
		The function now also returns which validations were performed, even if they were not requested.
- Added: Support for discoverable credentials
	- ⚠ BREAKING: Added: `CredentialStore::get_info` which returns `StoreInfo` containing `DiscoverabilitySupport`.
	- ⚠ BREAKING: Changed: `CredentialStore::save_credential` now also takes `Options`.
	- Changed: `Authenticator::make_credentials` now returns an error if a discoverable credential was requested but not supported by the store.

### passkey-client v0.3.0

- Changed: The `Client` no longer hardcodes the UV value sent to the `Authenticator` ([#22](https://github.com/1Password/passkey-rs/pull/22)).
- Changed: The `Client` no longer hardcodes the RK value sent to the `Authenticator` ([#27](https://github.com/1Password/passkey-rs/pull/27)).
- The client now supports additional user-defined properties in the client data, while also clarifying how the client
handles client data and its hash.
	- ⚠ BREAKING: Changed: `register` and `authenticate` take `ClientData<E>` instead of `Option<Vec<u8>>`.
	- ⚠ BREAKING: Changed: Custom client data hashes are now specified using `DefaultClientDataWithCustomHash(Vec<u8>)` instead of
		`Some(Vec<u8>)`.
	- Added: Additional fields can be added to the client data using `DefaultClientDataWithExtra(ExtraData)`.
- Added: The `Client` now has the ability to adjust the response for quirky relying parties
	when a fully featured response would break their server side validation. ([#31](https://github.com/1Password/passkey-rs/pull/31))
- ⚠ BREAKING: Added the `Origin` enum which is now the origin parameter for the following methods ([#32](https://github.com/1Password/passkey-rs/pull/27)):
	- `Client::register` takes an `impl Into<Origin>` instead of a `&Url`
	- `Client::authenticate` takes an `impl Into<Origin>` instead of a `&Url`
	- `RpIdValidator::assert_domain` takes an `&Origin` instead of a `&Url`
- ⚠ BREAKING: The collected client data will now have the android app signature as the origin when a request comes from an app directly. ([#32](https://github.com/1Password/passkey-rs/pull/27))

## passkey-types v0.3.0

- `CollectedClientData` is now generic and supports additional strongly typed fields. ([#28](https://github.com/1Password/passkey-rs/pull/28))
	- Changed: `CollectedClientData` has changed to `CollectedClientData<E = ()>`
- The `Client` now returns `CredProps::rk` depending on the authenticator's capabilities. ([#29](https://github.com/1Password/passkey-rs/pull/29))
- ⚠ BREAKING: Rename webauthn extension outputs to be consistent with inputs. ([#33](https://github.com/1Password/passkey-rs/pull/33))
- ⚠ BREAKING: Create new extension inputs for the CTAP authenticator inputs. ([#33](https://github.com/1Password/passkey-rs/pull/33))
- ⚠ BREAKING: Add unsigned extension outputs for the CTAP authenticator outputs. ([#34](https://github.com/1Password/passkey-rs/pull/33))
- ⚠ BREAKING: Add ability for `Passkey` to store associated extension data. ([#36](https://github.com/1Password/passkey-rs/pull/36))
- ⚠ BREAKING: Change version and extension information in `ctap2::get_info` from strings to enums. ([#39](https://github.com/1Password/passkey-rs/pull/39))
- ⚠ BREAKING: Add missing CTAP2.1 fields to `make_credential::Response` and `get_assertion::Response`. ([#39](https://github.com/1Password/passkey-rs/pull/39))
- Make the `PublicKeyCredential` outputs equatable in swift. ([#39](https://github.com/1Password/passkey-rs/pull/39))

## Passkey v0.2.0
### passkey-types v0.2.0

Most of these changes are adding fields to structs which are breaking changes due to the current lack of builder methods for these types. Due to this, additions of fields to structs or variants to enums won't be marked as breaking in this release's notes. Other types of breaking changes will be explicitly called out.

- ⚠ BREAKING: Update `bitflags` from v1 to v2. This means `ctap2::Flags` no longer implement `PartialOrd`, `Ord` and `Hash` as those traits aren't applicable.
- Added a `transports` field to `ctap2::get_info::Response`
- Changes in `webauthn::PublicKeyCredential`:
	- ⚠ BREAKING: `authenticator_attachment` is now optional
	- ⚠ BREAKING: `client_extension_results`'s type has been renamed from `AuthenticationExtensionsClientOutputs` to `AuthenticatorExtensionsClientOutputs`
- Changes for `webauthn::PublicKeyCredentialRequestOptions`:
	- `timeout` now supports deserializing from a stringified number
	- `user_verification` will now ignore unknown values instead of returning an error on deserialization
	- Add `hints` field (#9)
	- Add `attestation` and `attestation_formats` fields
- Changes for `webauthn::AuthenticatorAssertionResponse`
	- Add `attestation_object` field
- Changes for `webauthn::PublicKeyCredentialCreationOptions`:
	- `timeout` now supports deserializing from a stringified number
	- Add `hints` field (#9)
	- Add `attestation_formats` field
- Fix `webauthn::CollectedClientData` JSON serialization to correctly follow the spec. (#6)
	- Add `unknown_keys` field
	- Always serializes `cross_origin` with a boolean even if it is set to `None`
	- ⚠ BREAKING: Remove from `#[typeshare]` generation as `#[serde(flatten)]` on `unknown_keys` is not supported.
- Add `webauthn::ClientDataType::PaymentGet` variant.
- Make all enums with unit variants `Clone`, `Copy`, `PartialEq` and `Eq`
- Add support for the `CredProps` extension with `authenticatorDisplayName`

### passkey-authenticator v0.2.0

- Add `Authenticator::transports(Vec<AuthenticatorTransport>)` builder method for customizing the transports during credential creation. The default is `internal` and `hybrid`.
- Add `Authenticator:{set_display_name, display_name}` methods for setting a display name for the `CredProps` extension's `authenticatorDisplayName`.
- Update `p256` to version `0.13`
- Update `signature` to version `2`

### passkey-client v0.2.0

- Add `WebauthnError::is_vendor_error()` for verifying if the internal CTAP error was in the range of `passkey_types::ctap2::VendorError`
- Break out Rp Id verification from the `Client` into its own `RpIdVerifier` which it now uses internally. This allows the use of `RpIdVerifier::assert_domain` publicly now instead of it being a private method to client without the need for everything else the client needs.
- `Client::register` now handles `CredProps` extension requests.
- Update `idna` to version `0.5`

### public-suffix v0.1.1

- Update the public suffix list
