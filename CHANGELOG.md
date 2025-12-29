# Changelog

## Unreleased

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
