# Changelog

## Unreleased

### passkey-authenticator

- Added: support for signature counters
	- ⚠ BREAKING: Add `update_credential` function to `CredentialStore` ([#23](https://github.com/1Password/passkey-rs/pull/23)).
	- Add `make_credentials_with_signature_counter` to `Authenticator`.
- ⚠ BREAKING: Merge functions in `UserValidationMethod` ([#24](https://github.com/1Password/passkey-rs/pull/24))
	- Removed: `UserValidationMethod::check_user_presence`
	- Removed: `UserValidationMethod::check_user_verification`
	- Added: `UserValidationMethod::check_user`. This function now performs both user presence and user verification checks.
		The function now also returns which validations were performed, even if they were not requested.

### passkey-client

- Changed: The `Client` no longer hardcodes the UV value sent to the `Authenticator` ([#22](https://github.com/1Password/passkey-rs/pull/22)).

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