//! Error responses

use crate::utils::repr_enum::CodeOutOfRange;

/// <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#error-responses>
#[derive(Debug, PartialEq, Eq)]
pub enum StatusCode {
    /// Ctap1 or U2F error codes
    Ctap1(U2FError),
    /// CTAP2 error codes
    Ctap2(Ctap2Code),
}

impl From<u8> for StatusCode {
    fn from(value: u8) -> Self {
        // Default to trying Ctap2, otherwise it must be a U2F error
        Ctap2Code::try_from(value)
            .map(Self::from)
            .or_else(|err| U2FError::try_from(err.0).map(Self::from))
            // SAFETY: this unwrap is safe because at this point we have exhausted all values of a byte.
            .unwrap()
    }
}

impl From<StatusCode> for u8 {
    fn from(src: StatusCode) -> Self {
        match src {
            StatusCode::Ctap1(u2f) => u2f.into(),
            StatusCode::Ctap2(ctap2) => ctap2.into(),
        }
    }
}

repr_enum! {
    /// U2F or CTAP1 error variants
    U2FError: u8 {
        /// Indicates successful response.
        Success : 0x00,
        /// The command is not a valid CTAP command.
        InvalidCommand : 0x01,
        /// The command included an invalid parameter.
        InvalidParameter : 0x02,
        /// Invalid message or item length.
        InvalidLength : 0x03,
        /// Invalid message sequencing.
        InvalidSequence : 0x04,
        /// Message timed out.
        Timeout : 0x05,
        /// Channel busy. Client SHOULD retry the request after a short delay. Note that the client MAY
        /// abort the transaction if the command is no longer relevant.
        ChannelBusy : 0x06,
        /// Command requires channel lock.
        LockRequired : 0x0A,
        /// Command not allowed on this cid.
        InvalidChannel : 0x0B,
        /// Other unspecified error.
        Other : 0x7F,
    }
}

impl From<U2FError> for StatusCode {
    fn from(ctap1: U2FError) -> Self {
        StatusCode::Ctap1(ctap1)
    }
}

/// Ctap2 error which may or may not be explicitly defined
#[derive(Debug, PartialEq, Eq)]
pub enum Ctap2Code {
    /// Known error codes
    Known(Ctap2Error),
    /// last spec reserved number 0xDF
    Other(UnknownSpecError),
    /// Range 0xE0..=0xEF
    Extension(ExtensionError),
    /// Range 0xF0..=0xFF
    Vendor(VendorError),
}

impl From<Ctap2Code> for StatusCode {
    fn from(src: Ctap2Code) -> Self {
        Self::Ctap2(src)
    }
}

impl TryFrom<u8> for Ctap2Code {
    type Error = CodeOutOfRange<u8>;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ctap2Error::try_from(value)
            .map(Self::from)
            .or_else(|err| ExtensionError::try_from(err.0).map(Self::from))
            .or_else(|err| VendorError::try_from(err.0).map(Self::from))
            .or_else(|err| UnknownSpecError::try_from(err.0).map(Self::from))
    }
}

impl From<Ctap2Code> for u8 {
    fn from(src: Ctap2Code) -> Self {
        match src {
            Ctap2Code::Known(known) => known.into(),
            Ctap2Code::Other(other) => other.into(),
            Ctap2Code::Extension(extension) => extension.into(),
            Ctap2Code::Vendor(vendor) => vendor.into(),
        }
    }
}

repr_enum! {
    /// Explicitly defined CTAP2 error variants
    Ctap2Error: u8 {
        /// Indicates successful response.
        ///
        /// > Note that this clashes with [`U2FError::Success`] but when deserializing from
        /// > [`StatusCode`] we will default to this one.
        Ok : 0x00,
        /// Invalid/unexpected CBOR error.
        CborUnexpectedType : 0x11,
        /// Error when parsing CBOR.
        InvalidCbor : 0x12,
        /// Missing non-optional parameter.
        MissingParameter : 0x14,
        /// Limit for number of items exceeded.
        LimitExceeded : 0x15,
        /// Fingerprint database is full, e.g. during enrollment.
        FingerprintDatabaseFull : 0x17,
        /// Large blob storage is full. (See [§ 6.10.3 Large, per-credential blobs.][1])
        ///
        /// [1]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#large-blob
        LargeBlobStorageFull : 0x18,
        /// Valid credential found in the exclude list.
        CredentialExcluded : 0x19,
        /// Processing (Lengthy operation is in progress).
        Processing : 0x21,
        /// Credential not valid for the authenticator.
        InvalidCredential : 0x22,
        /// Authentication is waiting for user interaction.
        UserActionPending : 0x23,
        /// Processing, lengthy operation is in progress.
        OperationPending : 0x24,
        /// No request is pending.
        NoOperations : 0x25,
        /// Authenticator does not support requested algorithm.
        UnsupportedAlgorithm : 0x26,
        /// Not authorized for requested operation.
        OperationDenied : 0x27,
        /// Internal key storage is full.
        KeyStoreFull : 0x28,
        /// Unsupported option.
        UnsupportedOption : 0x2B,
        /// Not a valid option for current operation.
        InvalidOption : 0x2C,
        /// Pending keep alive was cancelled.
        KeepAliveCancel : 0x2D,
        /// No valid credentials provided.
        NoCredentials : 0x2E,
        /// A [user action timeout][1] occurred.
        ///
        /// [1]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#user-action-timeout
        UserActionTimeout : 0x2F,
        /// Continuation command, such as, authenticatorGetNextAssertion[^1] not allowed.
        ///
        /// [^1]: Comming soon to an MR near you
        NotAllowed : 0x30,
        /// PIN Invalid.
        PinInvalid : 0x31,
        /// PIN Blocked.
        PinBlocked : 0x32,
        /// PIN authentication,pinUvAuthParam, verification failed.
        PinAuthInvalid : 0x33,
        /// PIN authentication using [pinUvAuthToken] blocked. Requires [power cycle] to reset.
        ///
        /// [pinUvAuthToken]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#puatoken-pinuvauthtoken
        /// [power cycle]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticator-power-up-configuration
        PinAuthBlocked : 0x34,
        /// No PIN has been set.
        PinNotSet : 0x35,
        /// A [pinUvAuthToken] is required for the selected operation. See also the pinUvAuthToken
        /// [option ID].
        ///
        /// [pinUvAuthToken]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#puatoken-pinuvauthtoken
        /// [option ID]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#option-id
        PuatRequired : 0x36,
        /// PIN policy violation. Currently only enforces minimum length.
        PinPolicyViolation : 0x37,
        /// Authenticator cannot handle this request due to memory constraints.
        RequestTooLarge : 0x39,
        /// The current operation has timed out.
        ActionTimeout : 0x3A,
        /// User presence is required for the requested operation.
        UserPresenceRequired : 0x3B,
        /// [Built-in user verification][1] is disabled.
        ///
        /// [1]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#built-in-user-verification-method
        UserVerficationBlocked : 0x3C,
        /// A checksum did not match.
        IntegrityFailure : 0x3D,
        /// The requested subcommand is either invalid or not implemented.
        InvalidSubcommand : 0x3E,
        /// [Built-in user verification][1] unsuccessful. The platform SHOULD retry.
        ///
        /// [1]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#built-in-user-verification-method
        UserVerificationInvalid : 0x3F,
        /// The [permissions] parameter contains an unauthorized permission.
        ///
        /// [permissions]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#perms-param-permissions
        UnauthorizedPermission : 0x40,
    }
}

impl From<Ctap2Error> for Ctap2Code {
    fn from(src: Ctap2Error) -> Self {
        Ctap2Code::Known(src)
    }
}

impl From<Ctap2Error> for StatusCode {
    fn from(src: Ctap2Error) -> Self {
        StatusCode::Ctap2(src.into())
    }
}

/// Error values that are not defined or reserved for future use at the time of writing
#[derive(Debug, PartialEq, Eq)]
pub struct UnknownSpecError(u8);

impl TryFrom<u8> for UnknownSpecError {
    type Error = CodeOutOfRange<u8>;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x07..=0x09
            | 0x0C..=0x10
            | 0x13
            | 0x16
            | 0x1A..=0x20
            | 0x29
            | 0x2A
            | 0x38 // Explicitly marked reserved for future use
            | 0x41..=0x7E
            | 0x80..=0xDF => Ok(UnknownSpecError(value)),
            _ => Err(CodeOutOfRange(value)),
        }
    }
}
impl From<UnknownSpecError> for u8 {
    fn from(src: UnknownSpecError) -> Self {
        src.0
    }
}

impl From<UnknownSpecError> for Ctap2Code {
    fn from(src: UnknownSpecError) -> Self {
        Ctap2Code::Other(src)
    }
}

impl From<UnknownSpecError> for StatusCode {
    fn from(src: UnknownSpecError) -> Self {
        StatusCode::Ctap2(src.into())
    }
}

/// Extension error codes
#[derive(Debug, PartialEq, Eq)]
pub struct ExtensionError(u8);

impl TryFrom<u8> for ExtensionError {
    type Error = CodeOutOfRange<u8>;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0xE0..=0xEF => Ok(Self(value)),
            _ => Err(CodeOutOfRange(value)),
        }
    }
}

impl From<ExtensionError> for u8 {
    fn from(src: ExtensionError) -> Self {
        src.0
    }
}

impl From<ExtensionError> for Ctap2Code {
    fn from(src: ExtensionError) -> Self {
        Ctap2Code::Extension(src)
    }
}

impl From<ExtensionError> for StatusCode {
    fn from(src: ExtensionError) -> Self {
        StatusCode::Ctap2(src.into())
    }
}

/// Vendor specific error codes
#[derive(Debug, PartialEq, Eq)]
pub struct VendorError(u8);

impl TryFrom<u8> for VendorError {
    type Error = CodeOutOfRange<u8>;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0xF0..=0xFF => Ok(Self(value)),
            _ => Err(CodeOutOfRange(value)),
        }
    }
}

impl From<VendorError> for u8 {
    fn from(src: VendorError) -> Self {
        src.0
    }
}

impl From<VendorError> for Ctap2Code {
    fn from(src: VendorError) -> Self {
        Ctap2Code::Vendor(src)
    }
}

impl From<VendorError> for StatusCode {
    fn from(src: VendorError) -> Self {
        StatusCode::Ctap2(src.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::ctap2::error::{ExtensionError, U2FError, UnknownSpecError, VendorError};

    use super::{Ctap2Error, StatusCode};

    #[test]
    fn from_byte_conversions() {
        // Assert success defaults to ctap2
        let success = StatusCode::from(0x00);
        assert_eq!(success, Ctap2Error::Ok.into());

        let invalid_len = StatusCode::from(0x03);
        assert_eq!(invalid_len, U2FError::InvalidLength.into());

        let unsupported_alg = StatusCode::from(0x26);
        assert_eq!(unsupported_alg, Ctap2Error::UnsupportedAlgorithm.into());

        let unknown = StatusCode::from(0x1B);
        assert_eq!(unknown, UnknownSpecError(0x1B).into());

        let first_extension_err = StatusCode::from(0xE0);
        assert_eq!(first_extension_err, ExtensionError(0xE0).into());
        let last_extension_err = StatusCode::from(0xEF);
        assert_eq!(last_extension_err, ExtensionError(0xEF).into());

        let first_vendor_err = StatusCode::from(0xF0);
        assert_eq!(first_vendor_err, VendorError(0xF0).into());
        let last_vendor_err = StatusCode::from(0xFF);
        assert_eq!(last_vendor_err, VendorError(0xFF).into());
    }

    #[test]
    fn all_byte_values() {
        // iterate through all byte values, it should not panic. Iterating through 256 cases should
        // be fairly quick
        for i in u8::MIN..=u8::MAX {
            let _code = StatusCode::from(i);
        }
    }
}
