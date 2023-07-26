//! U2F Authenticator API
mod authenticate;
mod commands;
mod register;
mod version;

pub use {authenticate::*, commands::*, register::*, version::*};

/// ISO 7816-4 Status Words (`SW_*`)
///
/// Values are taken from <https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#h3_status-codes>
#[repr(u16)]
#[derive(Debug)]
pub enum ResponseStatusWords {
    /// The command completed successfully without error
    NoError = 0x9000,
    /// The request was rejected due to test-of-user-presence being required.
    ConditionsNotSatisfied = 0x6985,
    /// The request was rejected due to an invalid key handle.
    WrongData = 0x6A80,
    /// The length of the request was invalid.
    WrongLength = 0x6700,
    /// The Class byte of the request is not supported. (i.e. CLA != 0)
    ClaNotSupported = 0x6E00,
    /// The Instruction of the request is not supported.
    InsNotSupported = 0x6D00,
}

impl From<ResponseStatusWords> for u16 {
    #[allow(clippy::as_conversions)]
    fn from(sw: ResponseStatusWords) -> Self {
        sw as u16
    }
}

impl ResponseStatusWords {
    /// Transform a `ResponseStatusWords` to a `u16` as postfix without needing to specify the type.
    pub fn as_primitive(self) -> u16 {
        self.into()
    }
}
