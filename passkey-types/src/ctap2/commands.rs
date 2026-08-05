/// Authenticator commands enumerated by the CTAP 2 specification.
#[repr(u8)]
pub enum Ctap2Command {
    /// CTAP_CMD_MAKE_CREDENTIAL
    MakeCredential = 0x01,
    /// CTAP_CMD_GET_ASSERTION
    GetAssertion = 0x02,
    /// CTAP_CMD_GET_INFO
    GetInfo = 0x04,
}

impl From<Ctap2Command> for u8 {
    #[expect(clippy::as_conversions)]
    fn from(value: Ctap2Command) -> Self {
        value as u8
    }
}
