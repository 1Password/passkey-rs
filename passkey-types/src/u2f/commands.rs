use super::{authenticate::AuthenticationRequest, register::RegisterRequest, ResponseStatusWords};

/// U2F command, determined at the INS position,
///
/// Anything between the values `0x40-0xbf` are vendor specific and therefore unsupported.
///
/// This Enum does not `#[repr(u8)]` with discriminant values since we cannot currently have tuple
/// variants in those enums until <https://github.com/rust-lang/rust/issues/60553> stabilizes.
#[derive(Debug)]
pub enum Command {
    /// Value of `0x01` with parameters of `P1 = 0x00`, `P2 = 0x00`
    Register,
    /// Value of `0x02` with parameters of `P1 = 0x03|0x07|0x08`, `P2 = 0x00`
    Authenticate,
    /// Value of `0x03` with parameters of `P1 = 0x00`, `P2 = 0x00`
    Version,
    /// Unsupported command value
    Unsuported(u8),
}

impl From<Command> for u8 {
    fn from(src: Command) -> Self {
        match src {
            Command::Register => 0x01,
            Command::Authenticate => 0x02,
            Command::Version => 0x03,
            Command::Unsuported(cmd) => cmd,
        }
    }
}

impl From<u8> for Command {
    fn from(src: u8) -> Self {
        match src {
            0x01 => Command::Register,
            0x02 => Command::Authenticate,
            0x03 => Command::Version,
            cmd => Command::Unsuported(cmd),
        }
    }
}

/// Data payload of a U2F Request
#[derive(Debug)]
pub enum RequestPayload {
    /// Register command payload
    Register(RegisterRequest),
    /// Authentication command payload
    Authenticate(AuthenticationRequest),
    /// Version command payload
    Version,
}

/// U2F request frame
#[derive(Debug)]
pub struct Request {
    /// Must be of value 0
    pub cla: u8,
    /// Command byte
    pub ins: Command,
    /// Parameter byte, only used during authentication
    pub p1: u8,
    /// Length of the data payload
    pub data_len: usize,
    /// Data payload
    pub data: RequestPayload,
}

const REQUEST_HEADER_LEN: usize = 6;

impl TryFrom<&[u8]> for Request {
    type Error = ResponseStatusWords;

    #[allow(clippy::as_conversions)]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < REQUEST_HEADER_LEN {
            return Err(ResponseStatusWords::WrongLength);
        }

        let cla = value[0];
        if cla != 0 {
            return Err(ResponseStatusWords::WrongData);
        }
        let ins = Command::from(value[1]);
        let p1 = value[2];
        let data_start = REQUEST_HEADER_LEN + 1;
        // SAFETY: This unwrap is safe since 3..7 gives 4 bytes which is a safe conversion to an
        // array of len 4. Technically the first of these bytes is `p2` the second parameter,
        // but in the base U2F spec this will always be 0. So this length is safe.
        let data_len = u32::from_be_bytes(value[3..data_start].try_into().unwrap()) as usize;
        let data_end = data_start + data_len;
        let payload = &value[data_start..data_end];

        let data = match ins {
            Command::Register => RequestPayload::Register(
                payload
                    .try_into()
                    // Wrong length because it must be two SHA256's which are 32 bytes each
                    .map_err(|_| ResponseStatusWords::WrongLength)?,
            ),
            Command::Authenticate => RequestPayload::Authenticate(
                AuthenticationRequest::try_from(payload, p1)
                    .map_err(|_| ResponseStatusWords::WrongLength)?,
            ),
            Command::Version => RequestPayload::Version,
            Command::Unsuported(_) => return Err(ResponseStatusWords::InsNotSupported),
        };

        Ok(Request {
            cla,
            ins,
            p1,
            data_len,
            data,
        })
    }
}
