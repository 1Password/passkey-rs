use std::array::TryFromSliceError;

use super::ResponseStatusWords;

/// Request payload to register a new user
#[derive(Debug)]
pub struct RegisterRequest {
    /// SHA256 hash challenge issued by the relying party
    pub challenge: [u8; 32],
    /// SHA256 of the application identity
    pub application: [u8; 32],
}

impl TryFrom<&[u8]> for RegisterRequest {
    type Error = TryFromSliceError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            challenge: data[..32].try_into()?,
            application: data[32..].try_into()?,
        })
    }
}

/// Register response payload
///
/// This message is output by the U2F token once it created a new keypair in response to the
/// registration request message. Note that U2F tokens SHOULD verify user presence before returning
/// a registration response success message (otherwise they SHOULD return a
/// test-of-user-presence-required message - see above).
pub struct RegisterResponse {
    // Reserved byte, value 0x05 which is added in the `encode` method
    /// This is the (uncompressed) x,y-representation of a curve point on the P-256 NIST elliptic
    /// curve. User's new public key
    pub public_key: PublicKey,

    // Key handle length byte which specifies the length of the key handle (see below). The value is
    // unsigned (range 0-255)
    /// This a handle that allows the U2F token to identify the generated key pair. U2F tokens MAY
    /// wrap the generated private key and the application id it was generated for, and output that
    /// as the key handle.
    pub key_handle: Vec<u8>,

    /// This is a certificate in X.509 DER format. Parsing of the X.509 certificate unambiguously
    /// establishes its ending.
    pub attestation_certificate: Vec<u8>,

    /// This is a ECDSA signature (on P-256) over the following byte string:
    /// 1. A byte reserved for future use [1 byte] with the value 0x00.
    /// 2. The application parameter [32 bytes] from the registration request message.
    /// 3. The challenge parameter [32 bytes] from the registration request message.
    /// 4. The above key handle [variable length]. (Note that the key handle length is not included in the signature base string.
    ///    This doesn't cause confusion in the signature base string, since all other parameters in the signature base string are fixed-length.)
    /// 5. The above user public key [65 bytes].
    pub signature: Vec<u8>,
}

/// U2F public key is the concatenation of `0x04 | x | y` where `0x04` signifies ecc uncompressed.
#[derive(Clone, Copy)]
pub struct PublicKey {
    // magic 0x04 byte which is added in the `encode` method
    /// X coordinate of the ECC public key
    pub x: [u8; 32],
    /// Y coordinate of the ECC public key
    pub y: [u8; 32],
}

impl RegisterResponse {
    /// Encode the Response to it's binary format for a successfull response
    #[allow(clippy::as_conversions)]
    pub fn encode(self) -> Vec<u8> {
        [0x05] // Reserved magic byte
            .into_iter()
            .chain(self.public_key.encode())
            .chain([self.key_handle.len() as u8])
            .chain(self.key_handle)
            .chain(self.attestation_certificate)
            .chain(self.signature)
            .chain(ResponseStatusWords::NoError.as_primitive().to_be_bytes()) // NoError indicates success
            .collect()
    }
}

impl PublicKey {
    /// Encode a Public key into an iterator
    pub fn encode(self) -> impl Iterator<Item = u8> {
        [0x04].into_iter().chain(self.x).chain(self.y)
    }
}
