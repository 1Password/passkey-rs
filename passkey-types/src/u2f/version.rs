use super::ResponseStatusWords;

/// The u2f version representation
pub struct Version;

impl Version {
    /// Encode this version into its byte representation.
    pub fn encode(self) -> Vec<u8> {
        b"U2F_V2"
            .iter()
            .copied()
            .chain(ResponseStatusWords::NoError.as_primitive().to_be_bytes())
            .collect()
    }
}
