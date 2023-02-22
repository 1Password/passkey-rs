use bitflags::bitflags;

bitflags! {
    /// Flags for authenticator Data
    ///
    /// <https://w3c.github.io/webauthn/#authdata-flags>
    #[repr(transparent)]
    pub struct Flags: u8 {
        /// User Present, bit 0
        const UP = 1 << 0;
        /// User Verified, bit 2
        const UV = 1 << 2;
        /// Backup Eligibility, bit 3
        const BE = 1 << 3;
        /// Backup state, bit 4
        const BS = 1 << 4;
        /// Attested Credential Data, bit 6
        const AT = 1 << 6;
        /// Extension Data Included, bit 7
        const ED = 1 << 7;
    }
}

/// Flags for 1Password will always verify the User's presence and will always be backed up.
impl Default for Flags {
    fn default() -> Self {
        Flags::UP | Flags::UV | Flags::BE | Flags::BS
    }
}

impl From<Flags> for u8 {
    fn from(src: Flags) -> Self {
        src.bits
    }
}

impl TryFrom<u8> for Flags {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Flags::from_bits(value).ok_or(())
    }
}
