//! The authenticator extensions as defined in [CTAP2 Defined Extensions][ctap2] or in
//! [WebAuthn Defined Extensions][webauthn].
//!
//! The currently supported extensions are:
//! * [`HmacSecret`][HmacSecretConfig]
//! * [AuthenticatorDisplayName]
//!
//! [ctap2]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-defined-extensions
//! [webauthn]: https://w3c.github.io/webauthn/#sctn-defined-extensions
//! [AuthenticatorDisplayName]: https://w3c.github.io/webauthn/#dom-credentialpropertiesoutput-authenticatordisplayname

use passkey_types::ctap2;

mod hmac_secret;
pub use hmac_secret::{HmacSecretConfig, HmacSecretCredentialSupport};

#[cfg(docs)]
use passkey_types::webauthn;

#[derive(Debug, Default)]
#[non_exhaustive]
pub(super) struct Extensions {
    /// The display name given when a [`webauthn::CredentialPropertiesOutput`] is requested
    pub display_name: Option<String>,

    /// Extension to retrieve a symmetric secret from the authenticator.
    pub hmac_secret: Option<HmacSecretConfig>,
}

impl Extensions {
    /// Get a list of extensions that are currently supported by this instance.
    pub fn list_extensions(&self) -> Option<Vec<ctap2::get_info::Extension>> {
        // We don't support Pin UV auth yet so we will only support the unsigned prf extension
        let prf = self
            .hmac_secret
            .is_some()
            .then_some(ctap2::get_info::Extension::Prf);

        prf.map(|ext| vec![ext])
    }
}
