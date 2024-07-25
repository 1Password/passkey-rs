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

use passkey_types::{
    ctap2::{get_assertion, get_info, make_credential, StatusCode},
    Passkey,
};

mod hmac_secret;
pub use hmac_secret::{HmacSecretConfig, HmacSecretCredentialSupport};

#[cfg(test)]
pub(crate) use hmac_secret::tests::prf_eval_request;

#[cfg(doc)]
use passkey_types::webauthn;

use crate::Authenticator;

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
    pub fn list_extensions(&self) -> Option<Vec<get_info::Extension>> {
        // We don't support Pin UV auth yet so we will only support the unsigned prf extension
        let prf = self
            .hmac_secret
            .is_some()
            .then_some(get_info::Extension::Prf);

        prf.map(|ext| vec![ext])
    }
}

pub(super) struct MakeExtensionOutputs {
    pub signed: Option<make_credential::SignedExtensionOutputs>,
    pub unsigned: Option<make_credential::UnsignedExtensionOutputs>,
    pub credential: passkey_types::CredentialExtensions,
}

#[derive(Default)]
pub(super) struct GetExtensionOutputs {
    pub signed: Option<get_assertion::SignedExtensionOutputs>,
    pub unsigned: Option<get_assertion::UnsignedExtensionOutputs>,
}

impl<S, U> Authenticator<S, U> {
    pub(super) fn make_extensions(
        &self,
        request: Option<make_credential::ExtensionInputs>,
        uv: bool,
    ) -> Result<MakeExtensionOutputs, StatusCode> {
        let request = request.and_then(|r| r.zip_contents());
        let pk_extensions = self.make_passkey_extensions(request.as_ref());

        let prf = request
            .and_then(|ext| {
                ext.prf.and_then(|input| {
                    self.make_prf(pk_extensions.hmac_secret.as_ref(), input, uv)
                        .transpose()
                })
            })
            .transpose()?;

        Ok(MakeExtensionOutputs {
            signed: None,
            unsigned: make_credential::UnsignedExtensionOutputs { prf }.zip_contents(),
            credential: pk_extensions,
        })
    }

    fn make_passkey_extensions(
        &self,
        request: Option<&make_credential::ExtensionInputs>,
    ) -> passkey_types::CredentialExtensions {
        let should_build_hmac_secret =
            request.and_then(|r| r.hmac_secret.or(Some(r.prf.is_some())));
        let hmac_secret = self.make_hmac_secret(should_build_hmac_secret);

        passkey_types::CredentialExtensions { hmac_secret }
    }

    pub(super) fn get_extensions(
        &self,
        passkey: &Passkey,
        request: Option<get_assertion::ExtensionInputs>,
        uv: bool,
    ) -> Result<GetExtensionOutputs, StatusCode> {
        let Some(ext) = request.and_then(get_assertion::ExtensionInputs::zip_contents) else {
            return Ok(Default::default());
        };

        let prf = ext
            .prf
            .and_then(|salts| {
                self.get_prf(
                    &passkey.credential_id,
                    passkey.extensions.hmac_secret.as_ref(),
                    salts,
                    uv,
                )
                .transpose()
            })
            .transpose()?;

        Ok(GetExtensionOutputs {
            signed: None,
            unsigned: get_assertion::UnsignedExtensionOutputs { prf }.zip_contents(),
        })
    }
}
