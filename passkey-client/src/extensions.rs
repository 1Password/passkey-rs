//! WebAuthn extensions as defined in [WebAuthn Defined Extensions][webauthn]
//! and [CTAP2 Defined Extensions][ctap2].
//!
//! The currently supported extensions are:
//! * [`Credential Properties`][credprops]
//! * [`Pseudo-random function`][prf]
//!
//! [ctap2]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-defined-extensions
//! [webauthn]: https://w3c.github.io/webauthn/#sctn-defined-extensions
//! [credprops]: https://w3c.github.io/webauthn/#sctn-authenticator-credential-properties-extension
//! [prf]: https://w3c.github.io/webauthn/#prf-extension

use passkey_authenticator::{CredentialStore, UserValidationMethod};
use passkey_types::{
    ctap2::{get_assertion, get_info, make_credential},
    webauthn::{
        AuthenticationExtensionsClientInputs, AuthenticationExtensionsClientOutputs,
        CredentialPropertiesOutput, PublicKeyCredentialRequestOptions,
    },
    Passkey,
};

use crate::{Client, WebauthnError};

mod prf;

impl<S, U, P> Client<S, U, P>
where
    S: CredentialStore + Sync,
    U: UserValidationMethod + Sync,
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
    Passkey: TryFrom<<S as CredentialStore>::PasskeyItem>,
{
    /// Create the extension inputs to be passed to an authenticator over CTAP2
    /// during a registration request.
    pub(super) fn registration_extension_ctap2_input(
        &self,
        request: Option<&AuthenticationExtensionsClientInputs>,
        supported_extensions: &[get_info::Extension],
    ) -> Result<Option<make_credential::ExtensionInputs>, WebauthnError> {
        prf::registration_prf_to_ctap2_input(request, supported_extensions)
    }

    /// Build the extension outputs for the WebAuthn client in a registration request.
    pub(super) fn registration_extension_outputs(
        &self,
        request: Option<&AuthenticationExtensionsClientInputs>,
        rk: bool,
    ) -> AuthenticationExtensionsClientOutputs {
        let cred_props = if let Some(true) = request.and_then(|ext| ext.cred_props) {
            Some(CredentialPropertiesOutput {
                discoverable: Some(rk),
                authenticator_display_name: self.authenticator.display_name().cloned(),
            })
        } else {
            None
        };

        AuthenticationExtensionsClientOutputs {
            cred_props,
            prf: None,
        }
    }

    /// Create the extension inputs to be passed to an authenticator over CTAP2
    /// during an authentication request.
    pub(super) fn auth_extension_ctap2_input(
        &self,
        request: &PublicKeyCredentialRequestOptions,
        supported_extensions: &[get_info::Extension],
    ) -> Result<Option<get_assertion::ExtensionInputs>, WebauthnError> {
        prf::auth_prf_to_ctap2_input(request, supported_extensions)
    }
}
