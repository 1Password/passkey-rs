//! WebAuthn extensions as defined in [WebAuthn Defined Extensions][webauthn]
//! and [CTAP2 Defined Extensions][ctap2].
//!
//! The currently supported extensions are:
//! * [`Credential Properties`][credprops]
//!
//! [ctap2]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-defined-extensions
//! [webauthn]: https://w3c.github.io/webauthn/#sctn-defined-extensions
//! [credprops]: https://w3c.github.io/webauthn/#sctn-authenticator-credential-properties-extension

use passkey_authenticator::{CredentialStore, UserValidationMethod};
use passkey_types::{
    ctap2::{get_assertion, make_credential},
    webauthn::{
        AuthenticationExtensionsClientInputs, AuthenticationExtensionsClientOutputs,
        CredentialPropertiesOutput,
    },
    Passkey,
};

use crate::Client;

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
    ) -> Option<make_credential::ExtensionInputs> {
        request.map(|_| make_credential::ExtensionInputs::default())
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
        request: Option<&AuthenticationExtensionsClientInputs>,
    ) -> Option<get_assertion::ExtensionInputs> {
        request.map(|_| get_assertion::ExtensionInputs::default())
    }
}
