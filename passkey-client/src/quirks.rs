//! The goal of this module is to address quirks with RP's different implementations.
//! We don't want to limit this library's functionality for all RPs because of only
//! a few RPs misbehave.

use passkey_types::webauthn::CreatedPublicKeyCredential;

/// List of quirky RPs, the default is [`Self::NotQuirky`] which maps to being a no-op
#[derive(Default)]
pub(crate) enum QuirkyRp {
    /// The RP is not known to be quirky, thus the mapping methods will be no-ops.
    #[default]
    NotQuirky,

    /// Adobe crashes on their server when they encounter the key
    /// [credProps.authenticatorDisplayName][adn] during key creation.
    ///
    /// RP_IDs:
    /// * `adobe.com`
    ///
    /// [adn]: https://w3c.github.io/webauthn/#dom-credentialpropertiesoutput-authenticatordisplayname
    Adobe,

    /// Hyatt returns an "invalid request" error when they encounter the key
    /// [credProps.authenticatorDisplayName][adn] during key creation.
    ///
    /// RP_IDs:
    /// * `hyatt.com`
    ///
    /// [adn]: https://w3c.github.io/webauthn/#dom-credentialpropertiesoutput-authenticatordisplayname
    Hyatt,
}

impl QuirkyRp {
    pub fn from_rp_id(rp_id: &str) -> Self {
        match rp_id {
            "adobe.com" => QuirkyRp::Adobe,
            "hyatt.com" => QuirkyRp::Hyatt,
            _ => QuirkyRp::NotQuirky,
        }
    }

    /// Use this after creating the response but before returning it to the function caller
    #[inline]
    pub fn map_create_credential(
        &self,
        response: CreatedPublicKeyCredential,
    ) -> CreatedPublicKeyCredential {
        match self {
            // no-op
            Self::NotQuirky => response,
            Self::Adobe | Self::Hyatt => remove_authenticator_display_name(response),
        }
    }
}

#[inline]
fn remove_authenticator_display_name(
    mut response: CreatedPublicKeyCredential,
) -> CreatedPublicKeyCredential {
    if let Some(cp) = response.client_extension_results.cred_props.as_mut() {
        cp.authenticator_display_name = None;
    }
    response
}
