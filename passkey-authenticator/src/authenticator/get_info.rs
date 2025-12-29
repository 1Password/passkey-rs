use passkey_types::{
    ctap2::get_info::{Options, Response, Version},
    webauthn::PublicKeyCredentialParameters,
};

use crate::{
    Authenticator, CredentialStore, UserValidationMethod, credential_store::DiscoverabilitySupport,
};

impl<S: CredentialStore, U: UserValidationMethod> Authenticator<S, U> {
    /// Using this method, the host can request that the authenticator report a list of all
    /// supported protocol versions, supported extensions, AAGUID of the device, and its capabilities.
    pub async fn get_info(&self) -> Box<Response> {
        Box::new(Response {
            versions: vec![Version::FIDO_2_0, Version::FIDO_2_1],
            extensions: self.extensions.list_extensions(),
            aaguid: *self.aaguid(),
            options: Some(Options {
                rk: self.store.get_info().await.discoverability
                    != DiscoverabilitySupport::OnlyNonDiscoverable,
                uv: self.user_validation.is_verification_enabled(),
                up: self.user_validation.is_presence_enabled(),
                ..Default::default()
            }),
            max_msg_size: None,
            pin_protocols: None,
            transports: Some(self.transports.clone()),
            algorithms: Some(
                self.algs
                    .iter()
                    .copied()
                    .map(PublicKeyCredentialParameters::from)
                    .collect(),
            ),
            ..Default::default()
        })
    }
}
