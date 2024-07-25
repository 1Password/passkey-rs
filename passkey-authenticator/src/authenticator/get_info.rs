use passkey_types::ctap2::get_info::{Options, Response};

use crate::{
    credential_store::DiscoverabilitySupport, Authenticator, CredentialStore, UserValidationMethod,
};

impl<S: CredentialStore, U: UserValidationMethod> Authenticator<S, U> {
    /// Using this method, the host can request that the authenticator report a list of all
    /// supported protocol versions, supported extensions, AAGUID of the device, and its capabilities.
    pub async fn get_info(&self) -> Response {
        Response {
            versions: vec!["FIDO_2_0".into(), "U2F_V2".into()],
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
        }
    }
}
