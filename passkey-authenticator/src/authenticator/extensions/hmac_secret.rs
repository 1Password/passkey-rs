/// Logical module for configuring the [hmac-secret] authenticator extension.
///
/// [hmac-secret]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension
#[derive(Debug)]
pub struct HmacSecretConfig {
    credentials: HmacSecretCredentialSupport,
}

impl HmacSecretConfig {
    /// Create a new configuration which only supports creating credentials
    /// gated by UV
    pub fn new_with_uv_only() -> Self {
        Self {
            credentials: HmacSecretCredentialSupport::WithUvOnly,
        }
    }

    /// Create a new configuration which supports creating 2 credentials:
    /// 1. Gated by UV
    /// 2. Not protected by UV, and only needs UP
    pub fn new_without_uv() -> Self {
        Self {
            credentials: HmacSecretCredentialSupport::WithoutUv,
        }
    }
}

/// Set whether the Hmac Secret generation supports one or two credentials
#[derive(Debug)]
pub enum HmacSecretCredentialSupport {
    /// Only support one credential, which is necessarily backed by User Verification
    WithUvOnly,
    /// Support 2 credentials, where the second one is not protected by User Verification
    WithoutUv,
}
