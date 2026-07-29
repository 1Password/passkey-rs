use coset::iana;
use passkey_crypto::{CryptoBackend, SecretKeyT, rng::RngBackend, rust_crypto::RustCryptoRng};

use crate::{Passkey, StoredHmacSecret};

/// A builder for the [`Passkey`] type which should be used as a mock for testing.
pub struct PasskeyBuilder {
    inner: Passkey,
}

impl PasskeyBuilder {
    /// Create a new
    pub(super) fn new<C: CryptoBackend>(rp_id: String, crypto: C) -> Self {
        // This expect is safe since this is test code and should never be used in production.
        let private_key = crypto
            .generate_key(iana::Algorithm::ES256)
            .expect("The crypto backend does not support ES256");

        let private = private_key.to_cose_key();
        Self {
            inner: Passkey {
                key: private,
                credential_id: RustCryptoRng::random_vec(16).into(),
                rp_id,
                user_handle: None,
                username: None,
                user_display_name: None,
                counter: None,
                extensions: Default::default(),
            },
        }
    }

    /// Regenerate the credential ID with a different size than the default 16 bytes
    pub fn credential_id(mut self, len: usize) -> Self {
        self.inner.credential_id = RustCryptoRng::random_vec(len).into();
        self
    }

    /// Generate the user handle with an optional custom size. The default is 16 bytes.
    pub fn user_handle(mut self, len: Option<usize>) -> Self {
        self.inner.user_handle = Some(RustCryptoRng::random_vec(len.unwrap_or(16)).into());
        self
    }

    /// Set the username for the passkey. The default is None
    pub fn username(mut self, username: String) -> Self {
        self.inner.username = Some(username);
        self
    }
    ///
    /// Set the user display name for the passkey. The default is None
    pub fn user_display_name(mut self, user_display_name: String) -> Self {
        self.inner.user_display_name = Some(user_display_name);
        self
    }

    /// Add a counter to the passkey. The default is None
    pub fn counter(mut self, counter: u32) -> Self {
        self.inner.counter = Some(counter);
        self
    }

    /// Add hmac-secret extension data associated to the passkey. The default is none
    pub fn hmac_secret(mut self, hmac_secret: StoredHmacSecret) -> Self {
        self.inner.extensions.hmac_secret = Some(hmac_secret);
        self
    }

    /// Get the built passkey
    pub fn build(self) -> Passkey {
        self.inner
    }
}
