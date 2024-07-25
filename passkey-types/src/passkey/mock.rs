use coset::{iana, CoseKeyBuilder};
use p256::{ecdsa::SigningKey, SecretKey};

use crate::{rand::random_vec, Passkey, StoredHmacSecret};

/// A builder for the [`Passkey`] type which should be used as a mock for testing.
pub struct PasskeyBuilder {
    inner: Passkey,
}

impl PasskeyBuilder {
    /// Create a new
    pub(super) fn new(rp_id: String) -> Self {
        let private_key = {
            let mut rng = rand::thread_rng();
            SecretKey::random(&mut rng)
        };

        let public_key = SigningKey::from(&private_key)
            .verifying_key()
            .to_encoded_point(false);
        // SAFETY: These unwraps are safe because the public_key above is not compressed (false
        // parameter) therefore x and y are guaranteed to contain values.
        let x = public_key.x().unwrap().as_slice().to_vec();
        let y = public_key.y().unwrap().as_slice().to_vec();
        let private = CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_256,
            x,
            y,
            private_key.to_bytes().to_vec(),
        )
        .algorithm(iana::Algorithm::ES256)
        .build();

        Self {
            inner: Passkey {
                key: private,
                credential_id: random_vec(16).into(),
                rp_id,
                user_handle: None,
                counter: None,
                extensions: Default::default(),
            },
        }
    }

    /// Regenerate the credential ID with a different size than the default 16 bytes
    pub fn credential_id(mut self, len: usize) -> Self {
        self.inner.credential_id = random_vec(len).into();
        self
    }

    /// Generate the user handle with an optional custom size. The default is 16 bytes.
    pub fn user_handle(mut self, len: Option<usize>) -> Self {
        self.inner.user_handle = Some(random_vec(len.unwrap_or(16)).into());
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
