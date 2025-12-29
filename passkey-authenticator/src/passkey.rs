use std::{borrow::Cow, ops::Deref};

use coset::CoseKey;
use passkey_types::{
    CredentialExtensions,
    webauthn::{AuthenticatorTransport, PublicKeyCredentialDescriptor, PublicKeyCredentialType},
};

#[cfg(doc)]
use passkey_types::Passkey;

/// A trait to model the different aspects of a passkey, this allows the abstraction of a passkey
/// on custom items.
pub trait PasskeyAccessor {
    /// The private key
    ///
    /// This is a Cow in case the type does not save the private key in Cose format.
    fn key(&self) -> Cow<'_, CoseKey>;
    /// The passkey's credential Id.
    fn credential_id(&self) -> &[u8];
    /// The Relying Party ID to which the passkey is bound to.
    fn rp_id(&self) -> &str;
    /// The user handle for which this passkey is bound to.
    fn user_handle(&self) -> Option<&[u8]>;
    /// The username that this passkey is created for.
    fn username(&self) -> Option<&str>;
    /// The user's display name.
    fn user_display_name(&self) -> Option<&str>;
    /// The counter of times this passkey has been used.
    ///
    /// See Counter considerations on [`Passkey::counter`]
    fn counter(&self) -> Option<u32>;
    /// Set a new value for the [`PasskeyAccessor::set_counter`]
    fn set_counter(&mut self, counter: u32);
    /// Get the extensions that that this passkey provides
    ///
    /// This is a Cow in case the type does not save the extension data in the format defined by
    /// `passkey-types`.
    fn extensions(&self) -> Cow<'_, CredentialExtensions>;
}

pub(crate) trait AsCredentialDescriptor: PasskeyAccessor {
    fn as_credential_descriptor(
        &self,
        transports: Option<Vec<AuthenticatorTransport>>,
    ) -> PublicKeyCredentialDescriptor;
}

impl<P> AsCredentialDescriptor for P
where
    P: PasskeyAccessor,
{
    fn as_credential_descriptor(
        &self,
        transports: Option<Vec<AuthenticatorTransport>>,
    ) -> PublicKeyCredentialDescriptor {
        PublicKeyCredentialDescriptor {
            ty: PublicKeyCredentialType::PublicKey,
            id: self.credential_id().into(),
            transports,
        }
    }
}

impl PasskeyAccessor for passkey_types::Passkey {
    fn key(&self) -> Cow<'_, CoseKey> {
        Cow::Borrowed(&self.key)
    }

    fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    fn rp_id(&self) -> &str {
        &self.rp_id
    }

    fn user_handle(&self) -> Option<&[u8]> {
        self.user_handle.as_ref().map(|b| b.deref().deref())
    }

    fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    fn user_display_name(&self) -> Option<&str> {
        self.user_display_name.as_deref()
    }

    fn counter(&self) -> Option<u32> {
        self.counter
    }

    fn set_counter(&mut self, counter: u32) {
        self.counter = Some(counter);
    }

    fn extensions(&self) -> Cow<'_, CredentialExtensions> {
        Cow::Borrowed(&self.extensions)
    }
}
