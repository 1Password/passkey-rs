#[cfg(any(feature = "tokio", test))]
use std::sync::Arc;

use passkey_types::{
    ctap2::{
        get_assertion::Options,
        make_credential::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity},
        Ctap2Error, StatusCode,
    },
    webauthn::PublicKeyCredentialDescriptor,
    Passkey,
};

/// A struct that defines the capabilities of a store.
pub struct StoreInfo {
    /// How the store handles discoverability.
    pub discoverability: DiscoverabilitySupport,
}

/// Enum to define how the store handles discoverability.
/// Note that this is does not say anything about which storage mode will be used.
#[derive(PartialEq)]
pub enum DiscoverabilitySupport {
    /// The store supports both discoverable and non-credentials.
    Full,

    /// The store only supports non-discoverable credentials.
    /// An error will be returned if a discoverable credential is requested.
    OnlyNonDiscoverable,

    /// The store only supports discoverable credential.
    /// No error will be returned if a non-discoverable credential is requested.
    ForcedDiscoverable,
}

impl DiscoverabilitySupport {
    /// Helper method to determine if the store created a discoverable credential or not.
    pub fn is_passkey_discoverable(&self, rk_input: bool) -> bool {
        match self {
            DiscoverabilitySupport::Full => rk_input,
            DiscoverabilitySupport::OnlyNonDiscoverable => false,
            DiscoverabilitySupport::ForcedDiscoverable => true,
        }
    }
}

/// Use this on a type that enables storage and fetching of credentials
#[async_trait::async_trait]
pub trait CredentialStore {
    /// Defines the return type of find_credentials(...)
    type PasskeyItem: TryInto<Passkey> + Send + Sync;

    /// Find all credentials matching the given `ids` and `rp_id`.
    ///
    /// If multiple are found, it is recommended to sort the credentials using their creation date
    /// before returning as the algorithm will take the first credential from the list for assertions.
    async fn find_credentials(
        &self,
        ids: Option<&[PublicKeyCredentialDescriptor]>,
        rp_id: &str,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode>;

    /// Save the new credential into your store
    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: PublicKeyCredentialUserEntity,
        rp: PublicKeyCredentialRpEntity,
        options: Options,
    ) -> Result<(), StatusCode>;

    /// Update the credential in your store
    async fn update_credential(&mut self, cred: Passkey) -> Result<(), StatusCode>;

    /// Get information about the store
    async fn get_info(&self) -> StoreInfo;
}

/// In-memory store for Passkeys
///
/// Useful for tests.
pub type MemoryStore = std::collections::HashMap<Vec<u8>, Passkey>;

#[async_trait::async_trait]
impl CredentialStore for MemoryStore {
    type PasskeyItem = Passkey;

    async fn find_credentials(
        &self,
        allow_credentials: Option<&[PublicKeyCredentialDescriptor]>,
        _rp_id: &str,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        let creds: Vec<Passkey> = allow_credentials
            .into_iter()
            .flatten()
            .filter_map(|id| self.get(&*id.id))
            .cloned()
            .collect();
        if creds.is_empty() {
            Err(Ctap2Error::NoCredentials.into())
        } else {
            Ok(creds)
        }
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        _user: PublicKeyCredentialUserEntity,
        _rp: PublicKeyCredentialRpEntity,
        _options: Options,
    ) -> Result<(), StatusCode> {
        self.insert(cred.credential_id.clone().into(), cred);
        Ok(())
    }

    async fn update_credential(&mut self, cred: Passkey) -> Result<(), StatusCode> {
        self.insert(cred.credential_id.clone().into(), cred);
        Ok(())
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo {
            discoverability: DiscoverabilitySupport::ForcedDiscoverable,
        }
    }
}

#[async_trait::async_trait]
impl CredentialStore for Option<Passkey> {
    type PasskeyItem = Passkey;

    async fn find_credentials(
        &self,
        id: Option<&[PublicKeyCredentialDescriptor]>,
        _rp_id: &str,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        if let Some(id) = id {
            id.iter().find_map(|id| {
                // TODO: && pk.rp_id == rp_id) need rp_id on typeshared passkey
                self.clone().filter(|pk| pk.credential_id == id.id)
            })
        } else {
            self.clone() // TODO: .filter(|pk| pk.rp_id == rp_id) need rp_id on typeshared passkey
        }
        .map(|pk| vec![pk])
        .ok_or(Ctap2Error::NoCredentials.into())
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        _user: PublicKeyCredentialUserEntity,
        _rp: PublicKeyCredentialRpEntity,
        _options: Options,
    ) -> Result<(), StatusCode> {
        self.replace(cred);
        Ok(())
    }

    async fn update_credential(&mut self, cred: Passkey) -> Result<(), StatusCode> {
        self.replace(cred);
        Ok(())
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo {
            discoverability: DiscoverabilitySupport::ForcedDiscoverable,
        }
    }
}

#[cfg(any(feature = "tokio", test))]
#[async_trait::async_trait]
impl<S: CredentialStore<PasskeyItem = Passkey> + Send + Sync> CredentialStore
    for Arc<tokio::sync::Mutex<S>>
{
    type PasskeyItem = Passkey;

    async fn find_credentials(
        &self,
        ids: Option<&[PublicKeyCredentialDescriptor]>,
        rp_id: &str,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        self.lock().await.find_credentials(ids, rp_id).await
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: PublicKeyCredentialUserEntity,
        rp: PublicKeyCredentialRpEntity,
        options: Options,
    ) -> Result<(), StatusCode> {
        self.lock()
            .await
            .save_credential(cred, user, rp, options)
            .await
    }

    async fn update_credential(&mut self, cred: Passkey) -> Result<(), StatusCode> {
        self.lock().await.update_credential(cred).await
    }

    async fn get_info(&self) -> StoreInfo {
        self.lock().await.get_info().await
    }
}

#[cfg(any(feature = "tokio", test))]
#[async_trait::async_trait]
impl<S: CredentialStore<PasskeyItem = Passkey> + Send + Sync> CredentialStore
    for Arc<tokio::sync::RwLock<S>>
{
    type PasskeyItem = Passkey;

    async fn find_credentials(
        &self,
        ids: Option<&[PublicKeyCredentialDescriptor]>,
        rp_id: &str,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        self.read().await.find_credentials(ids, rp_id).await
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: PublicKeyCredentialUserEntity,
        rp: PublicKeyCredentialRpEntity,
        options: Options,
    ) -> Result<(), StatusCode> {
        self.write()
            .await
            .save_credential(cred, user, rp, options)
            .await
    }

    async fn update_credential(&mut self, cred: Passkey) -> Result<(), StatusCode> {
        self.write().await.update_credential(cred).await
    }

    async fn get_info(&self) -> StoreInfo {
        self.read().await.get_info().await
    }
}

#[cfg(any(feature = "tokio", test))]
#[async_trait::async_trait]
impl<S: CredentialStore<PasskeyItem = Passkey> + Send + Sync> CredentialStore
    for tokio::sync::Mutex<S>
{
    type PasskeyItem = Passkey;

    async fn find_credentials(
        &self,
        ids: Option<&[PublicKeyCredentialDescriptor]>,
        rp_id: &str,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        self.lock().await.find_credentials(ids, rp_id).await
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: PublicKeyCredentialUserEntity,
        rp: PublicKeyCredentialRpEntity,
        options: Options,
    ) -> Result<(), StatusCode> {
        self.lock()
            .await
            .save_credential(cred, user, rp, options)
            .await
    }

    async fn update_credential(&mut self, cred: Passkey) -> Result<(), StatusCode> {
        self.lock().await.update_credential(cred).await
    }

    async fn get_info(&self) -> StoreInfo {
        self.lock().await.get_info().await
    }
}

#[cfg(any(feature = "tokio", test))]
#[async_trait::async_trait]
impl<S: CredentialStore<PasskeyItem = Passkey> + Send + Sync> CredentialStore
    for tokio::sync::RwLock<S>
{
    type PasskeyItem = Passkey;

    async fn find_credentials(
        &self,
        ids: Option<&[PublicKeyCredentialDescriptor]>,
        rp_id: &str,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        self.read().await.find_credentials(ids, rp_id).await
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: PublicKeyCredentialUserEntity,
        rp: PublicKeyCredentialRpEntity,
        options: Options,
    ) -> Result<(), StatusCode> {
        self.write()
            .await
            .save_credential(cred, user, rp, options)
            .await
    }

    async fn update_credential(&mut self, cred: Passkey) -> Result<(), StatusCode> {
        self.write().await.update_credential(cred).await
    }

    async fn get_info(&self) -> StoreInfo {
        self.read().await.get_info().await
    }
}
