#[cfg(any(feature = "tokio", test))]
use std::sync::Arc;

use passkey_types::{
    ctap2::{
        make_credential::PublicKeyCredentialRpEntity,
        make_credential::PublicKeyCredentialUserEntity, Ctap2Error, StatusCode,
    },
    webauthn::PublicKeyCredentialDescriptor,
    Passkey,
};

/// Use this on a type that enables storage and fetching of credentials
#[async_trait::async_trait]
pub trait CredentialStore {
    /// Defines the return type of find_credentials(...)
    type PasskeyItem: TryInto<Passkey>;

    /// Find all credentials matching the given `ids` and `rp_id`.
    ///
    /// If multiple are found, it is recommended to sort the credentials using their creation date
    /// before returning as the algorithm will take the first credential from the list for assertions.
    async fn find_credentials(
        &self,
        ids: Option<&[PublicKeyCredentialDescriptor]>,
        rp_id: &str,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode>;

    /// Save the new/updated credential into your store
    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: PublicKeyCredentialUserEntity,
        rp: PublicKeyCredentialRpEntity,
    ) -> Result<(), StatusCode>;
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
    ) -> Result<(), StatusCode> {
        self.insert(cred.credential_id.clone().into(), cred);
        Ok(())
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
    ) -> Result<(), StatusCode> {
        self.replace(cred);
        Ok(())
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
    ) -> Result<(), StatusCode> {
        self.lock().await.save_credential(cred, user, rp).await
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
    ) -> Result<(), StatusCode> {
        self.write().await.save_credential(cred, user, rp).await
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
    ) -> Result<(), StatusCode> {
        self.lock().await.save_credential(cred, user, rp).await
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
    ) -> Result<(), StatusCode> {
        self.write().await.save_credential(cred, user, rp).await
    }
}
