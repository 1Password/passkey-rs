use serde::Serialize;

/// A trait describing how client data should be generated during a WebAuthn operation.
pub trait ClientData<E: Serialize> {
    /// Extra client data to be appended to the automatically generated client data.
    fn extra_client_data(&self) -> E;

    /// The hash of the client data to be used in the WebAuthn operation.
    fn client_data_hash(&self) -> Option<Vec<u8>>;
}

/// The client data and its hash will be automatically generated from the request
/// according to the WebAuthn specification.
pub struct DefaultClientData;
impl ClientData<()> for DefaultClientData {
    fn extra_client_data(&self) -> () {
        ()
    }
    fn client_data_hash(&self) -> Option<Vec<u8>> {
        None
    }
}

/// The extra client data will be appended to the automatically generated client data.
/// The hash will be automatically generated from the result client data according to the WebAuthn specification.
pub struct DefaultClientDataWithExtra<E: Serialize>(pub E);
impl<E: Serialize + Clone> ClientData<E> for DefaultClientDataWithExtra<E> {
    fn extra_client_data(&self) -> E {
        self.0.clone()
    }
    fn client_data_hash(&self) -> Option<Vec<u8>> {
        None
    }
}

/// The client data will be automatically generated from the request according to the WebAuthn specification
/// but it will not be used as a base for the hash. The client data hash will instead be provided by the caller.
pub struct DefaultClientDataWithCustomHash(pub Vec<u8>);
impl ClientData<()> for DefaultClientDataWithCustomHash {
    fn extra_client_data(&self) -> () {
        ()
    }
    fn client_data_hash(&self) -> Option<Vec<u8>> {
        Some(self.0.clone())
    }
}

/// Backwards compatibility with the previous `register` and `authenticate` functions
/// which only took `Option<Vec<u8>>` as a client data hash.
impl ClientData<()> for Option<Vec<u8>> {
    fn extra_client_data(&self) -> () {
        ()
    }
    fn client_data_hash(&self) -> Option<Vec<u8>> {
        self.clone()
    }
}
