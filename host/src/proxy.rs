use crate::{HostError, Result, EphemeralError};

/// Trait for VSock proxy functionality
pub trait VSockProxy {
    /// Forward encrypted payload to enclave
    fn forward_to_enclave(&self, payload: &[u8]) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
    
    /// Store unstructured weights (encrypted)
    fn store_weights(&mut self, model_id: &str, weights: &[u8]) -> Result<()>;
    
    /// Retrieve unstructured weights (encrypted)
    fn retrieve_weights(&self, model_id: &str) -> Result<Vec<u8>>;
}

/// Default VSock proxy implementation
pub struct DefaultVSockProxy {
    pub enclave_cid: u32,
    pub enclave_port: u32,
    pub weight_storage: std::collections::HashMap<String, Vec<u8>>,
}

impl DefaultVSockProxy {
    pub fn new(enclave_cid: u32, enclave_port: u32) -> Self {
        Self {
            enclave_cid,
            enclave_port,
            weight_storage: std::collections::HashMap::new(),
        }
    }
}

impl VSockProxy for DefaultVSockProxy {
    async fn forward_to_enclave(&self, _payload: &[u8]) -> Result<Vec<u8>> {
        // Placeholder implementation - will be implemented in later tasks
        Err(HostError::Host(EphemeralError::VSockError("Not yet implemented".to_string())))
    }
    
    fn store_weights(&mut self, model_id: &str, weights: &[u8]) -> Result<()> {
        self.weight_storage.insert(model_id.to_string(), weights.to_vec());
        Ok(())
    }
    
    fn retrieve_weights(&self, model_id: &str) -> Result<Vec<u8>> {
        self.weight_storage
            .get(model_id)
            .cloned()
            .ok_or_else(|| HostError::Host(EphemeralError::StorageError(format!("Weights not found for model {}", model_id))))
    }
}