use crate::{HostError, Result, EphemeralError};
use std::collections::HashMap;

/// Trait for weight storage functionality
pub trait WeightStorage {
    /// Store weights for a model (encrypted)
    fn store(&mut self, model_id: &str, weights: &[u8]) -> Result<()>;
    
    /// Retrieve weights for a model (encrypted)
    fn retrieve(&self, model_id: &str) -> Result<Vec<u8>>;
    
    /// Check if weights exist for a model
    fn exists(&self, model_id: &str) -> bool;
    
    /// Remove weights for a model
    fn remove(&mut self, model_id: &str) -> Result<()>;
}

/// In-memory weight storage implementation
pub struct InMemoryWeightStorage {
    storage: HashMap<String, Vec<u8>>,
}

impl InMemoryWeightStorage {
    pub fn new() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }
}

impl Default for InMemoryWeightStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl WeightStorage for InMemoryWeightStorage {
    fn store(&mut self, model_id: &str, weights: &[u8]) -> Result<()> {
        self.storage.insert(model_id.to_string(), weights.to_vec());
        Ok(())
    }
    
    fn retrieve(&self, model_id: &str) -> Result<Vec<u8>> {
        self.storage
            .get(model_id)
            .cloned()
            .ok_or_else(|| HostError::Host(EphemeralError::StorageError(format!("Weights not found for model {}", model_id))))
    }
    
    fn exists(&self, model_id: &str) -> bool {
        self.storage.contains_key(model_id)
    }
    
    fn remove(&mut self, model_id: &str) -> Result<()> {
        self.storage.remove(model_id);
        Ok(())
    }
}