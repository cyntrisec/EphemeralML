use crate::{HostError, Result, EphemeralError};
use std::collections::HashMap;

#[cfg(feature = "production")]
use aws_sdk_s3::Client as S3Client;

/// Trait for weight storage functionality
#[async_trait::async_trait]
pub trait WeightStorage: Send + Sync {
    /// Store weights for a model (encrypted)
    async fn store(&self, model_id: &str, weights: &[u8]) -> Result<()>;
    
    /// Retrieve weights for a model (encrypted)
    async fn retrieve(&self, model_id: &str) -> Result<Vec<u8>>;
    
    /// Check if weights exist for a model
    async fn exists(&self, model_id: &str) -> bool;
    
    /// Remove weights for a model
    async fn remove(&self, model_id: &str) -> Result<()>;
}

/// In-memory weight storage implementation
pub struct InMemoryWeightStorage {
    storage: std::sync::RwLock<HashMap<String, Vec<u8>>>,
}

impl InMemoryWeightStorage {
    pub fn new() -> Self {
        Self {
            storage: std::sync::RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryWeightStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl WeightStorage for InMemoryWeightStorage {
    async fn store(&self, model_id: &str, weights: &[u8]) -> Result<()> {
        let mut storage = self.storage.write().map_err(|_| HostError::Host(EphemeralError::Internal("Lock poisoned".to_string())))?;
        storage.insert(model_id.to_string(), weights.to_vec());
        Ok(())
    }
    
    async fn retrieve(&self, model_id: &str) -> Result<Vec<u8>> {
        let storage = self.storage.read().map_err(|_| HostError::Host(EphemeralError::Internal("Lock poisoned".to_string())))?;
        storage
            .get(model_id)
            .cloned()
            .ok_or_else(|| HostError::Host(EphemeralError::StorageError(format!("Weights not found for model {}", model_id))))
    }
    
    async fn exists(&self, model_id: &str) -> bool {
        let storage = self.storage.read().unwrap();
        storage.contains_key(model_id)
    }
    
    async fn remove(&self, model_id: &str) -> Result<()> {
        let mut storage = self.storage.write().map_err(|_| HostError::Host(EphemeralError::Internal("Lock poisoned".to_string())))?;
        storage.remove(model_id);
        Ok(())
    }
}

/// S3-backed weight storage (production)
#[cfg(feature = "production")]
pub struct S3WeightStorage {
    client: S3Client,
    bucket: String,
}

#[cfg(feature = "production")]
impl S3WeightStorage {
    pub fn new(client: S3Client, bucket: String) -> Self {
        Self { client, bucket }
    }
}

#[cfg(feature = "production")]
#[async_trait::async_trait]
impl WeightStorage for S3WeightStorage {
    async fn store(&self, model_id: &str, weights: &[u8]) -> Result<()> {
        self.client.put_object()
            .bucket(&self.bucket)
            .key(model_id)
            .body(weights.to_vec().into())
            .send()
            .await
            .map_err(|e| HostError::Host(EphemeralError::StorageError(format!("S3 upload failed: {}", e))))?;
        Ok(())
    }

    async fn retrieve(&self, model_id: &str) -> Result<Vec<u8>> {
        let res = self.client.get_object()
            .bucket(&self.bucket)
            .key(model_id)
            .send()
            .await
            .map_err(|e| HostError::Host(EphemeralError::StorageError(format!("S3 download failed: {}", e))))?;

        let data = res.body.collect().await
            .map_err(|e| HostError::Host(EphemeralError::StorageError(format!("S3 body collection failed: {}", e))))?;
        
        Ok(data.to_vec())
    }

    async fn exists(&self, model_id: &str) -> bool {
        let res = self.client.head_object()
            .bucket(&self.bucket)
            .key(model_id)
            .send()
            .await;
        res.is_ok()
    }

    async fn remove(&self, model_id: &str) -> Result<()> {
        self.client.delete_object()
            .bucket(&self.bucket)
            .key(model_id)
            .send()
            .await
            .map_err(|e| HostError::Host(EphemeralError::StorageError(format!("S3 deletion failed: {}", e))))?;
        Ok(())
    }
}
