//! Common types and utilities for the EphemeralNet zero-trust AI inference system
//! 
//! This crate provides shared data structures, error types, and utilities that are used
//! across all components of the EphemeralNet system (client, host, and enclave).

pub mod error;
pub mod types;
pub mod validation;
pub mod hpke_session;
pub mod kms_proxy;
pub mod model_manifest;
pub mod protocol;
pub mod receipt_signing;
pub mod vsock;
pub mod storage_protocol;
pub mod audit;


// Re-export commonly used types and errors
pub use error::{
    EphemeralError, ClientError, HostError, EnclaveError,
    Result, ClientResult, HostResult, EnclaveResult,
};

pub use types::{
    // Core data structures
    TopologyKey, GraphNode, GraphEdge, TensorShape, ModelMetadata,
    WeightArrays, WeightIndex, WeightType, OperationType,
    
    // Encrypted communication types
    EncryptedTopologyKey, EncryptedTensor, EncryptedPayload, PayloadType,
    InferenceRequest, InferenceResponse,
    
    // Attestation types
    AttestationDocument, PcrMeasurements, SecureChannel,
    
    // Session and audit types
    SessionInfo, SessionStatus, AuditLogEntry, AuditEventType, AuditSeverity,
};

pub use hpke_session::{
    HPKESession, HPKESessionManager, HPKEConfig, EncryptedMessage, SessionId,
};

pub use kms_proxy::{
    KmsRequest,
    KmsResponse,
    KmsProxyRequestEnvelope,
    KmsProxyResponseEnvelope,
    KmsProxyErrorCode,
};
pub use model_manifest::ModelManifest;

pub use receipt_signing::{
    ReceiptSigningKey, AttestationUserData, AttestationReceipt, SecurityMode,
    EnclaveMeasurements, ReceiptBinding, ReceiptVerifier,
};

pub use vsock::{
    VSockMessage, MessageType,
};

pub use validation::{
    ValidationLimits, ValidationError, InputValidator,
};

/// Version information for the common crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Generate a new UUID v4 string
pub fn generate_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Get current Unix timestamp
pub fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a random nonce for cryptographic operations
pub fn generate_nonce() -> [u8; 12] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(uuid::Uuid::new_v4().as_bytes());
    hasher.update(&current_timestamp().to_be_bytes());
    
    let hash = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hash[0..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tensor_shape_creation() {
        let shape = TensorShape::new(vec![2, 3, 4]);
        assert_eq!(shape.dimensions, vec![2, 3, 4]);
        assert_eq!(shape.total_elements(), 24);
        assert!(shape.is_valid());
    }

    #[test]
    fn test_weight_arrays_creation() {
        let weights = WeightArrays::new("test_model".to_string(), vec![1.0, 2.0, 3.0]);
        assert_eq!(weights.model_id, "test_model");
        assert_eq!(weights.weight_data, vec![1.0, 2.0, 3.0]);
        assert_eq!(weights.total_parameters, 3);
        assert!(weights.verify_checksum());
    }

    #[test]
    fn test_weight_index_validation() {
        let shape = TensorShape::new(vec![2, 2]);
        let weight_index = WeightIndex::new(0, 4, shape, WeightType::Weights);
        assert!(weight_index.is_valid());
        assert_eq!(weight_index.end_idx(), 4);
    }

    #[test]
    fn test_pcr_measurements_validation() {
        let pcr = PcrMeasurements::new(vec![0u8; 48], vec![1u8; 48], vec![2u8; 48]);
        assert!(pcr.is_valid());
        
        let invalid_pcr = PcrMeasurements::new(vec![0u8; 32], vec![1u8; 48], vec![2u8; 48]);
        assert!(!invalid_pcr.is_valid());
    }

    #[test]
    fn test_secure_channel_expiration() {
        let channel = SecureChannel::new("test_endpoint".to_string(), vec![0u8; 32], 1);
        assert!(!channel.is_expired());
        
        // Wait for expiration (in a real test, you'd mock the time)
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(channel.is_expired());
    }

    #[test]
    fn test_utility_functions() {
        let id = generate_id();
        assert!(!id.is_empty());
        
        let timestamp = current_timestamp();
        assert!(timestamp > 0);
        
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 12);
    }
}
