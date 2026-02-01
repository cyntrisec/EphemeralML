//! Common types and utilities for the EphemeralNet zero-trust AI inference system
//!
//! This crate provides shared data structures, error types, and utilities that are used
//! across all components of the EphemeralNet system (client, host, and enclave).

pub mod audit;
pub mod error;
pub mod hpke_session;
pub mod kms_proxy;
pub mod model_manifest;
pub mod protocol;
pub mod receipt_signing;
pub mod storage_protocol;
pub mod types;
pub mod validation;
pub mod vsock;

// Re-export commonly used types and errors
pub use error::{
    ClientError, ClientResult, EnclaveError, EnclaveResult, EphemeralError, HostError, HostResult,
    Result,
};

pub use types::{
    // Attestation types
    AttestationDocument,
    AuditEventType,
    AuditLogEntry,
    AuditSeverity,
    EncryptedPayload,
    EncryptedTensor,
    // Encrypted communication types
    EncryptedTopologyKey,
    GraphEdge,
    GraphNode,
    InferenceRequest,
    InferenceResponse,

    ModelMetadata,
    OperationType,

    PayloadType,
    PcrMeasurements,
    SecureChannel,

    // Session and audit types
    SessionInfo,
    SessionStatus,
    TensorShape,
    // Core data structures
    TopologyKey,
    WeightArrays,
    WeightIndex,
    WeightType,
};

pub use hpke_session::{EncryptedMessage, HPKEConfig, HPKESession, HPKESessionManager, SessionId};

pub use kms_proxy::{
    KmsProxyErrorCode, KmsProxyRequestEnvelope, KmsProxyResponseEnvelope, KmsRequest, KmsResponse,
};
pub use model_manifest::ModelManifest;

pub use receipt_signing::{
    AttestationReceipt, AttestationUserData, EnclaveMeasurements, ReceiptBinding,
    ReceiptSigningKey, ReceiptVerifier, SecurityMode,
};

pub use vsock::{MessageType, VSockMessage};

pub use validation::{InputValidator, ValidationError, ValidationLimits};

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

/// Generate a cryptographically secure random nonce for cryptographic operations
///
/// Uses OsRng for secure random number generation. Each call produces a unique,
/// unpredictable 12-byte nonce suitable for use with ChaCha20-Poly1305.
pub fn generate_nonce() -> [u8; 12] {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
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
