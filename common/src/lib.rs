pub mod audit;
pub mod error;
#[cfg(feature = "inference")]
pub mod inference;
pub mod kms_proxy;
pub mod metrics;
pub mod model_manifest;
pub mod model_registry;
pub mod receipt_signing;
pub mod storage_protocol;
pub mod transport_types;
pub mod types;
pub mod validation;

// Re-export commonly used types and errors
pub use error::{
    ClientError, ClientResult, EnclaveError, EnclaveResult, EphemeralError, HostError, HostResult,
    Result,
};

pub use types::{
    AttestationDocument, AuditEventType, AuditLogEntry, AuditSeverity, PcrMeasurements,
    SessionInfo, SessionStatus,
};

pub use kms_proxy::{
    KmsProxyErrorCode, KmsProxyRequestEnvelope, KmsProxyResponseEnvelope, KmsRequest, KmsResponse,
};
pub use model_manifest::ModelManifest;

pub use receipt_signing::{
    AttestationReceipt, AttestationUserData, EnclaveMeasurements, ReceiptBinding,
    ReceiptSigningKey, ReceiptVerifier, SecurityMode,
};

pub use transport_types::{ConnectionState, EphemeralUserData};

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

/// Generate a cryptographically secure random nonce
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
    fn test_pcr_measurements_validation() {
        let pcr = PcrMeasurements::new(vec![0u8; 48], vec![1u8; 48], vec![2u8; 48]);
        assert!(pcr.is_valid());

        let invalid_pcr = PcrMeasurements::new(vec![0u8; 32], vec![1u8; 48], vec![2u8; 48]);
        assert!(!invalid_pcr.is_valid());
    }

    #[test]
    fn test_utility_functions() {
        let id = generate_id();
        assert!(!id.is_empty());

        let timestamp = current_timestamp();
        assert!(timestamp > 0);
    }
}
