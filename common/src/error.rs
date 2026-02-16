use thiserror::Error;

/// Common error types that can occur across the EphemeralNet system
#[derive(Error, Debug, Clone)]
pub enum EphemeralError {
    // Model decomposition and validation errors
    #[error("Model decomposition failed: {0}")]
    DecompositionError(String),

    #[error("ONNX validation failed: {0}")]
    ValidationError(String),

    #[error("Validation error: {0}")]
    Validation(#[from] crate::ValidationError),

    #[error("Unsupported operator: {0}")]
    UnsupportedOperatorError(String),

    // Attestation and security errors
    #[error("Attestation verification failed: {0}")]
    AttestationError(String),

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("KMS error: {0}")]
    KmsError(String),

    // Communication errors
    #[error("Communication error: {0}")]
    CommunicationError(String),

    #[error("VSock communication error: {0}")]
    VSockError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    // Assembly and inference errors
    #[error("Assembly error: {0}")]
    AssemblyError(String),

    #[error("Inference error: {0}")]
    InferenceError(String),

    #[error("Memory security error: {0}")]
    MemorySecurityError(String),

    // Storage and proxy errors
    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Proxy error: {0}")]
    ProxyError(String),

    // System errors
    #[error("IO error: {0}")]
    IoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Transport error: {0}")]
    TransportError(String),
}

impl EphemeralError {
    /// Returns a stable numeric error code for this error variant.
    ///
    /// Code ranges:
    /// - 1000-1099: Model/decomposition
    /// - 1100-1199: Security (attestation, crypto, KMS)
    /// - 1200-1299: Communication
    /// - 1300-1399: Inference/assembly
    /// - 1400-1499: System (storage, IO, config)
    /// - 1500-1599: Client (input, resource, timeout)
    /// - 1900-1999: Internal/transport
    pub fn code(&self) -> u16 {
        match self {
            EphemeralError::DecompositionError(_) => 1001,
            EphemeralError::ValidationError(_) => 1002,
            EphemeralError::Validation(_) => 1003,
            EphemeralError::UnsupportedOperatorError(_) => 1004,

            EphemeralError::AttestationError(_) => 1100,
            EphemeralError::EncryptionError(_) => 1101,
            EphemeralError::DecryptionError(_) => 1102,
            EphemeralError::KmsError(_) => 1103,

            EphemeralError::CommunicationError(_) => 1200,
            EphemeralError::VSockError(_) => 1201,
            EphemeralError::NetworkError(_) => 1202,

            EphemeralError::AssemblyError(_) => 1300,
            EphemeralError::InferenceError(_) => 1301,
            EphemeralError::MemorySecurityError(_) => 1302,

            EphemeralError::StorageError(_) => 1400,
            EphemeralError::ProxyError(_) => 1401,
            EphemeralError::IoError(_) => 1402,
            EphemeralError::SerializationError(_) => 1403,
            EphemeralError::ConfigurationError(_) => 1404,

            EphemeralError::InvalidInput(_) => 1500,
            EphemeralError::ResourceExhausted(_) => 1501,
            EphemeralError::Timeout(_) => 1502,
            EphemeralError::ProtocolError(_) => 1503,

            EphemeralError::Internal(_) => 1900,
            EphemeralError::TransportError(_) => 1901,
        }
    }

    /// Returns a structured error string in the format "E{code}: {redacted_message}".
    ///
    /// Safe for external consumption (logs, exit messages, CI parsing).
    pub fn to_structured(&self) -> String {
        format!("E{}: {}", self.code(), self.to_redacted_string())
    }

    /// Returns a redacted error message safe for external consumption.
    /// Sensitive details (keys, internal paths, specific validation failures) are hidden.
    pub fn to_redacted_string(&self) -> String {
        match self {
            EphemeralError::DecompositionError(_) => "Model decomposition failed".to_string(),
            EphemeralError::ValidationError(_) => "Model validation failed".to_string(),
            EphemeralError::Validation(_) => "Input validation failed".to_string(),
            EphemeralError::UnsupportedOperatorError(_) => "Unsupported model operator".to_string(),

            EphemeralError::AttestationError(_) => "Attestation verification failed".to_string(),
            EphemeralError::EncryptionError(_) => "Encryption operation failed".to_string(),
            EphemeralError::DecryptionError(_) => "Decryption operation failed".to_string(),
            EphemeralError::KmsError(_) => "Key management service error".to_string(),

            EphemeralError::CommunicationError(_) => "Communication error".to_string(),
            EphemeralError::VSockError(_) => "Internal communication error".to_string(),
            EphemeralError::NetworkError(_) => "Network error".to_string(),

            EphemeralError::AssemblyError(_) => "Model assembly failed".to_string(),
            EphemeralError::InferenceError(_) => "Inference execution failed".to_string(),
            EphemeralError::MemorySecurityError(_) => "Security boundary violation".to_string(),

            EphemeralError::StorageError(_) => "Storage operation failed".to_string(),
            EphemeralError::ProxyError(_) => "Proxy operation failed".to_string(),

            EphemeralError::IoError(_) => "I/O error".to_string(),
            EphemeralError::SerializationError(_) => "Data format error".to_string(),
            EphemeralError::ConfigurationError(_) => "Configuration error".to_string(),

            // These might be safe to return specific details for client debugging,
            // but we default to generic for high security unless specified.
            EphemeralError::InvalidInput(_) => "Invalid input provided".to_string(),
            EphemeralError::ResourceExhausted(_) => "Resource limit exceeded".to_string(),
            EphemeralError::Timeout(_) => "Operation timed out".to_string(),
            EphemeralError::ProtocolError(_) => "Protocol violation".to_string(),

            EphemeralError::Internal(_) => "Internal server error".to_string(),
            EphemeralError::TransportError(_) => "Transport error".to_string(),
        }
    }
}

impl From<std::io::Error> for EphemeralError {
    fn from(err: std::io::Error) -> Self {
        EphemeralError::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for EphemeralError {
    fn from(err: serde_json::Error) -> Self {
        EphemeralError::SerializationError(err.to_string())
    }
}

impl From<confidential_ml_transport::Error> for EphemeralError {
    fn from(err: confidential_ml_transport::Error) -> Self {
        EphemeralError::TransportError(err.to_string())
    }
}

/// Common result type for the EphemeralNet system
pub type Result<T> = std::result::Result<T, EphemeralError>;

/// Specialized error types for different components
#[derive(Error, Debug, Clone)]
pub enum ClientError {
    #[error("Client error: {0}")]
    Client(#[from] EphemeralError),

    #[error("HTTP error: {0}")]
    HttpError(String),
}

#[derive(Error, Debug, Clone)]
pub enum HostError {
    #[error("Host error: {0}")]
    Host(#[from] EphemeralError),
}

#[derive(Error, Debug, Clone)]
pub enum EnclaveError {
    #[error("Enclave error: {0}")]
    Enclave(#[from] EphemeralError),

    #[error("Candle error: {0}")]
    CandleError(String),
}

/// Result types for each component
pub type ClientResult<T> = std::result::Result<T, ClientError>;
pub type HostResult<T> = std::result::Result<T, HostError>;
pub type EnclaveResult<T> = std::result::Result<T, EnclaveError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes_unique() {
        let variants: Vec<EphemeralError> = vec![
            EphemeralError::DecompositionError(String::new()),
            EphemeralError::ValidationError(String::new()),
            EphemeralError::Validation(crate::ValidationError::InvalidFormat(String::new())),
            EphemeralError::UnsupportedOperatorError(String::new()),
            EphemeralError::AttestationError(String::new()),
            EphemeralError::EncryptionError(String::new()),
            EphemeralError::DecryptionError(String::new()),
            EphemeralError::KmsError(String::new()),
            EphemeralError::CommunicationError(String::new()),
            EphemeralError::VSockError(String::new()),
            EphemeralError::NetworkError(String::new()),
            EphemeralError::AssemblyError(String::new()),
            EphemeralError::InferenceError(String::new()),
            EphemeralError::MemorySecurityError(String::new()),
            EphemeralError::StorageError(String::new()),
            EphemeralError::ProxyError(String::new()),
            EphemeralError::IoError(String::new()),
            EphemeralError::SerializationError(String::new()),
            EphemeralError::ConfigurationError(String::new()),
            EphemeralError::InvalidInput(String::new()),
            EphemeralError::ResourceExhausted(String::new()),
            EphemeralError::Timeout(String::new()),
            EphemeralError::ProtocolError(String::new()),
            EphemeralError::Internal(String::new()),
            EphemeralError::TransportError(String::new()),
        ];

        let codes: Vec<u16> = variants.iter().map(|e| e.code()).collect();
        let mut seen = std::collections::HashSet::new();
        for code in &codes {
            assert!(seen.insert(code), "Duplicate error code: {}", code);
        }
        assert_eq!(codes.len(), 25, "Must cover all 25 EphemeralError variants");
    }

    #[test]
    fn test_error_structured_format() {
        let err = EphemeralError::KmsError("secret key data".to_string());
        let structured = err.to_structured();
        assert_eq!(structured, "E1103: Key management service error");
        assert!(!structured.contains("secret"));
    }

    #[test]
    fn test_error_redaction() {
        let sensitive_error =
            EphemeralError::KmsError("Failed to decrypt with key: [SECRET KEY BYTES]".to_string());
        let redacted = sensitive_error.to_redacted_string();

        assert_eq!(redacted, "Key management service error");
        assert!(!redacted.contains("SECRET KEY BYTES"));

        let internal_error = EphemeralError::Internal("Stack trace: ...".to_string());
        assert_eq!(internal_error.to_redacted_string(), "Internal server error");
    }
}
