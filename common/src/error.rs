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
    
    #[error("Internal error: {0}")]
    Internal(String),
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