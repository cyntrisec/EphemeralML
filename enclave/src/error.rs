// Re-export common error types with enclave-specific extensions
pub use ephemeral_ml_common::{EnclaveError, EnclaveResult, EphemeralError};

// Enclave-specific result type alias for convenience
pub type Result<T> = EnclaveResult<T>;
