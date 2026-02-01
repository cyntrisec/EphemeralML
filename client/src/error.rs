// Re-export common error types with client-specific extensions
pub use ephemeral_ml_common::{ClientError, ClientResult, EphemeralError};

// Client-specific result type alias for convenience
pub type Result<T> = ClientResult<T>;

// Helper function to convert reqwest::Error to ClientError
pub fn reqwest_error_to_client_error(err: reqwest::Error) -> ClientError {
    ClientError::Client(EphemeralError::NetworkError(err.to_string()))
}
