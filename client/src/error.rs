// Re-export common error types with client-specific extensions
pub use ephemeral_ml_common::{ClientError, ClientResult, EphemeralError};

// Client-specific result type alias for convenience
pub type Result<T> = ClientResult<T>;
