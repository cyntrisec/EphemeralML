// Re-export common error types with host-specific extensions
pub use ephemeral_ml_common::{EphemeralError, HostError, HostResult};

// Host-specific result type alias for convenience
pub type Result<T> = HostResult<T>;
