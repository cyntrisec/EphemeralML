pub mod types;
pub mod error;
pub mod decomposer;
pub mod secure_client;
pub mod policy;

#[cfg(feature = "mock")]
pub mod mock;

// Re-export common types and client-specific types
pub use ephemeral_ml_common::*;
pub use error::{ClientError, Result};
pub use decomposer::ModelDecomposer;
pub use secure_client::SecureClient;
pub use policy::{PolicyManager, PolicyBundle, MeasurementAllowlist, KeyReleasePolicy, PolicyError};