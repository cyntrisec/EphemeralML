pub mod types;
pub mod error;
pub mod decomposer;
pub mod secure_client;
pub mod policy;
pub mod attestation_verifier;
pub mod freshness;
pub mod model_validation;

#[cfg(feature = "mock")]
pub mod mock;

// Re-export common types and client-specific types
pub use ephemeral_ml_common::*;
pub use error::{ClientError, Result};
pub use decomposer::ModelDecomposer;
pub use secure_client::{SecureClient, SecureEnclaveClient};
pub use policy::{PolicyManager, PolicyBundle, MeasurementAllowlist, KeyReleasePolicy, PolicyError, PolicyUpdateManager, PolicyVersionHistory};
pub use attestation_verifier::{AttestationVerifier, EnclaveIdentity, AttestationError};
pub use freshness::{FreshnessEnforcer, NonceManager, FreshnessValidator, FreshnessError, NonceStats, FreshnessStats};
pub use model_validation::{ModelValidator, ModelValidationError, ModelType, SafetensorsInfo, ModelInfo, TensorInfo};