pub mod attestation_verifier;
pub mod decomposer;
pub mod error;
pub mod freshness;
pub mod model_validation;
pub mod policy;
pub mod secure_client;
pub mod types;

#[cfg(feature = "mock")]
pub mod mock;

// Re-export common types and client-specific types
pub use attestation_verifier::{AttestationError, AttestationVerifier, EnclaveIdentity};
pub use decomposer::ModelDecomposer;
pub use ephemeral_ml_common::*;
pub use error::{ClientError, Result};
pub use freshness::{
    FreshnessEnforcer, FreshnessError, FreshnessStats, FreshnessValidator, NonceManager, NonceStats,
};
pub use model_validation::{
    ModelInfo, ModelType, ModelValidationError, ModelValidator, SafetensorsInfo, TensorInfo,
};
pub use policy::{
    KeyReleasePolicy, MeasurementAllowlist, PolicyBundle, PolicyError, PolicyManager,
    PolicyUpdateManager, PolicyVersionHistory,
};
pub use secure_client::{SecureClient, SecureEnclaveClient};
