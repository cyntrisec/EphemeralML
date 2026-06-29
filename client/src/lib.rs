// Prevent accidentally building with conflicting features enabled.
#[cfg(all(feature = "mock", feature = "production"))]
compile_error!(
    "Features `mock` and `production` are mutually exclusive. \
     Build with: --no-default-features --features production"
);
#[cfg(all(feature = "mock", feature = "gcp"))]
compile_error!(
    "Features `mock` and `gcp` are mutually exclusive. \
     Build with: --no-default-features --features gcp"
);
#[cfg(all(feature = "production", feature = "gcp"))]
compile_error!(
    "Features `production` and `gcp` are mutually exclusive. \
     Build with: --no-default-features --features gcp"
);

pub mod attestation_bridge;
pub mod attestation_verifier;
pub mod chained_verify;
pub mod error;
pub mod evidence_event;
pub mod freshness;
pub mod gcp;
pub mod model_validation;
pub mod policy;
pub mod receipt_key;
pub mod secure_client;
#[deprecated(
    note = "use ephemeral_ml_common directly; this re-export module is kept for compatibility"
)]
pub mod types;

#[cfg(feature = "mock")]
pub mod mock;

// Re-export common types and client-specific types
pub use attestation_verifier::{AttestationError, AttestationVerifier, EnclaveIdentity};
pub use chained_verify::verify_air_v1_receipt_chained;
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
};
pub use secure_client::{InferenceResult, SecureClient, SecureEnclaveClient};
