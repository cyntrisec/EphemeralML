// Prevent accidentally building with conflicting features enabled.
// Production builds MUST use: --no-default-features --features production
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

pub mod attestation;
pub mod attestation_bridge;
pub mod audit;
pub mod candle_engine;
pub mod error;
pub mod kms_client;
pub mod kms_proxy_client;
pub mod model_loader;
pub mod receipt;
pub mod server;
pub mod stage_executor;

#[cfg(feature = "mock")]
pub mod mock;

pub mod tee_provider;
pub mod trust_evidence;

#[cfg(feature = "gcp")]
pub mod gcp_kms_client;
#[cfg(feature = "gcp")]
pub mod gcs_loader;

// Re-export common types and enclave-specific types
#[cfg(any(feature = "mock", feature = "production"))]
pub use attestation::DefaultAttestationProvider;
pub use attestation::{AttestationProvider, AttestationUserData, EphemeralKeyPair};
pub use candle_engine::CandleInferenceEngine;
pub use ephemeral_ml_common::*;
pub use error::{EnclaveError, Result};
pub use stage_executor::EphemeralStageExecutor;
