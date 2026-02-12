// Prevent accidentally building with both mock and production features enabled.
// Production builds MUST use: --no-default-features --features production
#[cfg(all(feature = "mock", feature = "production"))]
compile_error!(
    "Features `mock` and `production` are mutually exclusive. \
     Build with: --no-default-features --features production"
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

// Re-export common types and enclave-specific types
pub use attestation::{
    AttestationProvider, AttestationUserData, DefaultAttestationProvider, EphemeralKeyPair,
};
pub use candle_engine::CandleInferenceEngine;
pub use ephemeral_ml_common::*;
pub use error::{EnclaveError, Result};
pub use stage_executor::EphemeralStageExecutor;
