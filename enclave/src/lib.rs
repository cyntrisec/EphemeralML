pub mod assembly;
pub mod attestation;
pub mod audit;
pub mod candle_engine;
pub mod error;
pub mod inference;
pub mod inference_handler;
pub mod kms_client;
pub mod kms_proxy_client;
pub mod model_loader;
pub mod receipt;
pub mod server;
pub mod session_manager;

#[cfg(feature = "mock")]
pub mod mock;

// Re-export common types and enclave-specific types
pub use assembly::EphemeralAssembler;
pub use attestation::{
    AttestationProvider, AttestationUserData, DefaultAttestationProvider, EphemeralKeyPair,
};
pub use candle_engine::CandleInferenceEngine;
pub use ephemeral_ml_common::*;
pub use error::{EnclaveError, Result};
pub use inference::InferenceEngine;
