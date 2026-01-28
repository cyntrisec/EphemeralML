pub mod error;
pub mod attestation;
pub mod kms_client;
pub mod kms_proxy_client;
pub mod assembly;
pub mod model_loader;
pub mod session_manager;
pub mod receipt;
pub mod inference_handler;
pub mod inference;
pub mod candle_engine;
pub mod audit;
pub mod server;

#[cfg(feature = "mock")]
pub mod mock;

// Re-export common types and enclave-specific types
pub use ephemeral_ml_common::*;
pub use error::{EnclaveError, Result};
pub use attestation::{AttestationProvider, DefaultAttestationProvider, AttestationUserData, EphemeralKeyPair};
pub use assembly::EphemeralAssembler;
pub use inference::InferenceEngine;
pub use candle_engine::CandleInferenceEngine;