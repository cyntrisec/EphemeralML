pub mod error;
pub mod attestation;
pub mod kms_client;
pub mod assembly;
pub mod inference;

#[cfg(feature = "mock")]
pub mod mock;

// Re-export common types and enclave-specific types
pub use ephemeral_ml_common::*;
pub use error::{EnclaveError, Result};
pub use attestation::{AttestationProvider, DefaultAttestationProvider, AttestationUserData, EphemeralKeyPair};
pub use assembly::EphemeralAssembler;
pub use inference::InferenceEngine;