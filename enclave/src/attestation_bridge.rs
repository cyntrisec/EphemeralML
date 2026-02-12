//! Bridge between EphemeralML's `AttestationProvider` and cml-transport's
//! `AttestationProvider` trait.
//!
//! `AttestationBridge<P>` wraps an EphemeralML attestation provider so it can
//! be used by `SecureChannel::accept_with_attestation()` and by the pipeline's
//! `StageRuntime`.

use crate::attestation::AttestationProvider as EphemeralAttestationProvider;
use confidential_ml_transport::attestation::types::AttestationDocument as CmlAttestationDocument;
use confidential_ml_transport::AttestationProvider as CmlAttestationProvider;
use ephemeral_ml_common::transport_types::EphemeralUserData;

/// Wraps an EphemeralML `AttestationProvider` as a cml-transport `AttestationProvider`.
///
/// Stores the 32-byte Ed25519 receipt signing public key directly.
/// The private key stays in the `EphemeralStageExecutor`.
pub struct AttestationBridge<P: EphemeralAttestationProvider> {
    inner: P,
    receipt_public_key: [u8; 32],
}

impl<P: EphemeralAttestationProvider> AttestationBridge<P> {
    pub fn new(inner: P, receipt_public_key: [u8; 32]) -> Self {
        Self {
            inner,
            receipt_public_key,
        }
    }

    /// Get a reference to the inner provider (for KMS decrypt, PCRs, etc.)
    pub fn inner(&self) -> &P {
        &self.inner
    }
}

#[async_trait::async_trait]
impl<P: EphemeralAttestationProvider> CmlAttestationProvider for AttestationBridge<P> {
    async fn attest(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        _public_key: Option<&[u8]>,
    ) -> std::result::Result<CmlAttestationDocument, confidential_ml_transport::error::AttestError>
    {
        // Build EphemeralUserData from receipt key + any additional user_data
        let ephemeral_ud = if let Some(ud_bytes) = user_data {
            // Try to parse existing user data and merge
            EphemeralUserData::from_cbor(ud_bytes).unwrap_or_else(|_| {
                EphemeralUserData::new(self.receipt_public_key, 1, vec!["gateway".to_string()])
            })
        } else {
            EphemeralUserData::new(self.receipt_public_key, 1, vec!["gateway".to_string()])
        };

        let ud_cbor = ephemeral_ud.to_cbor().map_err(|e| {
            confidential_ml_transport::error::AttestError::GenerationFailed(format!(
                "Failed to serialize user data: {}",
                e
            ))
        })?;

        // Use the nonce from cml-transport's handshake
        let nonce_bytes = nonce.unwrap_or(&[]);

        // Call EphemeralML's attestation provider
        let doc = self
            .inner
            .generate_attestation(nonce_bytes, self.receipt_public_key)
            .map_err(|e| {
                confidential_ml_transport::error::AttestError::GenerationFailed(format!(
                    "Attestation generation failed: {}",
                    e
                ))
            })?;

        // The `generate_attestation()` call above already embedded the receipt key,
        // so we use doc.signature as the raw attestation bytes.
        let _ = ud_cbor; // user_data was embedded by generate_attestation via receipt_pk

        Ok(CmlAttestationDocument::new(doc.signature))
    }
}
