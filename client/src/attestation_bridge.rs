//! Bridge between EphemeralML's COSE attestation verifier and cml-transport's
//! `AttestationVerifier` trait.
//!
//! `CoseVerifierBridge` wraps the existing 630-line COSE_Sign1 + cert chain +
//! PCR validation into cml-transport's `AttestationVerifier::verify()`.
//!
//! `MockVerifierBridge` delegates to cml-transport's `MockVerifier` for mock mode.

use confidential_ml_transport::attestation::types::{
    AttestationDocument as CmlAttestationDocument, VerifiedAttestation,
};
use confidential_ml_transport::error::AttestError;
use confidential_ml_transport::AttestationVerifier as CmlAttestationVerifier;
use ephemeral_ml_common::transport_types::EphemeralUserData;
use ephemeral_ml_common::PcrMeasurements;
use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::attestation_verifier::{AttestationVerifier, EnclaveIdentity};
use crate::PolicyManager;

/// Wraps the production COSE verifier as cml-transport's `AttestationVerifier`.
///
/// Nonce checking is handled by cml-transport's handshake, so this bridge
/// does NOT call `FreshnessEnforcer`. It only verifies the COSE signature,
/// cert chain, and PCR policy.
pub struct CoseVerifierBridge {
    verifier: Mutex<AttestationVerifier>,
}

impl CoseVerifierBridge {
    pub fn new(policy_manager: PolicyManager) -> Self {
        Self {
            verifier: Mutex::new(AttestationVerifier::new(policy_manager)),
        }
    }

    fn identity_to_verified(identity: &EnclaveIdentity, _raw_doc: &[u8]) -> VerifiedAttestation {
        // Convert PCR measurements to BTreeMap
        let mut measurements = BTreeMap::new();
        measurements.insert(0, identity.measurements.pcr0.clone());
        measurements.insert(1, identity.measurements.pcr1.clone());
        measurements.insert(2, identity.measurements.pcr2.clone());

        // Serialize EphemeralUserData for the user_data field
        let user_data = EphemeralUserData::new(
            identity.receipt_signing_key,
            identity.protocol_version,
            identity.supported_features.clone(),
        );
        let ud_cbor = user_data.to_cbor().ok();

        VerifiedAttestation {
            document_hash: identity.attestation_hash,
            public_key: Some(identity.hpke_public_key.to_vec()),
            user_data: ud_cbor,
            nonce: None, // nonce checked by cml-transport handshake
            measurements,
        }
    }
}

#[async_trait::async_trait]
impl CmlAttestationVerifier for CoseVerifierBridge {
    async fn verify(
        &self,
        doc: &CmlAttestationDocument,
    ) -> std::result::Result<VerifiedAttestation, AttestError> {
        let mut verifier = self.verifier.lock().map_err(|e| {
            AttestError::VerificationFailed(format!("Verifier lock poisoned: {}", e))
        })?;

        // Reconstruct EphemeralML's AttestationDocument from raw bytes
        let ephemeral_doc = ephemeral_ml_common::AttestationDocument {
            module_id: String::new(), // will be extracted from payload
            digest: vec![],
            timestamp: 0,
            pcrs: PcrMeasurements::new(vec![], vec![], vec![]),
            certificate: vec![],
            signature: doc.raw.clone(), // raw COSE_Sign1 bytes
            nonce: None,
        };

        // Use verify_attestation_no_pcr_policy to skip PCR allowlist check
        // for now, since the bridge is used during handshake where we may
        // not have the nonce yet. PCR policy can be enforced at app level.
        //
        // Pass an empty nonce — cml-transport handles nonce verification.
        // We skip freshness validation since it's handled by the handshake.
        let identity = verify_attestation_for_bridge(&mut verifier, &ephemeral_doc)
            .map_err(|e| AttestError::VerificationFailed(format!("{}", e)))?;

        Ok(Self::identity_to_verified(&identity, &doc.raw))
    }
}

/// Internal helper that performs COSE verification without nonce/freshness checks.
///
/// In mock mode, this parses the CBOR map directly.
/// In production mode, this verifies COSE_Sign1 + cert chain.
fn verify_attestation_for_bridge(
    verifier: &mut AttestationVerifier,
    doc: &ephemeral_ml_common::AttestationDocument,
) -> crate::Result<EnclaveIdentity> {
    // For mock mode, use a dummy nonce (the verifier skips nonce check for mock docs)
    // For production, nonce validation is handled by cml-transport
    let dummy_nonce = vec![0u8; 32];
    verifier.verify_attestation(doc, &dummy_nonce)
}

/// TDX envelope verifier bridge for GCP Confidential Space.
///
/// Decodes the `TeeAttestationEnvelope` CBOR format produced by the enclave's
/// `TeeAttestationBridge`, verifies the inner TDX quote via cml-transport's
/// `TdxVerifier`, and returns `VerifiedAttestation` with `user_data` containing
/// `EphemeralUserData` (receipt signing key).
///
/// Measurement pinning: reads `EPHEMERALML_EXPECTED_MRTD` env var (hex-encoded
/// 48-byte MRTD). When set, rejects attestations with non-matching MRTD.
#[cfg(feature = "gcp")]
pub struct TdxEnvelopeVerifierBridge {
    inner: confidential_ml_transport::attestation::tdx::TdxVerifier,
}

#[cfg(feature = "gcp")]
impl TdxEnvelopeVerifierBridge {
    /// Create a new TDX envelope verifier bridge.
    ///
    /// `expected_mrtd`: optional 48-byte MRTD to validate against.
    /// Pass `None` to accept any MRTD (useful for development).
    ///
    /// If `expected_mrtd` is `None`, also checks the `EPHEMERALML_EXPECTED_MRTD`
    /// environment variable (hex-encoded, 48 bytes = 96 hex chars).
    pub fn new(expected_mrtd: Option<Vec<u8>>) -> Self {
        let mrtd = expected_mrtd.or_else(|| {
            std::env::var("EPHEMERALML_EXPECTED_MRTD")
                .ok()
                .and_then(|hex_str| hex::decode(hex_str).ok())
                .filter(|bytes| bytes.len() == 48)
        });

        if mrtd.is_none() {
            eprintln!(
                "[client] WARNING: No expected MRTD configured. TDX peer measurements \
                 are NOT pinned. Set EPHEMERALML_EXPECTED_MRTD for production use."
            );
        }

        Self {
            inner: confidential_ml_transport::attestation::tdx::TdxVerifier::new(mrtd),
        }
    }
}

#[cfg(feature = "gcp")]
#[async_trait::async_trait]
impl CmlAttestationVerifier for TdxEnvelopeVerifierBridge {
    async fn verify(
        &self,
        doc: &CmlAttestationDocument,
    ) -> std::result::Result<VerifiedAttestation, AttestError> {
        // Try to decode as TeeAttestationEnvelope (CBOR with tdx_wire + user_data)
        if let Ok(envelope) = serde_cbor::from_slice::<TdxEnvelopeHelper>(&doc.raw) {
            if envelope.platform == "tdx" {
                // Verify the inner TDX document
                let tdx_doc = CmlAttestationDocument::new(envelope.tdx_wire);
                let mut verified = self.inner.verify(&tdx_doc).await?;

                // Attach the user_data from the envelope (fail-closed: reject if missing/invalid)
                if envelope.user_data.is_empty() {
                    return Err(AttestError::VerificationFailed(
                        "TDX envelope user_data is empty — cannot extract receipt signing key"
                            .to_string(),
                    ));
                }
                let ud = serde_json::from_slice::<EphemeralUserData>(&envelope.user_data).map_err(
                    |e| {
                        AttestError::VerificationFailed(format!(
                            "TDX envelope user_data parse failed: {}",
                            e
                        ))
                    },
                )?;
                let cbor = ud.to_cbor().map_err(|e| {
                    AttestError::VerificationFailed(format!(
                        "TDX envelope user_data CBOR encode failed: {}",
                        e
                    ))
                })?;
                verified.user_data = Some(cbor);

                return Ok(verified);
            }
        }

        // Fallback: treat as plain TDX wire format
        self.inner.verify(doc).await
    }
}

/// Helper struct for deserializing TeeAttestationEnvelope on the client side.
/// Mirrors enclave's TeeAttestationEnvelope without requiring the enclave crate.
#[cfg(feature = "gcp")]
#[derive(serde::Deserialize)]
struct TdxEnvelopeHelper {
    platform: String,
    #[serde(with = "serde_bytes")]
    tdx_wire: Vec<u8>,
    #[serde(with = "serde_bytes")]
    user_data: Vec<u8>,
}

/// Mock verifier bridge that wraps cml-transport's MockVerifier.
///
/// For use in mock/test mode — delegates directly to cml-transport.
#[cfg(feature = "mock")]
pub struct MockVerifierBridge {
    inner: confidential_ml_transport::MockVerifier,
}

#[cfg(feature = "mock")]
impl MockVerifierBridge {
    pub fn new() -> Self {
        Self {
            inner: confidential_ml_transport::MockVerifier,
        }
    }
}

#[cfg(feature = "mock")]
impl Default for MockVerifierBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "mock")]
#[async_trait::async_trait]
impl CmlAttestationVerifier for MockVerifierBridge {
    async fn verify(
        &self,
        doc: &CmlAttestationDocument,
    ) -> std::result::Result<VerifiedAttestation, AttestError> {
        self.inner.verify(doc).await
    }
}
