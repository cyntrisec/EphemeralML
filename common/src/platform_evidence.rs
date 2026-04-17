//! Canonical platform evidence bundle for environment-level attestation facts.
//!
//! This sidecar is intentionally separate from AIR v1 receipts:
//! - AIR v1 captures per-inference facts.
//! - Platform evidence captures boot/session environment facts.
//! - Transport attestation binds the session to a hash of this bundle.
//!
//! # Hash stability
//!
//! [`PlatformEvidenceBundle::document_hash`] excludes the `generated_at`
//! timestamp from the hash input so the hash is stable across enclave reboots
//! that produce otherwise-identical evidence. The timestamp is still present
//! in the serialized CBOR for operational visibility — verifiers compare the
//! *canonical* hash, not the full-CBOR hash.

use crate::error::{EphemeralError, Result};
use serde::{Deserialize, Serialize};

/// Platform evidence bundle format version.
pub const PLATFORM_EVIDENCE_V1: u32 = 1;

/// Canonical environment evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformEvidenceBundle {
    /// Bundle schema version.
    pub version: u32,
    /// Human-readable deployment profile (for example `gcp-cvm-tdx`).
    pub platform_profile: String,
    /// Informational generation timestamp (Unix seconds).
    pub generated_at: u64,
    /// Cryptographic binding material shared across evidence layers.
    pub binding: EvidenceBinding,
    /// CPU / TEE evidence summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuEvidenceSummary>,
    /// GPU evidence summary (optional until direct GPU attestation is integrated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuEvidenceSummary>,
    /// Cloud / launcher evidence summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<CloudEvidenceSummary>,
    /// Appraisal and policy metadata.
    pub verifier: EvidenceVerifierSummary,
}

/// Cross-layer binding material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBinding {
    pub receipt_signing_key: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hpke_public_key: Option<[u8; 32]>,
    pub model_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hash: Option<[u8; 32]>,
    /// The primary attestation artifact already referenced by receipts today.
    pub base_attestation_hash: [u8; 32],
}

/// CPU/TEE evidence summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuEvidenceSummary {
    pub tee_type: String,
    pub measurement_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub measurements: Vec<MeasurementEntry>,
}

/// A single measurement register/value pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasurementEntry {
    pub index: u8,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

/// GPU evidence summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuEvidenceSummary {
    pub vendor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cc_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measres: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secboot: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dbgstat: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vbios_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rim_status: Option<String>,
    pub evidence_hashes: GpuEvidenceHashes,
}

/// Hashes of raw vendor evidence artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GpuEvidenceHashes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_evidence_sha256: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims_json_sha256: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detached_eat_sha256: Option<[u8; 32]>,
}

/// Cloud-side evidence summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudEvidenceSummary {
    pub attestation_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher_jwt_sha256: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
}

/// Appraisal metadata for the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceVerifierSummary {
    pub cpu_verifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_verifier: Option<String>,
    pub policy_version: String,
}

/// Canonical projection of [`PlatformEvidenceBundle`] used for hashing.
///
/// Excludes `generated_at` so the hash stays stable across reboots when the
/// rest of the evidence is unchanged. Any field added here participates in
/// the attested binding; any field added only to the outer bundle does not.
#[derive(Serialize)]
struct CanonicalBundle<'a> {
    version: u32,
    platform_profile: &'a str,
    binding: &'a EvidenceBinding,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu: &'a Option<CpuEvidenceSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gpu: &'a Option<GpuEvidenceSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cloud: &'a Option<CloudEvidenceSummary>,
    verifier: &'a EvidenceVerifierSummary,
}

impl PlatformEvidenceBundle {
    fn canonical(&self) -> CanonicalBundle<'_> {
        CanonicalBundle {
            version: self.version,
            platform_profile: &self.platform_profile,
            binding: &self.binding,
            cpu: &self.cpu,
            gpu: &self.gpu,
            cloud: &self.cloud,
            verifier: &self.verifier,
        }
    }

    /// Encode as deterministic CBOR for operator export / on-disk storage.
    ///
    /// Includes `generated_at`. Not used for hashing — see [`document_hash`].
    pub fn to_cbor_deterministic(&self) -> Result<Vec<u8>> {
        let value = crate::cbor::to_value(self).map_err(|e| {
            EphemeralError::SerializationError(format!(
                "PlatformEvidenceBundle CBOR value conversion failed: {}",
                e
            ))
        })?;
        crate::cbor::value_to_vec(&value).map_err(|e| {
            EphemeralError::SerializationError(format!(
                "PlatformEvidenceBundle CBOR encoding failed: {}",
                e
            ))
        })
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        crate::cbor::from_slice(data).map_err(|e| {
            EphemeralError::SerializationError(format!(
                "PlatformEvidenceBundle CBOR decoding failed: {}",
                e
            ))
        })
    }

    /// Stable hash used for attested binding. Excludes `generated_at`.
    pub fn document_hash(&self) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let value = crate::cbor::to_value(&self.canonical()).map_err(|e| {
            EphemeralError::SerializationError(format!(
                "PlatformEvidenceBundle canonical CBOR value conversion failed: {}",
                e
            ))
        })?;
        let cbor = crate::cbor::value_to_vec(&value).map_err(|e| {
            EphemeralError::SerializationError(format!(
                "PlatformEvidenceBundle canonical CBOR encoding failed: {}",
                e
            ))
        })?;
        Ok(Sha256::digest(&cbor).into())
    }

    /// Verify a received bundle against the hash + binding fields that were
    /// attested separately (e.g. embedded in attestation `user_data`).
    ///
    /// Decodes `bundle_bytes`, recomputes the canonical hash, and compares:
    /// - `document_hash()` == `expected_hash`
    /// - `binding.receipt_signing_key` == `expected_signing_key`
    /// - `binding.base_attestation_hash` == `expected_attestation_hash`
    ///
    /// Returns the decoded bundle on success, or an `AttestationError`
    /// identifying the specific mismatch on failure.
    pub fn verify_binding(
        bundle_bytes: &[u8],
        expected_hash: &[u8; 32],
        expected_signing_key: &[u8; 32],
        expected_attestation_hash: &[u8; 32],
    ) -> Result<Self> {
        let bundle = Self::from_cbor(bundle_bytes)?;
        let actual_hash = bundle.document_hash()?;
        if actual_hash != *expected_hash {
            return Err(EphemeralError::AttestationError(format!(
                "platform evidence hash mismatch: expected {}, got {}",
                hex::encode(expected_hash),
                hex::encode(actual_hash),
            )));
        }
        if &bundle.binding.receipt_signing_key != expected_signing_key {
            return Err(EphemeralError::AttestationError(format!(
                "platform evidence binding.receipt_signing_key mismatch: \
                 expected {}, got {}",
                hex::encode(expected_signing_key),
                hex::encode(bundle.binding.receipt_signing_key),
            )));
        }
        if &bundle.binding.base_attestation_hash != expected_attestation_hash {
            return Err(EphemeralError::AttestationError(format!(
                "platform evidence binding.base_attestation_hash mismatch: \
                 expected {}, got {}",
                hex::encode(expected_attestation_hash),
                hex::encode(bundle.binding.base_attestation_hash),
            )));
        }
        Ok(bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundle() -> PlatformEvidenceBundle {
        PlatformEvidenceBundle {
            version: PLATFORM_EVIDENCE_V1,
            platform_profile: "gcp-cvm-tdx".to_string(),
            generated_at: 1_744_500_000,
            binding: EvidenceBinding {
                receipt_signing_key: [0x11; 32],
                hpke_public_key: Some([0x22; 32]),
                model_id: "stage-0".to_string(),
                model_hash: Some([0x33; 32]),
                base_attestation_hash: [0x44; 32],
            },
            cpu: Some(CpuEvidenceSummary {
                tee_type: "tdx".to_string(),
                measurement_type: "tdx-mrtd-rtmr".to_string(),
                measurements: vec![
                    MeasurementEntry {
                        index: 0,
                        value: vec![0xAA; 48],
                    },
                    MeasurementEntry {
                        index: 1,
                        value: vec![0xBB; 48],
                    },
                ],
            }),
            gpu: None,
            cloud: Some(CloudEvidenceSummary {
                attestation_source: "cs-tdx".to_string(),
                launcher_jwt_sha256: Some([0x55; 32]),
                image_digest: Some("sha256:deadbeef".to_string()),
                project_id: Some("project-1".to_string()),
                zone: Some("us-central1-a".to_string()),
            }),
            verifier: EvidenceVerifierSummary {
                cpu_verifier: "cml-transport-tdx".to_string(),
                gpu_verifier: Some("launcher-only".to_string()),
                policy_version: "v1-default".to_string(),
            },
        }
    }

    #[test]
    fn platform_evidence_hash_is_stable() {
        let bundle = sample_bundle();
        let h1 = bundle.document_hash().unwrap();
        let h2 = bundle.document_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn platform_evidence_roundtrip_cbor() {
        let bundle = sample_bundle();
        let cbor = bundle.to_cbor_deterministic().unwrap();
        let decoded = PlatformEvidenceBundle::from_cbor(&cbor).unwrap();
        assert_eq!(decoded, bundle);
    }

    /// Regression for C-2: document_hash must ignore generated_at so the
    /// attested binding survives enclave reboots that produce otherwise
    /// identical evidence.
    #[test]
    fn platform_evidence_hash_ignores_generated_at() {
        let mut bundle = sample_bundle();
        let hash_a = bundle.document_hash().unwrap();
        bundle.generated_at = bundle.generated_at.wrapping_add(3_600);
        let hash_b = bundle.document_hash().unwrap();
        assert_eq!(hash_a, hash_b, "hash must not depend on generated_at");
    }

    /// Any change to a field that *does* participate in the canonical hash
    /// must move the hash.
    #[test]
    fn platform_evidence_hash_tracks_canonical_fields() {
        let base = sample_bundle();
        let base_hash = base.document_hash().unwrap();

        let mut with_different_profile = base.clone();
        with_different_profile.platform_profile = "aws-nitro-enclave".to_string();
        assert_ne!(base_hash, with_different_profile.document_hash().unwrap());

        let mut with_different_binding = base.clone();
        with_different_binding.binding.receipt_signing_key = [0x99; 32];
        assert_ne!(base_hash, with_different_binding.document_hash().unwrap());

        let mut with_different_attestation = base.clone();
        with_different_attestation.binding.base_attestation_hash = [0x88; 32];
        assert_ne!(
            base_hash,
            with_different_attestation.document_hash().unwrap()
        );
    }

    /// End-to-end binding check (fixes M-1): produce a bundle on one side,
    /// ship the CBOR + the `document_hash` + the expected binding fields
    /// over an attested side channel, and prove the verifier-side helper
    /// accepts them together.
    #[test]
    fn verify_binding_accepts_matching_bundle() {
        let bundle = sample_bundle();
        let bytes = bundle.to_cbor_deterministic().unwrap();
        let hash = bundle.document_hash().unwrap();
        let verified = PlatformEvidenceBundle::verify_binding(
            &bytes,
            &hash,
            &bundle.binding.receipt_signing_key,
            &bundle.binding.base_attestation_hash,
        )
        .expect("valid bundle should verify");
        assert_eq!(verified, bundle);
    }

    /// Accept a bundle whose `generated_at` differs from the producer's copy
    /// as long as the canonical fields (and thus `document_hash`) match.
    /// This is what lets the hash survive reboots.
    #[test]
    fn verify_binding_accepts_timestamp_drift() {
        let bundle_t0 = sample_bundle();
        let hash = bundle_t0.document_hash().unwrap();
        let mut bundle_t1 = bundle_t0.clone();
        bundle_t1.generated_at = bundle_t0.generated_at + 86_400;
        let bytes_t1 = bundle_t1.to_cbor_deterministic().unwrap();
        let verified = PlatformEvidenceBundle::verify_binding(
            &bytes_t1,
            &hash,
            &bundle_t0.binding.receipt_signing_key,
            &bundle_t0.binding.base_attestation_hash,
        )
        .expect("timestamp drift must not break binding");
        assert_eq!(verified.generated_at, bundle_t1.generated_at);
    }

    #[test]
    fn verify_binding_rejects_wrong_hash() {
        let bundle = sample_bundle();
        let bytes = bundle.to_cbor_deterministic().unwrap();
        let wrong_hash = [0xFF; 32];
        let err = PlatformEvidenceBundle::verify_binding(
            &bytes,
            &wrong_hash,
            &bundle.binding.receipt_signing_key,
            &bundle.binding.base_attestation_hash,
        )
        .unwrap_err();
        match err {
            EphemeralError::AttestationError(msg) => {
                assert!(msg.contains("hash mismatch"), "unexpected message: {}", msg);
            }
            other => panic!("expected AttestationError, got {:?}", other),
        }
    }

    #[test]
    fn verify_binding_rejects_wrong_signing_key() {
        let bundle = sample_bundle();
        let bytes = bundle.to_cbor_deterministic().unwrap();
        let hash = bundle.document_hash().unwrap();
        let err = PlatformEvidenceBundle::verify_binding(
            &bytes,
            &hash,
            &[0xDE; 32],
            &bundle.binding.base_attestation_hash,
        )
        .unwrap_err();
        match err {
            EphemeralError::AttestationError(msg) => {
                assert!(
                    msg.contains("receipt_signing_key"),
                    "unexpected message: {}",
                    msg
                );
            }
            other => panic!("expected AttestationError, got {:?}", other),
        }
    }

    #[test]
    fn verify_binding_rejects_wrong_attestation_hash() {
        let bundle = sample_bundle();
        let bytes = bundle.to_cbor_deterministic().unwrap();
        let hash = bundle.document_hash().unwrap();
        let err = PlatformEvidenceBundle::verify_binding(
            &bytes,
            &hash,
            &bundle.binding.receipt_signing_key,
            &[0xAD; 32],
        )
        .unwrap_err();
        match err {
            EphemeralError::AttestationError(msg) => {
                assert!(
                    msg.contains("base_attestation_hash"),
                    "unexpected message: {}",
                    msg
                );
            }
            other => panic!("expected AttestationError, got {:?}", other),
        }
    }

    #[test]
    fn verify_binding_rejects_tampered_bytes() {
        let bundle = sample_bundle();
        let hash = bundle.document_hash().unwrap();
        let mut tampered = bundle.to_cbor_deterministic().unwrap();
        // Flip the last byte of the encoded CBOR so the decoder either fails
        // or (more interestingly) produces a struct with a different hash.
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let result = PlatformEvidenceBundle::verify_binding(
            &tampered,
            &hash,
            &bundle.binding.receipt_signing_key,
            &bundle.binding.base_attestation_hash,
        );
        // Either CBOR parse fails (SerializationError) or the recomputed hash
        // differs (AttestationError). Both count as "rejected".
        assert!(result.is_err(), "tampered bundle must not verify");
    }
}
