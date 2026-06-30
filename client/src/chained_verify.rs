//! One-call chained AIR verification.
//!
//! [`verify_air_v1_receipt`] (the low-level building block) verifies a receipt
//! against an Ed25519 key the caller supplies; it deliberately does not touch
//! the platform attestation document, and never reports more than
//! [`AssuranceLevel::AirLocal`]. This module wires the full chain a production
//! verifier wants — verify the attestation document, take the receipt-signing
//! key from it, bind the receipt to it, run the layered verifier, and reconcile
//! measurements — and reports the resulting [`AssuranceLevel`] (UIUC/MATS
//! coordinated-disclosure finding #5).

use anyhow::{bail, Context, Result};
use ciborium::Value;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use ephemeral_ml_common::air_verify::{
    verify_air_v1_receipt, AirCheck, AirCheckStatus, AirVerifyPolicy, AirVerifyResult,
    AssuranceLevel,
};
use ephemeral_ml_common::PcrMeasurements;

use crate::attestation_verifier::AttestationVerifier;

/// Result of binding (and, for real documents, verifying) the attestation
/// document the receipt should chain to.
struct DocBinding {
    /// Receipt-signing key taken from the attestation document.
    signing_key: VerifyingKey,
    /// PCR measurements from a cryptographically verified document, if available.
    /// `None` for a mock document, which carries no verifiable measurements.
    measurements: Option<PcrMeasurements>,
    /// True only when the document's signature and certificate chain verified
    /// (the Nitro COSE_Sign1 path). A mock CBOR map is never `doc_verified`.
    doc_verified: bool,
}

fn bind_attestation(att_bytes: &[u8], allow_mock: bool) -> Result<DocBinding> {
    let doc: Value = ephemeral_ml_common::cbor::from_slice(att_bytes)
        .context("Invalid CBOR attestation document")?;

    match &doc {
        // Nitro COSE_Sign1 (untagged 4-element array): verify the signature and
        // certificate chain against the AWS Nitro root before trusting any
        // embedded value, then take the signing key and the measurements.
        Value::Array(arr) if arr.len() == 4 => {
            let policy = crate::PolicyManager::new();
            let mut verifier = AttestationVerifier::new(policy);
            let identity = verifier
                .verify_attestation_bytes_skip_nonce(att_bytes)
                .context(
                    "Attestation COSE signature or certificate chain verification failed; \
                     the attestation document is not authentic",
                )?;
            let signing_key = VerifyingKey::from_bytes(&identity.receipt_signing_key)
                .context("Invalid receipt signing key from verified attestation")?;
            Ok(DocBinding {
                signing_key,
                measurements: Some(identity.measurements),
                doc_verified: true,
            })
        }
        // Mock CBOR map: no cryptographic verification, no measurements.
        Value::Map(_) => {
            if !allow_mock {
                bail!(
                    "Attestation document is a plain CBOR map (mock format) without \
                     cryptographic verification; pass allow_mock to accept it for local testing"
                );
            }
            let signing_key = crate::receipt_key::extract_key_from_attestation(att_bytes, true)?;
            Ok(DocBinding {
                signing_key,
                measurements: None,
                doc_verified: false,
            })
        }
        _ => bail!("Attestation document is neither COSE_Sign1 nor a CBOR map"),
    }
}

/// TEE provenance requires a cryptographically verified document, successful
/// measurement reconciliation, a passing AIR-local verification, and a
/// production-mode receipt (an evaluation receipt is never TEE provenance,
/// regardless of the caller's policy). Anything else is AIR-local.
fn assurance_from(
    doc_verified: bool,
    reconciled: bool,
    air_verified: bool,
    production: bool,
) -> AssuranceLevel {
    if doc_verified && reconciled && air_verified && production {
        AssuranceLevel::TeeProvenance
    } else {
        AssuranceLevel::AirLocal
    }
}

/// Verify an AIR v1 receipt chained to its platform attestation document.
///
/// Steps:
/// 1. Verify the attestation document and extract the receipt-signing key
///    (Nitro COSE: signature + certificate chain vs the AWS Nitro root; a mock
///    CBOR map is accepted only when `allow_mock` is set).
/// 2. Pin `expected_attestation_doc_hash = SHA-256(attestation_bytes)` into the
///    policy (overriding any value the caller set), binding the receipt to this
///    document.
/// 3. Run the layered [`verify_air_v1_receipt`].
/// 4. Reconcile the receipt's `enclave_measurements` against the verified
///    document's PCRs via `EnclaveMeasurements::reconcile_against` (shared with
///    the hosted verifier), recorded as a `MEAS_RECONCILE` check. PCR0/1/2 must
///    match; any pcr3/pcr4/pcr8 present in the receipt fails closed because the
///    attestation identity exposes only PCR0/1/2. A mismatch fails verification;
///    an unverifiable/mock document is `Skip`.
/// 5. Report [`AssuranceLevel::TeeProvenance`] only when the document was
///    cryptographically verified, reconciliation passed, AIR-local verification
///    passed, and the receipt is production-mode; otherwise
///    [`AssuranceLevel::AirLocal`]. An evaluation receipt is never TEE
///    provenance, even if the caller set `allow_evaluation_mode`.
///
/// `TeeProvenance` asserts *platform* provenance (a verified, measured TEE) plus
/// PCR0/1/2 reconciliation — not that the *expected model or session* ran. To
/// bind those, pass a policy that pins them (e.g. [`AirVerifyPolicy::strict`], or
/// set `expected_model_hash`/`expected_model_id`); the chained verifier only adds
/// the attestation-doc-hash binding on top of the policy you supply.
///
/// This is the recommended production entry point; [`verify_air_v1_receipt`]
/// alone is a building block that never establishes TEE provenance.
pub fn verify_air_v1_receipt_chained(
    receipt_bytes: &[u8],
    attestation_bytes: &[u8],
    mut policy: AirVerifyPolicy,
    allow_mock: bool,
) -> Result<AirVerifyResult> {
    let binding = bind_attestation(attestation_bytes, allow_mock)?;

    // The chained verifier owns the document-hash binding.
    let doc_hash: [u8; 32] = Sha256::digest(attestation_bytes).into();
    policy.expected_attestation_doc_hash = Some(doc_hash);

    let mut result = verify_air_v1_receipt(receipt_bytes, &binding.signing_key, &policy);

    // Measurement reconciliation against the verified document's PCRs.
    let (status, detail, reconciled) = match (&binding.measurements, result.claims.as_ref()) {
        (Some(doc_m), Some(claims)) => {
            // Shared with the hosted verifier: PCR0/1/2 must match and any extra
            // self-asserted pcr3/4/8 fail closed.
            match claims.enclave_measurements.reconcile_against(doc_m) {
                None => (AirCheckStatus::Pass, None, true),
                Some(detail) => (AirCheckStatus::Fail, Some(detail), false),
            }
        }
        // Document verified but the receipt never decoded its claims: the
        // AIR-local result already failed; nothing to reconcile.
        (Some(_), None) => (
            AirCheckStatus::Skip,
            Some("receipt claims unavailable; AIR-local verification did not decode claims".to_string()),
            false,
        ),
        // No verifiable measurements (mock or unsupported document format).
        (None, _) => (
            AirCheckStatus::Skip,
            Some(
                "no verifiable measurements in attestation document (mock or unsupported format)"
                    .to_string(),
            ),
            false,
        ),
    };
    let reconcile_failed = matches!(status, AirCheckStatus::Fail);
    result.checks.push(AirCheck {
        name: "MEAS_RECONCILE",
        status,
        code: None,
        detail,
    });
    if reconcile_failed {
        result.verified = false;
    }

    // Production-mode floor: an evaluation receipt is never TEE provenance,
    // even if the caller's policy set allow_evaluation_mode = true.
    let is_production = result
        .claims
        .as_ref()
        .map(|c| c.security_mode == "production")
        .unwrap_or(false);
    result.assurance_level =
        assurance_from(binding.doc_verified, reconciled, result.verified, is_production);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_ml_common::air_receipt::{build_air_v1, AirReceiptClaims};
    use ephemeral_ml_common::air_verify::AirCheckCode;
    use ephemeral_ml_common::EnclaveMeasurements;
    use ephemeral_ml_common::receipt_signing::ReceiptSigningKey;
    use ephemeral_ml_common::WorkerAttestationUserData;

    /// Build a mock (plain CBOR map) attestation document embedding `pubkey`.
    /// `ud_model_hash` lets callers vary the encoded bytes (and thus the
    /// document hash) while keeping the same signing key.
    fn mock_attestation_doc(pubkey: [u8; 32], ud_model_hash: [u8; 32]) -> Vec<u8> {
        let user_data = WorkerAttestationUserData::new(pubkey, "minilm-l6-v2", ud_model_hash)
            .to_cbor()
            .unwrap();
        let map = Value::Map(vec![(
            Value::Text("user_data".to_string()),
            Value::Bytes(user_data),
        )]);
        ephemeral_ml_common::cbor::value_to_vec(&map).unwrap()
    }

    /// Build a receipt whose `attestation_doc_hash` is bound to `att_bytes`.
    fn receipt_bound_to(att_bytes: &[u8], key: &ReceiptSigningKey) -> Vec<u8> {
        let doc_hash: [u8; 32] = Sha256::digest(att_bytes).into();
        let claims = AirReceiptClaims {
            iss: "cyntrisec.com".to_string(),
            iat: 1_700_000_000,
            cti: *uuid::Uuid::new_v4().as_bytes(),
            eat_nonce: None,
            model_id: "minilm-l6-v2".to_string(),
            model_version: "1.0.0".to_string(),
            model_hash: [0xAA; 32],
            request_hash: [0xBB; 32],
            response_hash: [0xCC; 32],
            attestation_doc_hash: doc_hash,
            enclave_measurements: EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]),
            policy_version: "policy-2026.02".to_string(),
            sequence_number: 1,
            execution_time_ms: 10,
            memory_peak_mb: 64,
            security_mode: "production".to_string(),
            model_hash_scheme: Some("sha256-single".to_string()),
        };
        build_air_v1(&claims, key).unwrap()
    }

    #[test]
    fn reconcile_against_matches_pcr012_and_fails_closed_on_extra_pcrs() {
        let attested = PcrMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);

        let matching = EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);
        assert!(matching.reconcile_against(&attested).is_none());

        let mismatch = EnclaveMeasurements::new(vec![9u8; 48], vec![2u8; 48], vec![3u8; 48]);
        assert!(mismatch.reconcile_against(&attested).is_some());

        // Extra self-asserted PCRs the attestation cannot corroborate fail closed (#4).
        let mut extra = EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);
        extra.pcr8 = Some(vec![7u8; 48]);
        assert!(extra.reconcile_against(&attested).is_some());
    }

    #[test]
    fn assurance_decision_table() {
        // Only a verified document + reconciled measurements + a passing
        // AIR-local verification yields TEE provenance.
        assert_eq!(assurance_from(true, true, true, true), AssuranceLevel::TeeProvenance);
        assert_eq!(assurance_from(false, true, true, true), AssuranceLevel::AirLocal); // mock document
        assert_eq!(assurance_from(true, false, true, true), AssuranceLevel::AirLocal); // measurement mismatch
        assert_eq!(assurance_from(true, true, false, true), AssuranceLevel::AirLocal); // air-local failed
        assert_eq!(assurance_from(true, true, true, false), AssuranceLevel::AirLocal); // evaluation receipt
    }

    #[test]
    fn mock_chained_verify_is_air_local_not_provenance() {
        let key = ReceiptSigningKey::generate().unwrap();
        let att = mock_attestation_doc(key.public_key.to_bytes(), [0xAA; 32]);
        let receipt = receipt_bound_to(&att, &key);

        let result =
            verify_air_v1_receipt_chained(&receipt, &att, AirVerifyPolicy::unbounded(), true)
                .unwrap();

        assert!(result.verified, "failures: {:?}", result.failures());
        // A mock document can never reach TEE provenance.
        assert_eq!(result.assurance_level, AssuranceLevel::AirLocal);
        // The doc-hash binding (ADHASH) was pinned by the chained verifier and passed.
        assert!(result
            .checks
            .iter()
            .any(|c| c.name == "ADHASH" && matches!(c.status, AirCheckStatus::Pass)));
        // Reconciliation is skipped: a mock document carries no verifiable PCRs.
        assert!(result
            .checks
            .iter()
            .any(|c| c.name == "MEAS_RECONCILE" && matches!(c.status, AirCheckStatus::Skip)));
    }

    #[test]
    fn mock_doc_rejected_without_allow_mock() {
        let key = ReceiptSigningKey::generate().unwrap();
        let att = mock_attestation_doc(key.public_key.to_bytes(), [0xAA; 32]);
        let receipt = receipt_bound_to(&att, &key);
        let result =
            verify_air_v1_receipt_chained(&receipt, &att, AirVerifyPolicy::unbounded(), false);
        assert!(result.is_err(), "mock doc must be rejected unless allow_mock is set");
    }

    #[test]
    fn chained_verify_fails_when_receipt_bound_to_different_doc() {
        let key = ReceiptSigningKey::generate().unwrap();
        let att = mock_attestation_doc(key.public_key.to_bytes(), [0xAA; 32]);
        // Same signing key (signature still verifies), different bytes -> different hash.
        let other = mock_attestation_doc(key.public_key.to_bytes(), [0xBB; 32]);
        let receipt = receipt_bound_to(&att, &key); // bound to `att`

        let result =
            verify_air_v1_receipt_chained(&receipt, &other, AirVerifyPolicy::unbounded(), true)
                .unwrap();
        assert!(!result.verified, "receipt bound to a different document must fail");
        assert!(result.has_failure(&AirCheckCode::AttestationDocHashMismatch));
        assert_eq!(result.assurance_level, AssuranceLevel::AirLocal);
    }
}
