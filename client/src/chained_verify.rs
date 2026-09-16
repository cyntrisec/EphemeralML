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
    verify_air_v1_receipt, AirCheck, AirCheckCode, AirCheckStatus, AirVerifyPolicy,
    AirVerifyResult, AssuranceLevel,
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
/// measurement reconciliation (the receipt did not lie about the document's
/// registers), successful measurement *appraisal* (the document's registers
/// match the caller's reference / known-good set), a passing AIR-local
/// verification, and a production-labeled receipt. The self-asserted
/// `security_mode` carries no positive weight by itself; it is only a
/// fail-closed floor after the cryptographic and appraisal checks. Anything
/// else is AIR-local.
fn assurance_from(
    doc_verified: bool,
    reconciled: bool,
    appraised: bool,
    air_verified: bool,
    production_labeled: bool,
) -> AssuranceLevel {
    if doc_verified && reconciled && appraised && air_verified && production_labeled {
        AssuranceLevel::TeeProvenance
    } else {
        AssuranceLevel::AirLocal
    }
}

fn appraise_measurements(
    document: Option<&PcrMeasurements>,
    reference: Option<&PcrMeasurements>,
) -> (AirCheckStatus, Option<String>, bool) {
    match (document, reference) {
        (Some(document), Some(reference)) if document == reference => {
            (AirCheckStatus::Pass, None, true)
        }
        (Some(_), Some(_)) => (
            AirCheckStatus::Fail,
            Some(
                "attestation measurements do not match the reference (known-good) values"
                    .to_string(),
            ),
            false,
        ),
        (Some(_), None) => (
            AirCheckStatus::Skip,
            Some(
                "no reference measurements supplied (policy.expected_measurements is None); \
                 cannot establish TEE provenance"
                    .to_string(),
            ),
            false,
        ),
        (None, _) => (
            AirCheckStatus::Skip,
            Some("no verifiable measurements in attestation document".to_string()),
            false,
        ),
    }
}

/// Verify an AIR v1 receipt chained to its platform attestation document.
///
/// Steps:
/// 1. Verify the attestation document and extract the receipt-signing key
///    (Nitro COSE: signature + certificate chain vs the AWS Nitro root; a mock
///    CBOR map is accepted only when `allow_mock` is set).
/// 2. Pin `expected_attestation_doc_hash = SHA-256(attestation_bytes)` into the
///    policy (requiring any value the caller already pinned to match), binding
///    the receipt to this document.
/// 3. Run the layered [`verify_air_v1_receipt`].
/// 4. Reconcile the receipt's `enclave_measurements` against the verified
///    document's PCRs via `EnclaveMeasurements::reconcile_against` (shared with
///    the hosted verifier), recorded as a `MEAS_RECONCILE` check. PCR0/1/2 must
///    match; any pcr3/pcr4/pcr8 present in the receipt fails closed because the
///    attestation identity exposes only PCR0/1/2. A mismatch fails verification;
///    an unverifiable/mock document is `Skip`.
/// 5. Report [`AssuranceLevel::TeeProvenance`] only when the document was
///    cryptographically verified, reconciliation passed, the measurements were
///    appraised against the policy's reference values
///    (`expected_measurements`), AIR-local verification passed, and the receipt
///    is production-labeled; otherwise [`AssuranceLevel::AirLocal`]. The label
///    grants no positive weight by itself; evaluation receipts are never TEE
///    provenance.
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

    // Bind the receipt to the supplied document. If the caller pinned a
    // known-good `expected_attestation_doc_hash`, it MUST equal the supplied
    // document's hash -- do not silently override the caller's pin.
    let doc_hash: [u8; 32] = Sha256::digest(attestation_bytes).into();
    if let Some(caller_pin) = policy.expected_attestation_doc_hash {
        if caller_pin != doc_hash {
            bail!(
                "policy.expected_attestation_doc_hash does not match the supplied \
                 attestation document"
            );
        }
    }
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
            Some(
                "receipt claims unavailable; AIR-local verification did not decode claims"
                    .to_string(),
            ),
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
        code: reconcile_failed.then_some(AirCheckCode::MeasurementReconciliationMismatch),
        detail,
    });
    if reconcile_failed {
        result.verified = false;
    }

    // Appraisal: does the verified document's measurement set match the caller's
    // reference (known-good) values? Reconciliation above proves the receipt did
    // not lie about the document's registers; appraisal proves the document's
    // registers are the approved ones. Without a reference set, TEE provenance
    // cannot be established and assurance remains AIR-local.
    //
    // Coverage is limited to the three registers exposed by `PcrMeasurements`.
    // Reconciliation fails closed if the receipt asserts additional registers
    // that the verified document representation cannot corroborate.
    let (appraise_status, appraise_detail, appraised) = appraise_measurements(
        binding.measurements.as_ref(),
        policy.expected_measurements.as_ref(),
    );
    let appraise_failed = matches!(appraise_status, AirCheckStatus::Fail);
    let appraise_skipped = matches!(appraise_status, AirCheckStatus::Skip);
    result.checks.push(AirCheck {
        name: "MEAS_APPRAISE",
        status: appraise_status,
        code: appraise_failed.then_some(AirCheckCode::MeasurementAppraisalMismatch),
        detail: appraise_detail,
    });
    if appraise_failed {
        result.verified = false;
    }
    if appraise_skipped && !result.skipped_identity_checks.contains(&"MEAS_APPRAISE") {
        result.skipped_identity_checks.push("MEAS_APPRAISE");
    }

    // Fail closed on the exact production label. This claim grants no assurance
    // by itself, but evaluation or any future mode must not inherit production
    // provenance accidentally.
    let production_labeled = result
        .claims
        .as_ref()
        .map(|c| c.security_mode == "production")
        .unwrap_or(false);
    result.assurance_level = assurance_from(
        binding.doc_verified,
        reconciled,
        appraised,
        result.verified,
        production_labeled,
    );

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_ml_common::air_receipt::{build_air_v1, AirReceiptClaims};
    use ephemeral_ml_common::receipt_signing::ReceiptSigningKey;
    use ephemeral_ml_common::EnclaveMeasurements;
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
            enclave_measurements: EnclaveMeasurements::new(
                vec![1u8; 48],
                vec![2u8; 48],
                vec![3u8; 48],
            ),
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
    fn assurance_requires_appraisal_and_production_label() {
        // Signature: (doc_verified, reconciled, appraised, air_verified, production_labeled).
        assert_eq!(
            assurance_from(true, true, true, true, true),
            AssuranceLevel::TeeProvenance
        );
        // A verified, reconciled document that is not appraised against known-good
        // measurements does not get provenance.
        assert_eq!(
            assurance_from(true, true, false, true, true),
            AssuranceLevel::AirLocal
        );
        assert_eq!(
            assurance_from(false, true, true, true, true),
            AssuranceLevel::AirLocal
        ); // mock / unverified document
        assert_eq!(
            assurance_from(true, false, true, true, true),
            AssuranceLevel::AirLocal
        ); // reconcile mismatch
        assert_eq!(
            assurance_from(true, true, true, false, true),
            AssuranceLevel::AirLocal
        ); // air-local failed
        assert_eq!(
            assurance_from(true, true, true, true, false),
            AssuranceLevel::AirLocal
        ); // evaluation receipt
    }

    #[test]
    fn appraisal_requires_exact_reference_measurements() {
        let document = PcrMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);
        let matching = document.clone();
        let mismatch = PcrMeasurements::new(vec![9u8; 48], vec![2u8; 48], vec![3u8; 48]);

        let (status, _, appraised) = appraise_measurements(Some(&document), Some(&matching));
        assert!(matches!(status, AirCheckStatus::Pass));
        assert!(appraised);

        let (status, _, appraised) = appraise_measurements(Some(&document), Some(&mismatch));
        assert!(matches!(status, AirCheckStatus::Fail));
        assert!(!appraised);

        let (status, _, appraised) = appraise_measurements(Some(&document), None);
        assert!(matches!(status, AirCheckStatus::Skip));
        assert!(!appraised);
    }

    #[test]
    fn production_receipt_without_reference_measurements_is_air_local() {
        // A receipt self-marked security_mode="production" with no reference
        // measurements in the policy must not reach provenance: MEAS_APPRAISE is
        // skipped and assurance stays AIR-local.
        let key = ReceiptSigningKey::generate().unwrap();
        let att = mock_attestation_doc(key.public_key.to_bytes(), [0xAA; 32]);
        let receipt = receipt_bound_to(&att, &key); // security_mode = "production"
        let result =
            verify_air_v1_receipt_chained(&receipt, &att, AirVerifyPolicy::unbounded(), true)
                .unwrap();
        assert_eq!(result.assurance_level, AssuranceLevel::AirLocal);
        assert!(result
            .checks
            .iter()
            .any(|c| c.name == "MEAS_APPRAISE" && matches!(c.status, AirCheckStatus::Skip)));
        assert!(result.skipped_identity_checks.contains(&"MEAS_APPRAISE"));
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
        assert!(
            result.is_err(),
            "mock doc must be rejected unless allow_mock is set"
        );
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
        assert!(
            !result.verified,
            "receipt bound to a different document must fail"
        );
        assert!(result.has_failure(&AirCheckCode::AttestationDocHashMismatch));
        assert_eq!(result.assurance_level, AssuranceLevel::AirLocal);
    }

    #[test]
    fn chained_verify_rejects_conflicting_caller_document_pin() {
        let key = ReceiptSigningKey::generate().unwrap();
        let att = mock_attestation_doc(key.public_key.to_bytes(), [0xAA; 32]);
        let receipt = receipt_bound_to(&att, &key);
        let mut policy = AirVerifyPolicy::unbounded();
        policy.expected_attestation_doc_hash = Some([0xFF; 32]);

        let error = verify_air_v1_receipt_chained(&receipt, &att, policy, true)
            .expect_err("a conflicting caller pin must not be overwritten");
        assert!(error
            .to_string()
            .contains("does not match the supplied attestation document"));
    }
}
