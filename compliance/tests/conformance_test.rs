//! Receipt conformance tests (CT-001 through CT-016).
//!
//! These tests verify receipt verification and compliance evaluation against
//! the spec/receipt-v0.1.md specification using programmatic test vectors.
//! They exercise the same logic that the `spec/test-vectors/` CBOR files
//! would test, but are generated in-process for CI reliability.

use ed25519_dalek::SigningKey;
use ephemeral_ml_common::receipt_signing::{
    AttestationReceipt, DestroyAction, DestroyEvidence, EnclaveMeasurements, ReceiptSigningKey,
    SecurityMode,
};
use ephemeral_ml_common::receipt_verify::{verify_receipt, CheckStatus, VerifyOptions};
use ephemeral_ml_compliance::evidence::collector::EvidenceBundleCollector;
use ephemeral_ml_compliance::evidence::schema::validate_bundle;
use ephemeral_ml_compliance::policy::profiles::baseline_profile;
use ephemeral_ml_compliance::policy::PolicyEngine;
use sha2::{Digest, Sha256};

/// Deterministic key A (used for most test vectors)
fn key_a() -> ReceiptSigningKey {
    let sk = SigningKey::from_bytes(&[0x01; 32]);
    let vk = sk.verifying_key();
    ReceiptSigningKey::from_parts(sk, vk)
}

/// Deterministic key B (for wrong-key tests)
fn key_b() -> ReceiptSigningKey {
    let sk = SigningKey::from_bytes(&[0x02; 32]);
    let vk = sk.verifying_key();
    ReceiptSigningKey::from_parts(sk, vk)
}

fn make_valid_receipt_nitro(key: &ReceiptSigningKey) -> AttestationReceipt {
    let measurements = EnclaveMeasurements::new(vec![0xAA; 48], vec![0xBB; 48], vec![0xCC; 48]);
    let mut receipt = AttestationReceipt::new(
        "ct-valid-nitro-001".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [0x04; 32],
        [0x05; 32],
        [0x06; 32],
        "policy-v1".to_string(),
        0,
        "minilm-l6-v2".to_string(),
        "v1.0".to_string(),
        100,
        64,
    );
    receipt.sign(key).unwrap();
    receipt
}

fn make_valid_receipt_tdx(key: &ReceiptSigningKey) -> AttestationReceipt {
    let measurements = EnclaveMeasurements::new_tdx(vec![0xDD; 48], vec![0xEE; 48], vec![0xFF; 48]);
    let mut receipt = AttestationReceipt::new(
        "ct-valid-tdx-001".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [0x14; 32],
        [0x15; 32],
        [0x16; 32],
        "policy-v1".to_string(),
        0,
        "gpt2-medium".to_string(),
        "v2.0".to_string(),
        500,
        128,
    );
    receipt.sign(key).unwrap();
    receipt
}

// --- CT-001: Valid Nitro receipt verifies ---
#[test]
fn ct_001_valid_receipt_nitro() {
    let key = key_a();
    let receipt = make_valid_receipt_nitro(&key);
    let opts = VerifyOptions {
        expected_model: Some("minilm-l6-v2".to_string()),
        expected_measurement_type: Some("nitro-pcr".to_string()),
        max_age_secs: 3600,
        ..Default::default()
    };
    let result = verify_receipt(&receipt, &key.public_key, &opts);
    assert!(result.verified, "CT-001 failed: {:?}", result.errors);
    assert_eq!(result.checks.signature, CheckStatus::Pass);
    assert_eq!(result.checks.model_match, CheckStatus::Pass);
    assert_eq!(result.checks.measurement_type, CheckStatus::Pass);
    assert_eq!(result.checks.measurements_present, CheckStatus::Pass);
}

// --- CT-002: Valid TDX receipt verifies ---
#[test]
fn ct_002_valid_receipt_tdx() {
    let key = key_a();
    let receipt = make_valid_receipt_tdx(&key);
    let opts = VerifyOptions {
        expected_model: Some("gpt2-medium".to_string()),
        expected_measurement_type: Some("tdx-mrtd-rtmr".to_string()),
        max_age_secs: 3600,
        ..Default::default()
    };
    let result = verify_receipt(&receipt, &key.public_key, &opts);
    assert!(result.verified, "CT-002 failed: {:?}", result.errors);
}

// --- CT-003: Tampered receipt_id invalidates signature ---
#[test]
fn ct_003_tampered_receipt_id() {
    let key = key_a();
    let mut receipt = make_valid_receipt_nitro(&key);
    receipt.receipt_id = "tampered-id-xxxxx".to_string();
    let result = verify_receipt(&receipt, &key.public_key, &VerifyOptions::default());
    assert!(!result.verified);
    assert_eq!(result.checks.signature, CheckStatus::Fail);
}

// --- CT-004: Tampered model_id invalidates signature ---
#[test]
fn ct_004_tampered_model_id() {
    let key = key_a();
    let mut receipt = make_valid_receipt_nitro(&key);
    receipt.model_id = "backdoor-model".to_string();
    let result = verify_receipt(&receipt, &key.public_key, &VerifyOptions::default());
    assert!(!result.verified);
    assert_eq!(result.checks.signature, CheckStatus::Fail);
}

// --- CT-005: Wrong key fails signature ---
#[test]
fn ct_005_wrong_key() {
    let key_a = key_a();
    let key_b = key_b();
    let receipt = make_valid_receipt_nitro(&key_a);
    let result = verify_receipt(&receipt, &key_b.public_key, &VerifyOptions::default());
    assert!(!result.verified);
    assert_eq!(result.checks.signature, CheckStatus::Fail);
}

// --- CT-006: Stale receipt fails freshness ---
#[test]
fn ct_006_stale_receipt() {
    let key = key_a();
    let measurements = EnclaveMeasurements::new(vec![0xAA; 48], vec![0xBB; 48], vec![0xCC; 48]);
    let mut receipt = AttestationReceipt::new(
        "ct-stale".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [4u8; 32],
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        0,
        "model".to_string(),
        "v1".to_string(),
        100,
        64,
    );
    receipt.execution_timestamp = ephemeral_ml_common::current_timestamp().saturating_sub(7200);
    receipt.sign(&key).unwrap();

    let opts = VerifyOptions {
        max_age_secs: 3600,
        ..Default::default()
    };
    let result = verify_receipt(&receipt, &key.public_key, &opts);
    assert!(!result.verified);
    assert_eq!(result.checks.timestamp_fresh, CheckStatus::Fail);
}

// --- CT-007: Future-dated receipt fails freshness ---
#[test]
fn ct_007_future_receipt() {
    let key = key_a();
    let measurements = EnclaveMeasurements::new(vec![0xAA; 48], vec![0xBB; 48], vec![0xCC; 48]);
    let mut receipt = AttestationReceipt::new(
        "ct-future".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [4u8; 32],
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        0,
        "model".to_string(),
        "v1".to_string(),
        100,
        64,
    );
    receipt.execution_timestamp = ephemeral_ml_common::current_timestamp() + 3600;
    receipt.sign(&key).unwrap();

    let opts = VerifyOptions {
        max_age_secs: 3600,
        ..Default::default()
    };
    let result = verify_receipt(&receipt, &key.public_key, &opts);
    assert!(!result.verified);
    assert_eq!(result.checks.timestamp_fresh, CheckStatus::Fail);
}

// --- CT-008: Short measurements (32 bytes) fail ---
#[test]
fn ct_008_short_measurements() {
    let key = key_a();
    let measurements = EnclaveMeasurements::new(vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]);
    let mut receipt = AttestationReceipt::new(
        "ct-short-meas".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [4u8; 32],
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        0,
        "model".to_string(),
        "v1".to_string(),
        100,
        64,
    );
    receipt.sign(&key).unwrap();

    let result = verify_receipt(&receipt, &key.public_key, &VerifyOptions::default());
    assert!(!result.verified);
    assert_eq!(result.checks.measurements_present, CheckStatus::Fail);
}

// --- CT-009: Model ID mismatch ---
#[test]
fn ct_009_model_mismatch() {
    let key = key_a();
    let receipt = make_valid_receipt_nitro(&key);
    let opts = VerifyOptions {
        expected_model: Some("completely-different-model".to_string()),
        ..Default::default()
    };
    let result = verify_receipt(&receipt, &key.public_key, &opts);
    assert!(!result.verified);
    assert_eq!(result.checks.model_match, CheckStatus::Fail);
}

// --- CT-010: Measurement type mismatch ---
#[test]
fn ct_010_measurement_type_mismatch() {
    let key = key_a();
    let receipt = make_valid_receipt_nitro(&key); // nitro-pcr
    let opts = VerifyOptions {
        expected_measurement_type: Some("tdx-mrtd-rtmr".to_string()),
        ..Default::default()
    };
    let result = verify_receipt(&receipt, &key.public_key, &opts);
    assert!(!result.verified);
    assert_eq!(result.checks.measurement_type, CheckStatus::Fail);
}

// --- CT-011: Pipeline chained receipt ---
#[test]
fn ct_011_pipeline_chained() {
    let key = key_a();
    let measurements = EnclaveMeasurements::new(vec![0xAA; 48], vec![0xBB; 48], vec![0xCC; 48]);
    let mut receipt = AttestationReceipt::new(
        "ct-chained".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [4u8; 32],
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        1,
        "model".to_string(),
        "v1".to_string(),
        100,
        64,
    );
    receipt.previous_receipt_hash = Some([0xAB; 32]);
    receipt.sign(&key).unwrap();

    let result = verify_receipt(&receipt, &key.public_key, &VerifyOptions::default());
    assert!(result.verified, "CT-011 failed: {:?}", result.errors);
}

// --- CT-012: CBOR determinism check ---
#[test]
fn ct_012_cbor_determinism() {
    let key = key_a();
    let receipt = make_valid_receipt_nitro(&key);

    // Canonical encoding must be deterministic
    let enc1 = receipt.canonical_encoding().unwrap();
    let enc2 = receipt.canonical_encoding().unwrap();
    assert_eq!(
        enc1, enc2,
        "CT-012: canonical encoding is not deterministic"
    );

    // Round-trip through CBOR value must preserve bytes
    let value = ephemeral_ml_common::cbor::to_value(&receipt).unwrap();
    let bytes = ephemeral_ml_common::cbor::to_vec(&value).unwrap();
    let decoded: ciborium::Value = ephemeral_ml_common::cbor::from_slice(&bytes).unwrap();
    let re_encoded = ephemeral_ml_common::cbor::to_vec(&decoded).unwrap();
    assert_eq!(bytes, re_encoded, "CT-012: CBOR round-trip is not stable");
}

// --- CT-013: JSON/CBOR interop ---
#[test]
fn ct_013_json_cbor_interop() {
    let key = key_a();
    let receipt = make_valid_receipt_nitro(&key);

    let cbor_bytes = ephemeral_ml_common::cbor::to_vec(&receipt).unwrap();
    let json_bytes = serde_json::to_vec(&receipt).unwrap();

    let from_cbor: AttestationReceipt = ephemeral_ml_common::cbor::from_slice(&cbor_bytes).unwrap();
    let from_json: AttestationReceipt = serde_json::from_slice(&json_bytes).unwrap();

    // Both should verify with the same key
    assert!(from_cbor.verify_signature(&key.public_key).unwrap());
    assert!(from_json.verify_signature(&key.public_key).unwrap());

    // Field equality
    assert_eq!(from_cbor.receipt_id, from_json.receipt_id);
    assert_eq!(from_cbor.model_id, from_json.model_id);
    assert_eq!(from_cbor.sequence_number, from_json.sequence_number);
}

// --- CT-014: Baseline compliance pass ---
#[test]
fn ct_014_baseline_compliance_pass() {
    let key = key_a();

    let attestation_data = b"mock-attestation-document";
    let att_hash: [u8; 32] = Sha256::digest(attestation_data).into();

    // Build receipt with matching attestation hash
    let measurements = EnclaveMeasurements::new(vec![0xAA; 48], vec![0xBB; 48], vec![0xCC; 48]);
    let mut receipt = AttestationReceipt::new(
        "ct-baseline-pass".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        att_hash,
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        0,
        "minilm-l6-v2".to_string(),
        "v1.0".to_string(),
        100,
        64,
    )
    .with_destroy_evidence(DestroyEvidence {
        timestamp: 1234567890,
        actions: vec![DestroyAction {
            target: "session_keys".to_string(),
            mechanism: "zeroize_on_drop".to_string(),
        }],
    });
    receipt.sign(&key).unwrap();

    let receipt_cbor = ephemeral_ml_common::cbor::to_vec(&receipt).unwrap();
    let mut collector = EvidenceBundleCollector::new();
    let r_id = collector.add_receipt(&receipt_cbor).unwrap();
    let a_id = collector.add_attestation(attestation_data).unwrap();
    collector.add_model_manifest(b"manifest").unwrap();
    collector.add_binding(&r_id, &a_id, "signing-key-attestation", None);

    let bundle = collector.build().unwrap();
    validate_bundle(&bundle).unwrap();

    let engine = PolicyEngine;
    let profile = baseline_profile();
    let result = engine
        .evaluate(&bundle, &receipt, &key.public_key, &profile)
        .unwrap();

    assert!(result.compliant, "CT-014 failed: {}", result.summary);
    assert_eq!(result.rules.len(), 16);
    assert!(result.rules.iter().all(|r| r.passed));
}

// --- CT-015: Missing attestation fails compliance ---
#[test]
fn ct_015_missing_attestation_fail() {
    let key = key_a();
    let receipt = make_valid_receipt_nitro(&key);

    let receipt_cbor = ephemeral_ml_common::cbor::to_vec(&receipt).unwrap();
    let mut collector = EvidenceBundleCollector::new();
    collector.add_receipt(&receipt_cbor).unwrap();

    let bundle = collector.build().unwrap();
    let engine = PolicyEngine;
    let profile = baseline_profile();
    let result = engine
        .evaluate(&bundle, &receipt, &key.public_key, &profile)
        .unwrap();

    assert!(!result.compliant);
    let att_rule = result
        .rules
        .iter()
        .find(|r| r.rule_id == "ATT-001")
        .unwrap();
    assert!(!att_rule.passed);
}

// --- CT-016: Tampered receipt fails compliance ---
#[test]
fn ct_016_tampered_receipt_compliance_fail() {
    let key = key_a();
    let mut receipt = make_valid_receipt_nitro(&key);
    receipt.model_id = "tampered-model".to_string(); // breaks signature

    let receipt_cbor = ephemeral_ml_common::cbor::to_vec(&receipt).unwrap();
    let mut collector = EvidenceBundleCollector::new();
    let r_id = collector.add_receipt(&receipt_cbor).unwrap();
    let a_id = collector.add_attestation(b"att").unwrap();
    collector.add_binding(&r_id, &a_id, "signing-key-attestation", None);

    let bundle = collector.build().unwrap();
    let engine = PolicyEngine;
    let profile = baseline_profile();
    let result = engine
        .evaluate(&bundle, &receipt, &key.public_key, &profile)
        .unwrap();

    assert!(!result.compliant);
    let sig_rule = result
        .rules
        .iter()
        .find(|r| r.rule_id == "SIG-001")
        .unwrap();
    assert!(!sig_rule.passed);
}

// --- CT-017: Missing destroy evidence fails DESTROY-001 ---
#[test]
fn ct_017_missing_destroy_evidence_fail() {
    let key = key_a();

    // Create receipt without destroy evidence
    let attestation_data = b"mock-attestation-bytes-017";
    let att_hash: [u8; 32] = Sha256::digest(attestation_data).into();

    let measurements = EnclaveMeasurements::new(vec![0xAA; 48], vec![0xBB; 48], vec![0xCC; 48]);
    let mut receipt = AttestationReceipt::new(
        "ct-no-destroy-017".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        att_hash,
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        0,
        "minilm-l6-v2".to_string(),
        "v1.0".to_string(),
        100,
        64,
    );
    // Deliberately omit .with_destroy_evidence(...)
    receipt.sign(&key).unwrap();

    let receipt_cbor = ephemeral_ml_common::cbor::to_vec(&receipt).unwrap();
    let mut collector = EvidenceBundleCollector::new();
    let r_id = collector.add_receipt(&receipt_cbor).unwrap();
    let a_id = collector.add_attestation(attestation_data).unwrap();
    collector.add_model_manifest(b"manifest").unwrap();
    collector.add_binding(&r_id, &a_id, "signing-key-attestation", None);

    let bundle = collector.build().unwrap();
    let engine = PolicyEngine;
    let profile = baseline_profile();
    let result = engine
        .evaluate(&bundle, &receipt, &key.public_key, &profile)
        .unwrap();

    assert!(
        !result.compliant,
        "CT-017: should fail without destroy evidence"
    );
    let destroy_rule = result
        .rules
        .iter()
        .find(|r| r.rule_id == "DESTROY-001")
        .unwrap();
    assert!(!destroy_rule.passed);

    // All other 15 rules should pass
    let passing_count = result.rules.iter().filter(|r| r.passed).count();
    assert_eq!(passing_count, 15);
}

// --- CT-018: Empty destroy actions fails DESTROY-001 ---
#[test]
fn ct_018_empty_destroy_actions_fail() {
    let key = key_a();

    let attestation_data = b"mock-attestation-bytes-018";
    let att_hash: [u8; 32] = Sha256::digest(attestation_data).into();

    let measurements = EnclaveMeasurements::new(vec![0xAA; 48], vec![0xBB; 48], vec![0xCC; 48]);
    let mut receipt = AttestationReceipt::new(
        "ct-empty-destroy-018".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        att_hash,
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        0,
        "minilm-l6-v2".to_string(),
        "v1.0".to_string(),
        100,
        64,
    )
    .with_destroy_evidence(DestroyEvidence {
        timestamp: 1234567890,
        actions: vec![], // empty actions
    });
    receipt.sign(&key).unwrap();

    let receipt_cbor = ephemeral_ml_common::cbor::to_vec(&receipt).unwrap();
    let mut collector = EvidenceBundleCollector::new();
    let r_id = collector.add_receipt(&receipt_cbor).unwrap();
    let a_id = collector.add_attestation(attestation_data).unwrap();
    collector.add_model_manifest(b"manifest").unwrap();
    collector.add_binding(&r_id, &a_id, "signing-key-attestation", None);

    let bundle = collector.build().unwrap();
    let engine = PolicyEngine;
    let profile = baseline_profile();
    let result = engine
        .evaluate(&bundle, &receipt, &key.public_key, &profile)
        .unwrap();

    assert!(
        !result.compliant,
        "CT-018: should fail with empty destroy actions"
    );
    let destroy_rule = result
        .rules
        .iter()
        .find(|r| r.rule_id == "DESTROY-001")
        .unwrap();
    assert!(!destroy_rule.passed);
}

// --- CT-019: Verifier require-destroy-event flag ---
#[test]
fn ct_019_verifier_require_destroy_event() {
    let key = key_a();

    // Receipt WITHOUT destroy evidence
    let measurements = EnclaveMeasurements::new(vec![0xAA; 48], vec![0xBB; 48], vec![0xCC; 48]);
    let mut receipt_no_destroy = AttestationReceipt::new(
        "ct-verifier-destroy-019a".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements.clone(),
        [4u8; 32],
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        0,
        "minilm-l6-v2".to_string(),
        "v1.0".to_string(),
        100,
        64,
    );
    receipt_no_destroy.sign(&key).unwrap();

    // With require_destroy_evidence=false, should pass
    let opts_lax = VerifyOptions {
        require_destroy_evidence: false,
        ..Default::default()
    };
    let result_lax = verify_receipt(&receipt_no_destroy, &key.public_key, &opts_lax);
    assert!(
        result_lax.verified,
        "CT-019a: lax mode should pass without destroy evidence"
    );

    // With require_destroy_evidence=true, should fail
    let opts_strict = VerifyOptions {
        require_destroy_evidence: true,
        ..Default::default()
    };
    let result_strict = verify_receipt(&receipt_no_destroy, &key.public_key, &opts_strict);
    assert!(
        !result_strict.verified,
        "CT-019b: strict mode should fail without destroy evidence"
    );

    // Receipt WITH destroy evidence + require_destroy_evidence=true should pass
    let mut receipt_with_destroy = AttestationReceipt::new(
        "ct-verifier-destroy-019c".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [4u8; 32],
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        0,
        "minilm-l6-v2".to_string(),
        "v1.0".to_string(),
        100,
        64,
    )
    .with_destroy_evidence(DestroyEvidence {
        timestamp: 1234567890,
        actions: vec![DestroyAction {
            target: "session_keys".to_string(),
            mechanism: "zeroize_on_drop".to_string(),
        }],
    });
    receipt_with_destroy.sign(&key).unwrap();

    let result_with = verify_receipt(&receipt_with_destroy, &key.public_key, &opts_strict);
    assert!(
        result_with.verified,
        "CT-019c: strict mode should pass with destroy evidence"
    );
}
