//! Integration tests for the compliance crate.
//!
//! These tests exercise the full pipeline: collect evidence, evaluate policy,
//! evaluate controls, export, and sign.

use ephemeral_ml_common::receipt_signing::{
    AttestationReceipt, EnclaveMeasurements, ReceiptSigningKey, SecurityMode,
};
use ephemeral_ml_compliance::controls::baseline::baseline_registry;
use ephemeral_ml_compliance::controls::hipaa::hipaa_registry;
use ephemeral_ml_compliance::evidence::collector::EvidenceBundleCollector;
use ephemeral_ml_compliance::evidence::schema::validate_bundle;
use ephemeral_ml_compliance::export::json_export;
use ephemeral_ml_compliance::export::signing::{sign_bundle, verify_bundle_signature};
use ephemeral_ml_compliance::export::BundleExporter;
use ephemeral_ml_compliance::policy::profiles::{baseline_profile, hipaa_profile};
use ephemeral_ml_compliance::policy::PolicyEngine;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Helper: create a signed receipt with known attestation data.
fn make_test_receipt_and_attestation() -> (AttestationReceipt, ReceiptSigningKey, Vec<u8>) {
    let signing_key = ReceiptSigningKey::generate().unwrap();

    // Fake attestation document
    let attestation_data = b"mock-attestation-document-bytes";
    let mut hasher = Sha256::new();
    hasher.update(attestation_data);
    let att_hash: [u8; 32] = hasher.finalize().into();

    let measurements = EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);

    let mut receipt = AttestationReceipt::new(
        "integration-receipt-001".to_string(),
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
    receipt.sign(&signing_key).unwrap();

    (receipt, signing_key, attestation_data.to_vec())
}

#[test]
fn test_full_baseline_pipeline() {
    let (receipt, signing_key, attestation_data) = make_test_receipt_and_attestation();

    // 1. Collect evidence
    let receipt_cbor = serde_cbor::to_vec(&receipt).unwrap();
    let mut collector = EvidenceBundleCollector::new();
    let receipt_id = collector.add_receipt(&receipt_cbor).unwrap();
    let att_id = collector.add_attestation(&attestation_data).unwrap();
    let manifest_id = collector
        .add_model_manifest(b"model-manifest-data")
        .unwrap();
    collector.add_binding(&receipt_id, &att_id, "signing-key-attestation", None);
    collector.add_binding(&receipt_id, &manifest_id, "receipt-model", None);

    let bundle = collector.build().unwrap();

    // 2. Validate schema
    validate_bundle(&bundle).unwrap();

    // 3. Evaluate policy
    let engine = PolicyEngine;
    let profile = baseline_profile();
    let policy_result = engine
        .evaluate(&bundle, &receipt, &signing_key.public_key, &profile)
        .unwrap();

    assert!(
        policy_result.compliant,
        "Expected compliant but got: {}",
        policy_result.summary
    );
    assert_eq!(policy_result.rules.len(), 15);

    // 4. Evaluate controls
    let registry = baseline_registry();
    let control_results = registry.evaluate(&policy_result);
    assert_eq!(control_results.len(), 15);
    assert!(control_results.iter().all(|c| c.satisfied));

    // 5. Export
    let exporter = BundleExporter::new(bundle, policy_result, control_results);
    let mut signed = exporter.export().unwrap();

    // 6. Sign
    let export_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    sign_bundle(&mut signed, &export_key).unwrap();
    assert!(signed.signature.is_some());

    // 7. Verify signature
    let valid = verify_bundle_signature(&signed, &export_key.verifying_key()).unwrap();
    assert!(valid);

    // 8. JSON round-trip
    let json = json_export::to_json(&signed).unwrap();
    let decoded = json_export::from_json(&json).unwrap();
    assert_eq!(decoded.bundle.bundle_id, signed.bundle.bundle_id);
    assert!(decoded.policy_result.compliant);
}

#[test]
fn test_full_hipaa_pipeline() {
    let (receipt, signing_key, attestation_data) = make_test_receipt_and_attestation();

    let receipt_cbor = serde_cbor::to_vec(&receipt).unwrap();
    let mut collector = EvidenceBundleCollector::new();
    let receipt_id = collector.add_receipt(&receipt_cbor).unwrap();
    let att_id = collector.add_attestation(&attestation_data).unwrap();
    let _manifest_id = collector.add_model_manifest(b"manifest").unwrap();
    collector.add_binding(&receipt_id, &att_id, "signing-key-attestation", None);

    let bundle = collector.build().unwrap();
    validate_bundle(&bundle).unwrap();

    let engine = PolicyEngine;
    let profile = hipaa_profile();
    let policy_result = engine
        .evaluate(&bundle, &receipt, &signing_key.public_key, &profile)
        .unwrap();

    assert!(
        policy_result.compliant,
        "HIPAA compliance failed: {}",
        policy_result.summary
    );

    let registry = hipaa_registry();
    let control_results = registry.evaluate(&policy_result);
    assert_eq!(control_results.len(), 4);
    assert!(control_results.iter().all(|c| c.satisfied));
}

#[test]
fn test_non_compliant_receipt_no_signature() {
    let (mut receipt, signing_key, attestation_data) = make_test_receipt_and_attestation();
    // Remove signature
    receipt.signature = None;

    let receipt_cbor = serde_cbor::to_vec(&receipt).unwrap();
    let mut collector = EvidenceBundleCollector::new();
    let receipt_id = collector.add_receipt(&receipt_cbor).unwrap();
    let att_id = collector.add_attestation(&attestation_data).unwrap();
    collector.add_binding(&receipt_id, &att_id, "signing-key-attestation", None);

    let bundle = collector.build().unwrap();
    let engine = PolicyEngine;
    let profile = baseline_profile();
    let result = engine
        .evaluate(&bundle, &receipt, &signing_key.public_key, &profile)
        .unwrap();

    assert!(!result.compliant);
    let sig_rule = result
        .rules
        .iter()
        .find(|r| r.rule_id == "SIG-001")
        .unwrap();
    assert!(!sig_rule.passed);
}

#[test]
fn test_non_compliant_missing_attestation() {
    let (receipt, signing_key, _att_data) = make_test_receipt_and_attestation();

    let receipt_cbor = serde_cbor::to_vec(&receipt).unwrap();
    let mut collector = EvidenceBundleCollector::new();
    collector.add_receipt(&receipt_cbor).unwrap();

    let bundle = collector.build().unwrap();
    let engine = PolicyEngine;
    let profile = baseline_profile();
    let result = engine
        .evaluate(&bundle, &receipt, &signing_key.public_key, &profile)
        .unwrap();

    assert!(!result.compliant);
    let att_rule = result
        .rules
        .iter()
        .find(|r| r.rule_id == "ATT-001")
        .unwrap();
    assert!(!att_rule.passed);
}

#[test]
fn test_non_compliant_bad_measurements() {
    let signing_key = ReceiptSigningKey::generate().unwrap();
    let measurements = EnclaveMeasurements::new(
        vec![1u8; 32], // wrong length
        vec![2u8; 32],
        vec![3u8; 32],
    );

    let mut receipt = AttestationReceipt::new(
        "bad-meas".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [4u8; 32],
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        0,
        "model".to_string(),
        "v1.0".to_string(),
        100,
        64,
    );
    receipt.sign(&signing_key).unwrap();

    let receipt_cbor = serde_cbor::to_vec(&receipt).unwrap();
    let mut collector = EvidenceBundleCollector::new();
    collector.add_receipt(&receipt_cbor).unwrap();
    collector.add_attestation(b"att").unwrap();

    let bundle = collector.build().unwrap();
    let engine = PolicyEngine;
    let profile = baseline_profile();
    let result = engine
        .evaluate(&bundle, &receipt, &signing_key.public_key, &profile)
        .unwrap();

    assert!(!result.compliant);
    let meas_rule = result
        .rules
        .iter()
        .find(|r| r.rule_id == "MEAS-001")
        .unwrap();
    assert!(!meas_rule.passed);
}

#[test]
fn test_schema_validation_rejects_bad_version() {
    let mut collector = EvidenceBundleCollector::new();
    collector.add_receipt(b"data").unwrap();
    let mut bundle = collector.build().unwrap();
    bundle.schema_version = "2.0".to_string();
    assert!(validate_bundle(&bundle).is_err());
}

#[test]
fn test_export_json_round_trip_preserves_compliance() {
    let (receipt, signing_key, attestation_data) = make_test_receipt_and_attestation();

    let receipt_cbor = serde_cbor::to_vec(&receipt).unwrap();
    let mut collector = EvidenceBundleCollector::new();
    let receipt_id = collector.add_receipt(&receipt_cbor).unwrap();
    let att_id = collector.add_attestation(&attestation_data).unwrap();
    collector.add_model_manifest(b"manifest").unwrap();
    collector.add_binding(&receipt_id, &att_id, "signing-key-attestation", None);

    let bundle = collector.build().unwrap();
    let engine = PolicyEngine;
    let profile = baseline_profile();
    let policy_result = engine
        .evaluate(&bundle, &receipt, &signing_key.public_key, &profile)
        .unwrap();

    let registry = baseline_registry();
    let control_results = registry.evaluate(&policy_result);

    let exporter = BundleExporter::new(bundle, policy_result, control_results);
    let signed = exporter.export().unwrap();

    let json = json_export::to_json(&signed).unwrap();
    let decoded = json_export::from_json(&json).unwrap();

    assert_eq!(
        decoded.policy_result.compliant,
        signed.policy_result.compliant
    );
    assert_eq!(
        decoded.policy_result.rules.len(),
        signed.policy_result.rules.len()
    );
    assert_eq!(decoded.control_results.len(), signed.control_results.len());
}
