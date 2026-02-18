//! Workspace-level conformance test.
//!
//! Verifies that the compliance crate, common crate, and receipt verification
//! all work together correctly as an integrated system.

use ed25519_dalek::SigningKey;
use ephemeral_ml_common::receipt_signing::{
    AttestationReceipt, EnclaveMeasurements, ReceiptSigningKey, SecurityMode,
};
use ephemeral_ml_common::receipt_verify::{verify_receipt, CheckStatus, VerifyOptions};
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

/// End-to-end: create a receipt, collect evidence, evaluate compliance,
/// export signed bundle, verify export signature, round-trip through JSON.
#[test]
fn e2e_receipt_to_signed_compliance_bundle() {
    let key = ReceiptSigningKey::generate().unwrap();

    let attestation_data = b"e2e-attestation-document";
    let att_hash: [u8; 32] = Sha256::digest(attestation_data).into();

    let measurements = EnclaveMeasurements::new(vec![0x11; 48], vec![0x22; 48], vec![0x33; 48]);
    let mut receipt = AttestationReceipt::new(
        "e2e-receipt-001".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        att_hash,
        [0x55; 32],
        [0x66; 32],
        "policy-v1".to_string(),
        0,
        "e2e-model".to_string(),
        "v1.0".to_string(),
        200,
        128,
    );
    receipt.sign(&key).unwrap();

    // 1. Verify receipt
    let opts = VerifyOptions {
        expected_model: Some("e2e-model".to_string()),
        max_age_secs: 3600,
        ..Default::default()
    };
    let verify_result = verify_receipt(&receipt, &key.public_key, &opts);
    assert!(verify_result.verified);

    // 2. Collect evidence
    let receipt_cbor = ephemeral_ml_common::cbor::to_vec(&receipt).unwrap();
    let mut collector = EvidenceBundleCollector::new();
    let r_id = collector.add_receipt(&receipt_cbor).unwrap();
    let a_id = collector.add_attestation(attestation_data).unwrap();
    collector.add_model_manifest(b"e2e-manifest").unwrap();
    collector.add_binding(&r_id, &a_id, "signing-key-attestation", None);
    let bundle = collector.build().unwrap();
    validate_bundle(&bundle).unwrap();

    // 3. Evaluate baseline
    let engine = PolicyEngine;
    let baseline = baseline_profile();
    let baseline_result = engine
        .evaluate(&bundle, &receipt, &key.public_key, &baseline)
        .unwrap();
    assert!(baseline_result.compliant, "{}", baseline_result.summary);

    // 4. Evaluate HIPAA
    let hipaa = hipaa_profile();
    let hipaa_result = engine
        .evaluate(&bundle, &receipt, &key.public_key, &hipaa)
        .unwrap();
    assert!(hipaa_result.compliant, "{}", hipaa_result.summary);

    // 5. Control mapping
    let baseline_controls = baseline_registry().evaluate(&baseline_result);
    assert!(baseline_controls.iter().all(|c| c.satisfied));

    let hipaa_controls = hipaa_registry().evaluate(&hipaa_result);
    assert!(hipaa_controls.iter().all(|c| c.satisfied));

    // 6. Export and sign
    let exporter = BundleExporter::new(
        bundle,
        baseline_result,
        baseline_controls,
    );
    let mut signed = exporter.export().unwrap();

    let export_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    sign_bundle(&mut signed, &export_key).unwrap();
    assert!(signed.signature.is_some());

    // 7. Verify export signature
    let valid = verify_bundle_signature(&signed, &export_key.verifying_key()).unwrap();
    assert!(valid);

    // 8. JSON round-trip
    let json = json_export::to_json(&signed).unwrap();
    let decoded = json_export::from_json(&json).unwrap();
    assert!(decoded.policy_result.compliant);
    assert_eq!(decoded.bundle.bundle_id, signed.bundle.bundle_id);
}

/// Verify that receipt verification catches all expected failure modes.
#[test]
fn e2e_verification_failure_modes() {
    let key_a = {
        let sk = SigningKey::from_bytes(&[0x01; 32]);
        let vk = sk.verifying_key();
        ReceiptSigningKey::from_parts(sk, vk)
    };
    let key_b = {
        let sk = SigningKey::from_bytes(&[0x02; 32]);
        let vk = sk.verifying_key();
        ReceiptSigningKey::from_parts(sk, vk)
    };

    let measurements = EnclaveMeasurements::new(vec![0xAA; 48], vec![0xBB; 48], vec![0xCC; 48]);
    let mut receipt = AttestationReceipt::new(
        "e2e-fail-modes".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [4u8; 32],
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        0,
        "model-a".to_string(),
        "v1".to_string(),
        100,
        64,
    );
    receipt.sign(&key_a).unwrap();

    // Wrong key
    let r = verify_receipt(&receipt, &key_b.public_key, &VerifyOptions::default());
    assert!(!r.verified);
    assert_eq!(r.checks.signature, CheckStatus::Fail);

    // Tampered
    let mut tampered = receipt.clone();
    tampered.receipt_id = "tampered".to_string();
    let r = verify_receipt(&tampered, &key_a.public_key, &VerifyOptions::default());
    assert!(!r.verified);
    assert_eq!(r.checks.signature, CheckStatus::Fail);

    // Model mismatch
    let opts = VerifyOptions {
        expected_model: Some("model-b".to_string()),
        ..Default::default()
    };
    let r = verify_receipt(&receipt, &key_a.public_key, &opts);
    assert!(!r.verified);
    assert_eq!(r.checks.model_match, CheckStatus::Fail);
}
