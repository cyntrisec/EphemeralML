//! AIR v1 golden vector conformance tests (#75).
//!
//! Loads JSON vector files from `spec/v1/vectors/` and validates them
//! through the 4-layer verifier. Ensures the reference implementation
//! produces byte-stable output and detects all expected failure modes.
//!
//! These tests are the CI conformance gate for the AIR v1 wire format.

use ephemeral_ml_common::air_receipt::{build_air_v1, AirReceiptClaims};
use ephemeral_ml_common::air_verify::{
    verify_air_v1_receipt, AirCheckCode, AirCheckStatus, AirVerifyPolicy,
};
use ephemeral_ml_common::receipt_signing::{EnclaveMeasurements, ReceiptSigningKey};
use serde_json::Value;
use std::path::PathBuf;

// ── Helpers ──────────────────────────────────────────────────────────

fn vectors_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points to common/, vectors are in workspace root spec/
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("spec/v1/vectors")
}

fn load_vector(subdir: &str, name: &str) -> Value {
    let path = vectors_dir().join(subdir).join(name);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read vector {}: {}", path.display(), e));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("failed to parse vector {}: {}", path.display(), e))
}

fn decode_hex(v: &Value, field: &str) -> Vec<u8> {
    hex::decode(
        v[field]
            .as_str()
            .unwrap_or_else(|| panic!("missing {field}")),
    )
    .unwrap()
}

fn pubkey_from_hex(hex_str: &str) -> ed25519_dalek::VerifyingKey {
    let bytes = hex::decode(hex_str).unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&bytes.try_into().unwrap()).unwrap()
}

/// Deterministic golden key (seed = [0x2A; 32]).
fn golden_key() -> ReceiptSigningKey {
    let private = ed25519_dalek::SigningKey::from_bytes(&[0x2A; 32]);
    ReceiptSigningKey::from_parts(private.clone(), private.verifying_key())
}

/// Build golden claims V1 (Nitro, no nonce) — must match the JSON vector.
fn golden_claims_v1() -> AirReceiptClaims {
    AirReceiptClaims {
        iss: "cyntrisec.com".to_string(),
        iat: 1740500000,
        cti: [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ],
        eat_nonce: None,
        model_id: "minilm-l6-v2".to_string(),
        model_version: "1.0.0".to_string(),
        model_hash: [0xAA; 32],
        request_hash: [0xBB; 32],
        response_hash: [0xCC; 32],
        attestation_doc_hash: [0xDD; 32],
        enclave_measurements: EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]),
        policy_version: "policy-2026.02".to_string(),
        sequence_number: 42,
        execution_time_ms: 116,
        memory_peak_mb: 512,
        security_mode: "GatewayOnly".to_string(),
    }
}

/// Build golden claims V2 (TDX, with nonce) — must match the JSON vector.
fn golden_claims_v2() -> AirReceiptClaims {
    AirReceiptClaims {
        iss: "cyntrisec.com".to_string(),
        iat: 1740500100,
        cti: [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
            0x1F, 0x20,
        ],
        eat_nonce: Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]),
        model_id: "llama-7b".to_string(),
        model_version: "2.0.0".to_string(),
        model_hash: [0x55; 32],
        request_hash: [0x66; 32],
        response_hash: [0x77; 32],
        attestation_doc_hash: [0x88; 32],
        enclave_measurements: EnclaveMeasurements::new_tdx(
            vec![0x10; 48],
            vec![0x20; 48],
            vec![0x30; 48],
        ),
        policy_version: "policy-2026.03".to_string(),
        sequence_number: 1,
        execution_time_ms: 2500,
        memory_peak_mb: 8192,
        security_mode: "ShieldMode".to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Valid vector tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cv_v1_nitro_json_matches_code() {
    let v = load_vector("valid", "v1-nitro-no-nonce.json");
    let expected_receipt = decode_hex(&v, "receipt_hex");
    let expected_payload = decode_hex(&v, "payload_hex");

    let key = golden_key();
    let claims = golden_claims_v1();
    let actual_receipt = build_air_v1(&claims, &key).unwrap();
    let actual_payload = ephemeral_ml_common::air_receipt::encode_claims_exported(&claims).unwrap();

    assert_eq!(
        hex::encode(&actual_receipt),
        hex::encode(&expected_receipt),
        "V1 receipt bytes diverged from JSON vector"
    );
    assert_eq!(
        hex::encode(&actual_payload),
        hex::encode(&expected_payload),
        "V1 payload bytes diverged from JSON vector"
    );
}

#[test]
fn cv_v2_tdx_json_matches_code() {
    let v = load_vector("valid", "v1-tdx-with-nonce.json");
    let expected_receipt = decode_hex(&v, "receipt_hex");

    let key = golden_key();
    let claims = golden_claims_v2();
    let actual_receipt = build_air_v1(&claims, &key).unwrap();

    assert_eq!(
        hex::encode(&actual_receipt),
        hex::encode(&expected_receipt),
        "V2 receipt bytes diverged from JSON vector"
    );
}

#[test]
fn cv_v1_nitro_verifier_pass() {
    let v = load_vector("valid", "v1-nitro-no-nonce.json");
    let receipt = decode_hex(&v, "receipt_hex");
    let pubkey = pubkey_from_hex(v["public_key_hex"].as_str().unwrap());

    let result = verify_air_v1_receipt(&receipt, &pubkey, &AirVerifyPolicy::default());
    assert!(
        result.verified,
        "V1 Nitro vector failed: {:?}",
        result.failures()
    );

    let claims = result.claims.as_ref().unwrap();
    let vc = &v["claims"];
    assert_eq!(claims.iss, vc["iss"].as_str().unwrap());
    assert_eq!(claims.iat, vc["iat"].as_u64().unwrap());
    assert_eq!(claims.model_id, vc["model_id"].as_str().unwrap());
    assert_eq!(claims.model_version, vc["model_version"].as_str().unwrap());
    assert_eq!(
        claims.policy_version,
        vc["policy_version"].as_str().unwrap()
    );
    assert_eq!(
        claims.sequence_number,
        vc["sequence_number"].as_u64().unwrap()
    );
    assert_eq!(
        claims.execution_time_ms,
        vc["execution_time_ms"].as_u64().unwrap()
    );
    assert_eq!(
        claims.memory_peak_mb,
        vc["memory_peak_mb"].as_u64().unwrap()
    );
    assert_eq!(claims.security_mode, vc["security_mode"].as_str().unwrap());
    assert_eq!(
        hex::encode(claims.model_hash),
        vc["model_hash_hex"].as_str().unwrap()
    );
    assert_eq!(hex::encode(claims.cti), vc["cti_hex"].as_str().unwrap());
    assert!(claims.eat_nonce.is_none());
    assert_eq!(
        claims.enclave_measurements.measurement_type,
        vc["enclave_measurements"]["measurement_type"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn cv_v2_tdx_verifier_pass_with_nonce() {
    let v = load_vector("valid", "v1-tdx-with-nonce.json");
    let receipt = decode_hex(&v, "receipt_hex");
    let pubkey = pubkey_from_hex(v["public_key_hex"].as_str().unwrap());

    let policy = AirVerifyPolicy {
        expected_nonce: Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]),
        expected_platform: Some("tdx-mrtd-rtmr".to_string()),
        expected_model_hash: Some([0x55; 32]),
        expected_model_id: Some("llama-7b".to_string()),
        ..Default::default()
    };

    let result = verify_air_v1_receipt(&receipt, &pubkey, &policy);
    assert!(
        result.verified,
        "V2 TDX vector failed: {:?}",
        result.failures()
    );

    let claims = result.claims.as_ref().unwrap();
    assert_eq!(
        claims.eat_nonce,
        Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
    );
    assert_eq!(
        claims.enclave_measurements.measurement_type,
        "tdx-mrtd-rtmr"
    );
    assert_eq!(claims.security_mode, "ShieldMode");
}

// ═══════════════════════════════════════════════════════════════════
// Invalid vector tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cv_wrong_key_sig_fails() {
    let v = load_vector("invalid", "v1-wrong-key.json");
    let receipt = decode_hex(&v, "receipt_hex");
    let wrong_pubkey = pubkey_from_hex(v["wrong_public_key_hex"].as_str().unwrap());

    let result = verify_air_v1_receipt(&receipt, &wrong_pubkey, &AirVerifyPolicy::default());
    assert!(!result.verified);
    assert!(
        result.has_failure(&AirCheckCode::SignatureFailed),
        "expected SIG_FAILED, got: {:?}",
        result.failures()
    );
    // Claims should still parse
    assert!(result.claims.is_some());
}

#[test]
fn cv_wrong_alg_bad_alg() {
    let v = load_vector("invalid", "v1-wrong-alg.json");
    let receipt = decode_hex(&v, "receipt_hex");
    let pubkey = pubkey_from_hex(v["public_key_hex"].as_str().unwrap());

    let result = verify_air_v1_receipt(&receipt, &pubkey, &AirVerifyPolicy::default());
    assert!(!result.verified);
    assert!(
        result.has_failure(&AirCheckCode::BadAlg),
        "expected BAD_ALG, got: {:?}",
        result.failures()
    );
}

// ═══════════════════════════════════════════════════════════════════
// Vector file integrity
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cv_vector_directory_complete() {
    let dir = vectors_dir();
    assert!(dir.join("valid/v1-nitro-no-nonce.json").exists());
    assert!(dir.join("valid/v1-tdx-with-nonce.json").exists());
    assert!(dir.join("invalid/v1-wrong-key.json").exists());
    assert!(dir.join("invalid/v1-wrong-alg.json").exists());
    assert!(dir.join("README.md").exists());
}

#[test]
fn cv_all_valid_vectors_verify() {
    let valid_dir = vectors_dir().join("valid");
    for entry in std::fs::read_dir(valid_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let data = std::fs::read_to_string(entry.path()).unwrap();
        let v: Value = serde_json::from_str(&data).unwrap();

        let receipt = decode_hex(&v, "receipt_hex");
        let pubkey = pubkey_from_hex(v["public_key_hex"].as_str().unwrap());

        let result = verify_air_v1_receipt(&receipt, &pubkey, &AirVerifyPolicy::default());
        assert!(
            result.verified,
            "valid vector {} failed: {:?}",
            entry.path().display(),
            result.failures()
        );
    }
}

#[test]
fn cv_all_valid_vectors_tag_18() {
    let valid_dir = vectors_dir().join("valid");
    for entry in std::fs::read_dir(valid_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let data = std::fs::read_to_string(entry.path()).unwrap();
        let v: Value = serde_json::from_str(&data).unwrap();
        let receipt = decode_hex(&v, "receipt_hex");
        assert_eq!(
            receipt[0],
            0xD2,
            "vector {} missing COSE tag 18",
            entry.path().display()
        );
    }
}

#[test]
fn cv_all_invalid_vectors_fail() {
    let invalid_dir = vectors_dir().join("invalid");
    for entry in std::fs::read_dir(invalid_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let data = std::fs::read_to_string(entry.path()).unwrap();
        let v: Value = serde_json::from_str(&data).unwrap();
        let receipt = decode_hex(&v, "receipt_hex");

        // Use the wrong key if present, otherwise the correct key
        let pubkey = if let Some(wpk) = v.get("wrong_public_key_hex") {
            pubkey_from_hex(wpk.as_str().unwrap())
        } else {
            pubkey_from_hex(v["public_key_hex"].as_str().unwrap())
        };

        let result = verify_air_v1_receipt(&receipt, &pubkey, &AirVerifyPolicy::default());
        assert!(
            !result.verified,
            "invalid vector {} should have failed but passed",
            entry.path().display()
        );

        // Verify expected failure code matches
        let expected_code = v["expected_failure"]["code"].as_str().unwrap();
        let has_expected = result.checks.iter().any(|c| {
            matches!(c.status, AirCheckStatus::Fail)
                && c.code.as_ref().map(|code| code.to_string()) == Some(expected_code.to_string())
        });
        assert!(
            has_expected,
            "invalid vector {} expected failure code {}, got: {:?}",
            entry.path().display(),
            expected_code,
            result.failures()
        );
    }
}
