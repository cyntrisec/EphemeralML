//! Receipt format detection and verification dispatch.
//!
//! Detects whether input bytes are an AIR v1 COSE_Sign1 envelope or a
//! legacy EphemeralML receipt, and routes to the appropriate verifier.
//! Returns a normalized `TrustCenterResponse` in both cases.

use ed25519_dalek::VerifyingKey;
use ephemeral_ml_common::air_verify::{verify_air_v1_receipt, AirVerifyPolicy};
use ephemeral_ml_common::receipt_verify::{verify_receipt, VerifyOptions};
use ephemeral_ml_common::AttestationReceipt;

use crate::view_model::TrustCenterResponse;

/// Policy options that callers provide (unified across formats).
#[derive(Debug, Default)]
pub struct DispatchPolicy {
    pub expected_model: Option<String>,
    pub expected_model_hash: Option<[u8; 32]>,
    pub expected_request_hash: Option<[u8; 32]>,
    pub expected_response_hash: Option<[u8; 32]>,
    pub expected_pcrs: Option<ExpectedPcrs>,
    pub expected_security_mode: Option<String>,
    pub expected_measurement_type: Option<String>,
    pub max_age_secs: u64,
    pub expected_attestation_source: Option<String>,
    pub expected_image_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedPcrs {
    pub pcr0: [u8; 48],
    pub pcr1: [u8; 48],
    pub pcr2: [u8; 48],
}

/// Detect format and verify raw receipt bytes.
///
/// Detection heuristic:
/// - AIR v1 receipts start with CBOR tag 18 (COSE_Sign1): byte `0xD2` (1-byte tag)
///   or `0xD8 0x12` (2-byte tag form).
/// - Everything else is tried as legacy CBOR, then legacy JSON.
pub fn verify_bytes(
    data: &[u8],
    public_key: &VerifyingKey,
    policy: &DispatchPolicy,
) -> Result<TrustCenterResponse, String> {
    if is_likely_air_v1(data) {
        verify_air(data, public_key, policy)
    } else {
        verify_legacy_bytes(data, public_key, policy)
    }
}

/// Verify from a parsed `serde_json::Value` (JSON endpoint).
///
/// If the value is a base64 string, decode it first and try AIR v1.
/// If it's a JSON object, treat as legacy receipt.
pub fn verify_json_value(
    value: &serde_json::Value,
    public_key: &VerifyingKey,
    policy: &DispatchPolicy,
) -> Result<TrustCenterResponse, String> {
    match value {
        serde_json::Value::String(s) => {
            // Base64-encoded bytes — could be AIR v1 or legacy CBOR.
            let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s)
                .map_err(|e| format!("Invalid base64 receipt: {}", e))?;
            verify_bytes(&bytes, public_key, policy)
        }
        serde_json::Value::Object(_) => {
            // JSON object — must be legacy format (AIR v1 is always CBOR).
            let receipt: AttestationReceipt = serde_json::from_value(value.clone())
                .map_err(|e| format!("Invalid receipt JSON: {}", e))?;
            let options = to_legacy_options(policy);
            let result = verify_receipt(&receipt, public_key, &options);
            Ok(TrustCenterResponse::from_legacy(result))
        }
        _ => Err("receipt must be a JSON object or base64 string".to_string()),
    }
}

// ── Internal helpers ────────────────────────────────────────────────

/// Check if raw bytes look like a COSE_Sign1 envelope (AIR v1).
///
/// COSE_Sign1 is CBOR tag 18. In CBOR encoding:
/// - `0xD2` is the 1-byte encoding of tag 18
/// - `0xD8 0x12` is the 2-byte encoding of tag 18
fn is_likely_air_v1(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    // 1-byte CBOR tag for value 18 (0..23 range uses major type 6 + value)
    // Major type 6 = 0xC0, value 18 = 0xC0 | 18 = 0xD2
    if data[0] == 0xD2 {
        return true;
    }
    // 2-byte form: major type 6, additional info 24, followed by tag value
    // 0xD8 = 0xC0 | 24, then 0x12 = 18
    if data.len() >= 2 && data[0] == 0xD8 && data[1] == 0x12 {
        return true;
    }
    false
}

/// Verify as AIR v1 receipt.
fn verify_air(
    data: &[u8],
    public_key: &VerifyingKey,
    policy: &DispatchPolicy,
) -> Result<TrustCenterResponse, String> {
    let air_policy = AirVerifyPolicy {
        max_age_secs: policy.max_age_secs,
        clock_skew_secs: 30,
        expected_model_hash: policy.expected_model_hash,
        expected_request_hash: policy.expected_request_hash,
        expected_response_hash: policy.expected_response_hash,
        expected_attestation_doc_hash: None,
        expected_model_id: policy.expected_model.clone(),
        expected_security_mode: policy.expected_security_mode.clone(),
        allow_evaluation_mode: false,
        expected_platform: policy.expected_measurement_type.clone(),
        expected_nonce: None,
        require_nonce: false,
        seen_cti: None,
    };
    let result = verify_air_v1_receipt(data, public_key, &air_policy);
    Ok(TrustCenterResponse::from_air_v1(result))
}

/// Verify as legacy receipt from raw bytes (try CBOR then JSON).
fn verify_legacy_bytes(
    data: &[u8],
    public_key: &VerifyingKey,
    policy: &DispatchPolicy,
) -> Result<TrustCenterResponse, String> {
    let receipt: AttestationReceipt = ephemeral_ml_common::cbor::from_slice(data)
        .or_else(|_| serde_json::from_slice(data))
        .map_err(|_| "Failed to parse receipt (tried AIR v1, CBOR, and JSON)".to_string())?;
    let options = to_legacy_options(policy);
    let result = verify_receipt(&receipt, public_key, &options);
    Ok(TrustCenterResponse::from_legacy(result))
}

/// Convert dispatch policy to legacy VerifyOptions.
fn to_legacy_options(policy: &DispatchPolicy) -> VerifyOptions {
    VerifyOptions {
        expected_model: policy.expected_model.clone(),
        expected_measurement_type: policy.expected_measurement_type.clone(),
        max_age_secs: policy.max_age_secs,
        expected_attestation_source: policy.expected_attestation_source.clone(),
        expected_image_digest: policy.expected_image_digest.clone(),
        require_destroy_evidence: false,
    }
}
