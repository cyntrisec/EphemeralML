//! Shared receipt verification logic.
//!
//! Used by both the CLI verifier (`ephemeralml-verify`) and the hosted
//! verification API (`ephemeralml-verifier`). All verification is pure
//! computation — no I/O, no filesystem access.

use crate::receipt_signing::AttestationReceipt;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// Individual check outcome.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Fail,
    Skip,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckStatus::Pass => write!(f, "PASS"),
            CheckStatus::Fail => write!(f, "FAIL"),
            CheckStatus::Skip => write!(f, "SKIP"),
        }
    }
}

/// Results of the five verification checks.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckResults {
    pub signature: CheckStatus,
    pub model_match: CheckStatus,
    pub measurement_type: CheckStatus,
    pub timestamp_fresh: CheckStatus,
    pub measurements_present: CheckStatus,
}

/// Full verification result with metadata.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyResult {
    pub verified: bool,
    pub receipt_id: String,
    pub model_id: String,
    pub model_version: String,
    pub measurement_type: String,
    pub sequence_number: u64,
    pub execution_timestamp: u64,
    pub checks: CheckResults,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
}

/// Options controlling which checks are performed.
#[derive(Default)]
pub struct VerifyOptions {
    /// If set, the receipt's `model_id` must match this value.
    pub expected_model: Option<String>,
    /// If set to something other than `"any"`, the receipt's measurement type must match.
    pub expected_measurement_type: Option<String>,
    /// Maximum receipt age in seconds. `0` skips the freshness check.
    pub max_age_secs: u64,
}

/// Run the five verification checks on a receipt.
///
/// This is pure logic — no I/O. Both the CLI and the web API call this.
pub fn verify_receipt(
    receipt: &AttestationReceipt,
    public_key: &VerifyingKey,
    options: &VerifyOptions,
) -> VerifyResult {
    let mut errors: Vec<String> = Vec::new();
    let warnings: Vec<String> = Vec::new();

    // 1. Ed25519 signature
    let sig_status = match receipt.verify_signature(public_key) {
        Ok(true) => CheckStatus::Pass,
        Ok(false) => {
            errors.push("Ed25519 signature verification failed".to_string());
            CheckStatus::Fail
        }
        Err(e) => {
            errors.push(format!("Signature error: {}", e));
            CheckStatus::Fail
        }
    };

    // 2. Model ID match
    let model_status = if let Some(ref expected) = options.expected_model {
        if receipt.model_id == *expected {
            CheckStatus::Pass
        } else {
            errors.push(format!(
                "Model mismatch: receipt has '{}', expected '{}'",
                receipt.model_id, expected
            ));
            CheckStatus::Fail
        }
    } else {
        CheckStatus::Skip
    };

    // 3. Measurement type
    let mt_status = match &options.expected_measurement_type {
        Some(expected) if expected != "any" => {
            if receipt.enclave_measurements.measurement_type == *expected {
                CheckStatus::Pass
            } else {
                errors.push(format!(
                    "Measurement type mismatch: receipt has '{}', expected '{}'",
                    receipt.enclave_measurements.measurement_type, expected
                ));
                CheckStatus::Fail
            }
        }
        _ => CheckStatus::Skip,
    };

    // 4. Timestamp freshness (reject both stale and future timestamps)
    let ts_status = if options.max_age_secs == 0 {
        CheckStatus::Skip
    } else {
        let now = crate::current_timestamp();
        if receipt.execution_timestamp > now {
            errors.push(format!(
                "Receipt timestamp is in the future: {} > now {}",
                receipt.execution_timestamp, now
            ));
            CheckStatus::Fail
        } else {
            let age = now - receipt.execution_timestamp;
            if age <= options.max_age_secs {
                CheckStatus::Pass
            } else {
                errors.push(format!(
                    "Receipt is {}s old (max allowed: {}s)",
                    age, options.max_age_secs
                ));
                CheckStatus::Fail
            }
        }
    };

    // 5. Measurements present and valid (48 bytes = SHA-384)
    let meas_status = if receipt.enclave_measurements.is_valid() {
        CheckStatus::Pass
    } else {
        errors.push("Measurements are not 48 bytes (expected SHA-384)".to_string());
        CheckStatus::Fail
    };

    // Any Fail check must produce verified: false. We check all statuses
    // rather than relying solely on errors.is_empty(), as a defense against
    // future checks that might accidentally populate only warnings.
    let any_fail = matches!(sig_status, CheckStatus::Fail)
        || matches!(model_status, CheckStatus::Fail)
        || matches!(mt_status, CheckStatus::Fail)
        || matches!(ts_status, CheckStatus::Fail)
        || matches!(meas_status, CheckStatus::Fail);
    let verified = !any_fail;

    VerifyResult {
        verified,
        receipt_id: receipt.receipt_id.clone(),
        model_id: receipt.model_id.clone(),
        model_version: receipt.model_version.clone(),
        measurement_type: receipt.enclave_measurements.measurement_type.clone(),
        sequence_number: receipt.sequence_number,
        execution_timestamp: receipt.execution_timestamp,
        checks: CheckResults {
            signature: sig_status,
            model_match: model_status,
            measurement_type: mt_status,
            timestamp_fresh: ts_status,
            measurements_present: meas_status,
        },
        errors,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt_signing::{EnclaveMeasurements, ReceiptSigningKey, SecurityMode};

    fn make_signed_receipt(
        model_id: &str,
        signing_key: &ReceiptSigningKey,
    ) -> AttestationReceipt {
        let measurements =
            EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);
        let mut receipt = AttestationReceipt::new(
            "test-receipt-1".to_string(),
            1,
            SecurityMode::GatewayOnly,
            measurements,
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            "policy-v1".to_string(),
            1,
            model_id.to_string(),
            "v1.0".to_string(),
            100,
            64,
        );
        receipt.sign(signing_key).unwrap();
        receipt
    }

    #[test]
    fn test_valid_receipt_all_pass() {
        let key = ReceiptSigningKey::generate().unwrap();
        let receipt = make_signed_receipt("minilm-l6-v2", &key);
        let options = VerifyOptions {
            expected_model: Some("minilm-l6-v2".to_string()),
            expected_measurement_type: None,
            max_age_secs: 3600,
        };
        let result = verify_receipt(&receipt, &key.public_key, &options);
        assert!(result.verified);
        assert_eq!(result.checks.signature, CheckStatus::Pass);
        assert_eq!(result.checks.model_match, CheckStatus::Pass);
        assert_eq!(result.checks.timestamp_fresh, CheckStatus::Pass);
        assert_eq!(result.checks.measurements_present, CheckStatus::Pass);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_tampered_receipt_signature_fail() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut receipt = make_signed_receipt("model-a", &key);
        receipt.receipt_id = "tampered".to_string();
        let result = verify_receipt(&receipt, &key.public_key, &VerifyOptions::default());
        assert!(!result.verified);
        assert_eq!(result.checks.signature, CheckStatus::Fail);
    }

    #[test]
    fn test_wrong_key_signature_fail() {
        let key1 = ReceiptSigningKey::generate().unwrap();
        let key2 = ReceiptSigningKey::generate().unwrap();
        let receipt = make_signed_receipt("model-a", &key1);
        let result = verify_receipt(&receipt, &key2.public_key, &VerifyOptions::default());
        assert!(!result.verified);
        assert_eq!(result.checks.signature, CheckStatus::Fail);
    }

    #[test]
    fn test_model_mismatch_fail() {
        let key = ReceiptSigningKey::generate().unwrap();
        let receipt = make_signed_receipt("actual-model", &key);
        let options = VerifyOptions {
            expected_model: Some("expected-model".to_string()),
            ..Default::default()
        };
        let result = verify_receipt(&receipt, &key.public_key, &options);
        assert!(!result.verified);
        assert_eq!(result.checks.model_match, CheckStatus::Fail);
    }

    #[test]
    fn test_stale_timestamp_fail() {
        let key = ReceiptSigningKey::generate().unwrap();
        let measurements =
            EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);
        let mut receipt = AttestationReceipt::new(
            "old-receipt".to_string(),
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
        // Set timestamp to 2 hours ago
        receipt.execution_timestamp = crate::current_timestamp().saturating_sub(7200);
        receipt.sign(&key).unwrap();

        let options = VerifyOptions {
            max_age_secs: 3600,
            ..Default::default()
        };
        let result = verify_receipt(&receipt, &key.public_key, &options);
        assert!(!result.verified);
        assert_eq!(result.checks.signature, CheckStatus::Pass);
        assert_eq!(result.checks.timestamp_fresh, CheckStatus::Fail);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_skip_checks_with_defaults() {
        let key = ReceiptSigningKey::generate().unwrap();
        let receipt = make_signed_receipt("any-model", &key);
        let options = VerifyOptions::default();
        let result = verify_receipt(&receipt, &key.public_key, &options);
        assert!(result.verified);
        assert_eq!(result.checks.model_match, CheckStatus::Skip);
        assert_eq!(result.checks.measurement_type, CheckStatus::Skip);
        assert_eq!(result.checks.timestamp_fresh, CheckStatus::Skip);
    }

    #[test]
    fn test_measurement_type_mismatch() {
        let key = ReceiptSigningKey::generate().unwrap();
        let receipt = make_signed_receipt("model", &key);
        let options = VerifyOptions {
            expected_measurement_type: Some("tdx-mrtd-rtmr".to_string()),
            ..Default::default()
        };
        let result = verify_receipt(&receipt, &key.public_key, &options);
        // receipt uses "nitro-pcr" by default, so this should fail
        assert!(!result.verified);
        assert_eq!(result.checks.measurement_type, CheckStatus::Fail);
    }

    #[test]
    fn test_measurement_type_any_skips() {
        let key = ReceiptSigningKey::generate().unwrap();
        let receipt = make_signed_receipt("model", &key);
        let options = VerifyOptions {
            expected_measurement_type: Some("any".to_string()),
            ..Default::default()
        };
        let result = verify_receipt(&receipt, &key.public_key, &options);
        assert_eq!(result.checks.measurement_type, CheckStatus::Skip);
    }

    #[test]
    fn test_invalid_measurements_length() {
        let key = ReceiptSigningKey::generate().unwrap();
        let measurements =
            EnclaveMeasurements::new(vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]);
        let mut receipt = AttestationReceipt::new(
            "bad-meas".to_string(),
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
        receipt.sign(&key).unwrap();
        let result = verify_receipt(&receipt, &key.public_key, &VerifyOptions::default());
        assert!(!result.verified);
        assert_eq!(result.checks.measurements_present, CheckStatus::Fail);
        assert!(!result.errors.is_empty());
    }
}
