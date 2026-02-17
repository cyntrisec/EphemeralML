//! Individual compliance rule evaluators.
//!
//! Each function evaluates one rule and returns a `RuleResult`. Functions take
//! the minimum arguments needed so they can be unit-tested in isolation.

use ed25519_dalek::VerifyingKey;
use ephemeral_ml_common::receipt_signing::AttestationReceipt;
use sha2::{Digest, Sha256};

use super::RuleResult;
use crate::evidence::{EvidenceBundle, EvidenceType};

// ---------------------------------------------------------------------------
// Signature rules
// ---------------------------------------------------------------------------

/// SIG-001: Ed25519 verify_strict on the receipt.
pub fn check_sig_001(receipt: &AttestationReceipt, public_key: &VerifyingKey) -> RuleResult {
    let (passed, reason) = match receipt.verify_signature(public_key) {
        Ok(true) => (true, "Ed25519 signature verified (strict)".to_string()),
        Ok(false) => (false, "Ed25519 signature verification failed".to_string()),
        Err(e) => (false, format!("Signature error: {}", e)),
    };
    RuleResult {
        rule_id: "SIG-001".to_string(),
        rule_name: "Ed25519 signature verification".to_string(),
        passed,
        reason,
    }
}

/// SIG-002: CBOR canonical encoding round-trip determinism.
pub fn check_sig_002(receipt: &AttestationReceipt) -> RuleResult {
    let (passed, reason) = match (receipt.canonical_encoding(), receipt.canonical_encoding()) {
        (Ok(enc1), Ok(enc2)) => {
            if enc1 == enc2 {
                (true, "Canonical encoding is deterministic".to_string())
            } else {
                (
                    false,
                    "Canonical encoding produced different outputs".to_string(),
                )
            }
        }
        (Err(e), _) | (_, Err(e)) => (false, format!("Canonical encoding failed: {}", e)),
    };
    RuleResult {
        rule_id: "SIG-002".to_string(),
        rule_name: "CBOR canonical round-trip determinism".to_string(),
        passed,
        reason,
    }
}

// ---------------------------------------------------------------------------
// Attestation rules
// ---------------------------------------------------------------------------

/// ATT-001: Attestation document present in the bundle.
pub fn check_att_001(bundle: &EvidenceBundle) -> RuleResult {
    let has_attestation = bundle
        .items
        .iter()
        .any(|item| item.evidence_type == EvidenceType::Attestation);

    RuleResult {
        rule_id: "ATT-001".to_string(),
        rule_name: "Attestation document present".to_string(),
        passed: has_attestation,
        reason: if has_attestation {
            "Attestation evidence item found in bundle".to_string()
        } else {
            "No attestation evidence item found in bundle".to_string()
        },
    }
}

/// ATT-002: SHA-256 of attestation data matches `receipt.attestation_doc_hash`.
pub fn check_att_002(bundle: &EvidenceBundle, receipt: &AttestationReceipt) -> RuleResult {
    let att_item = bundle
        .items
        .iter()
        .find(|item| item.evidence_type == EvidenceType::Attestation);

    match att_item {
        Some(item) => {
            let mut hasher = Sha256::new();
            hasher.update(&item.data);
            let computed: [u8; 32] = hasher.finalize().into();

            let passed = computed == receipt.attestation_doc_hash;
            RuleResult {
                rule_id: "ATT-002".to_string(),
                rule_name: "Attestation hash matches receipt".to_string(),
                passed,
                reason: if passed {
                    "SHA-256(attestation) == receipt.attestation_doc_hash".to_string()
                } else {
                    format!(
                        "Hash mismatch: computed {} vs receipt {}",
                        hex::encode(computed),
                        hex::encode(receipt.attestation_doc_hash)
                    )
                },
            }
        }
        None => RuleResult {
            rule_id: "ATT-002".to_string(),
            rule_name: "Attestation hash matches receipt".to_string(),
            passed: false,
            reason: "No attestation evidence item found in bundle".to_string(),
        },
    }
}

// ---------------------------------------------------------------------------
// Measurement rules
// ---------------------------------------------------------------------------

/// MEAS-001: Enclave measurements are 48 bytes (SHA-384).
pub fn check_meas_001(receipt: &AttestationReceipt) -> RuleResult {
    let valid = receipt.enclave_measurements.is_valid();
    RuleResult {
        rule_id: "MEAS-001".to_string(),
        rule_name: "Measurements are 48 bytes".to_string(),
        passed: valid,
        reason: if valid {
            "All PCR/MRTD measurements are 48 bytes".to_string()
        } else {
            format!(
                "Invalid measurement lengths: pcr0={}, pcr1={}, pcr2={}",
                receipt.enclave_measurements.pcr0.len(),
                receipt.enclave_measurements.pcr1.len(),
                receipt.enclave_measurements.pcr2.len()
            )
        },
    }
}

/// MEAS-002: Measurement type is a recognized TEE platform.
pub fn check_meas_002(receipt: &AttestationReceipt) -> RuleResult {
    let mt = &receipt.enclave_measurements.measurement_type;
    let recognized = mt == "nitro-pcr" || mt == "tdx-mrtd-rtmr";
    RuleResult {
        rule_id: "MEAS-002".to_string(),
        rule_name: "Recognized measurement type".to_string(),
        passed: recognized,
        reason: if recognized {
            format!("Measurement type '{}' is recognized", mt)
        } else {
            format!("Unrecognized measurement type: '{}'", mt)
        },
    }
}

// ---------------------------------------------------------------------------
// Freshness rules
// ---------------------------------------------------------------------------

/// FRESH-001: Receipt is not older than `max_age_secs`.
pub fn check_fresh_001(receipt: &AttestationReceipt, max_age_secs: u64) -> RuleResult {
    let now = ephemeral_ml_common::current_timestamp();
    if receipt.execution_timestamp > now {
        return RuleResult {
            rule_id: "FRESH-001".to_string(),
            rule_name: "Receipt within max age".to_string(),
            passed: false,
            reason: format!(
                "Receipt timestamp {} is in the future (now={})",
                receipt.execution_timestamp, now
            ),
        };
    }
    let age = now - receipt.execution_timestamp;
    let passed = age <= max_age_secs;
    RuleResult {
        rule_id: "FRESH-001".to_string(),
        rule_name: "Receipt within max age".to_string(),
        passed,
        reason: if passed {
            format!("Receipt age {}s <= max {}s", age, max_age_secs)
        } else {
            format!("Receipt age {}s > max {}s", age, max_age_secs)
        },
    }
}

/// FRESH-002: Receipt timestamp is not in the future.
pub fn check_fresh_002(receipt: &AttestationReceipt) -> RuleResult {
    let now = ephemeral_ml_common::current_timestamp();
    let passed = receipt.execution_timestamp <= now;
    RuleResult {
        rule_id: "FRESH-002".to_string(),
        rule_name: "Receipt not future-dated".to_string(),
        passed,
        reason: if passed {
            "Receipt timestamp is not in the future".to_string()
        } else {
            format!(
                "Receipt timestamp {} is in the future (now={})",
                receipt.execution_timestamp, now
            )
        },
    }
}

// ---------------------------------------------------------------------------
// Model rules
// ---------------------------------------------------------------------------

/// MODEL-001: `model_id` is non-empty.
pub fn check_model_001(receipt: &AttestationReceipt) -> RuleResult {
    let passed = !receipt.model_id.is_empty();
    RuleResult {
        rule_id: "MODEL-001".to_string(),
        rule_name: "Model ID present".to_string(),
        passed,
        reason: if passed {
            format!("model_id = '{}'", receipt.model_id)
        } else {
            "model_id is empty".to_string()
        },
    }
}

/// MODEL-002: A ModelManifest evidence item exists in the bundle.
pub fn check_model_002(bundle: &EvidenceBundle) -> RuleResult {
    let has_manifest = bundle
        .items
        .iter()
        .any(|item| item.evidence_type == EvidenceType::ModelManifest);

    RuleResult {
        rule_id: "MODEL-002".to_string(),
        rule_name: "Model manifest present in bundle".to_string(),
        passed: has_manifest,
        reason: if has_manifest {
            "ModelManifest evidence item found".to_string()
        } else {
            "No ModelManifest evidence item found in bundle".to_string()
        },
    }
}

// ---------------------------------------------------------------------------
// Chain rule
// ---------------------------------------------------------------------------

/// CHAIN-001: If `previous_receipt_hash` is present, it must be 32 bytes.
///
/// This is always true by the type system (`Option<[u8; 32]>`), but we
/// include it for completeness and to surface the field's presence.
pub fn check_chain_001(receipt: &AttestationReceipt) -> RuleResult {
    let (passed, reason) = match receipt.previous_receipt_hash {
        Some(hash) => {
            // Always 32 bytes by type, but verify non-zero for semantic validity.
            if hash == [0u8; 32] {
                (false, "previous_receipt_hash is all zeroes".to_string())
            } else {
                (
                    true,
                    format!("previous_receipt_hash present: {}", hex::encode(hash)),
                )
            }
        }
        None => (
            true,
            "No previous_receipt_hash (single receipt or first in chain)".to_string(),
        ),
    };
    RuleResult {
        rule_id: "CHAIN-001".to_string(),
        rule_name: "Receipt chain hash valid".to_string(),
        passed,
        reason,
    }
}

// ---------------------------------------------------------------------------
// CBOR rule
// ---------------------------------------------------------------------------

/// CBOR-001: CBOR deterministic round-trip (identical to SIG-002 but
/// semantically distinct for the CBOR encoding guarantee).
pub fn check_cbor_001(receipt: &AttestationReceipt) -> RuleResult {
    let (passed, reason) = match receipt.canonical_encoding() {
        Ok(enc1) => match receipt.canonical_encoding() {
            Ok(enc2) => {
                if enc1 == enc2 {
                    (
                        true,
                        "CBOR canonical round-trip produces identical bytes".to_string(),
                    )
                } else {
                    (
                        false,
                        "CBOR canonical encoding is not deterministic".to_string(),
                    )
                }
            }
            Err(e) => (false, format!("Second canonical encoding failed: {}", e)),
        },
        Err(e) => (false, format!("Canonical encoding failed: {}", e)),
    };
    RuleResult {
        rule_id: "CBOR-001".to_string(),
        rule_name: "CBOR deterministic encoding".to_string(),
        passed,
        reason,
    }
}

// ---------------------------------------------------------------------------
// Key binding rule
// ---------------------------------------------------------------------------

/// KEY-001: A binding with `binding_type == "signing-key-attestation"` exists.
pub fn check_key_001(bundle: &EvidenceBundle) -> RuleResult {
    let has_binding = bundle
        .bindings
        .iter()
        .any(|b| b.binding_type == "signing-key-attestation");

    RuleResult {
        rule_id: "KEY-001".to_string(),
        rule_name: "Signing key bound to attestation".to_string(),
        passed: has_binding,
        reason: if has_binding {
            "signing-key-attestation binding found".to_string()
        } else {
            "No signing-key-attestation binding in bundle".to_string()
        },
    }
}

// ---------------------------------------------------------------------------
// Policy version rule
// ---------------------------------------------------------------------------

/// POLICY-001: `policy_version` is non-empty.
pub fn check_policy_001(receipt: &AttestationReceipt) -> RuleResult {
    let passed = !receipt.policy_version.is_empty();
    RuleResult {
        rule_id: "POLICY-001".to_string(),
        rule_name: "Policy version present".to_string(),
        passed,
        reason: if passed {
            format!("policy_version = '{}'", receipt.policy_version)
        } else {
            "policy_version is empty".to_string()
        },
    }
}

// ---------------------------------------------------------------------------
// Sequence rule
// ---------------------------------------------------------------------------

/// SEQ-001: Sequence numbers are strictly increasing across receipts.
///
/// For a single-receipt bundle this is trivially true (sequence >= 0 for u64).
pub fn check_seq_001(receipts: &[AttestationReceipt]) -> RuleResult {
    if receipts.is_empty() {
        return RuleResult {
            rule_id: "SEQ-001".to_string(),
            rule_name: "Sequence numbers increasing".to_string(),
            passed: false,
            reason: "No receipts to check".to_string(),
        };
    }

    if receipts.len() == 1 {
        return RuleResult {
            rule_id: "SEQ-001".to_string(),
            rule_name: "Sequence numbers increasing".to_string(),
            passed: true,
            reason: format!(
                "Single receipt with sequence_number={}",
                receipts[0].sequence_number
            ),
        };
    }

    // Multiple receipts: verify strictly increasing.
    for i in 1..receipts.len() {
        if receipts[i].sequence_number <= receipts[i - 1].sequence_number {
            return RuleResult {
                rule_id: "SEQ-001".to_string(),
                rule_name: "Sequence numbers increasing".to_string(),
                passed: false,
                reason: format!(
                    "sequence_number[{}]={} is not > sequence_number[{}]={}",
                    i,
                    receipts[i].sequence_number,
                    i - 1,
                    receipts[i - 1].sequence_number
                ),
            };
        }
    }

    RuleResult {
        rule_id: "SEQ-001".to_string(),
        rule_name: "Sequence numbers increasing".to_string(),
        passed: true,
        reason: format!(
            "All {} sequence numbers are strictly increasing",
            receipts.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_ml_common::receipt_signing::{
        EnclaveMeasurements, ReceiptSigningKey, SecurityMode,
    };

    fn make_receipt(model_id: &str, seq: u64) -> AttestationReceipt {
        AttestationReceipt::new(
            format!("receipt-{}", seq),
            1,
            SecurityMode::GatewayOnly,
            EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]),
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            "policy-v1".to_string(),
            seq,
            model_id.to_string(),
            "v1.0".to_string(),
            100,
            64,
        )
    }

    fn make_signed_receipt(model_id: &str, seq: u64) -> (AttestationReceipt, ReceiptSigningKey) {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut receipt = make_receipt(model_id, seq);
        receipt.sign(&key).unwrap();
        (receipt, key)
    }

    #[test]
    fn test_sig_001_pass() {
        let (receipt, key) = make_signed_receipt("model", 0);
        let result = check_sig_001(&receipt, &key.public_key);
        assert!(result.passed);
    }

    #[test]
    fn test_sig_001_fail_wrong_key() {
        let (receipt, _key) = make_signed_receipt("model", 0);
        let other_key = ReceiptSigningKey::generate().unwrap();
        let result = check_sig_001(&receipt, &other_key.public_key);
        assert!(!result.passed);
    }

    #[test]
    fn test_sig_002_pass() {
        let receipt = make_receipt("model", 0);
        let result = check_sig_002(&receipt);
        assert!(result.passed);
    }

    #[test]
    fn test_meas_001_pass() {
        let receipt = make_receipt("model", 0);
        let result = check_meas_001(&receipt);
        assert!(result.passed);
    }

    #[test]
    fn test_meas_001_fail() {
        let mut receipt = make_receipt("model", 0);
        receipt.enclave_measurements.pcr0 = vec![0u8; 32]; // wrong length
        let result = check_meas_001(&receipt);
        assert!(!result.passed);
    }

    #[test]
    fn test_meas_002_nitro() {
        let receipt = make_receipt("model", 0);
        let result = check_meas_002(&receipt);
        assert!(result.passed);
    }

    #[test]
    fn test_meas_002_unknown() {
        let mut receipt = make_receipt("model", 0);
        receipt.enclave_measurements.measurement_type = "sev-snp".to_string();
        let result = check_meas_002(&receipt);
        assert!(!result.passed);
    }

    #[test]
    fn test_fresh_001_pass() {
        let receipt = make_receipt("model", 0);
        let result = check_fresh_001(&receipt, 3600);
        assert!(result.passed);
    }

    #[test]
    fn test_fresh_002_pass() {
        let receipt = make_receipt("model", 0);
        let result = check_fresh_002(&receipt);
        assert!(result.passed);
    }

    #[test]
    fn test_fresh_002_future() {
        let mut receipt = make_receipt("model", 0);
        receipt.execution_timestamp = ephemeral_ml_common::current_timestamp() + 3600;
        let result = check_fresh_002(&receipt);
        assert!(!result.passed);
    }

    #[test]
    fn test_model_001_pass() {
        let receipt = make_receipt("model-x", 0);
        let result = check_model_001(&receipt);
        assert!(result.passed);
    }

    #[test]
    fn test_model_001_fail() {
        let receipt = make_receipt("", 0);
        let result = check_model_001(&receipt);
        assert!(!result.passed);
    }

    #[test]
    fn test_chain_001_none() {
        let receipt = make_receipt("model", 0);
        let result = check_chain_001(&receipt);
        assert!(result.passed);
    }

    #[test]
    fn test_chain_001_valid_hash() {
        let mut receipt = make_receipt("model", 1);
        receipt.previous_receipt_hash = Some([0xab; 32]);
        let result = check_chain_001(&receipt);
        assert!(result.passed);
    }

    #[test]
    fn test_chain_001_zero_hash() {
        let mut receipt = make_receipt("model", 1);
        receipt.previous_receipt_hash = Some([0u8; 32]);
        let result = check_chain_001(&receipt);
        assert!(!result.passed);
    }

    #[test]
    fn test_policy_001_pass() {
        let receipt = make_receipt("model", 0);
        let result = check_policy_001(&receipt);
        assert!(result.passed);
    }

    #[test]
    fn test_policy_001_fail() {
        let mut receipt = make_receipt("model", 0);
        receipt.policy_version = String::new();
        let result = check_policy_001(&receipt);
        assert!(!result.passed);
    }

    #[test]
    fn test_seq_001_single() {
        let receipt = make_receipt("model", 42);
        let result = check_seq_001(&[receipt]);
        assert!(result.passed);
    }

    #[test]
    fn test_seq_001_increasing() {
        let r1 = make_receipt("model", 0);
        let r2 = make_receipt("model", 1);
        let r3 = make_receipt("model", 2);
        let result = check_seq_001(&[r1, r2, r3]);
        assert!(result.passed);
    }

    #[test]
    fn test_seq_001_not_increasing() {
        let r1 = make_receipt("model", 5);
        let r2 = make_receipt("model", 3);
        let result = check_seq_001(&[r1, r2]);
        assert!(!result.passed);
    }

    #[test]
    fn test_seq_001_empty() {
        let result = check_seq_001(&[]);
        assert!(!result.passed);
    }
}
