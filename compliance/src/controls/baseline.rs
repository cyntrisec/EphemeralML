//! Baseline control definitions: EML-SIG-001 through EML-DESTROY-001.

use super::{ControlDefinition, ControlRegistry};

/// Create a `ControlRegistry` with all 16 baseline controls and their
/// rule-to-control mappings.
pub fn baseline_registry() -> ControlRegistry {
    let mappings = vec![
        (
            ControlDefinition {
                control_id: "EML-SIG-001".to_string(),
                name: "Receipt signature verification".to_string(),
                description: "Ed25519 verify_strict on every attested execution receipt"
                    .to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Signature".to_string(),
            },
            vec!["SIG-001".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-SIG-002".to_string(),
                name: "CBOR canonical determinism".to_string(),
                description:
                    "Receipt canonical encoding produces identical bytes across invocations"
                        .to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Signature".to_string(),
            },
            vec!["SIG-002".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-ATT-001".to_string(),
                name: "Attestation document present".to_string(),
                description: "Evidence bundle contains a raw attestation document".to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Attestation".to_string(),
            },
            vec!["ATT-001".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-ATT-002".to_string(),
                name: "Attestation hash binding".to_string(),
                description: "SHA-256 of attestation matches receipt.attestation_doc_hash"
                    .to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Attestation".to_string(),
            },
            vec!["ATT-002".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-MEAS-001".to_string(),
                name: "Measurement length validation".to_string(),
                description: "PCR/MRTD measurements are 48 bytes (SHA-384)".to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Measurements".to_string(),
            },
            vec!["MEAS-001".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-MEAS-002".to_string(),
                name: "Recognized measurement type".to_string(),
                description:
                    "Measurement type is a recognized TEE platform (nitro-pcr or tdx-mrtd-rtmr)"
                        .to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Measurements".to_string(),
            },
            vec!["MEAS-002".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-FRESH-001".to_string(),
                name: "Receipt freshness".to_string(),
                description: "Receipt is within the maximum allowed age".to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Freshness".to_string(),
            },
            vec!["FRESH-001".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-FRESH-002".to_string(),
                name: "Receipt not future-dated".to_string(),
                description: "Receipt timestamp is not in the future".to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Freshness".to_string(),
            },
            vec!["FRESH-002".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-MODEL-001".to_string(),
                name: "Model ID present".to_string(),
                description: "Receipt contains a non-empty model_id".to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Model".to_string(),
            },
            vec!["MODEL-001".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-MODEL-002".to_string(),
                name: "Model manifest present".to_string(),
                description: "Evidence bundle contains a ModelManifest evidence item".to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Model".to_string(),
            },
            vec!["MODEL-002".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-CHAIN-001".to_string(),
                name: "Receipt chain hash".to_string(),
                description:
                    "If previous_receipt_hash is present, it is a valid 32-byte non-zero hash"
                        .to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Chain".to_string(),
            },
            vec!["CHAIN-001".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-CBOR-001".to_string(),
                name: "CBOR deterministic encoding".to_string(),
                description: "CBOR canonical round-trip produces identical bytes".to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Encoding".to_string(),
            },
            vec!["CBOR-001".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-KEY-001".to_string(),
                name: "Signing key attestation binding".to_string(),
                description: "Evidence bundle contains a signing-key-attestation binding"
                    .to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Key Binding".to_string(),
            },
            vec!["KEY-001".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-POLICY-001".to_string(),
                name: "Policy version present".to_string(),
                description: "Receipt contains a non-empty policy_version".to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Policy".to_string(),
            },
            vec!["POLICY-001".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-SEQ-001".to_string(),
                name: "Sequence number ordering".to_string(),
                description: "Sequence numbers are strictly increasing across receipts".to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Sequencing".to_string(),
            },
            vec!["SEQ-001".to_string()],
        ),
        (
            ControlDefinition {
                control_id: "EML-DESTROY-001".to_string(),
                name: "Destroy evidence present".to_string(),
                description: "Receipt contains destroy evidence with at least one cleanup action"
                    .to_string(),
                regulation: "EphemeralML Baseline".to_string(),
                section: "Destruction".to_string(),
            },
            vec!["DESTROY-001".to_string()],
        ),
    ];

    ControlRegistry::new(mappings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyResult, RuleResult};

    fn all_passing_policy() -> PolicyResult {
        let rule_ids = [
            "SIG-001",
            "SIG-002",
            "ATT-001",
            "ATT-002",
            "MEAS-001",
            "MEAS-002",
            "FRESH-001",
            "FRESH-002",
            "MODEL-001",
            "MODEL-002",
            "CHAIN-001",
            "CBOR-001",
            "KEY-001",
            "POLICY-001",
            "SEQ-001",
            "DESTROY-001",
        ];
        let rules = rule_ids
            .iter()
            .map(|id| RuleResult {
                rule_id: id.to_string(),
                rule_name: format!("Rule {}", id),
                passed: true,
                reason: "pass".to_string(),
            })
            .collect();

        PolicyResult {
            compliant: true,
            profile_name: "baseline".to_string(),
            rules,
            summary: "all pass".to_string(),
        }
    }

    #[test]
    fn test_baseline_registry_all_pass() {
        let registry = baseline_registry();
        let policy = all_passing_policy();
        let results = registry.evaluate(&policy);
        assert_eq!(results.len(), 16);
        assert!(results.iter().all(|r| r.satisfied));
    }

    #[test]
    fn test_baseline_registry_one_failure() {
        let registry = baseline_registry();
        let mut policy = all_passing_policy();
        // Fail SIG-001
        policy.rules[0].passed = false;
        let results = registry.evaluate(&policy);
        // EML-SIG-001 should be unsatisfied
        let sig_ctl = results
            .iter()
            .find(|r| r.control.control_id == "EML-SIG-001")
            .unwrap();
        assert!(!sig_ctl.satisfied);

        // All others should still be satisfied
        let other_count = results
            .iter()
            .filter(|r| r.control.control_id != "EML-SIG-001" && r.satisfied)
            .count();
        assert_eq!(other_count, 15);
    }
}
