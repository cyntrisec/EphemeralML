//! HIPAA 164.312 control definitions and EML rule mappings.
//!
//! Maps HIPAA technical safeguard sections to EphemeralML rules:
//! - 164.312(a)(1) Access control: EML-ATT-001, EML-ATT-002, EML-MEAS-001
//! - 164.312(b) Audit controls: EML-SIG-001, EML-SEQ-001, EML-CHAIN-001
//! - 164.312(c)(1) Integrity: EML-MODEL-001, EML-MODEL-002, EML-CBOR-001
//! - 164.312(e)(1) Transmission security: EML-KEY-001, EML-ATT-002

use super::{ControlDefinition, ControlRegistry};

/// Create a `ControlRegistry` with HIPAA 164.312 controls.
pub fn hipaa_registry() -> ControlRegistry {
    let mappings = vec![
        (
            ControlDefinition {
                control_id: "HIPAA-AC-001".to_string(),
                name: "Access control via enclave isolation".to_string(),
                description: "Enclave attestation and measurement verification \
                              ensures only authorized, measured code can access ePHI. \
                              Maps to HIPAA 164.312(a)(1)."
                    .to_string(),
                regulation: "HIPAA".to_string(),
                section: "164.312(a)(1)".to_string(),
            },
            vec![
                "ATT-001".to_string(),
                "ATT-002".to_string(),
                "MEAS-001".to_string(),
            ],
        ),
        (
            ControlDefinition {
                control_id: "HIPAA-AUDIT-001".to_string(),
                name: "Audit controls via signed receipts".to_string(),
                description: "Per-inference signed receipts with monotonic sequence \
                              numbers and chain hashes provide a complete audit trail. \
                              Maps to HIPAA 164.312(b)."
                    .to_string(),
                regulation: "HIPAA".to_string(),
                section: "164.312(b)".to_string(),
            },
            vec![
                "SIG-001".to_string(),
                "SEQ-001".to_string(),
                "CHAIN-001".to_string(),
            ],
        ),
        (
            ControlDefinition {
                control_id: "HIPAA-INT-001".to_string(),
                name: "Integrity via model hash and CBOR determinism".to_string(),
                description: "Model identity and manifest verification with deterministic \
                              CBOR encoding ensures data and code integrity. \
                              Maps to HIPAA 164.312(c)(1)."
                    .to_string(),
                regulation: "HIPAA".to_string(),
                section: "164.312(c)(1)".to_string(),
            },
            vec![
                "MODEL-001".to_string(),
                "MODEL-002".to_string(),
                "CBOR-001".to_string(),
            ],
        ),
        (
            ControlDefinition {
                control_id: "HIPAA-TRANS-001".to_string(),
                name: "Transmission security via attested key binding".to_string(),
                description: "Signing key is cryptographically bound to attestation \
                              document, and attestation hash is verified. \
                              Maps to HIPAA 164.312(e)(1)."
                    .to_string(),
                regulation: "HIPAA".to_string(),
                section: "164.312(e)(1)".to_string(),
            },
            vec!["KEY-001".to_string(), "ATT-002".to_string()],
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
            profile_name: "hipaa".to_string(),
            rules,
            summary: "all pass".to_string(),
        }
    }

    #[test]
    fn test_hipaa_registry_all_pass() {
        let registry = hipaa_registry();
        let policy = all_passing_policy();
        let results = registry.evaluate(&policy);
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|r| r.satisfied));
    }

    #[test]
    fn test_hipaa_audit_fails_when_sig_fails() {
        let registry = hipaa_registry();
        let mut policy = all_passing_policy();
        // Fail SIG-001
        if let Some(rule) = policy.rules.iter_mut().find(|r| r.rule_id == "SIG-001") {
            rule.passed = false;
        }
        let results = registry.evaluate(&policy);
        let audit = results
            .iter()
            .find(|r| r.control.control_id == "HIPAA-AUDIT-001")
            .unwrap();
        assert!(!audit.satisfied);
    }

    #[test]
    fn test_hipaa_access_fails_when_att_fails() {
        let registry = hipaa_registry();
        let mut policy = all_passing_policy();
        if let Some(rule) = policy.rules.iter_mut().find(|r| r.rule_id == "ATT-001") {
            rule.passed = false;
        }
        let results = registry.evaluate(&policy);
        let ac = results
            .iter()
            .find(|r| r.control.control_id == "HIPAA-AC-001")
            .unwrap();
        assert!(!ac.satisfied);
    }

    #[test]
    fn test_hipaa_integrity_fails_when_model_fails() {
        let registry = hipaa_registry();
        let mut policy = all_passing_policy();
        if let Some(rule) = policy.rules.iter_mut().find(|r| r.rule_id == "MODEL-001") {
            rule.passed = false;
        }
        let results = registry.evaluate(&policy);
        let int = results
            .iter()
            .find(|r| r.control.control_id == "HIPAA-INT-001")
            .unwrap();
        assert!(!int.satisfied);
    }

    #[test]
    fn test_hipaa_transmission_fails_when_key_fails() {
        let registry = hipaa_registry();
        let mut policy = all_passing_policy();
        if let Some(rule) = policy.rules.iter_mut().find(|r| r.rule_id == "KEY-001") {
            rule.passed = false;
        }
        let results = registry.evaluate(&policy);
        let trans = results
            .iter()
            .find(|r| r.control.control_id == "HIPAA-TRANS-001")
            .unwrap();
        assert!(!trans.satisfied);
    }
}
