//! Control definitions and evaluation for regulatory frameworks.

pub mod baseline;
pub mod hipaa;

use serde::{Deserialize, Serialize};

use crate::policy::PolicyResult;

/// A control definition from a regulatory framework or internal standard.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ControlDefinition {
    /// Control identifier (e.g. "EML-SIG-001", "HIPAA-164.312(a)(1)").
    pub control_id: String,
    /// Human-readable control name.
    pub name: String,
    /// Detailed description of the control requirement.
    pub description: String,
    /// The regulation or standard (e.g. "EphemeralML Baseline", "HIPAA").
    pub regulation: String,
    /// The section of the regulation (e.g. "164.312(a)(1)").
    pub section: String,
}

/// The result of evaluating a single control against policy results.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ControlResult {
    /// The control that was evaluated.
    pub control: ControlDefinition,
    /// Whether the control is satisfied.
    pub satisfied: bool,
    /// Rule IDs that support this control.
    pub supporting_rules: Vec<String>,
    /// Evidence item IDs referenced by this control.
    pub evidence_refs: Vec<String>,
}

/// A registry of controls with rule-to-control mappings.
pub struct ControlRegistry {
    /// (control_definition, required_rule_ids)
    mappings: Vec<(ControlDefinition, Vec<String>)>,
}

impl ControlRegistry {
    /// Create a new registry with the given mappings.
    pub fn new(mappings: Vec<(ControlDefinition, Vec<String>)>) -> Self {
        Self { mappings }
    }

    /// Evaluate all registered controls against a policy result.
    ///
    /// A control is satisfied if all of its required rules passed.
    pub fn evaluate(&self, policy_result: &PolicyResult) -> Vec<ControlResult> {
        self.mappings
            .iter()
            .map(|(control, required_rules)| {
                let all_passed = required_rules.iter().all(|rule_id| {
                    policy_result
                        .rules
                        .iter()
                        .any(|r| r.rule_id == *rule_id && r.passed)
                });

                ControlResult {
                    control: control.clone(),
                    satisfied: all_passed,
                    supporting_rules: required_rules.clone(),
                    evidence_refs: Vec::new(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyResult, RuleResult};

    fn make_policy_result(rules: Vec<(&str, bool)>) -> PolicyResult {
        let rule_results: Vec<RuleResult> = rules
            .into_iter()
            .map(|(id, passed)| RuleResult {
                rule_id: id.to_string(),
                rule_name: format!("Rule {}", id),
                passed,
                reason: "test".to_string(),
            })
            .collect();

        let compliant = rule_results.iter().all(|r| r.passed);
        PolicyResult {
            compliant,
            profile_name: "test".to_string(),
            rules: rule_results,
            summary: "test".to_string(),
        }
    }

    #[test]
    fn test_control_satisfied_when_all_rules_pass() {
        let control = ControlDefinition {
            control_id: "CTL-001".to_string(),
            name: "Test control".to_string(),
            description: "Test".to_string(),
            regulation: "Test".to_string(),
            section: "1.1".to_string(),
        };
        let registry = ControlRegistry::new(vec![(
            control,
            vec!["SIG-001".to_string(), "ATT-001".to_string()],
        )]);

        let policy = make_policy_result(vec![("SIG-001", true), ("ATT-001", true)]);
        let results = registry.evaluate(&policy);
        assert_eq!(results.len(), 1);
        assert!(results[0].satisfied);
    }

    #[test]
    fn test_control_not_satisfied_when_rule_fails() {
        let control = ControlDefinition {
            control_id: "CTL-002".to_string(),
            name: "Test control".to_string(),
            description: "Test".to_string(),
            regulation: "Test".to_string(),
            section: "1.2".to_string(),
        };
        let registry = ControlRegistry::new(vec![(
            control,
            vec!["SIG-001".to_string(), "ATT-001".to_string()],
        )]);

        let policy = make_policy_result(vec![("SIG-001", true), ("ATT-001", false)]);
        let results = registry.evaluate(&policy);
        assert_eq!(results.len(), 1);
        assert!(!results[0].satisfied);
    }
}
