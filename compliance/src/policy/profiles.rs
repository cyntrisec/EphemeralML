//! Predefined compliance profiles.

use serde::{Deserialize, Serialize};

/// A compliance profile defines which rules to evaluate and with what parameters.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ComplianceProfile {
    /// Profile name (e.g. "baseline", "hipaa").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Ordered list of rule IDs to evaluate.
    pub rule_ids: Vec<String>,
    /// Maximum receipt age in seconds for freshness checks.
    pub max_receipt_age_secs: u64,
}

/// All 16 rule IDs in evaluation order.
fn all_rule_ids() -> Vec<String> {
    vec![
        "SIG-001".to_string(),
        "SIG-002".to_string(),
        "ATT-001".to_string(),
        "ATT-002".to_string(),
        "MEAS-001".to_string(),
        "MEAS-002".to_string(),
        "FRESH-001".to_string(),
        "FRESH-002".to_string(),
        "MODEL-001".to_string(),
        "MODEL-002".to_string(),
        "CHAIN-001".to_string(),
        "CBOR-001".to_string(),
        "KEY-001".to_string(),
        "POLICY-001".to_string(),
        "SEQ-001".to_string(),
        "DESTROY-001".to_string(),
    ]
}

/// Baseline compliance profile: all 16 rules, 1-hour max receipt age.
pub fn baseline_profile() -> ComplianceProfile {
    ComplianceProfile {
        name: "baseline".to_string(),
        description: "EphemeralML baseline compliance profile covering all 16 verification rules"
            .to_string(),
        rule_ids: all_rule_ids(),
        max_receipt_age_secs: 3600,
    }
}

/// HIPAA-aligned compliance profile: all 16 rules, 1-hour max receipt age.
///
/// Maps to HIPAA 164.312 technical safeguard controls:
/// - 164.312(a)(1) Access control: ATT-001, ATT-002, MEAS-001
/// - 164.312(b) Audit controls: SIG-001, SEQ-001, CHAIN-001, DESTROY-001
/// - 164.312(c)(1) Integrity: MODEL-001, MODEL-002, CBOR-001
/// - 164.312(e)(1) Transmission security: KEY-001, ATT-002
pub fn hipaa_profile() -> ComplianceProfile {
    ComplianceProfile {
        name: "hipaa".to_string(),
        description: "HIPAA 164.312 technical safeguard compliance profile. \
                       Maps EphemeralML rules to HIPAA access control, audit, \
                       integrity, and transmission security requirements."
            .to_string(),
        rule_ids: all_rule_ids(),
        max_receipt_age_secs: 3600,
    }
}

/// Look up a profile by name.
pub fn profile_by_name(name: &str) -> Option<ComplianceProfile> {
    match name {
        "baseline" => Some(baseline_profile()),
        "hipaa" => Some(hipaa_profile()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_profile() {
        let p = baseline_profile();
        assert_eq!(p.name, "baseline");
        assert_eq!(p.rule_ids.len(), 16);
        assert_eq!(p.max_receipt_age_secs, 3600);
    }

    #[test]
    fn test_hipaa_profile() {
        let p = hipaa_profile();
        assert_eq!(p.name, "hipaa");
        assert_eq!(p.rule_ids.len(), 16);
        assert!(p.description.contains("HIPAA"));
    }

    #[test]
    fn test_profile_by_name() {
        assert!(profile_by_name("baseline").is_some());
        assert!(profile_by_name("hipaa").is_some());
        assert!(profile_by_name("nonexistent").is_none());
    }
}
