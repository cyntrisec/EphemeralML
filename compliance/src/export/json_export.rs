//! JSON serialization for signed evidence bundles.

use super::SignedEvidenceBundle;
use crate::error::{ComplianceError, ComplianceResult};

/// Serialize a `SignedEvidenceBundle` to pretty-printed JSON.
pub fn to_json(bundle: &SignedEvidenceBundle) -> ComplianceResult<String> {
    serde_json::to_string_pretty(bundle).map_err(|e| {
        ComplianceError::serialization_error(format!("JSON serialization failed: {}", e))
    })
}

/// Deserialize a `SignedEvidenceBundle` from JSON.
pub fn from_json(json: &str) -> ComplianceResult<SignedEvidenceBundle> {
    serde_json::from_str(json).map_err(|e| {
        ComplianceError::serialization_error(format!("JSON deserialization failed: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{EvidenceBundle, EvidenceItem, EvidenceType};
    use crate::policy::{PolicyResult, RuleResult};

    fn make_test_bundle() -> SignedEvidenceBundle {
        SignedEvidenceBundle {
            bundle: EvidenceBundle {
                schema_version: "0.1".to_string(),
                bundle_id: "test-bundle".to_string(),
                created_at: "2026-02-17T00:00:00Z".to_string(),
                items: vec![EvidenceItem {
                    item_id: "item-1".to_string(),
                    evidence_type: EvidenceType::Receipt,
                    data: vec![1, 2, 3],
                    hash: [1u8; 32],
                    description: "test".to_string(),
                }],
                bindings: vec![],
            },
            policy_result: PolicyResult {
                compliant: true,
                profile_name: "baseline".to_string(),
                rules: vec![RuleResult {
                    rule_id: "SIG-001".to_string(),
                    rule_name: "test".to_string(),
                    passed: true,
                    reason: "ok".to_string(),
                }],
                summary: "ok".to_string(),
            },
            control_results: vec![],
            exported_at: "2026-02-17T00:00:00Z".to_string(),
            signature: None,
        }
    }

    #[test]
    fn test_json_round_trip() {
        let bundle = make_test_bundle();
        let json = to_json(&bundle).unwrap();
        let decoded = from_json(&json).unwrap();
        assert_eq!(decoded.bundle.bundle_id, "test-bundle");
        assert!(decoded.policy_result.compliant);
    }

    #[test]
    fn test_json_is_pretty() {
        let bundle = make_test_bundle();
        let json = to_json(&bundle).unwrap();
        assert!(json.contains('\n'));
    }
}
