//! Policy evaluation engine and result types.

pub mod profiles;
pub mod rules;

use ed25519_dalek::VerifyingKey;
use ephemeral_ml_common::receipt_signing::AttestationReceipt;
use serde::{Deserialize, Serialize};

use crate::error::ComplianceResult;
use crate::evidence::EvidenceBundle;
use profiles::ComplianceProfile;

/// Result of a single policy rule evaluation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuleResult {
    /// Unique rule identifier (e.g. "SIG-001").
    pub rule_id: String,
    /// Human-readable rule name.
    pub rule_name: String,
    /// Whether the rule passed.
    pub passed: bool,
    /// Explanation of the result.
    pub reason: String,
}

/// Aggregate result of evaluating all rules in a compliance profile.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PolicyResult {
    /// Whether all rules passed.
    pub compliant: bool,
    /// The name of the profile that was evaluated.
    pub profile_name: String,
    /// Individual rule results.
    pub rules: Vec<RuleResult>,
    /// Human-readable summary.
    pub summary: String,
}

/// Policy engine that evaluates evidence bundles against compliance profiles.
pub struct PolicyEngine;

impl PolicyEngine {
    /// Evaluate a bundle and receipt against the given compliance profile.
    ///
    /// Iterates through the profile's rule IDs and dispatches to the
    /// corresponding rule function. Unknown rule IDs are reported as
    /// failures rather than silently ignored.
    pub fn evaluate(
        &self,
        bundle: &EvidenceBundle,
        receipt: &AttestationReceipt,
        public_key: &VerifyingKey,
        profile: &ComplianceProfile,
    ) -> ComplianceResult<PolicyResult> {
        let mut results = Vec::new();

        for rule_id in &profile.rule_ids {
            let result = match rule_id.as_str() {
                "SIG-001" => rules::check_sig_001(receipt, public_key),
                "SIG-002" => rules::check_sig_002(receipt),
                "ATT-001" => rules::check_att_001(bundle),
                "ATT-002" => rules::check_att_002(bundle, receipt),
                "MEAS-001" => rules::check_meas_001(receipt),
                "MEAS-002" => rules::check_meas_002(receipt),
                "FRESH-001" => rules::check_fresh_001(receipt, profile.max_receipt_age_secs),
                "FRESH-002" => rules::check_fresh_002(receipt),
                "MODEL-001" => rules::check_model_001(receipt),
                "MODEL-002" => rules::check_model_002(bundle),
                "CHAIN-001" => rules::check_chain_001(receipt),
                "CBOR-001" => rules::check_cbor_001(receipt),
                "KEY-001" => rules::check_key_001(bundle),
                "POLICY-001" => rules::check_policy_001(receipt),
                // v0.1: single-receipt bundles only. SEQ-001 is a structural check
                // (sequence_number >= 0). Multi-receipt monotonicity deferred to v0.2.
                "SEQ-001" => rules::check_seq_001(std::slice::from_ref(receipt)),
                unknown => RuleResult {
                    rule_id: unknown.to_string(),
                    rule_name: "Unknown rule".to_string(),
                    passed: false,
                    reason: format!("Unknown rule ID: {}", unknown),
                },
            };
            results.push(result);
        }

        let pass_count = results.iter().filter(|r| r.passed).count();
        let total = results.len();
        let compliant = results.iter().all(|r| r.passed);

        let summary = if compliant {
            format!("All {} rules passed for profile '{}'", total, profile.name)
        } else {
            let failed: Vec<&str> = results
                .iter()
                .filter(|r| !r.passed)
                .map(|r| r.rule_id.as_str())
                .collect();
            format!(
                "{}/{} rules passed for profile '{}'. Failed: {}",
                pass_count,
                total,
                profile.name,
                failed.join(", ")
            )
        };

        Ok(PolicyResult {
            compliant,
            profile_name: profile.name.clone(),
            rules: results,
            summary,
        })
    }
}
