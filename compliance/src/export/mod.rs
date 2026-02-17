//! Bundle export with policy results, control results, and optional signing.

pub mod json_export;
pub mod signing;

use serde::{Deserialize, Serialize};

use crate::controls::ControlResult;
use crate::error::ComplianceResult;
use crate::evidence::EvidenceBundle;
use crate::policy::PolicyResult;

/// A signed (or unsigned) evidence bundle with all evaluation results.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedEvidenceBundle {
    /// The underlying evidence bundle.
    pub bundle: EvidenceBundle,
    /// Policy evaluation result.
    pub policy_result: PolicyResult,
    /// Control evaluation results.
    pub control_results: Vec<ControlResult>,
    /// RFC 3339 timestamp of when this export was created.
    pub exported_at: String,
    /// Optional Ed25519 signature over the JSON-serialized content.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature: Option<Vec<u8>>,
}

/// Builder for creating `SignedEvidenceBundle` instances.
pub struct BundleExporter {
    bundle: EvidenceBundle,
    policy_result: PolicyResult,
    control_results: Vec<ControlResult>,
}

impl BundleExporter {
    /// Create a new exporter with the given evaluation results.
    pub fn new(
        bundle: EvidenceBundle,
        policy_result: PolicyResult,
        control_results: Vec<ControlResult>,
    ) -> Self {
        Self {
            bundle,
            policy_result,
            control_results,
        }
    }

    /// Export as an unsigned `SignedEvidenceBundle`.
    pub fn export(self) -> ComplianceResult<SignedEvidenceBundle> {
        Ok(SignedEvidenceBundle {
            bundle: self.bundle,
            policy_result: self.policy_result,
            control_results: self.control_results,
            exported_at: chrono::Utc::now().to_rfc3339(),
            signature: None,
        })
    }
}
