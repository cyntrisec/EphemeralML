//! Durable Verification Center report schemas.
//!
//! These structs are intentionally separate from the existing stateless
//! verifier response model. A verifier response answers "did this receipt
//! verify right now?"; a verification report is a durable reviewer/auditor
//! object that can be saved, hashed, exported, and correlated with customer
//! evidence stores.

use crate::error::{EphemeralError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERIFICATION_REPORT_V1: &str = "1";
pub const RUNTIME_PASSPORT_V1: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportType {
    ExecutionReport,
    RuntimePassport,
    EvidenceBundleReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Pass,
    Fail,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportCheckStatus {
    Pass,
    Fail,
    Skip,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReportV1 {
    pub schema_version: String,
    pub report_id: String,
    pub report_type: ReportType,
    pub created_at: u64,
    pub verified_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub verifier: VerifierSummary,
    pub policy: PolicySummary,
    pub overall_status: ReportStatus,
    pub assurance_level: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ReceiptEvidenceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_passport_ref: Option<RuntimePassportRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_bundle: Option<EvidenceBundleSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_correlation: Option<CloudCorrelation>,
    pub checks: Vec<ReportCheck>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub limitations: Vec<Limitation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePassportV1 {
    pub schema_version: String,
    pub passport_id: String,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub overall_status: ReportStatus,
    pub deployment: DeploymentSummary,
    pub runtime: RuntimeSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_evidence: Option<PlatformEvidenceSummary>,
    pub doctor: ComponentResult,
    pub smoke_test: ComponentResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<ComponentResult>,
    pub release: ReleaseSummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub measurements: Vec<MeasurementSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_bundle: Option<EvidenceBundleSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<ReportCheck>,
    pub verifier: VerifierSummary,
    pub limitations: Vec<Limitation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierSummary {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySummary {
    pub policy_id: String,
    pub policy_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_security_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_model_hash: Option<String>,
    pub require_tee_provenance: bool,
    pub require_runtime_passport: bool,
    pub require_cloud_correlation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptEvidenceSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hash_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_doc_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePassportRef {
    pub passport_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundleSummary {
    pub bundle_type: String,
    pub bundle_format_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256sums_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDigest {
    pub name: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudCorrelation {
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_s3_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kms_request_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cloudtrail_event_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_manager_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siem_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportCheck {
    pub id: String,
    pub label: String,
    pub layer: String,
    pub status: ReportCheckStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limitation {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSummary {
    pub cloud_provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSummary {
    pub runtime_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enclave_cid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enclave_memory_mib: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enclave_cpu_count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentResult {
    pub status: ReportStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_bundle_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eif_sha384: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasurementSummary {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformEvidenceSummary {
    pub cloud_provider: String,
    pub runtime_type: String,
    pub adapter_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_nitro: Option<AwsNitroEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp_tdx: Option<GcpTdxEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_snp: Option<AzureSnpEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvidia_gpu_cc: Option<NvidiaGpuCcEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsNitroEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr0: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr8: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eif_sha384: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_key_ref_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iam_role_ref_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_s3_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcpTdxEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mrtd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtmr0: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtmr1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtmr2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtmr3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_token_issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_key_ref_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_gcs_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureSnpEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_data_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maa_result_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_vault_key_ref_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_storage_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvidiaGpuCcEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vbios_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rim_ref_hash: Option<String>,
}

impl VerificationReportV1 {
    /// Compute a stable SHA-256 over the report with `report_sha256` omitted.
    pub fn compute_report_sha256(&self) -> Result<String> {
        let mut normalized = self.clone();
        normalized.report_sha256 = None;
        let bytes = serde_json::to_vec(&normalized).map_err(|e| {
            EphemeralError::SerializationError(format!(
                "VerificationReportV1 JSON serialization failed: {}",
                e
            ))
        })?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    /// Set `report_sha256` to the current stable report hash.
    pub fn finalize_report_sha256(&mut self) -> Result<()> {
        self.report_sha256 = Some(self.compute_report_sha256()?);
        Ok(())
    }
}

impl RuntimePassportV1 {
    /// Compute a stable SHA-256 over the passport with `passport_sha256` omitted.
    pub fn compute_passport_sha256(&self) -> Result<String> {
        let mut normalized = self.clone();
        normalized.passport_sha256 = None;
        let bytes = serde_json::to_vec(&normalized).map_err(|e| {
            EphemeralError::SerializationError(format!(
                "RuntimePassportV1 JSON serialization failed: {}",
                e
            ))
        })?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    /// Set `passport_sha256` to the current stable passport hash.
    pub fn finalize_passport_sha256(&mut self) -> Result<()> {
        self.passport_sha256 = Some(self.compute_passport_sha256()?);
        Ok(())
    }
}

pub fn default_verification_limitations() -> Vec<Limitation> {
    vec![
        Limitation {
            code: "not_compliance_determination".to_string(),
            message: "Verification output is technical evidence, not a legal or regulatory compliance determination.".to_string(),
        },
        Limitation {
            code: "no_model_quality_claim".to_string(),
            message: "Verification does not prove model accuracy, fairness, safety, clinical correctness, or business appropriateness.".to_string(),
        },
        Limitation {
            code: "no_deletion_proof".to_string(),
            message: "Verification does not prove irrecoverable deletion of all possible copies.".to_string(),
        },
        Limitation {
            code: "raw_content_not_required".to_string(),
            message: "Input and output content are represented by hashes by default; raw content is not required for receipt verification.".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_report() -> VerificationReportV1 {
        VerificationReportV1 {
            schema_version: VERIFICATION_REPORT_V1.to_string(),
            report_id: "vrpt_test_001".to_string(),
            report_type: ReportType::ExecutionReport,
            created_at: 1_772_560_000,
            verified_at: 1_772_560_001,
            expires_at: Some(1_780_336_000),
            verifier: VerifierSummary {
                name: "ephemeralml-report".to_string(),
                version: "0.0.0-test".to_string(),
                git_commit: Some("abc123".to_string()),
            },
            policy: PolicySummary {
                policy_id: "production-default".to_string(),
                policy_version: "1".to_string(),
                expected_security_mode: Some("production".to_string()),
                max_age_secs: Some(3600),
                expected_model_id: Some("stage-0".to_string()),
                expected_model_hash: None,
                require_tee_provenance: true,
                require_runtime_passport: false,
                require_cloud_correlation: false,
            },
            overall_status: ReportStatus::Pass,
            assurance_level: "tee_provenance".to_string(),
            receipt: Some(ReceiptEvidenceSummary {
                receipt_id: Some("00000000-0000-4000-8000-000000000001".to_string()),
                receipt_sha256: Some("a".repeat(64)),
                model_id: Some("stage-0".to_string()),
                model_version: Some("1".to_string()),
                model_hash: Some("b".repeat(64)),
                model_hash_scheme: Some("sha256-single".to_string()),
                request_hash: None,
                response_hash: None,
                attestation_doc_hash: Some("c".repeat(64)),
                issued_at: Some(1_772_559_999),
                security_mode: Some("production".to_string()),
                platform: Some("nitro-pcr".to_string()),
            }),
            runtime_passport_ref: None,
            evidence_bundle: None,
            cloud_correlation: None,
            checks: vec![ReportCheck {
                id: "sig".to_string(),
                label: "Signature".to_string(),
                layer: "event".to_string(),
                status: ReportCheckStatus::Pass,
                detail: None,
                evidence_ref: Some("receipt.cbor".to_string()),
            }],
            warnings: vec![],
            limitations: default_verification_limitations(),
            report_sha256: None,
        }
    }

    fn fixture_passport() -> RuntimePassportV1 {
        RuntimePassportV1 {
            schema_version: RUNTIME_PASSPORT_V1.to_string(),
            passport_id: "rpass_test_001".to_string(),
            created_at: 1_772_560_000,
            expires_at: Some(1_780_336_000),
            overall_status: ReportStatus::Pass,
            deployment: DeploymentSummary {
                cloud_provider: "aws".to_string(),
                account_id: None,
                region: Some("us-east-1".to_string()),
                stack_name: Some("cyntrisec-test".to_string()),
            },
            runtime: RuntimeSummary {
                runtime_type: "aws-nitro".to_string(),
                instance_type: Some("m7i.xlarge".to_string()),
                enclave_cid: Some(16),
                enclave_memory_mib: Some(4096),
                enclave_cpu_count: Some(2),
            },
            platform_evidence: Some(PlatformEvidenceSummary {
                cloud_provider: "aws".to_string(),
                runtime_type: "aws-nitro".to_string(),
                adapter_version: "1".to_string(),
                aws_nitro: Some(AwsNitroEvidence {
                    pcr0: Some("a".repeat(96)),
                    pcr1: None,
                    pcr2: None,
                    pcr8: None,
                    eif_sha384: Some("a".repeat(96)),
                    kms_key_ref_hash: Some("sha256:".to_string() + &"b".repeat(64)),
                    iam_role_ref_hash: None,
                    evidence_s3_uri: None,
                }),
                gcp_tdx: None,
                azure_snp: None,
                nvidia_gpu_cc: None,
            }),
            doctor: ComponentResult {
                status: ReportStatus::Pass,
                duration_ms: Some(100),
                summary: Some("6/6 doctor checks passed".to_string()),
            },
            smoke_test: ComponentResult {
                status: ReportStatus::Pass,
                duration_ms: Some(200),
                summary: Some("5/5 smoke-test stages passed".to_string()),
            },
            compliance: None,
            release: ReleaseSummary {
                git_commit: Some("abc123".to_string()),
                release_bundle_sha256: None,
                eif_sha384: Some("a".repeat(96)),
            },
            measurements: vec![MeasurementSummary {
                name: "pcr0".to_string(),
                value: "a".repeat(96),
            }],
            evidence_bundle: None,
            checks: vec![ReportCheck {
                id: "platform_adapter".to_string(),
                label: "Platform evidence adapter".to_string(),
                layer: "platform".to_string(),
                status: ReportCheckStatus::Pass,
                detail: None,
                evidence_ref: None,
            }],
            verifier: VerifierSummary {
                name: "ephemeralml-runtime-passport".to_string(),
                version: "0.0.0-test".to_string(),
                git_commit: Some("abc123".to_string()),
            },
            limitations: default_verification_limitations(),
            passport_sha256: None,
        }
    }

    #[test]
    fn report_hash_is_stable_and_ignores_existing_hash_field() {
        let mut report = fixture_report();
        let first = report.compute_report_sha256().unwrap();
        report.report_sha256 = Some("0".repeat(64));
        let second = report.compute_report_sha256().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn report_hash_changes_when_evidence_changes() {
        let report = fixture_report();
        let first = report.compute_report_sha256().unwrap();
        let mut changed = report.clone();
        changed.checks[0].status = ReportCheckStatus::Fail;
        let second = changed.compute_report_sha256().unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn finalize_sets_report_hash() {
        let mut report = fixture_report();
        report.finalize_report_sha256().unwrap();
        let stored = report.report_sha256.clone().unwrap();
        assert_eq!(stored, report.compute_report_sha256().unwrap());
    }

    #[test]
    fn passport_hash_is_stable_and_ignores_existing_hash_field() {
        let mut passport = fixture_passport();
        let first = passport.compute_passport_sha256().unwrap();
        passport.passport_sha256 = Some("0".repeat(64));
        let second = passport.compute_passport_sha256().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn finalize_sets_passport_hash() {
        let mut passport = fixture_passport();
        passport.finalize_passport_sha256().unwrap();
        let stored = passport.passport_sha256.clone().unwrap();
        assert_eq!(stored, passport.compute_passport_sha256().unwrap());
    }
}
