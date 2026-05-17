//! Normalized trust-center response model.
//!
//! Unifies AIR v1 and legacy receipt verification results into a single
//! response shape that the UI and API consumers can rely on, regardless
//! of the underlying receipt format.

use ephemeral_ml_common::ui::{air_check_meta, legacy_check_meta};
use serde::Serialize;

/// Overall verification verdict.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Verified,
    Invalid,
}

/// Which receipt format was detected.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptFormat {
    AirV1,
    Legacy,
}

/// Verification assurance level represented by the response.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    /// Signature/claim/policy checks over the receipt only.
    AirLocal,
    /// Receipt-local checks plus attestation hash, signing-key binding, and
    /// platform attestation authenticity checks supplied in the request, without
    /// an explicit runtime measurement allowlist.
    PlatformAttested,
    /// Platform-attested receipt plus caller-supplied runtime measurement policy.
    TeeProvenance,
    /// Legacy receipt verification path.
    LegacyLocal,
}

/// Status of a single verification check.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Fail,
    Skip,
}

/// A single named verification check with status and optional explanation.
#[derive(Debug, Clone, Serialize)]
pub struct TrustCenterCheck {
    /// Stable check identifier (e.g. "signature", "model_match", "timestamp_fresh").
    pub id: &'static str,
    /// Human-readable label for display.
    pub label: &'static str,
    /// Check outcome.
    pub status: CheckStatus,
    /// Layer or category for grouping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<&'static str>,
    /// Optional detail on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Product-level verifier row status for compliance/auditor UX.
#[derive(Debug, Clone, Serialize)]
pub struct VerdictMatrixRow {
    /// Stable row identifier.
    pub id: &'static str,
    /// Human-readable label for display.
    pub label: &'static str,
    /// Row outcome.
    pub status: CheckStatus,
    /// Human-readable explanation for skipped or failed rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Six-row product verdict matrix shown above low-level verification checks.
#[derive(Debug, Clone, Serialize)]
pub struct VerdictMatrix {
    pub receipt_signature: VerdictMatrixRow,
    pub policy_match: VerdictMatrixRow,
    pub platform_attestation: VerdictMatrixRow,
    pub model_identity: VerdictMatrixRow,
    pub gpu_attestation: VerdictMatrixRow,
    pub overall_confidential_ai: VerdictMatrixRow,
}

/// Summary of the receipt artifact for display.
#[derive(Debug, Clone, Serialize)]
pub struct ReceiptSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_time_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_source: Option<String>,
    /// AIR v1: model_hash_scheme (e.g. "sha256-single", "sha256-manifest").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_hash_scheme: Option<String>,
}

/// The normalized trust-center API response.
///
/// This is the single response shape returned by all verification endpoints.
/// It hides whether the receipt was AIR v1 or legacy.
#[derive(Debug, Clone, Serialize)]
pub struct TrustCenterResponse {
    /// Overall verdict.
    pub verdict: Verdict,
    /// True if all non-skipped checks passed.
    pub verified: bool,
    /// Receipt format that was detected and verified.
    pub format: ReceiptFormat,
    /// Explicit assurance level. For AIR v1, `verified=true` can still be
    /// AIR-local unless attestation evidence was supplied and checked.
    pub assurance_level: AssuranceLevel,
    /// Product-level verdict rows for auditor/compliance surfaces.
    pub verdict_matrix: VerdictMatrix,
    /// True only when AIR local verification is paired with attestation hash,
    /// signing-key binding, and platform attestation authenticity checks.
    pub tee_provenance_verified: bool,
    /// API version.
    pub api_version: &'static str,
    /// Timestamp of this verification (Unix seconds).
    pub verified_at: u64,
    /// Summary of the receipt artifact.
    pub receipt: ReceiptSummary,
    /// Ordered list of verification checks.
    pub checks: Vec<TrustCenterCheck>,
    /// Errors encountered during verification.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    /// Warnings (non-fatal).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl TrustCenterResponse {
    /// Build from a legacy `VerifyResult`.
    pub fn from_legacy(result: ephemeral_ml_common::receipt_verify::VerifyResult) -> Self {
        use ephemeral_ml_common::receipt_verify::CheckStatus as LegacyStatus;

        let map_status = |s: &LegacyStatus| match s {
            LegacyStatus::Pass => CheckStatus::Pass,
            LegacyStatus::Fail => CheckStatus::Fail,
            LegacyStatus::Skip => CheckStatus::Skip,
        };

        let c = &result.checks;
        let checks = vec![
            legacy_check("signature", map_status(&c.signature)),
            legacy_check("model_match", map_status(&c.model_match)),
            legacy_check("measurement_type", map_status(&c.measurement_type)),
            legacy_check("timestamp_fresh", map_status(&c.timestamp_fresh)),
            legacy_check("measurements_present", map_status(&c.measurements_present)),
            legacy_check("attestation_source", map_status(&c.attestation_source)),
            legacy_check("image_digest", map_status(&c.image_digest)),
            legacy_check("destroy_evidence", map_status(&c.destroy_evidence)),
        ];

        let mut response = TrustCenterResponse {
            verdict: if result.verified {
                Verdict::Verified
            } else {
                Verdict::Invalid
            },
            verified: result.verified,
            format: ReceiptFormat::Legacy,
            assurance_level: AssuranceLevel::LegacyLocal,
            verdict_matrix: VerdictMatrix::default_for(ReceiptFormat::Legacy),
            tee_provenance_verified: false,
            api_version: "v1",
            verified_at: ephemeral_ml_common::current_timestamp().unwrap_or(0),
            receipt: ReceiptSummary {
                receipt_id: Some(result.receipt_id),
                model_id: Some(result.model_id),
                model_version: Some(result.model_version),
                platform: Some(result.measurement_type),
                execution_time_ms: None,
                sequence_number: Some(result.sequence_number),
                issued_at: Some(result.execution_timestamp),
                issuer: None,
                security_mode: None,
                attestation_source: result.attestation_source,
                model_hash_scheme: None,
            },
            checks,
            errors: result.errors,
            warnings: result.warnings,
        };
        response.refresh_verdict_matrix();
        response
    }

    /// Build from an AIR v1 `AirVerifyResult`.
    pub fn from_air_v1(result: ephemeral_ml_common::air_verify::AirVerifyResult) -> Self {
        use ephemeral_ml_common::air_verify::AirCheckStatus;

        let checks: Vec<TrustCenterCheck> = result
            .checks
            .iter()
            .map(|c| {
                let status = match c.status {
                    AirCheckStatus::Pass => CheckStatus::Pass,
                    AirCheckStatus::Fail => CheckStatus::Fail,
                    AirCheckStatus::Skip => CheckStatus::Skip,
                };
                let meta = air_check_meta(c.name);
                let failed = matches!(c.status, AirCheckStatus::Fail);
                let detail = c.detail.clone().or_else(|| {
                    ephemeral_ml_common::ui::explain_failed(c.name, failed)
                        .map(|e| e.why.to_string())
                });
                TrustCenterCheck {
                    id: c.name,
                    label: meta.label,
                    status,
                    layer: meta.layer,
                    detail,
                }
            })
            .collect();

        let summary = match &result.claims {
            Some(claims) => ReceiptSummary {
                receipt_id: Some(format_uuid(&claims.cti)),
                model_id: Some(claims.model_id.clone()),
                model_version: Some(claims.model_version.clone()),
                platform: Some(claims.enclave_measurements.measurement_type.clone()),
                execution_time_ms: Some(claims.execution_time_ms),
                sequence_number: Some(claims.sequence_number),
                issued_at: Some(claims.iat),
                issuer: Some(claims.iss.clone()),
                security_mode: Some(claims.security_mode.clone()),
                attestation_source: None,
                model_hash_scheme: claims.model_hash_scheme.clone(),
            },
            None => ReceiptSummary {
                receipt_id: None,
                model_id: None,
                model_version: None,
                platform: None,
                execution_time_ms: None,
                sequence_number: None,
                issued_at: None,
                issuer: None,
                security_mode: None,
                attestation_source: None,
                model_hash_scheme: None,
            },
        };

        // Collect errors from failed checks.
        let errors: Vec<String> = result
            .checks
            .iter()
            .filter(|c| matches!(c.status, AirCheckStatus::Fail))
            .map(|c| {
                let code_str = c
                    .code
                    .as_ref()
                    .map(|code| format!("{}", code))
                    .unwrap_or_default();
                match &c.detail {
                    Some(d) => format!("{}: {}", code_str, d),
                    None => code_str,
                }
            })
            .collect();

        let mut response = TrustCenterResponse {
            verdict: if result.verified {
                Verdict::Verified
            } else {
                Verdict::Invalid
            },
            verified: result.verified,
            format: ReceiptFormat::AirV1,
            assurance_level: AssuranceLevel::AirLocal,
            verdict_matrix: VerdictMatrix::default_for(ReceiptFormat::AirV1),
            tee_provenance_verified: false,
            api_version: "v1",
            verified_at: ephemeral_ml_common::current_timestamp().unwrap_or(0),
            receipt: summary,
            checks,
            errors,
            warnings: vec![],
        };
        response.refresh_verdict_matrix();
        response
    }

    pub fn add_check(&mut self, check: TrustCenterCheck) {
        self.checks.push(check);
        self.refresh_verdict_from_checks();
        self.refresh_verdict_matrix();
    }

    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    pub fn set_tee_provenance_verified(&mut self) {
        self.assurance_level = AssuranceLevel::TeeProvenance;
        self.tee_provenance_verified = true;
        self.refresh_verdict_matrix();
    }

    pub fn set_platform_attested(&mut self) {
        self.assurance_level = AssuranceLevel::PlatformAttested;
        self.tee_provenance_verified = false;
        self.refresh_verdict_matrix();
    }

    pub fn refresh_verdict_from_checks(&mut self) {
        if self
            .checks
            .iter()
            .any(|c| matches!(c.status, CheckStatus::Fail))
        {
            self.verified = false;
            self.verdict = Verdict::Invalid;
        }
    }

    pub fn refresh_verdict_matrix(&mut self) {
        self.verdict_matrix = VerdictMatrix::from_response(self);
    }
}

impl VerdictMatrix {
    fn default_for(format: ReceiptFormat) -> Self {
        Self {
            receipt_signature: matrix_row(
                "receipt_signature",
                "Receipt signature",
                CheckStatus::Skip,
                Some("receipt has not been evaluated".to_string()),
            ),
            policy_match: matrix_row(
                "policy_match",
                "Policy match",
                CheckStatus::Skip,
                Some("no policy checks evaluated".to_string()),
            ),
            platform_attestation: matrix_row(
                "platform_attestation",
                "Platform attestation",
                CheckStatus::Skip,
                Some(match format {
                    ReceiptFormat::AirV1 => "no attestation evidence supplied".to_string(),
                    ReceiptFormat::Legacy => {
                        "legacy receipt path does not expose AIR platform provenance".to_string()
                    }
                }),
            ),
            model_identity: matrix_row(
                "model_identity",
                "Model identity",
                CheckStatus::Skip,
                Some("model identity has not been evaluated".to_string()),
            ),
            gpu_attestation: matrix_row(
                "gpu_attestation",
                "GPU attestation",
                CheckStatus::Skip,
                Some("GPU evidence is not required for this verification policy".to_string()),
            ),
            overall_confidential_ai: matrix_row(
                "overall_confidential_ai",
                "Overall confidential AI",
                CheckStatus::Fail,
                Some("not enough evidence for confidential AI provenance".to_string()),
            ),
        }
    }

    fn from_response(response: &TrustCenterResponse) -> Self {
        let receipt_signature = receipt_signature_row(response);
        let policy_match = policy_match_row(response);
        let platform_attestation = platform_attestation_row(response);
        let model_identity = model_identity_row(response);
        let gpu_attestation = gpu_attestation_row(response);
        let overall_confidential_ai = overall_confidential_ai_row(
            response,
            &receipt_signature,
            &policy_match,
            &platform_attestation,
            &model_identity,
            &gpu_attestation,
        );

        Self {
            receipt_signature,
            policy_match,
            platform_attestation,
            model_identity,
            gpu_attestation,
            overall_confidential_ai,
        }
    }
}

fn receipt_signature_row(response: &TrustCenterResponse) -> VerdictMatrixRow {
    let ids = match response.format {
        ReceiptFormat::AirV1 => &[
            "SIZE",
            "COSE_DECODE",
            "ALG",
            "CONTENT_TYPE",
            "PAYLOAD",
            "CLAIMS_DECODE",
            "EAT_PROFILE",
            "SIG",
            "CTI",
            "MEAS",
            "MTYPE",
            "SECURITY_MODE",
        ][..],
        ReceiptFormat::Legacy => &["signature", "measurements_present"][..],
    };
    aggregate_row(
        response,
        "receipt_signature",
        "Receipt signature",
        ids,
        None,
    )
}

fn policy_match_row(response: &TrustCenterResponse) -> VerdictMatrixRow {
    let ids = match response.format {
        ReceiptFormat::AirV1 => &[
            "FRESH",
            "MHASH",
            "RHASH",
            "OHASH",
            "MODEL",
            "SECURITY_MODE_POLICY",
            "PLATFORM",
            "NONCE",
            "REPLAY",
        ][..],
        ReceiptFormat::Legacy => &[
            "model_match",
            "measurement_type",
            "timestamp_fresh",
            "attestation_source",
            "image_digest",
            "destroy_evidence",
        ][..],
    };
    aggregate_row(
        response,
        "policy_match",
        "Policy match",
        ids,
        Some("no expected policy fields were supplied".to_string()),
    )
}

fn platform_attestation_row(response: &TrustCenterResponse) -> VerdictMatrixRow {
    let row = aggregate_row(
        response,
        "platform_attestation",
        "Platform attestation",
        &[
            "attestation_doc_hash",
            "platform_attestation",
            "signing_key_binding",
            "runtime_measurement_policy",
        ],
        Some("no attestation evidence supplied".to_string()),
    );

    if matches!(row.status, CheckStatus::Pass)
        && matches!(response.assurance_level, AssuranceLevel::PlatformAttested)
    {
        return matrix_row(
            "platform_attestation",
            "Platform attestation",
            CheckStatus::Pass,
            Some(
                "platform evidence is authentic, but no runtime PCR allowlist was supplied"
                    .to_string(),
            ),
        );
    }

    row
}

fn model_identity_row(response: &TrustCenterResponse) -> VerdictMatrixRow {
    let ids = match response.format {
        ReceiptFormat::AirV1 => &["MHASH_PRESENT", "MHASH_SCHEME", "MHASH", "MODEL"][..],
        ReceiptFormat::Legacy => &["model_match"][..],
    };
    aggregate_row(
        response,
        "model_identity",
        "Model identity",
        ids,
        Some("no model identity evidence was evaluated".to_string()),
    )
}

fn gpu_attestation_row(response: &TrustCenterResponse) -> VerdictMatrixRow {
    aggregate_row(
        response,
        "gpu_attestation",
        "GPU attestation",
        &["gpu_attestation"],
        Some("GPU evidence is not required for this verification policy".to_string()),
    )
}

fn overall_confidential_ai_row(
    response: &TrustCenterResponse,
    receipt_signature: &VerdictMatrixRow,
    policy_match: &VerdictMatrixRow,
    platform_attestation: &VerdictMatrixRow,
    model_identity: &VerdictMatrixRow,
    gpu_attestation: &VerdictMatrixRow,
) -> VerdictMatrixRow {
    let required_pass = matches!(receipt_signature.status, CheckStatus::Pass)
        && matches!(platform_attestation.status, CheckStatus::Pass)
        && matches!(model_identity.status, CheckStatus::Pass)
        && matches!(response.assurance_level, AssuranceLevel::TeeProvenance)
        && response.verified;

    let optional_fail = matches!(policy_match.status, CheckStatus::Fail)
        || matches!(gpu_attestation.status, CheckStatus::Fail);

    if required_pass && !optional_fail {
        matrix_row(
            "overall_confidential_ai",
            "Overall confidential AI",
            CheckStatus::Pass,
            None,
        )
    } else {
        matrix_row(
            "overall_confidential_ai",
            "Overall confidential AI",
            CheckStatus::Fail,
            Some(overall_detail(
                response,
                receipt_signature,
                platform_attestation,
                model_identity,
                optional_fail,
            )),
        )
    }
}

fn overall_detail(
    response: &TrustCenterResponse,
    receipt_signature: &VerdictMatrixRow,
    platform_attestation: &VerdictMatrixRow,
    model_identity: &VerdictMatrixRow,
    optional_fail: bool,
) -> String {
    if !response.verified {
        return "receipt verification failed".to_string();
    }
    if !matches!(receipt_signature.status, CheckStatus::Pass) {
        return "receipt signature or claim structure was not proven".to_string();
    }
    if !matches!(platform_attestation.status, CheckStatus::Pass) {
        return "platform attestation was not proven; AIR-local is not confidential AI proof"
            .to_string();
    }
    if !matches!(model_identity.status, CheckStatus::Pass) {
        return "model identity was not proven".to_string();
    }
    if !matches!(response.assurance_level, AssuranceLevel::TeeProvenance) {
        return "runtime PCR policy was not supplied; assurance level is not tee_provenance"
            .to_string();
    }
    if optional_fail {
        return "one optional policy or GPU evidence row failed".to_string();
    }
    "not enough evidence for confidential AI provenance".to_string()
}

fn aggregate_row(
    response: &TrustCenterResponse,
    id: &'static str,
    label: &'static str,
    check_ids: &[&str],
    skip_detail: Option<String>,
) -> VerdictMatrixRow {
    let mut saw_pass = false;
    let mut saw_skip = false;
    let mut skip_details = Vec::new();

    for check_id in check_ids {
        for check in response.checks.iter().filter(|check| check.id == *check_id) {
            match check.status {
                CheckStatus::Fail => {
                    return matrix_row(
                        id,
                        label,
                        CheckStatus::Fail,
                        check
                            .detail
                            .clone()
                            .or_else(|| Some(format!("{} failed", check.label))),
                    );
                }
                CheckStatus::Pass => saw_pass = true,
                CheckStatus::Skip => {
                    saw_skip = true;
                    if let Some(detail) = &check.detail {
                        skip_details.push(detail.clone());
                    }
                }
            }
        }
    }

    if saw_pass {
        matrix_row(id, label, CheckStatus::Pass, None)
    } else if saw_skip {
        matrix_row(
            id,
            label,
            CheckStatus::Skip,
            skip_details.into_iter().next().or(skip_detail),
        )
    } else {
        matrix_row(id, label, CheckStatus::Skip, skip_detail)
    }
}

fn matrix_row(
    id: &'static str,
    label: &'static str,
    status: CheckStatus,
    detail: Option<String>,
) -> VerdictMatrixRow {
    VerdictMatrixRow {
        id,
        label,
        status,
        detail,
    }
}

fn legacy_check(id: &'static str, status: CheckStatus) -> TrustCenterCheck {
    use ephemeral_ml_common::ui::explain_failed;

    let meta = legacy_check_meta(id).expect("legacy check metadata must exist");
    let failed = matches!(status, CheckStatus::Fail);
    let detail = explain_failed(id, failed).map(|e| e.why.to_string());
    TrustCenterCheck {
        id,
        label: meta.label,
        status,
        layer: meta.layer,
        detail,
    }
}

/// Format a 16-byte UUID as standard hyphenated string.
fn format_uuid(bytes: &[u8; 16]) -> String {
    uuid::Uuid::from_bytes(*bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_air_response() -> TrustCenterResponse {
        TrustCenterResponse {
            verdict: Verdict::Verified,
            verified: true,
            format: ReceiptFormat::AirV1,
            assurance_level: AssuranceLevel::AirLocal,
            verdict_matrix: VerdictMatrix::default_for(ReceiptFormat::AirV1),
            tee_provenance_verified: false,
            api_version: "v1",
            verified_at: 0,
            receipt: ReceiptSummary {
                receipt_id: None,
                model_id: None,
                model_version: None,
                platform: None,
                execution_time_ms: None,
                sequence_number: None,
                issued_at: None,
                issuer: None,
                security_mode: None,
                attestation_source: None,
                model_hash_scheme: None,
            },
            checks: vec![],
            errors: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn platform_attested_is_distinct_from_tee_provenance() {
        let mut response = sample_air_response();
        response.set_platform_attested();

        assert!(matches!(
            response.assurance_level,
            AssuranceLevel::PlatformAttested
        ));
        assert!(!response.tee_provenance_verified);
    }

    #[test]
    fn tee_provenance_sets_explicit_boolean() {
        let mut response = sample_air_response();
        response.set_tee_provenance_verified();

        assert!(matches!(
            response.assurance_level,
            AssuranceLevel::TeeProvenance
        ));
        assert!(response.tee_provenance_verified);
    }

    #[test]
    fn verdict_matrix_keeps_air_local_from_overall_confidential_ai() {
        let mut response = sample_air_response();
        response.add_check(test_check("SIG", CheckStatus::Pass));
        response.add_check(test_check("MHASH_PRESENT", CheckStatus::Pass));

        assert!(matches!(
            response.verdict_matrix.receipt_signature.status,
            CheckStatus::Pass
        ));
        assert!(matches!(
            response.verdict_matrix.platform_attestation.status,
            CheckStatus::Skip
        ));
        assert!(matches!(
            response.verdict_matrix.overall_confidential_ai.status,
            CheckStatus::Fail
        ));
    }

    #[test]
    fn verdict_matrix_marks_tee_provenance_as_overall_pass() {
        let mut response = sample_air_response();
        response.add_check(test_check("SIG", CheckStatus::Pass));
        response.add_check(test_check("MHASH_PRESENT", CheckStatus::Pass));
        response.add_check(test_check("attestation_doc_hash", CheckStatus::Pass));
        response.add_check(test_check("platform_attestation", CheckStatus::Pass));
        response.add_check(test_check("signing_key_binding", CheckStatus::Pass));
        response.add_check(test_check("runtime_measurement_policy", CheckStatus::Pass));
        response.set_tee_provenance_verified();

        assert!(matches!(
            response.verdict_matrix.overall_confidential_ai.status,
            CheckStatus::Pass
        ));
    }

    fn test_check(id: &'static str, status: CheckStatus) -> TrustCenterCheck {
        TrustCenterCheck {
            id,
            label: id,
            status,
            layer: None,
            detail: None,
        }
    }
}
