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

        TrustCenterResponse {
            verdict: if result.verified {
                Verdict::Verified
            } else {
                Verdict::Invalid
            },
            verified: result.verified,
            format: ReceiptFormat::Legacy,
            assurance_level: AssuranceLevel::LegacyLocal,
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
        }
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

        TrustCenterResponse {
            verdict: if result.verified {
                Verdict::Verified
            } else {
                Verdict::Invalid
            },
            verified: result.verified,
            format: ReceiptFormat::AirV1,
            assurance_level: AssuranceLevel::AirLocal,
            tee_provenance_verified: false,
            api_version: "v1",
            verified_at: ephemeral_ml_common::current_timestamp().unwrap_or(0),
            receipt: summary,
            checks,
            errors,
            warnings: vec![],
        }
    }

    pub fn add_check(&mut self, check: TrustCenterCheck) {
        self.checks.push(check);
        self.refresh_verdict_from_checks();
    }

    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    pub fn set_tee_provenance_verified(&mut self) {
        self.assurance_level = AssuranceLevel::TeeProvenance;
        self.tee_provenance_verified = true;
    }

    pub fn set_platform_attested(&mut self) {
        self.assurance_level = AssuranceLevel::PlatformAttested;
        self.tee_provenance_verified = false;
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
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        // Last 6 bytes as a single hex string
        ((bytes[10] as u64) << 40)
            | ((bytes[11] as u64) << 32)
            | ((bytes[12] as u64) << 24)
            | ((bytes[13] as u64) << 16)
            | ((bytes[14] as u64) << 8)
            | (bytes[15] as u64),
    )
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
}
