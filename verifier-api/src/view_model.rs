//! Normalized trust-center response model.
//!
//! Unifies AIR v1 and legacy receipt verification results into a single
//! response shape that the UI and API consumers can rely on, regardless
//! of the underlying receipt format.

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
            TrustCenterCheck {
                id: "signature",
                label: "Signature (Ed25519)",
                status: map_status(&c.signature),
                layer: Some("crypto"),
                detail: None,
            },
            TrustCenterCheck {
                id: "model_match",
                label: "Model ID match",
                status: map_status(&c.model_match),
                layer: Some("policy"),
                detail: None,
            },
            TrustCenterCheck {
                id: "measurement_type",
                label: "Measurement type",
                status: map_status(&c.measurement_type),
                layer: Some("policy"),
                detail: None,
            },
            TrustCenterCheck {
                id: "timestamp_fresh",
                label: "Timestamp freshness",
                status: map_status(&c.timestamp_fresh),
                layer: Some("policy"),
                detail: None,
            },
            TrustCenterCheck {
                id: "measurements_present",
                label: "Measurements present",
                status: map_status(&c.measurements_present),
                layer: Some("claim"),
                detail: None,
            },
            TrustCenterCheck {
                id: "attestation_source",
                label: "Attestation source",
                status: map_status(&c.attestation_source),
                layer: Some("policy"),
                detail: None,
            },
            TrustCenterCheck {
                id: "image_digest",
                label: "Image digest",
                status: map_status(&c.image_digest),
                layer: Some("policy"),
                detail: None,
            },
            TrustCenterCheck {
                id: "destroy_evidence",
                label: "Destroy evidence",
                status: map_status(&c.destroy_evidence),
                layer: Some("policy"),
                detail: None,
            },
        ];

        TrustCenterResponse {
            verdict: if result.verified {
                Verdict::Verified
            } else {
                Verdict::Invalid
            },
            verified: result.verified,
            format: ReceiptFormat::Legacy,
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
                // Map AIR check names to layer categories.
                // Names must match actual AirCheck names emitted by air_verify.rs.
                let layer = match c.name {
                    "SIZE" | "COSE_DECODE" | "ALG" | "CONTENT_TYPE" | "PAYLOAD"
                    | "CLAIMS_DECODE" | "EAT_PROFILE" => Some("parse"),
                    "SIG" => Some("crypto"),
                    "CTI" | "MHASH_PRESENT" | "MEAS" | "MTYPE" | "MHASH_SCHEME" => Some("claim"),
                    n if n.starts_with("CLAIM_") || n.starts_with("HASH_") => Some("claim"),
                    // Layer 4 policy: FRESH, MHASH, MODEL, PLATFORM, NONCE, REPLAY
                    _ => Some("policy"),
                };
                TrustCenterCheck {
                    id: c.name,
                    label: air_check_label(c.name),
                    status,
                    layer,
                    detail: c.detail.clone(),
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
            api_version: "v1",
            verified_at: ephemeral_ml_common::current_timestamp().unwrap_or(0),
            receipt: summary,
            checks,
            errors,
            warnings: vec![],
        }
    }
}

/// Map AIR check name to a human-readable label.
///
/// Names must match the actual `AirCheck.name` values emitted by
/// `common/src/air_verify.rs`. Keep this in sync when adding checks.
fn air_check_label(name: &str) -> &'static str {
    match name {
        // Layer 1: parse
        "SIZE" => "Receipt size limit",
        "COSE_DECODE" => "COSE envelope",
        "ALG" => "Algorithm header",
        "CONTENT_TYPE" => "Content type",
        "PAYLOAD" => "Payload present",
        "CLAIMS_DECODE" => "Claims structure",
        "EAT_PROFILE" => "AIR v1 profile",
        // Layer 2: crypto
        "SIG" => "Signature (Ed25519)",
        // Layer 3: claim validation
        "CTI" => "Receipt ID valid",
        "MHASH_PRESENT" => "Model hash non-zero",
        "MEAS" => "Measurements present",
        "MTYPE" => "Measurement type valid",
        "MHASH_SCHEME" => "Model hash scheme",
        // Layer 4: policy
        "FRESH" => "Timestamp freshness",
        "MHASH" => "Model hash match",
        "MODEL" => "Model ID match",
        "PLATFORM" => "Platform match",
        "NONCE" => "Nonce match",
        "REPLAY" => "Replay detection",
        // Dynamic prefixes
        _ => {
            if name.starts_with("CLAIM_") {
                "Required claim present"
            } else if name.starts_with("HASH_") {
                "Hash field valid"
            } else {
                "Verification check"
            }
        }
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
