//! Cyntrisec evidence event export for SIEM integrations.
//!
//! The verifier owns receipt parsing and policy checks. This module maps those
//! verified results into the stable `cyntrisec.evidence_event.v1` JSON shape
//! consumed by the integrations repository.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::VerifyingKey;
use ephemeral_ml_common::air_verify::{AirCheckStatus, AirVerifyResult};
use ephemeral_ml_common::receipt_verify::VerifyResult;
use ephemeral_ml_common::AttestationReceipt;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct EvidenceEventExportOptions {
    pub tenant_id: Option<String>,
    pub receipt_uri: Option<String>,
    pub inline_receipt: bool,
    pub evidence_bundle_uri: Option<String>,
    pub evidence_bundle_sha256: Option<[u8; 32]>,
    pub cloud_provider: Option<String>,
    pub region: Option<String>,
    pub instance_id: Option<String>,
    pub verifier_version: String,
    pub legacy_model_hash: Option<[u8; 32]>,
    pub attestation_supplied: bool,
    pub attestation_sha256: Option<[u8; 32]>,
}

#[derive(Debug, Serialize)]
pub struct CyntrisecEvidenceEventV1 {
    pub schema_version: &'static str,
    pub tenant_id: String,
    pub event_id: String,
    pub event_type: &'static str,
    pub event_time: String,
    pub severity: &'static str,
    pub verifier_version: String,
    pub verifier_result: &'static str,
    pub policy_result: &'static str,
    pub policy_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub receipt_id: String,
    pub receipt_format: &'static str,
    pub receipt_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_b64: Option<String>,
    pub model_id: String,
    pub model_version: String,
    pub model_hash: String,
    pub request_hash: String,
    pub response_hash: String,
    pub environment: EvidenceEnvironment,
    pub attestation: EvidenceAttestation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_bundle: Option<EvidenceBundle>,
    pub privacy: EvidencePrivacy,
}

#[derive(Debug, Serialize)]
pub struct EvidenceEnvironment {
    pub cloud_provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    pub tee_type: String,
    pub attestation_mode: String,
}

#[derive(Debug, Serialize)]
pub struct EvidenceAttestation {
    pub vm_status: &'static str,
    pub gpu_status: &'static str,
    pub vm_evidence_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct EvidenceBundle {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EvidencePrivacy {
    pub raw_prompt_included: bool,
    pub raw_response_included: bool,
}

pub fn build_air_evidence_event(
    result: &AirVerifyResult,
    receipt_bytes: &[u8],
    public_key: &VerifyingKey,
    options: &EvidenceEventExportOptions,
) -> Result<CyntrisecEvidenceEventV1> {
    let claims = result
        .claims
        .as_ref()
        .context("AIR receipt claims are unavailable; cannot export cyntrisec-event-v1")?;
    let (receipt_uri, receipt_b64) = receipt_reference(options, receipt_bytes)?;
    let adhash_status = air_check_status(result, "ADHASH");
    let failure_reason = air_failure_reason(result);

    Ok(CyntrisecEvidenceEventV1 {
        schema_version: "cyntrisec.evidence_event.v1",
        tenant_id: tenant_id(options)?,
        event_id: hex::encode(claims.cti),
        event_type: event_type(result.verified, failure_reason.as_deref()),
        event_time: format_unix_timestamp(claims.iat),
        severity: if result.verified { "info" } else { "high" },
        verifier_version: verifier_version(options)?,
        verifier_result: if result.verified { "pass" } else { "fail" },
        policy_result: if result.verified { "allow" } else { "deny" },
        policy_version: claims.policy_version.clone(),
        policy_id: Some(claims.policy_version.clone()),
        failure_reason,
        receipt_id: hex::encode(claims.cti),
        receipt_format: "air_v1_cose_sign1_cbor",
        receipt_sha256: sha256_hex(receipt_bytes),
        receipt_uri,
        receipt_b64,
        model_id: claims.model_id.clone(),
        model_version: claims.model_version.clone(),
        model_hash: hex::encode(claims.model_hash),
        request_hash: hex::encode(claims.request_hash),
        response_hash: hex::encode(claims.response_hash),
        environment: EvidenceEnvironment {
            cloud_provider: cloud_provider(
                options,
                None,
                &claims.enclave_measurements.measurement_type,
            )?,
            region: options.region.clone(),
            instance_id: options.instance_id.clone(),
            tee_type: tee_type(None, &claims.enclave_measurements.measurement_type),
            attestation_mode: if options.attestation_supplied {
                "receipt_plus_attestation_hash_binding".to_string()
            } else {
                "receipt_only".to_string()
            },
        },
        attestation: EvidenceAttestation {
            vm_status: air_vm_status(adhash_status),
            gpu_status: "not_checked",
            vm_evidence_sha256: hex::encode(claims.attestation_doc_hash),
            signer: Some(format!("ed25519:{}", hex::encode(public_key.to_bytes()))),
            warnings: attestation_warnings(options, adhash_status),
        },
        evidence_bundle: evidence_bundle(options),
        privacy: EvidencePrivacy {
            raw_prompt_included: false,
            raw_response_included: false,
        },
    })
}

pub fn build_legacy_evidence_event(
    result: &VerifyResult,
    receipt: &AttestationReceipt,
    receipt_bytes: &[u8],
    options: &EvidenceEventExportOptions,
) -> Result<CyntrisecEvidenceEventV1> {
    let model_hash = options.legacy_model_hash.context(
        "--expected-model-hash is required for cyntrisec-event-v1 export of legacy receipts",
    )?;
    let (receipt_uri, receipt_b64) = receipt_reference(options, receipt_bytes)?;
    let vm_status = legacy_vm_status(options, receipt);
    let verified = result.verified && vm_status != "fail";
    let mut failure_reason = legacy_failure_reason(result);
    if vm_status == "fail" && failure_reason.is_none() {
        failure_reason = Some("platform_attestation_hash_mismatch".to_string());
    }

    Ok(CyntrisecEvidenceEventV1 {
        schema_version: "cyntrisec.evidence_event.v1",
        tenant_id: tenant_id(options)?,
        event_id: event_id_from_legacy_receipt_id(&receipt.receipt_id),
        event_type: event_type(verified, failure_reason.as_deref()),
        event_time: format_unix_timestamp(receipt.execution_timestamp),
        severity: if verified { "info" } else { "high" },
        verifier_version: verifier_version(options)?,
        verifier_result: if verified { "pass" } else { "fail" },
        policy_result: if verified { "allow" } else { "deny" },
        policy_version: receipt.policy_version.clone(),
        policy_id: Some(receipt.policy_version.clone()),
        failure_reason,
        receipt_id: receipt.receipt_id.clone(),
        receipt_format: "legacy_json",
        receipt_sha256: sha256_hex(receipt_bytes),
        receipt_uri,
        receipt_b64,
        model_id: receipt.model_id.clone(),
        model_version: receipt.model_version.clone(),
        model_hash: hex::encode(model_hash),
        request_hash: hex::encode(receipt.request_hash),
        response_hash: hex::encode(receipt.response_hash),
        environment: EvidenceEnvironment {
            cloud_provider: cloud_provider(
                options,
                receipt.attestation_source.as_deref(),
                &receipt.enclave_measurements.measurement_type,
            )?,
            region: options.region.clone(),
            instance_id: options.instance_id.clone(),
            tee_type: tee_type(
                receipt.attestation_source.as_deref(),
                &receipt.enclave_measurements.measurement_type,
            ),
            attestation_mode: if options.attestation_supplied {
                "legacy_receipt_plus_attestation_hash_check".to_string()
            } else {
                "legacy_receipt_only".to_string()
            },
        },
        attestation: EvidenceAttestation {
            vm_status,
            gpu_status: "not_checked",
            vm_evidence_sha256: hex::encode(receipt.attestation_doc_hash),
            signer: None,
            warnings: legacy_attestation_warnings(options, vm_status),
        },
        evidence_bundle: evidence_bundle(options),
        privacy: EvidencePrivacy {
            raw_prompt_included: false,
            raw_response_included: false,
        },
    })
}

fn tenant_id(options: &EvidenceEventExportOptions) -> Result<String> {
    let tenant = options
        .tenant_id
        .clone()
        .context("--tenant-id or CYNTRISEC_TENANT_ID is required for cyntrisec-event-v1")?;
    if tenant.len() < 3 {
        bail!("tenant_id must be at least 3 characters for cyntrisec-event-v1");
    }
    Ok(tenant)
}

fn verifier_version(options: &EvidenceEventExportOptions) -> Result<String> {
    let version = options.verifier_version.trim();
    if version.is_empty() {
        bail!("verifier_version is required for cyntrisec-event-v1");
    }
    Ok(version.to_string())
}

fn receipt_reference(
    options: &EvidenceEventExportOptions,
    receipt_bytes: &[u8],
) -> Result<(Option<String>, Option<String>)> {
    let receipt_uri = options.receipt_uri.clone();
    let receipt_b64 = if options.inline_receipt {
        Some(BASE64_STANDARD.encode(receipt_bytes))
    } else {
        None
    };

    if receipt_uri.is_none() && receipt_b64.is_none() {
        bail!("--receipt-uri or --inline-receipt is required for cyntrisec-event-v1");
    }

    Ok((receipt_uri, receipt_b64))
}

fn evidence_bundle(options: &EvidenceEventExportOptions) -> Option<EvidenceBundle> {
    if options.evidence_bundle_uri.is_none() && options.evidence_bundle_sha256.is_none() {
        return None;
    }
    Some(EvidenceBundle {
        uri: options.evidence_bundle_uri.clone(),
        sha256: options.evidence_bundle_sha256.as_ref().map(hex::encode),
    })
}

fn cloud_provider(
    options: &EvidenceEventExportOptions,
    attestation_source: Option<&str>,
    measurement_type: &str,
) -> Result<String> {
    let provider = options
        .cloud_provider
        .clone()
        .unwrap_or_else(|| infer_cloud_provider(attestation_source, measurement_type).to_string());
    match provider.as_str() {
        "aws" | "gcp" | "azure" | "local" | "unknown" => Ok(provider),
        other => {
            bail!("--cloud-provider must be one of: aws, gcp, azure, local, unknown (got {other})")
        }
    }
}

fn infer_cloud_provider(attestation_source: Option<&str>, measurement_type: &str) -> &'static str {
    match (attestation_source, measurement_type) {
        (Some("nitro"), _) | (_, "nitro-pcr") => "aws",
        (Some("cs-tdx"), _) | (Some("tdx"), _) => "gcp",
        (Some("mock"), _) => "local",
        _ => "unknown",
    }
}

fn tee_type(attestation_source: Option<&str>, measurement_type: &str) -> String {
    if matches!(attestation_source, Some("mock")) {
        return "mock".to_string();
    }
    match measurement_type {
        "nitro-pcr" => "nitro",
        "tdx-mrtd-rtmr" => "tdx",
        "sev-snp" | "amd-sev-snp" => "amd_sev_snp",
        "sev" | "amd-sev" => "amd_sev",
        _ => "unknown",
    }
    .to_string()
}

fn air_check_status<'a>(result: &'a AirVerifyResult, name: &str) -> Option<&'a AirCheckStatus> {
    result
        .checks
        .iter()
        .find(|check| check.name == name)
        .map(|check| &check.status)
}

fn air_vm_status(status: Option<&AirCheckStatus>) -> &'static str {
    match status {
        Some(AirCheckStatus::Pass) => "pass",
        Some(AirCheckStatus::Fail) => "fail",
        Some(AirCheckStatus::Skip) | None => "not_checked",
    }
}

fn legacy_vm_status(
    options: &EvidenceEventExportOptions,
    receipt: &AttestationReceipt,
) -> &'static str {
    let Some(attestation_sha256) = options.attestation_sha256 else {
        return "not_checked";
    };
    if attestation_sha256 == receipt.attestation_doc_hash {
        "pass"
    } else {
        "fail"
    }
}

fn attestation_warnings(
    options: &EvidenceEventExportOptions,
    adhash_status: Option<&AirCheckStatus>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if !options.attestation_supplied || matches!(adhash_status, Some(AirCheckStatus::Skip) | None) {
        warnings.push("platform_attestation_not_supplied".to_string());
    }
    warnings.push("gpu_attestation_not_checked".to_string());
    warnings
}

fn legacy_attestation_warnings(
    options: &EvidenceEventExportOptions,
    vm_status: &str,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if !options.attestation_supplied {
        warnings.push("platform_attestation_not_supplied".to_string());
    } else if vm_status == "fail" {
        warnings.push("platform_attestation_hash_mismatch".to_string());
    }
    warnings.push("gpu_attestation_not_checked".to_string());
    warnings
}

fn air_failure_reason(result: &AirVerifyResult) -> Option<String> {
    result.checks.iter().find_map(|check| {
        if !matches!(check.status, AirCheckStatus::Fail) {
            return None;
        }
        Some(
            check
                .code
                .as_ref()
                .map(ToString::to_string)
                .or_else(|| check.detail.clone())
                .unwrap_or_else(|| check.name.to_string()),
        )
    })
}

fn legacy_failure_reason(result: &VerifyResult) -> Option<String> {
    result
        .errors
        .first()
        .cloned()
        .or_else(|| (!result.verified).then(|| "verification_failed".to_string()))
}

fn event_type(verified: bool, failure_reason: Option<&str>) -> &'static str {
    if verified {
        return "execution_verified";
    }

    let Some(reason) = failure_reason else {
        return "verification_failed";
    };
    let reason = reason.to_ascii_uppercase();
    if reason.contains("MODEL_")
        || reason.contains("HASH_MISMATCH")
        || reason.contains("TIMESTAMP_")
        || reason.contains("SECURITY_MODE")
        || reason.contains("PLATFORM")
        || reason.contains("NONCE")
        || reason.contains("REPLAY")
        || reason.contains("DESTROY EVIDENCE")
        || reason.contains("POLICY")
        || reason.contains("MISMATCH")
    {
        "policy_violation"
    } else {
        "verification_failed"
    }
}

fn event_id_from_legacy_receipt_id(receipt_id: &str) -> String {
    if let Ok(uuid) = uuid::Uuid::parse_str(receipt_id) {
        return hex::encode(uuid.as_bytes());
    }
    let digest = Sha256::digest(receipt_id.as_bytes());
    hex::encode(&digest[..16])
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn format_unix_timestamp(timestamp: u64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp as i64, 0)
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_uuid_event_id_is_uuid_bytes_hex() {
        assert_eq!(
            event_id_from_legacy_receipt_id("550e8400-e29b-41d4-a716-446655440000"),
            "550e8400e29b41d4a716446655440000"
        );
    }

    #[test]
    fn unix_timestamp_is_schema_rfc3339() {
        assert_eq!(format_unix_timestamp(1_740_500_000), "2025-02-25T16:13:20Z");
    }

    #[test]
    fn event_type_classifies_policy_failures() {
        assert_eq!(
            event_type(false, Some("model_hash_mismatch")),
            "policy_violation"
        );
        assert_eq!(
            event_type(false, Some("SIGNATURE_INVALID")),
            "verification_failed"
        );
    }
}
