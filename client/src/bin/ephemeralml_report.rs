//! Offline Verification Center report generator.
//!
//! This command wraps the existing receipt verifier into durable report files
//! that a customer or reviewer can save without using hosted persistence.

use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use ephemeral_ml_common::air_receipt::parse_air_v1;
use ephemeral_ml_common::air_verify::{verify_air_v1_receipt, AirCheckStatus, AirVerifyPolicy};
use ephemeral_ml_common::receipt_verify::{
    verify_receipt, CheckStatus as LegacyStatus, VerifyOptions,
};
use ephemeral_ml_common::ui::{air_check_meta, legacy_check_meta};
use ephemeral_ml_common::{
    default_verification_limitations, CloudCorrelation, EvidenceBundleSummary, FileDigest,
    Limitation, PolicySummary, ReceiptEvidenceSummary, ReportCheck, ReportCheckStatus,
    ReportStatus, ReportType, RuntimePassportRef, RuntimePassportV1, VerificationReportV1,
    VerifierSummary, VERIFICATION_REPORT_V1,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "ephemeralml-report",
    about = "Generate durable Cyntrisec Verification Center reports offline"
)]
struct Args {
    /// Path to receipt file (AIR v1 COSE_Sign1 CBOR or legacy receipt).
    #[arg(long)]
    receipt: PathBuf,

    /// Ed25519 public key as 64 hex chars.
    #[arg(long, conflicts_with = "public_key_file")]
    public_key: Option<String>,

    /// File containing raw 32-byte Ed25519 public key.
    #[arg(long, conflicts_with = "public_key")]
    public_key_file: Option<PathBuf>,

    /// Optional attestation document. If present, AIR reports enforce
    /// attestation_doc_hash and derive the receipt signing key if no public
    /// key was supplied.
    #[arg(long)]
    attestation: Option<PathBuf>,

    /// Output directory for verification-report.{json,md,html} and SHA256SUMS.
    #[arg(long)]
    output_dir: PathBuf,

    /// Stable policy identifier rendered into the report.
    #[arg(long, default_value = "production-default")]
    policy_id: String,

    /// Stable policy version rendered into the report.
    #[arg(long, default_value = "1")]
    policy_version: String,

    /// Expected model ID.
    #[arg(long)]
    expected_model: Option<String>,

    /// Expected AIR model_hash as 64 hex chars.
    #[arg(long)]
    expected_model_hash: Option<String>,

    /// Expected AIR request_hash as 64 hex chars.
    #[arg(long)]
    expected_request_hash: Option<String>,

    /// Expected AIR response_hash as 64 hex chars.
    #[arg(long)]
    expected_response_hash: Option<String>,

    /// Expected AIR security_mode. Production reports accept only production.
    #[arg(long, default_value = "production")]
    expected_security_mode: String,

    /// Maximum receipt age in seconds. Set to 0 to skip freshness.
    #[arg(long, default_value = "3600")]
    max_age: u64,

    /// Expected measurement type: nitro-pcr, tdx-mrtd-rtmr, or any.
    #[arg(long, default_value = "any")]
    measurement_type: String,

    /// Optional evidence bundle directory containing manifest.json and/or SHA256SUMS.
    #[arg(long)]
    bundle_dir: Option<PathBuf>,

    /// Optional Runtime Passport JSON to link from this execution report.
    #[arg(long)]
    runtime_passport: Option<PathBuf>,

    /// Optional URI where the Runtime Passport can be retrieved.
    #[arg(long)]
    runtime_passport_uri: Option<String>,

    /// Optional customer-owned evidence URI, for example s3://bucket/prefix/.
    #[arg(long)]
    evidence_uri: Option<String>,

    /// Optional cloud provider label for correlation metadata.
    #[arg(long)]
    cloud_provider: Option<String>,

    /// Optional cloud account ID. Redact before sharing if needed.
    #[arg(long)]
    cloud_account_id: Option<String>,

    /// Optional cloud region.
    #[arg(long)]
    cloud_region: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    validate_args(&args)?;

    fs::create_dir_all(&args.output_dir).with_context(|| {
        format!(
            "failed to create output directory {}",
            args.output_dir.display()
        )
    })?;

    let receipt_bytes = fs::read(&args.receipt)
        .with_context(|| format!("failed to read receipt {}", args.receipt.display()))?;
    let attestation_bytes = match &args.attestation {
        Some(path) => Some(
            fs::read(path)
                .with_context(|| format!("failed to read attestation {}", path.display()))?,
        ),
        None => None,
    };
    let public_key = resolve_public_key(&args, attestation_bytes.as_deref())?;
    let receipt_sha256 = hex::encode(Sha256::digest(&receipt_bytes));

    let mut report = if is_air_v1(&receipt_bytes) {
        build_air_report(
            &args,
            &receipt_bytes,
            &receipt_sha256,
            &public_key,
            attestation_bytes.as_deref(),
        )?
    } else {
        build_legacy_report(&args, &receipt_bytes, &receipt_sha256, &public_key)?
    };

    if let Some(bundle) =
        evidence_bundle_summary(args.bundle_dir.as_deref(), args.evidence_uri.as_deref())?
    {
        report.evidence_bundle = Some(bundle);
    }
    if let Some(correlation) = cloud_correlation(&args) {
        report.cloud_correlation = Some(correlation);
    }
    if let Some(passport_path) = args.runtime_passport.as_deref() {
        let (runtime_passport_ref, passport_limitations) = runtime_passport_ref_and_limitations(
            passport_path,
            args.runtime_passport_uri.as_deref(),
        )?;
        report.runtime_passport_ref = Some(runtime_passport_ref);
        merge_runtime_passport_limitations(&mut report, passport_limitations);
    }
    if let Some(attestation_path) = args.attestation.as_deref() {
        report.checks.push(attestation_provenance_check(
            args.bundle_dir.as_deref(),
            attestation_path,
        ));
    }
    report.finalize_report_sha256()?;

    let json_path = args.output_dir.join("verification-report.json");
    let md_path = args.output_dir.join("verification-report.md");
    let html_path = args.output_dir.join("verification-report.html");

    fs::write(&json_path, serde_json::to_vec_pretty(&report)?)
        .with_context(|| format!("failed to write {}", json_path.display()))?;
    fs::write(&md_path, render_markdown(&report))
        .with_context(|| format!("failed to write {}", md_path.display()))?;
    fs::write(&html_path, render_html(&report))
        .with_context(|| format!("failed to write {}", html_path.display()))?;
    write_sha256sums(
        &args.output_dir,
        &[
            "verification-report.json",
            "verification-report.md",
            "verification-report.html",
        ],
    )?;

    println!("Verification report generated: {}", json_path.display());
    if let Some(hash) = &report.report_sha256 {
        println!("report_sha256: {}", hash);
    }
    Ok(())
}

fn validate_args(args: &Args) -> Result<()> {
    if args.expected_security_mode != "production" {
        bail!("expected-security-mode must be 'production' for this production report generator");
    }
    Ok(())
}

fn is_air_v1(data: &[u8]) -> bool {
    data.first() == Some(&0xD2) || (data.len() >= 2 && data[0] == 0xD8 && data[1] == 0x12)
}

fn resolve_public_key(args: &Args, attestation: Option<&[u8]>) -> Result<VerifyingKey> {
    if let Some(ref hex_key) = args.public_key {
        parse_public_key_hex(hex_key)
    } else if let Some(ref path) = args.public_key_file {
        let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        if bytes.len() != 32 {
            bail!(
                "public-key-file must contain exactly 32 bytes, got {}",
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key")
    } else if let Some(attestation) = attestation {
        ephemeral_ml_client::receipt_key::extract_key_from_attestation(attestation, false)
            .context("failed to extract receipt signing key from attestation")
    } else {
        bail!("provide --public-key, --public-key-file, or --attestation");
    }
}

fn parse_public_key_hex(hex_key: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_key.trim()).context("invalid hex in public key")?;
    if bytes.len() != 32 {
        bail!(
            "public key must be 64 hex chars / 32 bytes, got {}",
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key")
}

fn build_air_report(
    args: &Args,
    receipt_bytes: &[u8],
    receipt_sha256: &str,
    public_key: &VerifyingKey,
    attestation: Option<&[u8]>,
) -> Result<VerificationReportV1> {
    let expected_attestation_doc_hash = attestation.map(|bytes| Sha256::digest(bytes).into());
    let policy = AirVerifyPolicy {
        max_age_secs: args.max_age,
        clock_skew_secs: 30,
        expected_model_hash: parse_hash32(
            args.expected_model_hash.as_deref(),
            "expected-model-hash",
        )?,
        expected_request_hash: parse_hash32(
            args.expected_request_hash.as_deref(),
            "expected-request-hash",
        )?,
        expected_response_hash: parse_hash32(
            args.expected_response_hash.as_deref(),
            "expected-response-hash",
        )?,
        expected_attestation_doc_hash,
        expected_model_id: args.expected_model.clone(),
        expected_security_mode: Some(args.expected_security_mode.clone()),
        allow_evaluation_mode: false,
        expected_platform: if args.measurement_type == "any" {
            None
        } else {
            Some(args.measurement_type.clone())
        },
        expected_nonce: None,
        require_nonce: false,
        seen_cti: None,
    };
    let result = verify_air_v1_receipt(receipt_bytes, public_key, &policy);
    let parsed = parse_air_v1(receipt_bytes).ok();
    let adhash_pass = result
        .checks
        .iter()
        .any(|c| c.name == "ADHASH" && matches!(c.status, AirCheckStatus::Pass));

    let mut checks: Vec<ReportCheck> = result
        .checks
        .iter()
        .map(|check| {
            let meta = air_check_meta(check.name);
            ReportCheck {
                id: check.name.to_string(),
                label: meta.label.to_string(),
                layer: meta.layer.unwrap_or("air").to_string(),
                status: match check.status {
                    AirCheckStatus::Pass => ReportCheckStatus::Pass,
                    AirCheckStatus::Fail => ReportCheckStatus::Fail,
                    AirCheckStatus::Skip => ReportCheckStatus::Skip,
                },
                detail: check.detail.clone(),
                evidence_ref: Some("receipt.cbor".to_string()),
            }
        })
        .collect();

    let signing_key_bound = match attestation {
        Some(attestation_bytes) => {
            checks.push(ReportCheck {
                id: "platform_attestation".to_string(),
                label: "Platform attestation sidecar".to_string(),
                layer: "runtime".to_string(),
                status: ReportCheckStatus::Pass,
                detail: Some(
                    "attestation sidecar supplied; AIR ADHASH check binds the receipt to this sidecar"
                        .to_string(),
                ),
                evidence_ref: Some("attestation.cbor".to_string()),
            });
            match ephemeral_ml_client::receipt_key::extract_key_from_attestation(
                attestation_bytes,
                false,
            ) {
                Ok(attested_key) if attested_key.to_bytes() == public_key.to_bytes() => {
                    checks.push(ReportCheck {
                        id: "signing_key_binding".to_string(),
                        label: "Receipt signing key binding".to_string(),
                        layer: "runtime".to_string(),
                        status: ReportCheckStatus::Pass,
                        detail: Some(
                            "receipt public key matches the key carried by the attestation sidecar"
                                .to_string(),
                        ),
                        evidence_ref: Some("attestation.cbor".to_string()),
                    });
                    true
                }
                Ok(_) => {
                    checks.push(ReportCheck {
                        id: "signing_key_binding".to_string(),
                        label: "Receipt signing key binding".to_string(),
                        layer: "runtime".to_string(),
                        status: ReportCheckStatus::Fail,
                        detail: Some(
                            "receipt public key does not match the key carried by the attestation sidecar"
                                .to_string(),
                        ),
                        evidence_ref: Some("attestation.cbor".to_string()),
                    });
                    false
                }
                Err(err) => {
                    checks.push(ReportCheck {
                        id: "signing_key_binding".to_string(),
                        label: "Receipt signing key binding".to_string(),
                        layer: "runtime".to_string(),
                        status: ReportCheckStatus::Fail,
                        detail: Some(format!(
                            "failed to extract receipt signing key from attestation sidecar: {err}"
                        )),
                        evidence_ref: Some("attestation.cbor".to_string()),
                    });
                    false
                }
            }
        }
        None => {
            checks.push(ReportCheck {
                id: "tee_provenance".to_string(),
                label: "TEE provenance".to_string(),
                layer: "runtime".to_string(),
                status: ReportCheckStatus::Skip,
                detail: Some(
                    "no attestation sidecar supplied; report is receipt-local".to_string(),
                ),
                evidence_ref: None,
            });
            false
        }
    };

    let attestation_requirements_met = attestation.is_none() || (adhash_pass && signing_key_bound);
    let report_status = if result.verified && attestation_requirements_met {
        ReportStatus::Pass
    } else {
        ReportStatus::Fail
    };
    let tee_provenance =
        attestation.is_some() && result.verified && adhash_pass && signing_key_bound;

    let warnings = if attestation.is_none() {
        vec![
            "TEE provenance was not verified because no attestation sidecar was supplied."
                .to_string(),
        ]
    } else {
        vec![]
    };

    Ok(base_report(
        args,
        report_status,
        if tee_provenance {
            "tee_provenance"
        } else {
            "air_local"
        },
        parsed.map(|p| ReceiptEvidenceSummary {
            receipt_id: Some(format_uuid(&p.claims.cti)),
            receipt_sha256: Some(receipt_sha256.to_string()),
            model_id: Some(p.claims.model_id),
            model_version: Some(p.claims.model_version),
            model_hash: Some(hex::encode(p.claims.model_hash)),
            model_hash_scheme: p.claims.model_hash_scheme,
            request_hash: Some(hex::encode(p.claims.request_hash)),
            response_hash: Some(hex::encode(p.claims.response_hash)),
            attestation_doc_hash: Some(hex::encode(p.claims.attestation_doc_hash)),
            issued_at: Some(p.claims.iat),
            security_mode: Some(p.claims.security_mode),
            platform: Some(p.claims.enclave_measurements.measurement_type),
        }),
        checks,
        warnings,
    ))
}

fn build_legacy_report(
    args: &Args,
    receipt_bytes: &[u8],
    receipt_sha256: &str,
    public_key: &VerifyingKey,
) -> Result<VerificationReportV1> {
    let receipt: ephemeral_ml_common::AttestationReceipt =
        ephemeral_ml_common::cbor::from_slice(receipt_bytes)
            .or_else(|_| {
                serde_json::from_slice(receipt_bytes)
                    .map_err(|e| ephemeral_ml_common::cbor::CborError(e.to_string()))
            })
            .context("failed to parse receipt as AIR v1, legacy CBOR, or legacy JSON")?;
    let options = VerifyOptions {
        expected_model: args.expected_model.clone(),
        expected_measurement_type: Some(args.measurement_type.clone()),
        max_age_secs: args.max_age,
        expected_attestation_source: None,
        expected_image_digest: None,
        require_destroy_evidence: false,
    };
    let result = verify_receipt(&receipt, public_key, &options);
    let checks = legacy_checks(&result.checks);
    let receipt_summary = ReceiptEvidenceSummary {
        receipt_id: Some(result.receipt_id),
        receipt_sha256: Some(receipt_sha256.to_string()),
        model_id: Some(result.model_id),
        model_version: Some(result.model_version),
        model_hash: None,
        model_hash_scheme: None,
        request_hash: None,
        response_hash: None,
        attestation_doc_hash: Some(hex::encode(receipt.attestation_doc_hash)),
        issued_at: Some(result.execution_timestamp),
        security_mode: None,
        platform: Some(result.measurement_type),
    };
    Ok(base_report(
        args,
        if result.verified {
            ReportStatus::Pass
        } else {
            ReportStatus::Fail
        },
        "legacy_local",
        Some(receipt_summary),
        checks,
        result.warnings,
    ))
}

fn base_report(
    args: &Args,
    status: ReportStatus,
    assurance_level: &str,
    receipt: Option<ReceiptEvidenceSummary>,
    checks: Vec<ReportCheck>,
    warnings: Vec<String>,
) -> VerificationReportV1 {
    let now = ephemeral_ml_common::current_timestamp().unwrap_or(0);
    VerificationReportV1 {
        schema_version: VERIFICATION_REPORT_V1.to_string(),
        report_id: format!("vrpt_{}", ephemeral_ml_common::generate_id()),
        report_type: ReportType::ExecutionReport,
        created_at: now,
        verified_at: now,
        expires_at: Some(now.saturating_add(90 * 24 * 60 * 60)),
        verifier: VerifierSummary {
            name: "ephemeralml-report".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_commit: option_env!("GIT_COMMIT").map(ToString::to_string),
        },
        policy: PolicySummary {
            policy_id: args.policy_id.clone(),
            policy_version: args.policy_version.clone(),
            expected_security_mode: Some(args.expected_security_mode.clone()),
            max_age_secs: Some(args.max_age),
            expected_model_id: args.expected_model.clone(),
            expected_model_hash: args.expected_model_hash.clone(),
            require_tee_provenance: args.attestation.is_some(),
            require_runtime_passport: args.runtime_passport.is_some(),
            require_cloud_correlation: args.evidence_uri.is_some(),
        },
        overall_status: status,
        assurance_level: assurance_level.to_string(),
        receipt,
        runtime_passport_ref: None,
        evidence_bundle: None,
        cloud_correlation: None,
        checks,
        warnings,
        limitations: default_verification_limitations(),
        report_sha256: None,
    }
}

fn legacy_checks(checks: &ephemeral_ml_common::CheckResults) -> Vec<ReportCheck> {
    let items = [
        ("signature", &checks.signature),
        ("model_match", &checks.model_match),
        ("measurement_type", &checks.measurement_type),
        ("timestamp_fresh", &checks.timestamp_fresh),
        ("measurements_present", &checks.measurements_present),
        ("attestation_source", &checks.attestation_source),
        ("image_digest", &checks.image_digest),
        ("destroy_evidence", &checks.destroy_evidence),
    ];
    items
        .iter()
        .map(|(id, status)| {
            let meta = legacy_check_meta(id).expect("legacy check metadata exists");
            ReportCheck {
                id: (*id).to_string(),
                label: meta.label.to_string(),
                layer: meta.layer.unwrap_or("legacy").to_string(),
                status: match status {
                    LegacyStatus::Pass => ReportCheckStatus::Pass,
                    LegacyStatus::Fail => ReportCheckStatus::Fail,
                    LegacyStatus::Skip => ReportCheckStatus::Skip,
                },
                detail: None,
                evidence_ref: Some("receipt".to_string()),
            }
        })
        .collect()
}

fn parse_hash32(value: Option<&str>, name: &str) -> Result<Option<[u8; 32]>> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let bytes = hex::decode(value).with_context(|| format!("{name} must be hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must decode to exactly 32 bytes"))?;
    Ok(Some(arr))
}

fn evidence_bundle_summary(
    bundle_dir: Option<&Path>,
    evidence_uri: Option<&str>,
) -> Result<Option<EvidenceBundleSummary>> {
    let Some(bundle_dir) = bundle_dir else {
        return Ok(evidence_uri.map(|uri| EvidenceBundleSummary {
            bundle_type: "unknown".to_string(),
            bundle_format_version: "unknown".to_string(),
            uri: Some(uri.to_string()),
            manifest_sha256: None,
            sha256sums_sha256: None,
            bundle_sha256: None,
            files: vec![],
        }));
    };
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest = read_json_value(&manifest_path)?;
    let files = read_sha256sums(bundle_dir.join("SHA256SUMS"))?;
    verify_file_digests(bundle_dir, &files, "SHA256SUMS")?;
    verify_manifest_file_digests(bundle_dir, manifest.as_ref())?;
    Ok(Some(EvidenceBundleSummary {
        bundle_type: manifest
            .as_ref()
            .and_then(|v| v.get("bundle_type"))
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string()),
        bundle_format_version: manifest
            .as_ref()
            .and_then(|v| v.get("bundle_format_version"))
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string()),
        uri: evidence_uri.map(ToString::to_string),
        manifest_sha256: file_sha256_hex(manifest_path),
        sha256sums_sha256: file_sha256_hex(bundle_dir.join("SHA256SUMS")),
        bundle_sha256: None,
        files,
    }))
}

fn read_sha256sums(path: PathBuf) -> Result<Vec<FileDigest>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut digests = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let sha256 = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("malformed SHA256SUMS line {}", idx + 1))?;
        let name = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("malformed SHA256SUMS line {}", idx + 1))?;
        if parts.next().is_some() {
            bail!("malformed SHA256SUMS line {}", idx + 1);
        }
        validate_sha256_hex(sha256, &format!("SHA256SUMS line {}", idx + 1))?;
        digests.push(FileDigest {
            name: name.to_string(),
            sha256: sha256.to_string(),
        });
    }
    Ok(digests)
}

fn read_json_value(path: &Path) -> Result<Option<serde_json::Value>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))
        .map(Some)
}

fn verify_file_digests(bundle_dir: &Path, files: &[FileDigest], source: &str) -> Result<()> {
    for file in files {
        validate_bundle_file_digest(bundle_dir, &file.name, &file.sha256, source)?;
    }
    Ok(())
}

fn verify_manifest_file_digests(
    bundle_dir: &Path,
    manifest: Option<&serde_json::Value>,
) -> Result<()> {
    let Some(serde_json::Value::Array(files)) = manifest.and_then(|v| v.get("files")) else {
        return Ok(());
    };
    for (idx, file) in files.iter().enumerate() {
        let name = file
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("manifest.files[{idx}] missing name"))?;
        let sha256 = file
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("manifest.files[{idx}] missing sha256"))?;
        validate_bundle_file_digest(bundle_dir, name, sha256, "manifest.json")?;
    }
    Ok(())
}

fn validate_bundle_file_digest(
    bundle_dir: &Path,
    name: &str,
    expected_sha256: &str,
    source: &str,
) -> Result<()> {
    validate_sha256_hex(expected_sha256, source)?;
    let path = safe_bundle_file_path(bundle_dir, name)?;
    let bytes = fs::read(&path)
        .with_context(|| format!("{source} lists missing bundle file {}", path.display()))?;
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != expected_sha256 {
        bail!("{source} hash mismatch for {name}: expected {expected_sha256}, got {actual}");
    }
    Ok(())
}

fn safe_bundle_file_path(bundle_dir: &Path, name: &str) -> Result<PathBuf> {
    let relative = Path::new(name);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("unsafe bundle file path: {name}");
    }
    Ok(bundle_dir.join(relative))
}

fn validate_sha256_hex(value: &str, label: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{label} is not a valid SHA-256 hex digest");
    }
    Ok(())
}

fn cloud_correlation(args: &Args) -> Option<CloudCorrelation> {
    if args.evidence_uri.is_none()
        && args.cloud_provider.is_none()
        && args.cloud_account_id.is_none()
        && args.cloud_region.is_none()
    {
        return None;
    }
    Some(CloudCorrelation {
        provider: args
            .cloud_provider
            .clone()
            .unwrap_or_else(|| "aws".to_string()),
        account_id: args.cloud_account_id.clone(),
        region: args.cloud_region.clone(),
        evidence_s3_uri: args.evidence_uri.clone(),
        kms_request_ids: vec![],
        cloudtrail_event_refs: vec![],
        audit_manager_refs: vec![],
        siem_refs: vec![],
    })
}

fn runtime_passport_ref_and_limitations(
    path: &Path,
    uri: Option<&str>,
) -> Result<(RuntimePassportRef, Vec<Limitation>)> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let passport: RuntimePassportV1 = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok((
        RuntimePassportRef {
            passport_id: passport.passport_id,
            passport_sha256: passport.passport_sha256,
            uri: uri.map(ToString::to_string),
        },
        passport.limitations,
    ))
}

fn merge_runtime_passport_limitations(
    report: &mut VerificationReportV1,
    passport_limitations: Vec<Limitation>,
) {
    for limitation in passport_limitations {
        if report
            .limitations
            .iter()
            .any(|existing| existing.code == limitation.code)
        {
            continue;
        }
        report.limitations.push(Limitation {
            code: format!("runtime_passport_{}", limitation.code),
            message: format!("Runtime Passport limitation: {}", limitation.message),
        });
    }
}

fn attestation_provenance_check(bundle_dir: Option<&Path>, attestation_path: &Path) -> ReportCheck {
    let provenance = attestation_provenance(bundle_dir, attestation_path);
    let evidence_ref = if provenance == "bundle" {
        "attestation.cbor".to_string()
    } else {
        attestation_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("attestation sidecar")
            .to_string()
    };
    ReportCheck {
        id: "ATTESTATION_PROVENANCE".to_string(),
        label: "Attestation provenance".to_string(),
        layer: "evidence".to_string(),
        status: ReportCheckStatus::Pass,
        detail: Some(format!("attestation_provenance={provenance}")),
        evidence_ref: Some(evidence_ref),
    }
}

fn attestation_provenance(bundle_dir: Option<&Path>, attestation_path: &Path) -> &'static str {
    let Some(bundle_dir) = bundle_dir else {
        return "sidecar";
    };
    let Ok(bundle_attestation) = bundle_dir.join("attestation.cbor").canonicalize() else {
        return "sidecar";
    };
    let Ok(attestation_path) = attestation_path.canonicalize() else {
        return "sidecar";
    };
    if bundle_attestation == attestation_path {
        "bundle"
    } else {
        "sidecar"
    }
}

fn file_sha256_hex(path: PathBuf) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(hex::encode(Sha256::digest(bytes)))
}

fn write_sha256sums(dir: &Path, names: &[&str]) -> Result<()> {
    let mut lines = Vec::new();
    for name in names {
        let path = dir.join(name);
        let bytes =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        lines.push(format!("{}  {}", hex::encode(Sha256::digest(bytes)), name));
    }
    fs::write(dir.join("SHA256SUMS"), format!("{}\n", lines.join("\n")))
        .context("failed to write SHA256SUMS")
}

fn render_markdown(report: &VerificationReportV1) -> String {
    let mut out = String::new();
    out.push_str("# Cyntrisec Verification Report\n\n");
    out.push_str(&format!("Report ID: `{}`\n\n", report.report_id));
    out.push_str(&format!("Status: `{:?}`\n\n", report.overall_status));
    out.push_str(&format!(
        "Assurance level: `{}`\n\n",
        report.assurance_level
    ));
    if let Some(hash) = &report.report_sha256 {
        out.push_str(&format!("Report SHA-256: `{}`\n\n", hash));
    }
    append_warning_banner_markdown(&mut out, &report.limitations);
    if let Some(receipt) = &report.receipt {
        out.push_str("## Receipt\n\n");
        push_opt(&mut out, "Receipt ID", receipt.receipt_id.as_deref());
        push_opt(&mut out, "Model", receipt.model_id.as_deref());
        push_opt(&mut out, "Security mode", receipt.security_mode.as_deref());
        push_opt(&mut out, "Platform", receipt.platform.as_deref());
        push_opt(
            &mut out,
            "Receipt SHA-256",
            receipt.receipt_sha256.as_deref(),
        );
        out.push('\n');
    }
    out.push_str("## Checks\n\n");
    out.push_str("| Layer | Check | Status | Detail |\n|---|---|---|---|\n");
    for check in &report.checks {
        out.push_str(&format!(
            "| {} | {} | {:?} | {} |\n",
            check.layer,
            check.label,
            check.status,
            check.detail.as_deref().unwrap_or("")
        ));
    }
    out.push_str("\n## Limitations\n\n");
    for limitation in &report.limitations {
        out.push_str(&format!(
            "- **{}:** {}\n",
            limitation.code, limitation.message
        ));
    }
    out
}

fn push_opt(out: &mut String, label: &str, value: Option<&str>) {
    if let Some(value) = value {
        out.push_str(&format!("- {}: `{}`\n", label, value));
    }
}

fn render_html(report: &VerificationReportV1) -> String {
    let json = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string());
    let warning_html = warning_banner_html(&report.limitations);
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Cyntrisec Verification Report</title><style>body{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#050505;color:#f5f5f5;margin:0;padding:32px}}main{{max-width:980px;margin:auto}}.card{{border:1px solid #333;padding:20px;margin:16px 0;background:#0b0b0b}}.warning{{border-color:#ffb84a;background:#201600;color:#ffdc8a}}.pass{{color:#39ff7c}}.fail{{color:#ff5a5a}}pre{{white-space:pre-wrap;word-break:break-word;background:#000;padding:16px;border:1px solid #333}}</style></head><body><main><h1>Cyntrisec Verification Report</h1><div class=\"card\"><p>Report ID: <code>{}</code></p><p>Status: <strong class=\"{}\">{:?}</strong></p><p>Assurance: <code>{}</code></p><p>Report SHA-256: <code>{}</code></p></div>{}<div class=\"card\"><h2>Machine-readable report</h2><pre>{}</pre></div></main></body></html>\n",
        esc(&report.report_id),
        if matches!(&report.overall_status, ReportStatus::Pass) { "pass" } else { "fail" },
        report.overall_status,
        esc(&report.assurance_level),
        esc(report.report_sha256.as_deref().unwrap_or("not-finalized")),
        warning_html,
        esc(&json)
    )
}

fn esc(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn append_warning_banner_markdown(out: &mut String, limitations: &[Limitation]) {
    let warnings = prominent_limitations(limitations);
    if warnings.is_empty() {
        return;
    }
    out.push_str("> Warning: this report has reviewer-visible limitations:\n");
    for limitation in warnings {
        out.push_str(&format!(
            "> - **{}:** {}\n",
            limitation.code, limitation.message
        ));
    }
    out.push('\n');
}

fn warning_banner_html(limitations: &[Limitation]) -> String {
    let warnings = prominent_limitations(limitations);
    if warnings.is_empty() {
        return String::new();
    }
    let items = warnings
        .into_iter()
        .map(|limitation| {
            format!(
                "<li><strong>{}</strong>: {}</li>",
                esc(&limitation.code),
                esc(&limitation.message)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<div class=\"card warning\"><h2>Reviewer-visible limitation</h2><ul>{items}</ul></div>"
    )
}

fn prominent_limitations(limitations: &[Limitation]) -> Vec<&Limitation> {
    limitations
        .iter()
        .filter(|limitation| {
            limitation.code.starts_with("unsigned_")
                || limitation.code.starts_with("runtime_passport_unsigned_")
        })
        .collect()
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        ((bytes[10] as u64) << 40)
            | ((bytes[11] as u64) << 32)
            | ((bytes[12] as u64) << 24)
            | ((bytes[13] as u64) << 16)
            | ((bytes[14] as u64) << 8)
            | (bytes[15] as u64),
    )
}
