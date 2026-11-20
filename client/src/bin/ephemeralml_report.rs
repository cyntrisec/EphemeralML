//! Offline Verification Center report generator.
//!
//! This command wraps the existing receipt verifier into durable report files
//! that a customer or reviewer can save without using hosted persistence.

use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use ephemeral_ml_client::verify_air_v1_receipt_chained;
use ephemeral_ml_common::air_receipt::parse_air_v1;
use ephemeral_ml_common::air_verify::{
    verify_air_v1_receipt, AirCheckStatus, AirVerifyPolicy, AirVerifyResult, AssuranceLevel,
    SeenCtiFn,
};
use ephemeral_ml_common::receipt_verify::{
    verify_receipt, CheckStatus as LegacyStatus, VerifyOptions,
};
use ephemeral_ml_common::ui::{air_check_meta, legacy_check_meta};
use ephemeral_ml_common::{
    default_verification_limitations, CloudCorrelation, EvidenceBundleSummary, FileDigest,
    Limitation, PcrMeasurements, PolicySummary, ReceiptEvidenceSummary, ReportCheck,
    ReportCheckStatus, ReportStatus, ReportType, RuntimePassportRef, RuntimePassportV1,
    VerificationReportV1, VerifierSummary, VERIFICATION_REPORT_V1,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "ephemeralml-report",
    about = "Generate durable Cyntrisec Verification Center reports offline",
    after_help = "Exit status:\n  0  the report was written and its overall_status is pass\n  3  the report was written and its overall_status is not pass\n  1  no report was written (unreadable input, values that do not parse)\n  2  the command line itself was not understood"
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

    /// Optional attestation document. If present, AIR reports authenticate
    /// it, enforce attestation_doc_hash, reconcile the receipt's measurements
    /// against it and derive the receipt signing key if no public key was
    /// supplied. A report is labelled tee_provenance only when reference
    /// measurements (--expected-pcr0/1/2) and a freshness mechanism
    /// (--expected-nonce or --seen-cti-file) are supplied as well.
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

    /// Reference (known-good) PCR0 of the enclave image as 96 hex chars.
    /// Supply together with --expected-pcr1, --expected-pcr2 and
    /// --attestation. Without reference measurements a report is never
    /// labelled tee_provenance.
    #[arg(long)]
    expected_pcr0: Option<String>,

    /// Reference (known-good) PCR1 as 96 hex chars.
    #[arg(long)]
    expected_pcr1: Option<String>,

    /// Reference (known-good) PCR2 as 96 hex chars.
    #[arg(long)]
    expected_pcr2: Option<String>,

    /// Verifier nonce that was sent with the inference request, as hex
    /// (8 to 64 bytes). The receipt must carry it in eat_nonce. Without a
    /// freshness mechanism (this, or --seen-cti-file) a report is never
    /// labelled tee_provenance.
    #[arg(long)]
    expected_nonce: Option<String>,

    /// Ledger of the receipt identifiers (cti) this verifier has already
    /// accepted: one 32-hex-char value per line, created if missing. A
    /// receipt whose cti is listed is rejected as a replay, and the cti of a
    /// receipt whose report passes is appended. This is cti deduplication,
    /// the freshness mechanism for receipts that carry no verifier nonce.
    #[arg(long)]
    seen_cti_file: Option<PathBuf>,

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
    merge_dev_override_limitations(&mut report);
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

    // Record an accepted receipt in the ledger only now, after the report
    // files exist: a run that failed or stopped early leaves the ledger as it
    // was, so the same receipt can be checked again.
    let accepted = matches!(report.overall_status, ReportStatus::Pass);
    if let (true, Some(ledger), Ok(parsed)) = (
        accepted,
        args.seen_cti_file.as_deref(),
        parse_air_v1(&receipt_bytes),
    ) {
        record_seen_cti(ledger, &parsed.claims.cti)?;
    }

    println!("Verification report generated: {}", json_path.display());
    if let Some(hash) = &report.report_sha256 {
        println!("report_sha256: {}", hash);
    }

    // The report is on disk either way. Say in the exit status whether it
    // passed, so a caller that reads only the status cannot take a rejected
    // receipt for an accepted one.
    let code = report_exit_code(&report.overall_status);
    if code != 0 {
        eprintln!(
            "Verification did not pass: overall_status is {:?}; the report lists the failed checks",
            report.overall_status
        );
        std::process::exit(code);
    }
    Ok(())
}

/// Exit status when a report was written and did not pass. The other non-zero
/// statuses keep their meaning: 1, no report was written (unreadable input,
/// values that do not parse); 2, the argument parser's own usage error.
const EXIT_REPORT_NOT_PASSED: i32 = 3;

/// 0 when the report passed, [`EXIT_REPORT_NOT_PASSED`] otherwise. The program
/// used to exit 0 whenever it managed to write a report, whatever the report
/// said.
fn report_exit_code(status: &ReportStatus) -> i32 {
    match status {
        ReportStatus::Pass => 0,
        _ => EXIT_REPORT_NOT_PASSED,
    }
}

fn validate_args(args: &Args) -> Result<()> {
    if args.expected_security_mode != "production" {
        bail!("expected-security-mode must be 'production' for this production report generator");
    }
    let reference_measurements = parse_expected_measurements(args)?;
    if reference_measurements.is_some() && args.attestation.is_none() {
        bail!(
            "--expected-pcr0, --expected-pcr1 and --expected-pcr2 need --attestation: reference \
             measurements are appraised against the attestation document"
        );
    }
    parse_nonce(args.expected_nonce.as_deref())?;
    if let Some(ledger) = args.seen_cti_file.as_deref() {
        load_seen_cti(ledger)?;
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

/// The AIR policy for this run. `expected_attestation_doc_hash` is passed only
/// for the receipt-local fallback; the chained verifier pins the supplied
/// document's hash itself.
fn air_policy(
    args: &Args,
    expected_attestation_doc_hash: Option<[u8; 32]>,
) -> Result<AirVerifyPolicy> {
    Ok(AirVerifyPolicy {
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
        expected_measurements: parse_expected_measurements(args)?,
        expected_model_id: args.expected_model.clone(),
        expected_security_mode: Some(args.expected_security_mode.clone()),
        allow_evaluation_mode: false,
        expected_platform: if args.measurement_type == "any" {
            None
        } else {
            Some(args.measurement_type.clone())
        },
        expected_nonce: parse_nonce(args.expected_nonce.as_deref())?,
        require_nonce: false,
        seen_cti: seen_cti_hook(args)?,
        require_model_hash_scheme: false,
    })
}

/// The assurance level a report states.
///
/// `tee_provenance` only when the chained verifier established it for a
/// receipt that verified and the caller's key is the document's key. The
/// chained verifier is the one place that decides TEE provenance: an
/// authenticated document, the receipt bound to it, reconciled and appraised
/// measurements and a bound freshness mechanism. Everything else is
/// `air_local`.
fn air_assurance_level(
    chained_level: Option<AssuranceLevel>,
    verified: bool,
    signing_key_bound: bool,
) -> &'static str {
    match chained_level {
        Some(AssuranceLevel::TeeProvenance) if verified && signing_key_bound => "tee_provenance",
        _ => "air_local",
    }
}

/// Why a report with an authenticated attestation sidecar stopped short of
/// `tee_provenance`, in terms of the options that were not supplied.
fn provenance_gap_warning(result: &AirVerifyResult) -> Option<String> {
    let skipped = |name: &str| {
        result
            .checks
            .iter()
            .any(|check| check.name == name && matches!(check.status, AirCheckStatus::Skip))
    };
    let mut missing = Vec::new();
    if skipped("MEAS_APPRAISE") {
        missing.push(
            "no reference measurements were supplied (--expected-pcr0, --expected-pcr1, \
             --expected-pcr2)",
        );
    }
    if skipped("FRESH_BINDING") {
        missing.push(
            "no freshness mechanism was bound (--expected-nonce, or --seen-cti-file for receipts \
             that carry no nonce)",
        );
    }
    if missing.is_empty() {
        return None;
    }
    Some(format!(
        "TEE provenance was not asserted: {}. The assurance level is air_local.",
        missing.join("; ")
    ))
}

fn build_air_report(
    args: &Args,
    receipt_bytes: &[u8],
    receipt_sha256: &str,
    public_key: &VerifyingKey,
    attestation: Option<&[u8]>,
) -> Result<VerificationReportV1> {
    // With an attestation sidecar the receipt goes through the client library's
    // chained verifier: it authenticates the document, takes the receipt-signing
    // key from it, binds the receipt to it, reconciles the receipt's
    // measurements against it, appraises them against the reference values and
    // records whether a freshness mechanism is bound. If the document cannot be
    // authenticated, the receipt is still checked on its own against the key
    // the caller supplied, and the report fails.
    let (result, chained_level, document_error) = match attestation {
        Some(attestation_bytes) => match verify_air_v1_receipt_chained(
            receipt_bytes,
            attestation_bytes,
            air_policy(args, None)?,
            false,
        ) {
            Ok(result) => {
                let level = result.assurance_level;
                (result, Some(level), None)
            }
            Err(err) => {
                let doc_hash: [u8; 32] = Sha256::digest(attestation_bytes).into();
                let policy = air_policy(args, Some(doc_hash))?;
                (
                    verify_air_v1_receipt(receipt_bytes, public_key, &policy),
                    None,
                    Some(format!("{err:#}")),
                )
            }
        },
        None => {
            let policy = air_policy(args, None)?;
            (
                verify_air_v1_receipt(receipt_bytes, public_key, &policy),
                None,
                None,
            )
        }
    };
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
                evidence_ref: Some(
                    match check.name {
                        "MEAS_RECONCILE" | "MEAS_APPRAISE" => "attestation.cbor",
                        _ => "receipt.cbor",
                    }
                    .to_string(),
                ),
            }
        })
        .collect();

    let signing_key_bound = match (attestation, document_error.as_deref()) {
        (Some(attestation_bytes), None) => {
            checks.push(ReportCheck {
                id: "platform_attestation".to_string(),
                label: "Platform attestation sidecar".to_string(),
                layer: "runtime".to_string(),
                status: ReportCheckStatus::Pass,
                detail: Some(
                    "attestation sidecar signature and certificate chain verified; the AIR \
                     ADHASH check ties the receipt to this sidecar"
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
        (Some(_), Some(error)) => {
            checks.push(ReportCheck {
                id: "platform_attestation".to_string(),
                label: "Platform attestation sidecar".to_string(),
                layer: "runtime".to_string(),
                status: ReportCheckStatus::Fail,
                detail: Some(format!(
                    "attestation sidecar could not be authenticated: {error}"
                )),
                evidence_ref: Some("attestation.cbor".to_string()),
            });
            checks.push(ReportCheck {
                id: "signing_key_binding".to_string(),
                label: "Receipt signing key binding".to_string(),
                layer: "runtime".to_string(),
                status: ReportCheckStatus::Fail,
                detail: Some(
                    "no authenticated receipt signing key: the attestation sidecar was not verified"
                        .to_string(),
                ),
                evidence_ref: Some("attestation.cbor".to_string()),
            });
            false
        }
        (None, _) => {
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
    let assurance_level = air_assurance_level(chained_level, result.verified, signing_key_bound);

    let mut warnings = Vec::new();
    if attestation.is_none() {
        warnings.push(
            "TEE provenance was not verified because no attestation sidecar was supplied."
                .to_string(),
        );
    } else if document_error.is_some() {
        warnings.push(
            "TEE provenance was not verified because the attestation sidecar could not be \
             authenticated."
                .to_string(),
        );
    } else if assurance_level != "tee_provenance" {
        warnings.extend(provenance_gap_warning(&result));
    }

    // The report requires TEE provenance when the operator gave it everything
    // TEE provenance needs. Then either the level is tee_provenance or one of
    // the supplied values did not match and the report fails.
    let freshness_requested =
        parse_nonce(args.expected_nonce.as_deref())?.is_some() || args.seen_cti_file.is_some();
    let require_tee_provenance = attestation.is_some()
        && parse_expected_measurements(args)?.is_some()
        && freshness_requested;

    Ok(base_report(
        args,
        report_status,
        assurance_level,
        require_tee_provenance,
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
        false,
        Some(receipt_summary),
        checks,
        result.warnings,
    ))
}

fn base_report(
    args: &Args,
    status: ReportStatus,
    assurance_level: &str,
    require_tee_provenance: bool,
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
            require_tee_provenance,
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

/// Reference measurements from `--expected-pcr0/1/2`: all three or none.
fn parse_expected_measurements(args: &Args) -> Result<Option<PcrMeasurements>> {
    let pcr0 = parse_hash48(args.expected_pcr0.as_deref(), "expected-pcr0")?;
    let pcr1 = parse_hash48(args.expected_pcr1.as_deref(), "expected-pcr1")?;
    let pcr2 = parse_hash48(args.expected_pcr2.as_deref(), "expected-pcr2")?;
    match (pcr0, pcr1, pcr2) {
        (None, None, None) => Ok(None),
        (Some(pcr0), Some(pcr1), Some(pcr2)) => Ok(Some(PcrMeasurements::new(pcr0, pcr1, pcr2))),
        _ => {
            bail!("--expected-pcr0, --expected-pcr1 and --expected-pcr2 must be supplied together")
        }
    }
}

fn parse_hash48(value: Option<&str>, name: &str) -> Result<Option<Vec<u8>>> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let bytes = hex::decode(value).with_context(|| format!("{name} must be hex"))?;
    if bytes.len() != 48 {
        bail!(
            "{name} must decode to exactly 48 bytes, got {}",
            bytes.len()
        );
    }
    Ok(Some(bytes))
}

/// The verifier nonce from `--expected-nonce` (RFC 9711: 8 to 64 bytes).
fn parse_nonce(value: Option<&str>) -> Result<Option<Vec<u8>>> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let bytes = hex::decode(value).context("expected-nonce must be hex")?;
    if !(8..=64).contains(&bytes.len()) {
        bail!(
            "expected-nonce must decode to between 8 and 64 bytes (RFC 9711), got {}",
            bytes.len()
        );
    }
    Ok(Some(bytes))
}

/// Receipt identifiers this verifier has already accepted, from
/// `--seen-cti-file`. A missing file is an empty ledger.
fn load_seen_cti(path: &Path) -> Result<HashSet<[u8; 16]>> {
    let mut seen = HashSet::new();
    if !path.exists() {
        return Ok(seen);
    }
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let bytes = hex::decode(line)
            .with_context(|| format!("{} line {} is not hex", path.display(), idx + 1))?;
        let cti: [u8; 16] = bytes.try_into().map_err(|_| {
            anyhow::anyhow!("{} line {} is not a 16-byte cti", path.display(), idx + 1)
        })?;
        seen.insert(cti);
    }
    Ok(seen)
}

/// The replay hook for the AIR policy: true when the receipt's cti is already
/// in the ledger. The hook only reads; `record_seen_cti` writes, and only after
/// a report has passed.
fn seen_cti_hook(args: &Args) -> Result<Option<SeenCtiFn>> {
    let Some(path) = args.seen_cti_file.as_deref() else {
        return Ok(None);
    };
    let seen = load_seen_cti(path)?;
    let hook: SeenCtiFn = Box::new(move |cti: &[u8; 16]| seen.contains(cti));
    Ok(Some(hook))
}

/// Append an accepted receipt's cti to the ledger.
fn record_seen_cti(path: &Path, cti: &[u8; 16]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    writeln!(file, "{}", hex::encode(cti))
        .with_context(|| format!("failed to write {}", path.display()))
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

fn merge_dev_override_limitations(report: &mut VerificationReportV1) {
    let mut add = |code: &str, message: &str| {
        if report
            .limitations
            .iter()
            .any(|existing| existing.code == code)
        {
            return;
        }
        report.limitations.push(Limitation {
            code: code.to_string(),
            message: message.to_string(),
        });
    };

    if env_flag_is_false("EPHEMERALML_REQUIRE_MRTD") {
        add(
            "dev_override_mrtd_unpinned",
            "EPHEMERALML_REQUIRE_MRTD=false was active while generating this report. TDX peer measurements were not pinned; do not use this as production buyer evidence.",
        );
    }
    if env_flag_is_true("EPHEMERALML_ALLOW_UNPINNED_AUDIENCE") {
        add(
            "dev_override_audience_unpinned",
            "EPHEMERALML_ALLOW_UNPINNED_AUDIENCE=true was active while generating this report. Confidential Space audience was not pinned; do not use this as production buyer evidence.",
        );
    }
    if env_equals("EPHEMERALML_INSECURE_ALLOW_UNPINNED", "I_UNDERSTAND") {
        add(
            "dev_override_dual_attestation_bypass",
            "EPHEMERALML_INSECURE_ALLOW_UNPINNED=I_UNDERSTAND was active. Both MRTD and audience pinning may have been bypassed; this evidence is development-only.",
        );
    }
}

fn env_flag_is_false(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

fn env_flag_is_true(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn env_equals(name: &str, expected: &str) -> bool {
    std::env::var(name).map(|v| v == expected).unwrap_or(false)
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
                || limitation.code.starts_with("dev_override_")
                || limitation
                    .code
                    .starts_with("runtime_passport_dev_override_")
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

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_ml_common::air_receipt::{build_air_v1, AirReceiptClaims};
    use ephemeral_ml_common::receipt_signing::ReceiptSigningKey;
    use ephemeral_ml_common::{EnclaveMeasurements, WorkerAttestationUserData};

    const NONCE_HEX: &str = "deadbeefcafebabe";

    fn nonce() -> Vec<u8> {
        vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]
    }

    fn args(extra: &[&str]) -> Args {
        let mut argv = vec![
            "ephemeralml-report",
            "--receipt",
            "receipt.cbor",
            "--output-dir",
            "out",
        ];
        argv.extend_from_slice(extra);
        Args::parse_from(argv)
    }

    fn air_receipt(
        key: &ReceiptSigningKey,
        eat_nonce: Option<Vec<u8>>,
        attestation_doc_hash: [u8; 32],
    ) -> Vec<u8> {
        let claims = AirReceiptClaims {
            iss: "cyntrisec.com".to_string(),
            iat: ephemeral_ml_common::current_timestamp().unwrap(),
            cti: *uuid::Uuid::new_v4().as_bytes(),
            eat_nonce,
            model_id: "minilm-l6-v2".to_string(),
            model_version: "1.0.0".to_string(),
            model_hash: [0xAA; 32],
            request_hash: [0xBB; 32],
            response_hash: [0xCC; 32],
            attestation_doc_hash,
            enclave_measurements: EnclaveMeasurements::new(
                vec![1u8; 48],
                vec![2u8; 48],
                vec![3u8; 48],
            ),
            policy_version: "policy-v1".to_string(),
            sequence_number: 1,
            execution_time_ms: 10,
            memory_peak_mb: 64,
            security_mode: "production".to_string(),
            model_hash_scheme: Some("sha256-single".to_string()),
        };
        build_air_v1(&claims, key).unwrap()
    }

    /// A mock (plain CBOR map) attestation document carrying `pubkey`. This
    /// program refuses the format; the tests use it for exactly that, and to
    /// obtain the chained verifier's own rows.
    fn mock_attestation_doc(pubkey: [u8; 32]) -> Vec<u8> {
        let user_data = WorkerAttestationUserData::new(pubkey, "minilm-l6-v2", [0xAA; 32])
            .to_cbor()
            .unwrap();
        let map = ciborium::Value::Map(vec![(
            ciborium::Value::Text("user_data".to_string()),
            ciborium::Value::Bytes(user_data),
        )]);
        ephemeral_ml_common::cbor::value_to_vec(&map).unwrap()
    }

    fn check_status<'a>(
        report: &'a VerificationReportV1,
        id: &str,
    ) -> Option<&'a ReportCheckStatus> {
        report
            .checks
            .iter()
            .find(|check| check.id == id)
            .map(|check| &check.status)
    }

    #[test]
    fn exit_status_follows_the_report() {
        assert_eq!(report_exit_code(&ReportStatus::Pass), 0);
        assert_eq!(report_exit_code(&ReportStatus::Fail), 3);
        assert_eq!(report_exit_code(&ReportStatus::Partial), 3);
        assert_eq!(report_exit_code(&ReportStatus::Unknown), 3);
    }

    #[test]
    fn report_level_follows_the_chained_verifier() {
        // Arguments: the level the chained verifier reached, whether the
        // receipt verified, whether the caller's key is the document's key.
        assert_eq!(
            air_assurance_level(Some(AssuranceLevel::TeeProvenance), true, true),
            "tee_provenance"
        );
        // The chained verifier stops at AIR-local when reference measurements
        // or a freshness mechanism are missing. Attestation-hash and key
        // binding alone used to be reported as tee_provenance here.
        assert_eq!(
            air_assurance_level(Some(AssuranceLevel::AirLocal), true, true),
            "air_local"
        );
        // No attestation sidecar, or one that could not be authenticated.
        assert_eq!(air_assurance_level(None, true, true), "air_local");
        // A key other than the document's, or a receipt that failed.
        assert_eq!(
            air_assurance_level(Some(AssuranceLevel::TeeProvenance), true, false),
            "air_local"
        );
        assert_eq!(
            air_assurance_level(Some(AssuranceLevel::TeeProvenance), false, true),
            "air_local"
        );
    }

    #[test]
    fn report_without_attestation_is_air_local() {
        let key = ReceiptSigningKey::generate().unwrap();
        let receipt = air_receipt(&key, None, [0xDD; 32]);
        let report = build_air_report(&args(&[]), &receipt, "00", &key.public_key, None).unwrap();

        assert!(matches!(report.overall_status, ReportStatus::Pass));
        assert_eq!(report.assurance_level, "air_local");
        assert!(!report.policy.require_tee_provenance);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("no attestation sidecar")));
    }

    #[test]
    fn unauthenticated_attestation_fails_the_report() {
        let key = ReceiptSigningKey::generate().unwrap();
        let doc = mock_attestation_doc(key.public_key.to_bytes());
        let doc_hash: [u8; 32] = Sha256::digest(&doc).into();
        // The receipt names this document and the key is the right one, so
        // attestation-hash binding holds. The document itself carries no
        // signature: the report must fail and stay AIR-local.
        let receipt = air_receipt(&key, None, doc_hash);
        let report =
            build_air_report(&args(&[]), &receipt, "00", &key.public_key, Some(&doc[..])).unwrap();

        assert!(matches!(report.overall_status, ReportStatus::Fail));
        assert_eq!(report.assurance_level, "air_local");
        assert!(matches!(
            check_status(&report, "ADHASH"),
            Some(ReportCheckStatus::Pass)
        ));
        assert!(matches!(
            check_status(&report, "platform_attestation"),
            Some(ReportCheckStatus::Fail)
        ));
        assert!(matches!(
            check_status(&report, "signing_key_binding"),
            Some(ReportCheckStatus::Fail)
        ));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("could not be authenticated")));
    }

    #[test]
    fn verifier_nonce_is_checked_against_the_receipt() {
        let key = ReceiptSigningKey::generate().unwrap();
        let receipt = air_receipt(&key, Some(nonce()), [0xDD; 32]);

        let matching = args(&["--expected-nonce", NONCE_HEX]);
        let report = build_air_report(&matching, &receipt, "00", &key.public_key, None).unwrap();
        assert!(matches!(report.overall_status, ReportStatus::Pass));
        assert!(matches!(
            check_status(&report, "NONCE"),
            Some(ReportCheckStatus::Pass)
        ));
        // A nonce alone is not provenance: there is no attestation document.
        assert_eq!(report.assurance_level, "air_local");

        let other = args(&["--expected-nonce", "0011223344556677"]);
        let report = build_air_report(&other, &receipt, "00", &key.public_key, None).unwrap();
        assert!(matches!(report.overall_status, ReportStatus::Fail));
        assert!(matches!(
            check_status(&report, "NONCE"),
            Some(ReportCheckStatus::Fail)
        ));
    }

    #[test]
    fn gap_warning_names_the_missing_inputs() {
        let key = ReceiptSigningKey::generate().unwrap();
        let doc = mock_attestation_doc(key.public_key.to_bytes());
        let doc_hash: [u8; 32] = Sha256::digest(&doc).into();
        let receipt = air_receipt(&key, Some(nonce()), doc_hash);

        // Neither reference measurements nor a verifier nonce.
        let result =
            verify_air_v1_receipt_chained(&receipt, &doc, AirVerifyPolicy::default(), true)
                .unwrap();
        let warning = provenance_gap_warning(&result).unwrap();
        assert!(warning.contains("--expected-pcr0"), "{warning}");
        assert!(warning.contains("--expected-nonce"), "{warning}");
        assert!(warning.contains("--seen-cti-file"), "{warning}");

        // The verifier's nonce is bound; only the measurements are missing.
        let policy = AirVerifyPolicy {
            expected_nonce: Some(nonce()),
            ..AirVerifyPolicy::default()
        };
        let result = verify_air_v1_receipt_chained(&receipt, &doc, policy, true).unwrap();
        let warning = provenance_gap_warning(&result).unwrap();
        assert!(warning.contains("--expected-pcr0"), "{warning}");
        assert!(!warning.contains("--expected-nonce"), "{warning}");
    }

    fn temp_ledger() -> PathBuf {
        std::env::temp_dir().join(format!(
            "ephemeralml-report-seen-cti-{}.txt",
            uuid::Uuid::new_v4()
        ))
    }

    #[test]
    fn seen_cti_ledger_accepts_once_and_rejects_a_replay() {
        let key = ReceiptSigningKey::generate().unwrap();
        let receipt = air_receipt(&key, None, [0xDD; 32]);
        let ledger = temp_ledger();
        let ledger_arg = ledger.to_str().unwrap().to_string();
        let with_ledger = args(&["--seen-cti-file", ledger_arg.as_str()]);

        // First sight: the replay check passes. Building a report does not
        // write the ledger; only `record_seen_cti` does, after a report passed.
        let report = build_air_report(&with_ledger, &receipt, "00", &key.public_key, None).unwrap();
        assert!(matches!(report.overall_status, ReportStatus::Pass));
        assert!(matches!(
            check_status(&report, "REPLAY"),
            Some(ReportCheckStatus::Pass)
        ));
        assert!(!ledger.exists());

        let cti = parse_air_v1(&receipt).unwrap().claims.cti;
        record_seen_cti(&ledger, &cti).unwrap();
        assert_eq!(load_seen_cti(&ledger).unwrap().len(), 1);

        // The same receipt presented again is a replay.
        let report = build_air_report(&with_ledger, &receipt, "00", &key.public_key, None).unwrap();
        assert!(matches!(report.overall_status, ReportStatus::Fail));
        assert!(matches!(
            check_status(&report, "REPLAY"),
            Some(ReportCheckStatus::Fail)
        ));

        // Another receipt is not affected.
        let other = air_receipt(&key, None, [0xDD; 32]);
        let report = build_air_report(&with_ledger, &other, "00", &key.public_key, None).unwrap();
        assert!(matches!(report.overall_status, ReportStatus::Pass));

        let _ = fs::remove_file(&ledger);
    }

    #[test]
    fn seen_cti_ledger_counts_as_a_bound_freshness_mechanism() {
        let key = ReceiptSigningKey::generate().unwrap();
        let doc = mock_attestation_doc(key.public_key.to_bytes());
        let doc_hash: [u8; 32] = Sha256::digest(&doc).into();
        let receipt = air_receipt(&key, None, doc_hash);
        let ledger = temp_ledger();
        let ledger_arg = ledger.to_str().unwrap().to_string();
        let with_ledger = args(&["--seen-cti-file", ledger_arg.as_str()]);

        // The chained verifier sees a replay hook in the policy: freshness is
        // bound, so only the reference measurements are named as missing.
        let policy = air_policy(&with_ledger, None).unwrap();
        let result = verify_air_v1_receipt_chained(&receipt, &doc, policy, true).unwrap();
        assert!(result
            .checks
            .iter()
            .any(|c| c.name == "FRESH_BINDING" && matches!(c.status, AirCheckStatus::Pass)));
        let warning = provenance_gap_warning(&result).unwrap();
        assert!(warning.contains("--expected-pcr0"), "{warning}");
        assert!(!warning.contains("--seen-cti-file"), "{warning}");
    }

    #[test]
    fn seen_cti_ledger_refuses_malformed_lines() {
        let ledger = temp_ledger();

        fs::write(&ledger, "not-hex\n").unwrap();
        assert!(load_seen_cti(&ledger).is_err());

        // Hex, but not 16 bytes.
        fs::write(&ledger, "00112233\n").unwrap();
        assert!(load_seen_cti(&ledger).is_err());

        // Blank lines are ignored; a missing file is an empty ledger.
        fs::write(&ledger, "\n000102030405060708090a0b0c0d0e0f\n\n").unwrap();
        assert_eq!(load_seen_cti(&ledger).unwrap().len(), 1);
        fs::remove_file(&ledger).unwrap();
        assert!(load_seen_cti(&ledger).unwrap().is_empty());
    }

    #[test]
    fn reference_measurements_are_all_or_none_and_need_an_attestation() {
        let pcr = "11".repeat(48);
        let pcr = pcr.as_str();

        // One register alone is refused.
        assert!(parse_expected_measurements(&args(&["--expected-pcr0", pcr])).is_err());

        // All three parse.
        let all = args(&[
            "--expected-pcr0",
            pcr,
            "--expected-pcr1",
            pcr,
            "--expected-pcr2",
            pcr,
        ]);
        assert_eq!(
            parse_expected_measurements(&all).unwrap(),
            Some(PcrMeasurements::new(
                vec![0x11; 48],
                vec![0x11; 48],
                vec![0x11; 48]
            ))
        );
        // Without an attestation document there is nothing to appraise them
        // against, so the run is refused instead of ignoring them.
        assert!(validate_args(&all).is_err());

        // A register of the wrong length is refused.
        let short = "11".repeat(32);
        assert!(parse_expected_measurements(&args(&[
            "--expected-pcr0",
            short.as_str(),
            "--expected-pcr1",
            pcr,
            "--expected-pcr2",
            pcr,
        ]))
        .is_err());
    }

    #[test]
    fn verifier_nonce_must_be_8_to_64_bytes() {
        assert_eq!(parse_nonce(None).unwrap(), None);
        assert_eq!(parse_nonce(Some(NONCE_HEX)).unwrap(), Some(nonce()));
        assert!(parse_nonce(Some("deadbeef")).is_err());
        let too_long = "11".repeat(65);
        assert!(parse_nonce(Some(too_long.as_str())).is_err());
        assert!(parse_nonce(Some("not-hex")).is_err());
    }
}
