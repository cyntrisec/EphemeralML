//! Standalone EphemeralML receipt verifier.
//!
//! Verifies cryptographic receipts produced by EphemeralML inference sessions.
//! This is the core product artifact — a compliance officer or auditor runs this
//! to prove what happened inside a confidential workload.
//!
//! Usage:
//!   ephemeralml-verify receipt.cbor --public-key <hex>
//!   ephemeralml-verify receipt.json --public-key-file key.bin
//!   ephemeralml-verify receipt.cbor --attestation attestation.cbor
//!
//! Exit code 0 = VERIFIED, 1 = INVALID, 2 = ERROR

use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use ephemeral_ml_common::air_verify::{AirCheckStatus, AirVerifyPolicy, AirVerifyResult};
use ephemeral_ml_common::receipt_verify::{VerifyOptions, VerifyResult};
use ephemeral_ml_common::ui::{air_check_meta, legacy_check_meta, GhostState, Ui, UiConfig};
use ephemeral_ml_common::AttestationReceipt;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ephemeralml-verify",
    about = "Verify EphemeralML Attested Execution Receipts",
    long_about = "Verify an inference receipt signature and caller-supplied policy \
                  bindings. Full TEE provenance additionally requires platform \
                  attestation and signing-key binding checks. Supports AIR v1 and \
                  legacy receipts."
)]
struct Args {
    /// Path to the receipt file (CBOR or JSON)
    receipt: PathBuf,

    /// Ed25519 public key as hex string (64 hex chars = 32 bytes).
    /// Use this for direct verification without an attestation document.
    #[arg(long, conflicts_with = "attestation")]
    public_key: Option<String>,

    /// Path to file containing the raw 32-byte Ed25519 public key.
    #[arg(long, conflicts_with_all = ["public_key", "attestation"])]
    public_key_file: Option<PathBuf>,

    /// Path to attestation document (CBOR). The receipt signing key will
    /// be extracted from the attestation user_data field.
    #[arg(long, short)]
    attestation: Option<PathBuf>,

    /// Expected model ID (optional). Fails if receipt model_id doesn't match.
    #[arg(long)]
    expected_model: Option<String>,

    /// Expected AIR model_hash as 64 hex chars (optional).
    #[arg(long)]
    expected_model_hash: Option<String>,

    /// Expected AIR request_hash as 64 hex chars (optional).
    #[arg(long)]
    expected_request_hash: Option<String>,

    /// Expected AIR response_hash as 64 hex chars (optional).
    #[arg(long)]
    expected_response_hash: Option<String>,

    /// Expected AIR security_mode. This production verifier accepts only "production".
    #[arg(long)]
    expected_security_mode: Option<String>,

    /// Maximum receipt age in seconds (default: 1 hour). Set to 0 to skip.
    #[arg(long, default_value = "3600")]
    max_age: u64,

    /// Expected measurement type: nitro-pcr, tdx-mrtd-rtmr, or any (default: any).
    #[arg(long, default_value = "any")]
    measurement_type: String,

    /// Expected attestation source (e.g. cs-tdx, tdx, nitro). Skipped if not set.
    #[arg(long)]
    expected_attestation_source: Option<String>,

    /// Expected container image digest (e.g. sha256:<hex>). Skipped if not set.
    #[arg(long)]
    expected_image_digest: Option<String>,

    /// Output format: text or json
    #[arg(long, default_value = "text")]
    format: String,

    /// Show verbose details (hashes, measurements, timestamps)
    #[arg(short, long)]
    verbose: bool,

    /// Allow verification of mock/plain-CBOR attestation documents without
    /// cryptographic verification. DANGEROUS: only for local testing.
    /// Only available when built with `--features mock`.
    #[cfg(feature = "mock")]
    #[arg(long)]
    allow_mock: bool,

    /// Disable colors and mascot (plain text output)
    #[arg(long)]
    plain: bool,

    /// Disable color output
    #[arg(long)]
    no_color: bool,

    /// Disable ghost mascot
    #[arg(long)]
    no_mascot: bool,

    /// Require destroy evidence in the receipt. Fails if the receipt does not
    /// contain a destroy_evidence field with at least one action.
    #[arg(long)]
    require_destroy_event: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let format_json = args.format == "json";
    let ui_config = UiConfig::resolve(
        std::io::stdout().is_terminal(),
        args.plain,
        args.no_color,
        args.no_mascot,
        format_json,
    );
    let mut ui = Ui::stdout(ui_config);

    ui.ghost(GhostState::Idle);

    // 1. Load receipt
    let receipt_bytes = fs::read(&args.receipt).context("Failed to read receipt file")?;

    // 2. Auto-detect format: CBOR tag 18 (0xD2) = AIR v1 COSE_Sign1
    if receipt_bytes.first() == Some(&0xD2) {
        let public_key = resolve_public_key(&args)?;
        return verify_air_v1_path(&mut ui, &receipt_bytes, &public_key, &args);
    }

    // Legacy path: JSON or CBOR AttestationReceipt
    let receipt: AttestationReceipt = ephemeral_ml_common::cbor::from_slice(&receipt_bytes)
        .or_else(|_| {
            serde_json::from_slice(&receipt_bytes)
                .map_err(|e| ephemeral_ml_common::cbor::CborError(e.to_string()))
        })
        .context("Failed to parse receipt (tried CBOR and JSON)")?;

    // 2. Resolve public key
    let public_key = resolve_public_key(&args)?;

    // 3. Build options from CLI args
    let options = VerifyOptions {
        expected_model: args.expected_model.clone(),
        expected_measurement_type: Some(args.measurement_type.clone()),
        max_age_secs: args.max_age,
        expected_attestation_source: args.expected_attestation_source.clone(),
        expected_image_digest: args.expected_image_digest.clone(),
        require_destroy_evidence: args.require_destroy_event,
    };

    // 4. Run verification
    let result = ephemeral_ml_common::verify_receipt(&receipt, &public_key, &options);

    // 5. Output
    match args.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        _ => {
            print_text_report(&mut ui, &result, &receipt, args.verbose);
        }
    }

    if result.verified {
        ui.ghost(GhostState::Success);
        std::process::exit(0);
    } else {
        ui.ghost(GhostState::Fail);
        std::process::exit(1);
    }
}

fn resolve_public_key(args: &Args) -> Result<VerifyingKey> {
    if let Some(ref hex_key) = args.public_key {
        let bytes = hex::decode(hex_key).context("Invalid hex in --public-key")?;
        if bytes.len() != 32 {
            bail!(
                "--public-key must be 64 hex chars (32 bytes), got {} bytes",
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr).context("Invalid Ed25519 public key")
    } else if let Some(ref path) = args.public_key_file {
        let bytes = fs::read(path).context("Failed to read --public-key-file")?;
        if bytes.len() != 32 {
            bail!(
                "--public-key-file must contain exactly 32 bytes, got {}",
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr).context("Invalid Ed25519 public key")
    } else if let Some(ref att_path) = args.attestation {
        let att_bytes = fs::read(att_path).context("Failed to read attestation file")?;
        ephemeral_ml_client::receipt_key::extract_key_from_attestation(
            &att_bytes,
            #[cfg(feature = "mock")]
            args.allow_mock,
            #[cfg(not(feature = "mock"))]
            false,
        )
    } else {
        bail!("Must provide one of: --public-key, --public-key-file, or --attestation");
    }
}

/// Verify an AIR v1 receipt (COSE_Sign1 CBOR) using the 4-layer verifier.
fn verify_air_v1_path(
    ui: &mut Ui,
    data: &[u8],
    public_key: &VerifyingKey,
    args: &Args,
) -> Result<()> {
    validate_air_v1_cli_args(args)?;
    let expected_model_hash =
        parse_hash32_hex(args.expected_model_hash.as_deref(), "expected-model-hash")?;
    let expected_request_hash = parse_hash32_hex(
        args.expected_request_hash.as_deref(),
        "expected-request-hash",
    )?;
    let expected_response_hash = parse_hash32_hex(
        args.expected_response_hash.as_deref(),
        "expected-response-hash",
    )?;
    let expected_attestation_doc_hash = match args.attestation.as_ref() {
        Some(path) => {
            let attestation =
                fs::read(path).context("Failed to read attestation file for hash binding")?;
            Some(Sha256::digest(attestation).into())
        }
        None => None,
    };

    // Build policy from CLI args
    let policy = AirVerifyPolicy {
        max_age_secs: args.max_age,
        expected_model_hash,
        expected_request_hash,
        expected_response_hash,
        expected_attestation_doc_hash,
        expected_model_id: args.expected_model.clone(),
        expected_security_mode: args.expected_security_mode.clone(),
        expected_platform: if args.measurement_type == "any" {
            None
        } else {
            Some(args.measurement_type.clone())
        },
        ..Default::default()
    };

    let result = ephemeral_ml_common::air_verify::verify_air_v1_receipt(data, public_key, &policy);

    match args.format.as_str() {
        "json" => {
            // Serialize the check results as JSON
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        _ => {
            print_air_v1_text_report(ui, &result, args.verbose);
        }
    }

    if result.verified {
        ui.ghost(GhostState::Success);
        std::process::exit(0);
    } else {
        ui.ghost(GhostState::Fail);
        std::process::exit(1);
    }
}

fn validate_air_v1_cli_args(args: &Args) -> Result<()> {
    let mut unsupported: Vec<&str> = Vec::new();
    if args.expected_attestation_source.is_some() {
        unsupported.push("--expected-attestation-source");
    }
    if args.expected_image_digest.is_some() {
        unsupported.push("--expected-image-digest");
    }
    if args.require_destroy_event {
        unsupported.push("--require-destroy-event");
    }
    if matches!(args.expected_security_mode.as_deref(), Some("evaluation")) {
        bail!(
            "--expected-security-mode evaluation is not accepted by the production verifier; \
             use an evaluation-specific verifier"
        );
    }
    if let Some(mode) = args.expected_security_mode.as_deref() {
        if mode != "production" {
            bail!("--expected-security-mode must be 'production' for this verifier");
        }
    }

    if unsupported.is_empty() {
        return Ok(());
    }

    bail!(
        "Unsupported for AIR v1 receipts: {}. Supported AIR checks are --expected-model, \
         --expected-model-hash, --expected-request-hash, --expected-response-hash, \
         --expected-security-mode, --measurement-type, and --max-age (plus key/attestation inputs).",
        unsupported.join(", ")
    )
}

fn parse_hash32_hex(value: Option<&str>, flag_name: &str) -> Result<Option<[u8; 32]>> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let bytes = hex::decode(value).with_context(|| format!("--{flag_name} must be hex"))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("--{flag_name} must decode to exactly 32 bytes"))?;
    Ok(Some(array))
}

fn print_air_v1_text_report(ui: &mut Ui, result: &AirVerifyResult, verbose: bool) {
    use ephemeral_ml_common::receipt_verify::CheckStatus;

    ui.blank();
    ui.header("EphemeralML AIR v1 Receipt Verification");
    ui.blank();

    if let Some(ref claims) = result.claims {
        let cti_hex = hex::encode(claims.cti);
        ui.kv("Receipt", &cti_hex);
        ui.kv(
            "Model",
            &format!("{} v{}", claims.model_id, claims.model_version),
        );
        ui.kv("Platform", &claims.enclave_measurements.measurement_type);
        ui.kv("Sequence", &format!("#{}", claims.sequence_number));
        ui.kv("Issuer", &claims.iss);
    }

    ui.blank();
    ui.section("4-Layer Verification");

    for check in &result.checks {
        let failed = matches!(check.status, AirCheckStatus::Fail);
        let status = match check.status {
            AirCheckStatus::Pass => CheckStatus::Pass,
            AirCheckStatus::Fail => CheckStatus::Fail,
            AirCheckStatus::Skip => CheckStatus::Skip,
        };
        let meta = air_check_meta(check.name);
        let detail = check
            .code
            .as_ref()
            .map(|c| format!(" [{}]", c))
            .or_else(|| check.detail.as_ref().map(|d| format!(" ({})", d)))
            .unwrap_or_default();
        let label = if matches!(
            meta.label,
            "Required claim present" | "Hash field valid" | "Verification check"
        ) {
            format!("{} ({}){}", meta.label, check.name, detail)
        } else {
            format!("{}{}", meta.label, detail)
        };
        ui.check(&label, &status);
        if let Some(exp) = ephemeral_ml_common::ui::explain_failed(check.name, failed) {
            ui.bullet(&format!("{} {}", exp.why, exp.fix));
        }
    }
    ui.divider();

    ui.blank();
    if result.verified {
        ui.success("VERIFIED (AIR v1)");
    } else {
        ui.failure("INVALID (AIR v1)");
    }
    ui.blank();

    let failures = result.failures();
    if !failures.is_empty() {
        ui.info("Failures:");
        for code in &failures {
            ui.bullet(&format!("{}", code));
        }
        ui.blank();
    }

    if verbose {
        if let Some(ref claims) = result.claims {
            ui.section("Details");
            ui.kv("Exec time", &format!("{}ms", claims.execution_time_ms));
            ui.kv("Memory", &format!("{} MB", claims.memory_peak_mb));
            ui.kv("Timestamp (iat)", &claims.iat.to_string());
            ui.kv("Model hash", &hex::encode(claims.model_hash));
            ui.kv("Req hash", &hex::encode(claims.request_hash));
            ui.kv("Resp hash", &hex::encode(claims.response_hash));
            ui.kv("Att hash", &hex::encode(claims.attestation_doc_hash));
            ui.kv("Security mode", &claims.security_mode);
            ui.kv("Policy", &claims.policy_version);
            if let Some(ref scheme) = claims.model_hash_scheme {
                ui.kv("Hash scheme", scheme);
            }
            ui.blank();
        }
    }

    ui.divider();
}

fn print_text_report(
    ui: &mut Ui,
    result: &VerifyResult,
    receipt: &AttestationReceipt,
    verbose: bool,
) {
    ui.blank();
    ui.header("EphemeralML Receipt Verification");
    ui.blank();
    ui.kv("Receipt", &result.receipt_id);
    ui.kv(
        "Model",
        &format!("{} v{}", result.model_id, result.model_version),
    );
    ui.kv("Platform", &result.measurement_type);
    if let Some(ref src) = result.attestation_source {
        ui.kv("Att.Source", src);
    }
    if let Some(ref digest) = result.cs_image_digest {
        ui.kv("Image", digest);
    }
    ui.kv("Sequence", &format!("#{}", result.sequence_number));
    ui.blank();
    ui.section("Checks");
    ui.check_explained(
        legacy_check_meta("signature").unwrap().label,
        "signature",
        &result.checks.signature,
    );
    ui.check_explained(
        legacy_check_meta("model_match").unwrap().label,
        "model_match",
        &result.checks.model_match,
    );
    ui.check_explained(
        legacy_check_meta("measurement_type").unwrap().label,
        "measurement_type",
        &result.checks.measurement_type,
    );
    ui.check_explained(
        legacy_check_meta("timestamp_fresh").unwrap().label,
        "timestamp_fresh",
        &result.checks.timestamp_fresh,
    );
    ui.check_explained(
        legacy_check_meta("measurements_present").unwrap().label,
        "measurements_present",
        &result.checks.measurements_present,
    );
    ui.check_explained(
        legacy_check_meta("attestation_source").unwrap().label,
        "attestation_source",
        &result.checks.attestation_source,
    );
    ui.check_explained(
        legacy_check_meta("image_digest").unwrap().label,
        "image_digest",
        &result.checks.image_digest,
    );
    ui.check_explained(
        legacy_check_meta("destroy_evidence").unwrap().label,
        "destroy_evidence",
        &result.checks.destroy_evidence,
    );
    ui.divider();

    ui.blank();
    if result.verified {
        ui.success("VERIFIED");
    } else {
        ui.failure("INVALID");
    }
    ui.blank();

    if !result.errors.is_empty() {
        ui.info("Errors:");
        for err in &result.errors {
            ui.bullet(err);
        }
        ui.blank();
    }

    if !result.warnings.is_empty() {
        ui.info("Warnings:");
        for warn in &result.warnings {
            ui.bullet(warn);
        }
        ui.blank();
    }

    if verbose {
        ui.section("Details");
        ui.kv("Exec time", &format!("{}ms", receipt.execution_time_ms));
        ui.kv("Memory", &format!("{} MB", receipt.memory_peak_mb));
        ui.kv("Timestamp", &receipt.execution_timestamp.to_string());
        ui.kv("Req hash", &hex::encode(receipt.request_hash));
        ui.kv("Resp hash", &hex::encode(receipt.response_hash));
        ui.kv("Att hash", &hex::encode(receipt.attestation_doc_hash));
        ui.kv(
            "PCR0/MRTD",
            &hex::encode(&receipt.enclave_measurements.pcr0),
        );
        ui.kv(
            "PCR1/RTMR0",
            &hex::encode(&receipt.enclave_measurements.pcr1),
        );
        ui.kv(
            "PCR2/RTMR1",
            &hex::encode(&receipt.enclave_measurements.pcr2),
        );
        if let Some(sig) = &receipt.signature {
            ui.kv("Signature", &format!("{}...", &hex::encode(sig)[..32]));
        }
        ui.blank();
    }

    ui.divider();
}
