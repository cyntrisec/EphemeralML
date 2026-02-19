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
use ephemeral_ml_common::receipt_verify::{VerifyOptions, VerifyResult};
use ephemeral_ml_common::ui::{GhostState, Ui, UiConfig};
use ephemeral_ml_common::AttestationReceipt;
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ephemeralml-verify",
    about = "Verify EphemeralML Attested Execution Receipts",
    long_about = "Verify that an inference receipt was signed by a key bound to an \
                  attested confidential workload. Supports receipts from both AWS Nitro \
                  Enclaves (nitro-pcr) and GCP Confidential Space (tdx-mrtd-rtmr)."
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
        extract_key_from_attestation(
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

/// Extract the receipt signing key from an attestation document.
///
/// For COSE_Sign1 (Nitro) format: verifies the COSE signature and certificate
/// chain against the AWS Nitro root CA before extracting the key. Nonce and
/// PCR policy are NOT checked (this is offline verification — the caller must
/// independently verify those if needed).
///
/// For plain CBOR map (mock/TDX envelope) format: rejected by default.
/// Pass `allow_mock = true` (--allow-mock CLI flag) to accept unverified
/// mock attestation documents for local testing only.
fn extract_key_from_attestation(att_bytes: &[u8], allow_mock: bool) -> Result<VerifyingKey> {
    use ciborium::Value;

    let doc: Value = ephemeral_ml_common::cbor::from_slice(att_bytes)
        .context("Invalid CBOR attestation document")?;

    // Determine format and extract the payload map entries
    let map_entries = match &doc {
        Value::Array(arr) if arr.len() == 4 => {
            // COSE_Sign1: [protected, unprotected, payload, signature]
            // Verify COSE signature + cert chain before trusting the payload
            let att_doc = ephemeral_ml_common::AttestationDocument {
                module_id: String::new(),
                digest: vec![],
                timestamp: 0,
                pcrs: ephemeral_ml_common::PcrMeasurements::new(vec![], vec![], vec![]),
                certificate: vec![],
                signature: att_bytes.to_vec(),
                nonce: None,
            };

            // Use AttestationVerifier with a permissive policy (no PCR allowlist)
            // to verify COSE_Sign1 signature + certificate chain.
            // Nonce is skipped since this is offline verification.
            let policy = ephemeral_ml_client::PolicyManager::new();
            let mut verifier =
                ephemeral_ml_client::attestation_verifier::AttestationVerifier::new(policy);
            let identity = verifier.verify_attestation_skip_nonce(&att_doc).context(
                "Attestation COSE signature or certificate chain verification failed. \
                     The attestation document is not authentic.",
            )?;

            return VerifyingKey::from_bytes(&identity.receipt_signing_key)
                .context("Invalid receipt signing key from verified attestation");
        }
        Value::Map(m) => {
            if !allow_mock {
                bail!(
                    "Attestation document is a plain CBOR map (mock format) without \
                     cryptographic verification. This is NOT safe for production use.\n\
                     If you are testing locally, pass --allow-mock to accept unverified \
                     attestation documents."
                );
            }
            eprintln!("  WARNING: --allow-mock is set. Accepting unverified CBOR map attestation.");
            eprintln!("  The receipt signing key is extracted WITHOUT cryptographic verification.");
            eprintln!("  DO NOT use --allow-mock in production.");
            m.clone()
        }
        _ => bail!("Attestation document is neither COSE_Sign1 nor CBOR map"),
    };

    let user_data_key = Value::Text("user_data".to_string());
    let user_data_bytes = match ephemeral_ml_common::cbor::map_get(&map_entries, &user_data_key) {
        Some(Value::Bytes(b)) => b,
        _ => bail!("No user_data bytes in attestation document"),
    };

    // Try JSON first (EphemeralML format), then CBOR
    let ud: ephemeral_ml_common::AttestationUserData =
        if let Ok(parsed) = serde_json::from_slice(user_data_bytes) {
            parsed
        } else {
            ephemeral_ml_common::cbor::from_slice(user_data_bytes)
                .context("Failed to parse user_data from attestation (tried JSON and CBOR)")?
        };

    VerifyingKey::from_bytes(&ud.receipt_signing_key).context("Invalid receipt signing key")
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
    ui.check_explained("Signature (Ed25519)", "signature", &result.checks.signature);
    ui.check_explained("Model ID match", "model_match", &result.checks.model_match);
    ui.check_explained(
        "Measurement type",
        "measurement_type",
        &result.checks.measurement_type,
    );
    ui.check_explained(
        "Timestamp freshness",
        "timestamp_fresh",
        &result.checks.timestamp_fresh,
    );
    ui.check_explained(
        "Measurements present",
        "measurements_present",
        &result.checks.measurements_present,
    );
    ui.check_explained(
        "Attestation source",
        "attestation_source",
        &result.checks.attestation_source,
    );
    ui.check_explained("Image digest", "image_digest", &result.checks.image_digest);
    ui.check_explained(
        "Destroy evidence",
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
