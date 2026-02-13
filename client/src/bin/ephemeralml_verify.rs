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
use ephemeral_ml_common::AttestationReceipt;
use std::fs;
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

    /// Output format: text or json
    #[arg(long, default_value = "text")]
    format: String,

    /// Show verbose details (hashes, measurements, timestamps)
    #[arg(short, long)]
    verbose: bool,
}

#[derive(serde::Serialize)]
struct VerifyResult {
    verified: bool,
    receipt_id: String,
    model_id: String,
    model_version: String,
    measurement_type: String,
    sequence_number: u64,
    execution_timestamp: u64,
    checks: CheckResults,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(serde::Serialize)]
struct CheckResults {
    signature: CheckStatus,
    model_match: CheckStatus,
    measurement_type: CheckStatus,
    timestamp_fresh: CheckStatus,
    measurements_present: CheckStatus,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum CheckStatus {
    Pass,
    Fail,
    Skip,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckStatus::Pass => write!(f, "PASS"),
            CheckStatus::Fail => write!(f, "FAIL"),
            CheckStatus::Skip => write!(f, "SKIP"),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // 1. Load receipt
    let receipt_bytes = fs::read(&args.receipt).context("Failed to read receipt file")?;
    let receipt: AttestationReceipt = serde_cbor::from_slice(&receipt_bytes)
        .or_else(|_| serde_json::from_slice(&receipt_bytes))
        .context("Failed to parse receipt (tried CBOR and JSON)")?;

    // 2. Resolve public key
    let public_key = resolve_public_key(&args)?;

    // 3. Run checks
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Check: Ed25519 signature
    let sig_status = match receipt.verify_signature(&public_key) {
        Ok(true) => CheckStatus::Pass,
        Ok(false) => {
            errors.push("Ed25519 signature verification failed".to_string());
            CheckStatus::Fail
        }
        Err(e) => {
            errors.push(format!("Signature error: {}", e));
            CheckStatus::Fail
        }
    };

    // Check: model ID
    let model_status = if let Some(ref expected) = args.expected_model {
        if receipt.model_id == *expected {
            CheckStatus::Pass
        } else {
            errors.push(format!(
                "Model mismatch: receipt has '{}', expected '{}'",
                receipt.model_id, expected
            ));
            CheckStatus::Fail
        }
    } else {
        CheckStatus::Skip
    };

    // Check: measurement type
    let mt_status = if args.measurement_type == "any" {
        CheckStatus::Skip
    } else if receipt.enclave_measurements.measurement_type == args.measurement_type {
        CheckStatus::Pass
    } else {
        errors.push(format!(
            "Measurement type mismatch: receipt has '{}', expected '{}'",
            receipt.enclave_measurements.measurement_type, args.measurement_type
        ));
        CheckStatus::Fail
    };

    // Check: timestamp freshness
    let ts_status = if args.max_age == 0 {
        CheckStatus::Skip
    } else {
        let now = ephemeral_ml_common::current_timestamp();
        let age = now.saturating_sub(receipt.execution_timestamp);
        if age <= args.max_age {
            CheckStatus::Pass
        } else {
            warnings.push(format!(
                "Receipt is {}s old (max allowed: {}s)",
                age, args.max_age
            ));
            CheckStatus::Fail
        }
    };

    // Check: measurements present and valid
    let meas_status = if receipt.enclave_measurements.is_valid() {
        CheckStatus::Pass
    } else {
        warnings.push("Measurements are not 48 bytes (expected SHA-384)".to_string());
        CheckStatus::Fail
    };

    let verified = matches!(sig_status, CheckStatus::Pass) && errors.is_empty();

    let result = VerifyResult {
        verified,
        receipt_id: receipt.receipt_id.clone(),
        model_id: receipt.model_id.clone(),
        model_version: receipt.model_version.clone(),
        measurement_type: receipt.enclave_measurements.measurement_type.clone(),
        sequence_number: receipt.sequence_number,
        execution_timestamp: receipt.execution_timestamp,
        checks: CheckResults {
            signature: sig_status,
            model_match: model_status,
            measurement_type: mt_status,
            timestamp_fresh: ts_status,
            measurements_present: meas_status,
        },
        errors,
        warnings,
    };

    // 4. Output
    match args.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        _ => {
            print_text_report(&result, &receipt, args.verbose);
        }
    }

    if result.verified {
        std::process::exit(0);
    } else {
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
        extract_key_from_attestation(&att_bytes)
    } else {
        bail!("Must provide one of: --public-key, --public-key-file, or --attestation");
    }
}

/// Extract the receipt signing key from an attestation document.
///
/// Supports both COSE_Sign1 (Nitro) and plain CBOR map (mock/TDX envelope) formats.
fn extract_key_from_attestation(att_bytes: &[u8]) -> Result<VerifyingKey> {
    let doc: serde_cbor::Value =
        serde_cbor::from_slice(att_bytes).context("Invalid CBOR attestation document")?;

    // Get the map: either from COSE_Sign1 payload[2] or directly
    let map = match &doc {
        serde_cbor::Value::Array(arr) if arr.len() == 4 => {
            // COSE_Sign1: [protected, unprotected, payload, signature]
            let payload_bytes = match &arr[2] {
                serde_cbor::Value::Bytes(b) => b,
                _ => bail!("COSE_Sign1 payload is not bytes"),
            };
            let inner: serde_cbor::Value =
                serde_cbor::from_slice(payload_bytes).context("Invalid COSE_Sign1 payload")?;
            match inner {
                serde_cbor::Value::Map(m) => m,
                _ => bail!("COSE_Sign1 payload is not a CBOR map"),
            }
        }
        serde_cbor::Value::Map(m) => m.clone(),
        _ => bail!("Attestation document is neither COSE_Sign1 nor CBOR map"),
    };

    let user_data_key = serde_cbor::Value::Text("user_data".to_string());
    let user_data_bytes = match map.get(&user_data_key) {
        Some(serde_cbor::Value::Bytes(b)) => b,
        _ => bail!("No user_data bytes in attestation document"),
    };

    // Try JSON first (EphemeralML format), then CBOR
    let ud: ephemeral_ml_common::AttestationUserData = serde_json::from_slice(user_data_bytes)
        .or_else(|_| serde_cbor::from_slice(user_data_bytes))
        .context("Failed to parse user_data from attestation")?;

    VerifyingKey::from_bytes(&ud.receipt_signing_key).context("Invalid receipt signing key")
}

fn print_text_report(result: &VerifyResult, receipt: &AttestationReceipt, verbose: bool) {
    let w = 62;
    let bar = "=".repeat(w);
    let thin = "-".repeat(w);

    println!();
    println!("  {}", bar);
    println!("  EphemeralML Receipt Verification");
    println!("  {}", bar);
    println!();
    println!("  Receipt:   {}", result.receipt_id);
    println!("  Model:     {} v{}", result.model_id, result.model_version);
    println!("  Platform:  {}", result.measurement_type);
    println!("  Sequence:  #{}", result.sequence_number);
    println!();
    println!("  {}", thin);
    println!("  Checks:");
    println!("  {}", thin);
    println!(
        "  Signature (Ed25519)       {}",
        status_icon(&result.checks.signature)
    );
    println!(
        "  Model ID match            {}",
        status_icon(&result.checks.model_match)
    );
    println!(
        "  Measurement type          {}",
        status_icon(&result.checks.measurement_type)
    );
    println!(
        "  Timestamp freshness       {}",
        status_icon(&result.checks.timestamp_fresh)
    );
    println!(
        "  Measurements present      {}",
        status_icon(&result.checks.measurements_present)
    );
    println!("  {}", thin);

    if result.verified {
        println!();
        println!("  VERIFIED");
        println!();
    } else {
        println!();
        println!("  INVALID");
        println!();
    }

    if !result.errors.is_empty() {
        println!("  Errors:");
        for err in &result.errors {
            println!("    - {}", err);
        }
        println!();
    }

    if !result.warnings.is_empty() {
        println!("  Warnings:");
        for warn in &result.warnings {
            println!("    - {}", warn);
        }
        println!();
    }

    if verbose {
        println!("  {}", thin);
        println!("  Details:");
        println!("  {}", thin);
        println!("  Execution time:    {}ms", receipt.execution_time_ms);
        println!("  Memory peak:       {} MB", receipt.memory_peak_mb);
        println!("  Timestamp:         {}", receipt.execution_timestamp);
        println!("  Request hash:      {}", hex::encode(receipt.request_hash));
        println!(
            "  Response hash:     {}",
            hex::encode(receipt.response_hash)
        );
        println!(
            "  Attestation hash:  {}",
            hex::encode(receipt.attestation_doc_hash)
        );
        println!(
            "  PCR0/MRTD:         {}",
            hex::encode(&receipt.enclave_measurements.pcr0)
        );
        println!(
            "  PCR1/RTMR0:        {}",
            hex::encode(&receipt.enclave_measurements.pcr1)
        );
        println!(
            "  PCR2/RTMR1:        {}",
            hex::encode(&receipt.enclave_measurements.pcr2)
        );
        if let Some(sig) = &receipt.signature {
            println!("  Signature:         {}...", &hex::encode(sig)[..32]);
        }
        println!();
    }

    println!("  {}", bar);
}

fn status_icon(status: &CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "[PASS]",
        CheckStatus::Fail => "[FAIL]",
        CheckStatus::Skip => "[SKIP]",
    }
}
