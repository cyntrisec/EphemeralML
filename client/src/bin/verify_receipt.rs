//! Receipt Verification CLI Tool
//!
//! Usage: verify_receipt --receipt <receipt.json> --attestation <attestation.cbor> [--verbose]
//!
//! Verifies:
//! 1. Ed25519 signature on the receipt
//! 2. Binding to attestation document
//! 3. PCR measurements against allowlist (optional)
//! 4. Timestamp freshness (optional)

use anyhow::{bail, Context, Result};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use ephemeral_ml_common::{AttestationReceipt, AttestationUserData};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "verify_receipt")]
#[command(about = "Verify EphemeralML Attested Execution Receipts")]
struct Args {
    /// Path to the receipt JSON file
    #[arg(short, long)]
    receipt: PathBuf,

    /// Path to the attestation document (CBOR)
    #[arg(short, long)]
    attestation: PathBuf,

    /// Path to PCR allowlist file (optional)
    #[arg(short, long)]
    pcr_allowlist: Option<PathBuf>,

    /// Maximum age of receipt in seconds (optional)
    #[arg(long, default_value = "3600")]
    max_age_secs: u64,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output format: text, json
    #[arg(long, default_value = "text")]
    format: String,
}

#[derive(serde::Serialize)]
struct VerificationReport {
    receipt_id: String,
    model_id: String,
    model_version: String,
    signature_valid: bool,
    attestation_binding_valid: bool,
    pcr_measurements_valid: Option<bool>,
    timestamp_fresh: bool,
    overall_valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Load receipt
    let receipt_data = fs::read_to_string(&args.receipt).context("Failed to read receipt file")?;
    let receipt: AttestationReceipt =
        serde_json::from_str(&receipt_data).context("Failed to parse receipt JSON")?;

    // Load attestation document
    let attestation_bytes =
        fs::read(&args.attestation).context("Failed to read attestation file")?;

    // Initialize report
    let mut report = VerificationReport {
        receipt_id: receipt.receipt_id.clone(),
        model_id: receipt.model_id.clone(),
        model_version: receipt.model_version.clone(),
        signature_valid: false,
        attestation_binding_valid: false,
        pcr_measurements_valid: None,
        timestamp_fresh: false,
        overall_valid: false,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    // Step 1: Extract user data and public key from attestation
    let user_data = match extract_user_data_from_attestation(&attestation_bytes) {
        Ok(ud) => ud,
        Err(e) => {
            report
                .errors
                .push(format!("Failed to extract user data: {}", e));
            output_report(&report, &args)?;
            return Ok(());
        }
    };

    // Step 2: Verify signature
    match verify_signature(&receipt, &user_data.receipt_signing_key) {
        Ok(valid) => {
            report.signature_valid = valid;
            if !valid {
                report
                    .errors
                    .push("Signature verification failed".to_string());
            }
        }
        Err(e) => {
            report
                .errors
                .push(format!("Signature verification error: {}", e));
        }
    }

    // Step 3: Verify attestation binding
    match verify_attestation_binding(&receipt, &attestation_bytes) {
        Ok(valid) => {
            report.attestation_binding_valid = valid;
            if !valid {
                report
                    .errors
                    .push("Attestation binding mismatch".to_string());
            }
        }
        Err(e) => {
            report
                .errors
                .push(format!("Attestation binding error: {}", e));
        }
    }

    // Step 4: Verify PCR measurements (if allowlist provided)
    if let Some(allowlist_path) = &args.pcr_allowlist {
        match verify_pcr_measurements(&receipt, allowlist_path) {
            Ok(valid) => {
                report.pcr_measurements_valid = Some(valid);
                if !valid {
                    report
                        .errors
                        .push("PCR measurements not in allowlist".to_string());
                }
            }
            Err(e) => {
                report.errors.push(format!("PCR verification error: {}", e));
            }
        }
    }

    // Step 5: Verify timestamp freshness
    let now = ephemeral_ml_common::current_timestamp();
    let age = now.saturating_sub(receipt.execution_timestamp);
    report.timestamp_fresh = age <= args.max_age_secs;
    if !report.timestamp_fresh {
        report.warnings.push(format!(
            "Receipt is {} seconds old (max allowed: {})",
            age, args.max_age_secs
        ));
    }

    // Compute overall validity
    report.overall_valid = report.signature_valid
        && report.attestation_binding_valid
        && report.pcr_measurements_valid.unwrap_or(true)
        && report.errors.is_empty();

    output_report(&report, &args)?;

    if report.overall_valid {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}

fn extract_user_data_from_attestation(attestation_bytes: &[u8]) -> Result<AttestationUserData> {
    // Parse CBOR attestation document
    let doc: serde_cbor::Value =
        serde_cbor::from_slice(attestation_bytes).context("Failed to parse attestation CBOR")?;

    let map = match doc {
        serde_cbor::Value::Map(m) => m,
        _ => bail!("Attestation document is not a CBOR map"),
    };

    // Extract user_data field
    let user_data_key = serde_cbor::Value::Text("user_data".to_string());
    let user_data_bytes = match map.get(&user_data_key) {
        Some(serde_cbor::Value::Bytes(b)) => b.clone(),
        Some(_) => bail!("user_data field is not bytes"),
        None => bail!("user_data field not found in attestation"),
    };

    // Parse user data
    let user_data: AttestationUserData = serde_json::from_slice(&user_data_bytes)
        .or_else(|_| serde_cbor::from_slice(&user_data_bytes))
        .context("Failed to parse user_data")?;

    Ok(user_data)
}

fn verify_signature(receipt: &AttestationReceipt, public_key_bytes: &[u8; 32]) -> Result<bool> {
    let public_key =
        VerifyingKey::from_bytes(public_key_bytes).context("Invalid Ed25519 public key")?;

    receipt
        .verify_signature(&public_key)
        .context("Signature verification failed")
}

fn verify_attestation_binding(
    receipt: &AttestationReceipt,
    attestation_bytes: &[u8],
) -> Result<bool> {
    // Compute SHA-256 of attestation document
    let mut hasher = Sha256::new();
    hasher.update(attestation_bytes);
    let computed_hash = hasher.finalize();

    // Compare with receipt's attestation_doc_hash
    Ok(computed_hash.as_slice() == receipt.attestation_doc_hash.as_slice())
}

fn verify_pcr_measurements(receipt: &AttestationReceipt, allowlist_path: &PathBuf) -> Result<bool> {
    // Load allowlist (JSON format: {"allowed": [{"pcr0": "hex", "pcr1": "hex", "pcr2": "hex"}, ...]})
    let allowlist_data =
        fs::read_to_string(allowlist_path).context("Failed to read PCR allowlist")?;

    #[derive(serde::Deserialize)]
    struct PcrAllowlist {
        allowed: Vec<PcrEntry>,
    }

    #[derive(serde::Deserialize)]
    struct PcrEntry {
        pcr0: String,
        pcr1: String,
        pcr2: String,
    }

    let allowlist: PcrAllowlist =
        serde_json::from_str(&allowlist_data).context("Failed to parse PCR allowlist")?;

    // Convert receipt measurements to hex
    let receipt_pcr0 = hex::encode(&receipt.enclave_measurements.pcr0);
    let receipt_pcr1 = hex::encode(&receipt.enclave_measurements.pcr1);
    let receipt_pcr2 = hex::encode(&receipt.enclave_measurements.pcr2);

    // Check if measurements are in allowlist
    for entry in &allowlist.allowed {
        if entry.pcr0 == receipt_pcr0 && entry.pcr1 == receipt_pcr1 && entry.pcr2 == receipt_pcr2 {
            return Ok(true);
        }
    }

    Ok(false)
}

fn output_report(report: &VerificationReport, args: &Args) -> Result<()> {
    match args.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(report)?);
        }
        _ => {
            println!("╔══════════════════════════════════════════════════════════════╗");
            println!("║           EphemeralML Receipt Verification Report            ║");
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!(
                "║ Receipt ID: {:<48} ║",
                &report.receipt_id[..report.receipt_id.len().min(48)]
            );
            println!(
                "║ Model: {:<53} ║",
                format!("{}@{}", report.model_id, report.model_version)
            );
            println!("╠══════════════════════════════════════════════════════════════╣");

            let sig_status = if report.signature_valid {
                "✓ PASS"
            } else {
                "✗ FAIL"
            };
            let bind_status = if report.attestation_binding_valid {
                "✓ PASS"
            } else {
                "✗ FAIL"
            };
            let pcr_status = match report.pcr_measurements_valid {
                Some(true) => "✓ PASS",
                Some(false) => "✗ FAIL",
                None => "- SKIP",
            };
            let time_status = if report.timestamp_fresh {
                "✓ PASS"
            } else {
                "⚠ WARN"
            };

            println!("║ Signature:           {:<40} ║", sig_status);
            println!("║ Attestation Binding: {:<40} ║", bind_status);
            println!("║ PCR Measurements:    {:<40} ║", pcr_status);
            println!("║ Timestamp Fresh:     {:<40} ║", time_status);
            println!("╠══════════════════════════════════════════════════════════════╣");

            let overall = if report.overall_valid {
                "✓ VERIFIED"
            } else {
                "✗ INVALID"
            };
            println!("║ OVERALL: {:<52} ║", overall);
            println!("╚══════════════════════════════════════════════════════════════╝");

            if args.verbose {
                if !report.errors.is_empty() {
                    println!("\nErrors:");
                    for err in &report.errors {
                        println!("  • {}", err);
                    }
                }
                if !report.warnings.is_empty() {
                    println!("\nWarnings:");
                    for warn in &report.warnings {
                        println!("  • {}", warn);
                    }
                }
            }
        }
    }

    Ok(())
}
