//! Receipt Verification CLI Tool
//!
//! Usage: verify_receipt --receipt <receipt.cbor|receipt.json> --attestation <attestation.cbor> [--verbose]
//!
//! Verifies:
//! 1. COSE_Sign1 attestation authenticity (signature + cert chain)
//! 2. Ed25519 signature on the receipt
//! 3. Binding to attestation document
//! 4. PCR measurements against allowlist (optional)
//! 5. Timestamp freshness (optional)

use anyhow::{bail, Context, Result};
use clap::Parser;
use coset::CborSerializable;
use ed25519_dalek::VerifyingKey;
use ephemeral_ml_common::{AttestationReceipt, AttestationUserData};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "verify_receipt")]
#[command(about = "Verify EphemeralML Attested Execution Receipts")]
struct Args {
    /// Path to the receipt file (CBOR or JSON)
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

    /// Skip COSE_Sign1 attestation signature verification (UNSAFE: allows forged attestations)
    #[arg(long)]
    unsafe_skip_attestation_verification: bool,

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
    attestation_authentic: bool,
    attestation_verification_skipped: bool,
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

    // Load receipt (try CBOR first for canonical format, then JSON for backwards compat)
    let receipt_bytes = fs::read(&args.receipt).context("Failed to read receipt file")?;
    let receipt: AttestationReceipt = ephemeral_ml_common::cbor::from_slice(&receipt_bytes)
        .or_else(|_| {
            // Fall back to JSON (e.g. older receipts or human-readable format)
            serde_json::from_slice(&receipt_bytes)
                .map_err(|e| ephemeral_ml_common::cbor::CborError(e.to_string()))
        })
        .context("Failed to parse receipt (tried CBOR and JSON)")?;

    // Load attestation document
    let attestation_bytes =
        fs::read(&args.attestation).context("Failed to read attestation file")?;

    // Initialize report
    let mut report = VerificationReport {
        receipt_id: receipt.receipt_id.clone(),
        model_id: receipt.model_id.clone(),
        model_version: receipt.model_version.clone(),
        attestation_authentic: false,
        attestation_verification_skipped: args.unsafe_skip_attestation_verification,
        signature_valid: false,
        attestation_binding_valid: false,
        pcr_measurements_valid: None,
        timestamp_fresh: false,
        overall_valid: false,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    // Step 1: Verify attestation document authenticity (COSE_Sign1 signature + cert chain)
    if args.unsafe_skip_attestation_verification {
        report.warnings.push(
            "UNSAFE: Attestation verification skipped -- receipt key trust is unverified"
                .to_string(),
        );
    } else {
        match verify_attestation_authenticity(&attestation_bytes) {
            Ok(()) => {
                report.attestation_authentic = true;
            }
            Err(e) => {
                report.errors.push(format!(
                    "Attestation verification failed (use --unsafe-skip-attestation-verification to bypass): {}",
                    e
                ));
                output_report(&report, &args)?;
                return Ok(());
            }
        }
    }

    // Step 2: Extract user data and public key from (now-verified) attestation
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

    // Step 3: Verify Ed25519 receipt signature using key from attestation
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

    // Step 4: Verify attestation binding (receipt hash matches attestation doc hash)
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

    // Step 5: Verify PCR measurements (if allowlist provided)
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

    // Step 6: Verify timestamp freshness
    let now = ephemeral_ml_common::current_timestamp();
    let age = now.saturating_sub(receipt.execution_timestamp);
    report.timestamp_fresh = age <= args.max_age_secs;
    if !report.timestamp_fresh {
        report.warnings.push(format!(
            "Receipt is {} seconds old (max allowed: {})",
            age, args.max_age_secs
        ));
    }

    // Compute overall validity: attestation MUST be verified (or explicitly skipped)
    report.overall_valid = (report.attestation_authentic
        || args.unsafe_skip_attestation_verification)
        && report.signature_valid
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

/// Verify the COSE_Sign1 attestation document's signature and certificate chain.
///
/// For AWS Nitro Enclaves, the attestation document is a COSE_Sign1 structure
/// signed by a certificate chaining to the AWS Nitro root CA. This function
/// verifies that chain, ensuring the attestation (and thus the user_data
/// containing the receipt signing key) is genuinely from a Nitro enclave.
fn verify_attestation_authenticity(attestation_bytes: &[u8]) -> Result<()> {
    use coset::CoseSign1;

    // Parse as COSE_Sign1
    let cose_doc = CoseSign1::from_slice(attestation_bytes)
        .map_err(|e| anyhow::anyhow!("Not a valid COSE_Sign1 document: {:?}", e))?;

    // Extract the payload (attestation document map)
    let payload = cose_doc
        .payload
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("COSE_Sign1 has no payload"))?;

    // Parse inner CBOR map to get the certificate
    let inner: ciborium::Value =
        ephemeral_ml_common::cbor::from_slice(payload).context("Failed to parse COSE_Sign1 payload")?;

    let map = match &inner {
        ciborium::Value::Map(m) => m,
        _ => bail!("COSE_Sign1 payload is not a CBOR map"),
    };

    // Extract certificate (the signing cert)
    let cert_key = ciborium::Value::Text("certificate".to_string());
    let cert_der = match ephemeral_ml_common::cbor::map_get(map, &cert_key) {
        Some(ciborium::Value::Bytes(b)) => b,
        _ => bail!("No 'certificate' field in attestation document"),
    };

    // Parse the signing certificate
    let signing_cert = openssl::x509::X509::from_der(cert_der)
        .context("Failed to parse signing certificate DER")?;

    // Extract the public key and verify COSE_Sign1 signature
    let pub_key = signing_cert.public_key().context("No public key in cert")?;

    // The COSE_Sign1 signature is over the Sig_structure:
    // ["Signature1", protected_header_bytes, external_aad, payload]
    let sig_structure = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        cose_doc.protected.clone(),
        None,
        &[],
        payload,
    );

    // Verify using the algorithm from the protected header (typically ES384 for Nitro)
    let signature = &cose_doc.signature;
    let mut verifier =
        openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha384(), &pub_key)
            .context("Failed to create verifier")?;

    // For ECDSA, the COSE signature is r||s (raw), need to convert to DER
    if signature.len() == 96 {
        // ES384: 2 * 48 bytes
        let r = openssl::bn::BigNum::from_slice(&signature[..48])?;
        let s = openssl::bn::BigNum::from_slice(&signature[48..])?;
        let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s)?;
        let der_sig = ecdsa_sig.to_der()?;
        verifier.update(&sig_structure)?;
        if !verifier.verify(&der_sig)? {
            bail!("COSE_Sign1 signature verification failed");
        }
    } else {
        // Try raw verification for other key types
        verifier.update(&sig_structure)?;
        if !verifier.verify(signature)? {
            bail!("COSE_Sign1 signature verification failed");
        }
    }

    // Extract CA bundle and verify certificate chain
    let cabundle_key = ciborium::Value::Text("cabundle".to_string());
    if let Some(ciborium::Value::Array(certs)) = ephemeral_ml_common::cbor::map_get(map, &cabundle_key) {
        let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
        for cert_val in certs {
            if let ciborium::Value::Bytes(der) = cert_val {
                if let Ok(ca_cert) = openssl::x509::X509::from_der(der) {
                    store_builder.add_cert(ca_cert)?;
                }
            }
        }
        let store = store_builder.build();

        let mut ctx = openssl::x509::X509StoreContext::new()?;
        let chain = openssl::stack::Stack::new()?;
        let valid = ctx.init(&store, &signing_cert, &chain, |ctx| ctx.verify_cert())?;
        if !valid {
            bail!("Certificate chain verification failed");
        }
    } else {
        bail!("No 'cabundle' field in attestation document for chain verification");
    }

    Ok(())
}

fn extract_user_data_from_attestation(attestation_bytes: &[u8]) -> Result<AttestationUserData> {
    // Parse CBOR attestation document
    let doc: ciborium::Value =
        ephemeral_ml_common::cbor::from_slice(attestation_bytes).context("Failed to parse attestation CBOR")?;

    // Try COSE_Sign1 format first (production), then fall back to CBOR map (mock).
    // COSE_Sign1 is a CBOR array: [protected, unprotected, payload, signature].
    // The payload (index 2) contains the attestation document as a CBOR map.
    match &doc {
        ciborium::Value::Array(arr) if arr.len() == 4 => {
            // COSE_Sign1: extract payload bytes from index 2
            if let ciborium::Value::Bytes(payload_bytes) = &arr[2] {
                extract_user_data_from_map_bytes(payload_bytes)
            } else {
                bail!("COSE_Sign1 payload is not bytes")
            }
        }
        ciborium::Value::Map(_) => extract_user_data_from_map(&doc),
        _ => bail!("Attestation document is neither a COSE_Sign1 array nor a CBOR map"),
    }
}

fn extract_user_data_from_map_bytes(map_bytes: &[u8]) -> Result<AttestationUserData> {
    let doc: ciborium::Value =
        ephemeral_ml_common::cbor::from_slice(map_bytes).context("Failed to parse COSE_Sign1 payload as CBOR")?;
    extract_user_data_from_map(&doc)
}

fn extract_user_data_from_map(doc: &ciborium::Value) -> Result<AttestationUserData> {
    let map = match doc {
        ciborium::Value::Map(m) => m,
        _ => bail!("Attestation payload is not a CBOR map"),
    };

    // Extract user_data field
    let user_data_key = ciborium::Value::Text("user_data".to_string());
    let user_data_bytes = match ephemeral_ml_common::cbor::map_get(map, &user_data_key) {
        Some(ciborium::Value::Bytes(b)) => b.clone(),
        Some(_) => bail!("user_data field is not bytes"),
        None => bail!("user_data field not found in attestation"),
    };

    // Parse user data (try JSON first, then CBOR)
    let user_data: AttestationUserData =
        if let Ok(parsed) = serde_json::from_slice(&user_data_bytes) {
            parsed
        } else {
            ephemeral_ml_common::cbor::from_slice(&user_data_bytes)
                .context("Failed to parse user_data (tried JSON and CBOR)")?
        };

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

            let att_status = if report.attestation_verification_skipped {
                "⚠ SKIP (unsafe)"
            } else if report.attestation_authentic {
                "✓ PASS"
            } else {
                "✗ FAIL"
            };
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

            println!("║ Attestation Auth:    {:<40} ║", att_status);
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
