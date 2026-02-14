//! Polished demo CLI for EphemeralML confidential inference.
//!
//! Usage:
//!   ephemeralml infer --addr 34.63.158.243:9000 --text "Patient presents with..."
//!   ephemeralml infer --addr 127.0.0.1:9000 --file client/demo/radiology-report.txt
//!   ephemeralml verify receipt.json --public-key <hex>
//!   ephemeralml verify receipt.json --public-key-file receipt.json.pubkey

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use ephemeral_ml_client::{AttestationReceipt, SecureClient, SecureEnclaveClient};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "ephemeralml",
    about = "EphemeralML Confidential Inference CLI",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run confidential inference against an EphemeralML server
    Infer(InferArgs),
    /// Verify an attested execution receipt
    Verify(VerifyArgs),
}

#[derive(Parser)]
struct InferArgs {
    /// Server address (IP:PORT)
    #[arg(long)]
    addr: String,

    /// Input text to send for inference
    #[arg(long, conflicts_with = "file")]
    text: Option<String>,

    /// Path to a text file to send for inference
    #[arg(long, conflicts_with = "text")]
    file: Option<PathBuf>,

    /// Model ID to request
    #[arg(long, default_value = "stage-0")]
    model: String,

    /// Output path for the receipt JSON
    #[arg(long, default_value = "receipt.json")]
    receipt: PathBuf,
}

#[derive(Parser)]
struct VerifyArgs {
    /// Path to the receipt file (CBOR or JSON)
    receipt: PathBuf,

    /// Ed25519 public key as hex string (64 hex chars = 32 bytes)
    #[arg(long)]
    public_key: Option<String>,

    /// Path to file containing the raw 32-byte Ed25519 public key
    #[arg(long, conflicts_with = "public_key")]
    public_key_file: Option<PathBuf>,

    /// Maximum receipt age in seconds (0 to skip)
    #[arg(long, default_value = "3600")]
    max_age: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Infer(args) => run_infer(args).await,
        Commands::Verify(args) => run_verify(args),
    }
}

async fn run_infer(args: InferArgs) -> Result<()> {
    // Resolve input text
    let text = match (&args.text, &args.file) {
        (Some(t), _) => t.clone(),
        (_, Some(path)) => {
            fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?
        }
        _ => bail!("Provide either --text or --file"),
    };

    println!();
    println!("EphemeralML Confidential Inference");
    println!("==================================");
    println!();

    // Connect
    println!("Connecting to {}...", args.addr);
    let mut client = SecureEnclaveClient::new("ephemeralml-cli".to_string());
    client
        .establish_channel(&args.addr)
        .await
        .context("Failed to establish secure channel")?;

    // Determine attestation mode from features
    let attestation_label = if cfg!(feature = "gcp") {
        "TDX verified (Confidential Space)"
    } else if cfg!(feature = "mock") {
        "Mock (local development)"
    } else {
        "COSE-verified (Nitro)"
    };

    println!("  Attestation:    {}", attestation_label);
    println!("  Encryption:     HPKE-X25519-ChaCha20Poly1305");
    println!("  Channel:        established");

    // Save public key if available
    if let Some(pk_bytes) = client.server_receipt_signing_key() {
        let pubkey_path = format!("{}.pubkey", args.receipt.display());
        fs::write(&pubkey_path, pk_bytes)
            .with_context(|| format!("Failed to write {}", pubkey_path))?;
    }

    // Show input summary
    println!();
    let preview = if text.len() > 120 {
        format!("{}...", &text[..120])
    } else {
        text.clone()
    };
    // Collapse whitespace for display
    let preview_display: String = preview.split_whitespace().collect::<Vec<_>>().join(" ");
    println!("Input ({} bytes):", text.len());
    println!("  \"{}\"", preview_display);

    // Inference
    println!();
    println!("Inference");
    println!("---------");

    let start = Instant::now();
    let result = client
        .execute_inference_text(&args.model, &text)
        .await
        .context("Inference failed")?;
    let elapsed = start.elapsed();

    println!("  Model:          {}", args.model);
    println!("  Time:           {}ms", elapsed.as_millis());
    println!("  Output:         {}-dim embedding", result.output_tensor.len());

    // Show first 5 values
    let first_n: Vec<String> = result
        .output_tensor
        .iter()
        .take(5)
        .map(|v| format!("{:.4}", v))
        .collect();
    println!("  Values[0..5]:   [{}]", first_n.join(", "));

    // L2 norm
    let l2: f64 = result
        .output_tensor
        .iter()
        .map(|v| (*v as f64) * (*v as f64))
        .sum::<f64>()
        .sqrt();
    println!("  L2 norm:        {:.4}", l2);

    // Receipt
    println!();
    println!("Receipt");
    println!("-------");
    println!("  ID:             {}", result.receipt.receipt_id);
    println!(
        "  Platform:       {}",
        result.receipt.enclave_measurements.measurement_type
    );

    // Inline signature verification
    let sig_status = if let Some(pk_bytes) = client.server_receipt_signing_key() {
        match VerifyingKey::from_bytes(&pk_bytes) {
            Ok(vk) => match result.receipt.verify_signature(&vk) {
                Ok(true) => "VERIFIED (Ed25519)",
                Ok(false) => "INVALID",
                Err(_) => "ERROR",
            },
            Err(_) => "KEY ERROR",
        }
    } else {
        "NO KEY (cannot verify)"
    };
    println!("  Signature:      {}", sig_status);

    // Save receipt as JSON
    let receipt_json = serde_json::to_string_pretty(&result.receipt)
        .context("Failed to serialize receipt")?;
    fs::write(&args.receipt, &receipt_json)
        .with_context(|| format!("Failed to write {}", args.receipt.display()))?;
    println!("  Saved to:       {}", args.receipt.display());

    println!();
    Ok(())
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    // Load receipt
    let receipt_bytes = fs::read(&args.receipt).context("Failed to read receipt file")?;
    let receipt: AttestationReceipt = serde_cbor::from_slice(&receipt_bytes)
        .or_else(|_| serde_json::from_slice(&receipt_bytes))
        .context("Failed to parse receipt (tried CBOR and JSON)")?;

    // Resolve public key
    let public_key = resolve_public_key(&args)?;

    // Run checks
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Signature
    let sig_ok = match receipt.verify_signature(&public_key) {
        Ok(true) => true,
        Ok(false) => {
            errors.push("Ed25519 signature verification failed".to_string());
            false
        }
        Err(e) => {
            errors.push(format!("Signature error: {}", e));
            false
        }
    };

    // Timestamp freshness
    let ts_ok = if args.max_age == 0 {
        true
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age = now.saturating_sub(receipt.execution_timestamp);
        if age <= args.max_age {
            true
        } else {
            warnings.push(format!(
                "Receipt is {}s old (max allowed: {}s)",
                age, args.max_age
            ));
            false
        }
    };

    // Measurements
    let meas_ok = receipt.enclave_measurements.is_valid();
    if !meas_ok {
        warnings.push("Measurements are not 48 bytes (expected SHA-384)".to_string());
    }

    let verified = sig_ok && errors.is_empty();

    // Output
    let w = 62;
    let bar = "=".repeat(w);
    let thin = "-".repeat(w);

    println!();
    println!("  {}", bar);
    println!("  EphemeralML Receipt Verification");
    println!("  {}", bar);
    println!();
    println!("  Receipt:   {}", receipt.receipt_id);
    println!(
        "  Model:     {} v{}",
        receipt.model_id, receipt.model_version
    );
    println!(
        "  Platform:  {}",
        receipt.enclave_measurements.measurement_type
    );
    println!("  Sequence:  #{}", receipt.sequence_number);
    println!();
    println!("  {}", thin);
    println!("  Checks:");
    println!("  {}", thin);
    println!(
        "  Signature (Ed25519)       [{}]",
        if sig_ok { "PASS" } else { "FAIL" }
    );
    println!(
        "  Timestamp freshness       [{}]",
        if args.max_age == 0 {
            "SKIP"
        } else if ts_ok {
            "PASS"
        } else {
            "FAIL"
        }
    );
    println!(
        "  Measurements present      [{}]",
        if meas_ok { "PASS" } else { "FAIL" }
    );
    println!("  {}", thin);

    if verified {
        println!();
        println!("  VERIFIED");
        println!();
    } else {
        println!();
        println!("  INVALID");
        println!();
    }

    if !errors.is_empty() {
        println!("  Errors:");
        for err in &errors {
            println!("    - {}", err);
        }
        println!();
    }

    if !warnings.is_empty() {
        println!("  Warnings:");
        for warn in &warnings {
            println!("    - {}", warn);
        }
        println!();
    }

    println!("  {}", bar);

    if verified {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}

fn resolve_public_key(args: &VerifyArgs) -> Result<VerifyingKey> {
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
    } else {
        bail!("Must provide one of: --public-key or --public-key-file");
    }
}
