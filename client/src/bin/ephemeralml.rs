//! Polished demo CLI for EphemeralML confidential inference.
//!
//! Usage:
//!   ephemeralml infer --addr 34.63.158.243:9000 --text "Patient presents with..."
//!   ephemeralml infer --addr 127.0.0.1:9000 --file client/demo/radiology-report.txt
//!   ephemeralml verify receipt.json --public-key <hex>
//!   ephemeralml verify receipt.json --public-key-file receipt.json.pubkey
//!   ephemeralml verify-pipeline pipeline-proof-bundle.json

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
    /// Verify a pipeline proof bundle (chained stage receipts)
    VerifyPipeline(VerifyPipelineArgs),
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

    /// Use text generation mode (autoregressive) instead of embeddings
    #[arg(long, default_value = "false")]
    generate: bool,

    /// Maximum number of tokens to generate (only used with --generate)
    #[arg(long, default_value = "256")]
    max_tokens: usize,
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

#[derive(Parser)]
struct VerifyPipelineArgs {
    /// Path to the pipeline proof bundle JSON
    bundle: PathBuf,

    /// Maximum receipt age in seconds (0 to skip)
    #[arg(long, default_value = "3600")]
    max_age: u64,
}

/// Pipeline proof bundle (matches orchestrator output).
#[derive(serde::Deserialize)]
struct PipelineProofBundle {
    pipeline_id: String,
    model_name: String,
    num_stages: usize,
    stage_receipts: Vec<StageReceiptEntry>,
    #[allow(dead_code)]
    chain_valid: bool,
    #[allow(dead_code)]
    timestamp: u64,
}

#[derive(serde::Deserialize)]
struct StageReceiptEntry {
    stage_index: usize,
    receipt: AttestationReceipt,
    receipt_cbor_hash: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Infer(args) => run_infer(args).await,
        Commands::Verify(args) => run_verify(args),
        Commands::VerifyPipeline(args) => run_verify_pipeline(args),
    }
}

async fn run_infer(args: InferArgs) -> Result<()> {
    // Resolve input text
    let text = match (&args.text, &args.file) {
        (Some(t), _) => t.clone(),
        (_, Some(path)) => fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?,
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
    if args.generate {
        println!("Text Generation");
        println!("---------------");
    } else {
        println!("Inference");
        println!("---------");
    }

    let start = Instant::now();
    let result = if args.generate {
        client
            .execute_inference_generate(&args.model, &text, args.max_tokens)
            .await
            .context("Text generation failed")?
    } else {
        client
            .execute_inference_text(&args.model, &text)
            .await
            .context("Inference failed")?
    };
    let elapsed = start.elapsed();

    println!("  Model:          {}", args.model);
    println!("  Time:           {}ms", elapsed.as_millis());

    if args.generate {
        println!("  Tokens:         {} generated", result.output_tensor.len());
        println!();
        println!("Generated Text");
        println!("--------------");
        if let Some(ref gen_text) = result.generated_text {
            println!("{}", gen_text);
        } else {
            println!("  (no text returned)");
        }
    } else {
        println!(
            "  Output:         {}-dim embedding",
            result.output_tensor.len()
        );

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
    }

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
    let receipt_json =
        serde_json::to_string_pretty(&result.receipt).context("Failed to serialize receipt")?;
    fs::write(&args.receipt, &receipt_json)
        .with_context(|| format!("Failed to write {}", args.receipt.display()))?;
    println!("  Saved to:       {}", args.receipt.display());

    println!();
    Ok(())
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    // Load receipt
    let receipt_bytes = fs::read(&args.receipt).context("Failed to read receipt file")?;
    let receipt: AttestationReceipt = ephemeral_ml_client::cbor::from_slice(&receipt_bytes)
        .or_else(|_| {
            serde_json::from_slice(&receipt_bytes)
                .map_err(|e| ephemeral_ml_client::cbor::CborError(e.to_string()))
        })
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

    // Attestation hash non-zero
    let att_hash_ok = receipt.attestation_doc_hash != [0u8; 32];

    let verified = sig_ok && errors.is_empty();

    // Compact summary (audience-friendly)
    println!();
    println!("  EphemeralML Receipt Verification");
    println!("  ================================");
    println!();
    println!(
        "  Model:       {} v{}",
        receipt.model_id, receipt.model_version
    );
    println!("  Receipt:     {}", receipt.receipt_id);
    println!(
        "  Platform:    {}",
        receipt.enclave_measurements.measurement_type
    );
    println!("  Sequence:    #{}", receipt.sequence_number);
    println!();

    // Compact PASS/FAIL lines
    let tag = |ok: bool| if ok { "PASS" } else { "FAIL" };
    let skip_or = |skip: bool, ok: bool| {
        if skip {
            "SKIP"
        } else if ok {
            "PASS"
        } else {
            "FAIL"
        }
    };

    println!(
        "  Signature         {}  Ed25519 over canonical receipt",
        tag(sig_ok)
    );
    println!(
        "  Attestation hash  {}  {}",
        if att_hash_ok { "PASS" } else { "MOCK" },
        if att_hash_ok {
            format!("{}...", &hex::encode(receipt.attestation_doc_hash)[..16])
        } else {
            "no hardware binding (mock mode)".to_string()
        }
    );
    println!(
        "  Model hash        {}  request={:.8}... response={:.8}...",
        tag(true),
        hex::encode(receipt.request_hash),
        hex::encode(receipt.response_hash)
    );
    println!(
        "  Freshness         {}  {}",
        skip_or(args.max_age == 0, ts_ok),
        if args.max_age == 0 {
            "skipped".to_string()
        } else {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let age = now.saturating_sub(receipt.execution_timestamp);
            format!("{}s old (max {}s)", age, args.max_age)
        }
    );
    println!(
        "  Measurements      {}  {}",
        tag(meas_ok),
        receipt.enclave_measurements.measurement_type
    );
    println!();

    if verified {
        println!("  --> VERIFIED");
    } else {
        println!("  --> INVALID");
    }
    println!();

    if !errors.is_empty() {
        for err in &errors {
            println!("  Error: {}", err);
        }
    }
    if !warnings.is_empty() {
        for warn in &warnings {
            println!("  Warning: {}", warn);
        }
    }

    if verified {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}

fn run_verify_pipeline(args: VerifyPipelineArgs) -> Result<()> {
    let bundle_bytes = fs::read(&args.bundle)
        .with_context(|| format!("Failed to read {}", args.bundle.display()))?;
    let bundle: PipelineProofBundle = serde_json::from_slice(&bundle_bytes)
        .context("Failed to parse pipeline proof bundle JSON")?;

    println!();
    println!("  EphemeralML Pipeline Verification");
    println!("  =================================");
    println!();
    println!("  Pipeline:  {}", bundle.pipeline_id);
    println!("  Model:     {}", bundle.model_name);
    println!("  Stages:    {}", bundle.num_stages);
    println!();

    let tag = |ok: bool| if ok { "PASS" } else { "FAIL" };

    // Per-stage compact checks
    let mut all_sigs_ok = true;

    for entry in &bundle.stage_receipts {
        let sig_ok = entry.receipt.signature.is_some();
        if !sig_ok {
            all_sigs_ok = false;
        }

        println!(
            "  Stage {} | {} v{:<6} | sig {} | hash {}...",
            entry.stage_index,
            entry.receipt.model_id,
            entry.receipt.model_version,
            tag(sig_ok),
            &entry.receipt_cbor_hash[..16]
        );
    }

    println!();

    // Chain integrity
    let mut chain_ok = true;

    if bundle.stage_receipts.is_empty() {
        println!("  Chain       FAIL  no receipts");
        chain_ok = false;
    } else {
        let first = &bundle.stage_receipts[0];
        if first.receipt.previous_receipt_hash.is_some() {
            println!("  Chain[0]    FAIL  root should have no predecessor");
            chain_ok = false;
        } else {
            println!("  Chain[0]    PASS  root (no predecessor)");
        }

        for i in 1..bundle.stage_receipts.len() {
            let curr = &bundle.stage_receipts[i];
            let prev = &bundle.stage_receipts[i - 1];

            match &curr.receipt.previous_receipt_hash {
                Some(hash) => {
                    let actual = hex::encode(hash);
                    if actual == prev.receipt_cbor_hash {
                        println!("  Chain[{}]    PASS  links to stage {}", i, i - 1);
                    } else {
                        println!(
                            "  Chain[{}]    FAIL  expected {}..., got {}...",
                            i,
                            &prev.receipt_cbor_hash[..12],
                            &actual[..12]
                        );
                        chain_ok = false;
                    }
                }
                None => {
                    println!("  Chain[{}]    FAIL  missing previous_receipt_hash", i);
                    chain_ok = false;
                }
            }
        }
    }

    let overall = all_sigs_ok && chain_ok;

    println!();
    if overall {
        println!(
            "  --> PIPELINE VERIFIED ({} stages, chain intact)",
            bundle.num_stages
        );
    } else {
        println!("  --> PIPELINE INVALID");
        if !all_sigs_ok {
            println!("      - One or more stage signatures missing");
        }
        if !chain_ok {
            println!("      - Receipt chain integrity check failed");
        }
    }
    println!();

    if overall {
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
