//! Polished demo CLI for EphemeralML confidential inference.
//!
//! Usage:
//!   ephemeralml infer --addr 34.63.158.243:9000 --text "Patient presents with..."
//!   ephemeralml infer --addr 127.0.0.1:9000 --file client/demo/radiology-report.txt
//!   ephemeralml verify-pipeline pipeline-proof-bundle.json --public-key <hex>
//!   ephemeralml-verify receipt.json --public-key-file receipt.pubkey

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use ephemeral_ml_client::{AttestationReceipt, SecureClient, SecureEnclaveClient};
use ephemeral_ml_common::receipt_verify::CheckStatus;
use ephemeral_ml_common::ui::{GhostState, Ui, UiConfig};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "ephemeralml",
    about = "EphemeralML Confidential Inference CLI",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Disable colors and mascot (plain text output)
    #[arg(long, global = true)]
    plain: bool,

    /// Disable color output
    #[arg(long, global = true)]
    no_color: bool,

    /// Disable ghost mascot
    #[arg(long, global = true)]
    no_mascot: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run confidential inference against an EphemeralML server
    Infer(InferArgs),
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
struct VerifyPipelineArgs {
    /// Path to the pipeline proof bundle JSON
    bundle: PathBuf,

    /// Ed25519 public key as hex string (64 hex chars = 32 bytes).
    /// Repeat per stage, or provide once to use the same key for all stages.
    #[arg(
        long = "public-key",
        value_name = "HEX",
        num_args = 1..,
        required_unless_present = "public_key_file",
        conflicts_with = "public_key_file"
    )]
    public_key: Vec<String>,

    /// Path to file containing Ed25519 public key (32 raw bytes or 64-hex text).
    /// Repeat per stage, or provide once to use the same key for all stages.
    #[arg(
        long = "public-key-file",
        value_name = "PATH",
        num_args = 1..,
        required_unless_present = "public_key",
        conflicts_with = "public_key"
    )]
    public_key_file: Vec<PathBuf>,

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
    let ui_config = UiConfig::resolve(
        std::io::stdout().is_terminal(),
        cli.plain,
        cli.no_color,
        cli.no_mascot,
        false,
    );
    let mut ui = Ui::stdout(ui_config);
    match cli.command {
        Commands::Infer(args) => run_infer(&mut ui, args).await,
        Commands::VerifyPipeline(args) => run_verify_pipeline(&mut ui, args),
    }
}

async fn run_infer(ui: &mut Ui, args: InferArgs) -> Result<()> {
    ui.ghost(GhostState::Idle);

    // Resolve input text
    let text = match (&args.text, &args.file) {
        (Some(t), _) => t.clone(),
        (_, Some(path)) => fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?,
        _ => bail!("Provide either --text or --file"),
    };

    ui.blank();
    ui.header("EphemeralML Confidential Inference");
    ui.blank();

    // Connect
    ui.info(&format!("Connecting to {}...", args.addr));
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

    ui.kv("Attestation", attestation_label);
    ui.kv("Encryption", "HPKE-X25519-ChaCha20Poly1305");
    ui.kv("Channel", "established");

    // Save public key if available
    if let Some(pk_bytes) = client.server_receipt_signing_key() {
        let pubkey_path = format!("{}.pubkey", args.receipt.display());
        fs::write(&pubkey_path, pk_bytes)
            .with_context(|| format!("Failed to write {}", pubkey_path))?;
    }

    // Show input summary
    ui.blank();
    let preview = if text.len() > 120 {
        format!("{}...", &text[..120])
    } else {
        text.clone()
    };
    let preview_display: String = preview.split_whitespace().collect::<Vec<_>>().join(" ");
    ui.info(&format!("Input ({} bytes):", text.len()));
    ui.info(&format!("  \"{}\"", preview_display));

    // Inference
    ui.blank();
    if args.generate {
        ui.section("Text Generation");
    } else {
        ui.section("Inference");
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

    ui.kv("Model", &args.model);
    ui.kv("Time", &format!("{}ms", elapsed.as_millis()));

    if args.generate {
        ui.kv(
            "Tokens",
            &format!("{} generated", result.output_tensor.len()),
        );
        ui.blank();
        ui.section("Generated Text");
        if let Some(ref gen_text) = result.generated_text {
            ui.info(gen_text);
        } else {
            ui.info("(no text returned)");
        }
    } else {
        ui.kv(
            "Output",
            &format!("{}-dim embedding", result.output_tensor.len()),
        );

        let first_n: Vec<String> = result
            .output_tensor
            .iter()
            .take(5)
            .map(|v| format!("{:.4}", v))
            .collect();
        ui.kv("Values[0..5]", &format!("[{}]", first_n.join(", ")));

        let l2: f64 = result
            .output_tensor
            .iter()
            .map(|v| (*v as f64) * (*v as f64))
            .sum::<f64>()
            .sqrt();
        ui.kv("L2 norm", &format!("{:.4}", l2));
    }

    // Receipt
    ui.blank();
    ui.section("Receipt");
    ui.kv("ID", &result.receipt.receipt_id);
    ui.kv(
        "Platform",
        &result.receipt.enclave_measurements.measurement_type,
    );

    // Inline signature verification
    let sig_status = if let Some(pk_bytes) = client.server_receipt_signing_key() {
        match VerifyingKey::from_bytes(&pk_bytes) {
            Ok(vk) => match result.receipt.verify_signature(&vk) {
                Ok(true) => CheckStatus::Pass,
                Ok(false) => CheckStatus::Fail,
                Err(_) => CheckStatus::Fail,
            },
            Err(_) => CheckStatus::Fail,
        }
    } else {
        CheckStatus::Skip
    };
    ui.check("Signature (Ed25519)", &sig_status);

    // Save receipt as JSON
    let receipt_json =
        serde_json::to_string_pretty(&result.receipt).context("Failed to serialize receipt")?;
    fs::write(&args.receipt, &receipt_json)
        .with_context(|| format!("Failed to write {}", args.receipt.display()))?;
    ui.kv("Saved to", &args.receipt.display().to_string());

    // Save sidecar evidence files alongside receipt
    if let Some(ref att_b64) = result.boot_attestation_b64 {
        use base64::Engine as _;
        if let Ok(att_bytes) = base64::engine::general_purpose::STANDARD.decode(att_b64) {
            let att_path = "/tmp/ephemeralml-attestation.bin";
            fs::write(att_path, &att_bytes)
                .with_context(|| format!("Failed to write {}", att_path))?;
            ui.kv("Attestation", att_path);
        }
    }
    if let Some(ref manifest_json) = result.model_manifest_json {
        let manifest_path = "/tmp/ephemeralml-manifest.json";
        fs::write(manifest_path, manifest_json)
            .with_context(|| format!("Failed to write {}", manifest_path))?;
        ui.kv("Manifest", manifest_path);
    }

    ui.blank();
    ui.ghost(GhostState::Success);
    Ok(())
}

fn run_verify_pipeline(ui: &mut Ui, args: VerifyPipelineArgs) -> Result<()> {
    ui.ghost(GhostState::Idle);

    let bundle_bytes = fs::read(&args.bundle)
        .with_context(|| format!("Failed to read {}", args.bundle.display()))?;
    let bundle: PipelineProofBundle = serde_json::from_slice(&bundle_bytes)
        .context("Failed to parse pipeline proof bundle JSON")?;

    ui.blank();
    ui.header("EphemeralML Pipeline Verification");
    ui.blank();
    ui.kv("Pipeline", &bundle.pipeline_id);
    ui.kv("Model", &bundle.model_name);
    ui.kv("Stages", &bundle.num_stages.to_string());
    ui.blank();

    if bundle.stage_receipts.is_empty() {
        ui.failure("--> PIPELINE INVALID");
        ui.bullet("No receipts in bundle");
        ui.blank();
        std::process::exit(1);
    }

    let mut entries: Vec<&StageReceiptEntry> = bundle.stage_receipts.iter().collect();
    entries.sort_by_key(|e| e.stage_index);

    let mut stage_index_ok = true;
    for (expected, entry) in entries.iter().enumerate() {
        if entry.stage_index != expected {
            stage_index_ok = false;
            ui.stage_line(&format!(
                "Stage index FAIL  expected contiguous index {}, got {}",
                expected, entry.stage_index
            ));
        }
    }

    let count_ok = entries.len() == bundle.num_stages;
    if !count_ok {
        ui.stage_line(&format!(
            "Stage count FAIL  bundle says {} stages, found {} receipts",
            bundle.num_stages,
            entries.len()
        ));
    }

    let public_keys = resolve_pipeline_public_keys(&args, entries.len())?;

    let tag = |ok: bool| if ok { "PASS" } else { "FAIL" };
    let mut all_sigs_ok = true;
    let mut all_hashes_ok = true;
    let mut all_fresh_ok = true;
    let mut computed_hashes: Vec<[u8; 32]> = Vec::with_capacity(entries.len());

    for (i, entry) in entries.iter().enumerate() {
        let receipt_cbor = ephemeral_ml_common::cbor::to_vec(&entry.receipt)
            .with_context(|| format!("Failed to CBOR-encode receipt for stage {}", i))?;
        let computed_hash: [u8; 32] = Sha256::digest(&receipt_cbor).into();
        computed_hashes.push(computed_hash);
        let computed_hash_hex = hex::encode(computed_hash);
        let hash_ok = computed_hash_hex.eq_ignore_ascii_case(&entry.receipt_cbor_hash);
        if !hash_ok {
            all_hashes_ok = false;
        }

        let sig_ok = entry
            .receipt
            .verify_signature(&public_keys[i])
            .unwrap_or(false);
        if !sig_ok {
            all_sigs_ok = false;
        }

        let fresh_ok = if args.max_age == 0 {
            true
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if entry.receipt.execution_timestamp > now {
                false
            } else {
                let age = now - entry.receipt.execution_timestamp;
                age <= args.max_age
            }
        };
        if !fresh_ok {
            all_fresh_ok = false;
        }

        let hash_prefix_len = std::cmp::min(16, computed_hash_hex.len());
        ui.stage_line(&format!(
            "Stage {} | {} v{:<6} | sig {} | hash {} | fresh {} | cbor {}...",
            entry.stage_index,
            entry.receipt.model_id,
            entry.receipt.model_version,
            tag(sig_ok),
            tag(hash_ok),
            if args.max_age == 0 {
                "SKIP"
            } else {
                tag(fresh_ok)
            },
            &computed_hash_hex[..hash_prefix_len],
        ));
    }

    ui.blank();

    let mut chain_ok = true;
    let first = entries[0];
    if first.receipt.previous_receipt_hash.is_some() {
        ui.chain_status("Chain[0]", false, "root should have no predecessor");
        chain_ok = false;
    } else {
        ui.chain_status("Chain[0]", true, "root (no predecessor)");
    }

    for i in 1..entries.len() {
        let curr = entries[i];
        let label = format!("Chain[{}]", i);
        match curr.receipt.previous_receipt_hash {
            Some(hash) => {
                if hash == computed_hashes[i - 1] {
                    ui.chain_status(&label, true, &format!("links to stage {}", i - 1));
                } else {
                    ui.chain_status(
                        &label,
                        false,
                        &format!("previous hash mismatch against stage {}", i - 1),
                    );
                    chain_ok = false;
                }
            }
            None => {
                ui.chain_status(&label, false, "missing previous_receipt_hash");
                chain_ok = false;
            }
        }
    }

    let overall =
        stage_index_ok && count_ok && chain_ok && all_sigs_ok && all_hashes_ok && all_fresh_ok;

    ui.verdict(
        overall,
        &format!("{} stages, signatures + hash chain intact", entries.len()),
    );

    if !overall {
        if !stage_index_ok {
            ui.bullet("Stage indices are not contiguous from 0");
        }
        if !count_ok {
            ui.bullet("Receipt count does not match declared num_stages");
        }
        if !all_sigs_ok {
            ui.bullet("One or more receipt signatures are invalid");
        }
        if !all_hashes_ok {
            ui.bullet("One or more claimed receipt hashes do not match recomputed CBOR hashes");
        }
        if !chain_ok {
            ui.bullet("Receipt chain integrity check failed");
        }
        if !all_fresh_ok {
            ui.bullet("One or more receipts are stale/future relative to --max-age");
        }
    }
    ui.blank();

    if overall {
        ui.ghost(GhostState::Success);
        std::process::exit(0);
    } else {
        ui.ghost(GhostState::Fail);
        std::process::exit(1);
    }
}

fn resolve_pipeline_public_keys(
    args: &VerifyPipelineArgs,
    stage_count: usize,
) -> Result<Vec<VerifyingKey>> {
    let mut keys: Vec<VerifyingKey> = if !args.public_key.is_empty() {
        args.public_key
            .iter()
            .map(|k| parse_public_key_hex(k))
            .collect::<Result<Vec<_>>>()?
    } else {
        args.public_key_file
            .iter()
            .map(|p| parse_public_key_file(p))
            .collect::<Result<Vec<_>>>()?
    };

    if keys.len() == 1 && stage_count > 1 {
        let key = keys[0];
        keys = (0..stage_count).map(|_| key).collect();
    }

    if keys.len() != stage_count {
        bail!(
            "Expected either one key for all stages, or one key per stage ({}). Got {}",
            stage_count,
            keys.len()
        );
    }

    Ok(keys)
}

fn parse_public_key_hex(hex_key: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_key.trim()).context("Invalid hex in --public-key")?;
    if bytes.len() != 32 {
        bail!(
            "--public-key must be 64 hex chars (32 bytes), got {} bytes",
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).context("Invalid Ed25519 public key")
}

fn parse_public_key_file(path: &Path) -> Result<VerifyingKey> {
    let bytes = fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;

    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return VerifyingKey::from_bytes(&arr).context("Invalid Ed25519 public key");
    }

    if let Ok(text) = std::str::from_utf8(&bytes) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return parse_public_key_hex(trimmed)
                .with_context(|| format!("Invalid hex public key in {}", path.display()));
        }
    }

    bail!(
        "{} must contain either 32 raw bytes or 64-char hex key text",
        path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey_hex() -> String {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        hex::encode(sk.verifying_key().to_bytes())
    }

    fn temp_path(suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ephemeralml_cli_test_{}_{}_{}",
            std::process::id(),
            nanos,
            suffix
        ))
    }

    #[test]
    fn parse_public_key_hex_accepts_valid_key() {
        let hex = test_pubkey_hex();
        let vk = parse_public_key_hex(&hex).expect("valid hex key should parse");
        assert_eq!(hex::encode(vk.to_bytes()), hex);
    }

    #[test]
    fn parse_public_key_hex_rejects_wrong_length() {
        let err = parse_public_key_hex("abcd").unwrap_err();
        assert!(format!("{err}").contains("64 hex chars"));
    }

    #[test]
    fn parse_public_key_file_accepts_hex_text() {
        let path = temp_path("hex.pub");
        fs::write(&path, format!("{}\n", test_pubkey_hex())).expect("write temp pubkey file");
        let vk = parse_public_key_file(&path).expect("hex pubkey file should parse");
        fs::remove_file(&path).ok();
        assert_eq!(hex::encode(vk.to_bytes()), test_pubkey_hex());
    }

    #[test]
    fn parse_public_key_file_accepts_raw_32_bytes() {
        let path = temp_path("raw.pub");
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let expected = sk.verifying_key().to_bytes();
        fs::write(&path, expected).expect("write raw pubkey file");
        let vk = parse_public_key_file(&path).expect("raw pubkey file should parse");
        fs::remove_file(&path).ok();
        assert_eq!(vk.to_bytes(), expected);
    }

    #[test]
    fn resolve_pipeline_public_keys_fans_out_single_key() {
        let args = VerifyPipelineArgs {
            bundle: PathBuf::from("bundle.json"),
            public_key: vec![test_pubkey_hex()],
            public_key_file: vec![],
            max_age: 3600,
        };

        let keys = resolve_pipeline_public_keys(&args, 3).expect("single key should fan out");
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].to_bytes(), keys[1].to_bytes());
        assert_eq!(keys[1].to_bytes(), keys[2].to_bytes());
    }
}
