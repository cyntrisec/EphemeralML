//! EphemeralML Pipeline Orchestrator
//!
//! Connects to multiple stage workers, sends input through the pipeline,
//! collects output and receipt tensors, and produces a PipelineProofBundle.
//!
//! Usage:
//!   ephemeralml-orchestrator --manifest manifests/minilm-2stage.json --text "Hello world"

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use clap::Parser;
use confidential_ml_pipeline::tcp;
use confidential_ml_pipeline::{OrchestratorConfig, ShardManifest};
use confidential_ml_transport::{DType, MockProvider, MockVerifier, OwnedTensor};
use ephemeral_ml_common::AttestationReceipt;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ephemeralml-orchestrator",
    about = "EphemeralML Pipeline Orchestrator"
)]
struct Args {
    /// Path to the pipeline manifest JSON
    #[arg(long)]
    manifest: PathBuf,

    /// Input text to send through the pipeline
    #[arg(long)]
    text: String,

    /// Output path for the pipeline proof bundle
    #[arg(long, default_value = "pipeline-proof-bundle.json")]
    output: PathBuf,

    /// Sequence length for the pipeline
    #[arg(long, default_value = "16")]
    seq_len: u32,
}

/// Pipeline proof bundle containing chained stage receipts.
#[derive(Serialize, Deserialize, Debug)]
struct PipelineProofBundle {
    pipeline_id: String,
    model_name: String,
    num_stages: usize,
    stage_receipts: Vec<StageReceiptEntry>,
    chain_valid: bool,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct StageReceiptEntry {
    stage_index: usize,
    receipt: AttestationReceipt,
    receipt_cbor_hash: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // 1. Load manifest
    let manifest_bytes = fs::read(&args.manifest)
        .with_context(|| format!("Failed to read manifest: {}", args.manifest.display()))?;
    let manifest: ShardManifest =
        serde_json::from_slice(&manifest_bytes).context("Failed to parse manifest JSON")?;

    let num_stages = manifest.stages.len();
    println!("EphemeralML Pipeline Orchestrator");
    println!("=================================");
    println!("  Model:  {}", manifest.model_name);
    println!("  Stages: {}", num_stages);
    println!();

    // 2. Bind orchestrator's data_out listener (receives final stage output)
    let localhost: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let orch_dout_lis = tokio::net::TcpListener::bind(localhost).await?;
    let orch_dout_addr = orch_dout_lis.local_addr()?;
    println!("  Orchestrator data_out: {}", orch_dout_addr);

    // 3. Initialize orchestrator (connects to all stages)
    let verifier = MockVerifier::new();
    let provider = MockProvider::new();

    println!("  Connecting to stages...");
    let mut orch = tcp::init_orchestrator_tcp(
        OrchestratorConfig::default(),
        manifest.clone(),
        orch_dout_lis,
        &verifier,
        &provider,
    )
    .await
    .context("Failed to initialize orchestrator")?;

    // 4. Health check
    orch.health_check().await.context("Health check failed")?;
    println!("  Health check: PASS");

    // 5. Encode input text as tensor
    let input_bytes = args.text.as_bytes().to_vec();
    let input_tensor = OwnedTensor {
        name: "input".to_string(),
        dtype: DType::U8,
        shape: vec![input_bytes.len() as u32],
        data: Bytes::from(input_bytes),
    };

    println!();
    println!("Running inference...");
    println!(
        "  Input: \"{}\"",
        if args.text.len() > 80 {
            &args.text[..80]
        } else {
            &args.text
        }
    );

    let start = std::time::Instant::now();
    let result = orch
        .infer(vec![vec![input_tensor]], args.seq_len)
        .await
        .context("Pipeline inference failed")?;
    let elapsed = start.elapsed();

    println!("  Time: {}ms", elapsed.as_millis());

    // 6. Extract receipts from output tensors
    let tensors = &result.outputs[0];
    let mut stage_receipts: Vec<StageReceiptEntry> = Vec::new();

    for tensor in tensors {
        if tensor.name.starts_with("__receipt__") {
            // Try to parse as CBOR first (canonical), then JSON (legacy)
            let receipt: AttestationReceipt =
                ephemeral_ml_common::cbor::from_slice(&tensor.data)
                    .or_else(|_| {
                        serde_json::from_slice(&tensor.data)
                            .map_err(|e| ephemeral_ml_common::cbor::CborError(e.to_string()))
                    })
                .with_context(|| {
                    format!("Failed to parse receipt from tensor '{}'", tensor.name)
                })?;

            let cbor_hash = {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(&tensor.data))
            };

            // Determine stage index from tensor name
            let stage_idx = if tensor.name == "__receipt__" {
                // Last stage (unnamed = current stage)
                stage_receipts.len()
            } else if let Some(suffix) = tensor.name.strip_prefix("__receipt__stage") {
                suffix.parse::<usize>().unwrap_or(stage_receipts.len())
            } else {
                stage_receipts.len()
            };

            stage_receipts.push(StageReceiptEntry {
                stage_index: stage_idx,
                receipt,
                receipt_cbor_hash: cbor_hash,
            });
        }
    }

    // Sort by stage index
    stage_receipts.sort_by_key(|e| e.stage_index);

    // 7. Verify receipt chain
    let mut chain_valid = true;
    for i in 1..stage_receipts.len() {
        if let Some(prev_hash) = &stage_receipts[i].receipt.previous_receipt_hash {
            let expected = &stage_receipts[i - 1].receipt_cbor_hash;
            let actual = hex::encode(prev_hash);
            if actual != *expected {
                eprintln!(
                    "  Chain BREAK at stage {}: expected {}, got {}",
                    i,
                    &expected[..16],
                    &actual[..16]
                );
                chain_valid = false;
            }
        } else if i > 0 {
            // Stage > 0 should have a previous_receipt_hash
            eprintln!("  Chain MISSING at stage {}: no previous_receipt_hash", i);
            chain_valid = false;
        }
    }

    // 8. Build proof bundle
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let pipeline_id = format!(
        "pipeline-{}-{}",
        manifest.model_name,
        &hex::encode(now.to_be_bytes())[..8]
    );

    let bundle = PipelineProofBundle {
        pipeline_id: pipeline_id.clone(),
        model_name: manifest.model_name.clone(),
        num_stages,
        stage_receipts,
        chain_valid,
        timestamp: now,
    };

    // 9. Save and print summary
    let bundle_json = serde_json::to_string_pretty(&bundle)?;
    fs::write(&args.output, &bundle_json)?;

    println!();
    println!("Pipeline Proof Bundle");
    println!("---------------------");
    println!("  ID:         {}", bundle.pipeline_id);
    println!("  Model:      {}", bundle.model_name);
    println!("  Stages:     {}", bundle.num_stages);
    println!("  Receipts:   {}", bundle.stage_receipts.len());
    println!(
        "  Chain:      {}",
        if bundle.chain_valid {
            "VALID"
        } else {
            "BROKEN"
        }
    );
    println!("  Saved to:   {}", args.output.display());
    println!();

    // 10. Print per-stage summary
    for entry in &bundle.stage_receipts {
        println!(
            "  Stage {}: model={}, seq={}, hash={}...",
            entry.stage_index,
            entry.receipt.model_id,
            entry.receipt.sequence_number,
            &entry.receipt_cbor_hash[..16]
        );
    }

    // 11. Shutdown
    orch.shutdown().await.context("Shutdown failed")?;

    if !bundle.chain_valid {
        bail!("Receipt chain validation failed");
    }

    Ok(())
}
