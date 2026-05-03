#[cfg(feature = "mock")]
use ephemeral_ml_host::mock::MockKmsProxyServer;

use confidential_ml_pipeline::{
    ActivationDType, ActivationSpec, OrchestratorConfig, PortSpec, ShardManifest, StageEndpoint,
    StageSpec,
};
use confidential_ml_transport::{DType, OwnedTensor};
#[cfg(feature = "mock")]
use confidential_ml_transport::{MockProvider, MockVerifier};
use ephemeral_ml_common::AttestationReceipt;
use std::collections::BTreeMap;

#[cfg(feature = "mock")]
use confidential_ml_pipeline::tcp::init_orchestrator_tcp;

#[cfg(feature = "production")]
use clap::Parser;
#[cfg(feature = "production")]
use confidential_ml_pipeline::vsock::init_orchestrator_vsock;
#[cfg(feature = "production")]
use confidential_ml_transport::{
    ExpectedMeasurements, MockProvider as HostMockProvider, NitroVerifier,
};
#[cfg(feature = "production")]
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
#[cfg(feature = "production")]
use tracing::{error, info, warn};

/// Save receipt JSON to disk. Returns Ok(()) if path is None (no-op).
fn save_receipt(receipt: &AttestationReceipt, path: Option<&str>) -> Result<(), std::io::Error> {
    let Some(path) = path else { return Ok(()) };
    let json = serde_json::to_string_pretty(receipt)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, &json)?;
    println!("  Receipt saved to {}", path);
    Ok(())
}

/// Save raw receipt tensor bytes (wire format) to disk. Returns Ok(()) if path is None.
fn save_receipt_raw(raw_bytes: &[u8], path: Option<&str>) -> Result<(), std::io::Error> {
    let Some(path) = path else { return Ok(()) };
    std::fs::write(path, raw_bytes)?;
    println!(
        "  Raw receipt ({} bytes) saved to {}",
        raw_bytes.len(),
        path
    );
    Ok(())
}

/// Save raw boot attestation bytes to disk. Returns Ok(()) if path is None.
#[cfg(any(feature = "production", test))]
fn save_attestation_raw(
    attestation_bytes: &[u8],
    path: Option<&str>,
) -> Result<(), std::io::Error> {
    let Some(path) = path else { return Ok(()) };
    std::fs::write(path, attestation_bytes)?;
    println!(
        "  Attestation document ({} bytes) saved to {}",
        attestation_bytes.len(),
        path
    );
    Ok(())
}

/// Save raw KMS release evidence JSON to disk. Returns Ok(()) if path is None.
#[cfg(any(feature = "production", test))]
fn save_kms_release_raw(
    kms_release_bytes: &[u8],
    path: Option<&str>,
) -> Result<(), std::io::Error> {
    let Some(path) = path else { return Ok(()) };
    std::fs::write(path, kms_release_bytes)?;
    println!(
        "  KMS release evidence ({} bytes) saved to {}",
        kms_release_bytes.len(),
        path
    );
    Ok(())
}

fn print_receipt(receipt: &AttestationReceipt) {
    println!();
    println!("========================================================");
    println!("       ATTESTED EXECUTION RECEIPT");
    println!("========================================================");
    println!();
    println!("  Receipt ID:      {}", receipt.receipt_id);
    println!(
        "  Model:           {} v{}",
        receipt.model_id, receipt.model_version
    );
    println!("  Sequence:        #{}", receipt.sequence_number);
    println!("  Security Mode:   {:?}", receipt.security_mode);
    println!("  Protocol:        v{}", receipt.protocol_version);
    println!("  Policy:          {}", receipt.policy_version);
    println!();
    println!("  --- Cryptographic Bindings ---");
    println!("  Request hash:    {}", hex::encode(receipt.request_hash));
    println!("  Response hash:   {}", hex::encode(receipt.response_hash));
    println!(
        "  Attestation hash:{}",
        hex::encode(receipt.attestation_doc_hash)
    );
    println!();
    println!("  --- Enclave Measurements ---");
    println!(
        "  PCR0 (image):    {}...",
        hex::encode(
            &receipt.enclave_measurements.pcr0
                [..std::cmp::min(16, receipt.enclave_measurements.pcr0.len())]
        )
    );
    println!(
        "  PCR1 (kernel):   {}...",
        hex::encode(
            &receipt.enclave_measurements.pcr1
                [..std::cmp::min(16, receipt.enclave_measurements.pcr1.len())]
        )
    );
    println!(
        "  PCR2 (app):      {}...",
        hex::encode(
            &receipt.enclave_measurements.pcr2
                [..std::cmp::min(16, receipt.enclave_measurements.pcr2.len())]
        )
    );
    println!();
    println!("  --- Signature ---");
    match &receipt.signature {
        Some(sig) => {
            println!("  Algorithm:       Ed25519");
            println!(
                "  Signature:       {}...{}",
                hex::encode(&sig[..8]),
                hex::encode(&sig[sig.len() - 8..])
            );
            println!("  Status:          SIGNED");
        }
        None => {
            println!("  Status:          UNSIGNED");
        }
    }
    println!();
    println!("  --- Execution Metadata ---");
    println!("  Timestamp:       {}", receipt.execution_timestamp);
    println!("  Execution time:  {} ms", receipt.execution_time_ms);
    println!("  Peak memory:     {} MB", receipt.memory_peak_mb);
    println!();
    println!("  Receipt claims parsed from artifact:");
    println!("    - Input/output hashes bind request to response if verified by policy");
    println!("    - Enclave execution requires signature and attestation verification");
    println!("    - Ed25519 signature must be checked before relying on these claims");
    println!("    - Measurements are evidence inputs, not code-integrity proof by parsing alone");
    println!("========================================================");
    println!();
}

fn print_embeddings(data: &[u8], shape: &[u32]) {
    let floats: Vec<f32> = data
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();

    let dims = if shape.is_empty() {
        floats.len()
    } else {
        shape[shape.len() - 1] as usize
    };
    let l2_norm: f32 = floats.iter().map(|x| x * x).sum::<f32>().sqrt();
    let first_n: Vec<String> = floats.iter().take(5).map(|f| format!("{:.4}", f)).collect();

    println!();
    println!("  --- Embedding Output ---");
    println!("  Dimensions:      {}", dims);
    println!("  First 5 values:  [{}]", first_n.join(", "));
    println!("  L2 norm:         {:.4}", l2_norm);
    println!("  Total bytes:     {}", data.len());
    println!();
}

/// CLI arguments for production (Nitro) host orchestrator.
#[cfg(feature = "production")]
#[derive(Parser, Debug)]
#[command(
    name = "ephemeral-ml-host",
    about = "EphemeralML Host Orchestrator (AWS Nitro Production)"
)]
struct ProdArgs {
    /// CID of the Nitro enclave (from `nitro-cli describe-enclaves`)
    #[arg(long, env = "EPHEMERALML_ENCLAVE_CID", default_value = "16")]
    enclave_cid: u32,

    /// Control channel VSock port on the enclave
    #[arg(long, env = "EPHEMERALML_CONTROL_PORT", default_value = "5000")]
    control_port: u32,

    /// Data-in VSock port on the enclave
    #[arg(long, env = "EPHEMERALML_DATA_IN_PORT", default_value = "5001")]
    data_in_port: u32,

    /// Data-out VSock port (orchestrator binds, enclave connects)
    #[arg(long, env = "EPHEMERALML_DATA_OUT_PORT", default_value = "5002")]
    data_out_port: u32,

    /// Input text for inference
    #[arg(
        long,
        default_value = "Confidential AI inference with cryptographic proof"
    )]
    text: String,

    /// Sequence length for the pipeline
    #[arg(long, default_value = "16")]
    seq_len: u32,

    /// Model name for the manifest
    #[arg(long, default_value = "sentence-transformers/all-MiniLM-L6-v2")]
    model_name: String,

    /// Model version
    #[arg(long, default_value = "1.0")]
    model_version: String,

    /// Total layers in the model
    #[arg(long, default_value = "6")]
    total_layers: usize,

    /// Embedding hidden dimension
    #[arg(long, default_value = "384")]
    hidden_dim: u32,

    /// Allow running without PCR pinning (DANGEROUS — disables attestation verification).
    /// Only use for development/debugging, never in production.
    #[arg(long, default_value = "false")]
    allow_unpinned: bool,

    /// Save the attestation receipt to a JSON file at this path.
    #[arg(long, env = "EPHEMERALML_RECEIPT_OUTPUT")]
    receipt_output: Option<String>,

    /// Save the raw __receipt__ tensor bytes (CBOR/JSON wire format) to this path.
    /// Preserves the exact on-wire encoding for canonical verification.
    #[arg(long, env = "EPHEMERALML_RECEIPT_OUTPUT_RAW")]
    receipt_output_raw: Option<String>,

    /// Save the AIR v1 receipt (COSE_Sign1 CBOR bytes) to this path.
    #[arg(long, env = "EPHEMERALML_RECEIPT_OUTPUT_AIR_V1")]
    receipt_output_air_v1: Option<String>,

    /// Save the boot attestation document (COSE_Sign1 CBOR bytes) to this path.
    #[arg(long, env = "EPHEMERALML_ATTESTATION_OUTPUT")]
    attestation_output: Option<String>,

    /// Save the KMS RecipientInfo release evidence JSON to this path.
    #[arg(long, env = "EPHEMERALML_KMS_RELEASE_OUTPUT")]
    kms_release_output: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("EphemeralML Host v2.0");

    #[cfg(feature = "mock")]
    {
        println!("EphemeralML Host (Mock Mode)");

        let mock_receipt_output = std::env::var("EPHEMERALML_RECEIPT_OUTPUT").ok();
        let mock_receipt_output_raw = std::env::var("EPHEMERALML_RECEIPT_OUTPUT_RAW").ok();
        let mock_receipt_output_air_v1 = std::env::var("EPHEMERALML_RECEIPT_OUTPUT_AIR_V1").ok();

        // 1. Start KMS proxy in background
        let kms_handle = tokio::spawn(async move {
            let kms_proxy = MockKmsProxyServer::new(8081);
            if let Err(e) = kms_proxy.start().await {
                eprintln!("KMS proxy error: {}", e);
            }
        });

        // 2. Build single-stage manifest pointing to enclave's ports
        let manifest = ShardManifest {
            model_name: "sentence-transformers/all-MiniLM-L6-v2".into(),
            model_version: "1.0".into(),
            total_layers: 6,
            stages: vec![StageSpec {
                stage_idx: 0,
                layer_start: 0,
                layer_end: 6,
                require_weight_hashes: false,
                weight_hashes: vec![],
                expected_measurements: BTreeMap::new(),
                endpoint: StageEndpoint {
                    control: PortSpec::Tcp {
                        addr: "127.0.0.1:9000".to_string(),
                    },
                    data_in: PortSpec::Tcp {
                        addr: "127.0.0.1:9001".to_string(),
                    },
                    data_out: PortSpec::Tcp {
                        addr: "127.0.0.1:9002".to_string(),
                    },
                },
            }],
            activation_spec: ActivationSpec {
                dtype: ActivationDType::F32,
                hidden_dim: 384,
                max_seq_len: 512,
            },
        };

        // 3. Bind orchestrator's data_out listener (stage connects here)
        let orch_dout_lis = tokio::net::TcpListener::bind("127.0.0.1:9002").await?;
        println!("Orchestrator data_out listener bound on 127.0.0.1:9002");

        // 4. Wait briefly for enclave stage to start, then initialize orchestrator
        println!("Connecting to enclave stage worker...");
        let verifier = MockVerifier::new();
        let provider = MockProvider::new();

        // Mock mode: use Development profile since no TEE attestation is available.
        let mut orch = init_orchestrator_tcp(
            OrchestratorConfig::development(),
            manifest,
            orch_dout_lis,
            &verifier,
            &provider,
        )
        .await?;

        println!("Pipeline initialized successfully!");

        // 5. Health check
        orch.health_check().await?;
        println!("Health check passed.");

        // 6. Run inference
        let input_text =
            b"Confidential AI inference with cryptographic proof of ephemeral execution";
        let input = vec![vec![OwnedTensor {
            name: "input".to_string(),
            dtype: DType::U8,
            shape: vec![input_text.len() as u32],
            data: bytes::Bytes::from_static(input_text),
        }]];

        println!();
        println!("Input: \"{}\"", std::str::from_utf8(input_text).unwrap());
        println!("Running inference...");
        let infer_start = std::time::Instant::now();
        let result = orch.infer(input, 16).await?;
        let infer_elapsed = infer_start.elapsed();

        println!(
            "Inference complete in {:.1}ms: {} micro-batch(es) returned",
            infer_elapsed.as_secs_f64() * 1000.0,
            result.outputs.len()
        );

        // 7. Extract outputs
        for (i, tensors) in result.outputs.iter().enumerate() {
            for t in tensors {
                if t.name == "__receipt__" {
                    // Save raw wire-format bytes before parsing
                    if let Err(e) = save_receipt_raw(&t.data, mock_receipt_output_raw.as_deref()) {
                        eprintln!("Warning: failed to save raw receipt: {}", e);
                    }
                    // Try CBOR first (canonical format), fall back to JSON
                    match ephemeral_ml_common::cbor::from_slice::<AttestationReceipt>(&t.data)
                        .or_else(|_| {
                            serde_json::from_slice::<AttestationReceipt>(&t.data)
                                .map_err(|e| ephemeral_ml_common::cbor::CborError(e.to_string()))
                        }) {
                        Ok(receipt) => {
                            print_receipt(&receipt);
                            if let Err(e) = save_receipt(&receipt, mock_receipt_output.as_deref()) {
                                eprintln!("Warning: failed to save receipt: {}", e);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to parse receipt: {}", e);
                        }
                    }
                } else if t.name == "__receipt_air_v1__" {
                    if let Err(e) = save_receipt_raw(&t.data, mock_receipt_output_air_v1.as_deref())
                    {
                        eprintln!("Warning: failed to save AIR v1 receipt: {}", e);
                    } else if mock_receipt_output_air_v1.is_some() {
                        println!("  AIR v1 receipt ({} bytes) saved", t.data.len());
                    }
                } else {
                    print_embeddings(&t.data, &t.shape);
                    println!(
                        "  Output tensor [batch {}]: name={}, shape={:?}, {} bytes",
                        i,
                        t.name,
                        t.shape,
                        t.data.len()
                    );
                }
            }
        }

        // 8. Shutdown
        orch.shutdown().await?;
        println!("Pipeline shut down gracefully.");

        kms_handle.abort();
    }

    #[cfg(feature = "production")]
    {
        // Initialize structured logging
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .init();

        info!("EphemeralML Host (Production Mode — AWS Nitro)");

        let args = ProdArgs::parse();

        info!(
            enclave_cid = args.enclave_cid,
            control_port = args.control_port,
            data_in_port = args.data_in_port,
            data_out_port = args.data_out_port,
            "Connecting to Nitro enclave via VSock"
        );

        // 1. Build NitroVerifier with expected PCR measurements for enclave verification.
        //    Fail-closed: refuse to proceed without valid PCR pins unless --allow-unpinned.
        let expected_pcrs = ephemeral_ml_host::pcr::load_expected_pcrs_from_env(
            args.allow_unpinned,
        )
        .map_err(|e| {
            error!(error = %e, "PCR validation failed");
            Box::<dyn std::error::Error>::from(e.to_string())
        })?;

        for (i, bytes) in &expected_pcrs {
            info!(
                pcr = i,
                prefix = hex::encode(&bytes[..8]),
                "Pinned enclave PCR"
            );
        }
        if expected_pcrs.is_empty() {
            warn!("--allow-unpinned set: running WITHOUT PCR pinning. DO NOT USE IN PRODUCTION.");
        }

        let expected_stage_measurements = ExpectedMeasurements::new(expected_pcrs.clone());
        let verifier = NitroVerifier::new(expected_pcrs)?;

        // Host is not inside a TEE — use MockProvider for the mutual handshake.
        // The enclave uses MockVerifier for the host side (one-way attestation model:
        // only the enclave is cryptographically attested; host is trusted as same EC2 instance).
        let provider = HostMockProvider::new();

        // 2. Build single-stage VSock manifest.
        //    The enclave binds control/data_in on VSock. The orchestrator binds data_out
        //    on the host side and the enclave connects to it.
        let manifest = ShardManifest {
            model_name: args.model_name.clone(),
            model_version: args.model_version.clone(),
            total_layers: args.total_layers,
            stages: vec![StageSpec {
                stage_idx: 0,
                layer_start: 0,
                layer_end: args.total_layers,
                require_weight_hashes: false,
                weight_hashes: vec![],
                // Keep stage-side measurement expectations empty in the single-stage
                // Nitro host->enclave flow. The host enforces PCR pinning via its
                // own session config; sending the same measurements inside StageSpec
                // would make the enclave try to verify the non-TEE host as if it
                // were another enclave during the data-channel handshake.
                expected_measurements: BTreeMap::new(),
                endpoint: StageEndpoint {
                    control: PortSpec::VSock {
                        cid: args.enclave_cid,
                        port: args.control_port,
                    },
                    data_in: PortSpec::VSock {
                        cid: args.enclave_cid,
                        port: args.data_in_port,
                    },
                    // data_out: orchestrator listens; enclave connects to host CID 3.
                    // The manifest entry is used by the orchestrator to know where to bind.
                    data_out: PortSpec::VSock {
                        cid: VMADDR_CID_ANY,
                        port: args.data_out_port,
                    },
                },
            }],
            activation_spec: ActivationSpec {
                dtype: ActivationDType::F32,
                hidden_dim: args.hidden_dim,
                max_seq_len: 512,
            },
        };

        // 3. Bind orchestrator's data_out VSock listener.
        //    The enclave stage will connect to this after the control phase.
        let data_out_listener =
            VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, args.data_out_port)).map_err(
                |e| {
                    format!(
                        "Failed to bind VSock data_out listener on port {}: {}",
                        args.data_out_port, e
                    )
                },
            )?;
        info!(
            port = args.data_out_port,
            "Orchestrator data_out VSock listener bound"
        );

        // 4. Initialize orchestrator — connects to enclave stage via VSock.
        info!("Connecting to enclave stage worker...");
        let mut orch_config = OrchestratorConfig::default();
        orch_config.session_config.expected_measurements = Some(expected_stage_measurements);
        // The transport layer still enforces PCR pinning on every handshake.
        // Disable only the pipeline-level "some StageSpec must carry measurements"
        // sanity check because this single-stage Nitro flow keeps StageSpec empty to
        // avoid making the enclave verify the non-TEE host as another enclave.
        orch_config.require_measurements = false;

        let mut orch = init_orchestrator_vsock(
            orch_config,
            manifest,
            data_out_listener,
            &verifier,
            &provider,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to initialize orchestrator");
            e
        })?;

        info!("Pipeline initialized successfully");

        // 5. Health check
        orch.health_check().await.map_err(|e| {
            error!(error = %e, "Health check failed");
            e
        })?;
        info!("Health check passed");

        // 6. Run inference
        let input_bytes = args.text.as_bytes();
        let input = vec![vec![OwnedTensor {
            name: "input".to_string(),
            dtype: DType::U8,
            shape: vec![input_bytes.len() as u32],
            data: bytes::Bytes::copy_from_slice(input_bytes),
        }]];

        info!(input_len = input_bytes.len(), "Running inference...");
        let infer_start = std::time::Instant::now();
        let result = orch.infer(input, args.seq_len).await.map_err(|e| {
            error!(error = %e, "Inference failed");
            e
        })?;
        let infer_elapsed = infer_start.elapsed();

        info!(
            elapsed_ms = infer_elapsed.as_secs_f64() * 1000.0,
            batches = result.outputs.len(),
            "Inference complete"
        );

        // 7. Extract outputs
        for (i, tensors) in result.outputs.iter().enumerate() {
            for t in tensors {
                if t.name == "__receipt__" {
                    // Save raw wire-format bytes before parsing
                    if let Err(e) = save_receipt_raw(&t.data, args.receipt_output_raw.as_deref()) {
                        error!(error = %e, "Failed to save raw receipt");
                    }
                    match ephemeral_ml_common::cbor::from_slice::<AttestationReceipt>(&t.data)
                        .or_else(|_| {
                            serde_json::from_slice::<AttestationReceipt>(&t.data)
                                .map_err(|e| ephemeral_ml_common::cbor::CborError(e.to_string()))
                        }) {
                        Ok(receipt) => {
                            print_receipt(&receipt);
                            if let Err(e) = save_receipt(&receipt, args.receipt_output.as_deref()) {
                                error!(error = %e, "Failed to save receipt");
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to parse receipt");
                        }
                    }
                } else if t.name == "__receipt_air_v1__" {
                    if let Err(e) = save_receipt_raw(&t.data, args.receipt_output_air_v1.as_deref())
                    {
                        error!(error = %e, "Failed to save AIR v1 receipt");
                    } else if args.receipt_output_air_v1.is_some() {
                        info!(size = t.data.len(), "AIR v1 receipt saved");
                    }
                } else if t.name == "__attestation__" {
                    if let Err(e) =
                        save_attestation_raw(&t.data, args.attestation_output.as_deref())
                    {
                        error!(error = %e, "Failed to save boot attestation");
                    } else if args.attestation_output.is_some() {
                        info!(size = t.data.len(), "Boot attestation saved");
                    }
                } else if t.name == "__kms_release__" {
                    if let Err(e) =
                        save_kms_release_raw(&t.data, args.kms_release_output.as_deref())
                    {
                        error!(error = %e, "Failed to save KMS release evidence");
                    } else if args.kms_release_output.is_some() {
                        info!(size = t.data.len(), "KMS release evidence saved");
                    }
                } else {
                    print_embeddings(&t.data, &t.shape);
                    println!(
                        "  Output tensor [batch {}]: name={}, shape={:?}, {} bytes",
                        i,
                        t.name,
                        t.shape,
                        t.data.len()
                    );
                }
            }
        }

        // 8. Shutdown
        orch.shutdown().await.map_err(|e| {
            error!(error = %e, "Shutdown failed");
            e
        })?;
        info!("Pipeline shut down gracefully");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_receipt() -> AttestationReceipt {
        AttestationReceipt {
            receipt_id: "test-id".into(),
            model_id: "test-model".into(),
            model_version: "1.0".into(),
            sequence_number: 1,
            security_mode: ephemeral_ml_common::SecurityMode::GatewayOnly,
            protocol_version: 1,
            policy_version: "1.0".into(),
            request_hash: [0u8; 32],
            response_hash: [0u8; 32],
            attestation_doc_hash: [0u8; 32],
            enclave_measurements: ephemeral_ml_common::EnclaveMeasurements {
                pcr0: vec![0u8; 48],
                pcr1: vec![0u8; 48],
                pcr2: vec![0u8; 48],
                pcr3: None,
                pcr4: None,
                pcr8: None,
                measurement_type: "nitro-pcr".into(),
            },
            signature: None,
            execution_timestamp: 0,
            execution_time_ms: 42,
            memory_peak_mb: 10,
            previous_receipt_hash: None,
            attestation_source: None,
            cs_image_digest: None,
            cs_claims_hash: None,
            destroy_evidence: None,
        }
    }

    #[test]
    fn save_receipt_none_path_is_noop() {
        let receipt = sample_receipt();
        assert!(save_receipt(&receipt, None).is_ok());
    }

    #[test]
    fn save_receipt_writes_valid_json() {
        let dir = std::env::temp_dir().join("ephemeralml-test-receipt");
        let path = dir.join("receipt.json");
        std::fs::create_dir_all(&dir).unwrap();

        let receipt = sample_receipt();
        save_receipt(&receipt, Some(path.to_str().unwrap())).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed["receipt_id"], "test-id");
        assert_eq!(parsed["execution_time_ms"], 42);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_receipt_bad_path_returns_error() {
        let receipt = sample_receipt();
        let result = save_receipt(&receipt, Some("/nonexistent/deeply/nested/receipt.json"));
        assert!(result.is_err());
    }

    #[test]
    fn save_receipt_raw_none_path_is_noop() {
        assert!(save_receipt_raw(b"hello", None).is_ok());
    }

    #[test]
    fn save_receipt_raw_writes_exact_bytes() {
        let dir = std::env::temp_dir().join("ephemeralml-test-raw");
        let path = dir.join("receipt.raw");
        std::fs::create_dir_all(&dir).unwrap();

        let raw = b"\x82\xa1\x63foo\x63bar";
        save_receipt_raw(raw, Some(path.to_str().unwrap())).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, raw);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_receipt_raw_bad_path_returns_error() {
        let result = save_receipt_raw(b"data", Some("/nonexistent/deeply/nested/receipt.raw"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn save_receipt_raw_empty_bytes() {
        let dir = std::env::temp_dir().join("ephemeralml-test-raw-empty");
        let path = dir.join("receipt.raw");
        std::fs::create_dir_all(&dir).unwrap();

        save_receipt_raw(b"", Some(path.to_str().unwrap())).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert!(contents.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_attestation_raw_writes_bytes() {
        let dir = std::env::temp_dir().join("ephemeralml-test-attestation");
        let path = dir.join("attestation.cbor");
        std::fs::create_dir_all(&dir).unwrap();

        let attestation = [0xAB; 16];
        save_attestation_raw(&attestation, Some(path.to_str().unwrap())).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, attestation);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_kms_release_raw_writes_bytes() {
        let dir = std::env::temp_dir().join("ephemeralml-test-kms-release");
        let path = dir.join("kms-release.json");
        std::fs::create_dir_all(&dir).unwrap();

        let evidence = br#"{"status":"allowed"}"#;
        save_kms_release_raw(evidence, Some(path.to_str().unwrap())).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, evidence);

        std::fs::remove_dir_all(&dir).ok();
    }
}
