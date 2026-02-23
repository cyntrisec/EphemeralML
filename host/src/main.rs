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
use confidential_ml_transport::{MockProvider as HostMockProvider, NitroVerifier};
#[cfg(feature = "production")]
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
#[cfg(feature = "production")]
use tracing::{error, info, warn};

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
    println!("  This receipt cryptographically proves:");
    println!("    - Input/output hashes bind request to response");
    println!("    - Execution occurred inside an attested enclave");
    println!("    - Ed25519 signature prevents tampering");
    println!("    - Enclave measurements verify code integrity");
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("EphemeralML Host v2.0");

    #[cfg(feature = "mock")]
    {
        println!("EphemeralML Host (Mock Mode)");

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

        let mut orch = init_orchestrator_tcp(
            OrchestratorConfig::default(),
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
                    // Try CBOR first (canonical format), fall back to JSON
                    match ephemeral_ml_common::cbor::from_slice::<AttestationReceipt>(&t.data)
                        .or_else(|_| {
                            serde_json::from_slice::<AttestationReceipt>(&t.data)
                                .map_err(|e| ephemeral_ml_common::cbor::CborError(e.to_string()))
                        }) {
                        Ok(receipt) => {
                            print_receipt(&receipt);
                        }
                        Err(e) => {
                            eprintln!("Failed to parse receipt: {}", e);
                        }
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
                weight_hashes: vec![],
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
        let mut orch = init_orchestrator_vsock(
            OrchestratorConfig::default(),
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
                    match ephemeral_ml_common::cbor::from_slice::<AttestationReceipt>(&t.data)
                        .or_else(|_| {
                            serde_json::from_slice::<AttestationReceipt>(&t.data)
                                .map_err(|e| ephemeral_ml_common::cbor::CborError(e.to_string()))
                        }) {
                        Ok(receipt) => {
                            print_receipt(&receipt);
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to parse receipt");
                        }
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
