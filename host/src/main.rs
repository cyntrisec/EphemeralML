use ephemeral_ml_host::mock::MockKmsProxyServer;

use confidential_ml_pipeline::tcp::init_orchestrator_tcp;
use confidential_ml_pipeline::{
    ActivationDType, ActivationSpec, OrchestratorConfig, PortSpec, ShardManifest, StageEndpoint,
    StageSpec,
};
use confidential_ml_transport::{DType, MockProvider, MockVerifier, OwnedTensor};
use ephemeral_ml_common::AttestationReceipt;
use std::collections::BTreeMap;
use tokio::net::TcpListener;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("EphemeralML Host v2.0");

    #[cfg(not(feature = "production"))]
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
        let orch_dout_lis = TcpListener::bind("127.0.0.1:9002").await?;
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
                    match serde_json::from_slice::<AttestationReceipt>(&t.data) {
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
        eprintln!("ERROR: The main host binary is for pipeline orchestration only.");
        eprintln!(
            "For production KMS proxy, run: cargo run --features production --bin kms_proxy_host"
        );
        std::process::exit(1);
    }

    Ok(())
}
