use ephemeral_ml_enclave::candle_engine::CandleInferenceEngine;
use ephemeral_ml_enclave::server::run_stage_tcp;
use ephemeral_ml_enclave::stage_executor::EphemeralStageExecutor;

use confidential_ml_pipeline::StageConfig;
use confidential_ml_transport::MockVerifier;
use ephemeral_ml_common::ReceiptSigningKey;

use clap::Parser;
use std::path::PathBuf;

#[cfg(feature = "production")]
use ephemeral_ml_enclave::attestation_bridge::AttestationBridge;
#[cfg(feature = "production")]
use ephemeral_ml_enclave::DefaultAttestationProvider;

#[derive(Parser, Debug)]
#[command(name = "ephemeral-ml-enclave", about = "EphemeralML Enclave Stage Worker")]
struct Args {
    /// Path to model directory containing config.json, tokenizer.json, model.safetensors
    #[arg(long, default_value = "test_assets/minilm")]
    model_dir: PathBuf,

    /// Model ID to register (maps to stage ID, e.g. "stage-0")
    #[arg(long, default_value = "stage-0")]
    model_id: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("EphemeralML Enclave v2.0");

    #[cfg(not(feature = "production"))]
    {
        println!("EphemeralML Enclave (Mock Mode)");

        // Load model weights
        let load_start = std::time::Instant::now();

        let config_path = args.model_dir.join("config.json");
        let tokenizer_path = args.model_dir.join("tokenizer.json");
        let weights_path = args.model_dir.join("model.safetensors");

        println!("Loading model from: {}", args.model_dir.display());

        let config_bytes = std::fs::read(&config_path)
            .map_err(|e| format!("Failed to read {}: {}", config_path.display(), e))?;
        let tokenizer_bytes = std::fs::read(&tokenizer_path)
            .map_err(|e| format!("Failed to read {}: {}", tokenizer_path.display(), e))?;
        let weights_bytes = std::fs::read(&weights_path)
            .map_err(|e| format!("Failed to read {}: {}", weights_path.display(), e))?;

        let engine = CandleInferenceEngine::new()?;

        engine.register_model(
            &args.model_id,
            &config_bytes,
            &weights_bytes,
            &tokenizer_bytes,
        )?;

        let load_elapsed = load_start.elapsed();
        println!(
            "Model '{}' loaded in {:.1}ms (weights: {:.1} MB)",
            args.model_id,
            load_elapsed.as_secs_f64() * 1000.0,
            weights_bytes.len() as f64 / (1024.0 * 1024.0),
        );

        println!("Starting pipeline stage worker on TCP...");

        use ephemeral_ml_enclave::mock::MockAttestationProvider;
        use confidential_ml_transport::MockProvider;

        let mock_provider = MockAttestationProvider::new();
        let receipt_key = ReceiptSigningKey::generate()?;
        let _receipt_pk = receipt_key.public_key_bytes();

        let executor = EphemeralStageExecutor::new(engine, mock_provider, receipt_key);
        // Use transport-compatible MockProvider for handshake (matches host's MockVerifier)
        let transport_provider = MockProvider::new();
        let verifier = MockVerifier::new();

        println!("Stage worker: control=127.0.0.1:9000, data_in=127.0.0.1:9001, data_out→127.0.0.1:9002");

        run_stage_tcp(
            executor,
            StageConfig::default(),
            "127.0.0.1:9000",
            "127.0.0.1:9001",
            "127.0.0.1:9002".parse()?,
            &transport_provider,
            &verifier,
        )
        .await?;
    }

    #[cfg(feature = "production")]
    {
        println!("EphemeralML Enclave (Production Mode)");

        let attestation_provider = DefaultAttestationProvider::new()?;
        let engine = CandleInferenceEngine::new()?;

        // Connectivity health check
        println!("[boot] Starting connectivity health check...");
        use ephemeral_ml_enclave::kms_client::KmsClient;
        use ephemeral_ml_enclave::model_loader::ModelLoader;

        let kms_client = KmsClient::new(attestation_provider.clone());
        let loader = ModelLoader::new(kms_client, [0u8; 32]);

        let expected_encrypted_hash =
            hex::decode("542c469d0d4c936b05fc57e64e0f5acd1048f186c4705801dcddf718cfde9b74")
                .unwrap();

        println!("[boot] Fetching test-model-001 from S3 via Host Proxy...");
        let proxy = loader.kms_client().proxy_client();
        match proxy.fetch_model("test-model-001").await {
            Ok(bytes) => {
                println!("[boot] SUCCESS: Fetched {} bytes from S3!", bytes.len());
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let hash = hasher.finalize();
                if hash.as_slice() == expected_encrypted_hash.as_slice() {
                    println!("[boot] VERIFIED: Encrypted artifact hash matches.");
                } else {
                    println!("[boot] Hash mismatch! Got: {}", hex::encode(hash));
                }
            }
            Err(e) => println!(
                "[boot] WARNING: S3 fetch failed (expected if model not uploaded): {:?}",
                e
            ),
        }

        // Start stage worker on VSock
        let receipt_key = ReceiptSigningKey::generate()?;
        let receipt_pk = receipt_key.public_key_bytes();

        let executor = EphemeralStageExecutor::new(
            engine,
            attestation_provider.clone(),
            receipt_key,
        );
        let bridge = AttestationBridge::new(attestation_provider, receipt_pk);
        let verifier = MockVerifier::new();

        println!("Production stage worker: control=127.0.0.1:5000, data_in=127.0.0.1:5001, data_out→127.0.0.1:5002");

        run_stage_tcp(
            executor,
            StageConfig::default(),
            "127.0.0.1:5000",
            "127.0.0.1:5001",
            "127.0.0.1:5002".parse()?,
            &bridge,
            &verifier,
        )
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    }

    Ok(())
}
