use ephemeral_ml_enclave::candle_engine::CandleInferenceEngine;
use ephemeral_ml_enclave::server::run_stage_tcp;
use ephemeral_ml_enclave::stage_executor::EphemeralStageExecutor;

use confidential_ml_pipeline::StageConfig;
#[cfg(any(feature = "mock", feature = "production"))]
use confidential_ml_transport::MockVerifier;
use ephemeral_ml_common::ReceiptSigningKey;

use clap::Parser;
use std::path::PathBuf;

#[cfg(feature = "production")]
use ephemeral_ml_enclave::attestation_bridge::AttestationBridge;
#[cfg(feature = "production")]
use ephemeral_ml_enclave::DefaultAttestationProvider;

#[derive(Parser, Debug)]
#[command(
    name = "ephemeral-ml-enclave",
    about = "EphemeralML Enclave Stage Worker"
)]
struct Args {
    /// Path to model directory containing config.json, tokenizer.json, model.safetensors
    #[arg(long, default_value = "test_assets/minilm")]
    model_dir: PathBuf,

    /// Model ID to register (maps to stage ID, e.g. "stage-0")
    #[arg(long, default_value = "stage-0")]
    model_id: String,

    /// Smoke-test TDX attestation: generate a quote, print measurements, and exit.
    /// Uses real configfs-tsm on TDX hardware, or synthetic quotes with --synthetic.
    #[arg(long)]
    smoke_tdx: bool,

    /// Use synthetic TDX quotes (no real hardware needed). Combine with --smoke-tdx.
    #[arg(long)]
    synthetic: bool,

    /// GCP mode: run as a single-binary Confidential VM (TDX) with direct GCS/KMS access.
    #[arg(long)]
    gcp: bool,

    /// GCS bucket for model weights (GCP mode).
    #[arg(long, default_value = "ephemeralml-models")]
    gcp_bucket: String,

    /// GCS prefix for model files within the bucket (GCP mode).
    #[arg(long, default_value = "models/minilm")]
    gcp_model_prefix: String,

    /// GCP project ID (GCP mode).
    #[arg(long, default_value = "ephemeralml")]
    gcp_project: String,

    /// GCP location for Attestation API (GCP mode).
    #[arg(long, default_value = "us-central1")]
    gcp_location: String,

    /// Cloud KMS key resource name for model DEK decryption (GCP mode).
    /// Format: projects/P/locations/L/keyRings/KR/cryptoKeys/K
    /// When set, fetches encrypted model from GCS and decrypts via attestation-bound KMS.
    #[arg(long)]
    gcp_kms_key: Option<String>,

    /// Workload Identity Pool audience for STS token exchange (GCP mode).
    /// Format: //iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/POOL/providers/PROV
    #[arg(long)]
    gcp_wip_audience: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // --smoke-tdx: generate a TDX quote, print measurements, and exit.
    if args.smoke_tdx {
        #[cfg(feature = "tdx")]
        {
            use ephemeral_ml_enclave::tee_provider::{
                print_tdx_measurements, TeeAttestationEnvelope, TeeAttestationProvider,
            };
            use ephemeral_ml_enclave::AttestationProvider;

            println!("EphemeralML TDX Smoke Test");
            println!();

            let provider = if args.synthetic {
                println!("  Mode: synthetic (no hardware)");
                TeeAttestationProvider::synthetic()
            } else {
                println!("  Mode: real configfs-tsm");
                TeeAttestationProvider::new()?
            };

            let receipt_key = ReceiptSigningKey::generate()?;
            let nonce = [0xAB; 32];

            println!("  Generating TDX attestation...");
            let doc = provider.generate_attestation(&nonce, receipt_key.public_key_bytes())?;

            let envelope = TeeAttestationEnvelope::from_cbor(&doc.signature)
                .map_err(|e| format!("envelope decode: {}", e))?;

            // Extract raw quote from wire format
            let raw_quote = &envelope.tdx_wire[16..];
            print_tdx_measurements(raw_quote)?;

            println!(
                "  HPKE public key: {}",
                hex::encode(provider.get_hpke_public_key())
            );
            println!(
                "  Receipt signing key: {}",
                hex::encode(receipt_key.public_key_bytes())
            );
            println!("  Envelope size: {} bytes", doc.signature.len());
            println!("  Platform: {}", envelope.platform);
            println!();
            println!("  TDX smoke test PASSED");

            return Ok(());
        }

        #[cfg(not(feature = "tdx"))]
        {
            eprintln!("ERROR: --smoke-tdx requires the `tdx` feature.");
            eprintln!("Build with: cargo run --features mock,tdx -- --smoke-tdx --synthetic");
            std::process::exit(1);
        }
    }

    // GCP Confidential VM mode: direct network access, no host/enclave split
    if args.gcp {
        #[cfg(feature = "gcp")]
        {
            use ephemeral_ml_enclave::gcs_loader::GcsModelLoader;
            use ephemeral_ml_enclave::tee_provider::{
                TeeAttestationBridge, TeeAttestationProvider,
            };

            println!("EphemeralML Enclave v2.0 (GCP Confidential VM Mode)");
            println!();

            // 1. Initialize TEE attestation provider
            let tee_provider = if args.synthetic {
                println!("[gcp] Using synthetic TDX quotes (no hardware)");
                TeeAttestationProvider::synthetic()
            } else {
                println!("[gcp] Using real configfs-tsm TDX attestation");
                TeeAttestationProvider::new()?
            };

            let receipt_key = ReceiptSigningKey::generate()?;
            let receipt_pk = receipt_key.public_key_bytes();

            // 2. Load model: local > KMS-encrypted GCS > plaintext GCS
            let engine = CandleInferenceEngine::new()?;
            let load_start = std::time::Instant::now();

            if args.model_dir.exists() {
                // Local model directory takes precedence (for testing)
                println!(
                    "[gcp] Loading model from local: {}",
                    args.model_dir.display()
                );
                let config_bytes = std::fs::read(args.model_dir.join("config.json"))
                    .map_err(|e| format!("Failed to read config.json: {}", e))?;
                let tokenizer_bytes = std::fs::read(args.model_dir.join("tokenizer.json"))
                    .map_err(|e| format!("Failed to read tokenizer.json: {}", e))?;
                let weights_bytes = std::fs::read(args.model_dir.join("model.safetensors"))
                    .map_err(|e| format!("Failed to read model.safetensors: {}", e))?;

                engine.register_model(
                    &args.model_id,
                    &config_bytes,
                    &weights_bytes,
                    &tokenizer_bytes,
                )?;

                println!(
                    "[gcp] Model '{}' loaded in {:.1}ms (local, {:.1} MB)",
                    args.model_id,
                    load_start.elapsed().as_secs_f64() * 1000.0,
                    weights_bytes.len() as f64 / (1024.0 * 1024.0),
                );
            } else if let (Some(kms_key), Some(wip_audience)) =
                (&args.gcp_kms_key, &args.gcp_wip_audience)
            {
                // KMS-encrypted model: fetch encrypted weights + wrapped DEK from GCS,
                // decrypt DEK via attestation-bound Cloud KMS, decrypt weights.
                use ephemeral_ml_enclave::crypto_util::decrypt_artifact;
                use ephemeral_ml_enclave::gcp_kms_client::GcpKmsClient;

                println!(
                    "[gcp] Fetching encrypted model from gs://{}/{}",
                    args.gcp_bucket, args.gcp_model_prefix
                );

                let kms_provider = if args.synthetic {
                    ephemeral_ml_enclave::tee_provider::TeeAttestationProvider::synthetic()
                } else {
                    ephemeral_ml_enclave::tee_provider::TeeAttestationProvider::new()?
                };
                let kms_client = GcpKmsClient::new(
                    &args.gcp_project,
                    &args.gcp_location,
                    wip_audience,
                    kms_provider,
                );

                let gcs = GcsModelLoader::new(&args.gcp_bucket);

                // Config and tokenizer are not encrypted (not sensitive)
                let config_path = format!("{}/config.json", args.gcp_model_prefix);
                let tokenizer_path = format!("{}/tokenizer.json", args.gcp_model_prefix);
                // Encrypted weights and wrapped DEK
                let weights_enc_path = format!("{}/model.safetensors.enc", args.gcp_model_prefix);
                let dek_path = format!("{}/wrapped_dek.bin", args.gcp_model_prefix);

                let (config_art, tokenizer_art, weights_enc_art, dek_art) = tokio::join!(
                    gcs.fetch_object(&config_path),
                    gcs.fetch_object(&tokenizer_path),
                    gcs.fetch_object(&weights_enc_path),
                    gcs.fetch_object(&dek_path),
                );

                let config_bytes = config_art?.bytes;
                let tokenizer_bytes = tokenizer_art?.bytes;
                let encrypted_weights = weights_enc_art?.bytes;
                let wrapped_dek = dek_art?.bytes;

                println!(
                    "[gcp] Decrypting DEK via Cloud KMS (key: {})",
                    &kms_key[kms_key.rfind('/').map(|i| i + 1).unwrap_or(0)..]
                );
                let dek = kms_client.decrypt(kms_key, &wrapped_dek).await?;

                if dek.len() != 32 {
                    return Err(format!(
                        "Invalid DEK length from KMS: expected 32, got {}",
                        dek.len()
                    )
                    .into());
                }

                let dek_array: [u8; 32] = dek.try_into().unwrap();
                let weights_bytes = decrypt_artifact(&encrypted_weights, &dek_array)?;

                engine.register_model(
                    &args.model_id,
                    &config_bytes,
                    &weights_bytes,
                    &tokenizer_bytes,
                )?;

                println!(
                    "[gcp] Model '{}' loaded in {:.1}ms (KMS-encrypted GCS, {:.1} MB)",
                    args.model_id,
                    load_start.elapsed().as_secs_f64() * 1000.0,
                    weights_bytes.len() as f64 / (1024.0 * 1024.0),
                );
            } else {
                // Fetch plaintext from GCS (requires metadata server for auth)
                println!(
                    "[gcp] Fetching model from gs://{}/{}",
                    args.gcp_bucket, args.gcp_model_prefix
                );
                let gcs = GcsModelLoader::new(&args.gcp_bucket);
                let (config_bytes, tokenizer_bytes, weights_bytes) =
                    gcs.fetch_model_files(&args.gcp_model_prefix).await?;

                engine.register_model(
                    &args.model_id,
                    &config_bytes,
                    &weights_bytes,
                    &tokenizer_bytes,
                )?;

                println!(
                    "[gcp] Model '{}' loaded in {:.1}ms (GCS, {:.1} MB)",
                    args.model_id,
                    load_start.elapsed().as_secs_f64() * 1000.0,
                    weights_bytes.len() as f64 / (1024.0 * 1024.0),
                );
            }

            // 3. Probe Confidential Space Launcher socket for container identity
            {
                use ephemeral_ml_enclave::cs_token_client::CsTokenClient;

                let cs_client = CsTokenClient::new();
                let nonce = hex::encode(&receipt_pk[..16]);
                match cs_client
                    .get_token("ephemeralml-boot", vec![nonce.clone()])
                    .await
                {
                    Ok(jwt) => match CsTokenClient::parse_claims(&jwt) {
                        Ok(claims) => {
                            println!("[gcp] Confidential Space identity:");
                            println!("  issuer:  {}", claims.iss);
                            println!("  subject: {}", claims.sub);
                            println!("  swname:  {}", claims.swname);
                            if !claims.eat_nonce.is_empty() {
                                println!("  eat_nonce[0]: {}", claims.eat_nonce[0]);
                            }
                        }
                        Err(e) => {
                            println!("[gcp] CS token received but claims parse failed: {}", e);
                        }
                    },
                    Err(_) => {
                        println!(
                            "[gcp] Launcher socket not available (not running in Confidential Space)"
                        );
                    }
                }
            }

            // 4. Emit trust evidence bundle
            {
                use ephemeral_ml_enclave::tee_provider::TeeAttestationEnvelope;
                use ephemeral_ml_enclave::trust_evidence::TrustEvidenceBundle;
                use ephemeral_ml_enclave::AttestationProvider;

                let boot_nonce = [0u8; 32];
                let boot_doc = tee_provider.generate_attestation(&boot_nonce, receipt_pk)?;
                let envelope = TeeAttestationEnvelope::from_cbor(&boot_doc.signature)
                    .map_err(|e| format!("trust evidence: {}", e))?;
                let raw_quote = &envelope.tdx_wire[16..];

                let bundle = TrustEvidenceBundle::from_boot(
                    raw_quote,
                    tee_provider.get_hpke_public_key(),
                    receipt_pk,
                    &args.model_id,
                    None, // model weights hash logged separately
                    None,
                    "tdx",
                );
                bundle.print();
            }

            // 5. Create executor with TDX attestation provider
            let executor = EphemeralStageExecutor::new(engine, tee_provider, receipt_key);

            // 6. Create transport attestation bridge (for SecureChannel handshake)
            let bridge_provider = if args.synthetic {
                TeeAttestationProvider::synthetic()
            } else {
                TeeAttestationProvider::new()?
            };
            let bridge = TeeAttestationBridge::new(bridge_provider, receipt_pk);

            // Use TDX verifier for peer verification
            let verifier = confidential_ml_transport::attestation::tdx::TdxVerifier::new(None);

            println!(
                "[gcp] Stage worker: control=0.0.0.0:9000, data_in=0.0.0.0:9001, data_out=0.0.0.0:9002"
            );

            run_stage_tcp(
                executor,
                StageConfig::default(),
                "0.0.0.0:9000",
                "0.0.0.0:9001",
                "0.0.0.0:9002".parse()?,
                &bridge,
                &verifier,
            )
            .await?;

            return Ok(());
        }

        #[cfg(not(feature = "gcp"))]
        {
            eprintln!("ERROR: --gcp requires the `gcp` feature.");
            eprintln!("Build with: cargo run --features mock,gcp -- --gcp --synthetic");
            std::process::exit(1);
        }
    }

    println!("EphemeralML Enclave v2.0");

    #[cfg(feature = "mock")]
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

        use confidential_ml_transport::MockProvider;
        use ephemeral_ml_enclave::mock::MockAttestationProvider;

        let mock_provider = MockAttestationProvider::new();
        let receipt_key = ReceiptSigningKey::generate()?;
        let _receipt_pk = receipt_key.public_key_bytes();

        let executor = EphemeralStageExecutor::new(engine, mock_provider, receipt_key);
        // Use transport-compatible MockProvider for handshake (matches host's MockVerifier)
        let transport_provider = MockProvider::new();
        let verifier = MockVerifier::new();

        println!(
            "Stage worker: control=127.0.0.1:9000, data_in=127.0.0.1:9001, data_out→127.0.0.1:9002"
        );

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

        // Generate receipt signing key early — needed for KMS attestation binding
        let receipt_key = ReceiptSigningKey::generate()?;
        let receipt_pk = receipt_key.public_key_bytes();

        // Connectivity health check
        println!("[boot] Starting connectivity health check...");
        use ephemeral_ml_enclave::kms_client::KmsClient;
        use ephemeral_ml_enclave::model_loader::ModelLoader;

        let kms_client = KmsClient::new(attestation_provider.clone(), receipt_pk);

        // Load trusted model signing key from environment (hex-encoded Ed25519 public key)
        let trusted_signing_key: [u8; 32] = {
            let key_hex = std::env::var("EPHEMERALML_MODEL_SIGNING_KEY").unwrap_or_else(|_| {
                // Default to the policy root public key (same trust anchor)
                "12740b4f2ff1f9dac52cac6db77f3a57950fb15134c8580295c98bd809673444".to_string()
            });
            let key_bytes =
                hex::decode(&key_hex).expect("EPHEMERALML_MODEL_SIGNING_KEY must be valid hex");
            assert!(
                key_bytes.len() == 32 && key_bytes.iter().any(|&b| b != 0),
                "Model signing key must be 32 non-zero bytes"
            );
            key_bytes.try_into().unwrap()
        };
        let loader = ModelLoader::new(kms_client, trusted_signing_key);

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

        // Start stage worker
        let executor =
            EphemeralStageExecutor::new(engine, attestation_provider.clone(), receipt_key);
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
