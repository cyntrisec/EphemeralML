use ephemeral_ml_enclave::candle_engine::CandleInferenceEngine;
use ephemeral_ml_enclave::server::run_direct_tcp;
use ephemeral_ml_enclave::server::run_stage_tcp;
use ephemeral_ml_enclave::stage_executor::EphemeralStageExecutor;

use confidential_ml_pipeline::StageConfig;
#[cfg(feature = "mock")]
use confidential_ml_transport::MockVerifier;
#[cfg(feature = "production")]
use confidential_ml_transport::NitroVerifier;
use ephemeral_ml_common::ReceiptSigningKey;

use clap::Parser;
use std::path::PathBuf;
#[allow(unused_imports)]
use tracing::{error, info, warn};

#[cfg(feature = "production")]
use ephemeral_ml_enclave::attestation_bridge::AttestationBridge;
#[cfg(feature = "production")]
use ephemeral_ml_enclave::DefaultAttestationProvider;

/// MockProvider wrapper that injects fixed user_data (EphemeralUserData CBOR)
/// into every attestation while preserving the MOCK_ATT_V1 wire format.
#[cfg(feature = "mock")]
struct MockProviderWithUserData(Vec<u8>);

#[cfg(feature = "mock")]
#[async_trait::async_trait]
impl confidential_ml_transport::AttestationProvider for MockProviderWithUserData {
    async fn attest(
        &self,
        _user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> std::result::Result<
        confidential_ml_transport::attestation::types::AttestationDocument,
        confidential_ml_transport::error::AttestError,
    > {
        confidential_ml_transport::MockProvider
            .attest(Some(&self.0), nonce, public_key)
            .await
    }
}

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

    /// Model source for GCP mode (required when --gcp is set).
    ///   local:   read from --model-dir (bundled in container, no KMS)
    ///   gcs:     fetch plaintext from GCS (requires --expected-model-hash)
    ///   gcs-kms: fetch encrypted model from GCS, decrypt via attestation-bound Cloud KMS (requires --expected-model-hash)
    #[arg(long, env = "EPHEMERALML_MODEL_SOURCE")]
    model_source: Option<String>,

    /// GCS bucket for model weights (GCP mode, gcs/gcs-kms).
    #[arg(
        long,
        env = "EPHEMERALML_GCS_BUCKET",
        default_value = "ephemeralml-models"
    )]
    gcp_bucket: String,

    /// GCS prefix for model files within the bucket (GCP mode, gcs/gcs-kms).
    #[arg(
        long,
        env = "EPHEMERALML_GCP_MODEL_PREFIX",
        default_value = "models/minilm"
    )]
    gcp_model_prefix: String,

    /// GCP project ID (GCP mode).
    #[arg(long, env = "EPHEMERALML_GCP_PROJECT", default_value = "ephemeralml")]
    gcp_project: String,

    /// GCP location for Attestation API (GCP mode).
    #[arg(long, env = "EPHEMERALML_GCP_LOCATION", default_value = "us-central1")]
    gcp_location: String,

    /// Cloud KMS key resource name for model DEK decryption (GCP mode, gcs-kms).
    /// Format: projects/P/locations/L/keyRings/KR/cryptoKeys/K
    #[arg(long, env = "EPHEMERALML_GCP_KMS_KEY")]
    gcp_kms_key: Option<String>,

    /// Workload Identity Pool audience for STS token exchange (GCP mode, gcs-kms).
    /// Format: //iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/POOL/providers/PROV
    #[arg(long, env = "EPHEMERALML_GCP_WIP_AUDIENCE")]
    gcp_wip_audience: Option<String>,

    /// Expected SHA-256 hash of model.safetensors (hex, 64 chars).
    /// Model weights are verified against this hash after loading.
    /// Required for gcs and gcs-kms model sources; optional for local.
    #[arg(long, env = "EPHEMERALML_EXPECTED_MODEL_HASH")]
    expected_model_hash: Option<String>,

    /// Expected MRTD measurement (hex, 96 chars = 48 bytes) for TDX peer verification.
    /// When set, rejects peers with non-matching MRTD.
    #[arg(long, env = "EPHEMERALML_EXPECTED_MRTD")]
    expected_mrtd: Option<String>,

    /// Direct mode: accept client SecureChannel on a single port (9000) and run
    /// inference immediately. No orchestrator needed. For GCP smoke/E2E testing.
    #[arg(long, env = "EPHEMERALML_DIRECT")]
    direct: bool,

    /// Control channel listen address for pipeline mode.
    #[arg(long, default_value = "127.0.0.1:9000")]
    control_addr: String,

    /// Data-in channel listen address for pipeline mode.
    #[arg(long, default_value = "127.0.0.1:9001")]
    data_in_addr: String,

    /// Data-out target address for pipeline mode (connect to next stage or orchestrator).
    #[arg(long, default_value = "127.0.0.1:9002")]
    data_out_target: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging
    let log_format = std::env::var("EPHEMERALML_LOG_FORMAT").unwrap_or_default();
    if log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .init();
    }

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

            info!("EphemeralML Enclave v2.0 (GCP Confidential VM Mode)");

            // 0. Validate required --model-source
            let model_source = args
                .model_source
                .as_deref()
                .ok_or("--model-source is required in GCP mode (local, gcs, or gcs-kms)")?;

            // 1. Initialize TEE attestation provider (auto-detect CS vs configfs-tsm vs synthetic)
            let cs_mode = std::path::Path::new("/run/container_launcher/teeserver.sock").exists();
            let has_tsm = std::path::Path::new("/sys/kernel/config/tsm/report").exists();

            // In release builds, reject --synthetic for GCP mode to prevent
            // accidental use of fake attestation in production.
            #[cfg(not(debug_assertions))]
            if args.synthetic {
                return Err("--synthetic is not allowed in release builds. \
                    Deploy on a TDX CVM or Confidential Space for real attestation. \
                    Build with debug profile for local development."
                    .into());
            }

            let tee_provider = if args.synthetic {
                warn!(
                    step = "attestation",
                    mode = "synthetic",
                    "WARNING: Using synthetic TDX quotes — NOT FOR PRODUCTION"
                );
                TeeAttestationProvider::synthetic()
            } else if has_tsm {
                info!(
                    step = "attestation",
                    mode = "configfs-tsm",
                    "Using real TDX attestation"
                );
                TeeAttestationProvider::new()?
            } else if cs_mode {
                // Confidential Space detected. configfs-tsm may not be exposed
                // inside the container, but the Launcher has already attested
                // the workload. Use synthetic TDX quotes as a placeholder for
                // transport-level attestation; the real attestation is via
                // Launcher OIDC tokens (CsKmsClient path).
                warn!(
                    step = "attestation",
                    mode = "cs_launcher",
                    "Confidential Space detected — TDX configfs-tsm not available, \
                    using synthetic quotes for transport. Launcher JWT handles KMS attestation."
                );
                TeeAttestationProvider::synthetic()
            } else {
                return Err(
                    "No TDX attestation source available. Use --synthetic for local dev \
                    (debug builds only), or deploy on a TDX CVM / Confidential Space."
                        .into(),
                );
            };

            let receipt_key = ReceiptSigningKey::generate()?;
            let receipt_pk = receipt_key.public_key_bytes();

            // 2. Load model via explicit --model-source
            let engine = CandleInferenceEngine::new()?;
            let load_start = std::time::Instant::now();

            // Parse expected model hash if provided
            let expected_model_hash: Option<[u8; 32]> = match &args.expected_model_hash {
                Some(hex_str) => {
                    let bytes = hex::decode(hex_str)
                        .map_err(|e| format!("--expected-model-hash: invalid hex: {}", e))?;
                    if bytes.len() != 32 {
                        return Err(format!(
                            "--expected-model-hash must be 64 hex chars (32 bytes), got {}",
                            bytes.len()
                        )
                        .into());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                }
                None => None,
            };

            // Track the verified model weights hash for trust evidence.
            // Every match arm below assigns this before it is read.
            #[allow(unused_assignments)]
            let mut loaded_model_hash: Option<[u8; 32]> = None;

            match model_source {
                "local" => {
                    if !args.model_dir.exists() {
                        return Err(format!(
                            "--model-source=local but model directory does not exist: {}",
                            args.model_dir.display()
                        )
                        .into());
                    }
                    info!(step = "model_load", source = "local", path = %args.model_dir.display(), "Loading model from local directory");
                    let config_bytes = std::fs::read(args.model_dir.join("config.json"))
                        .map_err(|e| format!("Failed to read config.json: {}", e))?;
                    let tokenizer_bytes = std::fs::read(args.model_dir.join("tokenizer.json"))
                        .map_err(|e| format!("Failed to read tokenizer.json: {}", e))?;
                    let weights_bytes = std::fs::read(args.model_dir.join("model.safetensors"))
                        .map_err(|e| format!("Failed to read model.safetensors: {}", e))?;

                    // Compute and verify model hash
                    {
                        use sha2::{Digest, Sha256};
                        let actual: [u8; 32] = Sha256::digest(&weights_bytes).into();
                        if let Some(expected) = &expected_model_hash {
                            if &actual != expected {
                                return Err(format!(
                                    "Model hash mismatch (local): expected {}, got {}",
                                    hex::encode(expected),
                                    hex::encode(actual)
                                )
                                .into());
                            }
                            info!(step = "hash_verify", hash = %hex::encode(expected), "Model hash verified");
                        }
                        loaded_model_hash = Some(actual);
                    }

                    engine.register_model(
                        &args.model_id,
                        &config_bytes,
                        &weights_bytes,
                        &tokenizer_bytes,
                    )?;

                    info!(
                        step = "model_load",
                        source = "local",
                        model_id = %args.model_id,
                        elapsed_ms = load_start.elapsed().as_secs_f64() * 1000.0,
                        size_mb = weights_bytes.len() as f64 / (1024.0 * 1024.0),
                        "Model loaded"
                    );
                }
                "gcs-kms" => {
                    let kms_key = args
                        .gcp_kms_key
                        .as_ref()
                        .ok_or("--model-source=gcs-kms requires --gcp-kms-key")?;
                    let wip_audience = args
                        .gcp_wip_audience
                        .as_ref()
                        .ok_or("--model-source=gcs-kms requires --gcp-wip-audience")?;

                    use ephemeral_ml_enclave::crypto_util::decrypt_artifact;
                    use ephemeral_ml_enclave::gcp_kms_client::GcpKmsClient;

                    info!(step = "model_load", source = "gcs-kms", bucket = %args.gcp_bucket, prefix = %args.gcp_model_prefix, "Fetching encrypted model from GCS");

                    let gcs = GcsModelLoader::new(&args.gcp_bucket);

                    let config_path = format!("{}/config.json", args.gcp_model_prefix);
                    let tokenizer_path = format!("{}/tokenizer.json", args.gcp_model_prefix);
                    let weights_enc_path =
                        format!("{}/model.safetensors.enc", args.gcp_model_prefix);
                    let dek_path = format!("{}/wrapped_dek.bin", args.gcp_model_prefix);
                    let manifest_path = format!("{}/manifest.json", args.gcp_model_prefix);

                    let (config_art, tokenizer_art, weights_enc_art, dek_art, manifest_art) = tokio::join!(
                        gcs.fetch_object(&config_path),
                        gcs.fetch_object(&tokenizer_path),
                        gcs.fetch_object(&weights_enc_path),
                        gcs.fetch_object(&dek_path),
                        gcs.fetch_object(&manifest_path),
                    );

                    let config_bytes = config_art?.bytes;
                    let tokenizer_bytes = tokenizer_art?.bytes;
                    let encrypted_weights = weights_enc_art?.bytes;
                    let wrapped_dek = dek_art?.bytes;

                    // Determine if manifest verification is required (pubkey configured)
                    let require_manifest =
                        std::env::var("EPHEMERALML_MODEL_SIGNING_PUBKEY").is_ok();

                    // Parse manifest — fail-closed if pubkey is set
                    let manifest = match manifest_art {
                        Ok(art) => {
                            match ephemeral_ml_common::ModelManifest::from_json(&art.bytes) {
                                Ok(m) => {
                                    info!(step = "manifest", model_id = %m.model_id, version = %m.version, "Manifest found");
                                    Some(m)
                                }
                                Err(e) => {
                                    if require_manifest {
                                        return Err(format!(
                                            "manifest.json parse failed and EPHEMERALML_MODEL_SIGNING_PUBKEY is set: {}", e
                                        ).into());
                                    }
                                    warn!(step = "manifest", error = %e, "manifest.json parse failed");
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            if require_manifest {
                                return Err(format!(
                                    "manifest.json missing from GCS but EPHEMERALML_MODEL_SIGNING_PUBKEY is set \
                                     (manifest is required when signing pubkey is configured): {}", e
                                ).into());
                            }
                            info!(
                                step = "manifest",
                                "No manifest.json in GCS (backwards-compatible mode)"
                            );
                            None
                        }
                    };

                    // Verify manifest signature (fail-closed)
                    if let Some(ref m) = manifest {
                        if let Ok(pk_hex) = std::env::var("EPHEMERALML_MODEL_SIGNING_PUBKEY") {
                            let pk_bytes = hex::decode(&pk_hex).map_err(|e| {
                                format!("EPHEMERALML_MODEL_SIGNING_PUBKEY: invalid hex: {}", e)
                            })?;
                            if pk_bytes.len() != 32 {
                                return Err(format!(
                                    "EPHEMERALML_MODEL_SIGNING_PUBKEY must be 64 hex chars (32 bytes), got {}",
                                    pk_bytes.len()
                                ).into());
                            }
                            m.verify(&pk_bytes).map_err(|e| {
                                format!("Manifest signature verification failed: {}", e)
                            })?;
                            info!(step = "manifest", "Manifest signature verified");
                        }
                    }

                    let kms_key_short = &kms_key[kms_key.rfind('/').map(|i| i + 1).unwrap_or(0)..];
                    info!(step = "kms_decrypt", key = %kms_key_short, "Decrypting DEK via Cloud KMS");

                    // Auto-detect: use Confidential Space Launcher path if available,
                    // otherwise fall back to Cloud Attestation API path.
                    let launcher_socket =
                        std::path::Path::new("/run/container_launcher/teeserver.sock");
                    let dek = if launcher_socket.exists() {
                        info!(
                            step = "kms_decrypt",
                            path = "cs_launcher",
                            "Using Confidential Space Launcher KMS path"
                        );
                        let cs_kms =
                            ephemeral_ml_enclave::cs_kms_client::CsKmsClient::new(wip_audience);
                        cs_kms.decrypt(kms_key, &wrapped_dek).await?
                    } else {
                        info!(
                            step = "kms_decrypt",
                            path = "cloud_attestation_api",
                            "Using Cloud Attestation API KMS path"
                        );
                        // --synthetic is already rejected in release builds (see above).
                        // In debug builds, allow synthetic for local development.
                        let kms_provider = if args.synthetic {
                            warn!("Using synthetic TDX provider for KMS — NOT FOR PRODUCTION");
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
                        kms_client.decrypt(kms_key, &wrapped_dek).await?
                    };

                    if dek.len() != 32 {
                        return Err(format!(
                            "Invalid DEK length from KMS: expected 32, got {}",
                            dek.len()
                        )
                        .into());
                    }

                    let dek_array: [u8; 32] = dek.try_into().unwrap();
                    let weights_bytes = decrypt_artifact(&encrypted_weights, &dek_array)?;

                    // Verify hash (required for remote sources)
                    {
                        use sha2::{Digest, Sha256};
                        let actual: [u8; 32] = Sha256::digest(&weights_bytes).into();
                        if let Some(expected) = &expected_model_hash {
                            if &actual != expected {
                                return Err(format!(
                                    "Model hash mismatch (gcs-kms): expected {}, got {}",
                                    hex::encode(expected),
                                    hex::encode(actual)
                                )
                                .into());
                            }
                            info!(step = "hash_verify", source = "gcs-kms", hash = %hex::encode(expected), "Model hash verified");
                        } else {
                            return Err("--expected-model-hash is required for gcs-kms source. \
                                Cannot verify model integrity without a pinned hash."
                                .into());
                        }

                        // Validate manifest hash if present
                        if let Some(ref m) = manifest {
                            m.validate_hash(&actual)
                                .map_err(|e| format!("Manifest hash validation failed: {}", e))?;
                            info!(
                                step = "manifest",
                                "Manifest hash validated against decrypted weights"
                            );
                        }

                        loaded_model_hash = Some(actual);
                    }

                    engine.register_model(
                        &args.model_id,
                        &config_bytes,
                        &weights_bytes,
                        &tokenizer_bytes,
                    )?;

                    info!(
                        step = "model_load",
                        source = "gcs-kms",
                        model_id = %args.model_id,
                        elapsed_ms = load_start.elapsed().as_secs_f64() * 1000.0,
                        size_mb = weights_bytes.len() as f64 / (1024.0 * 1024.0),
                        "Model loaded"
                    );
                }
                "gcs" => {
                    info!(step = "model_load", source = "gcs", bucket = %args.gcp_bucket, prefix = %args.gcp_model_prefix, "Fetching model from GCS");
                    let gcs = GcsModelLoader::new(&args.gcp_bucket);

                    let expected = expected_model_hash.as_ref().ok_or(
                        "--expected-model-hash is required for gcs source. \
                         Cannot verify model integrity without a pinned hash.",
                    )?;

                    let config_path = format!("{}/config.json", args.gcp_model_prefix);
                    let tokenizer_path = format!("{}/tokenizer.json", args.gcp_model_prefix);
                    let weights_path = format!("{}/model.safetensors", args.gcp_model_prefix);
                    let manifest_path = format!("{}/manifest.json", args.gcp_model_prefix);

                    let (config_art, tokenizer_art, manifest_art) = tokio::join!(
                        gcs.fetch_object(&config_path),
                        gcs.fetch_object(&tokenizer_path),
                        gcs.fetch_object(&manifest_path),
                    );
                    let config_bytes = config_art?.bytes;
                    let tokenizer_bytes = tokenizer_art?.bytes;

                    // Determine if manifest verification is required (pubkey configured)
                    let require_manifest =
                        std::env::var("EPHEMERALML_MODEL_SIGNING_PUBKEY").is_ok();

                    // Parse manifest — fail-closed if pubkey is set
                    let manifest = match manifest_art {
                        Ok(art) => {
                            match ephemeral_ml_common::ModelManifest::from_json(&art.bytes) {
                                Ok(m) => {
                                    info!(step = "manifest", model_id = %m.model_id, version = %m.version, "Manifest found");
                                    Some(m)
                                }
                                Err(e) => {
                                    if require_manifest {
                                        return Err(format!(
                                            "manifest.json parse failed and EPHEMERALML_MODEL_SIGNING_PUBKEY is set: {}", e
                                        ).into());
                                    }
                                    warn!(step = "manifest", error = %e, "manifest.json parse failed");
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            if require_manifest {
                                return Err(format!(
                                    "manifest.json missing from GCS but EPHEMERALML_MODEL_SIGNING_PUBKEY is set \
                                     (manifest is required when signing pubkey is configured): {}", e
                                ).into());
                            }
                            info!(
                                step = "manifest",
                                "No manifest.json in GCS (backwards-compatible mode)"
                            );
                            None
                        }
                    };

                    // Verify manifest signature (fail-closed)
                    if let Some(ref m) = manifest {
                        if let Ok(pk_hex) = std::env::var("EPHEMERALML_MODEL_SIGNING_PUBKEY") {
                            let pk_bytes = hex::decode(&pk_hex).map_err(|e| {
                                format!("EPHEMERALML_MODEL_SIGNING_PUBKEY: invalid hex: {}", e)
                            })?;
                            if pk_bytes.len() != 32 {
                                return Err(format!(
                                    "EPHEMERALML_MODEL_SIGNING_PUBKEY must be 64 hex chars (32 bytes), got {}",
                                    pk_bytes.len()
                                ).into());
                            }
                            m.verify(&pk_bytes).map_err(|e| {
                                format!("Manifest signature verification failed: {}", e)
                            })?;
                            info!(step = "manifest", "Manifest signature verified");
                        }
                    }

                    let weights_bytes = gcs.fetch_verified(&weights_path, expected).await?;

                    // Validate manifest hash if present
                    if let Some(ref m) = manifest {
                        m.validate_hash(expected)
                            .map_err(|e| format!("Manifest hash validation failed: {}", e))?;
                        info!(
                            step = "manifest",
                            "Manifest hash validated against fetched weights"
                        );
                    }

                    engine.register_model(
                        &args.model_id,
                        &config_bytes,
                        &weights_bytes,
                        &tokenizer_bytes,
                    )?;

                    loaded_model_hash = Some(*expected);
                    info!(step = "hash_verify", source = "gcs", hash = %hex::encode(expected), "Model hash verified");

                    info!(
                        step = "model_load",
                        source = "gcs",
                        model_id = %args.model_id,
                        elapsed_ms = load_start.elapsed().as_secs_f64() * 1000.0,
                        "Model loaded"
                    );
                }
                other => {
                    return Err(format!(
                        "Unknown --model-source '{}'. Valid: local, gcs, gcs-kms",
                        other
                    )
                    .into());
                }
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
                            info!(
                                step = "cs_identity",
                                issuer = %claims.iss,
                                subject = %claims.sub,
                                swname = %claims.swname,
                                "Confidential Space identity obtained"
                            );
                        }
                        Err(e) => {
                            warn!(step = "cs_identity", error = %e, "CS token received but claims parse failed");
                        }
                    },
                    Err(_) => {
                        info!(
                            step = "cs_identity",
                            "Launcher socket not available (not running in Confidential Space)"
                        );
                    }
                }
            }

            // 4. Emit trust evidence bundle and capture boot attestation hash
            let boot_attestation_hash: [u8; 32];
            {
                use ephemeral_ml_enclave::tee_provider::TeeAttestationEnvelope;
                use ephemeral_ml_enclave::trust_evidence::TrustEvidenceBundle;
                use ephemeral_ml_enclave::AttestationProvider;

                let boot_nonce = [0u8; 32];
                let boot_doc = tee_provider.generate_attestation(&boot_nonce, receipt_pk)?;
                let envelope = TeeAttestationEnvelope::from_cbor(&boot_doc.signature)
                    .map_err(|e| format!("trust evidence: {}", e))?;
                let raw_quote = &envelope.tdx_wire[16..];

                let mut bundle = TrustEvidenceBundle::from_boot(
                    raw_quote,
                    tee_provider.get_hpke_public_key(),
                    receipt_pk,
                    &args.model_id,
                    None,
                    None,
                    "tdx",
                );
                bundle.model_hash = loaded_model_hash;
                bundle.print();

                // Capture quote hash for binding receipts to TDX attestation
                boot_attestation_hash = bundle.quote_hash;
            }

            // 5. Create transport attestation bridge (for SecureChannel handshake)
            // --synthetic already rejected in release builds at startup.
            let bridge_provider = if args.synthetic {
                warn!("Using synthetic TDX provider for transport bridge — NOT FOR PRODUCTION");
                TeeAttestationProvider::synthetic()
            } else if has_tsm {
                TeeAttestationProvider::new()?
            } else if cs_mode {
                // CS mode without configfs-tsm: Launcher handles attestation,
                // transport uses synthetic quotes as placeholder.
                warn!("CS mode without configfs-tsm — transport bridge uses synthetic quotes");
                TeeAttestationProvider::synthetic()
            } else {
                return Err("No TDX attestation source for transport bridge. \
                    Deploy on TDX CVM or Confidential Space."
                    .into());
            };
            let bridge = TeeAttestationBridge::new(bridge_provider, receipt_pk);

            // Use TDX verifier for peer verification with measurement pinning.
            // Fail-closed: require MRTD in non-synthetic mode.
            let peer_mrtd: Option<Vec<u8>> = args
                .expected_mrtd
                .as_ref()
                .and_then(|hex_str| hex::decode(hex_str).ok())
                .filter(|bytes| bytes.len() == 48);
            if peer_mrtd.is_none() && !args.synthetic && !cs_mode && !args.direct {
                return Err(
                    "--expected-mrtd (or EPHEMERALML_EXPECTED_MRTD env) is required in GCP mode. \
                     Peer TDX measurements must be pinned for production use. \
                     Use --synthetic to skip this check in development, \
                     or --direct to run single-server mode without peer verification."
                        .into(),
                );
            }
            let verifier = confidential_ml_transport::attestation::tdx::TdxVerifier::new(peer_mrtd);

            // Direct mode: single-port SecureChannel server, no pipeline orchestrator.
            // Clients are external (not in TEEs), so use MockVerifier to accept
            // their mock attestation. The server still presents its TDX attestation
            // via the bridge — one-way attestation model.
            if args.direct {
                info!(
                    step = "boot_evidence",
                    mode = "direct",
                    quote_hash = %hex::encode(boot_attestation_hash),
                    synthetic = args.synthetic,
                    "Direct mode: accepting client connections on 0.0.0.0:9000"
                );
                let client_verifier = confidential_ml_transport::MockVerifier::new();
                run_direct_tcp(
                    engine,
                    tee_provider,
                    receipt_key,
                    "0.0.0.0:9000",
                    &bridge,
                    &client_verifier,
                    boot_attestation_hash,
                )
                .await
                .map_err(|e| -> Box<dyn std::error::Error> { e })?;
                return Ok(());
            }

            // Pipeline mode: orchestrator connects to control, then data channels.
            let executor = EphemeralStageExecutor::new(engine, tee_provider, receipt_key);

            // Use configurable addresses (default: 0.0.0.0:9000/9001/9002 for GCP)
            let gcp_control = if args.control_addr == "127.0.0.1:9000" {
                "0.0.0.0:9000".to_string()
            } else {
                args.control_addr.clone()
            };
            let gcp_data_in = if args.data_in_addr == "127.0.0.1:9001" {
                "0.0.0.0:9001".to_string()
            } else {
                args.data_in_addr.clone()
            };
            let gcp_data_out = if args.data_out_target == "127.0.0.1:9002" {
                "0.0.0.0:9002".to_string()
            } else {
                args.data_out_target.clone()
            };

            info!(
                step = "pipeline",
                control = %gcp_control,
                data_in = %gcp_data_in,
                data_out = %gcp_data_out,
                "Stage worker starting"
            );

            run_stage_tcp(
                executor,
                StageConfig::default(),
                &gcp_control,
                &gcp_data_in,
                gcp_data_out.parse()?,
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

    info!("EphemeralML Enclave v2.0");

    #[cfg(feature = "mock")]
    {
        info!("EphemeralML Enclave (Mock Mode)");

        // Load model weights
        let load_start = std::time::Instant::now();

        let config_path = args.model_dir.join("config.json");
        let tokenizer_path = args.model_dir.join("tokenizer.json");
        let weights_path = args.model_dir.join("model.safetensors");

        info!(step = "model_load", source = "local", path = %args.model_dir.display(), "Loading model");

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
        info!(
            step = "model_load",
            source = "local",
            model_id = %args.model_id,
            elapsed_ms = load_elapsed.as_secs_f64() * 1000.0,
            size_mb = weights_bytes.len() as f64 / (1024.0 * 1024.0),
            "Model loaded"
        );

        info!("Starting pipeline stage worker on TCP...");

        use confidential_ml_transport::MockProvider;
        use ephemeral_ml_enclave::mock::MockAttestationProvider;

        let mock_provider = MockAttestationProvider::new();
        let receipt_key = ReceiptSigningKey::generate()?;
        let _receipt_pk = receipt_key.public_key_bytes();

        // Use transport-compatible MockProvider for handshake (matches host's MockVerifier)
        let transport_provider = MockProvider::new();
        let verifier = MockVerifier::new();

        if args.direct {
            let receipt_pk = receipt_key.public_key_bytes();

            // Mock mode has no hardware attestation. Use [0; 32] sentinel.
            // The client check skips when receipt has zero attestation hash.
            // Real attestation binding happens in GCP mode via boot_attestation_hash.
            let mock_attestation_hash: [u8; 32] = [0u8; 32];

            // Wrap MockProvider to embed receipt signing key as user_data.
            // This preserves the MOCK_ATT_V1 format (so MockVerifier works) while
            // passing EphemeralUserData so the client can extract the signing key.
            let ud = ephemeral_ml_common::transport_types::EphemeralUserData::new(
                receipt_pk,
                1,
                vec!["gateway".to_string()],
            );
            let ud_cbor = ud.to_cbor().expect("CBOR encode");
            let mock_transport = MockProviderWithUserData(ud_cbor);

            let client_verifier = MockVerifier::new();

            info!(
                step = "boot_evidence",
                mode = "direct",
                "Mock direct mode: accepting client connections on 127.0.0.1:9000"
            );
            run_direct_tcp(
                engine,
                mock_provider,
                receipt_key,
                "127.0.0.1:9000",
                &mock_transport,
                &client_verifier,
                mock_attestation_hash,
            )
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e })?;
        } else {
            let executor = EphemeralStageExecutor::new(engine, mock_provider, receipt_key);

            info!(
                step = "pipeline",
                control = %args.control_addr,
                data_in = %args.data_in_addr,
                data_out = %args.data_out_target,
                "Stage worker starting"
            );

            run_stage_tcp(
                executor,
                StageConfig::default(),
                &args.control_addr,
                &args.data_in_addr,
                args.data_out_target.parse()?,
                &transport_provider,
                &verifier,
            )
            .await?;
        }
    }

    #[cfg(feature = "production")]
    {
        info!("EphemeralML Enclave (Production Mode)");

        let attestation_provider = DefaultAttestationProvider::new()?;
        let engine = CandleInferenceEngine::new()?;

        // Generate receipt signing key early — needed for KMS attestation binding
        let receipt_key = ReceiptSigningKey::generate()?;
        let receipt_pk = receipt_key.public_key_bytes();

        // Connectivity health check
        info!(step = "health_check", "Starting connectivity health check");
        use ephemeral_ml_enclave::kms_client::KmsClient;
        use ephemeral_ml_enclave::model_loader::ModelLoader;

        let kms_client = KmsClient::new(attestation_provider.clone(), receipt_pk);

        // Load trusted model signing public key from environment (hex-encoded Ed25519 public key)
        let trusted_signing_key: [u8; 32] = {
            let key_hex = std::env::var("EPHEMERALML_MODEL_SIGNING_PUBKEY").unwrap_or_else(|_| {
                // Default to the policy root public key (same trust anchor)
                "12740b4f2ff1f9dac52cac6db77f3a57950fb15134c8580295c98bd809673444".to_string()
            });
            let key_bytes = hex::decode(&key_hex).map_err(|e| {
                format!("EPHEMERALML_MODEL_SIGNING_PUBKEY must be valid hex: {}", e)
            })?;
            if key_bytes.len() != 32 || key_bytes.iter().all(|&b| b == 0) {
                return Err("Model signing key must be 32 non-zero bytes".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key_bytes);
            arr
        };
        let loader = ModelLoader::new(kms_client, trusted_signing_key);

        let expected_encrypted_hash =
            hex::decode("542c469d0d4c936b05fc57e64e0f5acd1048f186c4705801dcddf718cfde9b74")
                .unwrap();

        info!(
            step = "model_load",
            source = "s3",
            "Fetching test-model-001 from S3 via Host Proxy"
        );
        let proxy = loader.kms_client().proxy_client();
        match proxy.fetch_model("test-model-001").await {
            Ok(bytes) => {
                info!(
                    step = "model_load",
                    bytes = bytes.len(),
                    "Fetched model from S3"
                );
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let hash = hasher.finalize();
                if hash.as_slice() == expected_encrypted_hash.as_slice() {
                    info!(step = "hash_verify", "Encrypted artifact hash matches");
                } else {
                    error!(step = "hash_verify", expected = %hex::encode(&expected_encrypted_hash), actual = %hex::encode(&hash), "Hash mismatch");
                }
            }
            Err(e) => warn!(
                step = "model_load",
                error = ?e,
                "S3 fetch failed (expected if model not uploaded)"
            ),
        }

        // Start stage worker
        let executor =
            EphemeralStageExecutor::new(engine, attestation_provider.clone(), receipt_key);
        let bridge = AttestationBridge::new(attestation_provider, receipt_pk);

        // Build NitroVerifier with expected PCR measurements for peer verification.
        // In single-stage mode this verifies pipeline orchestrator connections.
        // PCRs are loaded from environment: EPHEMERALML_EXPECTED_PCR0, _PCR1, _PCR2 (hex).
        let mut expected_pcrs = std::collections::BTreeMap::new();
        for i in 0..3u16 {
            if let Ok(hex_str) = std::env::var(format!("EPHEMERALML_EXPECTED_PCR{}", i)) {
                match hex::decode(&hex_str) {
                    Ok(bytes) if bytes.len() == 48 => {
                        expected_pcrs.insert(i as usize, bytes);
                        info!(
                            step = "pcr_pin",
                            pcr = i,
                            prefix = &hex_str[..16],
                            "Pinned PCR"
                        );
                    }
                    Ok(bytes) => {
                        warn!(
                            step = "pcr_pin",
                            pcr = i,
                            len = bytes.len(),
                            "EPHEMERALML_EXPECTED_PCR has wrong length, ignoring"
                        );
                    }
                    Err(e) => {
                        warn!(step = "pcr_pin", pcr = i, error = %e, "EPHEMERALML_EXPECTED_PCR invalid hex, ignoring");
                    }
                }
            }
        }
        if expected_pcrs.is_empty() {
            warn!(step = "pcr_pin", "No EPHEMERALML_EXPECTED_PCR0/1/2 set. Peer Nitro attestation measurements are NOT pinned.");
        }
        let verifier =
            NitroVerifier::new(expected_pcrs).expect("Failed to initialize NitroVerifier");

        info!(
            step = "pipeline",
            control = "127.0.0.1:5000",
            data_in = "127.0.0.1:5001",
            data_out = "127.0.0.1:5002",
            "Production stage worker starting"
        );

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
