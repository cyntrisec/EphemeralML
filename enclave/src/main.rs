#[cfg(any(feature = "mock", feature = "gcp", feature = "production"))]
use ephemeral_ml_enclave::candle_engine::CandleInferenceEngine;
#[cfg(any(feature = "mock", feature = "gcp"))]
use ephemeral_ml_enclave::server::run_direct_tcp;
#[cfg(any(feature = "mock", feature = "gcp"))]
use ephemeral_ml_enclave::server::run_stage_tcp;
#[cfg(any(feature = "mock", feature = "gcp", feature = "production"))]
use ephemeral_ml_enclave::stage_executor::EphemeralStageExecutor;

#[cfg(any(feature = "mock", feature = "gcp", feature = "production"))]
use confidential_ml_pipeline::StageConfig;
#[cfg(feature = "mock")]
use confidential_ml_transport::MockVerifier;
#[cfg(any(feature = "mock", feature = "gcp", feature = "production"))]
use ephemeral_ml_common::ReceiptSigningKey;

use clap::Parser;
use std::path::PathBuf;
#[allow(unused_imports)]
use tracing::{error, info, warn};

#[cfg(feature = "production")]
use ephemeral_ml_enclave::attestation_bridge::AttestationBridge;
#[cfg(feature = "production")]
use ephemeral_ml_enclave::DefaultAttestationProvider;

#[cfg(any(feature = "mock", feature = "gcp", feature = "production"))]
fn host_control_plane_stage_config() -> StageConfig {
    // The stage peer is the host/orchestrator control plane, not another TEE.
    // This permits an unmeasured host peer by design. Do not use this channel
    // as evidence of peer TEE identity; AIR TEE provenance is established by
    // the receipt signing key's binding to platform attestation.
    StageConfig {
        session_config: confidential_ml_transport::session::SessionConfig::builder()
            .allow_empty_measurements()
            .build()
            .expect("host-control-plane stage config must be valid"),
        ..StageConfig::default()
    }
}

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

/// Verifier for host/control-plane peers in one-way attestation deployments.
///
/// The host/orchestrator is outside the enclave and cannot produce TEE evidence.
/// This verifier accepts the transport's minimal host attestation envelope only
/// to bind the session transcript, while AIR TEE provenance is established by
/// the enclave's own platform attestation and receipt signing key.
#[cfg(any(feature = "gcp", feature = "production"))]
struct OneWayHostVerifier;

#[cfg(any(feature = "gcp", feature = "production"))]
impl OneWayHostVerifier {
    fn new() -> Self {
        Self
    }
}

#[cfg(any(feature = "gcp", feature = "production"))]
#[async_trait::async_trait]
impl confidential_ml_transport::AttestationVerifier for OneWayHostVerifier {
    async fn verify(
        &self,
        doc: &confidential_ml_transport::attestation::types::AttestationDocument,
    ) -> Result<
        confidential_ml_transport::attestation::types::VerifiedAttestation,
        confidential_ml_transport::error::AttestError,
    > {
        use confidential_ml_transport::error::AttestError;
        use sha2::{Digest, Sha256};
        use std::collections::BTreeMap;

        let raw = &doc.raw;
        if !raw.starts_with(b"MOCK_ATT_V1\0") {
            return Err(AttestError::VerificationFailed(
                "host control-plane attestation envelope has unexpected format".to_string(),
            ));
        }

        let mut offset = 12;
        let mut fields = Vec::with_capacity(3);
        for _ in 0..3 {
            if offset + 4 > raw.len() {
                return Err(AttestError::VerificationFailed(
                    "truncated host control-plane attestation envelope".to_string(),
                ));
            }
            let len = u32::from_le_bytes([
                raw[offset],
                raw[offset + 1],
                raw[offset + 2],
                raw[offset + 3],
            ]) as usize;
            offset += 4;
            if len == 0 {
                fields.push(None);
            } else {
                if offset + len > raw.len() {
                    return Err(AttestError::VerificationFailed(
                        "truncated host control-plane attestation field".to_string(),
                    ));
                }
                fields.push(Some(raw[offset..offset + len].to_vec()));
                offset += len;
            }
        }

        Ok(
            confidential_ml_transport::attestation::types::VerifiedAttestation {
                document_hash: Sha256::digest(raw).into(),
                user_data: fields[0].clone(),
                nonce: fields[1].clone(),
                public_key: fields[2].clone(),
                measurements: BTreeMap::new(),
            },
        )
    }
}

#[cfg(feature = "gcp")]
fn allow_unsigned_models_for_poc() -> bool {
    std::env::var("EPHEMERALML_ALLOW_UNSIGNED_MODELS")
        .map(|v| v == "I_UNDERSTAND")
        .unwrap_or(false)
}

#[cfg(feature = "gcp")]
fn model_signing_pubkey_bytes() -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
    let Some(pk_hex) = std::env::var("EPHEMERALML_MODEL_SIGNING_PUBKEY")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    else {
        return Ok(None);
    };

    let pk_bytes = hex::decode(&pk_hex)
        .map_err(|e| format!("EPHEMERALML_MODEL_SIGNING_PUBKEY: invalid hex: {e}"))?;
    if pk_bytes.len() != 32 {
        return Err(format!(
            "EPHEMERALML_MODEL_SIGNING_PUBKEY must be 64 hex chars (32 bytes), got {}",
            pk_bytes.len()
        )
        .into());
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&pk_bytes);
    Ok(Some(key))
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

    /// [DEV ONLY] Use synthetic TDX quotes (no real hardware). Rejected in release builds.
    /// For local development/testing with --smoke-tdx. Never use in production.
    #[arg(long)]
    synthetic: bool,

    /// GCP mode: run as a single-binary Confidential VM (TDX) with direct GCS/KMS access.
    #[arg(long)]
    gcp: bool,

    /// Model source. Required for GCP remote sources; optional in Nitro.
    ///   local:   read from --model-dir (bundled in container, no KMS)
    ///   gcs:     fetch plaintext from GCS (requires --expected-model-hash)
    ///   gcs-kms: fetch encrypted model from GCS, decrypt via attestation-bound Cloud KMS (requires --expected-model-hash)
    ///   aws-s3-kms: fetch encrypted model from S3 via VSock proxy and unwrap DEK via AWS KMS RecipientInfo
    #[arg(long, env = "EPHEMERALML_MODEL_SOURCE")]
    model_source: Option<String>,

    /// Local signed model manifest path for Nitro aws-s3-kms mode.
    #[arg(
        long,
        env = "EPHEMERALML_AWS_MODEL_MANIFEST_PATH",
        default_value = "/app/test_assets/minilm/manifest.json"
    )]
    aws_model_manifest_path: PathBuf,

    /// Local KMS-wrapped DEK path for Nitro aws-s3-kms mode.
    #[arg(
        long,
        env = "EPHEMERALML_AWS_WRAPPED_DEK_PATH",
        default_value = "/app/test_assets/minilm/wrapped_dek.bin"
    )]
    aws_wrapped_dek_path: PathBuf,

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

    /// Model format for loading.
    ///   safetensors: config.json + tokenizer.json + model.safetensors (BERT-style)
    ///   gguf:        tokenizer.json + model.gguf (quantized Llama/Mistral/Phi)
    #[arg(long, env = "EPHEMERALML_MODEL_FORMAT", default_value = "safetensors")]
    model_format: String,

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

    /// Issuer identifier for AIR v1 receipts (e.g. domain name).
    #[arg(
        long,
        env = "EPHEMERALML_RECEIPT_ISSUER",
        default_value = "cyntrisec.com"
    )]
    receipt_issuer: String,
}

/// Classify an error message into a structured exit code for CI/script parsing.
///
/// Exit codes:
///   1  — general/unknown error
///   10 — configuration error (missing flags, bad env vars, feature not enabled)
///   11 — model loading error (hash mismatch, fetch failure, manifest error)
///   12 — attestation/KMS error (TEE unavailable, KMS decrypt failure, DEK error)
///   13 — network/bind error (address in use, connection refused)
fn classify_exit_code(err: &str) -> i32 {
    let e = err.to_lowercase();

    // Configuration errors (exit 10)
    if e.contains("--model-source is required")
        || e.contains("requires --gcp-kms-key")
        || e.contains("requires --gcp-wip-audience")
        || e.contains("unknown --model-source")
        || e.contains("--synthetic is not allowed")
        || e.contains("--expected-mrtd")
        || e.contains("requires the `tdx` feature")
        || e.contains("requires the `gcp` feature")
        || e.contains("model signing key must be")
        || e.contains("ephemeralml_model_signing_pubkey")
        || e.contains("unknown --model-format")
        || e.contains("aws-s3-kms currently supports")
    {
        return 10;
    }

    // Model loading errors (exit 11)
    if e.contains("model hash mismatch")
        || e.contains("failed to read config.json")
        || e.contains("failed to read tokenizer.json")
        || e.contains("failed to read model.safetensors")
        || e.contains("failed to read model.gguf")
        || e.contains("model directory does not exist")
        || e.contains("manifest")
        || e.contains("--expected-model-hash")
        || e.contains("model decomposition")
        || e.contains("register_model")
    {
        return 11;
    }

    // Attestation/KMS errors (exit 12)
    if e.contains("attestation")
        || e.contains("kms")
        || e.contains("invalid dek length")
        || e.contains("no tdx attestation source")
        || e.contains("configfs-tsm")
    {
        return 12;
    }

    // Network/bind errors (exit 13)
    if e.contains("address already in use")
        || e.contains("connection refused")
        || e.contains("addr")
        || e.contains("bind")
    {
        return 13;
    }

    1
}

/// Default filesystem path for exporting the platform-evidence bundle.
///
/// The attested `platform_evidence_hash` in transport user-data commits to
/// this bundle. Verifiers need the bundle bytes (not just the hash) to check
/// the binding via [`ephemeral_ml_common::PlatformEvidenceBundle::verify_binding`].
/// Clients can fetch the same bytes in-band via the direct-mode
/// `get_platform_evidence` request; this file export is kept as a fallback
/// for operator-driven retrieval (scp, `ephemeralml gcp verify`, etc.).
#[cfg(any(feature = "gcp", feature = "production"))]
pub const PLATFORM_EVIDENCE_EXPORT_PATH: &str = "/tmp/ephemeralml-platform-evidence.cbor";

/// Write the already-encoded platform-evidence CBOR to
/// `PLATFORM_EVIDENCE_EXPORT_PATH` and log its location. Failures are
/// logged but non-fatal: the attested hash is already committed in
/// `user_data`; losing the export file only degrades operator
/// observability, it does not weaken the attestation.
#[cfg(any(feature = "gcp", feature = "production"))]
fn export_platform_evidence_bytes(bytes: &[u8], hash: &[u8; 32]) {
    match std::fs::write(PLATFORM_EVIDENCE_EXPORT_PATH, bytes) {
        Ok(()) => info!(
            path = PLATFORM_EVIDENCE_EXPORT_PATH,
            bytes = bytes.len(),
            hash = %hex::encode(hash),
            "Exported platform-evidence bundle for operator retrieval"
        ),
        Err(e) => warn!(
            path = PLATFORM_EVIDENCE_EXPORT_PATH,
            error = %e,
            "Failed to write platform-evidence bundle; operators will need \
             the bundle delivered via another channel to verify the binding"
        ),
    }
}

#[tokio::main]
async fn main() {
    // Initialize structured logging before anything else
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

    if let Err(e) = run().await {
        let msg = e.to_string();
        let exit_code = classify_exit_code(&msg);
        error!(exit_code = exit_code, "Fatal: {}", msg);
        std::process::exit(exit_code);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
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
            let doc =
                provider.generate_attestation(&nonce, receipt_key.public_key_bytes(), None)?;

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
                // Confidential Space detected without configfs-tsm.
                // Boot-time TDX measurements are unavailable without configfs-tsm,
                // but the Launcher JWT provides equivalent attestation for transport.
                // Use a synthetic TeeAttestationProvider for HPKE keypair generation
                // and boot evidence; transport attestation uses the CS Launcher JWT
                // bridge (set up in step 5 below).
                info!(
                    step = "attestation",
                    mode = "cs_launcher",
                    "Confidential Space detected (no configfs-tsm). Transport attestation \
                    will use Launcher JWT. Boot evidence from synthetic provider."
                );
                TeeAttestationProvider::synthetic()
            } else {
                return Err("No TDX attestation source available.\n\
                    \n  Expected one of:\n    \
                    - /sys/kernel/config/tsm/report (configfs-tsm on TDX CVM)\n    \
                    - /run/container_launcher/teeserver.sock (Confidential Space)\n\
                    \n  For local development: use --synthetic (debug builds only).\n  \
                    For production: deploy on a TDX CVM or Confidential Space."
                    .into());
            };

            let receipt_key = ReceiptSigningKey::generate()?;
            let receipt_pk = receipt_key.public_key_bytes();

            // 2. Load model via explicit --model-source
            let model_format = args.model_format.as_str();
            if model_format != "safetensors" && model_format != "gguf" {
                return Err(format!(
                    "Unknown --model-format '{}'. Valid: safetensors, gguf",
                    model_format
                )
                .into());
            }

            let engine = CandleInferenceEngine::new()?;
            let load_start = std::time::Instant::now();

            // Parse expected model hash if provided.
            // Empty strings from env vars (e.g. EPHEMERALML_EXPECTED_MODEL_HASH="") are treated as None.
            let expected_model_hash: Option<[u8; 32]> = match &args.expected_model_hash {
                Some(hex_str) if !hex_str.is_empty() => {
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
                _ => None,
            };

            // Track the verified model weights hash for trust evidence.
            // Every match arm below assigns this before it is read.
            #[allow(unused_assignments)]
            let mut loaded_model_hash: Option<[u8; 32]> = None;
            #[allow(unused_assignments)]
            let mut loaded_model_hash_scheme: Option<String> = None;
            #[allow(unused_assignments)]
            let mut loaded_model_identity_coverage: Option<
                std::collections::BTreeMap<String, bool>,
            > = None;

            // Track model manifest JSON for client sidecar evidence.
            #[allow(unused_assignments)]
            let mut captured_manifest_json: Option<String> = None;

            match model_source {
                "local" => {
                    if !args.model_dir.exists() {
                        return Err(format!(
                            "--model-source=local but model directory does not exist: {}",
                            args.model_dir.display()
                        )
                        .into());
                    }
                    info!(step = "model_load", source = "local", format = model_format, path = %args.model_dir.display(), "Loading model from local directory");

                    let tokenizer_bytes = std::fs::read(args.model_dir.join("tokenizer.json"))
                        .map_err(|e| format!("Failed to read tokenizer.json: {}", e))?;

                    if model_format == "gguf" {
                        // GGUF format: single model.gguf file (quantized Llama/Mistral/Phi)
                        let gguf_bytes = std::fs::read(args.model_dir.join("model.gguf"))
                            .map_err(|e| format!("Failed to read model.gguf: {}", e))?;

                        // Compute and verify model hash
                        {
                            use sha2::{Digest, Sha256};
                            let actual: [u8; 32] = Sha256::digest(&gguf_bytes).into();
                            if let Some(expected) = &expected_model_hash {
                                if &actual != expected {
                                    return Err(format!(
                                        "Model hash mismatch (local/gguf): expected {}, got {}",
                                        hex::encode(expected),
                                        hex::encode(actual)
                                    )
                                    .into());
                                }
                                info!(step = "hash_verify", hash = %hex::encode(expected), "Model hash verified");
                            } else {
                                warn!(
                                    step = "hash_verify",
                                    hash = %hex::encode(actual),
                                    "WARNING: No --expected-model-hash set for local source. \
                                     Model integrity is NOT pinned. Receipts will include the \
                                     computed hash but no external verification was performed. \
                                     Set --expected-model-hash for production deployments."
                                );
                            }
                            loaded_model_hash = Some(actual);
                        }

                        engine.register_model_gguf(
                            &args.model_id,
                            &gguf_bytes,
                            &tokenizer_bytes,
                        )?;

                        info!(
                            step = "model_load",
                            source = "local",
                            format = "gguf",
                            model_id = %args.model_id,
                            elapsed_ms = load_start.elapsed().as_secs_f64() * 1000.0,
                            size_mb = gguf_bytes.len() as f64 / (1024.0 * 1024.0),
                            "Model loaded"
                        );
                    } else {
                        // Safetensors format: config.json + model.safetensors (BERT-style)
                        let config_bytes = std::fs::read(args.model_dir.join("config.json"))
                            .map_err(|e| format!("Failed to read config.json: {}", e))?;
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
                            } else {
                                warn!(
                                    step = "hash_verify",
                                    hash = %hex::encode(actual),
                                    "WARNING: No --expected-model-hash set for local source. \
                                     Model integrity is NOT pinned. Set --expected-model-hash \
                                     for production deployments."
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
                            source = "local",
                            format = "safetensors",
                            model_id = %args.model_id,
                            elapsed_ms = load_start.elapsed().as_secs_f64() * 1000.0,
                            size_mb = weights_bytes.len() as f64 / (1024.0 * 1024.0),
                            "Model loaded"
                        );
                    }
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

                    info!(step = "model_load", source = "gcs-kms", format = model_format, bucket = %args.gcp_bucket, prefix = %args.gcp_model_prefix, "Fetching encrypted model from GCS");

                    let gcs = GcsModelLoader::new(&args.gcp_bucket);

                    // File names depend on model format
                    let weights_enc_name = if model_format == "gguf" {
                        "model.gguf.enc"
                    } else {
                        "model.safetensors.enc"
                    };

                    let tokenizer_path = format!("{}/tokenizer.json", args.gcp_model_prefix);
                    let weights_enc_path =
                        format!("{}/{}", args.gcp_model_prefix, weights_enc_name);
                    let dek_path = format!("{}/wrapped_dek.bin", args.gcp_model_prefix);
                    let manifest_path = format!("{}/manifest.json", args.gcp_model_prefix);

                    // Fetch artifacts in parallel. config.json is only needed for safetensors.
                    let config_path = format!("{}/config.json", args.gcp_model_prefix);
                    let (config_art, tokenizer_art, weights_enc_art, dek_art, manifest_art) = tokio::join!(
                        gcs.fetch_object(&config_path),
                        gcs.fetch_object(&tokenizer_path),
                        gcs.fetch_object(&weights_enc_path),
                        gcs.fetch_object(&dek_path),
                        gcs.fetch_object(&manifest_path),
                    );

                    // config.json is only required for safetensors format
                    let config_bytes = if model_format == "safetensors" {
                        Some(config_art?.bytes)
                    } else {
                        if let Err(e) = config_art {
                            info!(
                                step = "model_load",
                                "config.json not fetched (GGUF mode): {}", e
                            );
                        }
                        None
                    };
                    let tokenizer_bytes = tokenizer_art?.bytes;
                    let encrypted_weights = weights_enc_art?.bytes;
                    let wrapped_dek = dek_art?.bytes;

                    // Model approval is fail-closed by default. Unsigned model
                    // artifacts are allowed only under an explicit PoC override.
                    let allow_unsigned_models = allow_unsigned_models_for_poc();
                    let signing_pubkey = model_signing_pubkey_bytes()?;
                    let require_manifest = !allow_unsigned_models;

                    // Parse manifest — fail-closed unless the unsigned-model
                    // PoC override is explicitly acknowledged.
                    let manifest = match manifest_art {
                        Ok(art) => {
                            match ephemeral_ml_common::ModelManifest::from_json(&art.bytes) {
                                Ok(m) => {
                                    info!(step = "manifest", model_id = %m.model_id, version = %m.version, "Manifest found");
                                    // Capture raw manifest JSON for client sidecar evidence
                                    captured_manifest_json =
                                        String::from_utf8(art.bytes.clone()).ok();
                                    Some(m)
                                }
                                Err(e) => {
                                    if require_manifest {
                                        return Err(format!(
                                            "manifest.json parse failed; signed model manifest verification is required by default. \
                                             Set EPHEMERALML_MODEL_SIGNING_PUBKEY for production or \
                                             EPHEMERALML_ALLOW_UNSIGNED_MODELS=I_UNDERSTAND for internal PoC only: {}", e
                                        ).into());
                                    }
                                    warn!(step = "manifest", error = %e, "manifest.json parse failed under unsigned-model PoC override");
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            if require_manifest {
                                return Err(format!(
                                    "manifest.json missing from GCS; signed model manifest verification is required by default. \
                                     Set EPHEMERALML_MODEL_SIGNING_PUBKEY for production or \
                                     EPHEMERALML_ALLOW_UNSIGNED_MODELS=I_UNDERSTAND for internal PoC only: {}", e
                                ).into());
                            }
                            warn!(
                                step = "manifest",
                                "No manifest.json in GCS; continuing only because EPHEMERALML_ALLOW_UNSIGNED_MODELS=I_UNDERSTAND"
                            );
                            None
                        }
                    };

                    // Verify manifest signature (fail-closed).
                    let mut manifest_authoritative = false;
                    if let Some(ref m) = manifest {
                        if let Some(pk_bytes) = signing_pubkey {
                            m.verify(&pk_bytes).map_err(|e| {
                                format!("Manifest signature verification failed: {}", e)
                            })?;
                            manifest_authoritative = true;
                            info!(step = "manifest", "Manifest signature verified");
                        } else if require_manifest {
                            return Err(
                                "manifest.json found but EPHEMERALML_MODEL_SIGNING_PUBKEY is not set. \
                                 Signed model manifest verification is required by default; configure the public key \
                                 or set EPHEMERALML_ALLOW_UNSIGNED_MODELS=I_UNDERSTAND for internal PoC only."
                                    .into(),
                            );
                        } else {
                            warn!(
                                step = "manifest",
                                "manifest.json was not signature-verified because unsigned-model PoC override is enabled"
                            );
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

                        // Validate manifest hashes if present
                        if let Some(ref m) = manifest {
                            m.validate_hash(&actual).map_err(|e| {
                                format!("Manifest weight hash validation failed: {}", e)
                            })?;
                            info!(step = "manifest", "Manifest weight hash validated");

                            // Validate tokenizer hash if manifest includes it
                            {
                                use sha2::{Digest as _, Sha256};
                                let tok_actual: [u8; 32] = Sha256::digest(&tokenizer_bytes).into();
                                m.validate_tokenizer_hash(&tok_actual).map_err(|e| {
                                    format!("Manifest tokenizer hash validation failed: {}", e)
                                })?;
                                if m.tokenizer_hash.is_some() {
                                    info!(step = "manifest", "Manifest tokenizer hash validated");
                                }
                            }

                            // Validate config hash if manifest includes it (safetensors only)
                            if let Some(ref cb) = config_bytes {
                                use sha2::{Digest as _, Sha256};
                                let cfg_actual: [u8; 32] = Sha256::digest(cb).into();
                                m.validate_config_hash(&cfg_actual).map_err(|e| {
                                    format!("Manifest config hash validation failed: {}", e)
                                })?;
                                if m.config_hash.is_some() {
                                    info!(step = "manifest", "Manifest config hash validated");
                                }
                            }

                            // Log identity coverage
                            let coverage = m.identity_coverage();
                            info!(
                                step = "manifest",
                                weights = coverage["weights"],
                                tokenizer = coverage["tokenizer"],
                                config = coverage["config"],
                                adapters = coverage["adapters"],
                                "Model identity coverage"
                            );
                            if manifest_authoritative {
                                loaded_model_hash_scheme = Some("sha256-manifest".to_string());
                                loaded_model_identity_coverage = Some(
                                    coverage
                                        .into_iter()
                                        .map(|(k, v)| (k.to_string(), v))
                                        .collect(),
                                );
                            }
                        }

                        loaded_model_hash = Some(actual);
                    }

                    let effective_model_id = manifest
                        .as_ref()
                        .map(|m| m.model_id.as_str())
                        .unwrap_or(args.model_id.as_str());

                    if model_format == "gguf" {
                        engine.register_model_gguf(
                            effective_model_id,
                            &weights_bytes,
                            &tokenizer_bytes,
                        )?;
                    } else {
                        let config = config_bytes
                            .as_ref()
                            .ok_or("config.json required for safetensors format but not fetched")?;
                        engine.register_model(
                            effective_model_id,
                            config,
                            &weights_bytes,
                            &tokenizer_bytes,
                        )?;
                    }

                    // Also register under the CLI-provided model_id (e.g. "stage-0")
                    // so pipeline and verify scripts that use the default ID still work.
                    if effective_model_id != args.model_id {
                        engine.add_alias(&args.model_id, effective_model_id)?;
                        info!(
                            step = "model_alias",
                            alias = %args.model_id,
                            target = %effective_model_id,
                            "Registered model alias"
                        );
                    }

                    info!(
                        step = "model_load",
                        source = "gcs-kms",
                        format = model_format,
                        model_id = %effective_model_id,
                        elapsed_ms = load_start.elapsed().as_secs_f64() * 1000.0,
                        size_mb = weights_bytes.len() as f64 / (1024.0 * 1024.0),
                        "Model loaded"
                    );
                }
                "gcs" => {
                    info!(step = "model_load", source = "gcs", format = model_format, bucket = %args.gcp_bucket, prefix = %args.gcp_model_prefix, "Fetching model from GCS");
                    let gcs = GcsModelLoader::new(&args.gcp_bucket);

                    let expected = expected_model_hash.as_ref().ok_or(
                        "--expected-model-hash is required for gcs source. \
                         Cannot verify model integrity without a pinned hash.",
                    )?;

                    let weights_name = if model_format == "gguf" {
                        "model.gguf"
                    } else {
                        "model.safetensors"
                    };

                    let config_path = format!("{}/config.json", args.gcp_model_prefix);
                    let tokenizer_path = format!("{}/tokenizer.json", args.gcp_model_prefix);
                    let weights_path = format!("{}/{}", args.gcp_model_prefix, weights_name);
                    let manifest_path = format!("{}/manifest.json", args.gcp_model_prefix);

                    let (config_art, tokenizer_art, manifest_art) = tokio::join!(
                        gcs.fetch_object(&config_path),
                        gcs.fetch_object(&tokenizer_path),
                        gcs.fetch_object(&manifest_path),
                    );
                    // config.json only required for safetensors format
                    let config_bytes = if model_format == "safetensors" {
                        Some(config_art?.bytes)
                    } else {
                        if let Err(e) = config_art {
                            info!(
                                step = "model_load",
                                "config.json not fetched (GGUF mode): {}", e
                            );
                        }
                        None
                    };
                    let tokenizer_bytes = tokenizer_art?.bytes;

                    // Model approval is fail-closed by default. Unsigned model
                    // artifacts are allowed only under an explicit PoC override.
                    let allow_unsigned_models = allow_unsigned_models_for_poc();
                    let signing_pubkey = model_signing_pubkey_bytes()?;
                    let require_manifest = !allow_unsigned_models;

                    // Parse manifest — fail-closed unless the unsigned-model
                    // PoC override is explicitly acknowledged.
                    let manifest = match manifest_art {
                        Ok(art) => {
                            match ephemeral_ml_common::ModelManifest::from_json(&art.bytes) {
                                Ok(m) => {
                                    info!(step = "manifest", model_id = %m.model_id, version = %m.version, "Manifest found");
                                    // Capture raw manifest JSON for client sidecar evidence
                                    captured_manifest_json =
                                        String::from_utf8(art.bytes.clone()).ok();
                                    Some(m)
                                }
                                Err(e) => {
                                    if require_manifest {
                                        return Err(format!(
                                            "manifest.json parse failed; signed model manifest verification is required by default. \
                                             Set EPHEMERALML_MODEL_SIGNING_PUBKEY for production or \
                                             EPHEMERALML_ALLOW_UNSIGNED_MODELS=I_UNDERSTAND for internal PoC only: {}", e
                                        ).into());
                                    }
                                    warn!(step = "manifest", error = %e, "manifest.json parse failed under unsigned-model PoC override");
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            if require_manifest {
                                return Err(format!(
                                    "manifest.json missing from GCS; signed model manifest verification is required by default. \
                                     Set EPHEMERALML_MODEL_SIGNING_PUBKEY for production or \
                                     EPHEMERALML_ALLOW_UNSIGNED_MODELS=I_UNDERSTAND for internal PoC only: {}", e
                                ).into());
                            }
                            warn!(
                                step = "manifest",
                                "No manifest.json in GCS; continuing only because EPHEMERALML_ALLOW_UNSIGNED_MODELS=I_UNDERSTAND"
                            );
                            None
                        }
                    };

                    // Verify manifest signature (fail-closed).
                    let mut manifest_authoritative = false;
                    if let Some(ref m) = manifest {
                        if let Some(pk_bytes) = signing_pubkey {
                            m.verify(&pk_bytes).map_err(|e| {
                                format!("Manifest signature verification failed: {}", e)
                            })?;
                            manifest_authoritative = true;
                            info!(step = "manifest", "Manifest signature verified");
                        } else if require_manifest {
                            return Err(
                                "manifest.json found but EPHEMERALML_MODEL_SIGNING_PUBKEY is not set. \
                                 Signed model manifest verification is required by default; configure the public key \
                                 or set EPHEMERALML_ALLOW_UNSIGNED_MODELS=I_UNDERSTAND for internal PoC only."
                                    .into(),
                            );
                        } else {
                            warn!(
                                step = "manifest",
                                "manifest.json was not signature-verified because unsigned-model PoC override is enabled"
                            );
                        }
                    }

                    let weights_bytes = gcs.fetch_verified(&weights_path, expected).await?;

                    // Validate manifest hashes if present
                    if let Some(ref m) = manifest {
                        m.validate_hash(expected).map_err(|e| {
                            format!("Manifest weight hash validation failed: {}", e)
                        })?;
                        info!(
                            step = "manifest",
                            "Manifest weight hash validated against fetched weights"
                        );

                        // Validate tokenizer hash if manifest includes it
                        {
                            use sha2::{Digest as _, Sha256};
                            let tok_actual: [u8; 32] = Sha256::digest(&tokenizer_bytes).into();
                            m.validate_tokenizer_hash(&tok_actual).map_err(|e| {
                                format!("Manifest tokenizer hash validation failed: {}", e)
                            })?;
                            if m.tokenizer_hash.is_some() {
                                info!(step = "manifest", "Manifest tokenizer hash validated");
                            }
                        }

                        // Validate config hash if manifest includes it (safetensors only)
                        if let Some(ref cb) = config_bytes {
                            use sha2::{Digest as _, Sha256};
                            let cfg_actual: [u8; 32] = Sha256::digest(cb).into();
                            m.validate_config_hash(&cfg_actual).map_err(|e| {
                                format!("Manifest config hash validation failed: {}", e)
                            })?;
                            if m.config_hash.is_some() {
                                info!(step = "manifest", "Manifest config hash validated");
                            }
                        }

                        // Log identity coverage
                        let coverage = m.identity_coverage();
                        info!(
                            step = "manifest",
                            weights = coverage["weights"],
                            tokenizer = coverage["tokenizer"],
                            config = coverage["config"],
                            adapters = coverage["adapters"],
                            "Model identity coverage"
                        );
                        if manifest_authoritative {
                            loaded_model_hash_scheme = Some("sha256-manifest".to_string());
                            loaded_model_identity_coverage = Some(
                                coverage
                                    .into_iter()
                                    .map(|(k, v)| (k.to_string(), v))
                                    .collect(),
                            );
                        }
                    }

                    let effective_model_id = manifest
                        .as_ref()
                        .map(|m| m.model_id.as_str())
                        .unwrap_or(args.model_id.as_str());

                    if model_format == "gguf" {
                        engine.register_model_gguf(
                            effective_model_id,
                            &weights_bytes,
                            &tokenizer_bytes,
                        )?;
                    } else {
                        let config = config_bytes
                            .as_ref()
                            .ok_or("config.json required for safetensors format but not fetched")?;
                        engine.register_model(
                            effective_model_id,
                            config,
                            &weights_bytes,
                            &tokenizer_bytes,
                        )?;
                    }

                    loaded_model_hash = Some(*expected);
                    info!(step = "hash_verify", source = "gcs", hash = %hex::encode(expected), "Model hash verified");

                    // Also register under the CLI-provided model_id so
                    // pipeline and verify scripts that use the default ID still work.
                    if effective_model_id != args.model_id {
                        engine.add_alias(&args.model_id, effective_model_id)?;
                        info!(
                            step = "model_alias",
                            alias = %args.model_id,
                            target = %effective_model_id,
                            "Registered model alias"
                        );
                    }

                    info!(
                        step = "model_load",
                        source = "gcs",
                        format = model_format,
                        model_id = %effective_model_id,
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

            // 4. Emit trust evidence bundle and capture boot attestation hash + raw bytes
            let boot_attestation_hash: [u8; 32];
            let platform_evidence_hash: [u8; 32];
            let boot_attestation_bytes: std::sync::Arc<Vec<u8>>;
            let platform_evidence_bytes: std::sync::Arc<Vec<u8>>;
            {
                use ephemeral_ml_common::{
                    CloudEvidenceSummary, CpuEvidenceSummary, EvidenceBinding,
                    EvidenceVerifierSummary, MeasurementEntry, PlatformEvidenceBundle,
                    PLATFORM_EVIDENCE_V1,
                };
                use ephemeral_ml_enclave::tee_provider::TeeAttestationEnvelope;
                use ephemeral_ml_enclave::trust_evidence::TrustEvidenceBundle;
                use ephemeral_ml_enclave::AttestationProvider;

                let boot_nonce = [0u8; 32];
                let boot_doc = tee_provider.generate_attestation(&boot_nonce, receipt_pk, None)?;
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
                // Store raw attestation bytes for client sidecar evidence
                boot_attestation_bytes = std::sync::Arc::new(raw_quote.to_vec());

                let measurements = tee_provider.get_pcr_measurements()?;
                let platform_evidence = PlatformEvidenceBundle {
                    version: PLATFORM_EVIDENCE_V1,
                    platform_profile: if cs_mode {
                        "gcp-cs-tdx".to_string()
                    } else {
                        "gcp-cvm-tdx".to_string()
                    },
                    generated_at: ephemeral_ml_common::current_timestamp()?,
                    binding: EvidenceBinding {
                        receipt_signing_key: receipt_pk,
                        hpke_public_key: Some(tee_provider.get_hpke_public_key()),
                        model_id: args.model_id.clone(),
                        model_hash: loaded_model_hash,
                        base_attestation_hash: boot_attestation_hash,
                    },
                    cpu: Some(CpuEvidenceSummary {
                        tee_type: "tdx".to_string(),
                        measurement_type: "tdx-mrtd-rtmr".to_string(),
                        measurements: vec![
                            MeasurementEntry {
                                index: 0,
                                value: measurements.pcr0,
                            },
                            MeasurementEntry {
                                index: 1,
                                value: measurements.pcr1,
                            },
                            MeasurementEntry {
                                index: 2,
                                value: measurements.pcr2,
                            },
                        ],
                    }),
                    gpu: None,
                    cloud: Some(CloudEvidenceSummary {
                        attestation_source: if cs_mode {
                            "cs-tdx".to_string()
                        } else {
                            "gcp-tdx".to_string()
                        },
                        // Fetched at client-handshake time, not boot time: the
                        // launcher JWT's `iat` would change every reboot and
                        // churn the canonical bundle hash.
                        launcher_jwt_sha256: None,
                        // Requires a launcher-token fetch or metadata-server
                        // call — left for a later pass; the image digest is
                        // already committed elsewhere via container measurements.
                        image_digest: None,
                        project_id: Some(args.gcp_project.clone()),
                        // Zone is more specific than `gcp_location` (region);
                        // reading it needs the GCE metadata server. Deferred.
                        zone: None,
                    }),
                    verifier: EvidenceVerifierSummary {
                        cpu_verifier: "cml-transport-tdx".to_string(),
                        gpu_verifier: None,
                        policy_version: "v1-default".to_string(),
                    },
                };
                platform_evidence_hash = platform_evidence.document_hash()?;
                // Persist the deterministic CBOR once — reused both for
                // filesystem export (operator retrieval) and for in-band
                // delivery via the direct-mode `get_platform_evidence` op.
                let bundle_cbor = platform_evidence.to_cbor_deterministic()?;
                platform_evidence_bytes = std::sync::Arc::new(bundle_cbor);
                export_platform_evidence_bytes(
                    platform_evidence_bytes.as_slice(),
                    &platform_evidence_hash,
                );
            }

            // 5. Create transport attestation bridge (for SecureChannel handshake)
            // --synthetic already rejected in release builds at startup.
            let bridge: Box<dyn confidential_ml_transport::AttestationProvider + Send + Sync> =
                if args.synthetic {
                    warn!("Using synthetic TDX provider for transport bridge — NOT FOR PRODUCTION");
                    let p = TeeAttestationProvider::synthetic();
                    Box::new(
                        TeeAttestationBridge::new(p, receipt_pk)
                            .with_platform_evidence_hash(platform_evidence_hash),
                    )
                } else if has_tsm {
                    let p = TeeAttestationProvider::new()?;
                    Box::new(
                        TeeAttestationBridge::new(p, receipt_pk)
                            .with_platform_evidence_hash(platform_evidence_hash),
                    )
                } else if cs_mode {
                    // CS mode without configfs-tsm: use Launcher JWT for transport attestation.
                    // The WIP audience is needed for the JWT audience field.
                    let wip_audience = args.gcp_wip_audience.as_deref().unwrap_or_default();
                    if wip_audience.is_empty() {
                        return Err("CS mode transport attestation requires --gcp-wip-audience \
                            (or EPHEMERALML_GCP_WIP_AUDIENCE) for the Launcher JWT audience."
                            .into());
                    }
                    info!(
                        step = "transport_bridge",
                        mode = "cs_launcher_jwt",
                        "Using Confidential Space Launcher JWT for transport attestation"
                    );
                    Box::new(
                        ephemeral_ml_enclave::cs_transport_bridge::CsTransportAttestationBridge::new(
                            receipt_pk,
                            wip_audience.to_string(),
                        )
                        .with_platform_evidence_hash(platform_evidence_hash),
                    )
                } else {
                    return Err("No TDX attestation source for transport bridge.\n\
                        \n  Deploy on a TDX CVM (configfs-tsm) or Confidential Space."
                        .into());
                };

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
            // Clients are external (not in TEEs), so use a one-way host verifier
            // for their control-plane envelope. The server still presents its TDX
            // attestation via the bridge.
            if args.direct {
                info!(
                    step = "boot_evidence",
                    mode = "direct",
                    quote_hash = %hex::encode(boot_attestation_hash),
                    synthetic = args.synthetic,
                    "Direct mode: accepting client connections on 0.0.0.0:9000"
                );
                let client_verifier = OneWayHostVerifier::new();
                let manifest_arc = captured_manifest_json.map(std::sync::Arc::new);
                run_direct_tcp(
                    engine,
                    tee_provider,
                    receipt_key,
                    "0.0.0.0:9000",
                    bridge.as_ref(),
                    &client_verifier,
                    boot_attestation_hash,
                    Some(platform_evidence_hash),
                    Some(boot_attestation_bytes),
                    Some(platform_evidence_bytes.clone()),
                    manifest_arc,
                    loaded_model_hash,
                    loaded_model_hash_scheme.clone(),
                    loaded_model_identity_coverage.map(std::sync::Arc::new),
                    args.receipt_issuer.clone(),
                )
                .await
                .map_err(|e| -> Box<dyn std::error::Error> { e })?;
                return Ok(());
            }

            // Pipeline mode: orchestrator connects to control, then data channels.
            let executor = EphemeralStageExecutor::with_air_v1(
                engine,
                tee_provider,
                receipt_key,
                Some(boot_attestation_hash),
                Some(platform_evidence_hash),
                None,
                loaded_model_hash,
                loaded_model_hash_scheme.clone(),
                args.receipt_issuer.clone(),
            );

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
                host_control_plane_stage_config(),
                &gcp_control,
                &gcp_data_in,
                gcp_data_out.parse()?,
                bridge.as_ref(),
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
        warn!("==================================================");
        warn!("  MOCK MODE — NO ATTESTATION, NO ENCRYPTION");
        warn!("  This build is for local development only.");
        warn!("  Do NOT use for production.");
        warn!("==================================================");
        info!("EphemeralML Enclave (Mock Mode)");

        // Load model weights
        let load_start = std::time::Instant::now();
        let model_format = args.model_format.as_str();

        info!(step = "model_load", source = "local", format = model_format, path = %args.model_dir.display(), "Loading model");

        let engine = CandleInferenceEngine::new()?;

        let weights_size_mb;
        if model_format == "gguf" {
            let weights_path = args.model_dir.join("model.gguf");
            let tokenizer_path = args.model_dir.join("tokenizer.json");

            let weights_bytes = std::fs::read(&weights_path)
                .map_err(|e| format!("Failed to read {}: {}", weights_path.display(), e))?;
            let tokenizer_bytes = std::fs::read(&tokenizer_path)
                .map_err(|e| format!("Failed to read {}: {}", tokenizer_path.display(), e))?;

            weights_size_mb = weights_bytes.len() as f64 / (1024.0 * 1024.0);
            engine.register_model_gguf(&args.model_id, &weights_bytes, &tokenizer_bytes)?;
        } else {
            let config_path = args.model_dir.join("config.json");
            let tokenizer_path = args.model_dir.join("tokenizer.json");
            let weights_path = args.model_dir.join("model.safetensors");

            let config_bytes = std::fs::read(&config_path)
                .map_err(|e| format!("Failed to read {}: {}", config_path.display(), e))?;
            let tokenizer_bytes = std::fs::read(&tokenizer_path)
                .map_err(|e| format!("Failed to read {}: {}", tokenizer_path.display(), e))?;
            let weights_bytes = std::fs::read(&weights_path)
                .map_err(|e| format!("Failed to read {}: {}", weights_path.display(), e))?;

            weights_size_mb = weights_bytes.len() as f64 / (1024.0 * 1024.0);
            engine.register_model(
                &args.model_id,
                &config_bytes,
                &weights_bytes,
                &tokenizer_bytes,
            )?;
        }

        let load_elapsed = load_start.elapsed();
        info!(
            step = "model_load",
            source = "local",
            model_id = %args.model_id,
            format = model_format,
            elapsed_ms = load_elapsed.as_secs_f64() * 1000.0,
            size_mb = weights_size_mb,
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
                addr = %args.control_addr,
                "Mock direct mode: accepting client connections"
            );
            run_direct_tcp(
                engine,
                mock_provider,
                receipt_key,
                &args.control_addr,
                &mock_transport,
                &client_verifier,
                mock_attestation_hash,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                args.receipt_issuer.clone(),
            )
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e })?;
        } else {
            let executor = EphemeralStageExecutor::with_air_v1(
                engine,
                mock_provider,
                receipt_key,
                None,
                None,
                None,
                None,
                None,
                args.receipt_issuer.clone(),
            );

            info!(
                step = "pipeline",
                control = %args.control_addr,
                data_in = %args.data_in_addr,
                data_out = %args.data_out_target,
                "Stage worker starting"
            );

            run_stage_tcp(
                executor,
                host_control_plane_stage_config(),
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

        // --direct is not yet supported in Nitro production (requires VSock direct-mode server).
        // Fail fast with a clear message rather than silently ignoring.
        if args.direct {
            return Err("--direct is not supported in Nitro production mode. \
                 Use pipeline mode (default) with the host orchestrator. \
                 Direct mode is available in GCP (--gcp --direct) and mock (--direct) modes."
                .into());
        }

        let attestation_provider = DefaultAttestationProvider::new()?;
        let engine = CandleInferenceEngine::new()?;

        // Generate receipt signing key early — needed for KMS attestation binding
        let receipt_key = ReceiptSigningKey::generate()?;
        let receipt_pk = receipt_key.public_key_bytes();

        // Load model from the selected production source.
        // `local` keeps the historical bundled-model behavior. `aws-s3-kms`
        // exercises the AWS-native high-confidence path: encrypted weights are
        // fetched through the host VSock proxy and the DEK is released through
        // AWS KMS RecipientInfo bound to a Nitro attestation document.
        let model_format = args.model_format.as_str();
        if !args.model_dir.exists() {
            return Err(format!(
                "Model directory does not exist: {}. \
                 Bundle model metadata in the enclave Docker image or mount via --model-dir.",
                args.model_dir.display()
            )
            .into());
        }

        let load_start = std::time::Instant::now();
        let model_source = args.model_source.as_deref().unwrap_or("local");
        #[allow(unused_assignments)]
        let mut model_hash: Option<[u8; 32]> = None;
        let mut model_hash_scheme: Option<String> = None;
        let mut kms_release_evidence: Option<Vec<u8>> = None;

        match model_source {
            "local" => {
                info!(
                    step = "model_load",
                    source = "local",
                    format = model_format,
                    path = %args.model_dir.display(),
                    "Loading model from local directory"
                );

                let tokenizer_bytes = std::fs::read(args.model_dir.join("tokenizer.json"))
                    .map_err(|e| format!("Failed to read tokenizer.json: {}", e))?;

                if model_format == "gguf" {
                    let gguf_bytes = std::fs::read(args.model_dir.join("model.gguf"))
                        .map_err(|e| format!("Failed to read model.gguf: {}", e))?;

                    info!(
                        step = "model_load",
                        size_mb = gguf_bytes.len() as f64 / (1024.0 * 1024.0),
                        "GGUF model file loaded into memory"
                    );

                    {
                        use sha2::{Digest, Sha256};
                        model_hash = Some(Sha256::digest(&gguf_bytes).into());
                    }

                    engine.register_model_gguf(&args.model_id, &gguf_bytes, &tokenizer_bytes)?;
                } else if model_format == "safetensors" {
                    let config_bytes = std::fs::read(args.model_dir.join("config.json"))
                        .map_err(|e| format!("Failed to read config.json: {}", e))?;
                    let weights_bytes = std::fs::read(args.model_dir.join("model.safetensors"))
                        .map_err(|e| format!("Failed to read model.safetensors: {}", e))?;

                    info!(
                        step = "model_load",
                        size_mb = weights_bytes.len() as f64 / (1024.0 * 1024.0),
                        "Safetensors model files loaded into memory"
                    );

                    {
                        use sha2::{Digest, Sha256};
                        model_hash = Some(Sha256::digest(&weights_bytes).into());
                    }

                    engine.register_model(
                        &args.model_id,
                        &config_bytes,
                        &weights_bytes,
                        &tokenizer_bytes,
                    )?;
                } else {
                    return Err(format!(
                        "Unknown --model-format '{}'. Valid: safetensors, gguf",
                        model_format
                    )
                    .into());
                }
            }
            "aws-s3-kms" => {
                if model_format != "safetensors" {
                    return Err("--model-source=aws-s3-kms currently supports --model-format=safetensors only"
                        .into());
                }

                use ephemeral_ml_enclave::kms_client::KmsClient;
                use ephemeral_ml_enclave::model_loader::ModelLoader;
                use sha2::{Digest, Sha256};

                let pk_hex = std::env::var("EPHEMERALML_MODEL_SIGNING_PUBKEY")
                    .map(|v| v.trim().to_string())
                    .map_err(|_| {
                        "--model-source=aws-s3-kms requires EPHEMERALML_MODEL_SIGNING_PUBKEY"
                    })?;
                let pk_bytes = hex::decode(&pk_hex)
                    .map_err(|e| format!("EPHEMERALML_MODEL_SIGNING_PUBKEY: invalid hex: {}", e))?;
                if pk_bytes.len() != 32 {
                    return Err(format!(
                        "EPHEMERALML_MODEL_SIGNING_PUBKEY must be 64 hex chars (32 bytes), got {}",
                        pk_bytes.len()
                    )
                    .into());
                }
                let mut trusted_signing_key = [0u8; 32];
                trusted_signing_key.copy_from_slice(&pk_bytes);

                info!(
                    step = "model_load",
                    source = "aws-s3-kms",
                    format = model_format,
                    manifest = %args.aws_model_manifest_path.display(),
                    wrapped_dek = %args.aws_wrapped_dek_path.display(),
                    "Loading encrypted model via AWS KMS RecipientInfo"
                );

                let config_bytes = std::fs::read(args.model_dir.join("config.json"))
                    .map_err(|e| format!("Failed to read config.json: {}", e))?;
                let tokenizer_bytes = std::fs::read(args.model_dir.join("tokenizer.json"))
                    .map_err(|e| format!("Failed to read tokenizer.json: {}", e))?;
                let manifest_bytes = std::fs::read(&args.aws_model_manifest_path).map_err(|e| {
                    format!(
                        "Failed to read {}: {}",
                        args.aws_model_manifest_path.display(),
                        e
                    )
                })?;
                let wrapped_dek = std::fs::read(&args.aws_wrapped_dek_path).map_err(|e| {
                    format!(
                        "Failed to read {}: {}",
                        args.aws_wrapped_dek_path.display(),
                        e
                    )
                })?;
                let manifest = ephemeral_ml_common::ModelManifest::from_json(&manifest_bytes)
                    .map_err(|e| format!("manifest.json parse failed: {}", e))?;

                let kms_client = KmsClient::new(attestation_provider.clone(), receipt_pk);
                let loader = ModelLoader::new(kms_client, trusted_signing_key);
                let (weights_bytes, mut release_evidence) = loader
                    .load_model_with_evidence(&manifest, &wrapped_dek)
                    .await
                    .map_err(|e| format!("AWS KMS model load failed: {}", e))?;

                let actual_model_hash: [u8; 32] = Sha256::digest(&weights_bytes).into();
                manifest
                    .validate_hash(&actual_model_hash)
                    .map_err(|e| format!("Manifest weight hash validation failed: {}", e))?;

                let tokenizer_hash: [u8; 32] = Sha256::digest(&tokenizer_bytes).into();
                manifest
                    .validate_tokenizer_hash(&tokenizer_hash)
                    .map_err(|e| format!("Manifest tokenizer hash validation failed: {}", e))?;
                let config_hash: [u8; 32] = Sha256::digest(&config_bytes).into();
                manifest
                    .validate_config_hash(&config_hash)
                    .map_err(|e| format!("Manifest config hash validation failed: {}", e))?;

                let effective_model_id = manifest.model_id.as_str();
                engine.register_model(
                    effective_model_id,
                    &config_bytes,
                    &weights_bytes,
                    &tokenizer_bytes,
                )?;
                if effective_model_id != args.model_id {
                    engine.add_alias(&args.model_id, effective_model_id)?;
                    info!(
                        step = "model_alias",
                        alias = %args.model_id,
                        target = %effective_model_id,
                        "Registered model alias"
                    );
                }

                if release_evidence.kms_key_arn.is_none() {
                    release_evidence.kms_key_arn = Some(manifest.key_id.clone());
                }
                if release_evidence.model_kms_key_arn.is_none() {
                    release_evidence.model_kms_key_arn = Some(manifest.key_id.clone());
                }
                if release_evidence
                    .recipient_attestation
                    .image_sha384
                    .is_none()
                {
                    if let Ok(image_sha384) = std::env::var("CYNTRISEC_APPROVED_EIF_SHA384")
                        .or_else(|_| std::env::var("EPHEMERALML_EIF_IMAGE_SHA384"))
                    {
                        let trimmed = image_sha384.trim();
                        if trimmed.len() == 96 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                            release_evidence.recipient_attestation.image_sha384 =
                                Some(trimmed.to_ascii_lowercase());
                        }
                    }
                }

                kms_release_evidence =
                    Some(serde_json::to_vec_pretty(&release_evidence).map_err(|e| {
                        format!("KMS release evidence serialization failed: {}", e)
                    })?);
                model_hash = Some(actual_model_hash);
                model_hash_scheme = Some("sha256-manifest".to_string());

                info!(
                    step = "model_load",
                    source = "aws-s3-kms",
                    model_id = %effective_model_id,
                    kms_key = %manifest.key_id,
                    elapsed_ms = load_start.elapsed().as_secs_f64() * 1000.0,
                    size_mb = weights_bytes.len() as f64 / (1024.0 * 1024.0),
                    "Model loaded through attestation-bound AWS KMS"
                );
            }
            other => {
                return Err(format!(
                    "Unknown --model-source '{}'. Valid in Nitro production: local, aws-s3-kms",
                    other
                )
                .into());
            }
        }

        info!(
            step = "model_load",
            model_id = %args.model_id,
            format = model_format,
            elapsed_ms = load_start.elapsed().as_secs_f64() * 1000.0,
            "Model registered successfully"
        );

        let ((boot_attestation_hash, platform_evidence_hash), boot_attestation_bytes) = {
            use ephemeral_ml_common::{
                CloudEvidenceSummary, CpuEvidenceSummary, EvidenceBinding, EvidenceVerifierSummary,
                MeasurementEntry, PlatformEvidenceBundle, PLATFORM_EVIDENCE_V1,
            };
            use ephemeral_ml_enclave::AttestationProvider;
            use sha2::{Digest, Sha256};

            let boot_nonce = [0u8; 32];
            let boot_doc =
                attestation_provider.generate_attestation(&boot_nonce, receipt_pk, None)?;
            let boot_doc_bytes = boot_doc.signature;
            let attestation_hash: [u8; 32] = Sha256::digest(&boot_doc_bytes).into();
            let measurements = attestation_provider.get_pcr_measurements()?;
            let platform_evidence = PlatformEvidenceBundle {
                version: PLATFORM_EVIDENCE_V1,
                platform_profile: "aws-nitro-enclave".to_string(),
                generated_at: ephemeral_ml_common::current_timestamp()?,
                binding: EvidenceBinding {
                    receipt_signing_key: receipt_pk,
                    hpke_public_key: Some(attestation_provider.get_hpke_public_key()),
                    model_id: args.model_id.clone(),
                    model_hash,
                    base_attestation_hash: attestation_hash,
                },
                cpu: Some(CpuEvidenceSummary {
                    tee_type: "nitro".to_string(),
                    measurement_type: "nitro-pcr".to_string(),
                    measurements: vec![
                        MeasurementEntry {
                            index: 0,
                            value: measurements.pcr0,
                        },
                        MeasurementEntry {
                            index: 1,
                            value: measurements.pcr1,
                        },
                        MeasurementEntry {
                            index: 2,
                            value: measurements.pcr2,
                        },
                    ],
                }),
                gpu: None,
                cloud: Some(CloudEvidenceSummary {
                    attestation_source: "aws-nitro".to_string(),
                    launcher_jwt_sha256: None,
                    image_digest: None,
                    project_id: None,
                    zone: None,
                }),
                verifier: EvidenceVerifierSummary {
                    cpu_verifier: "nitro-cose".to_string(),
                    gpu_verifier: None,
                    policy_version: "v1-default".to_string(),
                },
            };
            let platform_evidence_hash = platform_evidence.document_hash()?;
            // Nitro production uses VSock pipeline rather than run_direct_tcp;
            // the bundle bytes are only needed for filesystem-based export here.
            match platform_evidence.to_cbor_deterministic() {
                Ok(cbor) => export_platform_evidence_bytes(&cbor, &platform_evidence_hash),
                Err(e) => warn!(
                    error = %e,
                    "Failed to encode platform-evidence bundle; filesystem export skipped"
                ),
            }

            info!(
                step = "boot_evidence",
                attestation_doc_hash = %hex::encode(attestation_hash),
                platform_evidence_hash = %hex::encode(platform_evidence_hash),
                bytes = boot_doc_bytes.len(),
                "Captured Nitro boot attestation for receipt binding"
            );

            ((attestation_hash, platform_evidence_hash), boot_doc_bytes)
        };

        // Build stage executor and attestation bridge (with AIR v1 receipt support)
        let mut executor = EphemeralStageExecutor::with_air_v1(
            engine,
            attestation_provider.clone(),
            receipt_key,
            Some(boot_attestation_hash),
            Some(platform_evidence_hash),
            Some(boot_attestation_bytes),
            model_hash,
            model_hash_scheme,
            args.receipt_issuer.clone(),
        );
        if let Some(kms_release_evidence) = kms_release_evidence {
            executor = executor.with_kms_release_evidence(kms_release_evidence);
        }
        let bridge = AttestationBridge::new(attestation_provider, receipt_pk)
            .with_platform_evidence_hash(platform_evidence_hash);

        // Use explicit one-way host verification for host connections: the host
        // orchestrator is NOT inside a TEE and cannot produce Nitro attestation.
        // The enclave attests to the host (via NSM COSE_Sign1), while the host
        // control-plane peer is accepted as unmeasured same-instance infrastructure.
        // For multi-enclave pipelines, switch to NitroVerifier with PCR pinning.
        let verifier = OneWayHostVerifier::new();
        info!(
            step = "verifier",
            mode = "one_way_host",
            "Using one-way host verifier for host control-plane connections"
        );

        // Parse VSock ports from CLI args (format: "CID:PORT" or just "PORT").
        // Fail fast on malformed values — silent defaults are dangerous in production.
        fn parse_vsock_port(
            arg: &str,
            label: &str,
        ) -> std::result::Result<u32, Box<dyn std::error::Error>> {
            let port_str = arg.split(':').last().unwrap_or(arg);
            port_str.parse::<u32>().map_err(|e| {
                format!(
                    "Failed to parse {} port from '{}': {}. Expected format: CID:PORT or PORT.",
                    label, arg, e
                )
                .into()
            })
        }
        let control_port = parse_vsock_port(&args.control_addr, "control")?;
        let data_in_port = parse_vsock_port(&args.data_in_addr, "data_in")?;
        let data_out_port = parse_vsock_port(&args.data_out_target, "data_out")?;

        // Host CID is always 3 from the enclave's perspective.
        const HOST_CID: u32 = 3;

        info!(
            step = "pipeline",
            control_port = control_port,
            data_in_port = data_in_port,
            data_out_host_cid = HOST_CID,
            data_out_port = data_out_port,
            "Production stage worker starting on VSock"
        );

        // Bind stage listeners and run pipeline over VSock.
        let (ctrl_listener, din_listener) =
            confidential_ml_pipeline::vsock::bind_stage_listeners_vsock(control_port, data_in_port)
                .map_err(|e| format!("Failed to bind VSock stage listeners: {}", e))?;

        confidential_ml_pipeline::vsock::run_stage_with_listeners_vsock(
            executor,
            host_control_plane_stage_config(),
            ctrl_listener,
            din_listener,
            HOST_CID,
            data_out_port,
            &bridge,
            &verifier,
        )
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    }

    Ok(())
}
