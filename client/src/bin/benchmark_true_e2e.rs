//! True end-to-end benchmark for EphemeralML.
//!
//! Measures the full client→enclave→client round trip including real BERT inference:
//! session setup + HPKE encrypt request + decrypt request + Candle inference +
//! receipt sign + HPKE encrypt response + decrypt response + receipt verify.
//!
//! Runs in mock mode on bare metal. Excludes only VSock transport
//! (measured separately in the vsock RTT benchmark).

use candle_core::{DType, Device};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config as BertConfig};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ephemeral_ml_client::secure_client::{InferenceHandlerInput, InferenceHandlerOutput};
use ephemeral_ml_common::inference::run_single_inference;
use ephemeral_ml_common::metrics;
use ephemeral_ml_common::model_registry::{
    get_model_info_or_default, list_models, resolve_local_artifact_paths,
};
use ephemeral_ml_common::{
    AttestationDocument, AttestationReceipt, EnclaveMeasurements, HPKESession, PcrMeasurements,
    ReceiptSigningKey, SecurityMode,
};
use sha2::{Digest, Sha256};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const BENCHMARK_TEXT: &str = "What is the capital of France?";
const NUM_WARMUP: usize = 3;
const NUM_ITERATIONS: usize = 100;

fn round4(v: f64) -> f64 {
    (v * 10000.0).round() / 10000.0
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn latency_stats(sorted: &[f64]) -> serde_json::Value {
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    serde_json::json!({
        "mean": round4(mean),
        "p50": round4(metrics::percentile_nearest(sorted, 50.0)),
        "p95": round4(metrics::percentile_nearest(sorted, 95.0)),
        "p99": round4(metrics::percentile_nearest(sorted, 99.0)),
        "min": round4(sorted.first().copied().unwrap_or(0.0)),
        "max": round4(sorted.last().copied().unwrap_or(0.0))
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let model_id = args
        .iter()
        .position(|a| a == "--model-id")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("minilm-l6");

    let model_dir = args
        .iter()
        .position(|a| a == "--model-dir")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("test_artifacts");

    let instance_type = args
        .iter()
        .position(|a| a == "--instance-type")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("unknown");

    if args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!("Usage: benchmark_true_e2e [OPTIONS]");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --model-id MODEL      Model to benchmark (default: minilm-l6)");
        eprintln!("  --model-dir DIR       Directory containing model artifacts");
        eprintln!("  --instance-type TYPE  Hardware identifier for JSON output");
        eprintln!();
        eprintln!("Available models: {}", list_models().join(", "));
        return Ok(());
    }

    let model_info = get_model_info_or_default(model_id);

    eprintln!("[true_e2e] Starting true end-to-end benchmark (with real inference)");
    eprintln!(
        "[true_e2e] Model: {} ({}, {} params)",
        model_info.display_name, model_id, model_info.params
    );
    eprintln!("[true_e2e] Model directory: {}", model_dir);

    let device = Device::Cpu;

    // Load and decrypt model
    let (config_path, tokenizer_path, weights_path) =
        resolve_local_artifact_paths(model_dir, model_id);
    let config_bytes = std::fs::read(config_path)?;
    let tokenizer_bytes = std::fs::read(tokenizer_path)?;
    let encrypted_weights = std::fs::read(weights_path)?;

    let fixed_dek =
        hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")?;
    let (nonce_bytes, ciphertext) = encrypted_weights.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&fixed_dek));
    let weights_plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| format!("decryption failed: {}", e))?;

    let config: BertConfig = serde_json::from_slice(&config_bytes)?;
    let vb = VarBuilder::from_buffered_safetensors(weights_plaintext, DType::F32, &device)?;
    let model = BertModel::load(vb, &config)?;
    let tokenizer =
        tokenizers::Tokenizer::from_bytes(&tokenizer_bytes).map_err(|e| e.to_string())?;

    eprintln!("[true_e2e] Model loaded");

    // Set up crypto fixtures (reused across iterations)
    use ed25519_dalek::SigningKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    let pcr_val = vec![0u8; 48];
    let attestation = AttestationDocument {
        module_id: "mock".to_string(),
        digest: vec![0u8; 32],
        timestamp: 0,
        pcrs: PcrMeasurements::new(pcr_val.clone(), pcr_val.clone(), pcr_val),
        certificate: vec![],
        signature: vec![0u8; 64],
        nonce: None,
    };
    // Unified: attestation_hash = attestation_doc_hash = SHA-256(attestation.signature)
    let mut hasher = Sha256::new();
    hasher.update(&attestation.signature);
    let attestation_hash: [u8; 32] = hasher.finalize().into();
    let attestation_doc_hash = attestation_hash;

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let receipt_signing = ReceiptSigningKey::from_parts(signing_key, verifying_key);

    // Prepare request payload (simulating what the client sends)
    let request_payload = serde_json::to_vec(&InferenceHandlerInput {
        model_id: model_id.to_string(),
        input_data: BENCHMARK_TEXT.as_bytes().to_vec(),
        input_shape: None,
    })?;

    let mut setup_latencies = Vec::with_capacity(NUM_ITERATIONS);
    let mut e2e_latencies = Vec::with_capacity(NUM_ITERATIONS);
    let mut inference_only_latencies = Vec::with_capacity(NUM_ITERATIONS);

    for i in 0..(NUM_WARMUP + NUM_ITERATIONS) {
        // === SESSION SETUP ===
        let setup_start = Instant::now();

        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let mut client_session = HPKESession::new(
            format!("bench-session-{}", i),
            1,
            attestation_hash,
            *client_public.as_bytes(),
            *server_public.as_bytes(),
            [3u8; 12],
            3600,
        )?;
        client_session.establish(client_secret.as_bytes())?;

        let mut server_session = HPKESession::new(
            format!("bench-session-{}", i),
            1,
            attestation_hash,
            *server_public.as_bytes(),
            *client_public.as_bytes(),
            [3u8; 12],
            3600,
        )?;
        server_session.establish(server_secret.as_bytes())?;

        let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;

        // === PER-REQUEST E2E (crypto + real inference) ===
        let e2e_start = Instant::now();

        // Client: encrypt request
        let encrypted_request = client_session.encrypt(&request_payload)?;
        let _request_wire = serde_json::to_vec(&encrypted_request)?;

        // Server: decrypt request
        let _decrypted_request = server_session.decrypt(&encrypted_request)?;

        // Server: run real BERT inference
        let inference_start = Instant::now();
        let embedding = run_single_inference(&model, &tokenizer, BENCHMARK_TEXT, &device);
        let inference_ms = inference_start.elapsed().as_secs_f64() * 1000.0;

        // Server: generate and sign receipt
        let mut receipt = AttestationReceipt::new(
            format!("receipt-{}", i),
            1,
            SecurityMode::GatewayOnly,
            EnclaveMeasurements::new(vec![0x01; 48], vec![0x02; 48], vec![0x03; 48]),
            attestation_doc_hash,
            [0u8; 32],
            [0u8; 32],
            "v1".to_string(),
            i as u64,
            model_info.display_name.to_string(),
            "1.0.0".to_string(),
            93,
            1064,
        );
        receipt.sign(&receipt_signing)?;

        // Server: encrypt response
        let response = InferenceHandlerOutput {
            output_tensor: embedding,
            receipt,
        };
        let response_payload = serde_json::to_vec(&response)?;
        let encrypted_response = server_session.encrypt(&response_payload)?;
        let _response_wire = serde_json::to_vec(&encrypted_response)?;

        // Client: decrypt response
        let decrypted_response = client_session.decrypt(&encrypted_response)?;
        let output: InferenceHandlerOutput = serde_json::from_slice(&decrypted_response)?;

        // Client: verify receipt signature
        let _valid = output.receipt.verify_signature(&verifying_key)?;

        let e2e_ms = e2e_start.elapsed().as_secs_f64() * 1000.0;

        if i >= NUM_WARMUP {
            setup_latencies.push(setup_ms);
            e2e_latencies.push(e2e_ms);
            inference_only_latencies.push(inference_ms);
        }
    }

    setup_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    e2e_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    inference_only_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let e2e_mean = e2e_latencies.iter().sum::<f64>() / e2e_latencies.len() as f64;
    let inf_mean =
        inference_only_latencies.iter().sum::<f64>() / inference_only_latencies.len() as f64;
    let crypto_overhead_ms = round4(e2e_mean - inf_mean);

    eprintln!(
        "[true_e2e] E2E mean={:.2}ms (inference={:.2}ms, crypto overhead={:.4}ms)",
        e2e_mean, inf_mean, crypto_overhead_ms
    );

    let commit = option_env!("GIT_COMMIT").unwrap_or("unknown");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (peak_rss_mb, peak_rss_source) = metrics::peak_rss_mb_with_source();

    let results = serde_json::json!({
        "benchmark": "true_e2e",
        "environment": "mock",
        "hardware": instance_type,
        "model": model_info.display_name,
        "model_id": model_id,
        "model_params": model_info.params,
        "timestamp": format!("{}Z", timestamp),
        "commit": commit,
        "iterations": NUM_ITERATIONS,
        "warmup": NUM_WARMUP,
        "session_setup_ms": latency_stats(&setup_latencies),
        "per_request_e2e_ms": latency_stats(&e2e_latencies),
        "inference_only_ms": latency_stats(&inference_only_latencies),
        "crypto_overhead_ms": crypto_overhead_ms,
        "memory": {
            "peak_rss_mb": round2(peak_rss_mb),
            "peak_rss_source": peak_rss_source
        },
        "notes": "Excludes VSock transport (measured separately in vsock RTT benchmark). E2E = HPKE encrypt + decrypt + BERT inference + receipt sign + receipt verify."
    });

    println!("{}", serde_json::to_string_pretty(&results)?);
    eprintln!("[true_e2e] Benchmark complete");
    Ok(())
}
