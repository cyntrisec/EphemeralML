//! Enclave concurrency benchmark for EphemeralML.
//!
//! Spawns N concurrent client sessions (N=1,2,4), each running the full E2E path:
//! session setup + HPKE encrypt + decrypt + real BERT inference + receipt sign +
//! encrypt response + decrypt + receipt verify.
//!
//! Measures throughput scaling and per-request latency under concurrent load.
//! Runs in mock mode (no enclave needed).

use candle_core::{DType, Device};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config as BertConfig};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ephemeral_ml_client::secure_client::{InferenceHandlerInput, InferenceHandlerOutput};
use ephemeral_ml_common::inference::run_single_inference;
use ephemeral_ml_common::metrics;
use ephemeral_ml_common::{
    AttestationDocument, AttestationReceipt, EnclaveMeasurements, HPKESession, PcrMeasurements,
    ReceiptSigningKey, SecurityMode,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const BENCHMARK_INPUT_TEXTS: &[&str] = &[
    "What is the capital of France?",
    "Machine learning enables computers to learn from data.",
    "The quick brown fox jumps over the lazy dog.",
    "Confidential computing protects data in use.",
    "Rust provides memory safety without garbage collection.",
];

const NUM_WARMUP: usize = 3;
const ITERATIONS_PER_CLIENT: usize = 50;
const CONCURRENCY_LEVELS: &[usize] = &[1, 2, 4];

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn round4(v: f64) -> f64 {
    (v * 10000.0).round() / 10000.0
}

/// Run a single E2E inference request including crypto + real BERT inference.
fn run_e2e_inference(
    client_session: &mut HPKESession,
    server_session: &mut HPKESession,
    model: &BertModel,
    tokenizer: &tokenizers::Tokenizer,
    text: &str,
    device: &Device,
    receipt_signing: &ReceiptSigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    attestation_doc_hash: [u8; 32],
    iteration: usize,
) -> f64 {
    let start = Instant::now();

    // Client: encrypt request
    let request_payload = serde_json::to_vec(&InferenceHandlerInput {
        model_id: "MiniLM-L6-v2".to_string(),
        input_data: text.as_bytes().to_vec(),
        input_shape: None,
    })
    .unwrap();
    let encrypted_request = client_session.encrypt(&request_payload).unwrap();

    // Server: decrypt request
    let _decrypted = server_session.decrypt(&encrypted_request).unwrap();

    // Server: real inference
    let embedding = run_single_inference(model, tokenizer, text, device);

    // Server: sign receipt
    let mut receipt = AttestationReceipt::new(
        format!("receipt-{}", iteration),
        1,
        SecurityMode::GatewayOnly,
        EnclaveMeasurements::new(vec![0x01; 48], vec![0x02; 48], vec![0x03; 48]),
        attestation_doc_hash,
        [0u8; 32],
        [0u8; 32],
        "v1".to_string(),
        iteration as u64,
        "MiniLM-L6-v2".to_string(),
        "1.0.0".to_string(),
        93,
        1064,
    );
    receipt.sign(receipt_signing).unwrap();

    // Server: encrypt response
    let response = InferenceHandlerOutput {
        output_tensor: embedding,
        receipt,
    };
    let response_payload = serde_json::to_vec(&response).unwrap();
    let encrypted_response = server_session.encrypt(&response_payload).unwrap();

    // Client: decrypt + verify
    let decrypted_response = client_session.decrypt(&encrypted_response).unwrap();
    let output: InferenceHandlerOutput = serde_json::from_slice(&decrypted_response).unwrap();
    let _valid = output.receipt.verify_signature(verifying_key).unwrap();

    start.elapsed().as_secs_f64() * 1000.0
}

fn bench_at_concurrency(
    n_clients: usize,
    model: &Arc<BertModel>,
    tokenizer: &Arc<tokenizers::Tokenizer>,
    device: &Device,
    attestation_hash: [u8; 32],
    attestation_doc_hash: [u8; 32],
) -> serde_json::Value {
    eprintln!(
        "[enclave_concurrency] Testing N={} concurrent clients, {} iterations each...",
        n_clients, ITERATIONS_PER_CLIENT
    );

    // Warmup with single thread
    {
        use ed25519_dalek::SigningKey;
        use x25519_dalek::{PublicKey, StaticSecret};

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let receipt_signing = ReceiptSigningKey::from_parts(signing_key, verifying_key);

        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let mut client_session = HPKESession::new(
            "warmup".to_string(),
            1,
            attestation_hash,
            *client_public.as_bytes(),
            *server_public.as_bytes(),
            [3u8; 12],
            3600,
        )
        .unwrap();
        client_session.establish(client_secret.as_bytes()).unwrap();

        let mut server_session = HPKESession::new(
            "warmup".to_string(),
            1,
            attestation_hash,
            *server_public.as_bytes(),
            *client_public.as_bytes(),
            [3u8; 12],
            3600,
        )
        .unwrap();
        server_session.establish(server_secret.as_bytes()).unwrap();

        for i in 0..NUM_WARMUP {
            let text = BENCHMARK_INPUT_TEXTS[i % BENCHMARK_INPUT_TEXTS.len()];
            let _ = run_e2e_inference(
                &mut client_session,
                &mut server_session,
                model,
                tokenizer,
                text,
                device,
                &receipt_signing,
                &verifying_key,
                attestation_doc_hash,
                i,
            );
        }
    }

    let wall_start = Instant::now();

    let handles: Vec<_> = (0..n_clients)
        .map(|client_id| {
            let model = Arc::clone(model);
            let tokenizer = Arc::clone(tokenizer);
            let device = device.clone();

            std::thread::spawn(move || {
                use ed25519_dalek::SigningKey;
                use x25519_dalek::{PublicKey, StaticSecret};

                let signing_key = SigningKey::from_bytes(&[7u8; 32]);
                let verifying_key = signing_key.verifying_key();
                let receipt_signing = ReceiptSigningKey::from_parts(signing_key, verifying_key);

                // Each client establishes its own session
                let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
                let client_public = PublicKey::from(&client_secret);
                let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
                let server_public = PublicKey::from(&server_secret);

                let mut client_session = HPKESession::new(
                    format!("client-{}", client_id),
                    1,
                    attestation_hash,
                    *client_public.as_bytes(),
                    *server_public.as_bytes(),
                    [3u8; 12],
                    3600,
                )
                .unwrap();
                client_session.establish(client_secret.as_bytes()).unwrap();

                let mut server_session = HPKESession::new(
                    format!("client-{}", client_id),
                    1,
                    attestation_hash,
                    *server_public.as_bytes(),
                    *client_public.as_bytes(),
                    [3u8; 12],
                    3600,
                )
                .unwrap();
                server_session.establish(server_secret.as_bytes()).unwrap();

                let mut latencies = Vec::with_capacity(ITERATIONS_PER_CLIENT);
                for i in 0..ITERATIONS_PER_CLIENT {
                    let text = BENCHMARK_INPUT_TEXTS
                        [(client_id * 7 + i) % BENCHMARK_INPUT_TEXTS.len()];
                    let ms = run_e2e_inference(
                        &mut client_session,
                        &mut server_session,
                        &model,
                        &tokenizer,
                        text,
                        &device,
                        &receipt_signing,
                        &verifying_key,
                        attestation_doc_hash,
                        i,
                    );
                    latencies.push(ms);
                }
                latencies
            })
        })
        .collect();

    let mut all_latencies: Vec<f64> = Vec::new();
    for handle in handles {
        all_latencies.extend(handle.join().unwrap());
    }

    let wall_ms = wall_start.elapsed().as_secs_f64() * 1000.0;
    let total_inferences = n_clients * ITERATIONS_PER_CLIENT;
    let throughput = (total_inferences as f64) / (wall_ms / 1000.0);

    all_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = all_latencies.iter().sum::<f64>() / all_latencies.len() as f64;

    eprintln!(
        "[enclave_concurrency]   N={}: mean={:.2}ms, p95={:.2}ms, throughput={:.2} inf/s",
        n_clients,
        mean,
        metrics::percentile_nearest(&all_latencies, 95.0),
        throughput,
    );

    serde_json::json!({
        "concurrency": n_clients,
        "iterations_per_client": ITERATIONS_PER_CLIENT,
        "total_inferences": total_inferences,
        "wall_time_ms": round2(wall_ms),
        "throughput_inferences_per_sec": round2(throughput),
        "latency_ms": {
            "mean": round4(mean),
            "p50": round4(metrics::percentile_nearest(&all_latencies, 50.0)),
            "p95": round4(metrics::percentile_nearest(&all_latencies, 95.0)),
            "p99": round4(metrics::percentile_nearest(&all_latencies, 99.0)),
            "min": round4(all_latencies.first().copied().unwrap_or(0.0)),
            "max": round4(all_latencies.last().copied().unwrap_or(0.0))
        }
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

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

    eprintln!("[enclave_concurrency] Starting enclave concurrency benchmark");
    eprintln!("[enclave_concurrency] Model directory: {}", model_dir);
    eprintln!(
        "[enclave_concurrency] Concurrency levels: {:?}",
        CONCURRENCY_LEVELS
    );

    let device = Device::Cpu;

    // Load and decrypt model
    let config_bytes = std::fs::read(format!("{}/config.json", model_dir))?;
    let tokenizer_bytes = std::fs::read(format!("{}/tokenizer.json", model_dir))?;
    let encrypted_weights = std::fs::read(format!("{}/mini-lm-v2-weights.enc", model_dir))?;

    let fixed_dek =
        hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")?;
    let (nonce_bytes, ciphertext) = encrypted_weights.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&fixed_dek));
    let weights_plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| format!("decryption failed: {}", e))?;

    let config: BertConfig = serde_json::from_slice(&config_bytes)?;
    let vb = VarBuilder::from_buffered_safetensors(weights_plaintext, DType::F32, &device)?;
    let model = Arc::new(BertModel::load(vb, &config)?);
    let tokenizer =
        Arc::new(tokenizers::Tokenizer::from_bytes(&tokenizer_bytes).map_err(|e| e.to_string())?);

    eprintln!("[enclave_concurrency] Model loaded");

    // Compute attestation hashes
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
    let attestation_doc_bytes = serde_json::to_vec(&attestation)?;

    let mut hasher = Sha256::new();
    hasher.update(attestation.module_id.as_bytes());
    hasher.update(&attestation.digest);
    hasher.update(attestation.timestamp.to_be_bytes());
    hasher.update(&attestation.pcrs.pcr0);
    hasher.update(&attestation.pcrs.pcr1);
    hasher.update(&attestation.pcrs.pcr2);
    hasher.update(&attestation.certificate);
    let attestation_hash: [u8; 32] = hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(&attestation_doc_bytes);
    let attestation_doc_hash: [u8; 32] = hasher.finalize().into();

    let commit = option_env!("GIT_COMMIT").unwrap_or("unknown");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut results_per_level = Vec::new();
    for &n in CONCURRENCY_LEVELS {
        let result = bench_at_concurrency(
            n,
            &model,
            &tokenizer,
            &device,
            attestation_hash,
            attestation_doc_hash,
        );
        results_per_level.push(result);
    }

    // Compute scaling efficiency
    let baseline_throughput = results_per_level[0]["throughput_inferences_per_sec"]
        .as_f64()
        .unwrap_or(1.0);

    let scaling: Vec<serde_json::Value> = results_per_level
        .iter()
        .map(|r| {
            let n = r["concurrency"].as_u64().unwrap_or(1) as f64;
            let tp = r["throughput_inferences_per_sec"].as_f64().unwrap_or(0.0);
            let efficiency = if n > 0.0 && baseline_throughput > 0.0 {
                (tp / baseline_throughput / n) * 100.0
            } else {
                0.0
            };
            serde_json::json!({
                "concurrency": r["concurrency"],
                "throughput": round2(tp),
                "speedup": round2(tp / baseline_throughput),
                "efficiency_pct": round2(efficiency)
            })
        })
        .collect();

    let results = serde_json::json!({
        "benchmark": "enclave_concurrency",
        "environment": "mock",
        "hardware": instance_type,
        "model": "MiniLM-L6-v2",
        "timestamp": format!("{}Z", timestamp),
        "commit": commit,
        "iterations_per_client": ITERATIONS_PER_CLIENT,
        "warmup": NUM_WARMUP,
        "levels": results_per_level,
        "scaling_efficiency": scaling,
        "notes": "Full E2E path per request: HPKE encrypt + decrypt + BERT inference + receipt sign/verify. Excludes VSock transport."
    });

    println!("{}", serde_json::to_string_pretty(&results)?);
    eprintln!("[enclave_concurrency] Benchmark complete");
    Ok(())
}
