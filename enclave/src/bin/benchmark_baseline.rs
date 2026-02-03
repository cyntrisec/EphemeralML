//! Bare-metal benchmark baseline for EphemeralML.
//!
//! Runs the same MiniLM-L6-v2 inference workload as the enclave benchmark mode,
//! but on the host without any TEE overhead. Outputs JSON results to stdout
//! for direct comparison with enclave results.

use candle_core::{DType, Device};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config as BertConfig};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ephemeral_ml_common::inference::run_single_inference;
use ephemeral_ml_common::metrics;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const BENCHMARK_INPUT_TEXTS: &[&str] = &[
    "What is the capital of France?",
    "Machine learning enables computers to learn from data.",
    "The quick brown fox jumps over the lazy dog.",
    "Confidential computing protects data in use.",
    "Rust provides memory safety without garbage collection.",
];

const NUM_WARMUP: usize = 3;
const NUM_ITERATIONS: usize = 100;

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Parse optional arguments
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

    eprintln!("[baseline] Starting bare-metal benchmark");
    eprintln!("[baseline] Model directory: {}", model_dir);

    let total_start = Instant::now();
    let device = Device::Cpu;

    // ── Stage 1: Load model artifacts from local filesystem ──
    eprintln!("[baseline] Stage 1: Loading model artifacts from disk");
    let fetch_start = Instant::now();

    let config_bytes = std::fs::read(format!("{}/config.json", model_dir))?;
    let tokenizer_bytes = std::fs::read(format!("{}/tokenizer.json", model_dir))?;
    let encrypted_weights = std::fs::read(format!("{}/mini-lm-v2-weights.enc", model_dir))?;

    let model_fetch_ms = fetch_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "[baseline] model_fetch_ms = {:.2} (config={}B, tokenizer={}B, weights={}B)",
        model_fetch_ms,
        config_bytes.len(),
        tokenizer_bytes.len(),
        encrypted_weights.len()
    );

    // ── Stage 2: Decrypt weights ──
    eprintln!("[baseline] Stage 2: Decrypting model weights");
    let decrypt_start = Instant::now();
    let fixed_dek =
        hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")?;
    let (nonce_bytes, ciphertext) = encrypted_weights.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&fixed_dek));
    let weights_plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| format!("decryption failed: {}", e))?;
    let model_decrypt_ms = decrypt_start.elapsed().as_secs_f64() * 1000.0;
    let plaintext_size = weights_plaintext.len();
    eprintln!(
        "[baseline] model_decrypt_ms = {:.2} (plaintext={}B)",
        model_decrypt_ms, plaintext_size
    );

    // ── Stage 3: Model deserialization ──
    eprintln!("[baseline] Stage 3: Loading model into Candle BertModel");
    let load_start = Instant::now();
    let config: BertConfig = serde_json::from_slice(&config_bytes)?;
    let vb = VarBuilder::from_buffered_safetensors(weights_plaintext, DType::F32, &device)?;
    let model = BertModel::load(vb, &config)?;
    let model_load_ms = load_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!("[baseline] model_load_ms = {:.2}", model_load_ms);

    // ── Stage 4: Tokenizer setup ──
    let tokenizer_start = Instant::now();
    let tokenizer =
        tokenizers::Tokenizer::from_bytes(&tokenizer_bytes).map_err(|e| e.to_string())?;
    let tokenizer_setup_ms = tokenizer_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!("[baseline] tokenizer_setup_ms = {:.2}", tokenizer_setup_ms);

    // cold_start_total_ms includes everything up to "ready to serve first inference"
    let cold_start_total_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    // ── Stage 4b: Reference embedding for quality verification ──
    let reference_embedding =
        run_single_inference(&model, &tokenizer, BENCHMARK_INPUT_TEXTS[0], &device);
    eprintln!(
        "[baseline] reference_embedding: dim={}, first_5={:?}",
        reference_embedding.len(),
        &reference_embedding[..5.min(reference_embedding.len())]
    );

    // ── Stage 5: Warmup ──
    eprintln!("[baseline] Stage 5: Warmup ({} iterations)", NUM_WARMUP);
    for i in 0..NUM_WARMUP {
        let text = BENCHMARK_INPUT_TEXTS[i % BENCHMARK_INPUT_TEXTS.len()];
        let _ = run_single_inference(&model, &tokenizer, text, &device);
    }

    // ── Stage 6: Timed inference iterations ──
    eprintln!(
        "[baseline] Stage 6: Running {} inference iterations",
        NUM_ITERATIONS
    );
    let mut latencies_ms: Vec<f64> = Vec::with_capacity(NUM_ITERATIONS);
    for i in 0..NUM_ITERATIONS {
        let text = BENCHMARK_INPUT_TEXTS[i % BENCHMARK_INPUT_TEXTS.len()];
        let start = Instant::now();
        let _ = run_single_inference(&model, &tokenizer, text, &device);
        latencies_ms.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = latencies_ms.iter().sum::<f64>() / latencies_ms.len() as f64;
    let p50 = metrics::percentile_nearest(&latencies_ms, 50.0);
    let p95 = metrics::percentile_nearest(&latencies_ms, 95.0);
    let p99 = metrics::percentile_nearest(&latencies_ms, 99.0);
    let min_val = latencies_ms.first().copied().unwrap_or(0.0);
    let max_val = latencies_ms.last().copied().unwrap_or(0.0);
    let throughput = if mean > 0.0 { 1000.0 / mean } else { 0.0 };

    // ── Stage 7: Memory measurement ──
    let (peak_rss_mb, peak_rss_source) = metrics::peak_rss_mb_with_source();
    let peak_vmsize_mb = metrics::peak_vmsize_mb();
    let model_size_mb = plaintext_size as f64 / (1024.0 * 1024.0);

    // ── Stage 8: Localhost TCP RTT for baseline comparison ──
    // Not applicable for bare metal — set to 0
    let commit = option_env!("GIT_COMMIT").unwrap_or("unknown");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let results = serde_json::json!({
        "environment": "bare_metal",
        "model": "MiniLM-L6-v2",
        "model_params": 22_700_000,
        "hardware": instance_type,
        "timestamp": format!("{}Z", timestamp),
        "commit": commit,
        "stages": {
            "attestation_ms": 0.0,
            "kms_key_release_ms": 0.0,
            "model_fetch_ms": round2(model_fetch_ms),
            "model_decrypt_ms": round2(model_decrypt_ms),
            "model_load_ms": round2(model_load_ms),
            "tokenizer_setup_ms": round2(tokenizer_setup_ms),
            "cold_start_total_ms": round2(cold_start_total_ms)
        },
        "inference": {
            "input_texts": BENCHMARK_INPUT_TEXTS,
            "num_iterations": NUM_ITERATIONS,
            "latency_ms": {
                "mean": round2(mean),
                "p50": round2(p50),
                "p95": round2(p95),
                "p99": round2(p99),
                "min": round2(min_val),
                "max": round2(max_val)
            },
            "throughput_inferences_per_sec": round2(throughput)
        },
        "memory": {
            "peak_rss_mb": round2(peak_rss_mb),
            "peak_rss_source": peak_rss_source,
            "peak_vmsize_mb": round2(peak_vmsize_mb),
            "model_size_mb": round2(model_size_mb)
        },
        "vsock": {
            "rtt_64b_ms": 0.0,
            "rtt_1kb_ms": 0.0,
            "rtt_64kb_ms": 0.0,
            "rtt_1mb_ms": 0.0,
            "upload_throughput_mbps": 0.0
        },
        "quality": {
            "reference_text": BENCHMARK_INPUT_TEXTS[0],
            "embedding_dim": reference_embedding.len(),
            "embedding_first_8": &reference_embedding[..8.min(reference_embedding.len())],
            "embedding_sha256": metrics::sha256_f32_le(&reference_embedding),
            "embedding": reference_embedding
        }
    });

    // Output JSON to stdout for capture
    println!("{}", serde_json::to_string_pretty(&results)?);

    eprintln!("[baseline] Benchmark complete");
    Ok(())
}
