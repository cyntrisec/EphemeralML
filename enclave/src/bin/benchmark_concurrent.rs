//! Concurrency scaling benchmark for EphemeralML.
//!
//! Runs N concurrent inference threads on the same loaded model and measures
//! how throughput and per-request latency scale with concurrency.
//! Tests N = 1, 2, 4, 8 threads.

use candle_core::{Device, DType, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config as BertConfig};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
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
const ITERATIONS_PER_THREAD: usize = 50;
const CONCURRENCY_LEVELS: &[usize] = &[1, 2, 4, 8];

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn run_single_inference(
    model: &BertModel,
    tokenizer: &tokenizers::Tokenizer,
    text: &str,
    device: &Device,
) -> Vec<f32> {
    let encoding = tokenizer.encode(text, true).expect("tokenization failed");
    let input_ids = encoding.get_ids();
    let token_type_ids = encoding.get_type_ids();
    let attention_mask: Vec<u32> = encoding
        .get_attention_mask()
        .iter()
        .map(|&v| v as u32)
        .collect();

    let input_ids_t = Tensor::new(input_ids, device).unwrap().unsqueeze(0).unwrap();
    let token_type_ids_t = Tensor::new(token_type_ids, device)
        .unwrap()
        .unsqueeze(0)
        .unwrap();

    let output = model
        .forward(&input_ids_t, &token_type_ids_t, None)
        .expect("inference failed");

    let (_batch, _seq_len, _hidden) = output.dims3().unwrap();
    let mask = Tensor::new(&attention_mask[..], device)
        .unwrap()
        .unsqueeze(0)
        .unwrap()
        .unsqueeze(2)
        .unwrap()
        .to_dtype(DType::F32)
        .unwrap();
    let masked = output.broadcast_mul(&mask).unwrap();
    let summed = masked.sum(1).unwrap();
    let count = mask.sum(1).unwrap();
    let mean_pooled = summed.broadcast_div(&count).unwrap();

    mean_pooled
        .squeeze(0)
        .unwrap()
        .to_vec1::<f32>()
        .unwrap()
}

/// Run concurrent inference test at a given concurrency level
fn bench_concurrent(
    n_threads: usize,
    model: &Arc<BertModel>,
    tokenizer: &Arc<tokenizers::Tokenizer>,
    device: &Device,
) -> serde_json::Value {
    eprintln!("[concurrent] Testing N={} threads, {} iterations each...", n_threads, ITERATIONS_PER_THREAD);

    // Warmup with single thread
    for i in 0..NUM_WARMUP {
        let text = BENCHMARK_INPUT_TEXTS[i % BENCHMARK_INPUT_TEXTS.len()];
        let _ = run_single_inference(model, tokenizer, text, device);
    }

    let wall_start = Instant::now();

    // Spawn N threads, each running ITERATIONS_PER_THREAD inferences
    let handles: Vec<_> = (0..n_threads)
        .map(|thread_id| {
            let model = Arc::clone(model);
            let tokenizer = Arc::clone(tokenizer);
            let device = device.clone();

            std::thread::spawn(move || {
                let mut latencies = Vec::with_capacity(ITERATIONS_PER_THREAD);
                for i in 0..ITERATIONS_PER_THREAD {
                    let text = BENCHMARK_INPUT_TEXTS[(thread_id * 7 + i) % BENCHMARK_INPUT_TEXTS.len()];
                    let start = Instant::now();
                    let _ = run_single_inference(&model, &tokenizer, text, &device);
                    latencies.push(start.elapsed().as_secs_f64() * 1000.0);
                }
                latencies
            })
        })
        .collect();

    let mut all_latencies: Vec<f64> = Vec::new();
    for handle in handles {
        let thread_latencies = handle.join().unwrap();
        all_latencies.extend(thread_latencies);
    }

    let wall_ms = wall_start.elapsed().as_secs_f64() * 1000.0;
    let total_inferences = n_threads * ITERATIONS_PER_THREAD;
    let throughput = (total_inferences as f64) / (wall_ms / 1000.0);

    all_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = all_latencies.iter().sum::<f64>() / all_latencies.len() as f64;

    eprintln!(
        "[concurrent]   N={}: mean={:.2}ms, p95={:.2}ms, throughput={:.2} inf/s, wall={:.0}ms",
        n_threads,
        mean,
        percentile(&all_latencies, 95.0),
        throughput,
        wall_ms,
    );

    serde_json::json!({
        "concurrency": n_threads,
        "iterations_per_thread": ITERATIONS_PER_THREAD,
        "total_inferences": total_inferences,
        "wall_time_ms": round2(wall_ms),
        "throughput_inferences_per_sec": round2(throughput),
        "latency_ms": {
            "mean": round2(mean),
            "p50": round2(percentile(&all_latencies, 50.0)),
            "p95": round2(percentile(&all_latencies, 95.0)),
            "p99": round2(percentile(&all_latencies, 99.0)),
            "min": round2(all_latencies.first().copied().unwrap_or(0.0)),
            "max": round2(all_latencies.last().copied().unwrap_or(0.0))
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

    eprintln!("[concurrent] Starting concurrency scaling benchmark");
    eprintln!("[concurrent] Model directory: {}", model_dir);
    eprintln!("[concurrent] Concurrency levels: {:?}", CONCURRENCY_LEVELS);

    let device = Device::Cpu;

    // Load model (same as benchmark_baseline)
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
    let tokenizer = Arc::new(
        tokenizers::Tokenizer::from_bytes(&tokenizer_bytes).map_err(|e| e.to_string())?,
    );

    eprintln!("[concurrent] Model loaded, starting benchmarks...");

    let commit = option_env!("GIT_COMMIT").unwrap_or("unknown");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Run at each concurrency level
    let mut results_per_level = Vec::new();
    for &n in CONCURRENCY_LEVELS {
        let result = bench_concurrent(n, &model, &tokenizer, &device);
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
        "benchmark": "concurrency_scaling",
        "environment": "bare_metal",
        "hardware": instance_type,
        "model": "MiniLM-L6-v2",
        "timestamp": format!("{}Z", timestamp),
        "commit": commit,
        "iterations_per_thread": ITERATIONS_PER_THREAD,
        "warmup": NUM_WARMUP,
        "levels": results_per_level,
        "scaling_efficiency": scaling
    });

    println!("{}", serde_json::to_string_pretty(&results)?);
    eprintln!("[concurrent] Benchmark complete");
    Ok(())
}
