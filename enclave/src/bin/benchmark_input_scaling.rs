//! Input-shape scaling benchmark for EphemeralML.
//!
//! Measures inference latency as a function of token count (32, 64, 128, 256 tokens)
//! on bare metal. Computes a linear fit: latency = base_overhead + per_token_cost * tokens.

use candle_core::{DType, Device};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config as BertConfig};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ephemeral_ml_common::inference::run_single_inference;
use ephemeral_ml_common::metrics;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const TARGET_TOKEN_COUNTS: &[usize] = &[32, 64, 128, 256];
const NUM_WARMUP: usize = 3;
const NUM_ITERATIONS: usize = 100;

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn round4(v: f64) -> f64 {
    (v * 10000.0).round() / 10000.0
}

/// Generate text that tokenizes to approximately `target` tokens.
/// Returns (text, actual_token_count).
fn generate_text_with_n_tokens(
    tokenizer: &tokenizers::Tokenizer,
    target: usize,
) -> (String, usize) {
    let base = "The quick brown fox jumps over the lazy dog near the river bank. ";
    let base_tokens = tokenizer
        .encode(base, true)
        .expect("tokenization failed")
        .get_ids()
        .len();

    // Estimate how many repetitions we need (subtract 2 for [CLS] and [SEP])
    let content_target = if target > 2 { target - 2 } else { target };
    let reps = (content_target as f64 / (base_tokens - 2) as f64).ceil() as usize;
    let mut text = base.repeat(reps.max(1));

    // Binary search trim: reduce text until we hit the target
    loop {
        let actual = tokenizer
            .encode(text.as_str(), true)
            .expect("tokenization failed")
            .get_ids()
            .len();
        if actual <= target {
            return (text, actual);
        }
        // Remove roughly the right number of characters
        let excess = actual - target;
        let chars_to_remove = (excess * text.len() / actual).max(1);
        let new_len = text.len().saturating_sub(chars_to_remove);
        if new_len == 0 {
            return (text, actual);
        }
        // Trim to a word boundary
        text.truncate(new_len);
        if let Some(pos) = text.rfind(' ') {
            text.truncate(pos + 1);
        }
    }
}

/// Simple linear regression: y = a + b*x.
/// Returns (intercept, slope).
fn linear_fit(points: &[(f64, f64)]) -> (f64, f64) {
    let n = points.len() as f64;
    if n < 2.0 {
        return (0.0, 0.0);
    }
    let sum_x: f64 = points.iter().map(|(x, _)| x).sum();
    let sum_y: f64 = points.iter().map(|(_, y)| y).sum();
    let sum_xy: f64 = points.iter().map(|(x, y)| x * y).sum();
    let sum_xx: f64 = points.iter().map(|(x, _)| x * x).sum();

    let denom = n * sum_xx - sum_x * sum_x;
    if denom.abs() < 1e-12 {
        return (sum_y / n, 0.0);
    }
    let slope = (n * sum_xy - sum_x * sum_y) / denom;
    let intercept = (sum_y - slope * sum_x) / n;
    (intercept, slope)
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

    eprintln!("[input_scaling] Starting input-shape scaling benchmark");
    eprintln!("[input_scaling] Model directory: {}", model_dir);
    eprintln!("[input_scaling] Token counts: {:?}", TARGET_TOKEN_COUNTS);

    let device = Device::Cpu;

    // Load and decrypt model (same as benchmark_baseline)
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
    let model = BertModel::load(vb, &config)?;
    let tokenizer =
        tokenizers::Tokenizer::from_bytes(&tokenizer_bytes).map_err(|e| e.to_string())?;

    eprintln!("[input_scaling] Model loaded, generating input texts...");

    // Generate texts for each target token count
    let mut size_results = Vec::new();
    let mut fit_points = Vec::new();

    for &target in TARGET_TOKEN_COUNTS {
        let (text, actual_tokens) = generate_text_with_n_tokens(&tokenizer, target);
        eprintln!(
            "[input_scaling] Target={}, actual={}, text_len={}",
            target,
            actual_tokens,
            text.len()
        );

        // Warmup
        for _ in 0..NUM_WARMUP {
            let _ = run_single_inference(&model, &tokenizer, &text, &device);
        }

        // Timed iterations
        let mut latencies_ms: Vec<f64> = Vec::with_capacity(NUM_ITERATIONS);
        for _ in 0..NUM_ITERATIONS {
            let start = Instant::now();
            let _ = run_single_inference(&model, &tokenizer, &text, &device);
            latencies_ms.push(start.elapsed().as_secs_f64() * 1000.0);
        }

        latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mean = latencies_ms.iter().sum::<f64>() / latencies_ms.len() as f64;
        let p50 = metrics::percentile_nearest(&latencies_ms, 50.0);
        let p95 = metrics::percentile_nearest(&latencies_ms, 95.0);
        let p99 = metrics::percentile_nearest(&latencies_ms, 99.0);
        let min_val = latencies_ms.first().copied().unwrap_or(0.0);
        let max_val = latencies_ms.last().copied().unwrap_or(0.0);

        eprintln!(
            "[input_scaling]   tokens={}: mean={:.2}ms, p95={:.2}ms",
            actual_tokens, mean, p95
        );

        fit_points.push((actual_tokens as f64, mean));

        size_results.push(serde_json::json!({
            "target_tokens": target,
            "actual_tokens": actual_tokens,
            "text_length_chars": text.len(),
            "latency_ms": {
                "mean": round2(mean),
                "p50": round2(p50),
                "p95": round2(p95),
                "p99": round2(p99),
                "min": round2(min_val),
                "max": round2(max_val)
            }
        }));
    }

    // Compute linear fit
    let (intercept, slope) = linear_fit(&fit_points);
    eprintln!(
        "[input_scaling] Linear fit: latency = {:.2}ms + {:.4}ms/token",
        intercept, slope
    );

    let commit = option_env!("GIT_COMMIT").unwrap_or("unknown");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (peak_rss_mb, peak_rss_source) = metrics::peak_rss_mb_with_source();

    let results = serde_json::json!({
        "benchmark": "input_scaling",
        "environment": "bare_metal",
        "model": "MiniLM-L6-v2",
        "hardware": instance_type,
        "timestamp": format!("{}Z", timestamp),
        "commit": commit,
        "iterations_per_size": NUM_ITERATIONS,
        "warmup": NUM_WARMUP,
        "sizes": size_results,
        "scaling_fit": {
            "base_overhead_ms": round2(intercept),
            "per_token_ms": round4(slope)
        },
        "memory": {
            "peak_rss_mb": round2(peak_rss_mb),
            "peak_rss_source": peak_rss_source
        }
    });

    println!("{}", serde_json::to_string_pretty(&results)?);
    eprintln!("[input_scaling] Benchmark complete");
    Ok(())
}
