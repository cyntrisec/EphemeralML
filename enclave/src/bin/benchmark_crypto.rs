//! Crypto & security primitives benchmark for EphemeralML.
//!
//! Measures Tier 4 (Security & Attestation Overhead) metrics:
//! - HPKE session setup (X25519 ECDH + transcript hash + key derivation)
//! - HPKE encrypt/decrypt at various payload sizes
//! - Ed25519 keypair generation
//! - Receipt generation + Ed25519 signing
//! - Receipt verification
//!
//! These are pure crypto operations that run on bare metal.

use ephemeral_ml_common::{
    AttestationReceipt, EnclaveMeasurements, HPKESession, ReceiptSigningKey, SecurityMode,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

const NUM_WARMUP: usize = 3;
const NUM_ITERATIONS: usize = 100;

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn round4(v: f64) -> f64 {
    (v * 10000.0).round() / 10000.0
}

/// Compute latency stats from a sorted array of millisecond measurements
fn latency_stats(sorted: &[f64]) -> serde_json::Value {
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    serde_json::json!({
        "mean": round4(mean),
        "p50": round4(percentile(sorted, 50.0)),
        "p95": round4(percentile(sorted, 95.0)),
        "p99": round4(percentile(sorted, 99.0)),
        "min": round4(sorted.first().copied().unwrap_or(0.0)),
        "max": round4(sorted.last().copied().unwrap_or(0.0))
    })
}

/// Create a pair of established HPKE sessions (client + server)
fn create_session_pair() -> (HPKESession, HPKESession) {
    let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let client_public = PublicKey::from(&client_secret);
    let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let server_public = PublicKey::from(&server_secret);

    let mut client_session = HPKESession::new(
        "bench-session".to_string(),
        1,
        [1u8; 32],
        *client_public.as_bytes(),
        *server_public.as_bytes(),
        [3u8; 12],
        3600,
    )
    .unwrap();
    client_session.establish(client_secret.as_bytes()).unwrap();

    let mut server_session = HPKESession::new(
        "bench-session".to_string(),
        1,
        [1u8; 32],
        *server_public.as_bytes(),
        *client_public.as_bytes(),
        [3u8; 12],
        3600,
    )
    .unwrap();
    server_session.establish(server_secret.as_bytes()).unwrap();

    (client_session, server_session)
}

/// Create a realistic receipt for benchmarking
fn create_test_receipt(seq: u64) -> AttestationReceipt {
    AttestationReceipt::new(
        format!("bench-receipt-{}", seq),
        1,
        SecurityMode::GatewayOnly,
        EnclaveMeasurements::new(vec![0u8; 48], vec![0u8; 48], vec![0u8; 48]),
        [5u8; 32], // attestation_doc_hash
        [6u8; 32], // request_hash
        [7u8; 32], // response_hash
        "v1.0".to_string(),
        seq,
        "MiniLM-L6-v2".to_string(),
        "1.0.0".to_string(),
        85,  // execution_time_ms
        535, // memory_peak_mb
    )
}

fn bench_hpke_session_setup() -> serde_json::Value {
    eprintln!("[crypto] Benchmarking HPKE session setup...");
    let mut latencies = Vec::with_capacity(NUM_ITERATIONS);

    // Warmup
    for _ in 0..NUM_WARMUP {
        let _ = create_session_pair();
    }

    for _ in 0..NUM_ITERATIONS {
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let start = Instant::now();

        // Full session setup: create + establish (both sides)
        let mut client_session = HPKESession::new(
            "bench".to_string(),
            1,
            [1u8; 32],
            *client_public.as_bytes(),
            *server_public.as_bytes(),
            [3u8; 12],
            3600,
        )
        .unwrap();
        client_session.establish(client_secret.as_bytes()).unwrap();

        let mut server_session = HPKESession::new(
            "bench".to_string(),
            1,
            [1u8; 32],
            *server_public.as_bytes(),
            *client_public.as_bytes(),
            [3u8; 12],
            3600,
        )
        .unwrap();
        server_session.establish(server_secret.as_bytes()).unwrap();

        latencies.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let stats = latency_stats(&latencies);
    eprintln!("[crypto] HPKE session setup: mean={:.4}ms", stats["mean"]);
    stats
}

fn bench_hpke_keygen() -> serde_json::Value {
    eprintln!("[crypto] Benchmarking X25519 keypair generation...");
    let mut latencies = Vec::with_capacity(NUM_ITERATIONS);

    for _ in 0..NUM_WARMUP {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let _ = PublicKey::from(&secret);
    }

    for _ in 0..NUM_ITERATIONS {
        let start = Instant::now();
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let _ = PublicKey::from(&secret);
        latencies.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let stats = latency_stats(&latencies);
    eprintln!("[crypto] X25519 keygen: mean={:.4}ms", stats["mean"]);
    stats
}

fn bench_hpke_encrypt_decrypt(payload_size: usize) -> serde_json::Value {
    eprintln!(
        "[crypto] Benchmarking HPKE encrypt+decrypt ({}B payload)...",
        payload_size
    );
    let payload = vec![0xABu8; payload_size];
    let mut encrypt_latencies = Vec::with_capacity(NUM_ITERATIONS);
    let mut decrypt_latencies = Vec::with_capacity(NUM_ITERATIONS);

    // We need fresh sessions since sequence numbers increment
    let (mut client, mut server) = create_session_pair();

    // Warmup
    for _ in 0..NUM_WARMUP {
        let enc = client.encrypt(&payload).unwrap();
        let _ = server.decrypt(&enc).unwrap();
    }

    // Re-create to reset sequence counters
    let (mut client, mut server) = create_session_pair();

    for _ in 0..NUM_ITERATIONS {
        let enc_start = Instant::now();
        let encrypted = client.encrypt(&payload).unwrap();
        encrypt_latencies.push(enc_start.elapsed().as_secs_f64() * 1000.0);

        let dec_start = Instant::now();
        let _ = server.decrypt(&encrypted).unwrap();
        decrypt_latencies.push(dec_start.elapsed().as_secs_f64() * 1000.0);
    }

    encrypt_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    decrypt_latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let enc_stats = latency_stats(&encrypt_latencies);
    let dec_stats = latency_stats(&decrypt_latencies);
    eprintln!(
        "[crypto]   encrypt: mean={:.4}ms, decrypt: mean={:.4}ms",
        enc_stats["mean"], dec_stats["mean"]
    );

    serde_json::json!({
        "payload_bytes": payload_size,
        "encrypt": enc_stats,
        "decrypt": dec_stats
    })
}

fn bench_ed25519_keygen() -> serde_json::Value {
    eprintln!("[crypto] Benchmarking Ed25519 keypair generation...");
    let mut latencies = Vec::with_capacity(NUM_ITERATIONS);

    for _ in 0..NUM_WARMUP {
        let _ = ReceiptSigningKey::generate().unwrap();
    }

    for _ in 0..NUM_ITERATIONS {
        let start = Instant::now();
        let _ = ReceiptSigningKey::generate().unwrap();
        latencies.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let stats = latency_stats(&latencies);
    eprintln!("[crypto] Ed25519 keygen: mean={:.4}ms", stats["mean"]);
    stats
}

fn bench_receipt_sign() -> serde_json::Value {
    eprintln!("[crypto] Benchmarking receipt generation + Ed25519 signing...");
    let signing_key = ReceiptSigningKey::generate().unwrap();
    let mut latencies = Vec::with_capacity(NUM_ITERATIONS);

    // Warmup
    for i in 0..NUM_WARMUP {
        let mut receipt = create_test_receipt(i as u64);
        receipt.sign(&signing_key).unwrap();
    }

    for i in 0..NUM_ITERATIONS {
        let start = Instant::now();
        // Measure: receipt creation + canonical CBOR encoding + Ed25519 sign
        let mut receipt = create_test_receipt(i as u64 + 1000);
        receipt.sign(&signing_key).unwrap();
        latencies.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let stats = latency_stats(&latencies);
    eprintln!("[crypto] Receipt sign: mean={:.4}ms", stats["mean"]);
    stats
}

fn bench_receipt_verify() -> serde_json::Value {
    eprintln!("[crypto] Benchmarking receipt verification...");
    let signing_key = ReceiptSigningKey::generate().unwrap();
    let public_key = signing_key.public_key;

    // Pre-sign a batch of receipts
    let signed_receipts: Vec<AttestationReceipt> = (0..NUM_ITERATIONS + NUM_WARMUP)
        .map(|i| {
            let mut receipt = create_test_receipt(i as u64);
            receipt.sign(&signing_key).unwrap();
            receipt
        })
        .collect();

    let mut latencies = Vec::with_capacity(NUM_ITERATIONS);

    // Warmup
    for receipt in signed_receipts.iter().take(NUM_WARMUP) {
        let _ = receipt.verify_signature(&public_key).unwrap();
    }

    for i in 0..NUM_ITERATIONS {
        let start = Instant::now();
        let valid = signed_receipts[NUM_WARMUP + i]
            .verify_signature(&public_key)
            .unwrap();
        latencies.push(start.elapsed().as_secs_f64() * 1000.0);
        assert!(valid, "Signature verification failed");
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let stats = latency_stats(&latencies);
    eprintln!("[crypto] Receipt verify: mean={:.4}ms", stats["mean"]);
    stats
}

fn bench_receipt_canonical_encoding() -> serde_json::Value {
    eprintln!("[crypto] Benchmarking receipt canonical CBOR encoding...");
    let receipt = create_test_receipt(0);
    let mut latencies = Vec::with_capacity(NUM_ITERATIONS);

    for _ in 0..NUM_WARMUP {
        let _ = receipt.canonical_encoding().unwrap();
    }

    for _ in 0..NUM_ITERATIONS {
        let start = Instant::now();
        let _ = receipt.canonical_encoding().unwrap();
        latencies.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let stats = latency_stats(&latencies);
    let encoding_size = receipt.canonical_encoding().unwrap().len();
    eprintln!(
        "[crypto] CBOR encoding: mean={:.4}ms, size={}B",
        stats["mean"], encoding_size
    );

    serde_json::json!({
        "latency": stats,
        "encoding_size_bytes": encoding_size
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let instance_type = args
        .iter()
        .position(|a| a == "--instance-type")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("unknown");

    eprintln!("[crypto] Starting crypto primitives benchmark");
    eprintln!(
        "[crypto] Iterations: {}, Warmup: {}",
        NUM_ITERATIONS, NUM_WARMUP
    );

    let commit = option_env!("GIT_COMMIT").unwrap_or("unknown");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Run all benchmarks
    let hpke_session_setup = bench_hpke_session_setup();
    let x25519_keygen = bench_hpke_keygen();
    let hpke_encrypt_64b = bench_hpke_encrypt_decrypt(64);
    let hpke_encrypt_1kb = bench_hpke_encrypt_decrypt(1024);
    let hpke_encrypt_64kb = bench_hpke_encrypt_decrypt(65536);
    let hpke_encrypt_1mb = bench_hpke_encrypt_decrypt(1_048_576);
    let ed25519_keygen = bench_ed25519_keygen();
    let receipt_sign = bench_receipt_sign();
    let receipt_verify = bench_receipt_verify();
    let receipt_cbor = bench_receipt_canonical_encoding();

    let results = serde_json::json!({
        "benchmark": "crypto_primitives",
        "environment": "bare_metal",
        "hardware": instance_type,
        "timestamp": format!("{}Z", timestamp),
        "commit": commit,
        "iterations": NUM_ITERATIONS,
        "warmup": NUM_WARMUP,
        "hpke": {
            "session_setup_ms": hpke_session_setup,
            "x25519_keygen_ms": x25519_keygen,
            "encrypt_decrypt": {
                "64B": hpke_encrypt_64b,
                "1KB": hpke_encrypt_1kb,
                "64KB": hpke_encrypt_64kb,
                "1MB": hpke_encrypt_1mb
            }
        },
        "receipt": {
            "ed25519_keygen_ms": ed25519_keygen,
            "sign_ms": receipt_sign,
            "verify_ms": receipt_verify,
            "canonical_encoding": receipt_cbor
        }
    });

    println!("{}", serde_json::to_string_pretty(&results)?);
    eprintln!("[crypto] Benchmark complete");
    Ok(())
}
