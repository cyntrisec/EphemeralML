//! AIR v1 receipt microbenchmark.
//!
//! Measures receipt construction and verification costs without running model
//! inference. Batch verification uses a pre-generated on-disk receipt corpus
//! loaded into memory before timing, so the throughput number is pure verify
//! work rather than create+verify.

use clap::Parser;
use ephemeral_ml_common::air_receipt::{
    build_air_v1, build_air_v1_with_timings, encode_claims_exported, parse_air_v1, verify_air_v1,
    AirReceiptClaims,
};
use ephemeral_ml_common::air_verify::{verify_air_v1_receipt, AirVerifyPolicy};
use ephemeral_ml_common::{
    AttestationReceipt, EnclaveMeasurements, ReceiptSigningKey, SecurityMode,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const DEFAULT_WARMUP: usize = 1_000;
const DEFAULT_ITERATIONS: usize = 10_000;
const DEFAULT_PAYLOAD_BYTES: usize = 1_024;
const DEFAULT_BATCH_RECEIPTS: usize = 1_000;
const DEFAULT_BATCH_PASSES: usize = 5;
const SCHEMA_VERSION: u64 = 1;

#[derive(Parser, Debug)]
#[command(
    name = "benchmark_air_receipt",
    about = "Benchmark AIR v1 receipt build and verify costs",
    long_about = "Benchmarks AIR v1 receipt build/verify costs and emits schema_version=1 benchmark JSON."
)]
struct Args {
    /// Warmup iterations excluded from per-operation statistics.
    #[arg(long, default_value_t = DEFAULT_WARMUP)]
    warmup: usize,

    /// Measured iterations for per-operation statistics.
    #[arg(long, default_value_t = DEFAULT_ITERATIONS)]
    iterations: usize,

    /// Synthetic request/response payload size used for SHA-256 hash timings.
    #[arg(long, default_value_t = DEFAULT_PAYLOAD_BYTES)]
    payload_bytes: usize,

    /// Number of pre-generated AIR receipts in the audit-verify corpus.
    #[arg(long, default_value_t = DEFAULT_BATCH_RECEIPTS)]
    batch_receipts: usize,

    /// Number of timed passes over the cached receipt corpus.
    #[arg(long, default_value_t = DEFAULT_BATCH_PASSES)]
    batch_passes: usize,

    /// Directory for the pre-generated receipt corpus. Defaults to /tmp.
    #[arg(long)]
    cache_dir: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.iterations == 0 {
        anyhow::bail!("--iterations must be > 0");
    }
    if args.batch_receipts == 0 {
        anyhow::bail!("--batch-receipts must be > 0");
    }
    if args.batch_passes == 0 {
        anyhow::bail!("--batch-passes must be > 0");
    }

    let repo_root = repo_root();
    let git_sha = command_output(
        Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .current_dir(&repo_root),
    )
    .unwrap_or_else(|| "unknown".to_string());

    let signing_key = ReceiptSigningKey::generate()?;
    let request = vec![0xA5; args.payload_bytes];
    let response = vec![0x5A; args.payload_bytes];
    let request_hash: [u8; 32] = Sha256::digest(&request).into();
    let response_hash: [u8; 32] = Sha256::digest(&response).into();
    let model_hash = [0x11; 32];
    let attestation_hash = [0x22; 32];
    let base_receipt = make_legacy_receipt(0, request_hash, response_hash, attestation_hash);
    let base_claims = AirReceiptClaims::from_legacy_with_scheme(
        &base_receipt,
        "https://cyntrisec.com/issuer/benchmark".to_string(),
        model_hash,
        Some("sha256-manifest".to_string()),
    )?;
    let base_air = build_air_v1(&base_claims, &signing_key)?;
    let parsed = parse_air_v1(&base_air)?;
    let policy = AirVerifyPolicy {
        max_age_secs: 0,
        expected_model_hash: Some(model_hash),
        expected_request_hash: Some(request_hash),
        expected_response_hash: Some(response_hash),
        expected_attestation_doc_hash: Some(attestation_hash),
        expected_model_id: Some("benchmark-minilm-l6".to_string()),
        expected_security_mode: Some("production".to_string()),
        expected_platform: Some("nitro-pcr".to_string()),
        ..AirVerifyPolicy::default()
    };

    let mut mutable_receipt = base_receipt.clone();
    let air_timed_samples =
        measure_air_build_timed(args.warmup, args.iterations, &base_claims, &signing_key);

    let metrics = json!({
        "sha256_request_hash_us": stats_us(measure(args.warmup, args.iterations, || {
            let digest = Sha256::digest(black_box(&request));
            black_box(digest);
        })),
        "sha256_response_hash_us": stats_us(measure(args.warmup, args.iterations, || {
            let digest = Sha256::digest(black_box(&response));
            black_box(digest);
        })),
        "legacy_receipt_canonical_cbor_us": stats_us(measure(args.warmup, args.iterations, || {
            let bytes = black_box(&base_receipt).canonical_encoding().expect("canonical receipt encoding");
            black_box(bytes);
        })),
        "legacy_receipt_sign_including_canonical_cbor_us": stats_us(measure(args.warmup, args.iterations, || {
            mutable_receipt.signature = None;
            mutable_receipt.sign(black_box(&signing_key)).expect("legacy receipt sign");
            black_box(&mutable_receipt.signature);
        })),
        "air_claim_validate_us": stats_us(measure(args.warmup, args.iterations, || {
            black_box(&base_claims).validate().expect("AIR claims validate");
        })),
        "air_claims_cbor_encode_us": stats_us(measure(args.warmup, args.iterations, || {
            let bytes = encode_claims_exported(black_box(&base_claims)).expect("AIR claims encode");
            black_box(bytes);
        })),
        "air_from_legacy_claims_us": stats_us(measure(args.warmup, args.iterations, || {
            let claims = AirReceiptClaims::from_legacy_with_scheme(
                black_box(&base_receipt),
                "https://cyntrisec.com/issuer/benchmark".to_string(),
                model_hash,
                Some("sha256-manifest".to_string()),
            ).expect("AIR claims from legacy");
            black_box(claims);
        })),
        "air_build_full_us": stats_us(measure(args.warmup, args.iterations, || {
            let bytes = build_air_v1(black_box(&base_claims), black_box(&signing_key)).expect("AIR build");
            black_box(bytes);
        })),
        "air_build_timed_total_us": stats_us(air_timed_samples.total_us),
        "air_claim_validate_via_builder_us": stats_us(air_timed_samples.validate_us),
        "air_claims_cbor_encode_via_builder_us": stats_us(air_timed_samples.claims_cbor_encode_us),
        "air_cose_create_signature_us": stats_us(air_timed_samples.cose_create_signature_us),
        "air_ed25519_sign_us": stats_us(air_timed_samples.ed25519_sign_us),
        "air_cose_serialize_us": stats_us(air_timed_samples.cose_serialize_us),
        "air_parse_only_us": stats_us(measure(args.warmup, args.iterations, || {
            let parsed = parse_air_v1(black_box(&base_air)).expect("AIR parse");
            black_box(parsed.claims.sequence_number);
        })),
        "air_ed25519_verify_only_us": stats_us(measure(args.warmup, args.iterations, || {
            let ok = verify_air_v1(black_box(&parsed), black_box(&signing_key.public_key)).expect("AIR verify");
            assert!(ok);
            black_box(ok);
        })),
        "air_verify_full_policy_us": stats_us(measure(args.warmup, args.iterations, || {
            let result = verify_air_v1_receipt(
                black_box(&base_air),
                black_box(&signing_key.public_key),
                black_box(&policy),
            );
            assert!(result.verified);
            black_box(result.checks.len());
        })),
        "runtime_receipt_path_without_model_inference_us": stats_us(measure(args.warmup, args.iterations, || {
            let mut receipt = make_legacy_receipt(1, request_hash, response_hash, attestation_hash);
            receipt.sign(black_box(&signing_key)).expect("legacy receipt sign");
            let claims = AirReceiptClaims::from_legacy_with_scheme(
                &receipt,
                "https://cyntrisec.com/issuer/benchmark".to_string(),
                model_hash,
                Some("sha256-manifest".to_string()),
            ).expect("AIR claims from legacy");
            let bytes = build_air_v1(&claims, black_box(&signing_key)).expect("AIR build");
            black_box(bytes);
        })),
    });

    let cache_dir = args.cache_dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!(
            "ephemeralml-air-receipt-bench-{}",
            uuid::Uuid::new_v4()
        ))
    });
    let cache_path = prepare_receipt_cache(
        &cache_dir,
        args.batch_receipts,
        &signing_key,
        request_hash,
        response_hash,
        attestation_hash,
        model_hash,
    )?;
    let cached_receipts = load_cached_receipts(&cache_path)?;
    let batch = bench_cached_batch_verify(
        &cached_receipts,
        args.batch_passes,
        &signing_key.public_key,
        &policy,
    );

    let output = json!({
        "schema_version": SCHEMA_VERSION,
        "benchmark_id": "air_receipt_microbench",
        "generated_at_unix": ephemeral_ml_common::current_timestamp()?,
        "binary": "benchmark_air_receipt",
        "git_sha": git_sha,
        "environment": {
            "host": host_info(),
            "software": software_info(&repo_root),
        },
        "workload": {
            "receipt_format": "AIR v1 COSE_Sign1 / CWT / EAT profile",
            "signature_algorithm": "Ed25519",
            "hash_algorithm": "SHA-256",
            "payload_bytes": args.payload_bytes,
            "receipt_bytes": base_air.len(),
            "batch_receipts": args.batch_receipts,
            "batch_cache_dir": cache_dir,
            "batch_cache_path": cache_path,
        },
        "measurement": {
            "warmup_iterations": args.warmup,
            "measured_iterations": args.iterations,
            "batch_verify_passes": args.batch_passes,
            "timer": "std::time::Instant",
            "unit": "microseconds",
        },
        "metrics": metrics,
        "batch_verify": batch,
        "caveats": [
            "air_build_full_us includes claim validation, deterministic CBOR payload encoding, COSE_Sign1 Sig_structure construction, Ed25519 signing, and tagged CBOR serialization",
            "air_build_timed_total_us is measured with instrumentation enabled and decomposes the same AIR build path into validate, claims CBOR encode, COSE signature creation, Ed25519 sign, and COSE serialization",
            "air_verify_full_policy_us measures wall-clock around verify_air_v1_receipt including COSE/CBOR parse, Ed25519 verify_strict, claim validation, and policy checks",
            "runtime_receipt_path_without_model_inference_us excludes model inference, TEE attestation collection, KMS release, transport encryption, and network/gateway latency",
            "verify_cached_batch loads pre-generated receipts into memory before timing; disk I/O and receipt creation are excluded from the throughput metric",
            "This benchmark does not measure HPKE or ChaCha20-Poly1305 AEAD transport cost; use transport crypto benches for AEAD seal/open numbers",
            "CPU governor, turbo/boost status, and process affinity are recorded in environment.host; quoteable runs should pin the process with taskset and run on an otherwise idle host"
        ]
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn make_legacy_receipt(
    sequence: u64,
    request_hash: [u8; 32],
    response_hash: [u8; 32],
    attestation_hash: [u8; 32],
) -> AttestationReceipt {
    AttestationReceipt::new(
        uuid::Uuid::new_v4().to_string(),
        1,
        SecurityMode::GatewayOnly,
        EnclaveMeasurements::new(vec![0x01; 48], vec![0x02; 48], vec![0x03; 48]),
        attestation_hash,
        request_hash,
        response_hash,
        "v1-default".to_string(),
        sequence,
        "benchmark-minilm-l6".to_string(),
        "benchmark".to_string(),
        75,
        0,
    )
}

fn measure<F>(warmup: usize, iterations: usize, mut f: F) -> Vec<f64>
where
    F: FnMut(),
{
    let mut values = Vec::with_capacity(iterations);
    for i in 0..(warmup + iterations) {
        let start = Instant::now();
        f();
        let us = start.elapsed().as_secs_f64() * 1_000_000.0;
        if i >= warmup {
            values.push(us);
        }
    }
    values
}

fn stats_us(mut values: Vec<f64>) -> Value {
    values.sort_by(|a, b| a.partial_cmp(b).expect("latency values are finite"));
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let total = values.iter().sum::<f64>();
    json!({
        "n": values.len(),
        "total_us": round3(total),
        "mean_us": round3(mean),
        "p50_us": round3(percentile(&values, 50.0)),
        "p95_us": round3(percentile(&values, 95.0)),
        "p99_us": round3(percentile(&values, 99.0)),
        "min_us": round3(*values.first().unwrap_or(&0.0)),
        "max_us": round3(*values.last().unwrap_or(&0.0)),
    })
}

fn stats_plain(mut values: Vec<f64>) -> Value {
    values.sort_by(|a, b| a.partial_cmp(b).expect("values are finite"));
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let total = values.iter().sum::<f64>();
    json!({
        "n": values.len(),
        "total": round3(total),
        "mean": round3(mean),
        "p50": round3(percentile(&values, 50.0)),
        "p95": round3(percentile(&values, 95.0)),
        "p99": round3(percentile(&values, 99.0)),
        "min": round3(*values.first().unwrap_or(&0.0)),
        "max": round3(*values.last().unwrap_or(&0.0)),
    })
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn prepare_receipt_cache(
    dir: &Path,
    count: usize,
    signing_key: &ReceiptSigningKey,
    request_hash: [u8; 32],
    response_hash: [u8; 32],
    attestation_hash: [u8; 32],
    model_hash: [u8; 32],
) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let corpus_path = dir.join(format!("air-receipts-v1-{count}.bin"));
    let mut corpus = Vec::new();

    for i in 0..count {
        let receipt = make_legacy_receipt(i as u64, request_hash, response_hash, attestation_hash);
        let claims = AirReceiptClaims::from_legacy_with_scheme(
            &receipt,
            "https://cyntrisec.com/issuer/benchmark".to_string(),
            model_hash,
            Some("sha256-manifest".to_string()),
        )?;
        let bytes = build_air_v1(&claims, signing_key)?;
        let len: u32 = bytes
            .len()
            .try_into()
            .map_err(|_| anyhow::anyhow!("receipt too large for u32 length prefix"))?;
        corpus.extend_from_slice(&len.to_be_bytes());
        corpus.extend_from_slice(&bytes);
    }
    std::fs::write(&corpus_path, corpus)?;
    Ok(corpus_path)
}

fn load_cached_receipts(path: &Path) -> anyhow::Result<Vec<Vec<u8>>> {
    let bytes = std::fs::read(path)?;
    let mut receipts = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            anyhow::bail!("truncated length prefix at offset {offset}");
        }
        let len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;
        if bytes.len() - offset < len {
            anyhow::bail!("truncated receipt at offset {offset}: need {len} bytes");
        }
        receipts.push(bytes[offset..offset + len].to_vec());
        offset += len;
    }
    Ok(receipts)
}

fn bench_cached_batch_verify(
    receipts: &[Vec<u8>],
    passes: usize,
    public_key: &ed25519_dalek::VerifyingKey,
    policy: &AirVerifyPolicy,
) -> Value {
    let mut total_us = Vec::with_capacity(passes);
    let mut receipts_per_sec = Vec::with_capacity(passes);

    for _ in 0..passes {
        let start = Instant::now();
        let mut verified = 0usize;
        for receipt in receipts {
            let result =
                verify_air_v1_receipt(black_box(receipt), black_box(public_key), black_box(policy));
            assert!(result.verified);
            verified += 1;
        }
        let elapsed = start.elapsed();
        let us = elapsed.as_secs_f64() * 1_000_000.0;
        total_us.push(us);
        receipts_per_sec.push(verified as f64 / elapsed.as_secs_f64());
    }

    json!({
        "cache_mode": "pre_generated_disk_corpus_loaded_before_timer",
        "receipt_count": receipts.len(),
        "verify_passes": passes,
        "verify_cached_batch_total_us": stats_us(total_us),
        "verify_cached_batch_receipts_per_sec": stats_plain(receipts_per_sec),
    })
}

struct AirTimedSamples {
    validate_us: Vec<f64>,
    claims_cbor_encode_us: Vec<f64>,
    cose_create_signature_us: Vec<f64>,
    ed25519_sign_us: Vec<f64>,
    cose_serialize_us: Vec<f64>,
    total_us: Vec<f64>,
}

fn measure_air_build_timed(
    warmup: usize,
    iterations: usize,
    claims: &AirReceiptClaims,
    signing_key: &ReceiptSigningKey,
) -> AirTimedSamples {
    let mut samples = AirTimedSamples {
        validate_us: Vec::with_capacity(iterations),
        claims_cbor_encode_us: Vec::with_capacity(iterations),
        cose_create_signature_us: Vec::with_capacity(iterations),
        ed25519_sign_us: Vec::with_capacity(iterations),
        cose_serialize_us: Vec::with_capacity(iterations),
        total_us: Vec::with_capacity(iterations),
    };

    for i in 0..(warmup + iterations) {
        let timed = build_air_v1_with_timings(black_box(claims), black_box(signing_key))
            .expect("AIR build");
        black_box(&timed.bytes);
        if i >= warmup {
            samples.validate_us.push(timed.timings.validate_us as f64);
            samples
                .claims_cbor_encode_us
                .push(timed.timings.claims_cbor_encode_us as f64);
            samples
                .cose_create_signature_us
                .push(timed.timings.cose_create_signature_us as f64);
            samples
                .ed25519_sign_us
                .push(timed.timings.ed25519_sign_us as f64);
            samples
                .cose_serialize_us
                .push(timed.timings.cose_serialize_us as f64);
            samples.total_us.push(timed.timings.total_us as f64);
        }
    }

    samples
}

fn host_info() -> Value {
    json!({
        "cpu_model": first_cpu_model().unwrap_or_else(|| "unknown".to_string()),
        "logical_cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "kernel": command_output(Command::new("uname").arg("-sr")).unwrap_or_else(|| "unknown".to_string()),
        "mem_total_kb": mem_total_kb(),
        "cpu_frequency": cpu_frequency_info(),
        "process_affinity": process_affinity_info(),
    })
}

fn software_info(repo_root: &Path) -> Value {
    json!({
        "rustc": command_output(Command::new("rustc").arg("--version")).unwrap_or_else(|| "unknown".to_string()),
        "crate_versions": {
            "ephemeral-ml-client": env!("CARGO_PKG_VERSION"),
            "ephemeral-ml-common": cargo_lock_version(repo_root, "ephemeral-ml-common").unwrap_or_else(|| "unknown".to_string()),
            "confidential-ml-transport": cargo_lock_version(repo_root, "confidential-ml-transport").unwrap_or_else(|| "unknown".to_string()),
        }
    })
}

fn first_cpu_model() -> Option<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    cpuinfo.lines().find_map(|line| {
        line.strip_prefix("model name").and_then(|rest| {
            rest.split_once(':')
                .map(|(_, value)| value.trim().to_string())
        })
    })
}

fn mem_total_kb() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    meminfo.lines().find_map(|line| {
        line.strip_prefix("MemTotal:")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|n| n.parse().ok())
    })
}

fn cpu_frequency_info() -> Value {
    json!({
        "scaling_governors": unique_cpu_sys_values("scaling_governor"),
        "scaling_drivers": unique_cpu_sys_values("scaling_driver"),
        "intel_pstate_no_turbo": read_trimmed("/sys/devices/system/cpu/intel_pstate/no_turbo"),
        "cpufreq_boost": read_trimmed("/sys/devices/system/cpu/cpufreq/boost"),
    })
}

fn unique_cpu_sys_values(file_name: &str) -> Vec<String> {
    let mut values = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu") else {
        return values;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("cpu") || !name[3..].chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let path = entry.path().join("cpufreq").join(file_name);
        if let Some(value) = read_trimmed(path) {
            if !values.contains(&value) {
                values.push(value);
            }
        }
    }
    values.sort();
    values
}

fn process_affinity_info() -> Value {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let cpus_allowed_list = status.lines().find_map(|line| {
        line.strip_prefix("Cpus_allowed_list:")
            .map(|value| value.trim().to_string())
    });
    json!({
        "cpus_allowed_list": cpus_allowed_list,
        "taskset_hint": "For quoteable runs, pin the process explicitly, e.g. taskset -c 2 target/release/benchmark_air_receipt ..."
    })
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn command_output(cmd: &mut Command) -> Option<String> {
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    Some(text.trim().to_string())
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("client crate has workspace parent")
        .to_path_buf()
}

fn cargo_lock_version(repo_root: &Path, package_name: &str) -> Option<String> {
    let lock = std::fs::read_to_string(repo_root.join("Cargo.lock")).ok()?;
    let mut in_package = false;
    let mut seen_name = false;

    for line in lock.lines() {
        if line.trim() == "[[package]]" {
            in_package = true;
            seen_name = false;
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(name) = line.trim().strip_prefix("name = ") {
            seen_name = name.trim_matches('"') == package_name;
            continue;
        }
        if seen_name {
            if let Some(version) = line.trim().strip_prefix("version = ") {
                return Some(version.trim_matches('"').to_string());
            }
        }
    }
    None
}
