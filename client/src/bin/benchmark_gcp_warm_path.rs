//! GCP Confidential Space warm-path benchmark.
//!
//! Runs independent SecureChannel sessions directly against a deployed GCP TDX
//! backend and records development-only enclave timing metadata. This bypasses
//! the OpenAI gateway intentionally: current gateway state uses a single locked
//! backend client, so HTTP concurrency would not represent independent enclave
//! sessions.

use clap::Parser;
use ephemeral_ml_client::{SecureClient, SecureEnclaveClient};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

const SCHEMA_VERSION: u32 = 2;
const REQUIRED_SERVER_TIMINGS: &[&str] = &[
    "request_decrypt",
    "request_hash",
    "inference",
    "response_canonicalize",
    "response_hash",
    "legacy_receipt_build",
    "legacy_receipt_sign",
    "air_claims_from_legacy",
    "air_build",
    "air_claim_validate",
    "air_claims_cbor_encode",
    "air_cose_create_signature",
    "air_sign",
    "air_serialize",
];
const REQUIRED_CLIENT_TIMINGS: &[&str] = &["client_request_encrypt", "client_response_decrypt"];

#[derive(Parser, Debug, Clone)]
#[command(
    name = "benchmark_gcp_warm_path",
    about = "Benchmark GCP Confidential Space warm-path timing records"
)]
struct Args {
    /// Backend address in host:port form, usually the CVM external IP plus :9000.
    #[arg(long)]
    backend_addr: String,

    /// Model ID to request from the backend.
    #[arg(long, default_value = "stage-0")]
    model_id: String,

    /// Receipt model ID accepted when the signed manifest model differs from request model.
    #[arg(long, default_value = "minilm-l6-v2")]
    receipt_model_id: String,

    /// Comma-separated concurrency levels.
    #[arg(long, default_value = "1,4,16")]
    concurrency: String,

    /// Prompt sizes to run: short,medium,long.
    #[arg(long, default_value = "short,medium,long")]
    prompt_sizes: String,

    /// Warmup requests per independent session.
    #[arg(long, default_value_t = 10)]
    warmup: usize,

    /// Measured requests per (concurrency, prompt_size) point.
    #[arg(long, default_value_t = 120)]
    measured: usize,

    /// Output JSONL path.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Clone)]
struct RequestSample {
    wall_us: f64,
    timings_us: BTreeMap<String, f64>,
}

#[derive(Debug, Serialize)]
struct RequestRecord {
    schema_version: u32,
    record_type: &'static str,
    benchmark_id: &'static str,
    generated_at_unix: u64,
    git_sha: String,
    mode: &'static str,
    environment: Value,
    workload: Value,
    measurement: Value,
    request: Value,
    timings_us: Value,
    metrics: Value,
    caveats: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct SummaryRecord {
    schema_version: u32,
    record_type: &'static str,
    benchmark_id: &'static str,
    generated_at_unix: u64,
    git_sha: String,
    mode: &'static str,
    environment: Value,
    workload: Value,
    measurement: Value,
    metrics: Value,
    caveats: Vec<&'static str>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.measured == 0 {
        anyhow::bail!("--measured must be > 0");
    }

    std::env::set_var("EPHEMERALML_BENCHMARK_MODE", "development");
    std::env::set_var(
        "EPHEMERALML_ACCEPT_RECEIPT_MODEL_ID",
        &args.receipt_model_id,
    );

    let concurrencies = parse_usize_csv(&args.concurrency, "--concurrency")?;
    let prompt_sizes = parse_string_csv(&args.prompt_sizes, "--prompt-sizes")?;
    let git_sha = std::env::var("EPHEMERALML_BENCHMARK_GIT_SHA")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| {
            command_output(Command::new("git").args(["rev-parse", "--short", "HEAD"]))
                .unwrap_or_else(|| "unknown".to_string())
        });
    let env = environment(&args);

    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::File::create(&args.output)?;
    let writer = Arc::new(Mutex::new(std::io::BufWriter::new(file)));

    for prompt_size in prompt_sizes {
        let prompt = prompt_for_size(&prompt_size)?;
        for concurrency in &concurrencies {
            let samples = run_point(
                &args,
                &git_sha,
                &env,
                &writer,
                &prompt_size,
                &prompt,
                *concurrency,
            )
            .await?;
            let summary = build_summary_record(
                &args,
                &git_sha,
                &env,
                &prompt_size,
                prompt.len(),
                *concurrency,
                &samples,
            )?;
            write_jsonl(&writer, &summary).await?;
        }
    }

    writer.lock().await.flush()?;
    Ok(())
}

async fn run_point(
    args: &Args,
    git_sha: &str,
    env: &Value,
    writer: &Arc<Mutex<std::io::BufWriter<std::fs::File>>>,
    prompt_size: &str,
    prompt: &str,
    concurrency: usize,
) -> anyhow::Result<Vec<RequestSample>> {
    if concurrency == 0 {
        anyhow::bail!("concurrency must be > 0");
    }

    let counts = distribute(args.measured, concurrency);
    let mut tasks = Vec::with_capacity(concurrency);

    for (session_index, measured_for_session) in counts.into_iter().enumerate() {
        let args = args.clone();
        let git_sha = git_sha.to_string();
        let env = env.clone();
        let writer = Arc::clone(writer);
        let prompt_size = prompt_size.to_string();
        let prompt = prompt.to_string();
        tasks.push(tokio::spawn(async move {
            run_session(
                args,
                git_sha,
                env,
                writer,
                prompt_size,
                prompt,
                concurrency,
                session_index,
                measured_for_session,
            )
            .await
        }));
    }

    let mut samples = Vec::new();
    for task in tasks {
        let mut session_samples = task.await??;
        samples.append(&mut session_samples);
    }
    Ok(samples)
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    args: Args,
    git_sha: String,
    env: Value,
    writer: Arc<Mutex<std::io::BufWriter<std::fs::File>>>,
    prompt_size: String,
    prompt: String,
    concurrency: usize,
    session_index: usize,
    measured_for_session: usize,
) -> anyhow::Result<Vec<RequestSample>> {
    let mut client = SecureEnclaveClient::new(format!("gcp-warm-path-{session_index}"));
    client.establish_channel(&args.backend_addr).await?;

    for _ in 0..args.warmup {
        let _ = client
            .execute_inference_text(&args.model_id, &prompt)
            .await?;
    }

    let mut samples = Vec::with_capacity(measured_for_session);
    for request_index in 0..measured_for_session {
        let start = Instant::now();
        let result = client
            .execute_inference_text(&args.model_id, &prompt)
            .await?;
        let wall_us = start.elapsed().as_secs_f64() * 1_000_000.0;

        let benchmark = result.benchmark.ok_or_else(|| {
            anyhow::anyhow!("backend response did not include benchmark metadata")
        })?;
        let backend_schema_version = benchmark
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("backend benchmark record missing schema_version"))?;
        if backend_schema_version != u64::from(SCHEMA_VERSION) {
            anyhow::bail!(
                "backend benchmark schema_version mismatch: expected {}, got {}",
                SCHEMA_VERSION,
                backend_schema_version
            );
        }
        let timings = benchmark
            .get("timings_us")
            .ok_or_else(|| anyhow::anyhow!("benchmark record missing timings_us"))?;
        let mut timings_json = timings.clone();
        let mut timings_map = numeric_timings(timings)?;
        require_timings(&timings_map, REQUIRED_SERVER_TIMINGS, "backend")?;
        if let Some(transport) = result.transport_timings {
            add_transport_timing(
                &mut timings_json,
                &mut timings_map,
                "client_request_encrypt",
                transport.request_encrypt_us,
            );
            add_transport_timing(
                &mut timings_json,
                &mut timings_map,
                "client_response_decrypt",
                transport.response_decrypt_us,
            );
        }
        require_timings(&timings_map, REQUIRED_CLIENT_TIMINGS, "client")?;

        let sample = RequestSample {
            wall_us,
            timings_us: timings_map,
        };
        let record = RequestRecord {
            schema_version: SCHEMA_VERSION,
            record_type: "request",
            benchmark_id: "gcp_cs_tdx_warm_path",
            generated_at_unix: ephemeral_ml_common::current_timestamp()?,
            git_sha: git_sha.clone(),
            mode: "development",
            environment: env.clone(),
            workload: workload(&args, &prompt_size, prompt.len(), concurrency),
            measurement: measurement(&args),
            request: json!({
                "session_index": session_index,
                "request_index": request_index,
                "warmup_discarded_for_session": args.warmup,
            }),
            timings_us: timings_json,
            metrics: json!({
                "gateway_to_receipt_wall_us": round3(wall_us),
            }),
            caveats: caveats(),
        };
        write_jsonl(&writer, &record).await?;
        samples.push(sample);
    }

    Ok(samples)
}

fn build_summary_record(
    args: &Args,
    git_sha: &str,
    env: &Value,
    prompt_size: &str,
    prompt_bytes: usize,
    concurrency: usize,
    samples: &[RequestSample],
) -> anyhow::Result<SummaryRecord> {
    let mut metrics = serde_json::Map::new();
    metrics.insert(
        "gateway_to_receipt_wall_us".to_string(),
        stats(samples.iter().map(|s| s.wall_us).collect()),
    );

    let mut stage_values: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for sample in samples {
        for (name, value) in &sample.timings_us {
            stage_values.entry(name.clone()).or_default().push(*value);
        }
    }
    for (stage, values) in stage_values {
        metrics.insert(format!("{stage}_us"), stats(values));
    }

    Ok(SummaryRecord {
        schema_version: SCHEMA_VERSION,
        record_type: "summary",
        benchmark_id: "gcp_cs_tdx_warm_path",
        generated_at_unix: ephemeral_ml_common::current_timestamp()?,
        git_sha: git_sha.to_string(),
        mode: "development",
        environment: env.clone(),
        workload: workload(args, prompt_size, prompt_bytes, concurrency),
        measurement: measurement(args),
        metrics: Value::Object(metrics),
        caveats: caveats(),
    })
}

fn workload(args: &Args, prompt_size: &str, prompt_bytes: usize, concurrency: usize) -> Value {
    json!({
        "model_id": args.model_id,
        "model_family": "embedding",
        "prompt_size": prompt_size,
        "input_bytes": prompt_bytes,
        "concurrency": concurrency,
        "session_mode": "independent_sessions",
    })
}

fn measurement(args: &Args) -> Value {
    json!({
        "warmup_iterations_per_session": args.warmup,
        "measured_requests_per_point": args.measured,
        "timer": "std::time::Instant",
        "unit": "microseconds",
    })
}

fn environment(args: &Args) -> Value {
    json!({
        "backend_addr": args.backend_addr,
        "host": {
            "cpu_model": first_cpu_model().unwrap_or_else(|| "unknown".to_string()),
            "logical_cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
            "kernel": command_output(Command::new("uname").arg("-sr")).unwrap_or_else(|| "unknown".to_string()),
        },
        "software": {
            "rustc": command_output(Command::new("rustc").arg("--version")).unwrap_or_else(|| "unknown".to_string()),
            "ephemeral-ml-client": env!("CARGO_PKG_VERSION"),
        }
    })
}

fn caveats() -> Vec<&'static str> {
    vec![
        "development-only timing channel; production responses must not expose per-stage timings",
        "request_decrypt is server-side SecureChannel AEAD open time for the inbound request frame",
        "client_request_encrypt and client_response_decrypt are client-side SecureChannel AEAD timings",
        "response_encrypt remains null because exact same-response server-side AEAD seal happens after the benchmark record is serialized",
        "gateway_to_receipt_wall_us is local client wall-clock around execute_inference_text and includes client/gateway-equivalent transport overhead",
        "environment.host describes the benchmark runner/client host; record backend VM metadata separately when publishing cloud artifacts",
        "concurrency uses independent SecureChannel sessions, not multiple in-flight requests on one session",
    ]
}

fn add_transport_timing(
    timings_json: &mut Value,
    timings_map: &mut BTreeMap<String, f64>,
    name: &str,
    value: Option<u64>,
) {
    let Some(value) = value else {
        return;
    };
    timings_map.insert(name.to_string(), value as f64);
    if let Some(obj) = timings_json.as_object_mut() {
        obj.insert(name.to_string(), json!(value));
    }
}

fn numeric_timings(value: &Value) -> anyhow::Result<BTreeMap<String, f64>> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("timings_us is not an object"))?;
    let mut out = BTreeMap::new();
    for (key, value) in obj {
        if let Some(n) = value.as_f64() {
            out.insert(key.clone(), n);
        }
    }
    Ok(out)
}

fn require_timings(
    timings: &BTreeMap<String, f64>,
    required: &[&str],
    source: &str,
) -> anyhow::Result<()> {
    let missing = required
        .iter()
        .copied()
        .filter(|name| !timings.contains_key(*name))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        anyhow::bail!("{source} benchmark timings missing required fields: {missing:?}");
    }
    Ok(())
}

async fn write_jsonl<T: Serialize>(
    writer: &Arc<Mutex<std::io::BufWriter<std::fs::File>>>,
    value: &T,
) -> anyhow::Result<()> {
    let line = serde_json::to_vec(value)?;
    let mut writer = writer.lock().await;
    writer.write_all(&line)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn distribute(total: usize, workers: usize) -> Vec<usize> {
    let base = total / workers;
    let extra = total % workers;
    (0..workers)
        .map(|i| base + usize::from(i < extra))
        .collect()
}

fn parse_usize_csv(input: &str, name: &str) -> anyhow::Result<Vec<usize>> {
    let values = input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<usize>())
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() {
        anyhow::bail!("{name} must contain at least one value");
    }
    Ok(values)
}

fn parse_string_csv(input: &str, name: &str) -> anyhow::Result<Vec<String>> {
    let values = input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if values.is_empty() {
        anyhow::bail!("{name} must contain at least one value");
    }
    Ok(values)
}

fn prompt_for_size(size: &str) -> anyhow::Result<String> {
    match size {
        "short" => Ok("Classify the risk in this sentence.".to_string()),
        "medium" => Ok(repeat_to_len(
            "Sensitive customer workflow requires audit-ready AI inference evidence. ",
            1_024,
        )),
        "long" => Ok(repeat_to_len(
            "A regulated enterprise evaluates confidential AI inference for sensitive workflows and requires verifiable execution evidence, attestation, request and response hashing, and audit-side receipt verification. ",
            10_240,
        )),
        other => anyhow::bail!("unknown prompt size: {other}"),
    }
}

fn repeat_to_len(seed: &str, len: usize) -> String {
    let mut out = String::with_capacity(len);
    while out.len() < len {
        out.push_str(seed);
    }
    out.truncate(len);
    out
}

fn stats(mut values: Vec<f64>) -> Value {
    values.sort_by(|a, b| a.partial_cmp(b).expect("values are finite"));
    let total = values.iter().sum::<f64>();
    let mean = total / values.len().max(1) as f64;
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

fn command_output(cmd: &mut Command) -> Option<String> {
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
