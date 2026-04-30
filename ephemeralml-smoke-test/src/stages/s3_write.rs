//! Stage 5 — evidence bundle upload to customer's S3.
//!
//! Real probe: build the evidence bundle in `/tmp/cyntrisec-smoke-{uuid}/`,
//! compute `SHA256SUMS`, upload every file to
//! `s3://{evidence-bucket}/smoke-tests/{iso-timestamp-utc}/` with
//! `--sse aws:kms` (enforced by bucket policy `DenyUnencryptedObjectUploads`).
//! Sequential PUT (small bundle; no need for parallel).
//!
//! On any PUT failure: `failed_stage: s3_write`; preserve the on-host bundle;
//! print the local path for post-mortem.
//!
//! Skipped when `--no-upload` is set (CI mode per spec).
//!
use super::{Stage, StageResult};
use crate::bundle::{
    BenchmarkEnvironment, BenchmarkReport, BenchmarkTimings, CostInputs, EvidenceSizes,
    NegativeTestResult, BENCHMARK_SCHEMA_VERSION, BUNDLE_FILE_NAMES, BUNDLE_FORMAT_VERSION,
    BUNDLE_TYPE,
};
use crate::cli::Args;
use crate::context::Context;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::primitives::ByteStream;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

pub struct S3Write;

#[async_trait]
impl Stage for S3Write {
    fn name(&self) -> &'static str {
        "s3_write"
    }

    async fn run(&self, ctx: &Context, args: &Args) -> StageResult {
        if let Err(e) = write_benchmark(ctx, args, None) {
            return StageResult::fail(
                "s3_write",
                "BENCHMARK_WRITE_FAILED",
                e,
                json!({ "bundle_dir": &ctx.bundle_dir }),
            );
        }

        let missing = required_bundle_files(&ctx.bundle_dir)
            .into_iter()
            .filter(|p| !p.exists())
            .map(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("<unknown>")
                    .to_string()
            })
            .collect::<Vec<_>>();

        if !missing.is_empty() {
            return StageResult::fail(
                "s3_write",
                "BUNDLE_REQUIRED_FILES_MISSING",
                "required high-confidence evidence files are missing; refusing S3 upload",
                json!({
                    "bundle_dir": &ctx.bundle_dir,
                    "missing": missing,
                }),
            );
        }

        if let Err(e) = validate_kms_release(ctx) {
            return StageResult::fail(
                "s3_write",
                "KMS_RELEASE_EVIDENCE_INVALID",
                e,
                json!({ "path": ctx.bundle_dir.join("kms-release.json") }),
            );
        }

        let manifest = match build_manifest(ctx) {
            Ok(manifest) => manifest,
            Err(result) => return *result,
        };
        let manifest_path = ctx.bundle_dir.join("manifest.json");
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap_or_default();
        if let Err(e) = std::fs::write(&manifest_path, manifest_bytes) {
            return StageResult::fail(
                "s3_write",
                "MANIFEST_WRITE_FAILED",
                format!("failed to write manifest.json: {}", e),
                json!({ "bundle_dir": &ctx.bundle_dir }),
            );
        }

        if let Err(e) = write_sha256sums(&ctx.bundle_dir) {
            return StageResult::fail(
                "s3_write",
                "SHA256SUMS_WRITE_FAILED",
                e,
                json!({ "bundle_dir": &ctx.bundle_dir }),
            );
        }

        let bucket = match resolve_bucket(ctx, args).await {
            Ok(bucket) => bucket,
            Err(e) => {
                return StageResult::fail(
                    "s3_write",
                    "EVIDENCE_BUCKET_RESOLVE_FAILED",
                    e,
                    json!({ "stack_name": ctx.stack_name }),
                );
            }
        };

        let prefix = format!("smoke-tests/{}/", ctx.timestamp.format("%Y%m%dT%H%M%SZ"));
        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
        let s3 = aws_sdk_s3::Client::new(&config);

        let mut uploaded = Vec::new();
        let upload_started = Instant::now();
        for path in upload_files(&ctx.bundle_dir) {
            let key = match upload_one(&s3, &bucket, &prefix, &path).await {
                Ok(key) => key,
                Err(e) => {
                    return StageResult::fail(
                        "s3_write",
                        e.code,
                        e.message,
                        json!({ "bucket": bucket, "path": &path }),
                    );
                }
            };
            uploaded.push(key);
        }
        let s3_upload_ms = upload_started.elapsed().as_millis() as u64;

        if let Err(e) = write_benchmark(ctx, args, Some(s3_upload_ms)) {
            return StageResult::fail(
                "s3_write",
                "BENCHMARK_WRITE_FAILED",
                e,
                json!({ "bundle_dir": &ctx.bundle_dir }),
            );
        }
        let manifest = match build_manifest(ctx) {
            Ok(manifest) => manifest,
            Err(result) => return *result,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap_or_default();
        if let Err(e) = std::fs::write(&manifest_path, manifest_bytes) {
            return StageResult::fail(
                "s3_write",
                "MANIFEST_WRITE_FAILED",
                format!("failed to rewrite manifest.json: {}", e),
                json!({ "bundle_dir": &ctx.bundle_dir }),
            );
        }
        if let Err(e) = write_sha256sums(&ctx.bundle_dir) {
            return StageResult::fail(
                "s3_write",
                "SHA256SUMS_WRITE_FAILED",
                e,
                json!({ "bundle_dir": &ctx.bundle_dir }),
            );
        }
        for name in ["benchmark.json", "manifest.json", "SHA256SUMS"] {
            let path = ctx.bundle_dir.join(name);
            let key = match upload_one(&s3, &bucket, &prefix, &path).await {
                Ok(key) => key,
                Err(e) => {
                    return StageResult::fail(
                        "s3_write",
                        e.code,
                        e.message,
                        json!({ "bucket": bucket, "path": path }),
                    );
                }
            };
            uploaded.push(key);
        }

        StageResult::pass(
            "s3_write",
            json!({
                "bucket": bucket,
                "prefix": prefix,
                "uploaded": uploaded,
                "s3_upload_ms": s3_upload_ms,
                "bundle_dir": &ctx.bundle_dir,
            }),
        )
    }
}

fn write_benchmark(ctx: &Context, args: &Args, s3_upload_ms: Option<u64>) -> Result<(), String> {
    let path = ctx.bundle_dir.join("benchmark.json");
    let stage_results = read_stage_results(ctx);
    let doctor_json = read_json(ctx.bundle_dir.join("doctor.json"));
    let negative_tests = read_negative_tests(ctx);
    let eif_sha384 = read_json(ctx.bundle_dir.join("enclave-measurements.json")).and_then(|v| {
        v.get("pcr0")
            .and_then(Value::as_str)
            .map(ToString::to_string)
    });
    let total_smoke_test_ms = s3_upload_ms.map(|s3_upload_ms| {
        stage_duration(&stage_results, "doctor").unwrap_or_default()
            + stage_duration(&stage_results, "enclave_launch").unwrap_or_default()
            + stage_duration(&stage_results, "inference").unwrap_or_default()
            + stage_duration(&stage_results, "receipt_verify").unwrap_or_default()
            + s3_upload_ms
    });
    let report = BenchmarkReport {
        schema_version: BENCHMARK_SCHEMA_VERSION.to_string(),
        run_id: ctx.timestamp.format("%Y%m%dT%H%M%SZ").to_string(),
        timestamp_utc: ctx.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        git_commit: option_env!("GIT_COMMIT").map(ToString::to_string),
        release_bundle_sha256: std::env::var("CYNTRISEC_RELEASE_BUNDLE_SHA256").ok(),
        eif_sha384,
        environment: BenchmarkEnvironment {
            region: Some(ctx.region.clone()),
            availability_zone: imds_metadata("placement/availability-zone"),
            instance_type: imds_metadata("instance-type"),
            ami_id: imds_metadata("ami-id"),
            kernel: command_output("uname", &["-r"]),
            nitro_cli_version: command_output(&args.nitro_cli, &["--version"]),
            enclave_cid: Some(args.enclave_cid),
            enclave_cpu_count: Some(args.enclave_cpu_count),
            enclave_memory_mib: Some(args.enclave_memory_mib),
        },
        timings_ms: BenchmarkTimings {
            doctor_total_ms: stage_duration(&stage_results, "doctor"),
            doctor_allocator_ms: doctor_check_duration(&doctor_json, "allocator"),
            doctor_eif_ms: doctor_check_duration(&doctor_json, "eif"),
            doctor_role_ms: doctor_check_duration(&doctor_json, "role"),
            doctor_bucket_ms: doctor_check_duration(&doctor_json, "bucket"),
            doctor_kms_ms: doctor_check_duration(&doctor_json, "kms"),
            doctor_clock_ms: doctor_check_duration(&doctor_json, "clock"),
            kms_model_decrypt_ms: parse_kms_proxy_elapsed_ms(ctx),
            enclave_launch_ms: stage_duration(&stage_results, "enclave_launch"),
            synthetic_inference_ms: parse_host_inference_elapsed_ms(ctx),
            receipt_verify_ms: stage_duration(&stage_results, "receipt_verify"),
            s3_upload_ms,
            total_smoke_test_ms,
            ..Default::default()
        },
        evidence_sizes: EvidenceSizes {
            receipt_bytes: file_len(ctx.bundle_dir.join("receipt.cbor")),
            attestation_document_bytes: file_len(ctx.bundle_dir.join("attestation.cbor")),
            verification_json_bytes: file_len(ctx.bundle_dir.join("verification.json")),
            full_bundle_bytes: dir_size(&ctx.bundle_dir),
        },
        negative_tests,
        cost: CostInputs::default(),
    };
    let bytes = serde_json::to_vec_pretty(&report)
        .map_err(|e| format!("failed to serialize benchmark.json: {}", e))?;
    std::fs::write(path, bytes).map_err(|e| format!("failed to write benchmark.json: {}", e))
}

fn required_bundle_files(bundle_dir: &Path) -> Vec<PathBuf> {
    BUNDLE_FILE_NAMES
        .iter()
        .map(|name| bundle_dir.join(name))
        .collect()
}

fn upload_files(bundle_dir: &Path) -> Vec<PathBuf> {
    let mut files = required_bundle_files(bundle_dir);
    files.push(bundle_dir.join("manifest.json"));
    files.push(bundle_dir.join("SHA256SUMS"));
    files
}

struct UploadError {
    code: &'static str,
    message: String,
}

async fn upload_one(
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    prefix: &str,
    path: &Path,
) -> Result<String, UploadError> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| UploadError {
            code: "BUNDLE_FILE_READ_FAILED",
            message: format!("bad bundle filename: {}", path.display()),
        })?;
    let key = format!("{}{}", prefix, name);
    let body = std::fs::read(path).map_err(|e| UploadError {
        code: "BUNDLE_FILE_READ_FAILED",
        message: format!("failed to read {}: {}", path.display(), e),
    })?;
    s3.put_object()
        .bucket(bucket)
        .key(&key)
        .body(ByteStream::from(body))
        .server_side_encryption(aws_sdk_s3::types::ServerSideEncryption::AwsKms)
        .send()
        .await
        .map_err(|e| UploadError {
            code: "S3_PUT_FAILED",
            message: format!("failed to upload s3://{}/{}: {}", bucket, key, e),
        })?;
    Ok(key)
}

fn validate_kms_release(ctx: &Context) -> Result<(), String> {
    let path = ctx.bundle_dir.join("kms-release.json");
    let bytes =
        std::fs::read(&path).map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("{} is not valid JSON: {}", path.display(), e))?;

    require_str(&value, "status")
        .filter(|v| *v == "allowed")
        .ok_or_else(|| "kms-release.json status must be \"allowed\"".to_string())?;
    require_str_any(&value, &["model_kms_key_arn", "kms_key_arn"])
        .ok_or_else(|| "kms-release.json missing model_kms_key_arn or kms_key_arn".to_string())?;
    let aws_request_id = require_str(&value, "aws_request_id")
        .ok_or_else(|| "kms-release.json missing aws_request_id".to_string())?;
    if aws_request_id == "unavailable" {
        return Err("kms-release.json aws_request_id is unavailable; real AWS KMS response evidence is required".to_string());
    }
    require_str_any(
        &value,
        &[
            "ciphertext_for_recipient_sha256",
            "wrapped_key_sha256",
            "kms_response_sha256",
        ],
    )
    .ok_or_else(|| {
        "kms-release.json must include a hash of the recipient-bound KMS response".to_string()
    })?;

    let image_sha384 = value
        .get("recipient_attestation")
        .and_then(|v| v.get("image_sha384"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| require_str(&value, "enclave_image_sha384"))
        .ok_or_else(|| {
            "kms-release.json missing recipient_attestation.image_sha384 or enclave_image_sha384"
                .to_string()
        })?;
    if image_sha384.len() != 96 || !image_sha384.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("kms-release.json image_sha384 must be 96 hex chars".to_string());
    }
    Ok(())
}

fn require_str<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn require_str_any<'a>(value: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| require_str(value, key))
}

fn build_manifest(ctx: &Context) -> Result<crate::bundle::Manifest, Box<StageResult>> {
    let mut files = Vec::new();
    for name in BUNDLE_FILE_NAMES {
        let path = ctx.bundle_dir.join(name);
        let bytes = std::fs::read(&path).map_err(|e| {
            Box::new(StageResult::fail(
                "s3_write",
                "BUNDLE_FILE_READ_FAILED",
                format!("failed to read {}: {}", path.display(), e),
                json!({ "path": &path }),
            ))
        })?;
        files.push(crate::bundle::FileEntry {
            name: (*name).to_string(),
            sha256: hex::encode(Sha256::digest(bytes)),
        });
    }
    Ok(crate::bundle::Manifest {
        bundle_format_version: BUNDLE_FORMAT_VERSION.to_string(),
        bundle_type: BUNDLE_TYPE.to_string(),
        smoke_test_version: ctx.smoke_test_version.to_string(),
        timestamp_utc: ctx.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        stack_name: ctx.stack_name.clone(),
        account_id: ctx.account_id.clone(),
        region: ctx.region.clone(),
        fixture_version: crate::context::FIXTURE_VERSION.to_string(),
        overall_status: "pass".to_string(),
        files,
    })
}

fn write_sha256sums(bundle_dir: &Path) -> Result<(), String> {
    let mut lines = Vec::new();
    for path in required_bundle_files(bundle_dir) {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("bad bundle filename: {}", path.display()))?;
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
        lines.push(format!("{}  {}", hex::encode(Sha256::digest(bytes)), name));
    }
    std::fs::write(
        bundle_dir.join("SHA256SUMS"),
        format!("{}\n", lines.join("\n")),
    )
    .map_err(|e| format!("failed to write SHA256SUMS: {}", e))
}

async fn resolve_bucket(ctx: &Context, args: &Args) -> Result<String, String> {
    if let Some(bucket) = args
        .evidence_bucket
        .as_ref()
        .map(|b| b.trim())
        .filter(|b| !b.is_empty())
    {
        return Ok(bucket.to_string());
    }
    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let ssm = aws_sdk_ssm::Client::new(&config);
    let ssm_path = format!("/cyntrisec/pilot/config/{}/bucket-name", ctx.stack_name);
    let out = ssm
        .get_parameter()
        .name(&ssm_path)
        .send()
        .await
        .map_err(|e| format!("SSM GetParameter on '{}' failed: {}", ssm_path, e))?;
    out.parameter
        .and_then(|p| p.value)
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| format!("SSM parameter '{}' is empty", ssm_path))
}

fn file_len(path: impl AsRef<Path>) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.len())
}

fn dir_size(path: &Path) -> Option<u64> {
    let mut total = 0u64;
    for entry in std::fs::read_dir(path).ok()? {
        let entry = entry.ok()?;
        let meta = entry.metadata().ok()?;
        if meta.is_file() {
            total = total.saturating_add(meta.len());
        }
    }
    Some(total)
}

fn read_json(path: impl AsRef<Path>) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn read_stage_results(ctx: &Context) -> Option<Value> {
    read_json(ctx.bundle_dir.join("_stage-results.json"))
}

fn stage_duration(stage_results: &Option<Value>, name: &str) -> Option<u64> {
    stage_results
        .as_ref()?
        .get("stages")?
        .as_array()?
        .iter()
        .find(|stage| stage.get("stage").and_then(Value::as_str) == Some(name))?
        .get("duration_ms")?
        .as_u64()
}

fn doctor_check_duration(doctor_json: &Option<Value>, check_name: &str) -> Option<u64> {
    doctor_json
        .as_ref()?
        .get("checks")?
        .as_array()?
        .iter()
        .find(|check| check.get("check").and_then(Value::as_str) == Some(check_name))?
        .get("duration_ms")?
        .as_u64()
}

fn read_negative_tests(ctx: &Context) -> Vec<NegativeTestResult> {
    let Some(Value::Array(items)) = read_json(ctx.bundle_dir.join("negative-tests.json")) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|item| NegativeTestResult {
            name: item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            expected_failure_code: item
                .get("expected")
                .and_then(Value::as_str)
                .unwrap_or("reject")
                .to_string(),
            actual_failure_code: negative_test_failure_code(item),
            duration_ms: item.get("duration_ms").and_then(Value::as_u64),
            passed: item.get("passed").and_then(Value::as_bool).unwrap_or(false),
        })
        .collect()
}

fn negative_test_failure_code(item: &Value) -> Option<String> {
    let verifier = item.get("verifier")?;
    if let Some(code) = verifier
        .get("checks")
        .and_then(Value::as_array)
        .and_then(|checks| {
            checks
                .iter()
                .find(|check| check.get("status").and_then(Value::as_str) == Some("Fail"))
        })
        .and_then(|check| {
            check
                .get("code")
                .or_else(|| check.get("name"))
                .and_then(Value::as_str)
        })
    {
        return Some(code.to_string());
    }
    verifier
        .get("stderr_excerpt")
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .map(|_| "VerifierRejected".to_string())
}

fn parse_kms_proxy_elapsed_ms(ctx: &Context) -> Option<u64> {
    let text = std::fs::read_to_string(ctx.bundle_dir.join("kms_proxy_host.stdout")).ok()?;
    text.lines()
        .find(|line| line.contains("kms_request_complete"))
        .and_then(parse_elapsed_ms_field)
}

fn parse_host_inference_elapsed_ms(ctx: &Context) -> Option<u64> {
    let text = std::fs::read_to_string(ctx.bundle_dir.join("host_output.log")).ok()?;
    text.lines()
        .find(|line| line.contains("Inference complete"))
        .and_then(parse_elapsed_ms_field)
}

fn parse_elapsed_ms_field(line: &str) -> Option<u64> {
    let (_, rest) = line.split_once("elapsed_ms")?;
    let rest = strip_ansi_codes(rest);
    let value_text = rest
        .split_once('=')
        .map(|(_, value)| value)
        .unwrap_or(&rest);
    let digits: String = value_text
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<f64>().ok().map(|value| value.round() as u64)
}

fn strip_ansi_codes(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            let _ = chars.next();
            for code_ch in chars.by_ref() {
                if code_ch.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        output.push(ch);
    }
    output
}

fn command_output(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.is_empty() {
        return Some(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        None
    } else {
        Some(stderr)
    }
}

fn imds_metadata(path: &str) -> Option<String> {
    let token = imds_v2_token().ok();
    imds_get(path, token.as_deref()).ok()
}

fn imds_v2_token() -> Result<String, String> {
    let response = imds_request(
        "PUT",
        "/latest/api/token",
        &["X-aws-ec2-metadata-token-ttl-seconds: 60"],
    )?;
    Ok(response.trim().to_string())
}

fn imds_get(path: &str, token: Option<&str>) -> Result<String, String> {
    let mut headers = Vec::new();
    if let Some(token) = token {
        headers.push(format!("X-aws-ec2-metadata-token: {}", token));
    }
    let header_refs = headers.iter().map(String::as_str).collect::<Vec<_>>();
    let body = imds_request(
        "GET",
        &format!("/latest/meta-data/{}", path.trim_start_matches('/')),
        &header_refs,
    )?;
    Ok(body.trim().to_string())
}

fn imds_request(method: &str, path: &str, headers: &[&str]) -> Result<String, String> {
    let mut stream = TcpStream::connect_timeout(
        &"169.254.169.254:80".parse().unwrap(),
        Duration::from_millis(250),
    )
    .map_err(|e| format!("IMDS connect failed: {}", e))?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n",
        method, path
    );
    for header in headers {
        request.push_str(header);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("IMDS write failed: {}", e))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("IMDS read failed: {}", e))?;
    if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
        return Err("IMDS returned non-200".to_string());
    }
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .ok_or_else(|| "IMDS response missing body".to_string())
}
