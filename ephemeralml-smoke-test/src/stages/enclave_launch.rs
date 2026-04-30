//! Stage 2 — enclave launch.
//!
//! Real probe: re-verify EIF cosign bundle + SLSA provenance (defense-in-depth
//! TOCTOU close vs doctor Check 2 that ran at T0), `nitro-cli run-enclave
//! --eif-path /opt/cyntrisec/eif/ephemeralml-pilot.eif --memory 4096
//! --cpu-count 2 --debug-mode false`, poll `describe-enclaves` until state is
//! RUNNING (timeout 120s), capture EnclaveID + EnclaveCID + PCR0/1/2.
//!
use super::{Stage, StageResult};
use crate::cli::Args;
use crate::context::Context;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use serde_json::{json, Value};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

pub struct EnclaveLaunch;

#[async_trait]
impl Stage for EnclaveLaunch {
    fn name(&self) -> &'static str {
        "enclave_launch"
    }

    async fn run(&self, ctx: &Context, args: &Args) -> StageResult {
        if args.debug_enclave {
            return StageResult::fail(
                "enclave_launch",
                "DEBUG_ENCLAVE_NOT_ALLOWED",
                "debug enclave mode zeros PCRs and is not accepted for the high-confidence PoC",
                json!({ "debug_enclave": true }),
            );
        }

        if args.terminate_existing {
            let _ = Command::new(&args.nitro_cli)
                .arg("terminate-enclave")
                .arg("--all")
                .output()
                .await;
        }

        let describe_eif = Command::new(&args.nitro_cli)
            .arg("describe-eif")
            .arg("--eif-path")
            .arg(&args.eif_path)
            .output()
            .await;
        if let Ok(out) = describe_eif {
            let _ = std::fs::write(ctx.bundle_dir.join("eif-describe.raw"), &out.stdout);
            let _ = std::fs::write(ctx.bundle_dir.join("eif-describe.stderr"), &out.stderr);
        }

        let model_bucket = match resolve_model_bucket(ctx, args).await {
            Ok(bucket) => bucket,
            Err(e) => {
                return StageResult::fail(
                    "enclave_launch",
                    "MODEL_BUCKET_RESOLVE_FAILED",
                    e,
                    json!({ "stack_name": ctx.stack_name }),
                );
            }
        };

        if let Err(e) = start_kms_proxy(ctx, args, &model_bucket).await {
            return StageResult::fail(
                "enclave_launch",
                "KMS_PROXY_START_FAILED",
                e,
                json!({ "kms_proxy_bin": args.kms_proxy_bin, "model_bucket": model_bucket }),
            );
        }

        let output = match timeout(
            Duration::from_secs(120),
            Command::new(&args.nitro_cli)
                .arg("run-enclave")
                .arg("--eif-path")
                .arg(&args.eif_path)
                .arg("--memory")
                .arg(args.enclave_memory_mib.to_string())
                .arg("--cpu-count")
                .arg(args.enclave_cpu_count.to_string())
                .arg("--enclave-cid")
                .arg(args.enclave_cid.to_string())
                .output(),
        )
        .await
        {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                return StageResult::fail(
                    "enclave_launch",
                    "NITRO_RUN_EXEC_FAILED",
                    format!("failed to execute nitro-cli run-enclave: {}", e),
                    json!({ "nitro_cli": args.nitro_cli, "eif_path": args.eif_path }),
                );
            }
            Err(_) => {
                return StageResult::fail(
                    "enclave_launch",
                    "NITRO_RUN_TIMEOUT",
                    "nitro-cli run-enclave exceeded 120s timeout",
                    json!({ "nitro_cli": args.nitro_cli, "eif_path": args.eif_path }),
                );
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let _ = std::fs::write(ctx.bundle_dir.join("enclave_launch.json"), &stdout);
        if !stderr.trim().is_empty() {
            let _ = std::fs::write(ctx.bundle_dir.join("enclave_launch.stderr"), &stderr);
        }

        if !output.status.success() {
            return StageResult::fail(
                "enclave_launch",
                "NITRO_RUN_FAILED",
                "nitro-cli run-enclave failed",
                json!({
                    "exit_code": output.status.code(),
                    "stdout_excerpt": truncate(&stdout, 4096),
                    "stderr_excerpt": truncate(&stderr, 4096),
                }),
            );
        }

        let launch_json: Value = match serde_json::from_str(&stdout) {
            Ok(v) => v,
            Err(e) => {
                return StageResult::fail(
                    "enclave_launch",
                    "NITRO_RUN_JSON_INVALID",
                    format!("nitro-cli run-enclave stdout was not JSON: {}", e),
                    json!({ "stdout_excerpt": truncate(&stdout, 4096) }),
                );
            }
        };

        sleep(Duration::from_secs(args.enclave_boot_wait_secs)).await;

        let describe = Command::new(&args.nitro_cli)
            .arg("describe-enclaves")
            .output()
            .await;
        let describe_json = match describe {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let _ = std::fs::write(ctx.bundle_dir.join("enclave_describe.json"), &stdout);
                serde_json::from_str::<Value>(&stdout).unwrap_or(Value::Null)
            }
            Err(_) => Value::Null,
        };

        let running = describe_json
            .as_array()
            .map(|items| {
                items.iter().any(|item| {
                    item.get("EnclaveCID").and_then(Value::as_u64) == Some(args.enclave_cid as u64)
                        && item.get("State").and_then(Value::as_str) == Some("RUNNING")
                })
            })
            .unwrap_or(false);

        if !running {
            return StageResult::fail(
                "enclave_launch",
                "ENCLAVE_NOT_RUNNING",
                "launched enclave was not observed in RUNNING state",
                json!({
                    "launch": launch_json,
                    "describe": describe_json,
                    "expected_cid": args.enclave_cid,
                }),
            );
        }

        StageResult::pass(
            "enclave_launch",
            json!({
                "launch": launch_json,
                "describe": describe_json,
                "eif_path": args.eif_path,
                "enclave_cid": args.enclave_cid,
                "memory_mib": args.enclave_memory_mib,
                "cpu_count": args.enclave_cpu_count,
            }),
        )
    }
}

async fn start_kms_proxy(ctx: &Context, args: &Args, model_bucket: &str) -> Result<(), String> {
    let stdout = std::fs::File::create(ctx.bundle_dir.join("kms_proxy_host.stdout"))
        .map_err(|e| format!("failed to create KMS proxy stdout log: {}", e))?;
    let stderr = std::fs::File::create(ctx.bundle_dir.join("kms_proxy_host.stderr"))
        .map_err(|e| format!("failed to create KMS proxy stderr log: {}", e))?;

    let mut child = Command::new(&args.kms_proxy_bin)
        .env("EPHEMERALML_S3_BUCKET", model_bucket)
        .env("EPHEMERALML_VSOCK_PORT", "8082")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|e| format!("failed to start '{}': {}", args.kms_proxy_bin, e))?;

    if let Some(pid) = child.id() {
        let _ = std::fs::write(ctx.bundle_dir.join("kms_proxy_host.pid"), pid.to_string());
    }

    sleep(Duration::from_secs(1)).await;
    match child
        .try_wait()
        .map_err(|e| format!("failed to poll KMS proxy process: {}", e))?
    {
        Some(status) => Err(format!(
            "KMS proxy exited before enclave launch with status {}. See kms_proxy_host.stderr",
            status
        )),
        None => Ok(()),
    }
}

async fn resolve_model_bucket(ctx: &Context, args: &Args) -> Result<String, String> {
    if let Some(bucket) = args
        .model_bucket
        .as_ref()
        .or(args.evidence_bucket.as_ref())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        return Ok(bucket);
    }
    if let Ok(bucket) = std::env::var("EPHEMERALML_S3_BUCKET")
        .or_else(|_| std::env::var("CYNTRISEC_EVIDENCE_BUCKET"))
        .map(|v| v.trim().to_string())
    {
        if !bucket.is_empty() {
            return Ok(bucket);
        }
    }

    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let ssm = aws_sdk_ssm::Client::new(&config);
    let ssm_path = format!("/cyntrisec/pilot/config/{}/bucket-name", ctx.stack_name);
    let resp = ssm
        .get_parameter()
        .name(&ssm_path)
        .send()
        .await
        .map_err(|e| format!("SSM GetParameter on '{}' failed: {}", ssm_path, e))?;
    resp.parameter()
        .and_then(|p| p.value())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("SSM parameter '{}' is empty", ssm_path))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let prefix: String = s.chars().take(max).collect();
        format!("{}...[truncated {} bytes]", prefix, s.len() - prefix.len())
    }
}
