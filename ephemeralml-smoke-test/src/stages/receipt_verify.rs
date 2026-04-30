//! Stage 4 — in-process AIR v1 receipt verification BEFORE S3 upload.
//!
//! This is the gating stage for bundle persistence: if verification fails,
//! Stage 5 is skipped and the on-host bundle is preserved at
//! `/tmp/cyntrisec-smoke-{uuid}/` for post-mortem, but NOTHING is written to
//! S3. Bad receipts never leave the host.
//!
//! Real probe: invoke the production `ephemeralml-verify` CLI on the AIR
//! receipt and Nitro attestation sidecar. Then run local negative checks for
//! tampered receipt, tampered attestation, and wrong model hash.
//!
use super::{Stage, StageResult};
use crate::cli::Args;
use crate::context::Context;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

pub struct ReceiptVerify;

#[async_trait]
impl Stage for ReceiptVerify {
    fn name(&self) -> &'static str {
        "receipt_verify"
    }

    async fn run(&self, ctx: &Context, args: &Args) -> StageResult {
        let receipt = ctx.bundle_dir.join("receipt.cbor");
        let attestation = ctx.bundle_dir.join("attestation.cbor");
        if !receipt.exists() || !attestation.exists() {
            return StageResult::fail(
                "receipt_verify",
                "VERIFY_INPUTS_MISSING",
                "receipt.cbor and attestation.cbor must exist before verification",
                json!({
                    "receipt_exists": receipt.exists(),
                    "attestation_exists": attestation.exists(),
                }),
            );
        }

        let mut cmd = Command::new(&args.verifier_bin);
        cmd.arg(&receipt)
            .arg("--attestation")
            .arg(&attestation)
            .arg("--expected-model")
            .arg(&args.expected_model)
            .arg("--expected-security-mode")
            .arg(&args.expected_security_mode)
            .arg("--measurement-type")
            .arg(&args.measurement_type)
            .arg("--max-age")
            .arg(args.max_age_secs.to_string())
            .arg("--format")
            .arg("json")
            .arg("--plain");
        if let Some(ref expected_model_hash) = args.expected_model_hash {
            cmd.arg("--expected-model-hash").arg(expected_model_hash);
        }

        let output = match timeout(Duration::from_secs(60), cmd.output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                return StageResult::fail(
                    "receipt_verify",
                    "VERIFIER_EXEC_FAILED",
                    format!("failed to execute verifier '{}': {}", args.verifier_bin, e),
                    json!({ "verifier_bin": args.verifier_bin }),
                );
            }
            Err(_) => {
                return StageResult::fail(
                    "receipt_verify",
                    "VERIFIER_TIMEOUT",
                    "offline verifier exceeded 60s timeout",
                    json!({ "verifier_bin": args.verifier_bin }),
                );
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let _ = std::fs::write(ctx.bundle_dir.join("verification.json"), &stdout);
        if !stderr.trim().is_empty() {
            let _ = std::fs::write(ctx.bundle_dir.join("verification.stderr"), &stderr);
        }

        let verification_json: Value = match serde_json::from_str(&stdout) {
            Ok(v) => v,
            Err(e) => {
                return StageResult::fail(
                    "receipt_verify",
                    "VERIFIER_JSON_INVALID",
                    format!("verifier stdout was not JSON: {}", e),
                    json!({
                        "exit_code": output.status.code(),
                        "stdout_excerpt": truncate(&stdout, 4096),
                        "stderr_excerpt": truncate(&stderr, 4096),
                    }),
                );
            }
        };

        let verified = verification_json
            .get("verified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if output.status.success() && verified {
            let negative_tests = match run_negative_tests(ctx, args, &receipt, &attestation).await {
                Ok(results) => results,
                Err(e) => {
                    return StageResult::fail(
                        "receipt_verify",
                        "NEGATIVE_TEST_FAILED",
                        e,
                        json!({ "bundle_dir": &ctx.bundle_dir }),
                    );
                }
            };
            let _ = std::fs::write(
                ctx.bundle_dir.join("approval-report.md"),
                approval_report(ctx, args, &verification_json, &negative_tests),
            );
            StageResult::pass(
                "receipt_verify",
                json!({
                    "verification": verification_json,
                    "negative_tests": negative_tests,
                    "receipt": receipt,
                    "attestation": attestation,
                }),
            )
        } else {
            StageResult::fail(
                "receipt_verify",
                "AIR_VERIFY_FAILED",
                "offline AIR verification failed",
                json!({
                    "exit_code": output.status.code(),
                    "verification": verification_json,
                    "stderr_excerpt": truncate(&stderr, 4096),
                }),
            )
        }
    }
}

async fn run_negative_tests(
    ctx: &Context,
    args: &Args,
    receipt: &Path,
    attestation: &Path,
) -> Result<Value, String> {
    let mut results = Vec::new();

    let tampered_receipt = ctx.bundle_dir.join("negative-tampered-receipt.cbor");
    tamper_copy(receipt, &tampered_receipt)?;
    results.push(
        run_expected_reject(
            "tampered_receipt",
            args,
            &tampered_receipt,
            attestation,
            args.expected_model_hash.as_deref(),
        )
        .await?,
    );

    let tampered_attestation = ctx.bundle_dir.join("negative-tampered-attestation.cbor");
    tamper_copy(attestation, &tampered_attestation)?;
    results.push(
        run_expected_reject(
            "wrong_attestation_sidecar",
            args,
            receipt,
            &tampered_attestation,
            args.expected_model_hash.as_deref(),
        )
        .await?,
    );

    let wrong_model_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    results.push(
        run_expected_reject(
            "wrong_model_hash",
            args,
            receipt,
            attestation,
            Some(wrong_model_hash),
        )
        .await?,
    );

    let value = Value::Array(results);
    let bytes = serde_json::to_vec_pretty(&value)
        .map_err(|e| format!("failed to serialize negative-tests.json: {}", e))?;
    std::fs::write(ctx.bundle_dir.join("negative-tests.json"), bytes)
        .map_err(|e| format!("failed to write negative-tests.json: {}", e))?;
    Ok(value)
}

async fn run_expected_reject(
    name: &str,
    args: &Args,
    receipt: &Path,
    attestation: &Path,
    expected_model_hash: Option<&str>,
) -> Result<Value, String> {
    let mut cmd = Command::new(&args.verifier_bin);
    cmd.arg(receipt)
        .arg("--attestation")
        .arg(attestation)
        .arg("--expected-model")
        .arg(&args.expected_model)
        .arg("--expected-security-mode")
        .arg(&args.expected_security_mode)
        .arg("--measurement-type")
        .arg(&args.measurement_type)
        .arg("--max-age")
        .arg(args.max_age_secs.to_string())
        .arg("--format")
        .arg("json")
        .arg("--plain");
    if let Some(hash) = expected_model_hash {
        cmd.arg("--expected-model-hash").arg(hash);
    }

    let output = timeout(Duration::from_secs(60), cmd.output())
        .await
        .map_err(|_| format!("negative test '{}' verifier timeout", name))?
        .map_err(|e| format!("negative test '{}' failed to execute verifier: {}", name, e))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let parsed = serde_json::from_str::<Value>(&stdout).unwrap_or_else(|_| {
        json!({
            "stdout_excerpt": truncate(&stdout, 2048),
            "stderr_excerpt": truncate(&stderr, 2048),
        })
    });
    let verified = parsed
        .get("verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let rejected = !output.status.success() || !verified;
    if !rejected {
        return Err(format!(
            "negative test '{}' unexpectedly verified successfully",
            name
        ));
    }

    Ok(json!({
        "name": name,
        "expected": "reject",
        "passed": true,
        "exit_code": output.status.code(),
        "verifier": parsed,
    }))
}

fn tamper_copy(src: &Path, dst: &Path) -> Result<(), String> {
    let mut bytes =
        std::fs::read(src).map_err(|e| format!("failed to read {}: {}", src.display(), e))?;
    if bytes.is_empty() {
        return Err(format!("cannot tamper empty file {}", src.display()));
    }
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(dst, bytes).map_err(|e| format!("failed to write {}: {}", dst.display(), e))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let prefix: String = s.chars().take(max).collect();
        format!("{}...[truncated {} bytes]", prefix, s.len() - prefix.len())
    }
}

fn approval_report(
    ctx: &Context,
    args: &Args,
    verification: &Value,
    negative_tests: &Value,
) -> String {
    format!(
        "# Cyntrisec AWS-Native PoC Approval Evidence\n\n\
         Status: PASS\n\n\
         Timestamp: {}\n\n\
         Stack: `{}`\n\n\
         Account: `{}`\n\n\
         Region: `{}`\n\n\
         Verified model: `{}`\n\n\
         Expected security mode: `{}`\n\n\
         Measurement type: `{}`\n\n\
         Evidence directory: `{}`\n\n\
         What was verified:\n\n\
         - AIR receipt cryptographic verification passed.\n\
         - The verifier used the supplied Nitro attestation document as the AIR signing-key source.\n\
         - The verifier enforced the expected model, security mode, measurement type, and freshness policy.\n\
         - The AIR `attestation_doc_hash` was checked against the supplied attestation document by the verifier.\n\n\
         Negative checks:\n\n\
         - Tampered receipt rejected.\n\
         - Tampered attestation sidecar rejected.\n\
         - Wrong model hash rejected.\n\n\
         What this does not prove:\n\n\
         - It does not prove model safety, fairness, regulatory compliance, or GPU attestation.\n\
         - It does not prove irrecoverable deletion of all possible copies.\n\
         - It is CPU Nitro evidence only.\n\n\
         Machine-readable verifier result is stored in `verification.json`.\n\n\
         Verifier summary:\n\n```json\n{}\n```\n\n\
         Negative-test summary:\n\n```json\n{}\n```\n",
        ctx.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
        ctx.stack_name,
        ctx.account_id,
        ctx.region,
        args.expected_model,
        args.expected_security_mode,
        args.measurement_type,
        ctx.bundle_dir.display(),
        serde_json::to_string_pretty(verification).unwrap_or_else(|_| "{}".to_string()),
        serde_json::to_string_pretty(negative_tests).unwrap_or_else(|_| "[]".to_string())
    )
}
