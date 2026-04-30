//! Output rendering — text (default) and JSON (`--json`).
//!
//! Hard spec rules:
//! - `stages[]` ALWAYS has exactly 5 entries regardless of where failure
//!   occurred. Non-reached stages carry `status: "skipped"` + a reason.
//! - No customer workflow data is emitted — the synthetic fixture is the
//!   only input path, so by construction nothing customer-specific can leak.

use crate::context::Context;
use crate::stages::{StageResult, StageStatus};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

pub enum Format {
    Text { verbose: bool },
    Json { verbose: bool },
}

#[derive(Serialize)]
struct JsonReport<'a> {
    smoke_test_version: &'a str,
    timestamp_utc: String,
    stack_name: &'a str,
    account_id: &'a str,
    region: &'a str,
    fixture_version: &'a str,
    overall_status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_stage: Option<&'a str>,
    total_duration_ms: u64,
    stages: Vec<JsonStage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_s3_uri: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    on_host_bundle_path: Option<&'a str>,
}

#[derive(Serialize)]
struct JsonStage<'a> {
    stage: &'a str,
    status: &'a str,
    duration_ms: u64,
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    details: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    check_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

pub fn render(ctx: &Context, results: &[StageResult], format: Format) {
    match format {
        Format::Text { verbose } => render_text(ctx, results, verbose),
        Format::Json { verbose } => render_json(ctx, results, verbose),
    }
}

fn render_text(ctx: &Context, results: &[StageResult], verbose: bool) {
    println!(
        "Cyntrisec pilot smoke test — {}",
        ctx.timestamp.format("%Y-%m-%dT%H:%M:%SZ")
    );

    let total = results.len();
    for (i, r) in results.iter().enumerate() {
        let tag = match r.status {
            StageStatus::Pass => "OK     ",
            StageStatus::Fail => "FAIL   ",
            StageStatus::Skipped => "SKIPPED",
        };
        let duration = format_duration(r.duration_ms);
        println!(
            "  [{}/{}] {:<25} {}  ({})",
            i + 1,
            total,
            r.stage_label(),
            tag,
            duration
        );

        if matches!(r.status, StageStatus::Fail) {
            if let Some(ref err) = r.error {
                println!("         {}", err);
            }
            if let Some(ref code) = r.check_code {
                println!("         check_code: {}", code);
            }
        }
        if matches!(r.status, StageStatus::Skipped) {
            if let Some(ref reason) = r.reason {
                println!("         reason: {}", reason);
            }
        }
        if verbose && !r.details.is_null() {
            println!(
                "         details: {}",
                serde_json::to_string(&r.details).unwrap_or_default()
            );
        }
    }

    let failed = results
        .iter()
        .find(|r| matches!(r.status, StageStatus::Fail));
    match failed {
        None => {
            println!("SMOKE TEST PASSED.");
        }
        Some(f) => {
            println!();
            println!("SMOKE TEST FAILED at stage: {}", f.stage_name());
        }
    }
}

fn render_json(ctx: &Context, results: &[StageResult], _verbose: bool) {
    let failed_stage = results
        .iter()
        .find(|r| matches!(r.status, StageStatus::Fail))
        .map(|r| r.stage_name());
    let overall_status = if failed_stage.is_some() {
        "fail"
    } else {
        "pass"
    };
    let total_duration_ms: u64 = results.iter().map(|r| r.duration_ms).sum();
    let evidence_s3_uri = evidence_s3_uri(results);
    let receipt_sha256 = file_sha256_hex(ctx.bundle_dir.join("receipt.cbor"));
    let on_host_bundle_path = ctx.bundle_dir.to_string_lossy().to_string();

    let stages: Vec<JsonStage> = results
        .iter()
        .map(|r| JsonStage {
            stage: r.stage_name(),
            status: match r.status {
                StageStatus::Pass => "pass",
                StageStatus::Fail => "fail",
                StageStatus::Skipped => "skipped",
            },
            duration_ms: r.duration_ms,
            details: r.details.clone(),
            check_code: r.check_code.as_deref(),
            error: r.error.as_deref(),
            reason: r.reason.as_deref(),
        })
        .collect();

    let report = JsonReport {
        smoke_test_version: ctx.smoke_test_version,
        timestamp_utc: ctx.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        stack_name: &ctx.stack_name,
        account_id: &ctx.account_id,
        region: &ctx.region,
        fixture_version: crate::context::FIXTURE_VERSION,
        overall_status,
        failed_stage,
        total_duration_ms,
        stages,
        evidence_s3_uri: evidence_s3_uri.as_deref(),
        receipt_sha256: receipt_sha256.as_deref(),
        on_host_bundle_path: Some(&on_host_bundle_path),
    };

    match serde_json::to_string(&report) {
        Ok(s) => println!("{}", s),
        Err(_) => {
            println!(
                "{}",
                json!({
                    "overall_status": overall_status,
                    "error": "serialization failed",
                })
            );
        }
    }
}

fn evidence_s3_uri(results: &[StageResult]) -> Option<String> {
    let s3 = results
        .iter()
        .find(|r| r.stage_name() == "s3_write" && matches!(r.status, StageStatus::Pass))?;
    let bucket = s3
        .details
        .get("bucket")
        .and_then(serde_json::Value::as_str)?;
    let prefix = s3
        .details
        .get("prefix")
        .and_then(serde_json::Value::as_str)?;
    Some(format!("s3://{}/{}", bucket, prefix))
}

fn file_sha256_hex(path: impl AsRef<std::path::Path>) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(hex::encode(Sha256::digest(bytes)))
}

fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}
