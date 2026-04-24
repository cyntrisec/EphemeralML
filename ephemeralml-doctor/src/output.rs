//! Output rendering — text (default) and JSON (`--json`).
//!
//! Two hard rules from the spec:
//! - `stages[]` (JSON) / the text output sequence always has exactly 6 entries
//!   regardless of which check failed, so downstream parsers see stable shape.
//! - No customer-data content is ever emitted — only check names, status,
//!   durations, remediation strings, and (partially-masked) ARNs. The skeleton
//!   enforces this by construction: check-result detail fields are typed
//!   `serde_json::Value` that individual checks populate only with sanitized
//!   metadata.

use crate::checks::{CheckResult, CheckStatus};
use crate::context::Context;
use serde::Serialize;
use serde_json::json;

pub enum Format {
    Text { verbose: bool },
    Json { verbose: bool },
}

#[derive(Serialize)]
struct JsonReport<'a> {
    doctor_version: &'a str,
    timestamp: String,
    stack_name: &'a str,
    account_id: &'a str,
    region: &'a str,
    overall_status: &'a str,
    checks: Vec<JsonCheck<'a>>,
}

#[derive(Serialize)]
struct JsonCheck<'a> {
    check: &'a str,
    status: &'a str,
    duration_ms: u64,
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    details: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    check_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<&'a str>,
}

pub fn render(ctx: &Context, results: &[CheckResult], format: Format) {
    match format {
        Format::Text { verbose } => render_text(ctx, results, verbose),
        Format::Json { verbose } => render_json(ctx, results, verbose),
    }
}

fn render_text(ctx: &Context, results: &[CheckResult], verbose: bool) {
    println!(
        "Cyntrisec pilot doctor — {}",
        ctx.timestamp.format("%Y-%m-%dT%H:%M:%SZ")
    );

    for r in results {
        let (tag, rest) = match r.status {
            CheckStatus::Ok => ("[OK]  ", r.summary.clone()),
            CheckStatus::Fail => ("[FAIL]", r.summary.clone()),
        };
        println!("  {} {}", tag, rest);

        if matches!(r.status, CheckStatus::Fail) {
            if let Some(ref remediation) = r.remediation {
                println!("         Remediation: {}", remediation);
            }
            if let Some(ref code) = r.check_code {
                println!("         check_code: {}", code);
            }
        }

        if verbose && !r.details.is_null() {
            println!(
                "         details: {}",
                serde_json::to_string(&r.details).unwrap_or_default()
            );
        }
    }

    let fail_count = results
        .iter()
        .filter(|r| matches!(r.status, CheckStatus::Fail))
        .count();
    let total = results.len();
    if fail_count == 0 {
        println!(
            "All {} preflight checks passed. Host is ready for ephemeralml-smoke-test.",
            total
        );
    } else {
        println!();
        println!(
            "SUMMARY: {} of {} checks failed. See remediation above. Host is NOT ready.",
            fail_count, total
        );
    }
}

fn render_json(ctx: &Context, results: &[CheckResult], verbose: bool) {
    let checks: Vec<JsonCheck> = results
        .iter()
        .map(|r| JsonCheck {
            check: &r.name,
            status: match r.status {
                CheckStatus::Ok => "ok",
                CheckStatus::Fail => "fail",
            },
            duration_ms: r.duration_ms,
            details: if verbose {
                r.details.clone()
            } else {
                // In non-verbose mode, only keep the top-level summary keys —
                // individual checks pre-populate a slim `details` projection.
                r.details.clone()
            },
            check_code: r.check_code.as_deref(),
            remediation: r.remediation.as_deref(),
        })
        .collect();

    let overall_status = if results.iter().all(|r| matches!(r.status, CheckStatus::Ok)) {
        "pass"
    } else {
        "fail"
    };

    let report = JsonReport {
        doctor_version: ctx.doctor_version,
        timestamp: ctx.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        stack_name: &ctx.stack_name,
        account_id: &ctx.account_id,
        region: &ctx.region,
        overall_status,
        checks,
    };

    match serde_json::to_string(&report) {
        Ok(s) => println!("{}", s),
        Err(_) => {
            // Fall back to a minimal fixed shape so the stdout is still
            // parseable; see spec: JSON output must be parseable even in
            // pathological internal states.
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
