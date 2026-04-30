//! Stage 1 — doctor preflight.
//!
//! Real probe: invoke `/opt/cyntrisec/bin/ephemeralml-doctor --json` as a
//! subprocess with a 60-second timeout; parse stdout as JSON; require
//! `overall_status == "pass"` and all 6 checks `"ok"`. Failure aborts the
//! smoke test with `failed_stage: doctor` and includes the doctor output
//! verbatim in the evidence bundle's `doctor.json` file.
//!
//! This stage is intentionally a subprocess boundary instead of linking the
//! doctor crate directly: the PoC must exercise the same binary a customer
//! runs from the admin quickstart.

use super::{Stage, StageResult};
use crate::cli::Args;
use crate::context::Context;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

pub struct Doctor;

#[async_trait]
impl Stage for Doctor {
    fn name(&self) -> &'static str {
        "doctor"
    }

    async fn run(&self, ctx: &Context, args: &Args) -> StageResult {
        let mut cmd = Command::new(&args.doctor_bin);
        cmd.arg("--json").arg("--stack-name").arg(&ctx.stack_name);
        if args.verbose {
            cmd.arg("--verbose");
        }

        let output =
            match timeout(Duration::from_secs(args.doctor_timeout_secs), cmd.output()).await {
                Ok(Ok(output)) => output,
                Ok(Err(e)) => {
                    return StageResult::fail(
                        "doctor",
                        "DOCTOR_EXEC_FAILED",
                        format!(
                            "failed to execute doctor binary '{}': {}",
                            args.doctor_bin, e
                        ),
                        json!({
                            "doctor_bin": args.doctor_bin,
                            "stack_name": ctx.stack_name,
                        }),
                    );
                }
                Err(_) => {
                    return StageResult::fail(
                        "doctor",
                        "DOCTOR_TIMEOUT",
                        format!(
                            "doctor preflight exceeded {}s timeout",
                            args.doctor_timeout_secs
                        ),
                        json!({
                            "doctor_bin": args.doctor_bin,
                            "stack_name": ctx.stack_name,
                            "timeout_secs": args.doctor_timeout_secs,
                        }),
                    );
                }
            };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let doctor_json: Value = match serde_json::from_str(&stdout) {
            Ok(value) => value,
            Err(e) => {
                return StageResult::fail(
                    "doctor",
                    "DOCTOR_JSON_INVALID",
                    format!("doctor stdout was not valid JSON: {}", e),
                    json!({
                        "doctor_bin": args.doctor_bin,
                        "exit_code": output.status.code(),
                        "stdout_excerpt": truncate(&stdout, 4096),
                        "stderr_excerpt": truncate(&stderr, 4096),
                    }),
                );
            }
        };
        let _ = std::fs::write(ctx.bundle_dir.join("doctor.json"), &stdout);

        let overall_pass =
            doctor_json.get("overall_status").and_then(Value::as_str) == Some("pass");
        let checks_pass = doctor_json
            .get("checks")
            .and_then(Value::as_array)
            .map(|checks| {
                checks.len() == 6
                    && checks
                        .iter()
                        .all(|c| c.get("status").and_then(Value::as_str) == Some("ok"))
            })
            .unwrap_or(false);

        let details = json!({
            "doctor_bin": args.doctor_bin,
            "exit_code": output.status.code(),
            "doctor": doctor_json,
            "stderr_excerpt": if stderr.trim().is_empty() {
                Value::Null
            } else {
                Value::String(truncate(&stderr, 4096))
            },
        });

        if output.status.success() && overall_pass && checks_pass {
            StageResult::pass("doctor", details)
        } else {
            StageResult::fail(
                "doctor",
                "DOCTOR_FAILED",
                "doctor preflight did not pass all 6 checks",
                details,
            )
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let prefix: String = s.chars().take(max).collect();
        format!("{}...[truncated {} bytes]", prefix, s.len() - prefix.len())
    }
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn truncate_leaves_short_strings_unchanged() {
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn truncate_marks_long_strings() {
        let out = truncate("abcdef", 3);
        assert!(out.starts_with("abc...[truncated "));
    }
}
