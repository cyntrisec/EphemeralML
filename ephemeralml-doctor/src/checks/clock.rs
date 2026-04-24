//! Check 6 — System clock within 5 seconds of NTP reference.
//!
//! Spec: `byoc-phase-1-ephemeralml-doctor-spec-2026-04-23.md` § Check 6.
//!
//! Probes `chronyc tracking` and parses the `Last offset` field. Passes iff
//! `|offset| < 5 seconds`. Catching clock skew here produces a clean
//! remediation instead of a confusing downstream receipt-verification
//! failure from mismatched `iat` claims.
//!
//! On non-chrony hosts the check fails cleanly with a
//! `CLOCK_CHRONYD_NOT_RUNNING` code rather than a generic "probe failed".
//! Amazon Linux 2023 ships chronyd enabled by default so this failure
//! typically means either chronyd was stopped after provisioning or the
//! customer's security group is blocking outbound UDP/123 to time.aws.com.

use super::{Check, CheckResult, CheckStatus};
use crate::context::Context;
use async_trait::async_trait;
use serde_json::json;
use std::time::Instant;

/// Maximum absolute offset (seconds) between system time and NTP reference
/// that still counts as a pass. AIR v1 receipts' `iat` claim tolerance
/// downstream is looser than this, but catching >= 5s here produces a clean
/// actionable remediation before the smoke-test fails with a confusing
/// cryptographic error.
const MAX_OFFSET_SECONDS: f64 = 5.0;

const CHRONYC_BIN: &str = "chronyc";

pub struct Clock;

/// Parsed projection over `chronyc tracking` output. `reference` is the
/// NTP server identifier — on AL2023 EC2 this is typically
/// `169.254.169.123` (Amazon Time Sync Service) or `time.aws.com`.
#[derive(Debug, PartialEq)]
struct TrackingStatus {
    last_offset_seconds: f64,
    reference: Option<String>,
}

#[derive(Debug, PartialEq)]
enum ParseError {
    NoLastOffsetLine,
    InvalidOffset(String),
}

#[async_trait]
impl Check for Clock {
    fn name(&self) -> &'static str {
        "clock"
    }

    async fn run(&self, _ctx: &Context) -> CheckResult {
        let start = Instant::now();

        let output = match run_chronyc_tracking().await {
            Ok(o) => o,
            Err(ChronycError::DaemonNotRunning) => {
                return fail(
                    start,
                    "CLOCK_CHRONYD_NOT_RUNNING",
                    "chronyd is not running".to_string(),
                    "sudo systemctl start chronyd; wait 30 seconds; re-run doctor. \
                     Amazon Linux 2023 has chronyd pre-installed and enabled by default; \
                     if it's down, something stopped it after provisioning.",
                );
            }
            Err(ChronycError::BinaryNotFound) => {
                return fail(
                    start,
                    "CLOCK_CHRONYC_MISSING",
                    "chronyc binary not found on PATH".to_string(),
                    "chronyc is expected on Amazon Linux 2023 by default. If the host \
                     was customized to remove it, install the `chrony` package: \
                     sudo dnf install -y chrony.",
                );
            }
            Err(ChronycError::Other(msg)) => {
                return fail(
                    start,
                    "CLOCK_PROBE_FAILED",
                    format!("chronyc tracking failed: {}", msg),
                    "inspect chronyd status: sudo systemctl status chronyd; \
                     review /var/log/chrony/ for errors.",
                );
            }
        };

        let status = match parse_tracking(&output) {
            Ok(s) => s,
            Err(ParseError::NoLastOffsetLine) => {
                return fail(
                    start,
                    "CLOCK_PARSE_FAILED",
                    "chronyc tracking output did not contain a `Last offset` line".to_string(),
                    "check chronyc version / output format; the doctor parser expects \
                     standard chronyc 4.x output.",
                );
            }
            Err(ParseError::InvalidOffset(v)) => {
                return fail(
                    start,
                    "CLOCK_PARSE_FAILED",
                    format!("could not parse Last offset value '{}'", v),
                    "unexpected chronyc output; share the doctor --verbose output with \
                     Cyntrisec support.",
                );
            }
        };

        if status.last_offset_seconds.abs() >= MAX_OFFSET_SECONDS {
            return fail(
                start,
                "CLOCK_OFFSET_TOO_LARGE",
                format!(
                    "Clock offset is {:.3} seconds from NTP reference",
                    status.last_offset_seconds
                ),
                "check /etc/chrony.conf for misconfigured servers; check security group \
                 allows outbound UDP/123 to time.aws.com or configured NTP servers; \
                 for severe skew, sudo chronyc makestep to force an immediate correction.",
            );
        }

        // Pass
        CheckResult {
            name: "clock".to_string(),
            status: CheckStatus::Ok,
            duration_ms: start.elapsed().as_millis() as u64,
            summary: format!(
                "System clock within {} seconds of NTP reference (current offset: {:.3}s)",
                MAX_OFFSET_SECONDS as u32, status.last_offset_seconds
            ),
            details: json!({
                "offset_seconds": status.last_offset_seconds,
                "ntp_reference": status.reference,
                "max_offset_seconds": MAX_OFFSET_SECONDS,
            }),
            check_code: None,
            remediation: None,
        }
    }
}

// --- probes ----------------------------------------------------------------

#[derive(Debug)]
enum ChronycError {
    /// chronyc exists but chronyd is not running (chronyc prints something
    /// like "506 Cannot talk to daemon").
    DaemonNotRunning,
    /// chronyc binary not on PATH (exec returned ENOENT).
    BinaryNotFound,
    Other(String),
}

async fn run_chronyc_tracking() -> Result<String, ChronycError> {
    let output = match tokio::process::Command::new(CHRONYC_BIN)
        .arg("tracking")
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ChronycError::BinaryNotFound);
        }
        Err(e) => return Err(ChronycError::Other(e.to_string())),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // chronyc's canonical "daemon not up" message.
        if stderr.contains("506") || stderr.contains("Cannot talk to daemon") {
            return Err(ChronycError::DaemonNotRunning);
        }
        return Err(ChronycError::Other(format!(
            "chronyc exited {}: {}",
            output.status,
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// --- parser ----------------------------------------------------------------

fn parse_tracking(output: &str) -> Result<TrackingStatus, ParseError> {
    let mut last_offset: Option<f64> = None;
    let mut reference: Option<String> = None;

    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("Last offset") {
            // "Last offset     : +0.000024000 seconds"
            let after_colon = rest.split_once(':').map(|(_, v)| v).unwrap_or("");
            let first_word = after_colon.split_whitespace().next().unwrap_or("");
            match first_word.parse::<f64>() {
                Ok(v) => last_offset = Some(v),
                Err(_) => return Err(ParseError::InvalidOffset(first_word.to_string())),
            }
        } else if let Some(rest) = line.strip_prefix("Reference ID") {
            // "Reference ID    : A9FEA97B (169.254.169.123)"
            // Prefer the parenthesized identifier; fall back to the hex token.
            let after_colon = rest.split_once(':').map(|(_, v)| v).unwrap_or("").trim();
            if let (Some(lparen), Some(rparen)) = (after_colon.find('('), after_colon.rfind(')')) {
                if rparen > lparen + 1 {
                    reference = Some(after_colon[lparen + 1..rparen].to_string());
                }
            } else if let Some(first) = after_colon.split_whitespace().next() {
                if !first.is_empty() {
                    reference = Some(first.to_string());
                }
            }
        }
    }

    let last_offset_seconds = last_offset.ok_or(ParseError::NoLastOffsetLine)?;
    Ok(TrackingStatus {
        last_offset_seconds,
        reference,
    })
}

// --- helpers ---------------------------------------------------------------

fn fail(
    start: Instant,
    code: &'static str,
    summary: String,
    remediation: &'static str,
) -> CheckResult {
    CheckResult {
        name: "clock".to_string(),
        status: CheckStatus::Fail,
        duration_ms: start.elapsed().as_millis() as u64,
        summary,
        details: serde_json::Value::Null,
        check_code: Some(code.to_string()),
        remediation: Some(remediation.to_string()),
    }
}

// --- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical chronyc 4.x output from an Amazon Linux 2023 host using the
    /// Amazon Time Sync Service.
    const AL2023_TYPICAL: &str = "\
Reference ID    : A9FEA97B (169.254.169.123)
Stratum         : 4
Ref time (UTC)  : Wed Apr 23 15:30:12 2026
System time     : 0.000012345 seconds fast of NTP time
Last offset     : +0.000024000 seconds
RMS offset      : 0.000234567 seconds
Frequency       : 2.345 ppm slow
Residual freq   : +0.001 ppm
Skew            : 0.123 ppm
Root delay      : 0.002345 seconds
Root dispersion : 0.000456 seconds
Update interval : 1024.3 seconds
Leap status     : Normal
";

    const NEGATIVE_OFFSET: &str = "\
Reference ID    : A9FEA97B (169.254.169.123)
Last offset     : -0.000456 seconds
";

    const LARGE_OFFSET_ABOVE_THRESHOLD: &str = "\
Reference ID    : A9FEA97B (169.254.169.123)
Last offset     : +12.345678 seconds
";

    const REFERENCE_WITHOUT_PARENS: &str = "\
Reference ID    : some.ntp.pool.example.org
Last offset     : +0.001 seconds
";

    const MISSING_LAST_OFFSET: &str = "\
Reference ID    : A9FEA97B (169.254.169.123)
Stratum         : 4
System time     : 0.000012345 seconds fast of NTP time
";

    #[test]
    fn parses_al2023_typical_output() {
        let status = parse_tracking(AL2023_TYPICAL).unwrap();
        assert!((status.last_offset_seconds - 0.000024).abs() < 1e-9);
        assert_eq!(status.reference.as_deref(), Some("169.254.169.123"));
    }

    #[test]
    fn parses_negative_offset() {
        let status = parse_tracking(NEGATIVE_OFFSET).unwrap();
        assert!((status.last_offset_seconds - (-0.000456)).abs() < 1e-9);
    }

    #[test]
    fn parses_large_offset_above_threshold() {
        let status = parse_tracking(LARGE_OFFSET_ABOVE_THRESHOLD).unwrap();
        assert!(status.last_offset_seconds > MAX_OFFSET_SECONDS);
    }

    #[test]
    fn parses_reference_without_parens() {
        let status = parse_tracking(REFERENCE_WITHOUT_PARENS).unwrap();
        assert_eq!(
            status.reference.as_deref(),
            Some("some.ntp.pool.example.org")
        );
    }

    #[test]
    fn rejects_output_missing_last_offset() {
        assert_eq!(
            parse_tracking(MISSING_LAST_OFFSET),
            Err(ParseError::NoLastOffsetLine)
        );
    }

    #[test]
    fn rejects_empty_output() {
        assert_eq!(parse_tracking(""), Err(ParseError::NoLastOffsetLine));
    }

    #[test]
    fn rejects_malformed_offset_value() {
        let bad = "Last offset     : NOT_A_NUMBER seconds\n";
        match parse_tracking(bad) {
            Err(ParseError::InvalidOffset(v)) => assert_eq!(v, "NOT_A_NUMBER"),
            other => panic!("expected InvalidOffset, got {:?}", other),
        }
    }

    #[test]
    fn max_offset_matches_spec() {
        // Spec says offset must be `< 5 seconds`; this test pins the
        // production constant against the spec so future changes are
        // deliberate rather than silent.
        assert_eq!(MAX_OFFSET_SECONDS, 5.0);
    }

    #[tokio::test]
    async fn run_on_non_chrony_host_fails_cleanly() {
        // This sandbox may or may not have chronyc installed. Regardless,
        // running the check produces a specific, non-generic failure —
        // NOT `SKELETON_UNIMPLEMENTED` and NOT a panic. The outcome that
        // makes it through is one of:
        //   - CLOCK_CHRONYC_MISSING (no chronyc binary)
        //   - CLOCK_CHRONYD_NOT_RUNNING (chronyc present, chronyd down)
        //   - CLOCK_PROBE_FAILED (other subprocess error)
        //   - CLOCK_OFFSET_TOO_LARGE (unexpected on test hosts)
        //   - Ok (if the test host happens to have healthy chrony)
        let ctx = Context {
            doctor_version: "0.0.0-test",
            timestamp: chrono::Utc::now(),
            stack_name: "cyntrisec-pilot".into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let result = Clock.run(&ctx).await;
        match result.status {
            CheckStatus::Ok => {
                // Healthy chrony — details should carry offset_seconds.
                assert!(result.details.get("offset_seconds").is_some());
            }
            CheckStatus::Fail => {
                let code = result.check_code.as_deref().unwrap_or("");
                let allowed = [
                    "CLOCK_CHRONYC_MISSING",
                    "CLOCK_CHRONYD_NOT_RUNNING",
                    "CLOCK_PROBE_FAILED",
                    "CLOCK_OFFSET_TOO_LARGE",
                    "CLOCK_PARSE_FAILED",
                ];
                assert!(
                    allowed.contains(&code),
                    "unexpected clock check_code: {}",
                    code
                );
                // Remediation is always present on a fail.
                assert!(result.remediation.is_some());
            }
        }
    }
}
