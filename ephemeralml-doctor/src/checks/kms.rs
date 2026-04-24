//! Check 5 — Evidence KMS key available and usable via S3 only.
//!
//! Spec: `byoc-phase-1-ephemeralml-doctor-spec-2026-04-23.md` § Check 5.
//!
//! Probes, in order:
//! 1. Discover key alias from
//!    `/cyntrisec/pilot/config/{StackName}/kms-key-alias` via SSM.
//! 2. `kms:DescribeKey` returns `KeyState: Enabled` and `Origin: AWS_KMS`.
//! 3. `kms:GetKeyRotationStatus` returns `KeyRotationEnabled: true`.
//! 4. `kms:GenerateDataKey` called DIRECTLY (not via S3) MUST return
//!    `AccessDeniedException`. That denial is the PASS signal — it confirms
//!    the `kms:ViaService=s3.${Region}.amazonaws.com` condition on the
//!    instance role's inline policy is enforced.
//!
//! If the direct call unexpectedly succeeds, the key grant is too broad and
//! the check FAILS with `KMS_CONDITION_NOT_ENFORCED`. This is the most
//! counter-intuitive spec point in the doctor — AccessDenied is success
//! here — and the check_code / remediation text reflect that explicitly.

use super::{Check, CheckResult, CheckStatus};
use crate::context::Context;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_kms::types::{KeyState, OriginType};
use serde_json::json;
use std::time::Instant;

pub struct Kms;

#[async_trait]
impl Check for Kms {
    fn name(&self) -> &'static str {
        "kms"
    }

    async fn run(&self, ctx: &Context) -> CheckResult {
        let start = Instant::now();

        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
        let ssm = aws_sdk_ssm::Client::new(&config);
        let kms = aws_sdk_kms::Client::new(&config);

        // 1. Discover key alias from SSM.
        let ssm_path = format!("/cyntrisec/pilot/config/{}/kms-key-alias", ctx.stack_name);
        let alias = match ssm.get_parameter().name(&ssm_path).send().await {
            Ok(out) => match out
                .parameter
                .and_then(|p| p.value)
                .filter(|v| !v.trim().is_empty())
            {
                Some(v) => v,
                None => {
                    return fail(
                        start,
                        "KMS_SSM_PARAMETER_EMPTY",
                        format!("SSM parameter '{}' is empty", ssm_path),
                        "re-deploy the stack; CloudFormation should have populated this path.",
                    );
                }
            },
            Err(e) => {
                return fail(
                    start,
                    "KMS_SSM_READ_FAILED",
                    format!("SSM GetParameter on '{}' failed: {}", ssm_path, e),
                    "verify the stack-name arg matches the deployed CloudFormation stack.",
                );
            }
        };

        // 2. DescribeKey — KeyState=Enabled, Origin=AWS_KMS.
        let (key_state, key_origin, key_arn) = match kms.describe_key().key_id(&alias).send().await
        {
            Ok(out) => match out.key_metadata {
                Some(meta) => (
                    meta.key_state.clone(),
                    meta.origin.clone(),
                    meta.arn.clone(),
                ),
                None => {
                    return fail(
                        start,
                        "KMS_DESCRIBE_EMPTY",
                        format!("DescribeKey for '{}' returned no key metadata", alias),
                        "alias may be dangling; re-deploy the stack or re-point the alias.",
                    );
                }
            },
            Err(e) => {
                return fail(
                    start,
                    "KMS_DESCRIBE_FAILED",
                    format!("DescribeKey on '{}' failed: {}", alias, e),
                    "verify the key alias exists and the instance role has \
                     kms:DescribeKey on the key (covered by PilotKmsAccess policy statement).",
                );
            }
        };

        match key_state {
            Some(KeyState::Enabled) => {}
            Some(state) => {
                let state_str = state.as_str().to_string();
                let (code, remediation) = match state_str.as_str() {
                    "PendingDeletion" => (
                        "KMS_KEY_PENDING_DELETION",
                        "someone scheduled this key for deletion. Either cancel the deletion \
                         or re-deploy the stack with a fresh key.",
                    ),
                    "Disabled" => (
                        "KMS_KEY_DISABLED",
                        "re-enable the key: aws kms enable-key --key-id <alias>; \
                         if it was disabled intentionally, a stack re-deploy with a new key is safer.",
                    ),
                    _ => (
                        "KMS_KEY_NOT_ENABLED",
                        "inspect key state in the KMS console; re-enable or re-deploy.",
                    ),
                };
                return fail(
                    start,
                    code,
                    format!("KMS key '{}' is in state {}", alias, state_str),
                    remediation,
                );
            }
            None => {
                return fail(
                    start,
                    "KMS_KEY_STATE_MISSING",
                    format!("DescribeKey for '{}' returned no KeyState", alias),
                    "unexpected KMS response; share the doctor --verbose output with Cyntrisec support.",
                );
            }
        }

        if !matches!(key_origin, Some(OriginType::AwsKms)) {
            return fail(
                start,
                "KMS_WRONG_ORIGIN",
                format!(
                    "KMS key '{}' has non-AWS_KMS origin {:?}",
                    alias, key_origin
                ),
                "Phase 1 requires Origin=AWS_KMS (SYMMETRIC_DEFAULT, AES-256-GCM). \
                 External key stores (XKS) and imported keys are out of scope.",
            );
        }

        // 3. GetKeyRotationStatus. Unlike most KMS APIs, this one rejects
        //    aliases with InvalidArnException — we must use the key ARN
        //    resolved from the DescribeKey call above. Fall back to alias
        //    if (impossibly) DescribeKey returned no Arn, which would
        //    surface as the same InvalidArnException with a clearer
        //    remediation.
        let key_ref_for_rotation = key_arn.as_deref().unwrap_or(&alias);
        let rotation_enabled = match kms
            .get_key_rotation_status()
            .key_id(key_ref_for_rotation)
            .send()
            .await
        {
            Ok(out) => out.key_rotation_enabled,
            Err(e) => {
                return fail(
                    start,
                    "KMS_ROTATION_STATUS_FAILED",
                    format!(
                        "GetKeyRotationStatus on '{}' failed: {}",
                        key_ref_for_rotation, e
                    ),
                    "verify the instance role has kms:GetKeyRotationStatus on the key ARN \
                     (not the alias — this API rejects aliases with InvalidArnException).",
                );
            }
        };
        if !rotation_enabled {
            return fail(
                start,
                "KMS_ROTATION_DISABLED",
                format!("KMS key '{}' rotation is disabled", alias),
                "the customer-managed key must have rotation enabled. Run \
                 'aws kms enable-key-rotation --key-id <alias>' — if this was disabled \
                 manually post-deploy, that's a compliance regression.",
            );
        }

        // 4. Direct GenerateDataKey MUST return AccessDeniedException.
        //    Success here = the kms:ViaService=s3 condition is missing/too loose.
        let direct_probe = kms
            .generate_data_key()
            .key_id(&alias)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
            .encryption_context("Purpose", "doctor-probe")
            .send()
            .await;

        match classify_direct_probe(&direct_probe) {
            DirectProbeOutcome::AccessDeniedAsExpected => {}
            DirectProbeOutcome::UnexpectedSuccess => {
                return fail(
                    start,
                    "KMS_CONDITION_NOT_ENFORCED",
                    format!(
                        "Direct kms:GenerateDataKey on '{}' unexpectedly SUCCEEDED",
                        alias
                    ),
                    "CRITICAL: the instance role has broader KMS access than the spec allows. \
                     The kms:ViaService=s3.<region>.amazonaws.com condition must restrict KMS \
                     usage to S3 service principals only. Re-deploy the stack with the \
                     PilotKmsAccess policy statement intact.",
                );
            }
            DirectProbeOutcome::OtherError(msg) => {
                return fail(
                    start,
                    "KMS_DIRECT_PROBE_FAILED",
                    format!(
                        "Direct kms:GenerateDataKey on '{}' failed with a non-AccessDenied \
                         error (expected AccessDeniedException): {}",
                        alias, msg
                    ),
                    "probe returned an unexpected error class. Re-run with --verbose and \
                     share output with Cyntrisec support.",
                );
            }
        }

        // All four probes passed.
        CheckResult {
            name: "kms".to_string(),
            status: CheckStatus::Ok,
            duration_ms: start.elapsed().as_millis() as u64,
            summary: format!(
                "KMS key {} available (Enabled, rotation on, kms:ViaService=s3 condition enforced)",
                alias
            ),
            details: json!({
                "key_alias": alias,
                "key_arn": key_arn,
                "key_state": "Enabled",
                "rotation_enabled": true,
                "direct_generate_data_key": "AccessDenied (expected PASS signal)",
            }),
            check_code: None,
            remediation: None,
        }
    }
}

// --- parsers ---------------------------------------------------------------

/// Outcome classifier for the direct `GenerateDataKey` probe. Encapsulates
/// the "AccessDenied is the pass" inversion so the main run() body reads
/// naturally.
#[derive(Debug, PartialEq)]
enum DirectProbeOutcome {
    /// The probe returned AccessDeniedException — this is the PASS signal.
    AccessDeniedAsExpected,
    /// The probe succeeded — this FAILS the check because the kms:ViaService
    /// condition is not enforced.
    UnexpectedSuccess,
    /// Any other error — the probe is inconclusive.
    OtherError(String),
}

fn classify_direct_probe<T: std::fmt::Debug, E: std::fmt::Debug>(
    result: &Result<T, E>,
) -> DirectProbeOutcome {
    match result {
        Ok(_) => DirectProbeOutcome::UnexpectedSuccess,
        Err(e) => {
            let debug = format!("{:?}", e);
            if debug.contains("AccessDenied") || debug.contains("AccessDeniedException") {
                DirectProbeOutcome::AccessDeniedAsExpected
            } else {
                DirectProbeOutcome::OtherError(debug)
            }
        }
    }
}

// --- helpers ---------------------------------------------------------------

fn fail(
    start: Instant,
    code: &'static str,
    summary: impl Into<String>,
    remediation: &'static str,
) -> CheckResult {
    CheckResult {
        name: "kms".to_string(),
        status: CheckStatus::Fail,
        duration_ms: start.elapsed().as_millis() as u64,
        summary: summary.into(),
        details: serde_json::Value::Null,
        check_code: Some(code.to_string()),
        remediation: Some(remediation.to_string()),
    }
}

// --- tests -----------------------------------------------------------------
//
// Tests cover the outcome classifier (the most subtle piece — AccessDenied =
// pass, success = fail). The AWS SDK probes are exercised by the Phase 1
// real-AWS deploy run.

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct AccessDeniedException;

    #[derive(Debug)]
    struct SomeOtherError;

    #[test]
    fn classify_direct_probe_pass_signal_on_access_denied() {
        // Real SDK errors stringify to something like:
        // `ServiceError(ServiceError { source: AccessDeniedException(...), ... })`.
        // Our classifier matches on the substring.
        let result: Result<(), AccessDeniedException> = Err(AccessDeniedException);
        assert_eq!(
            classify_direct_probe(&result),
            DirectProbeOutcome::AccessDeniedAsExpected
        );
    }

    #[test]
    fn classify_direct_probe_fail_on_unexpected_success() {
        let result: Result<String, SomeOtherError> = Ok("leaked key".into());
        assert_eq!(
            classify_direct_probe(&result),
            DirectProbeOutcome::UnexpectedSuccess
        );
    }

    #[test]
    fn classify_direct_probe_other_error_carries_message() {
        let result: Result<(), SomeOtherError> = Err(SomeOtherError);
        match classify_direct_probe(&result) {
            DirectProbeOutcome::OtherError(msg) => {
                assert!(
                    msg.contains("SomeOtherError"),
                    "expected Debug output, got: {}",
                    msg
                );
            }
            other => panic!("expected OtherError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn run_without_aws_creds_fails_cleanly_not_panics() {
        // Off-EC2 / no-AWS-creds behavior: must produce a specific KMS_* code,
        // never SKELETON_UNIMPLEMENTED, never panic.
        let ctx = Context {
            doctor_version: "0.0.0-test",
            timestamp: chrono::Utc::now(),
            stack_name: "cyntrisec-pilot".into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let result = Kms.run(&ctx).await;
        if result.status == CheckStatus::Fail {
            let code = result.check_code.as_deref().unwrap_or("");
            assert_ne!(code, "SKELETON_UNIMPLEMENTED", "kms is now a real probe");
            assert!(
                code.starts_with("KMS_"),
                "unexpected kms check_code off-EC2: {}",
                code
            );
        }
    }
}
