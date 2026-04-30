//! Check 3 — Instance IAM role resolves to expected ARN.
//!
//! Spec: `byoc-phase-1-ephemeralml-doctor-spec-2026-04-23.md` § Check 3.
//!
//! Probes, in order:
//! 1. IMDSv2 token fetch (`PUT /latest/api/token`) — proves the metadata
//!    service is reachable and `HttpTokens=required` is honored.
//! 2. `GET /latest/meta-data/iam/info` with the token — returns JSON carrying
//!    `InstanceProfileArn`. We parse the instance-profile name out of the ARN
//!    and require it to equal `{StackName}-host-profile`.
//! 3. `ssm:GetParameter` on `/cyntrisec/pilot/config/{StackName}/bucket-name`
//!    — proves the `PilotConfigRead` inline-policy statement works end-to-end.
//!    This is the first cross-service call; a pass here implies the role-binding
//!    from (2) is real (not just IMDS advertising the expected name).
//!
//! On failure, reports a specific `ROLE_*` check_code plus the remediation
//! text from the spec.

use super::{Check, CheckResult, CheckStatus};
use crate::context::Context;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use serde::Deserialize;
use serde_json::json;
use std::time::Instant;

const IMDS_METADATA_PATH: &str = "/latest/meta-data/iam/info";

/// Minimal projection over the `iam/info` IMDS response. The real response
/// also carries `LastUpdated` and `Code` but we only need the ARN.
#[derive(Debug, Deserialize)]
struct IamInfo {
    #[serde(rename = "InstanceProfileArn")]
    instance_profile_arn: String,
}

pub struct Role;

#[async_trait]
impl Check for Role {
    fn name(&self) -> &'static str {
        "role"
    }

    async fn run(&self, ctx: &Context) -> CheckResult {
        let start = Instant::now();

        // 1 + 2. IMDSv2 token + iam/info — handled inside the SDK IMDS client,
        //        which performs the PUT/GET dance automatically.
        let imds_client = aws_config::imds::client::Client::builder().build();
        let iam_info_raw = match imds_client.get(IMDS_METADATA_PATH).await {
            Ok(body) => body.as_ref().to_string(),
            Err(e) => {
                return fail(
                    start,
                    "ROLE_IMDS_UNREACHABLE",
                    format!("IMDSv2 iam/info fetch failed: {}", e),
                    "instance metadata service may be disabled or misconfigured. \
                     Verify EC2 instance metadata options: HttpTokens=required, \
                     HttpEndpoint=enabled. If running this doctor off-EC2 by mistake, \
                     the check can only pass on the Nitro host itself.",
                );
            }
        };

        let info: IamInfo = match serde_json::from_str(&iam_info_raw) {
            Ok(p) => p,
            Err(e) => {
                return fail(
                    start,
                    "ROLE_IMDS_PARSE_FAILED",
                    format!("IMDSv2 iam/info body was not valid JSON: {}", e),
                    "IMDS appears reachable but returned unexpected content. \
                     Check instance-profile attach status in the console.",
                );
            }
        };

        let profile_name = match parse_instance_profile_name(&info.instance_profile_arn) {
            Ok(name) => name.to_string(),
            Err(e) => {
                return fail(
                    start,
                    "ROLE_ARN_MALFORMED",
                    format!(
                        "IMDS returned InstanceProfileArn that the doctor could not parse: \
                         '{}' ({})",
                        info.instance_profile_arn, e
                    ),
                    "unexpected IMDS response; share the doctor --verbose output with \
                     Cyntrisec support.",
                );
            }
        };

        let expected_profile = std::env::var("CYNTRISEC_EXPECTED_HOST_PROFILE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("{}-host-profile", ctx.stack_name));
        if profile_name != expected_profile {
            return fail(
                start,
                "ROLE_NAME_MISMATCH",
                format!(
                    "Instance profile name '{}' does not match expected pattern '{}'",
                    profile_name, expected_profile
                ),
                "either the instance was re-created outside CloudFormation, or the \
                 stack-name auto-detection is wrong. Pass --stack-name explicitly.",
            );
        }

        // 3. Prove PilotConfigRead works by reading one parameter from the
        //    stack's config namespace. We use bucket-name (required by Check 4
        //    anyway), so a failure here is a real policy miss — not a spurious
        //    SSM read of an unrelated path.
        let ssm_path = format!("/cyntrisec/pilot/config/{}/bucket-name", ctx.stack_name);
        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
        let ssm = aws_sdk_ssm::Client::new(&config);

        let ssm_result = ssm
            .get_parameter()
            .name(&ssm_path)
            .send()
            .await
            .map_err(|e| e.into_service_error());

        match ssm_result {
            Ok(_) => {}
            Err(ref e) if is_access_denied_ssm(e) => {
                return fail(
                    start,
                    "ROLE_CONFIG_READ_DENIED",
                    format!(
                        "Instance role cannot read SSM parameter '{}' (AccessDenied)",
                        ssm_path
                    ),
                    "the PilotConfigRead inline-policy statement is missing or too narrow. \
                     Re-deploy the stack so the host role is granted ssm:GetParameter on \
                     arn:aws:ssm:<region>:<account>:parameter/cyntrisec/pilot/config/<stack>/*.",
                );
            }
            Err(e) => {
                return fail(
                    start,
                    "ROLE_CONFIG_READ_FAILED",
                    format!(
                        "SSM GetParameter on '{}' failed unexpectedly: {}",
                        ssm_path, e
                    ),
                    "verify SSM endpoint reachability (VPC endpoint or public route) \
                     and the stack-name arg matches the deployed CloudFormation stack.",
                );
            }
        };

        // All three checks pass.
        CheckResult {
            name: "role".to_string(),
            status: CheckStatus::Ok,
            duration_ms: start.elapsed().as_millis() as u64,
            summary: format!(
                "Instance role: {} (ARN verified via IMDSv2)",
                // Drop the trailing "-profile" for a friendlier display — the
                // ROLE Arn is what operators reason about, the profile Arn is
                // plumbing.
                profile_name.trim_end_matches("-profile")
            ),
            details: json!({
                "instance_profile_arn": redact_arn_middle(&info.instance_profile_arn),
                "instance_profile_name": profile_name,
                "expected_profile_name": expected_profile,
                "ssm_config_path": ssm_path,
                "ssm_config_read_ok": true,
            }),
            check_code: None,
            remediation: None,
        }
    }
}

// --- parsers ---------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum ArnParseError {
    NotAnArn,
    NotInstanceProfile,
    EmptyName,
}

impl std::fmt::Display for ArnParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnArn => f.write_str("not an AWS ARN"),
            Self::NotInstanceProfile => f.write_str("ARN resource is not 'instance-profile'"),
            Self::EmptyName => f.write_str("instance-profile name segment was empty"),
        }
    }
}

/// Extract the instance-profile name from an ARN like
/// `arn:aws:iam::272493677165:instance-profile/cyntrisec-pilot-test-1-host-profile`.
fn parse_instance_profile_name(arn: &str) -> Result<&str, ArnParseError> {
    let rest = arn
        .strip_prefix("arn:aws:iam::")
        .ok_or(ArnParseError::NotAnArn)?;
    // Expect "{account}:instance-profile/{name}"
    let (_account, resource) = rest.split_once(':').ok_or(ArnParseError::NotAnArn)?;
    let name = resource
        .strip_prefix("instance-profile/")
        .ok_or(ArnParseError::NotInstanceProfile)?;
    if name.is_empty() {
        return Err(ArnParseError::EmptyName);
    }
    Ok(name)
}

/// Mask the 12-digit account portion of an ARN for `--verbose` output. We
/// want to give the operator enough information to debug ("yes, that's my
/// stack"), but not log the full account identifier to stdout where it may
/// end up in support tickets / shared terminals.
fn redact_arn_middle(arn: &str) -> String {
    // Find the "::<12 digits>:" window.
    let Some(prefix_end) = arn.find("::") else {
        return arn.to_string();
    };
    let after_colons = &arn[prefix_end + 2..];
    let Some(colon_after_account) = after_colons.find(':') else {
        return arn.to_string();
    };
    let account = &after_colons[..colon_after_account];
    if account.len() < 8 {
        return arn.to_string();
    }
    let masked = format!("{}****{}", &account[..2], &account[account.len() - 2..]);
    format!(
        "{}::{}:{}",
        &arn[..prefix_end],
        masked,
        &after_colons[colon_after_account + 1..]
    )
}

/// SSM `GetParameter` does not surface a typed `AccessDeniedException` variant
/// — the service returns it as an unhandled error. We match on the error code
/// string via the Debug representation because the smithy `meta()` API on the
/// error isn't exposed uniformly across SDK minor versions.
fn is_access_denied_ssm(e: &aws_sdk_ssm::operation::get_parameter::GetParameterError) -> bool {
    let debug = format!("{:?}", e);
    debug.contains("AccessDenied") || debug.contains("AccessDeniedException")
}

// --- helpers ---------------------------------------------------------------

fn fail(
    start: Instant,
    code: &'static str,
    summary: impl Into<String>,
    remediation: &'static str,
) -> CheckResult {
    CheckResult {
        name: "role".to_string(),
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
// Tests cover pure parsers (ARN parse, redaction). The IMDS + SSM probes are
// exercised only by the real Phase 1 deploy run; mocking them cleanly would
// require wrapping behind a trait, which is scope creep for the
// skeleton→real conversion.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_expected_instance_profile_arn() {
        let arn = "arn:aws:iam::272493677165:instance-profile/cyntrisec-pilot-test-1-host-profile";
        assert_eq!(
            parse_instance_profile_name(arn).unwrap(),
            "cyntrisec-pilot-test-1-host-profile"
        );
    }

    #[test]
    fn parses_short_stack_name() {
        let arn = "arn:aws:iam::000000000000:instance-profile/cyntrisec-pilot-host-profile";
        assert_eq!(
            parse_instance_profile_name(arn).unwrap(),
            "cyntrisec-pilot-host-profile"
        );
    }

    #[test]
    fn rejects_non_arn_string() {
        assert_eq!(
            parse_instance_profile_name("not-an-arn"),
            Err(ArnParseError::NotAnArn)
        );
    }

    #[test]
    fn rejects_role_arn_instead_of_profile_arn() {
        let arn = "arn:aws:iam::272493677165:role/cyntrisec-pilot-host-role";
        assert_eq!(
            parse_instance_profile_name(arn),
            Err(ArnParseError::NotInstanceProfile)
        );
    }

    #[test]
    fn rejects_empty_instance_profile_name() {
        let arn = "arn:aws:iam::272493677165:instance-profile/";
        assert_eq!(
            parse_instance_profile_name(arn),
            Err(ArnParseError::EmptyName)
        );
    }

    #[test]
    fn redact_masks_12_digit_account() {
        let arn = "arn:aws:iam::272493677165:instance-profile/cyntrisec-pilot-test-1-host-profile";
        let out = redact_arn_middle(arn);
        assert!(
            out.contains("27****65"),
            "expected masked account, got {}",
            out
        );
        assert!(
            !out.contains("272493677165"),
            "full account still present: {}",
            out
        );
    }

    #[test]
    fn redact_leaves_non_arn_untouched() {
        assert_eq!(redact_arn_middle("plain-string"), "plain-string");
    }

    #[tokio::test]
    async fn run_off_ec2_fails_cleanly_not_panics() {
        // On a non-EC2 host the IMDS call at 169.254.169.254 will fail. The
        // check must produce a specific ROLE_IMDS_UNREACHABLE code, not a
        // panic and not SKELETON_UNIMPLEMENTED. This is the regression test
        // for the skeleton→real transition.
        let ctx = Context {
            doctor_version: "0.0.0-test",
            timestamp: chrono::Utc::now(),
            stack_name: "cyntrisec-pilot".into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let result = Role.run(&ctx).await;
        // On a dev laptop or CI runner we expect either IMDS unreachable or
        // (rarely) a name mismatch if IMDS happens to respond. Anything
        // outside this set means the skeleton→real wiring is broken.
        let code = result.check_code.as_deref().unwrap_or("");
        let allowed = [
            "ROLE_IMDS_UNREACHABLE",
            "ROLE_IMDS_PARSE_FAILED",
            "ROLE_ARN_MALFORMED",
            "ROLE_NAME_MISMATCH",
            "ROLE_CONFIG_READ_DENIED",
            "ROLE_CONFIG_READ_FAILED",
        ];
        if result.status == CheckStatus::Fail {
            assert!(
                allowed.contains(&code),
                "unexpected role check_code off-EC2: {}",
                code
            );
            assert_ne!(code, "SKELETON_UNIMPLEMENTED", "role is now a real probe");
        }
    }
}
