//! Check 4 — Evidence bucket reachable with correct permissions.
//!
//! Spec: `byoc-phase-1-ephemeralml-doctor-spec-2026-04-23.md` § Check 4.
//!
//! Probes, in order:
//! 1. Discover bucket name from
//!    `/cyntrisec/pilot/config/{StackName}/bucket-name` via SSM.
//! 2. `s3:HeadBucket` succeeds.
//! 3. `s3:GetBucketEncryption` returns SSE-KMS (not AES256).
//! 4. `s3:GetPublicAccessBlock` returns all four flags true.
//! 5. `s3:ListObjectsV2` with `max-keys=1` succeeds (proves ListBucket).
//! 6. `s3:PutObject` writes a zero-byte `_doctor/ping-{ts}` object with the
//!    SSE-KMS header set — proves PutObject + KMS generate-data-key via S3.
//!
//! The ping object is deliberately NOT deleted. `DeleteObject` is not in the
//! Phase 1 role policy by design; the smoke-test handles prefix cleanup.
//! Cost: a few bytes per doctor run.

use super::{Check, CheckResult, CheckStatus};
use crate::context::Context;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::types::ServerSideEncryption;
use chrono::Utc;
use serde_json::json;
use std::time::Instant;

pub struct Bucket;

#[async_trait]
impl Check for Bucket {
    fn name(&self) -> &'static str {
        "bucket"
    }

    async fn run(&self, ctx: &Context) -> CheckResult {
        let start = Instant::now();

        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
        let ssm = aws_sdk_ssm::Client::new(&config);
        let s3 = aws_sdk_s3::Client::new(&config);

        // 1. Discover bucket name from SSM.
        let ssm_path = format!("/cyntrisec/pilot/config/{}/bucket-name", ctx.stack_name);
        let bucket_name = match ssm.get_parameter().name(&ssm_path).send().await {
            Ok(out) => match out
                .parameter
                .and_then(|p| p.value)
                .filter(|v| !v.trim().is_empty())
            {
                Some(v) => v,
                None => {
                    return fail(
                        start,
                        "BUCKET_SSM_PARAMETER_EMPTY",
                        format!("SSM parameter '{}' is empty", ssm_path),
                        "re-deploy the stack; the CloudFormation SSM::Parameter resource \
                         should have populated this path. Inspect via: \
                         aws ssm get-parameters-by-path --path /cyntrisec/pilot/config/",
                    );
                }
            },
            Err(e) => {
                return fail(
                    start,
                    "BUCKET_SSM_READ_FAILED",
                    format!("SSM GetParameter on '{}' failed: {}", ssm_path, e),
                    "verify the stack-name arg matches the deployed CloudFormation stack \
                     and that the instance role has ssm:GetParameter (covered by Check 3).",
                );
            }
        };

        // 2. HeadBucket.
        if let Err(e) = s3.head_bucket().bucket(&bucket_name).send().await {
            return fail(
                start,
                "BUCKET_NOT_REACHABLE",
                format!("HeadBucket on '{}' failed: {}", bucket_name, e),
                "check that CloudFormation stack reached CREATE_COMPLETE; \
                 run 'aws cloudformation describe-stacks --stack-name <stack>' \
                 to inspect stack events.",
            );
        }

        // 3. GetBucketEncryption.
        let sse_algorithm = match s3.get_bucket_encryption().bucket(&bucket_name).send().await {
            Ok(out) => {
                let rules = out
                    .server_side_encryption_configuration
                    .map(|c| c.rules)
                    .unwrap_or_default();
                match sse_algorithm_from_rules(&rules) {
                    Some(algo) => algo,
                    None => {
                        return fail(
                            start,
                            "BUCKET_ENCRYPTION_MISSING",
                            format!(
                                "Bucket '{}' returned encryption config without an SSE algorithm",
                                bucket_name
                            ),
                            "re-apply SSE-KMS via CloudFormation or \
                             'aws s3api put-bucket-encryption' with a KMS key reference.",
                        );
                    }
                }
            }
            Err(e) => {
                return fail(
                    start,
                    "BUCKET_ENCRYPTION_READ_FAILED",
                    format!("GetBucketEncryption on '{}' failed: {}", bucket_name, e),
                    "the instance role must have s3:GetEncryptionConfiguration on this bucket; \
                     this should be covered by the stack's PilotBucketAccess statement.",
                );
            }
        };

        if !sse_algorithm_is_kms(&sse_algorithm) {
            return fail(
                start,
                "BUCKET_ENCRYPTION_WRONG_ALGORITHM",
                format!(
                    "Bucket '{}' uses SSE algorithm '{}', not aws:kms",
                    bucket_name,
                    sse_algorithm.as_str()
                ),
                "CRITICAL: evidence bucket must use customer-managed KMS encryption. \
                 Re-deploy the stack or run 'aws s3api put-bucket-encryption' with \
                 ServerSideEncryptionByDefault.SSEAlgorithm=aws:kms.",
            );
        }

        // 4. GetPublicAccessBlock — all four flags must be true.
        let pab = match s3
            .get_public_access_block()
            .bucket(&bucket_name)
            .send()
            .await
        {
            Ok(out) => match out.public_access_block_configuration {
                Some(c) => c,
                None => {
                    return fail(
                        start,
                        "BUCKET_PAB_NOT_CONFIGURED",
                        format!(
                            "Bucket '{}' has no public-access-block configuration",
                            bucket_name
                        ),
                        "CRITICAL SECURITY ISSUE — stop using this bucket immediately. \
                         Re-deploy the stack or run 'aws s3api put-public-access-block' \
                         with all four blocks true.",
                    );
                }
            },
            Err(e) => {
                return fail(
                    start,
                    "BUCKET_PAB_READ_FAILED",
                    format!("GetPublicAccessBlock on '{}' failed: {}", bucket_name, e),
                    "the instance role must have s3:GetBucketPublicAccessBlock on this bucket.",
                );
            }
        };

        let pab_report = PabReport {
            block_public_acls: pab.block_public_acls.unwrap_or(false),
            ignore_public_acls: pab.ignore_public_acls.unwrap_or(false),
            block_public_policy: pab.block_public_policy.unwrap_or(false),
            restrict_public_buckets: pab.restrict_public_buckets.unwrap_or(false),
        };
        if !pab_report.all_true() {
            return fail(
                start,
                "BUCKET_PAB_INCOMPLETE",
                format!(
                    "Bucket '{}' PublicAccessBlock is incomplete: {:?}",
                    bucket_name, pab_report
                ),
                "CRITICAL SECURITY ISSUE — stop using this bucket immediately. \
                 Re-deploy the stack or run 'aws s3api put-public-access-block' \
                 with all four blocks true.",
            );
        }

        // 5. ListObjectsV2 with max-keys=1 — proves ListBucket permission.
        if let Err(e) = s3
            .list_objects_v2()
            .bucket(&bucket_name)
            .max_keys(1)
            .send()
            .await
        {
            return fail(
                start,
                "BUCKET_LIST_FAILED",
                format!("ListObjectsV2 on '{}' failed: {}", bucket_name, e),
                "the instance role must have s3:ListBucket on this bucket; \
                 this should be covered by the stack's PilotBucketAccess statement.",
            );
        }

        // 6. PutObject a zero-byte _doctor/ping-{ts} with SSE-KMS.
        let ping_key = format!("_doctor/ping-{}", Utc::now().format("%Y%m%dT%H%M%SZ"));
        if let Err(e) = s3
            .put_object()
            .bucket(&bucket_name)
            .key(&ping_key)
            .body(aws_sdk_s3::primitives::ByteStream::from(Vec::<u8>::new()))
            .server_side_encryption(ServerSideEncryption::AwsKms)
            .send()
            .await
        {
            return fail(
                start,
                "BUCKET_PUT_FAILED",
                format!(
                    "PutObject for ping marker '{}' on '{}' failed: {}",
                    ping_key, bucket_name, e
                ),
                "the instance role must have s3:PutObject on this bucket, AND the \
                 object must include the aws:kms SSE header (bucket policy \
                 DenyUnencryptedObjectUploads enforces this).",
            );
        }

        // All six probes passed.
        CheckResult {
            name: "bucket".to_string(),
            status: CheckStatus::Ok,
            duration_ms: start.elapsed().as_millis() as u64,
            summary: format!(
                "Evidence bucket {} reachable (SSE-KMS on, public access blocked, list+put verified)",
                bucket_name
            ),
            details: json!({
                "bucket_name": bucket_name,
                "sse_algorithm": sse_algorithm.as_str(),
                "public_access_block": {
                    "block_public_acls": pab_report.block_public_acls,
                    "ignore_public_acls": pab_report.ignore_public_acls,
                    "block_public_policy": pab_report.block_public_policy,
                    "restrict_public_buckets": pab_report.restrict_public_buckets,
                },
                "ping_marker_key": ping_key,
            }),
            check_code: None,
            remediation: None,
        }
    }
}

// --- parsers ---------------------------------------------------------------

#[derive(Debug, PartialEq)]
struct PabReport {
    block_public_acls: bool,
    ignore_public_acls: bool,
    block_public_policy: bool,
    restrict_public_buckets: bool,
}

impl PabReport {
    fn all_true(&self) -> bool {
        self.block_public_acls
            && self.ignore_public_acls
            && self.block_public_policy
            && self.restrict_public_buckets
    }
}

/// Extract the `SSEAlgorithm` from `GetBucketEncryption.Rules[0]`. S3 allows
/// multiple rules; in practice only one is configured per bucket and the
/// effective default comes from the first rule's
/// `ApplyServerSideEncryptionByDefault.SSEAlgorithm`.
fn sse_algorithm_from_rules(
    rules: &[aws_sdk_s3::types::ServerSideEncryptionRule],
) -> Option<ServerSideEncryption> {
    rules
        .iter()
        .filter_map(|r| r.apply_server_side_encryption_by_default.as_ref())
        .map(|d| d.sse_algorithm.clone())
        .next()
}

fn sse_algorithm_is_kms(algo: &ServerSideEncryption) -> bool {
    matches!(
        algo,
        ServerSideEncryption::AwsKms | ServerSideEncryption::AwsKmsDsse
    )
}

// --- helpers ---------------------------------------------------------------

fn fail(
    start: Instant,
    code: &'static str,
    summary: impl Into<String>,
    remediation: &'static str,
) -> CheckResult {
    CheckResult {
        name: "bucket".to_string(),
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
// Unit tests cover the PAB aggregator and the SSE-algorithm classifier. The
// AWS SDK probes are exercised by the Phase 1 real-AWS deploy (Day 3 onward).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pab_all_true_requires_all_four_flags() {
        let r = PabReport {
            block_public_acls: true,
            ignore_public_acls: true,
            block_public_policy: true,
            restrict_public_buckets: true,
        };
        assert!(r.all_true());
    }

    #[test]
    fn pab_fails_if_any_flag_false() {
        for mask in [0b0001u8, 0b0010, 0b0100, 0b1000] {
            let r = PabReport {
                block_public_acls: mask & 0b0001 == 0,
                ignore_public_acls: mask & 0b0010 == 0,
                block_public_policy: mask & 0b0100 == 0,
                restrict_public_buckets: mask & 0b1000 == 0,
            };
            assert!(
                !r.all_true(),
                "PabReport with mask {:#06b} should NOT be all-true, got {:?}",
                mask,
                r
            );
        }
    }

    #[test]
    fn sse_algorithm_is_kms_accepts_kms_and_dsse() {
        assert!(sse_algorithm_is_kms(&ServerSideEncryption::AwsKms));
        assert!(sse_algorithm_is_kms(&ServerSideEncryption::AwsKmsDsse));
    }

    #[test]
    fn sse_algorithm_is_kms_rejects_aes256() {
        assert!(!sse_algorithm_is_kms(&ServerSideEncryption::Aes256));
    }

    #[tokio::test]
    async fn run_without_aws_creds_fails_cleanly_not_panics() {
        // On a non-EC2 host with no AWS credentials the SSM call will fail
        // or produce an auth error. The check must produce a specific
        // BUCKET_* code, never SKELETON_UNIMPLEMENTED and never a panic.
        let ctx = Context {
            doctor_version: "0.0.0-test",
            timestamp: chrono::Utc::now(),
            stack_name: "cyntrisec-pilot".into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let result = Bucket.run(&ctx).await;
        if result.status == CheckStatus::Fail {
            let code = result.check_code.as_deref().unwrap_or("");
            assert_ne!(code, "SKELETON_UNIMPLEMENTED", "bucket is now a real probe");
            assert!(
                code.starts_with("BUCKET_"),
                "unexpected bucket check_code off-EC2: {}",
                code
            );
        }
    }
}
