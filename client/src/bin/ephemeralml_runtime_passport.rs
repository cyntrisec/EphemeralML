//! Offline Runtime Passport generator.
//!
//! A Runtime Passport is deployment-level evidence. It summarizes the runtime
//! that produced receipts: doctor checks, smoke-test stages, native platform
//! measurements, evidence bundle hashes, and provider-specific evidence
//! references. It is intentionally offline and customer-owned first.

use anyhow::{bail, Context, Result};
use clap::Parser;
use ephemeral_ml_common::{
    default_verification_limitations, AwsNitroEvidence, AzureSnpEvidence, ComponentResult,
    DeploymentSummary, EvidenceBundleSummary, FileDigest, GcpTdxEvidence, Limitation,
    MeasurementSummary, NvidiaGpuCcEvidence, PlatformEvidenceSummary, ReleaseSummary, ReportCheck,
    ReportCheckStatus, ReportStatus, RuntimePassportV1, RuntimeSummary, VerifierSummary,
    RUNTIME_PASSPORT_V1,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};

const SMOKE_BUNDLE_TYPE: &str = "cyntrisec-phase-1-smoke-test";
const SMOKE_BUNDLE_REQUIRED_FILES: &[&str] = &[
    "doctor.json",
    "receipt.cbor",
    "receipt.txt",
    "verification.json",
    "enclave-measurements.json",
    "inference-metadata.json",
    "model-info.json",
    "kms-release.json",
    "negative-tests.json",
    "benchmark.json",
    "approval-report.md",
];
const SMOKE_BUNDLE_REQUIRED_FILES_V3: &[&str] = &[
    "doctor.json",
    "receipt.cbor",
    "attestation.cbor",
    "receipt.txt",
    "verification.json",
    "enclave-measurements.json",
    "inference-metadata.json",
    "model-info.json",
    "kms-release.json",
    "negative-tests.json",
    "benchmark.json",
    "approval-report.md",
];

#[derive(Parser, Debug)]
#[command(
    name = "ephemeralml-runtime-passport",
    about = "Generate a Cyntrisec Runtime Passport from doctor/smoke/evidence outputs"
)]
struct Args {
    /// Output directory for runtime-passport.{json,md,html} and SHA256SUMS.
    #[arg(long)]
    output_dir: PathBuf,

    /// Cloud provider label: aws, gcp, azure, or nvidia.
    #[arg(long, default_value = "aws")]
    cloud_provider: String,

    /// Runtime type: aws-nitro, gcp-tdx, azure-sev-snp, or nvidia-h100-cc.
    #[arg(long, default_value = "aws-nitro")]
    runtime_type: String,

    /// JSON output from `ephemeralml-doctor --json`.
    #[arg(long)]
    doctor_json: Option<PathBuf>,

    /// JSON output from `ephemeralml-smoke-test --json`.
    #[arg(long)]
    smoke_json: Option<PathBuf>,

    /// Optional smoke-test evidence bundle directory.
    #[arg(long)]
    bundle_dir: Option<PathBuf>,

    /// Optional platform metadata JSON, for example evidence/mvp-*/metadata.json.
    #[arg(long)]
    metadata_json: Option<PathBuf>,

    /// Optional verifier/compliance report JSON.
    #[arg(long)]
    compliance_report: Option<PathBuf>,

    /// Optional receipt JSON used to extract runtime measurements.
    #[arg(long)]
    receipt_json: Option<PathBuf>,

    /// Optional customer-owned evidence URI, for example s3://bucket/prefix/.
    #[arg(long)]
    evidence_uri: Option<String>,

    /// Optional cloud account/project/subscription ID. Redact before sharing if needed.
    #[arg(long)]
    account_id: Option<String>,

    /// Optional region.
    #[arg(long)]
    region: Option<String>,

    /// Optional stack/deployment name.
    #[arg(long)]
    stack_name: Option<String>,

    /// Optional instance/VM type.
    #[arg(long)]
    instance_type: Option<String>,

    /// Optional enclave CID.
    #[arg(long)]
    enclave_cid: Option<u32>,

    /// Optional enclave memory in MiB.
    #[arg(long)]
    enclave_memory_mib: Option<u32>,

    /// Optional enclave CPU count.
    #[arg(long)]
    enclave_cpu_count: Option<u32>,

    /// Optional release git commit.
    #[arg(long)]
    git_commit: Option<String>,

    /// Optional release bundle SHA-256.
    #[arg(long)]
    release_bundle_sha256: Option<String>,

    /// Optional EIF SHA-384 / platform image measurement.
    #[arg(long)]
    eif_sha384: Option<String>,

    /// Optional KMS/Key Vault key reference. Stored as SHA-256, not raw value.
    #[arg(long)]
    key_ref: Option<String>,

    /// Optional IAM/service-account/managed-identity reference. Stored as SHA-256.
    #[arg(long)]
    identity_ref: Option<String>,

    /// Number of days before the passport should be considered stale.
    #[arg(long, default_value = "90")]
    ttl_days: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.output_dir).with_context(|| {
        format!(
            "failed to create output directory {}",
            args.output_dir.display()
        )
    })?;

    let doctor = read_json_opt(args.doctor_json.as_deref())?;
    let smoke = read_json_opt(args.smoke_json.as_deref())?;
    let metadata = read_json_opt(args.metadata_json.as_deref())?;
    let compliance_report = read_json_opt(args.compliance_report.as_deref())?;
    let receipt = read_json_opt(args.receipt_json.as_deref())?;
    let benchmark = read_bundle_json(&args, "benchmark.json")
        .or_else(|| read_bundle_json(&args, "benchmark.redacted.json"));
    let measurement_doc = read_bundle_json(&args, "enclave-measurements.json");
    let manifest = read_bundle_json(&args, "manifest.json");

    let mut passport = build_passport(
        &args,
        doctor.as_ref(),
        smoke.as_ref(),
        benchmark.as_ref(),
        measurement_doc.as_ref(),
        manifest.as_ref(),
        metadata.as_ref(),
        compliance_report.as_ref(),
        receipt.as_ref(),
    )?;
    passport.finalize_passport_sha256()?;

    let json_path = args.output_dir.join("runtime-passport.json");
    let md_path = args.output_dir.join("runtime-passport.md");
    let html_path = args.output_dir.join("runtime-passport.html");

    fs::write(&json_path, serde_json::to_vec_pretty(&passport)?)
        .with_context(|| format!("failed to write {}", json_path.display()))?;
    fs::write(&md_path, render_markdown(&passport))
        .with_context(|| format!("failed to write {}", md_path.display()))?;
    fs::write(&html_path, render_html(&passport))
        .with_context(|| format!("failed to write {}", html_path.display()))?;
    write_sha256sums(
        &args.output_dir,
        &[
            "runtime-passport.json",
            "runtime-passport.md",
            "runtime-passport.html",
        ],
    )?;

    println!("Runtime Passport generated: {}", json_path.display());
    if let Some(hash) = &passport.passport_sha256 {
        println!("passport_sha256: {}", hash);
    }
    Ok(())
}

fn build_passport(
    args: &Args,
    doctor: Option<&Value>,
    smoke: Option<&Value>,
    benchmark: Option<&Value>,
    measurement_doc: Option<&Value>,
    manifest: Option<&Value>,
    metadata: Option<&Value>,
    compliance_report: Option<&Value>,
    receipt: Option<&Value>,
) -> Result<RuntimePassportV1> {
    let now = ephemeral_ml_common::current_timestamp().unwrap_or(0);
    let doctor_result = component_from_doctor(doctor, benchmark);
    let smoke_result = component_from_smoke(smoke, benchmark, manifest, args.bundle_dir.as_deref());
    let compliance_result = component_from_compliance(compliance_report);
    let overall_status = overall_status(
        &doctor_result.status,
        &smoke_result.status,
        compliance_result.as_ref(),
    );
    let measurements = measurements(measurement_doc, benchmark, receipt);
    let platform_evidence = platform_evidence(args, &measurements, benchmark, smoke, metadata);
    let account_id = args
        .account_id
        .clone()
        .or_else(|| str_field(doctor, "account_id"))
        .or_else(|| str_field(smoke, "account_id"))
        .or_else(|| str_field(manifest, "account_id"))
        .or_else(|| str_field(metadata, "project"));
    warn_if_inherited_unredacted_account_id(args.account_id.as_deref(), account_id.as_deref());
    let stack_name = args
        .stack_name
        .clone()
        .or_else(|| str_field(doctor, "stack_name"))
        .or_else(|| str_field(smoke, "stack_name"))
        .or_else(|| str_field(manifest, "stack_name"));
    let limitations = passport_limitations(
        doctor,
        smoke,
        compliance_result.as_ref(),
        &args.runtime_type,
    );
    let mut checks = Vec::new();
    let emit_missing_runtime_checks = compliance_result.is_none();
    checks.extend(doctor_checks(doctor, emit_missing_runtime_checks));
    checks.extend(smoke_checks(
        smoke,
        emit_missing_runtime_checks,
        manifest,
        args.bundle_dir.as_deref(),
    ));
    checks.extend(compliance_checks(compliance_report));
    checks.extend(platform_checks(&platform_evidence));

    Ok(RuntimePassportV1 {
        schema_version: RUNTIME_PASSPORT_V1.to_string(),
        passport_id: format!("rpass_{}", ephemeral_ml_common::generate_id()),
        created_at: now,
        expires_at: Some(now.saturating_add(args.ttl_days.saturating_mul(24 * 60 * 60))),
        overall_status,
        deployment: DeploymentSummary {
            cloud_provider: args.cloud_provider.clone(),
            account_id,
            region: args
                .region
                .clone()
                .or_else(|| str_field(doctor, "region"))
                .or_else(|| str_field(smoke, "region"))
                .or_else(|| str_field(manifest, "region"))
                .or_else(|| nested_str(benchmark, &["environment", "region"]))
                .or_else(|| metadata_region(metadata)),
            stack_name,
        },
        runtime: RuntimeSummary {
            runtime_type: args.runtime_type.clone(),
            instance_type: args
                .instance_type
                .clone()
                .or_else(|| nested_str(benchmark, &["environment", "instance_type"]))
                .or_else(|| str_field(metadata, "machine_type")),
            enclave_cid: args.enclave_cid.or_else(|| {
                nested_u64(benchmark, &["environment", "enclave_cid"]).map(|v| v as u32)
            }),
            enclave_memory_mib: args.enclave_memory_mib.or_else(|| {
                nested_u64(benchmark, &["environment", "enclave_memory_mib"]).map(|v| v as u32)
            }),
            enclave_cpu_count: args.enclave_cpu_count.or_else(|| {
                nested_u64(benchmark, &["environment", "enclave_cpu_count"]).map(|v| v as u32)
            }),
        },
        platform_evidence: Some(platform_evidence),
        doctor: doctor_result,
        smoke_test: smoke_result,
        compliance: compliance_result,
        release: ReleaseSummary {
            git_commit: args
                .git_commit
                .clone()
                .or_else(|| str_field(benchmark, "git_commit")),
            release_bundle_sha256: args
                .release_bundle_sha256
                .clone()
                .or_else(|| str_field(benchmark, "release_bundle_sha256")),
            eif_sha384: args
                .eif_sha384
                .clone()
                .or_else(|| str_field(benchmark, "eif_sha384"))
                .or_else(|| measurement_value(&measurements, "pcr0")),
        },
        measurements,
        evidence_bundle: evidence_bundle_summary(
            args.bundle_dir.as_deref(),
            args.evidence_uri.as_deref(),
        )?,
        checks,
        verifier: VerifierSummary {
            name: "ephemeralml-runtime-passport".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_commit: option_env!("GIT_COMMIT").map(ToString::to_string),
        },
        limitations,
        passport_sha256: None,
    })
}

fn overall_status(
    doctor: &ReportStatus,
    smoke: &ReportStatus,
    compliance: Option<&ComponentResult>,
) -> ReportStatus {
    if matches!(doctor, ReportStatus::Fail)
        || matches!(smoke, ReportStatus::Fail)
        || compliance
            .map(|component| matches!(component.status, ReportStatus::Fail))
            .unwrap_or(false)
    {
        ReportStatus::Fail
    } else if matches!(doctor, ReportStatus::Pass) && matches!(smoke, ReportStatus::Pass) {
        ReportStatus::Pass
    } else {
        ReportStatus::Partial
    }
}

fn passport_limitations(
    doctor: Option<&Value>,
    smoke: Option<&Value>,
    compliance: Option<&ComponentResult>,
    runtime_type: &str,
) -> Vec<Limitation> {
    let mut limitations = default_verification_limitations();
    if compliance.is_some() && (doctor.is_none() || smoke.is_none()) {
        limitations.push(Limitation {
            code: "runtime_probe_json_not_supplied".to_string(),
            message: format!(
                "This {runtime_type} passport was generated from verifier/compliance evidence, not from BYOC doctor/smoke-test runtime probe JSON. Do not use it as evidence that those BYOC probes passed."
            ),
        });
    }
    if doctor_uses_unsigned_internal_poc(doctor) {
        limitations.push(Limitation {
            code: "unsigned_eif_internal_poc".to_string(),
            message: "Doctor EIF verification passed under CYNTRISEC_DOCTOR_ALLOW_UNSIGNED_EIF_FOR_POC because the host lacks an adjacent cosign bundle. This is acceptable only for internal PoC evidence and must be closed before production buyer evidence.".to_string(),
        });
    }
    limitations
}

fn component_from_doctor(doctor: Option<&Value>, benchmark: Option<&Value>) -> ComponentResult {
    let Some(doctor) = doctor else {
        return ComponentResult {
            status: ReportStatus::Unknown,
            duration_ms: nested_u64(benchmark, &["timings_ms", "doctor_total_ms"]),
            summary: Some("doctor JSON not supplied".to_string()),
        };
    };
    let status = match doctor.get("overall_status").and_then(Value::as_str) {
        Some("pass") => ReportStatus::Pass,
        Some("fail") => ReportStatus::Fail,
        _ => ReportStatus::Unknown,
    };
    let (passed, total) = count_status(doctor.get("checks"), "ok");
    ComponentResult {
        status,
        duration_ms: sum_duration(doctor.get("checks"))
            .or_else(|| nested_u64(benchmark, &["timings_ms", "doctor_total_ms"])),
        summary: Some(format!("{passed}/{total} doctor checks passed")),
    }
}

fn component_from_smoke(
    smoke: Option<&Value>,
    benchmark: Option<&Value>,
    manifest: Option<&Value>,
    bundle_dir: Option<&Path>,
) -> ComponentResult {
    let Some(smoke) = smoke else {
        if let Some(result) = component_from_smoke_bundle(benchmark, manifest, bundle_dir) {
            return result;
        }
        return ComponentResult {
            status: ReportStatus::Unknown,
            duration_ms: nested_u64(benchmark, &["timings_ms", "total_smoke_test_ms"]),
            summary: Some("smoke-test JSON not supplied".to_string()),
        };
    };
    let status = match smoke.get("overall_status").and_then(Value::as_str) {
        Some("pass") => ReportStatus::Pass,
        Some("fail") => ReportStatus::Fail,
        _ => ReportStatus::Unknown,
    };
    let (passed, total) = count_status(smoke.get("stages"), "pass");
    ComponentResult {
        status,
        duration_ms: smoke
            .get("total_duration_ms")
            .and_then(Value::as_u64)
            .or_else(|| nested_u64(benchmark, &["timings_ms", "total_smoke_test_ms"])),
        summary: Some(format!("{passed}/{total} smoke-test stages passed")),
    }
}

fn component_from_smoke_bundle(
    benchmark: Option<&Value>,
    manifest: Option<&Value>,
    bundle_dir: Option<&Path>,
) -> Option<ComponentResult> {
    let manifest = manifest?;
    let bundle_dir = bundle_dir?;
    let manifest_status = manifest.get("overall_status").and_then(Value::as_str);
    let bundle_type_ok =
        manifest.get("bundle_type").and_then(Value::as_str) == Some(SMOKE_BUNDLE_TYPE);
    let required_files = required_bundle_files_for_manifest(manifest);
    let missing = missing_required_bundle_files(bundle_dir, required_files);
    let (negative_passed, negative_total) = negative_test_counts(bundle_dir);
    let status = if manifest_status == Some("pass")
        && bundle_type_ok
        && missing.is_empty()
        && negative_total > 0
        && negative_passed == negative_total
    {
        ReportStatus::Pass
    } else if manifest_status == Some("fail") || !missing.is_empty() {
        ReportStatus::Fail
    } else {
        ReportStatus::Unknown
    };
    Some(ComponentResult {
        status,
        duration_ms: nested_u64(benchmark, &["timings_ms", "total_smoke_test_ms"]),
        summary: Some(format!(
            "bundle-derived smoke result: manifest_status={}, required_files={}/{}, negative_tests={}/{}",
            manifest_status.unwrap_or("unknown"),
            required_files.len().saturating_sub(missing.len()),
            required_files.len(),
            negative_passed,
            negative_total
        )),
    })
}

fn component_from_compliance(report: Option<&Value>) -> Option<ComponentResult> {
    let policy_result = report?.get("policy_result")?;
    let compliant = policy_result.get("compliant").and_then(Value::as_bool)?;
    let rules = policy_result.get("rules").and_then(Value::as_array);
    let total = rules.map(Vec::len).unwrap_or(0);
    let passed = rules
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| rule.get("passed").and_then(Value::as_bool) == Some(true))
                .count()
        })
        .unwrap_or(0);
    Some(ComponentResult {
        status: if compliant {
            ReportStatus::Pass
        } else {
            ReportStatus::Fail
        },
        duration_ms: None,
        summary: policy_result
            .get("summary")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .or_else(|| Some(format!("{passed}/{total} compliance rules passed"))),
    })
}

fn count_status(items: Option<&Value>, pass_value: &str) -> (usize, usize) {
    let Some(Value::Array(items)) = items else {
        return (0, 0);
    };
    let passed = items
        .iter()
        .filter(|item| item.get("status").and_then(Value::as_str) == Some(pass_value))
        .count();
    (passed, items.len())
}

fn sum_duration(items: Option<&Value>) -> Option<u64> {
    let Value::Array(items) = items? else {
        return None;
    };
    Some(
        items
            .iter()
            .filter_map(|item| item.get("duration_ms").and_then(Value::as_u64))
            .sum(),
    )
}

fn doctor_checks(doctor: Option<&Value>, emit_missing: bool) -> Vec<ReportCheck> {
    let Some(Value::Array(items)) = doctor.and_then(|v| v.get("checks")) else {
        if !emit_missing {
            return vec![];
        }
        return vec![unknown_check(
            "doctor",
            "Doctor preflight",
            "doctor JSON not supplied",
            "doctor.json",
        )];
    };
    items
        .iter()
        .filter_map(|item| {
            let id = item.get("check")?.as_str()?;
            let uses_unsigned_poc = id == "eif" && check_uses_unsigned_internal_poc(item);
            let mut status = match item.get("status").and_then(Value::as_str) {
                Some("ok") => ReportCheckStatus::Pass,
                Some("fail") => ReportCheckStatus::Fail,
                _ => ReportCheckStatus::Unknown,
            };
            let detail = if uses_unsigned_poc {
                status = ReportCheckStatus::Skip;
                Some("unsigned_internal_poc=true; cosign_verified=false".to_string())
            } else {
                item.get("check_code")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("remediation").and_then(Value::as_str))
                    .map(ToString::to_string)
            };
            Some(ReportCheck {
                id: format!("doctor_{id}"),
                label: format!("Doctor: {id}"),
                layer: "runtime".to_string(),
                status,
                detail,
                evidence_ref: Some("doctor.json".to_string()),
            })
        })
        .collect()
}

fn doctor_uses_unsigned_internal_poc(doctor: Option<&Value>) -> bool {
    let Some(Value::Array(items)) = doctor.and_then(|v| v.get("checks")) else {
        return false;
    };
    items.iter().any(check_uses_unsigned_internal_poc)
}

fn check_uses_unsigned_internal_poc(item: &Value) -> bool {
    item.get("check").and_then(Value::as_str) == Some("eif")
        && item
            .get("details")
            .and_then(|v| v.get("unsigned_internal_poc"))
            .and_then(Value::as_bool)
            == Some(true)
}

fn smoke_checks(
    smoke: Option<&Value>,
    emit_missing: bool,
    manifest: Option<&Value>,
    bundle_dir: Option<&Path>,
) -> Vec<ReportCheck> {
    let Some(Value::Array(items)) = smoke.and_then(|v| v.get("stages")) else {
        if let Some(check) = smoke_bundle_check(manifest, bundle_dir) {
            return vec![check];
        }
        if !emit_missing {
            return vec![];
        }
        return vec![unknown_check(
            "smoke_test",
            "Smoke test",
            "smoke-test JSON not supplied",
            "smoke-test.json",
        )];
    };
    items
        .iter()
        .filter_map(|item| {
            let id = item.get("stage")?.as_str()?;
            let status = match item.get("status").and_then(Value::as_str) {
                Some("pass") => ReportCheckStatus::Pass,
                Some("fail") => ReportCheckStatus::Fail,
                Some("skipped") => ReportCheckStatus::Skip,
                _ => ReportCheckStatus::Unknown,
            };
            Some(ReportCheck {
                id: format!("smoke_{id}"),
                label: format!("Smoke test: {id}"),
                layer: "runtime".to_string(),
                status,
                detail: item
                    .get("check_code")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("error").and_then(Value::as_str))
                    .or_else(|| item.get("reason").and_then(Value::as_str))
                    .map(ToString::to_string),
                evidence_ref: Some("smoke-test.json".to_string()),
            })
        })
        .collect()
}

fn smoke_bundle_check(manifest: Option<&Value>, bundle_dir: Option<&Path>) -> Option<ReportCheck> {
    let manifest = manifest?;
    let bundle_dir = bundle_dir?;
    let bundle_type_ok =
        manifest.get("bundle_type").and_then(Value::as_str) == Some(SMOKE_BUNDLE_TYPE);
    let manifest_status = manifest.get("overall_status").and_then(Value::as_str);
    let required_files = required_bundle_files_for_manifest(manifest);
    let missing = missing_required_bundle_files(bundle_dir, required_files);
    let (negative_passed, negative_total) = negative_test_counts(bundle_dir);
    let pass = manifest_status == Some("pass")
        && bundle_type_ok
        && missing.is_empty()
        && negative_total > 0
        && negative_passed == negative_total;
    Some(ReportCheck {
        id: "smoke_bundle_manifest".to_string(),
        label: "Smoke test bundle manifest".to_string(),
        layer: "runtime".to_string(),
        status: if pass {
            ReportCheckStatus::Pass
        } else {
            ReportCheckStatus::Fail
        },
        detail: Some(format!(
            "manifest_status={}, bundle_type_ok={}, required_files_missing={}, negative_tests={}/{}",
            manifest_status.unwrap_or("unknown"),
            bundle_type_ok,
            missing.len(),
            negative_passed,
            negative_total
        )),
        evidence_ref: Some("manifest.json".to_string()),
    })
}

fn compliance_checks(report: Option<&Value>) -> Vec<ReportCheck> {
    let Some(Value::Array(items)) = report
        .and_then(|v| v.get("policy_result"))
        .and_then(|v| v.get("rules"))
    else {
        return vec![];
    };
    items
        .iter()
        .filter_map(|item| {
            let id = item.get("rule_id")?.as_str()?;
            let label = item
                .get("rule_name")
                .and_then(Value::as_str)
                .unwrap_or(id)
                .to_string();
            Some(ReportCheck {
                id: format!("compliance_{id}"),
                label,
                layer: "policy".to_string(),
                status: match item.get("passed").and_then(Value::as_bool) {
                    Some(true) => ReportCheckStatus::Pass,
                    Some(false) => ReportCheckStatus::Fail,
                    None => ReportCheckStatus::Unknown,
                },
                detail: item
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                evidence_ref: Some("compliance-report.json".to_string()),
            })
        })
        .collect()
}

fn platform_checks(platform: &PlatformEvidenceSummary) -> Vec<ReportCheck> {
    let has_native = platform.aws_nitro.is_some()
        || platform.gcp_tdx.is_some()
        || platform.azure_snp.is_some()
        || platform.nvidia_gpu_cc.is_some();
    vec![ReportCheck {
        id: "platform_adapter".to_string(),
        label: "Platform evidence adapter".to_string(),
        layer: "platform".to_string(),
        status: if has_native {
            ReportCheckStatus::Pass
        } else {
            ReportCheckStatus::Unknown
        },
        detail: Some(format!(
            "{} / {} adapter_version={}",
            platform.cloud_provider, platform.runtime_type, platform.adapter_version
        )),
        evidence_ref: None,
    }]
}

fn unknown_check(id: &str, label: &str, detail: &str, evidence_ref: &str) -> ReportCheck {
    ReportCheck {
        id: id.to_string(),
        label: label.to_string(),
        layer: "runtime".to_string(),
        status: ReportCheckStatus::Unknown,
        detail: Some(detail.to_string()),
        evidence_ref: Some(evidence_ref.to_string()),
    }
}

fn measurements(
    measurement_doc: Option<&Value>,
    benchmark: Option<&Value>,
    receipt: Option<&Value>,
) -> Vec<MeasurementSummary> {
    let mut out = Vec::new();
    if let Some(doc) = measurement_doc {
        for key in [
            "measurement_type",
            "pcr0",
            "pcr1",
            "pcr2",
            "pcr8",
            "mrtd",
            "rtmr0",
            "rtmr1",
            "rtmr2",
            "rtmr3",
            "measurement",
            "report_data_hash",
        ] {
            if let Some(value) = doc.get(key).and_then(Value::as_str) {
                out.push(MeasurementSummary {
                    name: key.to_string(),
                    value: value.to_string(),
                });
            }
        }
    }
    if let Some(receipt) = receipt {
        if let Some(measurements) = receipt.get("enclave_measurements") {
            push_measurement_str(
                &mut out,
                measurements,
                "measurement_type",
                "measurement_type",
            );
            push_measurement_bytes(&mut out, measurements, "pcr0", "pcr0");
            push_measurement_bytes(&mut out, measurements, "pcr1", "pcr1");
            push_measurement_bytes(&mut out, measurements, "pcr2", "pcr2");
            push_measurement_bytes(&mut out, measurements, "pcr8", "pcr8");

            // Legacy receipts used pcr0/pcr1/pcr2 field names for TDX
            // measurements. Expose cloud-native aliases in the passport too.
            if measurements.get("measurement_type").and_then(Value::as_str) == Some("tdx-mrtd-rtmr")
            {
                push_measurement_bytes(&mut out, measurements, "pcr0", "mrtd");
                push_measurement_bytes(&mut out, measurements, "pcr1", "rtmr0");
                push_measurement_bytes(&mut out, measurements, "pcr2", "rtmr1");
            }
        }
        push_top_level_bytes(&mut out, receipt, "attestation_doc_hash");
        push_top_level_bytes(&mut out, receipt, "request_hash");
        push_top_level_bytes(&mut out, receipt, "response_hash");
    }
    if let Some(eif) = str_field(benchmark, "eif_sha384") {
        if !out.iter().any(|m| m.name == "eif_sha384") {
            out.push(MeasurementSummary {
                name: "eif_sha384".to_string(),
                value: eif,
            });
        }
    }
    out
}

fn push_measurement_str(
    out: &mut Vec<MeasurementSummary>,
    value: &Value,
    source: &str,
    name: &str,
) {
    if out.iter().any(|m| m.name == name) {
        return;
    }
    if let Some(value) = value.get(source).and_then(Value::as_str) {
        out.push(MeasurementSummary {
            name: name.to_string(),
            value: value.to_string(),
        });
    }
}

fn push_measurement_bytes(
    out: &mut Vec<MeasurementSummary>,
    value: &Value,
    source: &str,
    name: &str,
) {
    if out.iter().any(|m| m.name == name) {
        return;
    }
    if let Some(value) = value.get(source).and_then(json_bytes_to_hex) {
        out.push(MeasurementSummary {
            name: name.to_string(),
            value,
        });
    }
}

fn push_top_level_bytes(out: &mut Vec<MeasurementSummary>, value: &Value, name: &str) {
    push_measurement_bytes(out, value, name, name);
}

fn platform_evidence(
    args: &Args,
    measurements: &[MeasurementSummary],
    benchmark: Option<&Value>,
    smoke: Option<&Value>,
    metadata: Option<&Value>,
) -> PlatformEvidenceSummary {
    let evidence_uri = args
        .evidence_uri
        .clone()
        .or_else(|| str_field(smoke, "evidence_s3_uri"));
    let key_ref = args
        .key_ref
        .clone()
        .or_else(|| str_field(metadata, "kms_key"));
    let key_hash = key_ref.as_deref().map(hash_ref);
    let identity_hash = args.identity_ref.as_deref().map(hash_ref);
    let eif = args
        .eif_sha384
        .clone()
        .or_else(|| str_field(benchmark, "eif_sha384"))
        .or_else(|| measurement_value(measurements, "eif_sha384"))
        .or_else(|| measurement_value(measurements, "pcr0"));

    let mut summary = PlatformEvidenceSummary {
        cloud_provider: args.cloud_provider.clone(),
        runtime_type: args.runtime_type.clone(),
        adapter_version: "1".to_string(),
        aws_nitro: None,
        gcp_tdx: None,
        azure_snp: None,
        nvidia_gpu_cc: None,
    };

    match args.runtime_type.as_str() {
        "aws-nitro" => {
            summary.aws_nitro = Some(AwsNitroEvidence {
                pcr0: measurement_value(measurements, "pcr0").or_else(|| eif.clone()),
                pcr1: measurement_value(measurements, "pcr1"),
                pcr2: measurement_value(measurements, "pcr2"),
                pcr8: measurement_value(measurements, "pcr8"),
                eif_sha384: eif,
                kms_key_ref_hash: key_hash,
                iam_role_ref_hash: identity_hash,
                evidence_s3_uri: evidence_uri,
            });
        }
        "gcp-tdx" => {
            summary.gcp_tdx = Some(GcpTdxEvidence {
                mrtd: measurement_value(measurements, "mrtd"),
                rtmr0: measurement_value(measurements, "rtmr0"),
                rtmr1: measurement_value(measurements, "rtmr1"),
                rtmr2: measurement_value(measurements, "rtmr2"),
                rtmr3: measurement_value(measurements, "rtmr3"),
                attestation_token_issuer: Some(
                    "https://confidentialcomputing.googleapis.com".to_string(),
                ),
                image_digest: str_field(metadata, "image_digest"),
                kms_key_ref_hash: key_hash,
                evidence_gcs_uri: evidence_uri,
            });
        }
        "azure-sev-snp" => {
            summary.azure_snp = Some(AzureSnpEvidence {
                measurement: measurement_value(measurements, "measurement"),
                report_data_hash: measurement_value(measurements, "report_data_hash"),
                maa_result_hash: None,
                key_vault_key_ref_hash: key_hash,
                evidence_storage_uri: evidence_uri,
            });
        }
        "nvidia-h100-cc" | "nvidia-gpu-cc" => {
            summary.nvidia_gpu_cc = Some(NvidiaGpuCcEvidence {
                gpu_model: nested_str(benchmark, &["environment", "gpu_model"]),
                driver_version: nested_str(benchmark, &["environment", "driver_version"]),
                vbios_version: nested_str(benchmark, &["environment", "vbios_version"]),
                verifier_result: None,
                rim_ref_hash: key_hash,
            });
        }
        _ => {}
    }
    summary
}

fn measurement_value(measurements: &[MeasurementSummary], name: &str) -> Option<String> {
    measurements
        .iter()
        .find(|m| m.name == name)
        .map(|m| m.value.clone())
}

fn evidence_bundle_summary(
    bundle_dir: Option<&Path>,
    evidence_uri: Option<&str>,
) -> Result<Option<EvidenceBundleSummary>> {
    let Some(bundle_dir) = bundle_dir else {
        return Ok(evidence_uri.map(|uri| EvidenceBundleSummary {
            bundle_type: "unknown".to_string(),
            bundle_format_version: "unknown".to_string(),
            uri: Some(uri.to_string()),
            manifest_sha256: None,
            sha256sums_sha256: None,
            bundle_sha256: None,
            files: vec![],
        }));
    };
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest = read_json_value(&manifest_path)?;
    let files = read_sha256sums(bundle_dir.join("SHA256SUMS"))?;
    verify_file_digests(bundle_dir, &files, "SHA256SUMS")?;
    verify_manifest_file_digests(bundle_dir, manifest.as_ref())?;
    Ok(Some(EvidenceBundleSummary {
        bundle_type: manifest
            .as_ref()
            .and_then(|v| v.get("bundle_type"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string()),
        bundle_format_version: manifest
            .as_ref()
            .and_then(|v| v.get("bundle_format_version"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string()),
        uri: evidence_uri.map(ToString::to_string),
        manifest_sha256: file_sha256_hex(manifest_path),
        sha256sums_sha256: file_sha256_hex(bundle_dir.join("SHA256SUMS")),
        bundle_sha256: None,
        files,
    }))
}

fn read_sha256sums(path: PathBuf) -> Result<Vec<FileDigest>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut digests = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let sha256 = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("malformed SHA256SUMS line {}", idx + 1))?;
        let name = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("malformed SHA256SUMS line {}", idx + 1))?;
        if parts.next().is_some() {
            bail!("malformed SHA256SUMS line {}", idx + 1);
        }
        validate_sha256_hex(sha256, &format!("SHA256SUMS line {}", idx + 1))?;
        digests.push(FileDigest {
            name: name.to_string(),
            sha256: sha256.to_string(),
        });
    }
    Ok(digests)
}

fn read_json_value(path: &Path) -> Result<Option<Value>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))
        .map(Some)
}

fn verify_file_digests(bundle_dir: &Path, files: &[FileDigest], source: &str) -> Result<()> {
    for file in files {
        validate_bundle_file_digest(bundle_dir, &file.name, &file.sha256, source)?;
    }
    Ok(())
}

fn verify_manifest_file_digests(bundle_dir: &Path, manifest: Option<&Value>) -> Result<()> {
    let Some(Value::Array(files)) = manifest.and_then(|v| v.get("files")) else {
        return Ok(());
    };
    for (idx, file) in files.iter().enumerate() {
        let name = file
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("manifest.files[{idx}] missing name"))?;
        let sha256 = file
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("manifest.files[{idx}] missing sha256"))?;
        validate_bundle_file_digest(bundle_dir, name, sha256, "manifest.json")?;
    }
    Ok(())
}

fn validate_bundle_file_digest(
    bundle_dir: &Path,
    name: &str,
    expected_sha256: &str,
    source: &str,
) -> Result<()> {
    validate_sha256_hex(expected_sha256, source)?;
    let path = safe_bundle_file_path(bundle_dir, name)?;
    let bytes = fs::read(&path)
        .with_context(|| format!("{source} lists missing bundle file {}", path.display()))?;
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != expected_sha256 {
        bail!("{source} hash mismatch for {name}: expected {expected_sha256}, got {actual}");
    }
    Ok(())
}

fn safe_bundle_file_path(bundle_dir: &Path, name: &str) -> Result<PathBuf> {
    let relative = Path::new(name);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("unsafe bundle file path: {name}");
    }
    Ok(bundle_dir.join(relative))
}

fn validate_sha256_hex(value: &str, label: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{label} is not a valid SHA-256 hex digest");
    }
    Ok(())
}

fn required_bundle_files_for_manifest(manifest: &Value) -> &'static [&'static str] {
    match manifest
        .get("bundle_format_version")
        .and_then(Value::as_str)
    {
        Some("3") => SMOKE_BUNDLE_REQUIRED_FILES_V3,
        _ => SMOKE_BUNDLE_REQUIRED_FILES,
    }
}

fn missing_required_bundle_files(
    bundle_dir: &Path,
    required_files: &'static [&'static str],
) -> Vec<&'static str> {
    required_files
        .iter()
        .copied()
        .filter(|name| !bundle_dir.join(name).exists())
        .collect()
}

fn negative_test_counts(bundle_dir: &Path) -> (usize, usize) {
    let path = bundle_dir.join("negative-tests.json");
    let Ok(bytes) = fs::read(path) else {
        return (0, 0);
    };
    let Ok(Value::Array(items)) = serde_json::from_slice::<Value>(&bytes) else {
        return (0, 0);
    };
    let passed = items
        .iter()
        .filter(|item| item.get("passed").and_then(Value::as_bool) == Some(true))
        .count();
    (passed, items.len())
}

fn read_json_opt(path: Option<&Path>) -> Result<Option<Value>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))
        .map(Some)
}

fn read_bundle_json(args: &Args, name: &str) -> Option<Value> {
    let dir = args.bundle_dir.as_ref()?;
    let bytes = fs::read(dir.join(name)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn file_sha256_hex(path: PathBuf) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(hex::encode(Sha256::digest(bytes)))
}

fn write_sha256sums(dir: &Path, names: &[&str]) -> Result<()> {
    let mut lines = Vec::new();
    for name in names {
        let path = dir.join(name);
        let bytes =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        lines.push(format!("{}  {}", hex::encode(Sha256::digest(bytes)), name));
    }
    fs::write(dir.join("SHA256SUMS"), format!("{}\n", lines.join("\n")))
        .context("failed to write SHA256SUMS")
}

fn hash_ref(input: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(input.as_bytes())))
}

fn str_field(value: Option<&Value>, key: &str) -> Option<String> {
    value?.get(key)?.as_str().map(ToString::to_string)
}

fn nested_str(value: Option<&Value>, path: &[&str]) -> Option<String> {
    let mut current = value?;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(ToString::to_string)
}

fn nested_u64(value: Option<&Value>, path: &[&str]) -> Option<u64> {
    let mut current = value?;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_u64()
}

fn metadata_region(metadata: Option<&Value>) -> Option<String> {
    let zone = str_field(metadata, "zone")?;
    let (region, _) = zone.rsplit_once('-')?;
    Some(region.to_string())
}

fn json_bytes_to_hex(value: &Value) -> Option<String> {
    match value {
        Value::Array(items) => {
            let mut bytes = Vec::with_capacity(items.len());
            for item in items {
                let n = item.as_u64()?;
                if n > u8::MAX as u64 {
                    return None;
                }
                bytes.push(n as u8);
            }
            Some(hex::encode(bytes))
        }
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn render_markdown(passport: &RuntimePassportV1) -> String {
    let mut out = String::new();
    out.push_str("# Cyntrisec Runtime Passport\n\n");
    out.push_str(&format!("Passport ID: `{}`\n\n", passport.passport_id));
    out.push_str(&format!("Status: `{:?}`\n\n", passport.overall_status));
    append_warning_banner_markdown(&mut out, &passport.limitations);
    if let Some(hash) = &passport.passport_sha256 {
        out.push_str(&format!("Passport SHA-256: `{}`\n\n", hash));
    }
    out.push_str("## Runtime\n\n");
    out.push_str(&format!(
        "- Provider: `{}`\n- Runtime type: `{}`\n",
        passport.deployment.cloud_provider, passport.runtime.runtime_type
    ));
    if let Some(region) = &passport.deployment.region {
        out.push_str(&format!("- Region: `{region}`\n"));
    }
    if let Some(instance) = &passport.runtime.instance_type {
        out.push_str(&format!("- Instance type: `{instance}`\n"));
    }
    out.push_str("\n## Components\n\n");
    out.push_str(&format!(
        "- Doctor: `{:?}` ({})\n",
        passport.doctor.status,
        passport.doctor.summary.as_deref().unwrap_or("no summary")
    ));
    out.push_str(&format!(
        "- Smoke test: `{:?}` ({})\n",
        passport.smoke_test.status,
        passport
            .smoke_test
            .summary
            .as_deref()
            .unwrap_or("no summary")
    ));
    if let Some(compliance) = &passport.compliance {
        out.push_str(&format!(
            "- Compliance policy: `{:?}` ({})\n",
            compliance.status,
            compliance.summary.as_deref().unwrap_or("no summary")
        ));
    }
    out.push_str("\n## Measurements\n\n");
    for measurement in &passport.measurements {
        out.push_str(&format!(
            "- {}: `{}`\n",
            measurement.name, measurement.value
        ));
    }
    out.push_str("\n## Checks\n\n");
    out.push_str("| Layer | Check | Status | Detail |\n|---|---|---|---|\n");
    for check in &passport.checks {
        out.push_str(&format!(
            "| {} | {} | {:?} | {} |\n",
            check.layer,
            check.label,
            check.status,
            check.detail.as_deref().unwrap_or("")
        ));
    }
    out.push_str("\n## Limitations\n\n");
    for limitation in &passport.limitations {
        out.push_str(&format!(
            "- **{}:** {}\n",
            limitation.code, limitation.message
        ));
    }
    out
}

fn render_html(passport: &RuntimePassportV1) -> String {
    let json = serde_json::to_string_pretty(passport).unwrap_or_else(|_| "{}".to_string());
    let status_class = if matches!(&passport.overall_status, ReportStatus::Pass) {
        "pass"
    } else if matches!(&passport.overall_status, ReportStatus::Fail) {
        "fail"
    } else {
        "partial"
    };
    let warning_html = warning_banner_html(&passport.limitations);
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Cyntrisec Runtime Passport</title><style>body{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#050505;color:#f5f5f5;margin:0;padding:32px}}main{{max-width:980px;margin:auto}}.card{{border:1px solid #333;padding:20px;margin:16px 0;background:#0b0b0b}}.warning{{border-color:#ffb84a;background:#201600;color:#ffdc8a}}.pass{{color:#39ff7c}}.fail{{color:#ff5a5a}}.partial{{color:#ffb84a}}pre{{white-space:pre-wrap;word-break:break-word;background:#000;padding:16px;border:1px solid #333}}</style></head><body><main><h1>Cyntrisec Runtime Passport</h1><div class=\"card\"><p>Passport ID: <code>{}</code></p><p>Status: <strong class=\"{}\">{:?}</strong></p><p>Runtime: <code>{}/{}</code></p><p>Passport SHA-256: <code>{}</code></p></div>{}<div class=\"card\"><h2>Machine-readable passport</h2><pre>{}</pre></div></main></body></html>\n",
        esc(&passport.passport_id),
        status_class,
        passport.overall_status,
        esc(&passport.deployment.cloud_provider),
        esc(&passport.runtime.runtime_type),
        esc(passport.passport_sha256.as_deref().unwrap_or("not-finalized")),
        warning_html,
        esc(&json)
    )
}

fn esc(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn append_warning_banner_markdown(out: &mut String, limitations: &[Limitation]) {
    let warnings = prominent_limitations(limitations);
    if warnings.is_empty() {
        return;
    }
    out.push_str("> Warning: this passport has reviewer-visible limitations:\n");
    for limitation in warnings {
        out.push_str(&format!(
            "> - **{}:** {}\n",
            limitation.code, limitation.message
        ));
    }
    out.push('\n');
}

fn warning_banner_html(limitations: &[Limitation]) -> String {
    let warnings = prominent_limitations(limitations);
    if warnings.is_empty() {
        return String::new();
    }
    let items = warnings
        .into_iter()
        .map(|limitation| {
            format!(
                "<li><strong>{}</strong>: {}</li>",
                esc(&limitation.code),
                esc(&limitation.message)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<div class=\"card warning\"><h2>Reviewer-visible limitation</h2><ul>{items}</ul></div>"
    )
}

fn prominent_limitations(limitations: &[Limitation]) -> Vec<&Limitation> {
    limitations
        .iter()
        .filter(|limitation| {
            limitation.code.starts_with("unsigned_")
                || limitation.code.starts_with("runtime_passport_unsigned_")
        })
        .collect()
}

fn warn_if_inherited_unredacted_account_id(
    explicit_account_id: Option<&str>,
    account_id: Option<&str>,
) {
    if explicit_account_id.is_some() {
        return;
    }
    if let Some(account_id) = account_id {
        if is_aws_account_id(account_id) {
            eprintln!(
                "WARN: account_id {account_id:?} inherited from input evidence; pass --account-id aws-account-redacted before sharing this passport."
            );
        }
    }
}

fn is_aws_account_id(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn overall_status_requires_both_doctor_and_smoke_to_pass() {
        assert_eq!(
            overall_status(&ReportStatus::Pass, &ReportStatus::Pass, None),
            ReportStatus::Pass
        );
        assert_eq!(
            overall_status(&ReportStatus::Pass, &ReportStatus::Unknown, None),
            ReportStatus::Partial
        );
        assert_eq!(
            overall_status(&ReportStatus::Pass, &ReportStatus::Fail, None),
            ReportStatus::Fail
        );
        let compliance = ComponentResult {
            status: ReportStatus::Pass,
            duration_ms: None,
            summary: None,
        };
        assert_eq!(
            overall_status(
                &ReportStatus::Unknown,
                &ReportStatus::Unknown,
                Some(&compliance)
            ),
            ReportStatus::Partial
        );
    }

    #[test]
    fn doctor_component_counts_passed_checks() {
        let doctor = json!({
            "overall_status": "pass",
            "checks": [
                {"check": "allocator", "status": "ok", "duration_ms": 7},
                {"check": "clock", "status": "ok", "duration_ms": 2}
            ]
        });
        let result = component_from_doctor(Some(&doctor), None);
        assert_eq!(result.status, ReportStatus::Pass);
        assert_eq!(result.duration_ms, Some(9));
        assert_eq!(result.summary.as_deref(), Some("2/2 doctor checks passed"));
    }

    #[test]
    fn unsigned_eif_override_is_not_rendered_as_passed_check() {
        let doctor = json!({
            "overall_status": "pass",
            "checks": [
                {
                    "check": "eif",
                    "status": "ok",
                    "details": {
                        "unsigned_internal_poc": true,
                        "cosign_verified": false
                    }
                }
            ]
        });
        let checks = doctor_checks(Some(&doctor), true);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, ReportCheckStatus::Skip);
        assert_eq!(
            checks[0].detail.as_deref(),
            Some("unsigned_internal_poc=true; cosign_verified=false")
        );
    }

    #[test]
    fn aws_adapter_hashes_sensitive_refs() {
        let args = Args {
            output_dir: PathBuf::from("/tmp/out"),
            cloud_provider: "aws".to_string(),
            runtime_type: "aws-nitro".to_string(),
            doctor_json: None,
            smoke_json: None,
            bundle_dir: None,
            metadata_json: None,
            compliance_report: None,
            receipt_json: None,
            evidence_uri: Some("s3://bucket/prefix/".to_string()),
            account_id: None,
            region: None,
            stack_name: None,
            instance_type: None,
            enclave_cid: None,
            enclave_memory_mib: None,
            enclave_cpu_count: None,
            git_commit: None,
            release_bundle_sha256: None,
            eif_sha384: Some("a".repeat(96)),
            key_ref: Some("kms-ref-for-test".to_string()),
            identity_ref: Some("iam-ref-for-test".to_string()),
            ttl_days: 90,
        };
        let platform = platform_evidence(&args, &[], None, None, None);
        let aws = platform.aws_nitro.expect("aws adapter");
        let expected_eif = "a".repeat(96);
        assert_eq!(aws.eif_sha384.as_deref(), Some(expected_eif.as_str()));
        assert!(aws.kms_key_ref_hash.unwrap().starts_with("sha256:"));
        assert!(aws.iam_role_ref_hash.unwrap().starts_with("sha256:"));
    }
}
