//! Evidence bundle structure pinned by the spec.
//!
//! Every successful high-confidence smoke test uploads EXACTLY these 14 files to
//! `s3://{bucket}/smoke-tests/{iso-timestamp-utc}/`:
//!
//! - manifest.json
//! - doctor.json
//! - receipt.cbor
//! - attestation.cbor
//! - receipt.txt
//! - verification.json
//! - enclave-measurements.json
//! - inference-metadata.json
//! - model-info.json
//! - kms-release.json
//! - negative-tests.json
//! - benchmark.json
//! - approval-report.md
//! - SHA256SUMS
//!
//! The structure is frozen up-front to avoid "we'll figure out the layout"
//! during implementation. Bumps to the schema require a `bundle_format_version`
//! increment.

// These types and constants pin the bundle contract used by Stage 5.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

pub const BUNDLE_FORMAT_VERSION: &str = "3";
pub const BUNDLE_TYPE: &str = "cyntrisec-phase-1-smoke-test";
pub const BENCHMARK_SCHEMA_VERSION: &str = "1";

/// The canonical SHA256SUMS-covered file names in order. Used by Stage 5 to validate the
/// bundle contents against the manifest.
pub const BUNDLE_FILE_NAMES: &[&str] = &[
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
    // SHA256SUMS is generated last over the other files; manifest.json is
    // a companion index, not one of the SHA256SUMS targets.
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub bundle_format_version: String,
    pub bundle_type: String,
    pub smoke_test_version: String,
    pub timestamp_utc: String,
    pub stack_name: String,
    pub account_id: String,
    pub region: String,
    pub fixture_version: String,
    pub overall_status: String,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub sha256: String,
}

/// Stable shape for `benchmark.json`.
///
/// Fields are optional where the value may only be known in the live AWS run
/// or after a later stage lands. The file is still emitted with explicit nulls
/// rather than changing shape between local, CI, and AWS runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub schema_version: String,
    pub run_id: String,
    pub timestamp_utc: String,
    pub git_commit: Option<String>,
    pub release_bundle_sha256: Option<String>,
    pub eif_sha384: Option<String>,
    pub environment: BenchmarkEnvironment,
    pub timings_ms: BenchmarkTimings,
    pub evidence_sizes: EvidenceSizes,
    pub negative_tests: Vec<NegativeTestResult>,
    pub cost: CostInputs,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchmarkEnvironment {
    pub region: Option<String>,
    pub availability_zone: Option<String>,
    pub instance_type: Option<String>,
    pub ami_id: Option<String>,
    pub kernel: Option<String>,
    pub nitro_cli_version: Option<String>,
    pub enclave_cid: Option<u32>,
    pub enclave_cpu_count: Option<u32>,
    pub enclave_memory_mib: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchmarkTimings {
    pub cloudformation_stack_create_ms: Option<u64>,
    pub host_bootstrap_ms: Option<u64>,
    pub release_bundle_install_ms: Option<u64>,
    pub doctor_total_ms: Option<u64>,
    pub doctor_allocator_ms: Option<u64>,
    pub doctor_eif_ms: Option<u64>,
    pub doctor_role_ms: Option<u64>,
    pub doctor_bucket_ms: Option<u64>,
    pub doctor_kms_ms: Option<u64>,
    pub doctor_clock_ms: Option<u64>,
    pub kms_model_decrypt_ms: Option<u64>,
    pub enclave_launch_ms: Option<u64>,
    pub attestation_collect_ms: Option<u64>,
    pub model_load_ms: Option<u64>,
    pub synthetic_inference_ms: Option<u64>,
    pub air_sign_ms: Option<u64>,
    pub receipt_verify_ms: Option<u64>,
    pub s3_upload_ms: Option<u64>,
    pub total_smoke_test_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceSizes {
    pub receipt_bytes: Option<u64>,
    pub attestation_document_bytes: Option<u64>,
    pub verification_json_bytes: Option<u64>,
    pub full_bundle_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeTestResult {
    pub name: String,
    pub expected_failure_code: String,
    pub actual_failure_code: Option<String>,
    pub duration_ms: Option<u64>,
    pub passed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CostInputs {
    pub instance_runtime_minutes: Option<u64>,
    pub ec2_estimated_usd: Option<f64>,
    pub kms_api_calls: Option<u64>,
    pub s3_api_calls: Option<u64>,
    pub total_estimated_usd: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_has_twelve_hashed_files_plus_manifest_and_sha256sums() {
        // Spec's 14-file bundle = 12 hashed files + manifest.json (companion
        // index, not hashed into SHA256SUMS) + SHA256SUMS itself. The
        // BUNDLE_FILE_NAMES list names the 12 that go into SHA256SUMS.
        assert_eq!(BUNDLE_FILE_NAMES.len(), 12);
        assert!(BUNDLE_FILE_NAMES.contains(&"doctor.json"));
        assert!(BUNDLE_FILE_NAMES.contains(&"receipt.cbor"));
        assert!(BUNDLE_FILE_NAMES.contains(&"attestation.cbor"));
        assert!(BUNDLE_FILE_NAMES.contains(&"verification.json"));
        assert!(BUNDLE_FILE_NAMES.contains(&"enclave-measurements.json"));
        assert!(BUNDLE_FILE_NAMES.contains(&"model-info.json"));
        assert!(BUNDLE_FILE_NAMES.contains(&"kms-release.json"));
        assert!(BUNDLE_FILE_NAMES.contains(&"negative-tests.json"));
        assert!(BUNDLE_FILE_NAMES.contains(&"benchmark.json"));
        assert!(BUNDLE_FILE_NAMES.contains(&"approval-report.md"));
    }

    #[test]
    fn benchmark_schema_serializes_with_nulls_for_not_yet_known_values() {
        let report = BenchmarkReport {
            schema_version: BENCHMARK_SCHEMA_VERSION.to_string(),
            run_id: "test-run".to_string(),
            timestamp_utc: "2026-04-27T00:00:00Z".to_string(),
            git_commit: None,
            release_bundle_sha256: None,
            eif_sha384: None,
            environment: BenchmarkEnvironment::default(),
            timings_ms: BenchmarkTimings::default(),
            evidence_sizes: EvidenceSizes::default(),
            negative_tests: Vec::new(),
            cost: CostInputs::default(),
        };
        let json = serde_json::to_value(&report).expect("benchmark report serializes");
        assert_eq!(json["schema_version"], BENCHMARK_SCHEMA_VERSION);
        assert!(json["timings_ms"]["total_smoke_test_ms"].is_null());
    }
}
