//! Evidence bundle structure pinned by the spec.
//!
//! Every successful smoke test uploads EXACTLY these 9 files to
//! `s3://{bucket}/smoke-tests/{iso-timestamp-utc}/`:
//!
//! - manifest.json
//! - doctor.json
//! - receipt.cbor
//! - receipt.txt
//! - verification.json
//! - enclave-measurements.json
//! - inference-metadata.json
//! - model-info.json
//! - SHA256SUMS
//!
//! The structure is frozen up-front to avoid "we'll figure out the layout"
//! during implementation. Bumps to the schema require a `bundle_format_version`
//! increment.

// Skeleton: these types + constants pin the bundle contract. Real Stage 5
// implementation will construct Manifest values and use the constants.
// Suppress the skeleton-build dead-code warnings until that lands.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

pub const BUNDLE_FORMAT_VERSION: &str = "1";
pub const BUNDLE_TYPE: &str = "cyntrisec-phase-1-smoke-test";

/// The 9 canonical file names in order. Used by Stage 5 to validate the
/// bundle contents against the manifest (and by skeleton tests to verify
/// the framework knows the contract).
pub const BUNDLE_FILE_NAMES: &[&str] = &[
    "doctor.json",
    "receipt.cbor",
    "receipt.txt",
    "verification.json",
    "enclave-measurements.json",
    "inference-metadata.json",
    "model-info.json",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_has_seven_hashed_files_plus_manifest_and_sha256sums() {
        // Spec's 9-file bundle = 7 hashed files + manifest.json (companion
        // index, not hashed into SHA256SUMS) + SHA256SUMS itself. The
        // BUNDLE_FILE_NAMES list names the 7 that go into SHA256SUMS.
        assert_eq!(BUNDLE_FILE_NAMES.len(), 7);
        assert!(BUNDLE_FILE_NAMES.contains(&"doctor.json"));
        assert!(BUNDLE_FILE_NAMES.contains(&"receipt.cbor"));
        assert!(BUNDLE_FILE_NAMES.contains(&"verification.json"));
        assert!(BUNDLE_FILE_NAMES.contains(&"enclave-measurements.json"));
        assert!(BUNDLE_FILE_NAMES.contains(&"model-info.json"));
    }
}
