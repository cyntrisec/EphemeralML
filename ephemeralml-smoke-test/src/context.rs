//! Shared context available to every stage.
//!
//! Populated once per invocation with identity + stack metadata. Individual
//! stages pull their own probe data; the context does not cache AWS API
//! responses to keep stage independence.

// Skeleton: CANONICAL_INPUT + several Context fields are consumed by real
// Stage 3 / S3 write implementations when they land.
#![allow(dead_code)]

use crate::cli::Args;
use crate::error::SmokeTestError;
use chrono::{DateTime, Utc};

/// Fixture version for the synthetic input + expected outputs. Bumped when
/// the canonical input or model changes; old bundles remain interpretable
/// against their own fixture_version.
pub const FIXTURE_VERSION: &str = "1";

/// Canonical 97-byte synthetic input pinned by the smoke-test spec.
pub const CANONICAL_INPUT: &str =
    "smoke-test synthetic input for Cyntrisec Phase 1 dress rehearsal (RFC 3339: 2026-04-23)\n";

#[derive(Debug, Clone)]
pub struct Context {
    pub smoke_test_version: &'static str,
    pub timestamp: DateTime<Utc>,
    pub stack_name: String,
    pub account_id: String,
    pub region: String,
    pub retain_enclave: bool,
    pub no_upload: bool,
}

impl Context {
    /// Skeleton: placeholder identity without IMDSv2 / AWS API calls.
    pub async fn bootstrap(args: &Args) -> Result<Self, SmokeTestError> {
        Ok(Self {
            smoke_test_version: env!("CARGO_PKG_VERSION"),
            timestamp: Utc::now(),
            stack_name: args
                .stack_name
                .clone()
                .unwrap_or_else(|| "cyntrisec-pilot".to_string()),
            account_id: "000000000000".to_string(),
            region: "us-east-1".to_string(),
            retain_enclave: args.retain_enclave,
            no_upload: args.no_upload,
        })
    }
}
