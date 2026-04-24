//! Shared context available to every check.
//!
//! Bootstrapped once per binary invocation. Holds the pieces of identity +
//! configuration that are safe to share across checks (account ID, region,
//! stack name). Individual checks pull their own probe data — the context
//! itself intentionally does not cache AWS API responses, to keep check-level
//! independence and avoid stale-state bugs.

use crate::cli::Args;
use crate::error::DoctorError;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct Context {
    pub doctor_version: &'static str,
    pub timestamp: DateTime<Utc>,
    pub stack_name: String,
    pub account_id: String,
    pub region: String,
}

impl Context {
    /// Resolve identity + stack metadata.
    ///
    /// Skeleton behavior: produces a placeholder context without calling
    /// IMDSv2 or AWS APIs. Real implementation will fetch account + region
    /// from IMDSv2 and stack-name from either `--stack-name` or the instance's
    /// `aws:cloudformation:stack-name` tag per the doctor spec.
    pub async fn bootstrap(args: &Args) -> Result<Self, DoctorError> {
        Ok(Self {
            doctor_version: env!("CARGO_PKG_VERSION"),
            timestamp: Utc::now(),
            stack_name: args
                .stack_name
                .clone()
                .unwrap_or_else(|| "cyntrisec-pilot".to_string()),
            account_id: "000000000000".to_string(),
            region: "us-east-1".to_string(),
        })
    }
}
