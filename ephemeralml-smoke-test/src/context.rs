//! Shared context available to every stage.
//!
//! Populated once per invocation with identity + stack metadata. Individual
//! stages pull their own probe data; the context does not cache AWS API
//! responses to keep stage independence.

use crate::cli::Args;
use crate::error::SmokeTestError;
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use tokio::process::Command;

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
    pub bundle_dir: PathBuf,
}

impl Context {
    pub async fn bootstrap(args: &Args) -> Result<Self, SmokeTestError> {
        let bundle_dir = args.bundle_dir.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("cyntrisec-smoke-{}", uuid::Uuid::new_v4()))
        });
        std::fs::create_dir_all(&bundle_dir).map_err(|e| {
            SmokeTestError::Internal(format!(
                "failed to create bundle dir {}: {}",
                bundle_dir.display(),
                e
            ))
        })?;

        let region = discover_region().await;
        let account_id = discover_account_id().await;

        Ok(Self {
            smoke_test_version: env!("CARGO_PKG_VERSION"),
            timestamp: Utc::now(),
            stack_name: args
                .stack_name
                .clone()
                .unwrap_or_else(|| "cyntrisec-pilot".to_string()),
            account_id,
            region,
            retain_enclave: args.retain_enclave,
            bundle_dir,
        })
    }
}

async fn discover_region() -> String {
    if let Ok(region) = std::env::var("AWS_REGION")
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .map(|v| v.trim().to_string())
    {
        if !region.is_empty() {
            return region;
        }
    }

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    config
        .region()
        .map(|r| r.as_ref().to_string())
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| "us-east-1".to_string())
}

async fn discover_account_id() -> String {
    if let Ok(account) = std::env::var("AWS_ACCOUNT_ID").map(|v| v.trim().to_string()) {
        if is_account_id(&account) {
            return account;
        }
    }

    let output = Command::new("aws")
        .arg("sts")
        .arg("get-caller-identity")
        .arg("--output")
        .arg("json")
        .output()
        .await;

    let Ok(output) = output else {
        return "unknown".to_string();
    };
    if !output.status.success() {
        return "unknown".to_string();
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return "unknown".to_string();
    };
    value
        .get("Account")
        .and_then(serde_json::Value::as_str)
        .filter(|v| is_account_id(v))
        .unwrap_or("unknown")
        .to_string()
}

fn is_account_id(value: &str) -> bool {
    value.len() == 12 && value.chars().all(|c| c.is_ascii_digit())
}
