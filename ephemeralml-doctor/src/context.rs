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
use serde::Deserialize;

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
    pub async fn bootstrap(args: &Args) -> Result<Self, DoctorError> {
        let identity = fetch_instance_identity()
            .await
            .unwrap_or_else(|_| InstanceIdentity {
                account_id: "unknown".to_string(),
                region: "unknown".to_string(),
            });

        Ok(Self {
            doctor_version: env!("CARGO_PKG_VERSION"),
            timestamp: Utc::now(),
            stack_name: args
                .stack_name
                .clone()
                .unwrap_or_else(|| "cyntrisec-pilot".to_string()),
            account_id: identity.account_id,
            region: identity.region,
        })
    }
}

#[derive(Debug, Deserialize)]
struct InstanceIdentity {
    #[serde(rename = "accountId")]
    account_id: String,
    region: String,
}

async fn fetch_instance_identity() -> Result<InstanceIdentity, DoctorError> {
    let imds_client = aws_config::imds::client::Client::builder().build();
    let body = imds_client
        .get("/latest/dynamic/instance-identity/document")
        .await
        .map_err(|e| {
            DoctorError::InfrastructureUnreachable(format!(
                "IMDS identity document fetch failed: {}",
                e
            ))
        })?;
    serde_json::from_str(body.as_ref()).map_err(|e| {
        DoctorError::Internal(format!("IMDS identity document JSON parse failed: {}", e))
    })
}
