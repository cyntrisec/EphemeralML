use std::collections::HashSet;
use std::time::Duration;

use clap::{Parser, ValueEnum};

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Clone, Debug, Parser)]
#[command(name = "cyntrisec-relay-egress")]
#[command(about = "Nitro parent-side KMS and S3 egress helper for Cyntrisec workers")]
pub struct EgressConfig {
    #[arg(long, env = "CYNTRISEC_EGRESS_VSOCK_PORT", default_value_t = 5001)]
    pub vsock_listen_port: u32,

    #[arg(long, env = "CYNTRISEC_EGRESS_AWS_REGION", default_value = "us-east-1")]
    pub aws_region: String,

    #[arg(long, env = "CYNTRISEC_EGRESS_ALLOWED_BUCKETS", value_delimiter = ',')]
    pub allowed_buckets: Vec<String>,

    #[arg(long, env = "CYNTRISEC_EGRESS_ALLOWED_KMS_KEYS", value_delimiter = ',')]
    pub allowed_kms_keys: Vec<String>,

    #[arg(
        long,
        env = "CYNTRISEC_EGRESS_MAX_REQUEST_BYTES",
        default_value_t = 100 * 1024 * 1024
    )]
    pub max_request_bytes: usize,

    #[arg(long, env = "CYNTRISEC_EGRESS_MAX_CONN", default_value_t = 64)]
    pub max_concurrent: usize,

    #[arg(long, env = "CYNTRISEC_EGRESS_IDLE_SECS", default_value_t = 300)]
    pub idle_timeout_secs: u64,

    #[arg(
        long,
        env = "CYNTRISEC_EGRESS_LOG_FORMAT",
        value_enum,
        default_value_t = LogFormat::Json
    )]
    pub log_format: LogFormat,
}

impl EgressConfig {
    pub fn allowed_buckets_set(&self) -> HashSet<String> {
        non_empty_set(&self.allowed_buckets)
    }

    pub fn allowed_kms_keys_set(&self) -> HashSet<String> {
        non_empty_set(&self.allowed_kms_keys)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }
}

fn non_empty_set(values: &[String]) -> HashSet<String> {
    values
        .iter()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}
