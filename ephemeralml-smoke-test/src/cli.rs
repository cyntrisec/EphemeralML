//! CLI argument parsing.
//!
//! Flag contract locked by `byoc-phase-1-ephemeralml-smoke-test-spec-2026-04-23.md`.

use clap::Parser;
use std::fmt;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "ephemeralml-smoke-test",
    version,
    about = "Phase 1 BYOC end-to-end smoke test.",
    long_about = "Runs 5 stages in strict order: doctor preflight, enclave launch, \
                  synthetic inference, in-process AIR v1 receipt verification, \
                  evidence bundle upload to customer's S3.\n\n\
                  Contract: byoc-phase-1-ephemeralml-smoke-test-spec-2026-04-23.md"
)]
pub struct Args {
    /// Emit machine-readable JSON instead of human text output.
    #[arg(long)]
    pub json: bool,

    /// Run stages 1-4 only; skip the S3 evidence upload step. For CI / quick
    /// post-deploy sanity checks that do not need to produce a persisted bundle.
    #[arg(long)]
    pub no_upload: bool,

    /// Include raw probe data in output. Never includes customer workflow data.
    #[arg(long)]
    pub verbose: bool,

    /// Override the auto-detected CloudFormation stack name.
    #[arg(long, value_name = "NAME")]
    pub stack_name: Option<String>,

    /// Do NOT terminate the enclave after the test. For post-mortem debugging;
    /// normally cleanup runs on every exit path.
    #[arg(long)]
    pub retain_enclave: bool,

    /// Path to the doctor binary invoked by Stage 1.
    #[arg(long, value_name = "PATH", default_value = "ephemeralml-doctor")]
    pub doctor_bin: String,

    /// Maximum time to wait for doctor preflight.
    #[arg(long, value_name = "SECONDS", default_value_t = 60)]
    pub doctor_timeout_secs: u64,

    /// Directory where the local evidence bundle is assembled.
    #[arg(long, value_name = "PATH")]
    pub bundle_dir: Option<PathBuf>,

    /// Path to the EIF launched by Stage 2.
    #[arg(
        long,
        value_name = "PATH",
        default_value = "/opt/cyntrisec/eif/ephemeralml-pilot.eif"
    )]
    pub eif_path: PathBuf,

    /// Path to nitro-cli.
    #[arg(long, value_name = "PATH", default_value = "nitro-cli")]
    pub nitro_cli: String,

    /// Path to the host-side KMS/S3 VSock proxy. It must be running before the
    /// enclave boots when the EIF uses model_source=aws-s3-kms.
    #[arg(long, value_name = "PATH", default_value = "kms_proxy_host")]
    pub kms_proxy_bin: String,

    /// Terminate existing enclaves before launching the PoC enclave.
    #[arg(long)]
    pub terminate_existing: bool,

    /// Run enclave in debug mode. This is not accepted for the high-confidence PoC.
    #[arg(long)]
    pub debug_enclave: bool,

    /// Enclave CID used by nitro-cli and host orchestrator.
    #[arg(long, default_value_t = 16)]
    pub enclave_cid: u32,

    /// Enclave memory in MiB.
    #[arg(long, default_value_t = 4096)]
    pub enclave_memory_mib: u32,

    /// Enclave vCPU count.
    #[arg(long, default_value_t = 2)]
    pub enclave_cpu_count: u32,

    /// Seconds to wait after run-enclave before probing state.
    #[arg(long, default_value_t = 15)]
    pub enclave_boot_wait_secs: u64,

    /// Path to the host orchestrator binary invoked by Stage 3.
    #[arg(long, value_name = "PATH", default_value = "ephemeral-ml-host")]
    pub host_bin: String,

    /// Maximum time to wait for host orchestrator inference.
    #[arg(long, value_name = "SECONDS", default_value_t = 180)]
    pub inference_timeout_secs: u64,

    /// Synthetic workflow input text.
    #[arg(long, default_value = crate::context::CANONICAL_INPUT)]
    pub input_text: String,

    /// Path to the offline verifier binary invoked by Stage 4.
    #[arg(long, value_name = "PATH", default_value = "ephemeralml-verify")]
    pub verifier_bin: String,

    /// Expected AIR model_id.
    #[arg(long, default_value = "stage-0")]
    pub expected_model: String,

    /// Optional expected AIR model_hash as 64 hex chars.
    #[arg(long)]
    pub expected_model_hash: Option<String>,

    /// Expected AIR security_mode.
    #[arg(long, default_value = "production")]
    pub expected_security_mode: String,

    /// Expected AIR measurement_type.
    #[arg(long, default_value = "nitro-pcr")]
    pub measurement_type: String,

    /// Maximum AIR receipt age in seconds. Set to 0 to skip freshness.
    #[arg(long, default_value_t = 3600)]
    pub max_age_secs: u64,

    /// Evidence bucket override. If absent, Stage 5 discovers it from SSM.
    #[arg(long)]
    pub evidence_bucket: Option<String>,

    /// S3 bucket containing the encrypted model object. Defaults to
    /// --evidence-bucket / stack bucket for the AWS-native PoC.
    #[arg(long)]
    pub model_bucket: Option<String>,
}

impl Args {
    pub fn parse_strict() -> Result<Self, CliError> {
        Ok(Self::parse())
    }
}

#[derive(Debug)]
pub enum CliError {}

impl fmt::Display for CliError {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        unreachable!("CliError has no variants")
    }
}

impl std::error::Error for CliError {}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_builds() {
        Args::command().debug_assert();
    }
}
