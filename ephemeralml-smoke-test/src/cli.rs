//! CLI argument parsing.
//!
//! Flag contract locked by `byoc-phase-1-ephemeralml-smoke-test-spec-2026-04-23.md`.

use clap::Parser;
use std::fmt;

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
        unreachable!("CliError has no variants in skeleton")
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
