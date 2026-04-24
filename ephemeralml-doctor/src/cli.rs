//! CLI argument parsing.
//!
//! Flag contract locked by `byoc-phase-1-ephemeralml-doctor-spec-2026-04-23.md`:
//! `--json`, `--check <name>`, `--verbose`, `--stack-name <name>`, `--help`, `--version`.

use clap::Parser;
use std::fmt;

const VALID_CHECKS: &[&str] = &["allocator", "eif", "role", "bucket", "kms", "clock"];

#[derive(Parser, Debug, Clone)]
#[command(
    name = "ephemeralml-doctor",
    version,
    about = "Phase 1 BYOC preflight check for a deployed Cyntrisec pilot host.",
    long_about = "Runs 6 preflight checks against the local Nitro Enclaves host and its \
                  AWS-side backing resources. Must exit 0 before ephemeralml-smoke-test runs.\n\n\
                  Contract: byoc-phase-1-ephemeralml-doctor-spec-2026-04-23.md"
)]
pub struct Args {
    /// Emit machine-readable JSON instead of human text output.
    #[arg(long)]
    pub json: bool,

    /// Run a single named check: allocator, eif, role, bucket, kms, clock.
    /// Omit to run all 6 in fail-fast order.
    #[arg(long, value_name = "NAME")]
    pub check: Option<String>,

    /// Include raw probe data in output. Partially masks ARNs; never logs
    /// secret values or customer data.
    #[arg(long)]
    pub verbose: bool,

    /// Override the auto-detected CloudFormation stack name (e.g., when the
    /// instance hosts multiple Cyntrisec stacks).
    #[arg(long, value_name = "NAME")]
    pub stack_name: Option<String>,
}

impl Args {
    /// Parse with post-validation of `--check`.
    pub fn parse_strict() -> Result<Self, CliError> {
        let args = Self::parse();
        if let Some(ref name) = args.check {
            if !VALID_CHECKS.contains(&name.as_str()) {
                return Err(CliError::UnknownCheck(name.clone()));
            }
        }
        Ok(args)
    }
}

#[derive(Debug)]
pub enum CliError {
    UnknownCheck(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::UnknownCheck(name) => write!(
                f,
                "[CLI] unknown check: '{}'. Valid names: {}",
                name,
                VALID_CHECKS.join(", ")
            ),
        }
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

    #[test]
    fn valid_check_names_match_spec() {
        for name in VALID_CHECKS {
            assert!(
                !name.is_empty(),
                "check name in VALID_CHECKS is unexpectedly empty"
            );
        }
        assert_eq!(VALID_CHECKS.len(), 6, "spec requires exactly 6 checks");
    }
}
