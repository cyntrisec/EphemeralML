//! Typed errors for `ephemeralml-smoke-test`.
//!
//! Per-stage failures land in `StageResult` with a specific `failed_stage`
//! value and check_code; they produce exit 1 via the framework. This enum
//! captures errors that prevent the framework itself from running a stage:
//! exit 2 (CLI), 3 (infrastructure-unreachable), 4 (internal bug).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SmokeTestError {
    #[expect(
        dead_code,
        reason = "reserved for the exit-3 infrastructure-unreachable contract; stage-level infra failures are currently represented as StageResult failures"
    )]
    #[error("infrastructure unreachable: {0}")]
    InfrastructureUnreachable(String),

    #[error("internal error: {0}")]
    Internal(String),
}
