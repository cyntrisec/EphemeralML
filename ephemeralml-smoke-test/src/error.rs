//! Typed errors for `ephemeralml-smoke-test`.
//!
//! Per-stage failures land in `StageResult` with a specific `failed_stage`
//! value and check_code; they produce exit 1 via the framework. This enum
//! captures errors that prevent the framework itself from running a stage:
//! exit 2 (CLI), 3 (infrastructure-unreachable), 4 (internal bug).

use thiserror::Error;

#[allow(dead_code)] // Real Context::bootstrap + stage errors will construct these.
#[derive(Debug, Error)]
pub enum SmokeTestError {
    #[error("infrastructure unreachable: {0}")]
    InfrastructureUnreachable(String),

    #[error("internal error: {0}")]
    Internal(String),
}
