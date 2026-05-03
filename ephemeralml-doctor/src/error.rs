//! Typed errors for `ephemeralml-doctor`.
//!
//! User-facing check failures do NOT propagate as `DoctorError`; they land in
//! `CheckResult` with a specific `check_code` + remediation string. This enum
//! captures the narrower set of errors that abort the binary before or across
//! checks: CLI usage errors (exit 2), infrastructure-unreachable states that
//! prevent any check from running (exit 3), and genuine unexpected failures
//! (exit 4). Per spec exit-code contract.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DoctorError {
    /// IMDSv2 unreachable, AWS APIs unreachable, `/dev/nitro_enclaves` absent
    /// — states where the doctor cannot meaningfully evaluate the host. Maps
    /// to exit code 3.
    #[error("infrastructure unreachable: {0}")]
    InfrastructureUnreachable(String),

    /// Unexpected internal error (panic translation, unhandled I/O). Maps to
    /// exit code 4 and indicates a doctor bug, not an environment problem.
    #[error("internal error: {0}")]
    Internal(String),
}
