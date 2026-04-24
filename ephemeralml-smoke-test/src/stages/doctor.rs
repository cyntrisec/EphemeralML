//! Stage 1 — doctor preflight.
//!
//! Real probe: invoke `/opt/cyntrisec/bin/ephemeralml-doctor --json` as a
//! subprocess with a 60-second timeout; parse stdout as JSON; require
//! `overall_status == "pass"` and all 6 checks `"ok"`. Failure aborts the
//! smoke test with `failed_stage: doctor` and includes the doctor output
//! verbatim in the evidence bundle's `doctor.json` file.
//!
//! Skeleton: returns `SKELETON_UNIMPLEMENTED`.

use super::{Stage, StageResult};
use crate::cli::Args;
use crate::context::Context;
use async_trait::async_trait;

pub struct Doctor;

#[async_trait]
impl Stage for Doctor {
    fn name(&self) -> &'static str {
        "doctor"
    }

    async fn run(&self, _ctx: &Context, _args: &Args) -> StageResult {
        StageResult::skeleton_unimplemented("doctor")
    }
}
