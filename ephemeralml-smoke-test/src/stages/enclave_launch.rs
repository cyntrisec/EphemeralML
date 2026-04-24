//! Stage 2 — enclave launch.
//!
//! Real probe: re-verify EIF cosign bundle + SLSA provenance (defense-in-depth
//! TOCTOU close vs doctor Check 2 that ran at T0), `nitro-cli run-enclave
//! --eif-path /opt/cyntrisec/eif/ephemeralml-pilot.eif --memory 4096
//! --cpu-count 2 --debug-mode false`, poll `describe-enclaves` until state is
//! RUNNING (timeout 120s), capture EnclaveID + EnclaveCID + PCR0/1/2.
//!
//! Skeleton: returns `SKELETON_UNIMPLEMENTED`.

use super::{Stage, StageResult};
use crate::cli::Args;
use crate::context::Context;
use async_trait::async_trait;

pub struct EnclaveLaunch;

#[async_trait]
impl Stage for EnclaveLaunch {
    fn name(&self) -> &'static str {
        "enclave_launch"
    }

    async fn run(&self, _ctx: &Context, _args: &Args) -> StageResult {
        StageResult::skeleton_unimplemented("enclave_launch")
    }
}
