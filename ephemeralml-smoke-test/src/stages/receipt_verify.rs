//! Stage 4 — in-process AIR v1 receipt verification BEFORE S3 upload.
//!
//! This is the gating stage for bundle persistence: if verification fails,
//! Stage 5 is skipped and the on-host bundle is preserved at
//! `/tmp/cyntrisec-smoke-{uuid}/` for post-mortem, but NOTHING is written to
//! S3. Bad receipts never leave the host.
//!
//! Real probe: parse `air_receipt` bytes as COSE_Sign1 CBOR via `coset`, run
//! the 4-layer AIR v1 verification via `ephemeral_ml_common::receipt_verify::
//! verify_receipt` — the same library code that ships in the production
//! `ephemeralml-verify` CLI.
//!
//! Skeleton: returns `SKELETON_UNIMPLEMENTED`.

use super::{Stage, StageResult};
use crate::cli::Args;
use crate::context::Context;
use async_trait::async_trait;

pub struct ReceiptVerify;

#[async_trait]
impl Stage for ReceiptVerify {
    fn name(&self) -> &'static str {
        "receipt_verify"
    }

    async fn run(&self, _ctx: &Context, _args: &Args) -> StageResult {
        StageResult::skeleton_unimplemented("receipt_verify")
    }
}
