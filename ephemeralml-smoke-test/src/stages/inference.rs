//! Stage 3 — inference with the fixed synthetic fixture.
//!
//! Fixture (pinned by spec):
//! - Input: `context::CANONICAL_INPUT` — deterministic 97-byte UTF-8 string
//! - Model: MiniLM-L6-v2 (public, baked into the EIF)
//! - Output: 384 float32 embedding values (individual floats NOT compared due
//!   to model nondeterminism tolerance, but output hash is captured)
//!
//! Real probe: open VSock to `<EnclaveCID>:5005` (port pinned in enclave
//! contract), send a single framed request with the fixed input, receive
//! `{embedding: [f32; 384], air_receipt: Vec<u8>}`, verify the input SHA-256
//! echoed in the response matches what was sent.
//!
//! Skeleton: returns `SKELETON_UNIMPLEMENTED`.

use super::{Stage, StageResult};
use crate::cli::Args;
use crate::context::Context;
use async_trait::async_trait;

pub struct Inference;

#[async_trait]
impl Stage for Inference {
    fn name(&self) -> &'static str {
        "inference"
    }

    async fn run(&self, _ctx: &Context, _args: &Args) -> StageResult {
        StageResult::skeleton_unimplemented("inference")
    }
}
