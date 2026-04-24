//! Stage 5 — evidence bundle upload to customer's S3.
//!
//! Real probe: build the 9-file bundle in `/tmp/cyntrisec-smoke-{uuid}/`,
//! compute `SHA256SUMS`, upload every file to
//! `s3://{evidence-bucket}/smoke-tests/{iso-timestamp-utc}/` with
//! `--sse aws:kms` (enforced by bucket policy `DenyUnencryptedObjectUploads`).
//! Sequential PUT (8 files under 2 MiB each; no need for parallel).
//!
//! On any PUT failure: `failed_stage: s3_write`; preserve the on-host bundle;
//! print the local path for post-mortem.
//!
//! Skipped when `--no-upload` is set (CI mode per spec).
//!
//! Skeleton: returns `SKELETON_UNIMPLEMENTED`.

use super::{Stage, StageResult};
use crate::cli::Args;
use crate::context::Context;
use async_trait::async_trait;

pub struct S3Write;

#[async_trait]
impl Stage for S3Write {
    fn name(&self) -> &'static str {
        "s3_write"
    }

    async fn run(&self, _ctx: &Context, _args: &Args) -> StageResult {
        StageResult::skeleton_unimplemented("s3_write")
    }
}
