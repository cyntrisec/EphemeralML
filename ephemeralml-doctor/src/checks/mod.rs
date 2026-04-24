//! Check trait + registry + result type.
//!
//! The 6 checks from the spec are registered in `Registry::default()` in the
//! fail-fast order the spec pins. A caller that passed `--check <name>` runs
//! exactly that one check; otherwise all 6 run in order.
//!
//! Each check is an independent implementation of `Check`. Checks are `Send +
//! Sync` and async. No check shares mutable state with another check — the
//! only cross-check state is `Context`, which is read-only.

use crate::context::Context;
use async_trait::async_trait;
use serde_json::Value;
use std::time::Instant;

mod allocator;
mod bucket;
mod clock;
mod eif;
mod kms;
mod role;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Fail,
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub duration_ms: u64,
    pub summary: String,
    pub details: Value,
    pub check_code: Option<String>,
    pub remediation: Option<String>,
}

impl CheckResult {
    pub fn is_ok(&self) -> bool {
        matches!(self.status, CheckStatus::Ok)
    }
}

#[async_trait]
pub trait Check: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(&self, ctx: &Context) -> CheckResult;
}

pub struct Registry {
    checks: Vec<Box<dyn Check>>,
}

impl Default for Registry {
    fn default() -> Self {
        // Order matters: fail-fast per spec (allocator first — if the host
        // isn't Nitro-capable, every downstream check is meaningless).
        Self {
            checks: vec![
                Box::new(allocator::Allocator::default()),
                Box::new(eif::Eif::default()),
                Box::new(role::Role),
                Box::new(bucket::Bucket),
                Box::new(kms::Kms),
                Box::new(clock::Clock),
            ],
        }
    }
}

impl Registry {
    /// Run all registered checks (or a single named one).
    pub async fn run(&self, ctx: &Context, only: Option<&str>) -> Vec<CheckResult> {
        let mut out = Vec::with_capacity(self.checks.len());
        for c in &self.checks {
            if let Some(name) = only {
                if c.name() != name {
                    continue;
                }
            }
            let start = Instant::now();
            let mut result = c.run(ctx).await;
            result.duration_ms = start.elapsed().as_millis() as u64;
            out.push(result);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_runs_6_checks_by_default() {
        let ctx = Context {
            doctor_version: "0.0.0-test",
            timestamp: chrono::Utc::now(),
            stack_name: "cyntrisec-pilot".into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let reg = Registry::default();
        let results = reg.run(&ctx, None).await;
        assert_eq!(results.len(), 6, "spec requires exactly 6 checks");

        let names: Vec<&str> = results.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["allocator", "eif", "role", "bucket", "kms", "clock"],
            "check order must match spec's fail-fast sequence"
        );
    }

    #[tokio::test]
    async fn registry_runs_single_named_check() {
        let ctx = Context {
            doctor_version: "0.0.0-test",
            timestamp: chrono::Utc::now(),
            stack_name: "cyntrisec-pilot".into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let reg = Registry::default();
        let results = reg.run(&ctx, Some("clock")).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "clock");
    }

    #[tokio::test]
    async fn no_check_still_reports_skeleton_unimplemented() {
        // Regression guard: once all 6 checks were promoted to real probes,
        // the SKELETON_UNIMPLEMENTED code was retired. A future check added
        // as a placeholder must NOT reuse that sentinel — it should carry
        // its own specific check_code.
        let ctx = Context {
            doctor_version: "0.0.0-test",
            timestamp: chrono::Utc::now(),
            stack_name: "cyntrisec-pilot".into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        };
        let reg = Registry::default();
        let results = reg.run(&ctx, None).await;
        for r in &results {
            assert_ne!(
                r.check_code.as_deref(),
                Some("SKELETON_UNIMPLEMENTED"),
                "check {} should not report SKELETON_UNIMPLEMENTED — that code is retired",
                r.name
            );
        }
    }
}
