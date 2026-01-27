use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Minimal in-process counters for v1 operability.
///
/// We keep it intentionally simple (no external exporter yet):
/// - useful for structured logs and later wiring to Prometheus/CloudWatch.
#[derive(Clone, Debug, Default)]
pub struct Metrics {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    pub kms_requests_total: AtomicU64,
    pub kms_success_total: AtomicU64,
    pub kms_errors_total: AtomicU64,

    pub retries_total: AtomicU64,
    pub throttled_total: AtomicU64,
    pub timeouts_total: AtomicU64,
    pub rate_limited_total: AtomicU64,
    pub circuit_wait_total: AtomicU64,
}

impl Metrics {
    pub fn inc_requests(&self) {
        self.inner.kms_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_success(&self) {
        self.inner.kms_success_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_error(&self) {
        self.inner.kms_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_retry(&self) {
        self.inner.retries_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_throttled(&self) {
        self.inner.throttled_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_timeout(&self) {
        self.inner.timeouts_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rate_limited(&self) {
        self.inner.rate_limited_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_circuit_wait(&self) {
        self.inner.circuit_wait_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            kms_requests_total: self.inner.kms_requests_total.load(Ordering::Relaxed),
            kms_success_total: self.inner.kms_success_total.load(Ordering::Relaxed),
            kms_errors_total: self.inner.kms_errors_total.load(Ordering::Relaxed),
            retries_total: self.inner.retries_total.load(Ordering::Relaxed),
            throttled_total: self.inner.throttled_total.load(Ordering::Relaxed),
            timeouts_total: self.inner.timeouts_total.load(Ordering::Relaxed),
            rate_limited_total: self.inner.rate_limited_total.load(Ordering::Relaxed),
            circuit_wait_total: self.inner.circuit_wait_total.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub kms_requests_total: u64,
    pub kms_success_total: u64,
    pub kms_errors_total: u64,
    pub retries_total: u64,
    pub throttled_total: u64,
    pub timeouts_total: u64,
    pub rate_limited_total: u64,
    pub circuit_wait_total: u64,
}
