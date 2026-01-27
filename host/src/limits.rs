use std::sync::Arc;
use tokio::sync::Semaphore;

/// Simple concurrency limiter for upstream calls (e.g., AWS KMS).
#[derive(Clone, Debug)]
pub struct ConcurrencyLimiter {
    sem: Arc<Semaphore>,
}

impl ConcurrencyLimiter {
    pub fn new(max_in_flight: usize) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(max_in_flight)),
        }
    }

    pub async fn acquire(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.sem.clone().acquire_owned().await.expect("semaphore closed")
    }
}

/// v1 defaults (tunable):
/// - global in-flight cap for upstream KMS calls
pub const DEFAULT_MAX_IN_FLIGHT: usize = 100;
