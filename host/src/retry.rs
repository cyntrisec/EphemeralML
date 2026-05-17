use std::time::Duration;

/// Retry/backoff policy for upstream calls (e.g., AWS KMS).
///
/// v1 defaults are conservative and oriented toward predictable tail latency.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub backoff_base: Duration,
    pub backoff_cap: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            // 1 initial + 2 retries
            max_attempts: 3,
            backoff_base: Duration::from_millis(20),
            backoff_cap: Duration::from_millis(200),
        }
    }
}

impl RetryPolicy {
    pub fn compute_backoff(&self, attempt: u32, rng: &mut impl rand::RngCore) -> Duration {
        ephemeral_ml_common::compute_full_jitter_backoff(
            attempt,
            self.backoff_base.as_millis() as u64,
            self.backoff_cap.as_millis() as u64,
            rng,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded() {
        let p = RetryPolicy::default();
        use rand::{rngs::StdRng, SeedableRng};
        let mut rng = StdRng::from_seed([0u8; 32]);
        for attempt in 1..=10 {
            let b = p.compute_backoff(attempt, &mut rng);
            assert!(b <= p.backoff_cap);
        }
    }
}
