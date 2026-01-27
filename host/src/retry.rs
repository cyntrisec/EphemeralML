use rand::{rngs::ThreadRng, Rng};
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
    pub fn compute_backoff(&self, attempt: u32, rng: &mut ThreadRng) -> Duration {
        // attempt is 1-based. Backoff starts after a failed attempt.
        let exp = attempt.saturating_sub(1);
        let mut ms = self.backoff_base.as_millis() as u64;
        let shift = exp.min(16);
        let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        ms = ms.saturating_mul(factor); // avoid overflow
        let cap_ms = self.backoff_cap.as_millis() as u64;
        let capped = ms.min(cap_ms);

        // Full jitter: random in [0, capped]
        let jittered = rng.gen_range(0..=capped);
        Duration::from_millis(jittered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded() {
        let p = RetryPolicy::default();
        let mut rng = rand::thread_rng();
        for attempt in 1..=10 {
            let b = p.compute_backoff(attempt, &mut rng);
            assert!(b <= p.backoff_cap);
        }
    }
}
