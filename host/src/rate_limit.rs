use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// Token-bucket rate limiter (async, coarse).
///
/// Good enough for v1 protection against KMS throttling.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    inner: Arc<Mutex<State>>,
    cfg: Config,
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub rps: f64,
    pub burst: f64,
}

impl Default for Config {
    fn default() -> Self {
        // v1 defaults (tunable)
        Self { rps: 200.0, burst: 400.0 }
    }
}

#[derive(Debug)]
struct State {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(cfg: Config) -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                tokens: cfg.burst,
                last: Instant::now(),
            })),
            cfg,
        }
    }

    /// Wait until at least `cost` tokens are available, then consume them.
    pub async fn acquire(&self, cost: f64) {
        loop {
            let mut st = self.inner.lock().await;
            let now = Instant::now();
            let elapsed = now.duration_since(st.last);
            st.last = now;

            let refill = self.cfg.rps * elapsed.as_secs_f64();
            st.tokens = (st.tokens + refill).min(self.cfg.burst);

            if st.tokens >= cost {
                st.tokens -= cost;
                return;
            }

            // Need more tokens; compute sleep time and release lock.
            let deficit = cost - st.tokens;
            let secs = deficit / self.cfg.rps;
            drop(st);

            // Clamp small sleeps to avoid busy loops.
            let sleep_for = Duration::from_secs_f64(secs).max(Duration::from_millis(1));
            tokio::time::sleep(sleep_for).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn limiter_allows_burst_then_throttles() {
        let rl = RateLimiter::new(Config { rps: 10.0, burst: 2.0 });

        let t0 = Instant::now();
        rl.acquire(1.0).await;
        rl.acquire(1.0).await;
        // Third should wait ~100ms
        rl.acquire(1.0).await;
        assert!(t0.elapsed() >= Duration::from_millis(80));
    }
}
