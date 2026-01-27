use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::{sleep, Instant};

#[derive(Clone, Debug)]
pub struct CircuitBreaker {
    inner: Arc<Mutex<State>>,
    cfg: Config,
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub window: Duration,
    pub open_cooldown: Duration,
    pub min_requests: u32,
    pub open_error_rate: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(10),
            open_cooldown: Duration::from_secs(5),
            min_requests: 50,
            open_error_rate: 0.20,
        }
    }
}

#[derive(Debug)]
struct State {
    // open until this time (if Some)
    open_until: Option<Instant>,

    // rolling counters for current window
    window_start: Instant,
    req: u32,
    err: u32,
}

impl CircuitBreaker {
    pub fn new(cfg: Config) -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                open_until: None,
                window_start: Instant::now(),
                req: 0,
                err: 0,
            })),
            cfg,
        }
    }

    pub async fn before_request(&self) {
        loop {
            let mut st = self.inner.lock().await;
            let now = Instant::now();

            // reset window if expired
            if now.duration_since(st.window_start) >= self.cfg.window {
                st.window_start = now;
                st.req = 0;
                st.err = 0;
            }

            if let Some(until) = st.open_until {
                if now < until {
                    let sleep_for = until - now;
                    drop(st);
                    sleep(sleep_for).await;
                    continue;
                } else {
                    st.open_until = None;
                }
            }

            st.req = st.req.saturating_add(1);
            return;
        }
    }

    pub async fn record_result(&self, success: bool) {
        let mut st = self.inner.lock().await;
        if !success {
            st.err = st.err.saturating_add(1);
        }

        // Only consider opening when enough data.
        if st.req >= self.cfg.min_requests {
            let rate = (st.err as f64) / (st.req as f64);
            if rate >= self.cfg.open_error_rate {
                st.open_until = Some(Instant::now() + self.cfg.open_cooldown);
                // reset counters so we don't instantly re-open after cooldown
                st.window_start = Instant::now();
                st.req = 0;
                st.err = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn opens_on_error_rate() {
        let cb = CircuitBreaker::new(Config {
            window: Duration::from_secs(60),
            open_cooldown: Duration::from_millis(50),
            min_requests: 5,
            open_error_rate: 0.5,
        });

        for _ in 0..5 {
            cb.before_request().await;
            cb.record_result(false).await;
        }

        let t0 = Instant::now();
        cb.before_request().await; // should wait for cooldown
        assert!(t0.elapsed() >= Duration::from_millis(40));
    }
}
