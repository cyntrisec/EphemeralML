//! Per-IP and global rate limiting with a sliding-window token bucket.
//!
//! Uses `DashMap` for lock-free per-IP tracking. Each IP gets a bucket that
//! refills at `limit` tokens per 60-second window. The global limiter is a
//! single `AtomicU64`-based counter with the same semantics.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Per-IP bucket: tracks remaining tokens and the window start time.
struct IpBucket {
    remaining: AtomicU32,
    window_start: Instant,
}

/// Rate limiter supporting per-IP and global limits.
///
/// A limit of 0 means "disabled" for that dimension.
pub struct RateLimiter {
    per_ip_limit: u32,
    global_limit: u32,
    buckets: DashMap<String, IpBucket>,
    global_remaining: AtomicU32,
    global_window_start: AtomicU64, // epoch millis
    window_duration: Duration,
}

/// Result of a rate limit check.
pub enum RateLimitResult {
    /// Request is allowed.
    Allowed,
    /// Request is denied. `retry_after_secs` indicates when to retry.
    Denied { retry_after_secs: u64 },
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// - `per_ip_limit`: max requests per IP per window (0 = disabled)
    /// - `global_limit`: max requests globally per window (0 = disabled)
    pub fn new(per_ip_limit: u32, global_limit: u32) -> Self {
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            per_ip_limit,
            global_limit,
            buckets: DashMap::new(),
            global_remaining: AtomicU32::new(global_limit),
            global_window_start: AtomicU64::new(now_millis),
            window_duration: Duration::from_secs(60),
        }
    }

    /// Check whether a request from `ip` is allowed.
    pub fn check(&self, ip: &str) -> RateLimitResult {
        let now = Instant::now();
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Check global limit first.
        if self.global_limit > 0 {
            let window_start = self.global_window_start.load(Ordering::Acquire);
            let elapsed_ms = now_millis.saturating_sub(window_start);
            if elapsed_ms >= self.window_duration.as_millis() as u64 {
                // Window expired, reset. Use CAS to avoid races.
                if self
                    .global_window_start
                    .compare_exchange(
                        window_start,
                        now_millis,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    self.global_remaining
                        .store(self.global_limit, Ordering::Release);
                }
            }
            // Try to decrement.
            let prev = self.global_remaining.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |current| {
                    if current > 0 {
                        Some(current - 1)
                    } else {
                        None
                    }
                },
            );
            if prev.is_err() {
                let window_start_val = self.global_window_start.load(Ordering::Acquire);
                let elapsed = now_millis.saturating_sub(window_start_val);
                let remaining_ms =
                    (self.window_duration.as_millis() as u64).saturating_sub(elapsed);
                let retry_after = (remaining_ms / 1000).max(1);
                return RateLimitResult::Denied {
                    retry_after_secs: retry_after,
                };
            }
        }

        // Check per-IP limit.
        if self.per_ip_limit > 0 {
            let mut entry = self
                .buckets
                .entry(ip.to_string())
                .or_insert_with(|| IpBucket {
                    remaining: AtomicU32::new(self.per_ip_limit),
                    window_start: now,
                });

            let bucket = entry.value_mut();
            let elapsed = now.duration_since(bucket.window_start);
            if elapsed >= self.window_duration {
                // Reset window.
                bucket.window_start = now;
                bucket.remaining.store(self.per_ip_limit, Ordering::Release);
            }

            let prev =
                bucket
                    .remaining
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                        if current > 0 {
                            Some(current - 1)
                        } else {
                            None
                        }
                    });
            if prev.is_err() {
                let elapsed_since_start = now.duration_since(bucket.window_start);
                let remaining_ms = self
                    .window_duration
                    .as_millis()
                    .saturating_sub(elapsed_since_start.as_millis());
                let retry_after = ((remaining_ms as u64) / 1000).max(1);
                // Refund the global token we consumed (best-effort).
                if self.global_limit > 0 {
                    self.global_remaining.fetch_add(1, Ordering::Release);
                }
                return RateLimitResult::Denied {
                    retry_after_secs: retry_after,
                };
            }
        }

        // Periodic cleanup of stale IP buckets (every ~100th check).
        // This prevents unbounded memory growth from many unique IPs.
        if self.per_ip_limit > 0 {
            static CLEANUP_COUNTER: AtomicU64 = AtomicU64::new(0);
            let count = CLEANUP_COUNTER.fetch_add(1, Ordering::Relaxed);
            if count % 1000 == 0 {
                self.cleanup_stale(now);
            }
        }

        RateLimitResult::Allowed
    }

    /// Remove IP buckets whose window has expired.
    fn cleanup_stale(&self, now: Instant) {
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.window_start) < self.window_duration * 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_under_limit() {
        let rl = RateLimiter::new(5, 0);
        for _ in 0..5 {
            assert!(matches!(rl.check("1.2.3.4"), RateLimitResult::Allowed));
        }
    }

    #[test]
    fn denies_over_per_ip_limit() {
        let rl = RateLimiter::new(3, 0);
        for _ in 0..3 {
            assert!(matches!(rl.check("1.2.3.4"), RateLimitResult::Allowed));
        }
        assert!(matches!(
            rl.check("1.2.3.4"),
            RateLimitResult::Denied { .. }
        ));
    }

    #[test]
    fn different_ips_have_separate_buckets() {
        let rl = RateLimiter::new(2, 0);
        assert!(matches!(rl.check("1.1.1.1"), RateLimitResult::Allowed));
        assert!(matches!(rl.check("1.1.1.1"), RateLimitResult::Allowed));
        assert!(matches!(
            rl.check("1.1.1.1"),
            RateLimitResult::Denied { .. }
        ));
        // Different IP should still be allowed.
        assert!(matches!(rl.check("2.2.2.2"), RateLimitResult::Allowed));
    }

    #[test]
    fn global_limit_denies_all_ips() {
        let rl = RateLimiter::new(0, 3);
        assert!(matches!(rl.check("1.1.1.1"), RateLimitResult::Allowed));
        assert!(matches!(rl.check("2.2.2.2"), RateLimitResult::Allowed));
        assert!(matches!(rl.check("3.3.3.3"), RateLimitResult::Allowed));
        // Fourth request from any IP should be denied.
        assert!(matches!(
            rl.check("4.4.4.4"),
            RateLimitResult::Denied { .. }
        ));
    }

    #[test]
    fn disabled_limiters_always_allow() {
        let rl = RateLimiter::new(0, 0);
        for _ in 0..1000 {
            assert!(matches!(rl.check("1.2.3.4"), RateLimitResult::Allowed));
        }
    }

    #[test]
    fn retry_after_is_positive() {
        let rl = RateLimiter::new(1, 0);
        assert!(matches!(rl.check("1.1.1.1"), RateLimitResult::Allowed));
        match rl.check("1.1.1.1") {
            RateLimitResult::Denied { retry_after_secs } => {
                assert!(retry_after_secs >= 1);
                assert!(retry_after_secs <= 60);
            }
            _ => panic!("expected Denied"),
        }
    }
}
