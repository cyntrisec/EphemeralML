use ephemeral_ml_host::{
    circuit_breaker::{CircuitBreaker, Config as CircuitConfig},
    rate_limit::{Config as RateLimitConfig, RateLimiter},
    retry::RetryPolicy,
};
use std::time::Duration;
use tokio::time::Instant;

#[tokio::test]
async fn degradation_rate_limiter_throttles() {
    let rl = RateLimiter::new(RateLimitConfig { rps: 5.0, burst: 1.0 });

    assert!(!rl.acquire(1.0).await);
    let t0 = Instant::now();
    assert!(rl.acquire(1.0).await);
    assert!(t0.elapsed() >= Duration::from_millis(150));
}

#[tokio::test]
async fn degradation_circuit_breaker_opens() {
    let cb = CircuitBreaker::new(CircuitConfig {
        window: Duration::from_secs(60),
        open_cooldown: Duration::from_millis(80),
        min_requests: 5,
        open_error_rate: 0.6,
    });

    for _ in 0..5 {
        cb.before_request().await;
        cb.record_result(false).await;
    }

    let t0 = Instant::now();
    cb.before_request().await;
    assert!(t0.elapsed() >= Duration::from_millis(60));
}

#[test]
fn degradation_retry_policy_caps_backoff() {
    let p = RetryPolicy::default();
    assert_eq!(p.max_attempts, 3);
    assert_eq!(p.backoff_base, Duration::from_millis(20));
    assert_eq!(p.backoff_cap, Duration::from_millis(200));
}
