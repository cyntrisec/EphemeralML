//! Background reconnect loop with exponential backoff + jitter.
//!
//! Spawns a tokio task per backend that monitors connectivity and re-establishes
//! the secure channel when disconnected. Request handlers signal disconnection
//! via `Notify` for instant wakeup instead of waiting for the health interval.
//!
//! While connected, the loop performs a TCP liveness probe every
//! `health_interval`. If the probe fails, it marks the backend disconnected
//! and begins reconnect attempts immediately.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};

use ephemeral_ml_client::{SecureClient, SecureEnclaveClient};

/// Default timeout for TCP liveness probes and connect attempts.
/// Used by both the background reconnect loop and request-path
/// `ensure_connected()` to bound how long the client mutex is held.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration for a single reconnect loop.
pub struct ReconnectHandle {
    pub backend_name: String,
    pub backend_addr: String,
    pub backoff_base_ms: u64,
    pub backoff_cap_ms: u64,
    pub health_interval: Duration,
}

/// Spawn a background reconnect loop for one backend.
///
/// The task runs until the tokio runtime shuts down. When connected, it
/// performs a TCP liveness probe every `health_interval` and marks the backend
/// disconnected if the probe fails. When disconnected, it attempts to
/// reconnect with exponential backoff + full jitter. All lock-holding
/// operations (establish_channel) are bounded by `CONNECT_TIMEOUT` to avoid
/// blocking request handlers.
pub fn spawn_reconnect_loop(
    handle: ReconnectHandle,
    client: Arc<Mutex<SecureEnclaveClient>>,
    connected: Arc<AtomicBool>,
    notify: Arc<Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut rng = StdRng::from_entropy();
        let mut attempt: u32 = 0;

        loop {
            if connected.load(Ordering::Acquire) {
                // Connected — wait for health interval or until notified of disconnect.
                attempt = 0;
                tokio::select! {
                    _ = tokio::time::sleep(handle.health_interval) => {}
                    _ = notify.notified() => {}
                }

                // Re-check after wakeup.
                if !connected.load(Ordering::Acquire) {
                    tracing::info!(
                        backend = %handle.backend_name,
                        "Disconnect detected via notify, starting reconnect"
                    );
                    // Fall through to reconnect below.
                } else {
                    // Timer fired — perform active TCP liveness probe.
                    let probe_ok = tcp_probe(&handle.backend_addr, CONNECT_TIMEOUT).await;
                    if probe_ok {
                        continue; // Still healthy, loop back to sleep.
                    }
                    // Probe failed — mark disconnected.
                    connected.store(false, Ordering::Release);
                    tracing::warn!(
                        backend = %handle.backend_name,
                        "Health probe failed, marking disconnected"
                    );
                    // Fall through to reconnect below.
                }
            }

            // Disconnected — try to reconnect.
            attempt = attempt.saturating_add(1);

            let reconnected = {
                // Acquire lock with a timeout to avoid indefinitely blocking
                // request handlers that also need this mutex.
                let lock_result = tokio::time::timeout(CONNECT_TIMEOUT, client.lock()).await;
                let mut c = match lock_result {
                    Ok(guard) => guard,
                    Err(_) => {
                        tracing::warn!(
                            backend = %handle.backend_name,
                            attempt,
                            "Reconnect skipped: timed out acquiring client lock"
                        );
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                // Double-check: another task (e.g. ensure_connected) may have
                // reconnected while we waited for the lock.
                if connected.load(Ordering::Acquire) {
                    continue;
                }

                // Bound the establish_channel call so a hanging TCP connect
                // doesn't hold the mutex indefinitely.
                tokio::time::timeout(CONNECT_TIMEOUT, c.establish_channel(&handle.backend_addr))
                    .await
            };

            match reconnected {
                Ok(Ok(())) => {
                    connected.store(true, Ordering::Release);
                    tracing::info!(
                        backend = %handle.backend_name,
                        attempt,
                        "Background reconnect succeeded"
                    );
                    attempt = 0;
                }
                Ok(Err(e)) => {
                    let delay = compute_backoff(
                        attempt,
                        handle.backoff_base_ms,
                        handle.backoff_cap_ms,
                        &mut rng,
                    );
                    tracing::warn!(
                        backend = %handle.backend_name,
                        attempt,
                        delay_ms = delay.as_millis() as u64,
                        error = %e,
                        "Background reconnect failed, backing off"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(_) => {
                    let delay = compute_backoff(
                        attempt,
                        handle.backoff_base_ms,
                        handle.backoff_cap_ms,
                        &mut rng,
                    );
                    tracing::warn!(
                        backend = %handle.backend_name,
                        attempt,
                        delay_ms = delay.as_millis() as u64,
                        "Background reconnect timed out, backing off"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    })
}

/// TCP liveness probe — attempts a connect + immediate close.
///
/// Returns `true` if the backend port is reachable. This does not test the
/// secure channel itself, but catches the common case of a dead/restarted
/// backend process.
async fn tcp_probe(addr: &str, timeout: Duration) -> bool {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => true, // connect succeeded; drop closes the socket
        _ => false,              // timeout or connect error
    }
}

/// Exponential backoff with full jitter.
///
/// Returns a duration in `[0, min(base * 2^(attempt-1), cap)]`.
/// Same algorithm as `host/src/retry.rs` — duplicated to avoid cross-crate dep.
pub fn compute_backoff(
    attempt: u32,
    base_ms: u64,
    cap_ms: u64,
    rng: &mut impl RngCore,
) -> Duration {
    let exp = attempt.saturating_sub(1);
    let shift = exp.min(16);
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let ms = base_ms.saturating_mul(factor);
    let capped = ms.min(cap_ms);

    let jittered = if capped == 0 {
        0
    } else {
        rng.next_u64() % (capped + 1)
    };
    Duration::from_millis(jittered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_bounded_by_cap() {
        use rand::{rngs::StdRng, SeedableRng};
        let mut rng = StdRng::from_seed([0u8; 32]);
        let cap_ms = 30_000u64;
        for attempt in 1..=20 {
            let d = compute_backoff(attempt, 100, cap_ms, &mut rng);
            assert!(d.as_millis() <= cap_ms as u128, "attempt {attempt}: {d:?}");
        }
    }

    #[test]
    fn backoff_attempt_1_bounded_by_base() {
        use rand::{rngs::StdRng, SeedableRng};
        let mut rng = StdRng::from_seed([1u8; 32]);
        // attempt=1 → exp=0 → factor=1 → capped = min(100, 30000) = 100
        for _ in 0..100 {
            let d = compute_backoff(1, 100, 30_000, &mut rng);
            assert!(d.as_millis() <= 100);
        }
    }

    #[test]
    fn backoff_zero_cap_returns_zero() {
        use rand::{rngs::StdRng, SeedableRng};
        let mut rng = StdRng::from_seed([2u8; 32]);
        let d = compute_backoff(5, 100, 0, &mut rng);
        assert_eq!(d.as_millis(), 0);
    }

    #[test]
    fn backoff_large_attempt_saturates() {
        use rand::{rngs::StdRng, SeedableRng};
        let mut rng = StdRng::from_seed([3u8; 32]);
        let d = compute_backoff(100, 100, 30_000, &mut rng);
        assert!(d.as_millis() <= 30_000);
    }

    #[tokio::test]
    async fn tcp_probe_fails_on_unbound_port() {
        // Port 1 is almost certainly not listening.
        let result = tcp_probe("127.0.0.1:1", Duration::from_millis(200)).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn tcp_probe_times_out_on_unreachable() {
        // Non-routable address — should timeout, not hang.
        let result = tcp_probe("192.0.2.1:1", Duration::from_millis(200)).await;
        assert!(!result);
    }
}
