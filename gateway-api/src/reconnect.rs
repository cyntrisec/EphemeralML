//! Background reconnect loop with exponential backoff + jitter.
//!
//! Spawns a tokio task per backend that monitors connectivity and re-establishes
//! the secure channel when disconnected. Request handlers signal disconnection
//! via `Notify` for instant wakeup instead of waiting for the health interval.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use tokio::sync::{Mutex, Notify};

use ephemeral_ml_client::{SecureClient, SecureEnclaveClient};

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
/// The task runs until the tokio runtime shuts down. When connected, it sleeps
/// for `health_interval` or until woken by `notify`. When disconnected, it
/// attempts to reconnect with exponential backoff + full jitter.
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

                // Re-check after wakeup; if still connected, loop back to sleep.
                if connected.load(Ordering::Acquire) {
                    continue;
                }

                tracing::info!(
                    backend = %handle.backend_name,
                    "Disconnect detected, starting reconnect"
                );
            }

            // Disconnected — try to reconnect.
            attempt = attempt.saturating_add(1);

            let reconnected = {
                let mut c = client.lock().await;
                // Double-check: another task (e.g. ensure_connected) may have
                // reconnected while we waited for the lock.
                if connected.load(Ordering::Acquire) {
                    continue;
                }
                c.establish_channel(&handle.backend_addr).await
            };

            match reconnected {
                Ok(()) => {
                    connected.store(true, Ordering::Release);
                    tracing::info!(
                        backend = %handle.backend_name,
                        attempt,
                        "Background reconnect succeeded"
                    );
                    attempt = 0;
                }
                Err(e) => {
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
            }
        }
    })
}

/// Exponential backoff with full jitter.
///
/// Returns a duration in `[0, min(base * 2^(attempt-1), cap)]`.
/// Same algorithm as `host/src/retry.rs` — duplicated to avoid cross-crate dep.
pub fn compute_backoff(attempt: u32, base_ms: u64, cap_ms: u64, rng: &mut impl RngCore) -> Duration {
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
}
