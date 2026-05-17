//! Small shared helpers used across binaries and API crates.

use rand::RngCore;
use std::time::Duration;

/// Fixed-work byte comparison for bearer/API key checks.
///
/// The loop always visits every byte in `expected`; length differences are
/// folded into the accumulator instead of returning early.
pub fn constant_time_eq(expected: &str, provided: &str) -> bool {
    let expected_bytes = expected.as_bytes();
    let provided_bytes = provided.as_bytes();
    let mut diff = expected_bytes.len() ^ provided_bytes.len();

    for (index, expected_byte) in expected_bytes.iter().enumerate() {
        let provided_byte = provided_bytes.get(index).copied().unwrap_or(0);
        diff |= usize::from(*expected_byte ^ provided_byte);
    }

    diff == 0
}

/// API-key comparison wrapper with a domain-specific name at call sites.
pub fn api_key_matches(expected: &str, provided: &str) -> bool {
    constant_time_eq(expected, provided)
}

/// Exponential backoff with full jitter.
///
/// Returns a duration in `[0, min(base * 2^(attempt-1), cap)]`.
pub fn compute_full_jitter_backoff(
    attempt: u32,
    base_ms: u64,
    cap_ms: u64,
    rng: &mut impl RngCore,
) -> Duration {
    let exp = attempt.saturating_sub(1);
    let shift = exp.min(16);
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let capped = base_ms.saturating_mul(factor).min(cap_ms);

    let jittered = if capped == 0 {
        0
    } else {
        rng.next_u64() % (capped + 1)
    };
    Duration::from_millis(jittered)
}

/// Estimate GPT-style token count using the common chars/4 heuristic.
pub fn estimate_tokens(text: &str) -> u32 {
    if text.is_empty() {
        0
    } else {
        ((text.len() as f64 / 4.0).ceil() as u32).max(1)
    }
}
