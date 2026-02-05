use sha2::{Digest, Sha256};

fn parse_proc_status_kb(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        if !line.starts_with(key) {
            return None;
        }
        // Example: "VmHWM:\t  123456 kB"
        let mut parts = line.split_whitespace();
        let _label = parts.next()?;
        let value = parts.next()?;
        value.parse::<u64>().ok()
    })
}

/// Peak resident memory (RSS) in MB.
///
/// Linux exposes this as `VmHWM` (high-water mark for RSS) in `/proc/self/status`.
/// Falls back to current `VmRSS` if `VmHWM` is not available.
pub fn peak_rss_mb() -> f64 {
    peak_rss_mb_with_source().0
}

/// Peak resident memory (RSS) in MB, along with the `/proc/self/status` key used.
pub fn peak_rss_mb_with_source() -> (f64, &'static str) {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return (0.0, "unavailable"),
    };

    if let Some(kb) = parse_proc_status_kb(&status, "VmHWM:") {
        return ((kb as f64) / 1024.0, "VmHWM");
    }
    if let Some(kb) = parse_proc_status_kb(&status, "VmRSS:") {
        return ((kb as f64) / 1024.0, "VmRSS");
    }
    (0.0, "unavailable")
}

/// Peak virtual memory size (VMS) in MB (`VmPeak` in `/proc/self/status`).
pub fn peak_vmsize_mb() -> f64 {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return 0.0,
    };

    let kb = parse_proc_status_kb(&status, "VmPeak:").unwrap_or(0);
    (kb as f64) / 1024.0
}

/// SHA-256 over a float vector's raw little-endian bytes.
pub fn sha256_f32_le(values: &[f32]) -> String {
    let mut hasher = Sha256::new();
    for v in values {
        hasher.update(v.to_le_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Current UTC time as ISO-8601 string (e.g. "2026-02-05T12:34:56Z").
///
/// Uses only `std::time` — no chrono dependency.
pub fn iso8601_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm)
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

/// Nearest-rank percentile for pre-sorted samples.
///
/// This uses the same "index on [0..n-1]" approach as the benchmark binaries:
/// `round(p/100 * (n-1))`, clamped to bounds.
pub fn percentile_nearest(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_status_parsing_kb() {
        let status = "\
Name:\ttest\n\
VmPeak:\t  204800 kB\n\
VmHWM:\t   10240 kB\n\
VmRSS:\t    9000 kB\n";
        assert_eq!(parse_proc_status_kb(status, "VmPeak:"), Some(204800));
        assert_eq!(parse_proc_status_kb(status, "VmHWM:"), Some(10240));
        assert_eq!(parse_proc_status_kb(status, "VmRSS:"), Some(9000));
        assert_eq!(parse_proc_status_kb(status, "Nope:"), None);
    }

    #[test]
    fn sha256_f32_is_stable() {
        let a = [1.0f32, 2.5f32, -3.0f32];
        let b = [1.0f32, 2.5f32, -3.0f32];
        let c = [1.0f32, 2.5f32, -3.0000002f32];
        assert_eq!(sha256_f32_le(&a), sha256_f32_le(&b));
        assert_ne!(sha256_f32_le(&a), sha256_f32_le(&c));
    }

    #[test]
    fn iso8601_now_format() {
        let ts = iso8601_now();
        // Should match "YYYY-MM-DDTHH:MM:SSZ"
        assert_eq!(ts.len(), 20, "unexpected length: {}", ts);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
        assert!(ts.ends_with('Z'));
        // Year should be reasonable (2020+)
        let year: u32 = ts[0..4].parse().unwrap();
        assert!(year >= 2020, "year {} too low", year);
    }

    #[test]
    fn percentile_nearest_rank_behavior() {
        let mut v = vec![1.0, 2.0, 3.0, 4.0];
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(percentile_nearest(&v, 0.0), 1.0);
        assert_eq!(percentile_nearest(&v, 50.0), 3.0);
        assert_eq!(percentile_nearest(&v, 100.0), 4.0);
    }
}
