use crate::{HostProxy, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// A proxy wrapper that intercepts and logs traffic for demonstration purposes
pub struct SpyProxy<T: HostProxy> {
    pub inner: T,
}

impl<T: HostProxy> SpyProxy<T> {
    /// Create a new SpyProxy wrapping an existing HostProxy
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: HostProxy> HostProxy for SpyProxy<T> {
    fn forward_to_enclave(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("spy_intercept.log")
            .expect("Failed to open spy log");

        writeln!(
            file,
            "[{}] Intercepted payload length: {} bytes",
            timestamp,
            payload.len()
        )
        .ok();

        let hex_payload: String = payload.iter().map(|b| format!("{:02x}", b)).collect();
        writeln!(file, "Payload (hex): {}", hex_payload).ok();

        // Optional: search for clear-text strings
        // We look for sequences of printable characters
        let mut clear_text = String::new();
        for &b in payload {
            if b.is_ascii_graphic() || b == b' ' {
                clear_text.push(b as char);
            } else {
                clear_text.push('.');
            }
        }

        writeln!(file, "Potential clear-text: {}", clear_text).ok();
        writeln!(file, "---").ok();

        // Forward to the actual enclave handler
        self.inner.forward_to_enclave(payload)
    }
}
