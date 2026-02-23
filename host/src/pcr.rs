//! PCR (Platform Configuration Register) parsing and validation for Nitro attestation.
//!
//! Extracts expected PCR values from environment variables and validates format.
//! Fail-closed: returns an error if values are malformed, or if no PCRs are set
//! (unless `allow_unpinned` is true).
//!
//! ## Production policy
//!
//! **All three PCRs (0, 1, 2) should always be pinned in production.** Partial
//! pinning (e.g. only PCR0) is accepted by this parser and by `NitroVerifier`,
//! but it weakens attestation: an attacker who replaces the kernel (PCR1) or
//! application (PCR2) without changing the image hash (PCR0) would pass
//! verification. Partial pinning should only be used during debugging or
//! migration (e.g. when rotating the kernel but keeping the same application).

use std::collections::BTreeMap;

/// Parse PCR hex strings into a validated map of PCR index → 48-byte values.
///
/// `pcr_env_values` maps PCR index (0, 1, 2) to the raw env var string (if set).
/// Returns `Err` on malformed hex or wrong length. Returns `Err` if the map is
/// empty and `allow_unpinned` is false.
pub fn parse_expected_pcrs(
    pcr_env_values: &[(usize, Option<String>)],
    allow_unpinned: bool,
) -> Result<BTreeMap<usize, Vec<u8>>, PcrError> {
    let mut expected_pcrs: BTreeMap<usize, Vec<u8>> = BTreeMap::new();

    for (i, maybe_hex) in pcr_env_values {
        if let Some(hex_str) = maybe_hex {
            let bytes = hex::decode(hex_str).map_err(|e| PcrError::InvalidHex {
                pcr: *i,
                source: e.to_string(),
            })?;
            if bytes.len() != 48 {
                return Err(PcrError::WrongLength {
                    pcr: *i,
                    len: bytes.len(),
                });
            }
            expected_pcrs.insert(*i, bytes);
        }
    }

    if expected_pcrs.is_empty() && !allow_unpinned {
        return Err(PcrError::NoPcrsSet);
    }

    Ok(expected_pcrs)
}

/// Convenience: read PCR0/1/2 from environment variables and parse them.
pub fn load_expected_pcrs_from_env(
    allow_unpinned: bool,
) -> Result<BTreeMap<usize, Vec<u8>>, PcrError> {
    let env_values: Vec<(usize, Option<String>)> = (0..3)
        .map(|i| {
            let val = std::env::var(format!("EPHEMERALML_EXPECTED_PCR{}", i)).ok();
            (i, val)
        })
        .collect();
    parse_expected_pcrs(&env_values, allow_unpinned)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcrError {
    /// Hex string could not be decoded.
    InvalidHex { pcr: usize, source: String },
    /// Decoded bytes are not 48 bytes (384 bits).
    WrongLength { pcr: usize, len: usize },
    /// No PCR values set and allow_unpinned is false.
    NoPcrsSet,
}

impl std::fmt::Display for PcrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcrError::InvalidHex { pcr, source } => {
                write!(
                    f,
                    "EPHEMERALML_EXPECTED_PCR{} has invalid hex: {}",
                    pcr, source
                )
            }
            PcrError::WrongLength { pcr, len } => {
                write!(
                    f,
                    "EPHEMERALML_EXPECTED_PCR{} has wrong length: {} bytes (need 48)",
                    pcr, len
                )
            }
            PcrError::NoPcrsSet => {
                write!(
                    f,
                    "PCR pinning required. Set EPHEMERALML_EXPECTED_PCR0/1/2 or use --allow-unpinned."
                )
            }
        }
    }
}

impl std::error::Error for PcrError {}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid 48-byte (96 hex char) PCR value
    fn valid_pcr() -> String {
        "a".repeat(96)
    }

    fn all_three_set() -> Vec<(usize, Option<String>)> {
        vec![
            (0, Some(valid_pcr())),
            (1, Some(valid_pcr())),
            (2, Some(valid_pcr())),
        ]
    }

    #[test]
    fn valid_pcrs_accepted() {
        let result = parse_expected_pcrs(&all_three_set(), false);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map[&0].len(), 48);
        assert_eq!(map[&1].len(), 48);
        assert_eq!(map[&2].len(), 48);
    }

    #[test]
    fn partial_pcrs_accepted() {
        // Only PCR0 set — still valid (at least one pin)
        let input = vec![
            (0, Some(valid_pcr())),
            (1, None),
            (2, None),
        ];
        let result = parse_expected_pcrs(&input, false);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn no_pcrs_rejected_without_allow_unpinned() {
        let input: Vec<(usize, Option<String>)> = vec![
            (0, None),
            (1, None),
            (2, None),
        ];
        let result = parse_expected_pcrs(&input, false);
        assert_eq!(result.unwrap_err(), PcrError::NoPcrsSet);
    }

    #[test]
    fn no_pcrs_accepted_with_allow_unpinned() {
        let input: Vec<(usize, Option<String>)> = vec![
            (0, None),
            (1, None),
            (2, None),
        ];
        let result = parse_expected_pcrs(&input, true);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn invalid_hex_rejected() {
        let input = vec![
            (0, Some("not_valid_hex!@#$".to_string())),
            (1, None),
            (2, None),
        ];
        let result = parse_expected_pcrs(&input, false);
        match result.unwrap_err() {
            PcrError::InvalidHex { pcr, .. } => assert_eq!(pcr, 0),
            other => panic!("Expected InvalidHex, got {:?}", other),
        }
    }

    #[test]
    fn wrong_length_rejected_too_short() {
        // 32 hex chars = 16 bytes (not 48)
        let input = vec![
            (0, Some("ab".repeat(16))),
            (1, None),
            (2, None),
        ];
        let result = parse_expected_pcrs(&input, false);
        assert_eq!(
            result.unwrap_err(),
            PcrError::WrongLength { pcr: 0, len: 16 }
        );
    }

    #[test]
    fn wrong_length_rejected_too_long() {
        // 128 hex chars = 64 bytes (not 48)
        let input = vec![
            (0, Some(valid_pcr())),
            (1, Some("ab".repeat(64))),
            (2, None),
        ];
        let result = parse_expected_pcrs(&input, false);
        assert_eq!(
            result.unwrap_err(),
            PcrError::WrongLength { pcr: 1, len: 64 }
        );
    }

    #[test]
    fn empty_hex_string_rejected() {
        let input = vec![
            (0, Some(String::new())),
            (1, None),
            (2, None),
        ];
        let result = parse_expected_pcrs(&input, false);
        // Empty string decodes to 0 bytes
        assert_eq!(
            result.unwrap_err(),
            PcrError::WrongLength { pcr: 0, len: 0 }
        );
    }

    #[test]
    fn allow_unpinned_does_not_bypass_malformed() {
        // Even with allow_unpinned, a *set* but malformed value is an error
        let input = vec![
            (0, Some("zzzz".to_string())),
            (1, None),
            (2, None),
        ];
        let result = parse_expected_pcrs(&input, true);
        assert!(matches!(result.unwrap_err(), PcrError::InvalidHex { .. }));
    }

    #[test]
    fn error_display_messages() {
        assert!(PcrError::NoPcrsSet.to_string().contains("PCR pinning required"));
        assert!(PcrError::InvalidHex { pcr: 1, source: "odd length".into() }
            .to_string()
            .contains("PCR1"));
        assert!(PcrError::WrongLength { pcr: 2, len: 32 }
            .to_string()
            .contains("32 bytes"));
    }

    // --- Integration-level tests using load_expected_pcrs_from_env ---
    // These manipulate env vars, so they use a mutex to avoid races.

    use std::sync::Mutex;
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn clear_pcr_env() {
        for i in 0..3 {
            std::env::remove_var(format!("EPHEMERALML_EXPECTED_PCR{}", i));
        }
    }

    #[test]
    fn load_from_env_fails_without_pcrs() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_pcr_env();
        let result = load_expected_pcrs_from_env(false);
        assert_eq!(result.unwrap_err(), PcrError::NoPcrsSet);
    }

    #[test]
    fn load_from_env_succeeds_with_allow_unpinned() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_pcr_env();
        let result = load_expected_pcrs_from_env(true);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn load_from_env_succeeds_with_valid_pcrs() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_pcr_env();
        let pcr_hex = valid_pcr();
        std::env::set_var("EPHEMERALML_EXPECTED_PCR0", &pcr_hex);
        std::env::set_var("EPHEMERALML_EXPECTED_PCR1", &pcr_hex);
        std::env::set_var("EPHEMERALML_EXPECTED_PCR2", &pcr_hex);
        let result = load_expected_pcrs_from_env(false);
        clear_pcr_env();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3);
    }

    #[test]
    fn load_from_env_rejects_malformed_pcr() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_pcr_env();
        std::env::set_var("EPHEMERALML_EXPECTED_PCR0", "not-hex");
        let result = load_expected_pcrs_from_env(false);
        clear_pcr_env();
        assert!(matches!(result.unwrap_err(), PcrError::InvalidHex { pcr: 0, .. }));
    }
}
