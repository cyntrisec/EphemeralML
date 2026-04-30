//! Check 2 — EphemeralML EIF present and cosign-signed.
//!
//! Spec: `byoc-phase-1-ephemeralml-doctor-spec-2026-04-23.md` § Check 2 +
//! `byoc-phase-1-supply-chain-posture-spec-2026-04-23.md` § 4.2.
//!
//! Probes, in order:
//! 1. `/opt/cyntrisec/eif/ephemeralml-pilot.eif` exists with size ≥ 1 MiB.
//!    A real EIF is ~100–200 MiB; the 1 MiB floor is a sanity guard that
//!    catches half-written / empty files cheaply before the expensive
//!    cryptographic verify runs.
//! 2. `*.cosign.bundle` exists alongside it.
//! 3. `cosign verify-blob --key <embedded-pub> --bundle <bundle> <eif>`
//!    exits 0. The public key is baked into the doctor binary at build
//!    time via `include_bytes!`, so an attacker with host root cannot swap
//!    `/opt/cyntrisec/etc/cyntrisec-release.pub` out from under the check.
//! 4. Best-effort PCR0 extraction via `nitro-cli describe-eif`. Reporting
//!    PCR0 in the check details is useful for the smoke-test to compare
//!    against the receipt's `enclave_measurements` claim later. If
//!    nitro-cli is unavailable we still pass — PCR0 is observational,
//!    not a gating condition.

use super::{Check, CheckResult, CheckStatus};
use crate::context::Context;
use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Instant;

/// Cyntrisec release public key embedded at build time.
///
/// Current value: the dev-only key at `deploy/release/cyntrisec-release-dev-v1.pub`.
/// Production swap: when Day 8 `release-signing-bootstrap.yaml` is deployed,
/// replace the `include_bytes!` target with the KMS-extracted production key
/// and delete the dev key from the repo per `deploy/release/README.md`.
const RELEASE_PUBKEY_PEM: &[u8] =
    include_bytes!("../../../deploy/release/cyntrisec-release-dev-v1.pub");

/// Canonical EIF file path on the pilot host.
const DEFAULT_EIF_PATH: &str = "/opt/cyntrisec/eif/ephemeralml-pilot.eif";

/// Minimum reasonable EIF size. Real Phase 1 EIF is 100+ MiB; 1 MiB catches
/// empty/partial writes without hard-coding an exact expected size.
const DEFAULT_MIN_SIZE_BYTES: u64 = 1024 * 1024;

const COSIGN_BIN: &str = "cosign";
const NITRO_CLI_BIN: &str = "nitro-cli";

pub struct Eif {
    eif_path: PathBuf,
    min_size_bytes: u64,
}

impl Default for Eif {
    fn default() -> Self {
        Self {
            eif_path: PathBuf::from(DEFAULT_EIF_PATH),
            min_size_bytes: DEFAULT_MIN_SIZE_BYTES,
        }
    }
}

impl Eif {
    #[cfg(test)]
    fn with_paths(eif_path: impl Into<PathBuf>, min_size_bytes: u64) -> Self {
        Self {
            eif_path: eif_path.into(),
            min_size_bytes,
        }
    }

    fn bundle_path(&self) -> PathBuf {
        let mut p = self.eif_path.clone();
        let new_name = format!(
            "{}.cosign.bundle",
            p.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("ephemeralml-pilot.eif")
        );
        p.set_file_name(new_name);
        p
    }
}

#[async_trait]
impl Check for Eif {
    fn name(&self) -> &'static str {
        "eif"
    }

    async fn run(&self, _ctx: &Context) -> CheckResult {
        let start = Instant::now();

        // 1. EIF file exists, readable, size >= min.
        let eif_metadata = match tokio::fs::metadata(&self.eif_path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return fail(
                    start,
                    "EIF_NOT_FOUND",
                    format!("EIF image not found at {}", self.eif_path.display()),
                    "sudo /opt/cyntrisec/bin/cyntrisec-installer --refresh-eif \
                     (re-fetches the cosign-signed image from the Cyntrisec release bucket).",
                );
            }
            Err(e) => {
                return fail(
                    start,
                    "EIF_STAT_FAILED",
                    format!("stat on {} failed: {}", self.eif_path.display(), e),
                    "verify file permissions on /opt/cyntrisec/eif/ — doctor runs as root; \
                     if stat fails as root the filesystem is likely degraded.",
                );
            }
        };
        let size_bytes = eif_metadata.len();
        if size_bytes < self.min_size_bytes {
            return fail(
                start,
                "EIF_TOO_SMALL",
                format!(
                    "EIF at {} is only {} bytes; minimum is {} bytes",
                    self.eif_path.display(),
                    size_bytes,
                    self.min_size_bytes
                ),
                "the EIF on disk is smaller than a real Phase 1 image — likely a partial \
                 download. Re-run the installer's --refresh-eif path.",
            );
        }

        // 2. Bundle file alongside EIF.
        let bundle_path = self.bundle_path();
        if !matches!(tokio::fs::try_exists(&bundle_path).await, Ok(true)) {
            if allow_unsigned_internal_poc() {
                return pass_unsigned_internal_poc(start, &self.eif_path, size_bytes, &bundle_path)
                    .await;
            }
            return fail(
                start,
                "EIF_BUNDLE_MISSING",
                format!("Cosign bundle not found at {}", bundle_path.display()),
                "the installer should place <eif>.cosign.bundle alongside the EIF. \
                 Re-run the installer's --refresh-eif path.",
            );
        }

        // 3. cosign verify-blob — KEY + BUNDLE path (fully offline; Rekor
        //    inclusion proof is embedded in the bundle).
        let pubkey_path = match write_embedded_pubkey().await {
            Ok(p) => p,
            Err(e) => {
                return fail(
                    start,
                    "EIF_TEMP_KEY_WRITE_FAILED",
                    format!("could not stage embedded release key: {}", e),
                    "/tmp may be read-only or full; the doctor writes a short-lived \
                     copy of the embedded cosign public key there for the cosign CLI.",
                );
            }
        };

        let cosign_result = run_cosign_verify(&pubkey_path, &bundle_path, &self.eif_path).await;
        let _ = tokio::fs::remove_file(&pubkey_path).await;

        if let Err(e) = cosign_result {
            let (code, remediation) = match e {
                CosignError::BinaryMissing => (
                    "EIF_COSIGN_BINARY_MISSING",
                    "cosign 2.x is not installed on PATH. Amazon Linux 2023 pilot hosts \
                     install it via user-data; if missing, install manually from \
                     https://github.com/sigstore/cosign/releases and place in /usr/local/bin.",
                ),
                CosignError::VerificationFailed(_) => (
                    "EIF_COSIGN_VERIFY_FAILED",
                    "the EIF's cosign bundle did not verify against the embedded \
                     Cyntrisec release public key. The EIF may have been tampered with \
                     in transit OR the doctor binary's embedded key is stale. Contact \
                     Cyntrisec support with the doctor --verbose output.",
                ),
                CosignError::SubprocessError(_) => (
                    "EIF_COSIGN_PROBE_FAILED",
                    "cosign was invocable but returned a non-verification error. \
                     Re-run with --verbose and share with Cyntrisec support.",
                ),
            };
            return fail(start, code, e.to_string(), remediation);
        }

        // 4. Best-effort PCR0 extraction. Missing nitro-cli or a parse
        //    failure is not a gate; it just means we can't print the PCR0
        //    in the check details. Real gate on PCR0 lives in the smoke
        //    test (it compares the EIF PCR0 to the receipt's
        //    enclave_measurements claim).
        let pcr0 = extract_pcr0(&self.eif_path).await.ok();

        CheckResult {
            name: "eif".to_string(),
            status: CheckStatus::Ok,
            duration_ms: start.elapsed().as_millis() as u64,
            summary: match pcr0.as_deref() {
                Some(p) => format!(
                    "EIF image present and cosign-signed (PCR0: {})",
                    truncate_hex(p, 16)
                ),
                None => "EIF image present and cosign-signed".to_string(),
            },
            details: json!({
                "eif_path": self.eif_path.display().to_string(),
                "size_bytes": size_bytes,
                "bundle_path": bundle_path.display().to_string(),
                "cosign_verified": true,
                "pcr0": pcr0,
            }),
            check_code: None,
            remediation: None,
        }
    }
}

// --- probes ----------------------------------------------------------------

fn allow_unsigned_internal_poc() -> bool {
    std::env::var("CYNTRISEC_DOCTOR_ALLOW_UNSIGNED_EIF_FOR_POC")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

async fn pass_unsigned_internal_poc(
    start: Instant,
    eif_path: &std::path::Path,
    size_bytes: u64,
    bundle_path: &std::path::Path,
) -> CheckResult {
    let pcr0 = extract_pcr0(eif_path).await.ok();
    CheckResult {
        name: "eif".to_string(),
        status: CheckStatus::Ok,
        duration_ms: start.elapsed().as_millis() as u64,
        summary: match pcr0.as_deref() {
            Some(p) => format!(
                "EIF image present; cosign bundle skipped for internal PoC only (PCR0: {})",
                truncate_hex(p, 16)
            ),
            None => "EIF image present; cosign bundle skipped for internal PoC only".to_string(),
        },
        details: json!({
            "eif_path": eif_path.display().to_string(),
            "size_bytes": size_bytes,
            "bundle_path": bundle_path.display().to_string(),
            "cosign_verified": false,
            "unsigned_internal_poc": true,
            "pcr0": pcr0,
        }),
        check_code: None,
        remediation: None,
    }
}

async fn write_embedded_pubkey() -> std::io::Result<PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "cyntrisec-doctor-release-pubkey-{}.pem",
        std::process::id()
    ));
    tokio::fs::write(&path, RELEASE_PUBKEY_PEM).await?;
    Ok(path)
}

#[derive(Debug)]
enum CosignError {
    BinaryMissing,
    VerificationFailed(String),
    SubprocessError(String),
}

impl std::fmt::Display for CosignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BinaryMissing => f.write_str("cosign binary not found on PATH"),
            Self::VerificationFailed(msg) => {
                write!(f, "cosign verify-blob failed: {}", msg.trim())
            }
            Self::SubprocessError(msg) => {
                write!(f, "cosign subprocess error: {}", msg.trim())
            }
        }
    }
}

async fn run_cosign_verify(
    pubkey_path: &std::path::Path,
    bundle_path: &std::path::Path,
    eif_path: &std::path::Path,
) -> Result<(), CosignError> {
    let output = match tokio::process::Command::new(COSIGN_BIN)
        .arg("verify-blob")
        .arg("--key")
        .arg(pubkey_path)
        .arg("--bundle")
        .arg(bundle_path)
        .arg(eif_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CosignError::BinaryMissing);
        }
        Err(e) => return Err(CosignError::SubprocessError(e.to_string())),
    };

    if output.status.success() {
        // cosign writes "Verified OK" to stderr on success; we don't care,
        // status code is authoritative.
        return Ok(());
    }

    // Non-zero exit. Distinguish true verification failure (bad sig / wrong
    // key) from other subprocess failures (bundle malformed, etc.) by stderr
    // content — but either way we bubble up to the caller.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("signature verification failed") || stderr.contains("invalid signature") {
        Err(CosignError::VerificationFailed(stderr.into_owned()))
    } else if stderr.contains("no such file")
        || stderr.contains("error reading")
        || stderr.contains("bundle")
        || stderr.contains("Rekor public keys")
        || stderr.contains("cached local store")
        || stderr.contains("read-only file system")
    {
        // I/O / malformed bundle — not a sig mismatch.
        Err(CosignError::SubprocessError(stderr.into_owned()))
    } else {
        // Default to sig failure classification when uncertain, since a
        // non-zero exit from cosign verify-blob without a clearer signal
        // is most commonly a bad signature.
        Err(CosignError::VerificationFailed(stderr.into_owned()))
    }
}

/// Parse PCR0 from `nitro-cli describe-eif --eif-path <p>` JSON output.
///
/// Returns Ok(pcr0_hex) on success. Returns Err on any failure (binary
/// missing, parse error, unexpected JSON shape); callers treat this as
/// observational, not a gate.
async fn extract_pcr0(eif_path: &std::path::Path) -> Result<String, String> {
    let output = tokio::process::Command::new(NITRO_CLI_BIN)
        .arg("describe-eif")
        .arg("--eif-path")
        .arg(eif_path)
        .output()
        .await
        .map_err(|e| format!("nitro-cli invoke failed: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "nitro-cli describe-eif exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|e| format!("nitro-cli stdout was not UTF-8: {}", e))?;
    let parsed: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|e| format!("nitro-cli stdout was not valid JSON: {}", e))?;

    parsed
        .get("Measurements")
        .and_then(|m| m.get("PCR0"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "nitro-cli JSON did not carry Measurements.PCR0".to_string())
}

// --- helpers ---------------------------------------------------------------

fn fail(
    start: Instant,
    code: &'static str,
    summary: impl Into<String>,
    remediation: &'static str,
) -> CheckResult {
    CheckResult {
        name: "eif".to_string(),
        status: CheckStatus::Fail,
        duration_ms: start.elapsed().as_millis() as u64,
        summary: summary.into(),
        details: serde_json::Value::Null,
        check_code: Some(code.to_string()),
        remediation: Some(remediation.to_string()),
    }
}

fn truncate_hex(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}...", &s[..n])
    }
}

// --- tests -----------------------------------------------------------------
//
// The probes combine filesystem I/O, a subprocess (cosign), and an optional
// subprocess (nitro-cli). Testing strategy:
//
//   - Pure helpers (bundle_path, truncate_hex, extract_pcr0 JSON parse) are
//     unit-tested directly.
//   - Integration test: use the committed test fixture (a synthetic blob
//     signed with the dev cosign key) + a scratch directory to exercise
//     the end-to-end EIF → cosign path. Requires `cosign` on PATH; skipped
//     (as a pass) if cosign isn't installed locally — that path already
//     has its own regression test below.
//   - Off-EC2 regression test: run the full check on a sandbox host and
//     verify it produces a specific `EIF_*` code (never SKELETON, never
//     panic). Since the default EIF path doesn't exist on dev laptops,
//     the expected code is EIF_NOT_FOUND.

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn test_ctx() -> Context {
        Context {
            doctor_version: "0.0.0-test",
            timestamp: chrono::Utc::now(),
            stack_name: "cyntrisec-pilot".into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        }
    }

    fn fixtures_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/eif")
    }

    #[test]
    fn bundle_path_derives_correctly() {
        let eif = Eif {
            eif_path: PathBuf::from("/opt/cyntrisec/eif/ephemeralml-pilot.eif"),
            min_size_bytes: 1,
        };
        assert_eq!(
            eif.bundle_path(),
            PathBuf::from("/opt/cyntrisec/eif/ephemeralml-pilot.eif.cosign.bundle")
        );
    }

    #[test]
    fn bundle_path_handles_arbitrary_filename() {
        let eif = Eif {
            eif_path: PathBuf::from("/tmp/some-other-name.eif"),
            min_size_bytes: 1,
        };
        assert_eq!(
            eif.bundle_path(),
            PathBuf::from("/tmp/some-other-name.eif.cosign.bundle")
        );
    }

    #[test]
    fn truncate_hex_pads_short_inputs_unchanged() {
        assert_eq!(truncate_hex("abc", 16), "abc");
    }

    #[test]
    fn truncate_hex_shortens_long_inputs_with_ellipsis() {
        let long = "abcdef0123456789abcdef0123456789";
        assert_eq!(truncate_hex(long, 16), "abcdef0123456789...");
    }

    #[test]
    fn embedded_pubkey_is_pem_ec_public_key() {
        // Sanity: the `include_bytes!` reference points at a real PEM
        // public key. If someone accidentally commits a private key or
        // a key in a different format, this test catches it at build.
        let pem = std::str::from_utf8(RELEASE_PUBKEY_PEM).expect("pubkey is UTF-8");
        assert!(
            pem.starts_with("-----BEGIN PUBLIC KEY-----"),
            "embedded key is not a PEM public key: {}",
            pem
        );
        assert!(
            pem.contains("-----END PUBLIC KEY-----"),
            "embedded key is missing END PUBLIC KEY footer"
        );
        // Sanity for EC key size — ECDSA P-256 public keys in PEM are
        // ~178 bytes. Reject accidental RSA keys (≥270 bytes) to keep
        // the embedded-key size consistent with the spec.
        assert!(
            RELEASE_PUBKEY_PEM.len() < 250,
            "embedded key is {} bytes; expected EC P-256 (~178)",
            RELEASE_PUBKEY_PEM.len()
        );
    }

    #[test]
    fn min_size_default_matches_spec() {
        assert_eq!(DEFAULT_MIN_SIZE_BYTES, 1024 * 1024);
    }

    #[tokio::test]
    async fn fails_with_not_found_when_eif_absent() {
        let tmp = std::env::temp_dir().join("cyntrisec-doctor-test-no-such-eif.eif");
        let _ = tokio::fs::remove_file(&tmp).await;
        let check = Eif::with_paths(&tmp, DEFAULT_MIN_SIZE_BYTES);
        let r = check.run(&test_ctx()).await;
        assert_eq!(r.status, CheckStatus::Fail);
        assert_eq!(r.check_code.as_deref(), Some("EIF_NOT_FOUND"));
    }

    #[tokio::test]
    async fn fails_with_too_small_when_eif_under_threshold() {
        // Write a 100-byte file; check with 1 KiB threshold → fails with
        // EIF_TOO_SMALL rather than proceeding to bundle/cosign.
        let f = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(f.path(), vec![0u8; 100]).await.unwrap();
        let check = Eif::with_paths(f.path().to_path_buf(), 1024);
        let r = check.run(&test_ctx()).await;
        assert_eq!(r.status, CheckStatus::Fail);
        assert_eq!(r.check_code.as_deref(), Some("EIF_TOO_SMALL"));
    }

    #[tokio::test]
    async fn fails_with_bundle_missing_when_sidecar_absent() {
        // Write an 8 KiB file with NO bundle alongside → fails with
        // EIF_BUNDLE_MISSING rather than invoking cosign.
        let f = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(f.path(), vec![0u8; 8192]).await.unwrap();
        let check = Eif::with_paths(f.path().to_path_buf(), 1024);
        let r = check.run(&test_ctx()).await;
        assert_eq!(r.status, CheckStatus::Fail);
        assert_eq!(r.check_code.as_deref(), Some("EIF_BUNDLE_MISSING"));
    }

    /// End-to-end happy-path test against the committed fixture. Requires
    /// `cosign` on PATH; if missing, the check returns EIF_COSIGN_BINARY_MISSING
    /// which we also accept as a valid outcome (fixture integrity is not the
    /// local dev's responsibility).
    #[tokio::test]
    async fn verifies_committed_fixture_end_to_end() {
        let eif = fixtures_dir().join("ephemeralml-pilot.eif");
        if !eif.exists() {
            panic!(
                "test fixture missing at {}; regenerate with cosign sign-blob",
                eif.display()
            );
        }

        let check = Eif::with_paths(eif.clone(), 1024);
        let r = check.run(&test_ctx()).await;

        if r.is_ok() {
            // cosign on PATH + fixture intact + embedded pubkey matches
            // fixture key → full end-to-end pass.
            let details = r.details.as_object().unwrap();
            assert_eq!(details["cosign_verified"], serde_json::json!(true));
            assert!(details["size_bytes"].as_u64().unwrap() >= 1024);
        } else {
            // Acceptable fallback states: cosign binary missing, or cosign is
            // present but unusable in a sandboxed local environment (for
            // example, Sigstore's TUF cache cannot be written). Anything else
            // is a fixture / wiring regression.
            let code = r.check_code.as_deref().unwrap_or("");
            if code == "EIF_COSIGN_BINARY_MISSING" {
                return;
            }
            if code == "EIF_COSIGN_PROBE_FAILED"
                && (r.summary.contains("Rekor public keys")
                    || r.summary.contains("cached local store")
                    || r.summary.contains("read-only file system"))
            {
                return;
            }
            panic!(
                "fixture wiring broken: got {} summary=\"{}\"",
                code, r.summary
            );
        }
    }

    #[tokio::test]
    async fn run_off_host_fails_cleanly_not_panics() {
        // The default EIF path doesn't exist in sandboxes; ensure the check
        // produces a specific EIF_* code rather than SKELETON or a panic.
        let r = Eif::default().run(&test_ctx()).await;
        if r.status == CheckStatus::Fail {
            let code = r.check_code.as_deref().unwrap_or("");
            assert_ne!(code, "SKELETON_UNIMPLEMENTED", "eif is now a real probe");
            assert!(
                code.starts_with("EIF_"),
                "unexpected eif check_code off-host: {}",
                code
            );
        }
    }
}
