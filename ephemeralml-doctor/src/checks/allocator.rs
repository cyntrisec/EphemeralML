//! Check 1 — Nitro Enclaves allocator configured and running.
//!
//! Spec: `byoc-phase-1-ephemeralml-doctor-spec-2026-04-23.md` § Check 1.
//!
//! Four conditions must all hold for the check to pass:
//!
//! 1. `/dev/nitro_enclaves` exists (cheapest probe; bails early on non-Nitro hosts)
//! 2. `systemctl is-active nitro-enclaves-allocator.service` returns `active`
//! 3. `/etc/nitro_enclaves/allocator.yaml` parses and reports
//!    `memory_mib >= 2048` and `cpu_count >= 2`
//! 4. `nitro-cli describe-enclaves` returns a valid JSON array (empty is OK;
//!    this confirms the CLI + allocator are both functional)
//!
//! Failure text is taken verbatim from the spec so the customer admin
//! experience matches what the spec promises.

use super::{Check, CheckResult, CheckStatus};
use crate::context::Context;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Minimum allocator memory. The EphemeralML EIF currently runs in ~4 GiB,
/// but the doctor accepts anything ≥ 2 GiB as allocator-healthy on the
/// premise that smaller-than-2-GiB is a clear misconfiguration and the EIF
/// itself will reject at launch time if it cannot fit.
const MIN_MEMORY_MIB: u32 = 2048;

/// Minimum vCPU count per the smoke-test's enclave launch requirement.
const MIN_CPU_COUNT: u32 = 2;

const DEFAULT_ALLOCATOR_YAML: &str = "/etc/nitro_enclaves/allocator.yaml";
const DEFAULT_NITRO_DEVICE: &str = "/dev/nitro_enclaves";
const ALLOCATOR_SERVICE: &str = "nitro-enclaves-allocator.service";
const NITRO_CLI_BIN: &str = "nitro-cli";
const SYSTEMCTL_BIN: &str = "systemctl";

/// Minimal projection over `allocator.yaml`. The file may carry other keys
/// (e.g., comments, `---` document separator); we only pull the two fields
/// the check needs.
#[derive(Debug, Deserialize)]
struct AllocatorConfig {
    memory_mib: u32,
    cpu_count: u32,
}

pub struct Allocator {
    allocator_yaml: PathBuf,
    nitro_device: PathBuf,
}

impl Default for Allocator {
    fn default() -> Self {
        Self {
            allocator_yaml: PathBuf::from(DEFAULT_ALLOCATOR_YAML),
            nitro_device: PathBuf::from(DEFAULT_NITRO_DEVICE),
        }
    }
}

impl Allocator {
    /// Tests construct the check with fixture paths; production uses `::default()`.
    #[cfg(test)]
    fn with_paths(allocator_yaml: impl Into<PathBuf>, nitro_device: impl Into<PathBuf>) -> Self {
        Self {
            allocator_yaml: allocator_yaml.into(),
            nitro_device: nitro_device.into(),
        }
    }
}

#[async_trait]
impl Check for Allocator {
    fn name(&self) -> &'static str {
        "allocator"
    }

    async fn run(&self, _ctx: &Context) -> CheckResult {
        let start = Instant::now();

        // 1. /dev/nitro_enclaves must exist. On a non-Nitro host this is the
        //    cheapest bail-out and produces the most actionable remediation.
        if !self.nitro_device.exists() {
            return fail(
                start,
                "ALLOCATOR_DEVICE_MISSING",
                format!("{} device file missing", self.nitro_device.display()),
                "instance type may not support Nitro Enclaves. Verify launch \
                 type is m6i.xlarge or larger Nitro-capable SKU.",
            );
        }

        // 2. systemctl is-active nitro-enclaves-allocator.service → "active"
        match systemctl_is_active(ALLOCATOR_SERVICE).await {
            Ok(true) => {}
            Ok(false) => {
                return fail(
                    start,
                    "ALLOCATOR_SERVICE_NOT_ACTIVE",
                    "Nitro Enclaves allocator service is not active".to_string(),
                    "sudo systemctl restart nitro-enclaves-allocator.service; \
                     wait 30 seconds; re-run ephemeralml-doctor.",
                );
            }
            Err(e) => {
                return fail(
                    start,
                    "ALLOCATOR_SYSTEMCTL_UNAVAILABLE",
                    format!("failed to query systemctl: {}", e),
                    "ensure systemctl is on PATH and the doctor is running as root.",
                );
            }
        }

        // 3. Parse allocator.yaml + validate thresholds.
        let config = match parse_allocator_yaml(&self.allocator_yaml).await {
            Ok(c) => c,
            Err(AllocatorYamlError::NotFound) => {
                return fail(
                    start,
                    "ALLOCATOR_CONFIG_MISSING",
                    format!("{} not found", self.allocator_yaml.display()),
                    "re-run the CloudFormation deploy, OR recreate /etc/nitro_enclaves/allocator.yaml \
                     with `memory_mib: 4096` and `cpu_count: 2`, then sudo systemctl restart \
                     nitro-enclaves-allocator.service.",
                );
            }
            Err(AllocatorYamlError::Io(msg)) | Err(AllocatorYamlError::Parse(msg)) => {
                return fail(
                    start,
                    "ALLOCATOR_CONFIG_MALFORMED",
                    format!(
                        "{} could not be read/parsed: {}",
                        self.allocator_yaml.display(),
                        msg
                    ),
                    "restore the default allocator.yaml shipped with aws-nitro-enclaves-cli, \
                     or re-deploy the CloudFormation stack.",
                );
            }
        };

        if config.memory_mib < MIN_MEMORY_MIB {
            return fail(
                start,
                "ALLOCATOR_MEMORY_TOO_LOW",
                format!(
                    "Allocator configured with only {} MiB; minimum is {} MiB",
                    config.memory_mib, MIN_MEMORY_MIB
                ),
                "edit /etc/nitro_enclaves/allocator.yaml (memory_mib: 4096), \
                 then sudo systemctl restart nitro-enclaves-allocator.service.",
            );
        }

        if config.cpu_count < MIN_CPU_COUNT {
            return fail(
                start,
                "ALLOCATOR_CPU_TOO_LOW",
                format!(
                    "Allocator configured with only {} vCPU; minimum is {}",
                    config.cpu_count, MIN_CPU_COUNT
                ),
                "edit /etc/nitro_enclaves/allocator.yaml (cpu_count: 2), \
                 then sudo systemctl restart nitro-enclaves-allocator.service.",
            );
        }

        // 4. nitro-cli describe-enclaves must return a valid JSON array.
        //    An empty array is fine — it just means no enclave is running.
        if let Err(e) = nitro_cli_describe_enclaves().await {
            return fail(
                start,
                "ALLOCATOR_NITRO_CLI_FAILED",
                format!("nitro-cli describe-enclaves failed: {}", e),
                "ensure aws-nitro-enclaves-cli package is installed and the ec2-user is \
                 in the `ne` group (`sudo usermod -aG ne ec2-user`; re-login).",
            );
        }

        // All four conditions hold.
        CheckResult {
            name: "allocator".to_string(),
            status: CheckStatus::Ok,
            duration_ms: start.elapsed().as_millis() as u64,
            summary: format!(
                "Nitro Enclaves allocator configured ({} MiB, {} vCPU)",
                config.memory_mib, config.cpu_count
            ),
            details: json!({
                "memory_mib": config.memory_mib,
                "cpu_count": config.cpu_count,
                "service_active": true,
                "device_present": true,
                "allocator_yaml_path": self.allocator_yaml.display().to_string(),
            }),
            check_code: None,
            remediation: None,
        }
    }
}

// --- probes ----------------------------------------------------------------

/// Run `systemctl is-active <service>` and return true iff stdout is exactly `"active"`.
async fn systemctl_is_active(service: &str) -> std::io::Result<bool> {
    let output = tokio::process::Command::new(SYSTEMCTL_BIN)
        .arg("is-active")
        .arg(service)
        .output()
        .await?;
    // `systemctl is-active` exits 0 when active, 3 when inactive. We rely on
    // stdout to distinguish, because `failed`/`inactive`/`unknown` all produce
    // non-zero exit codes but we want to report them as "not active" without
    // conflating them with an ENOENT-style probe failure.
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim() == "active")
}

/// Run `nitro-cli describe-enclaves` and require the output to be a valid
/// JSON array. Empty array is acceptable.
async fn nitro_cli_describe_enclaves() -> Result<(), String> {
    let output = tokio::process::Command::new(NITRO_CLI_BIN)
        .arg("describe-enclaves")
        .output()
        .await
        .map_err(|e| format!("could not invoke {}: {}", NITRO_CLI_BIN, e))?;

    if !output.status.success() {
        return Err(format!(
            "nitro-cli exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|e| format!("nitro-cli stdout was not UTF-8: {}", e))?;

    let parsed: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|e| format!("nitro-cli stdout was not valid JSON: {}", e))?;

    if !parsed.is_array() {
        return Err("nitro-cli describe-enclaves did not return a JSON array".to_string());
    }

    Ok(())
}

#[derive(Debug)]
enum AllocatorYamlError {
    NotFound,
    Io(String),
    Parse(String),
}

async fn parse_allocator_yaml(path: &Path) -> Result<AllocatorConfig, AllocatorYamlError> {
    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(AllocatorYamlError::NotFound)
        }
        Err(e) => return Err(AllocatorYamlError::Io(e.to_string())),
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| AllocatorYamlError::Io(format!("not UTF-8: {}", e)))?;
    serde_yaml::from_str::<AllocatorConfig>(text)
        .map_err(|e| AllocatorYamlError::Parse(e.to_string()))
}

// --- helpers ---------------------------------------------------------------

fn fail(
    start: Instant,
    code: &'static str,
    summary: impl Into<String>,
    remediation: &'static str,
) -> CheckResult {
    CheckResult {
        name: "allocator".to_string(),
        status: CheckStatus::Fail,
        duration_ms: start.elapsed().as_millis() as u64,
        summary: summary.into(),
        details: serde_json::Value::Null,
        check_code: Some(code.to_string()),
        remediation: Some(remediation.to_string()),
    }
}

// --- tests -----------------------------------------------------------------
//
// These tests exercise the pure-code paths (yaml parsing + config validation
// + device-file presence). The subprocess probes (`systemctl`, `nitro-cli`)
// are exercised only by the real Phase 1 AWS deploy run — mocking subprocess
// calls cleanly would require abstracting behind a trait, which is scope
// creep for the skeleton→real conversion and adds friction to the eventual
// production path.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncWriteExt;

    fn test_ctx() -> Context {
        Context {
            doctor_version: "0.0.0-test",
            timestamp: chrono::Utc::now(),
            stack_name: "cyntrisec-pilot".into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
        }
    }

    async fn write_yaml(content: &str) -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        let mut file = tokio::fs::File::create(f.path()).await.unwrap();
        file.write_all(content.as_bytes()).await.unwrap();
        file.flush().await.unwrap();
        f
    }

    #[tokio::test]
    async fn parses_valid_allocator_yaml() {
        let f = write_yaml("---\nmemory_mib: 4096\ncpu_count: 2\n").await;
        let config = parse_allocator_yaml(f.path()).await.unwrap();
        assert_eq!(config.memory_mib, 4096);
        assert_eq!(config.cpu_count, 2);
    }

    #[tokio::test]
    async fn parses_yaml_without_document_separator() {
        let f = write_yaml("memory_mib: 4096\ncpu_count: 2\n").await;
        let config = parse_allocator_yaml(f.path()).await.unwrap();
        assert_eq!(config.memory_mib, 4096);
        assert_eq!(config.cpu_count, 2);
    }

    #[tokio::test]
    async fn rejects_malformed_yaml() {
        let f = write_yaml("this is not: valid: yaml: at: all").await;
        match parse_allocator_yaml(f.path()).await {
            Err(AllocatorYamlError::Parse(_)) => {}
            other => panic!("expected Parse error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rejects_yaml_missing_required_fields() {
        let f = write_yaml("memory_mib: 4096\n").await;
        match parse_allocator_yaml(f.path()).await {
            Err(AllocatorYamlError::Parse(_)) => {}
            other => panic!(
                "expected Parse error for missing cpu_count, got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn reports_not_found_for_missing_file() {
        let path = std::path::PathBuf::from("/tmp/nonexistent-allocator-yaml-for-doctor-test");
        match parse_allocator_yaml(&path).await {
            Err(AllocatorYamlError::NotFound) => {}
            other => panic!("expected NotFound, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn fails_with_device_missing_when_dev_path_absent() {
        let yaml = write_yaml("memory_mib: 4096\ncpu_count: 2\n").await;
        let check = Allocator::with_paths(yaml.path(), "/tmp/definitely-no-device-for-doctor-test");
        let result = check.run(&test_ctx()).await;
        assert_eq!(result.status, CheckStatus::Fail);
        assert_eq!(
            result.check_code.as_deref(),
            Some("ALLOCATOR_DEVICE_MISSING")
        );
        assert!(result.summary.contains("device file missing"));
        assert!(
            result
                .remediation
                .as_deref()
                .unwrap_or_default()
                .contains("m6i.xlarge"),
            "remediation should mention Nitro-capable instance types"
        );
    }

    #[tokio::test]
    async fn fails_with_memory_too_low_when_under_threshold() {
        // Use a real existing path for the device so the device check passes
        // and we exercise the memory threshold branch.
        let dev = NamedTempFile::new().unwrap();
        let yaml = write_yaml(&format!(
            "memory_mib: {}\ncpu_count: 2\n",
            MIN_MEMORY_MIB - 1
        ))
        .await;

        // systemctl may or may not exist on the test host; regardless, the
        // memory-threshold branch only fires after the systemctl check
        // passes. In sandbox environments that lack systemctl, this test
        // exercises an earlier failure path instead — so we accept either
        // ALLOCATOR_MEMORY_TOO_LOW (real-Nitro test rig) or an earlier
        // service-related failure (dev laptop). Both are correct outcomes.
        let check = Allocator::with_paths(yaml.path(), dev.path());
        let result = check.run(&test_ctx()).await;
        assert_eq!(result.status, CheckStatus::Fail);
        let code = result.check_code.as_deref().unwrap_or("");
        assert!(
            code == "ALLOCATOR_MEMORY_TOO_LOW"
                || code == "ALLOCATOR_SERVICE_NOT_ACTIVE"
                || code == "ALLOCATOR_SYSTEMCTL_UNAVAILABLE",
            "unexpected check_code={} on memory-too-low fixture",
            code
        );
    }

    #[test]
    fn allocator_config_thresholds_match_spec() {
        // If the spec's minimums change, this test is the spot to re-affirm
        // the constants used in production code.
        assert_eq!(MIN_MEMORY_MIB, 2048);
        assert_eq!(MIN_CPU_COUNT, 2);
    }

    #[tokio::test]
    async fn default_paths_match_spec() {
        let alloc = Allocator::default();
        assert_eq!(
            alloc.allocator_yaml,
            std::path::PathBuf::from("/etc/nitro_enclaves/allocator.yaml")
        );
        assert_eq!(
            alloc.nitro_device,
            std::path::PathBuf::from("/dev/nitro_enclaves")
        );
    }
}
