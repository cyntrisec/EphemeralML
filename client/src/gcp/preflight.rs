use anyhow::{bail, Result};
use std::process::Command;

use super::config::GcpConfig;

const MIN_DISK_GB: u64 = 20;

/// Run preflight checks before executing a GCP command.
///
/// Called automatically before deploy, setup, setup-kms, package-model.
/// Fails closed: any failure stops execution with a clear error.
pub fn run_preflight(config: &GcpConfig) -> Result<()> {
    check_disk_space(MIN_DISK_GB)?;
    check_gcloud_auth()?;
    config.require_project()?;
    Ok(())
}

fn check_disk_space(min_gb: u64) -> Result<()> {
    let output = Command::new("df")
        .args(["-BG", "."])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to check disk space (df not available): {}", e))?;
    if !output.status.success() {
        bail!(
            "Disk space check failed: df exited with code {}",
            output.status.code().unwrap_or(-1)
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text
        .lines()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Disk space check failed: could not parse df output"))?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 {
        bail!("Disk space check failed: unexpected df output format");
    }
    let avail_str = fields[3].trim_end_matches('G');
    let avail: u64 = avail_str.parse().map_err(|_| {
        anyhow::anyhow!(
            "Disk space check failed: could not parse '{}' as GB",
            avail_str
        )
    })?;
    if avail < min_gb {
        bail!(
            "Insufficient disk space: {}GB available, need at least {}GB.\n\
             Cleanup hints:\n  \
             - docker system prune -a   (remove unused images/containers)\n  \
             - cargo clean               (remove target/ build artifacts)\n  \
             - rm -rf /tmp/ephemeralml-* (remove temp inference files)",
            avail,
            min_gb
        );
    }
    Ok(())
}

fn check_gcloud_auth() -> Result<()> {
    match Command::new("gcloud")
        .args(["auth", "print-access-token"])
        .output()
    {
        Ok(output) if output.status.success() => Ok(()),
        _ => bail!(
            "gcloud is not authenticated. Run:\n  \
             gcloud auth login\n  \
             gcloud auth application-default login"
        ),
    }
}
