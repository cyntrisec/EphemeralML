use anyhow::Result;
use std::path::Path;
use std::process::Command;

use ephemeral_ml_common::receipt_verify::CheckStatus;
use ephemeral_ml_common::ui::Ui;

/// Run all doctor checks, returning true if all critical checks pass.
pub fn run_doctor(ui: &mut Ui, project_dir: &Path) -> Result<bool> {
    ui.header("EphemeralML GCP Doctor");
    ui.blank();

    let mut all_ok = true;

    // 1. gcloud installed + version
    let gcloud_ok = check_tool_version(ui, "gcloud", &["--version"], "Google Cloud SDK");
    if !gcloud_ok {
        all_ok = false;
    }

    // 2. gcloud auth active
    let auth_ok = check_gcloud_auth(ui);
    if !auth_ok {
        all_ok = false;
    }

    // 3. docker installed + daemon running
    let docker_ok = check_docker(ui);
    if !docker_ok {
        all_ok = false;
    }

    // 4. cargo / rustc installed
    let cargo_ok = check_tool_version(ui, "cargo", &["--version"], "Cargo");
    if !cargo_ok {
        all_ok = false;
    }

    // 5. Disk space >= 20GB free (Docker images + build artifacts)
    let disk_ok = check_disk_space(ui, 20);
    if !disk_ok {
        all_ok = false;
    }

    // 6. .env.gcp file exists (warn only)
    check_env_file(ui, project_dir);

    // 7. Project ID set
    let project_ok = check_project_set(ui, project_dir);
    if !project_ok {
        // Warn but don't fail — not needed for doctor
        ui.warn("  Project ID not set (needed for deploy/setup commands)");
    }

    ui.blank();
    if all_ok {
        ui.success("--> All critical checks passed");
    } else {
        ui.failure("--> Some checks failed (see above)");
    }
    ui.blank();

    Ok(all_ok)
}

fn check_tool_version(ui: &mut Ui, tool: &str, args: &[&str], label: &str) -> bool {
    match Command::new(tool).args(args).output() {
        Ok(output) if output.status.success() => {
            let ver = String::from_utf8_lossy(&output.stdout);
            let first_line = ver.lines().next().unwrap_or("(unknown version)");
            ui.check(&format!("{} installed", label), &CheckStatus::Pass);
            ui.info(&format!("  {}", first_line.trim()));
            true
        }
        _ => {
            ui.check(&format!("{} installed", label), &CheckStatus::Fail);
            ui.info(&format!("  Install {} and ensure it's in PATH", tool));
            false
        }
    }
}

fn check_gcloud_auth(ui: &mut Ui) -> bool {
    match Command::new("gcloud")
        .args(["auth", "print-access-token"])
        .output()
    {
        Ok(output) if output.status.success() => {
            ui.check("gcloud auth active", &CheckStatus::Pass);
            true
        }
        _ => {
            ui.check("gcloud auth active", &CheckStatus::Fail);
            ui.info("  Run: gcloud auth login && gcloud auth application-default login");
            false
        }
    }
}

fn check_docker(ui: &mut Ui) -> bool {
    // Check docker is installed
    let installed = match Command::new("docker").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let ver = String::from_utf8_lossy(&output.stdout);
            ui.check("Docker installed", &CheckStatus::Pass);
            ui.info(&format!("  {}", ver.trim()));
            true
        }
        _ => {
            ui.check("Docker installed", &CheckStatus::Fail);
            ui.info("  Install Docker: https://docs.docker.com/get-docker/");
            return false;
        }
    };

    // Check daemon is running
    if installed {
        match Command::new("docker").arg("info").output() {
            Ok(output) if output.status.success() => {
                ui.check("Docker daemon running", &CheckStatus::Pass);
                true
            }
            _ => {
                ui.check("Docker daemon running", &CheckStatus::Fail);
                ui.info("  Start Docker daemon: sudo systemctl start docker");
                false
            }
        }
    } else {
        false
    }
}

fn check_disk_space(ui: &mut Ui, min_gb: u64) -> bool {
    // Use df -BG . to get disk space in GB
    match Command::new("df").args(["-BG", "."]).output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            // Parse the "Available" column (4th field of 2nd line)
            if let Some(line) = text.lines().nth(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 4 {
                    let avail_str = fields[3].trim_end_matches('G');
                    if let Ok(avail) = avail_str.parse::<u64>() {
                        if avail >= min_gb {
                            ui.check(&format!("Disk space (>= {}GB)", min_gb), &CheckStatus::Pass);
                            ui.info(&format!("  {}GB available", avail));
                            return true;
                        } else {
                            ui.check(&format!("Disk space (>= {}GB)", min_gb), &CheckStatus::Fail);
                            ui.info(&format!(
                                "  Only {}GB available, need at least {}GB",
                                avail, min_gb
                            ));
                            ui.info("  Cleanup: docker system prune -a, cargo clean, rm -rf /tmp/ephemeralml-*");
                            return false;
                        }
                    }
                }
            }
            ui.check(&format!("Disk space (>= {}GB)", min_gb), &CheckStatus::Pass);
            ui.info("  (could not parse df output, assuming OK)");
            true
        }
        _ => {
            ui.check(&format!("Disk space (>= {}GB)", min_gb), &CheckStatus::Pass);
            ui.info("  (df not available, assuming OK)");
            true
        }
    }
}

fn check_env_file(ui: &mut Ui, project_dir: &Path) {
    let path = project_dir.join(".env.gcp");
    if path.exists() {
        ui.check(".env.gcp file", &CheckStatus::Pass);
    } else {
        ui.check(".env.gcp file", &CheckStatus::Skip);
        ui.info("  Optional: create .env.gcp with EPHEMERALML_GCP_PROJECT=your-project");
    }
}

fn check_project_set(ui: &mut Ui, project_dir: &Path) -> bool {
    // Check env var first
    if let Ok(v) = std::env::var("EPHEMERALML_GCP_PROJECT") {
        if !v.is_empty() {
            ui.check("GCP project ID", &CheckStatus::Pass);
            ui.info(&format!("  {}", v));
            return true;
        }
    }
    // Check .env.gcp file
    let vars = super::config::parse_env_file(&project_dir.join(".env.gcp"));
    if let Some(v) = vars.get("EPHEMERALML_GCP_PROJECT") {
        if !v.is_empty() {
            ui.check("GCP project ID", &CheckStatus::Pass);
            ui.info(&format!("  {} (from .env.gcp)", v));
            return true;
        }
    }
    ui.check("GCP project ID", &CheckStatus::Skip);
    false
}
