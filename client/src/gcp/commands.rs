use anyhow::Result;

use ephemeral_ml_common::ui::Ui;

use super::config::{find_project_dir, update_env_file, GcpConfig, GcpFlags};
use super::doctor::run_doctor;
use super::preflight::run_preflight;
use super::runner::ScriptRunner;

/// Run preflight, but skip (with warning) when dry_run is true.
fn preflight_or_dry_run(ui: &mut Ui, config: &GcpConfig) -> Result<()> {
    if config.dry_run {
        ui.warn("--dry-run: skipping preflight checks (auth, disk, project)");
        return Ok(());
    }
    run_preflight(config)
}

/// Print a "Next:" guidance line after a successful command.
fn next_step(ui: &mut Ui, msg: &str) {
    ui.blank();
    ui.info(&format!("Next: {}", msg));
}

/// Print structured JSON status if --json is set.
fn json_status(config: &GcpConfig, command: &str, success: bool, detail: &str) {
    if config.json {
        let status = if success { "ok" } else { "error" };
        println!(
            r#"{{"command":"gcp {}","status":"{}","detail":"{}"}}"#,
            command,
            status,
            detail.replace('"', "\\\"")
        );
    }
}

/// Run `ephemeralml gcp doctor`.
pub fn cmd_doctor(ui: &mut Ui) -> Result<()> {
    let project_dir = find_project_dir()?;
    let ok = run_doctor(ui, &project_dir)?;
    if ok {
        next_step(ui, "ephemeralml gcp init  (configure GCP project)");
    }
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

/// Run `ephemeralml gcp init`.
pub fn cmd_init(ui: &mut Ui, flags: GcpFlags) -> Result<()> {
    use anyhow::{bail, Context};
    use std::process::{Command, Stdio};

    let project_dir = find_project_dir()?;
    let config = GcpConfig::resolve(&flags, &project_dir)?;

    // init_gcp.sh lives at scripts/init_gcp.sh (not scripts/gcp/)
    let script_path = project_dir.join("scripts").join("init_gcp.sh");
    if !script_path.exists() {
        bail!(
            "Script not found: init_gcp.sh. Expected at {}",
            script_path.display()
        );
    }

    let mut args: Vec<&str> = Vec::new();
    if config.non_interactive {
        args.push("--non-interactive");
    }

    ui.info("Initializing GCP configuration...");
    ui.blank();

    if config.dry_run {
        let args_display = if args.is_empty() {
            String::new()
        } else {
            format!(" {}", args.join(" "))
        };
        println!("[dry-run] bash {}{}", script_path.display(), args_display);
        json_status(&config, "init", true, "dry-run");
        next_step(ui, "ephemeralml gcp setup  (provision GCP infrastructure)");
        return Ok(());
    }

    let mut cmd = Command::new("bash");
    cmd.arg(&script_path);
    cmd.args(&args);
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());
    cmd.current_dir(&project_dir);
    // Pass through all resolved config as env vars so non-interactive mode picks them up
    if !config.project.is_empty() {
        cmd.env("EPHEMERALML_GCP_PROJECT", &config.project);
    }
    if !config.zone.is_empty() {
        cmd.env("EPHEMERALML_GCP_ZONE", &config.zone);
    }
    if !config.region.is_empty() {
        cmd.env("EPHEMERALML_GCP_REGION", &config.region);
    }
    if !config.bucket.is_empty() {
        cmd.env("EPHEMERALML_GCS_BUCKET", &config.bucket);
    }
    if !config.model_source.is_empty() {
        cmd.env("EPHEMERALML_MODEL_SOURCE", &config.model_source);
    }
    if let Some(ref key) = config.kms_key {
        cmd.env("EPHEMERALML_GCP_KMS_KEY", key);
    }
    if let Some(ref aud) = config.wip_audience {
        cmd.env("EPHEMERALML_GCP_WIP_AUDIENCE", aud);
    }

    let status = cmd
        .status()
        .with_context(|| format!("Failed to execute {}", script_path.display()))?;

    if !status.success() {
        let code = status.code().unwrap_or(-1);
        bail!("init_gcp.sh exited with code {}", code);
    }

    json_status(&config, "init", true, "config generated");
    next_step(ui, "ephemeralml gcp setup  (provision GCP infrastructure)");
    Ok(())
}

/// Run `ephemeralml gcp setup`.
pub fn cmd_setup(ui: &mut Ui, flags: GcpFlags) -> Result<()> {
    let project_dir = find_project_dir()?;
    let config = GcpConfig::resolve(&flags, &project_dir)?;
    preflight_or_dry_run(ui, &config)?;

    let runner = ScriptRunner::new(project_dir);
    let mut args: Vec<&str> = Vec::new();
    if !config.project.is_empty() {
        args.push("--project");
        args.push(&config.project);
    }
    let source_ranges_clone;
    if let Some(ref sr) = config.source_ranges {
        source_ranges_clone = sr.clone();
        args.push("--source-ranges");
        args.push(&source_ranges_clone);
    }

    ui.info("Running GCP infrastructure setup...");
    ui.blank();
    let result = runner.run("setup.sh", &args, &config, config.dry_run);
    if result.is_ok() {
        json_status(&config, "setup", true, "infrastructure provisioned");
        next_step(ui, "ephemeralml gcp setup-kms  (configure KMS + WIP)");
    }
    result
}

/// Build positional args for setup_kms.sh: PROJECT REGION [DIGEST|--allow-broad-binding].
///
/// Returns `Err` if neither `--image-digest` nor `--allow-broad-binding` is set.
pub(crate) fn build_setup_kms_args(config: &GcpConfig) -> Result<Vec<String>> {
    use anyhow::bail;

    if !config.allow_broad_binding && config.image_digest.is_none() {
        bail!(
            "setup-kms requires either --image-digest <sha256:DIGEST> or --allow-broad-binding.\n\
             Production: ephemeralml gcp setup-kms --image-digest sha256:abc123...\n\
             Development: ephemeralml gcp setup-kms --allow-broad-binding"
        );
    }

    let mut args: Vec<String> = vec![config.project.clone(), config.region.clone()];
    if config.allow_broad_binding {
        args.push("--allow-broad-binding".to_string());
    } else if let Some(ref digest) = config.image_digest {
        args.push(digest.clone());
    }
    Ok(args)
}

/// Derive KMS output values from config + gcloud project number.
///
/// Returns `(bucket, kms_key, wip_audience)` computed from the same formulas
/// as `setup_kms.sh`. Requires `gcloud` to resolve the project number.
pub(crate) fn derive_kms_outputs(config: &GcpConfig) -> Result<(String, String, String)> {
    use anyhow::{bail, Context};
    use std::process::Command;

    let project = config.require_project()?;
    let region = &config.region;

    let bucket = format!("ephemeralml-models-{}", project);
    let kms_key = format!(
        "projects/{}/locations/{}/keyRings/ephemeralml/cryptoKeys/model-dek",
        project, region
    );

    // Get project number via gcloud
    let output = Command::new("gcloud")
        .args([
            "projects",
            "describe",
            project,
            "--format=value(projectNumber)",
        ])
        .output()
        .context("Failed to run gcloud to resolve project number")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "gcloud projects describe failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }

    let project_number = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if project_number.is_empty() {
        bail!("gcloud returned empty project number for '{}'", project);
    }

    let wip_audience = format!(
        "//iam.googleapis.com/projects/{}/locations/global/workloadIdentityPools/ephemeralml-pool/providers/ephemeralml-tdx",
        project_number
    );

    Ok((bucket, kms_key, wip_audience))
}

/// Persist KMS outputs to `.env.gcp`, idempotently.
///
/// Writes both canonical (`EPHEMERALML_*`) and compatibility alias (`GCP_*`) keys.
fn persist_kms_outputs(
    ui: &mut Ui,
    project_dir: &std::path::Path,
    config: &GcpConfig,
) -> Result<()> {
    let (bucket, kms_key, wip_audience) = derive_kms_outputs(config)?;

    let env_path = project_dir.join(".env.gcp");

    let updates: Vec<(&str, &str)> = vec![
        ("EPHEMERALML_GCS_BUCKET", &bucket),
        ("EPHEMERALML_GCP_KMS_KEY", &kms_key),
        ("EPHEMERALML_GCP_WIP_AUDIENCE", &wip_audience),
        // Compatibility aliases used by scripts
        ("GCP_BUCKET", &bucket),
        ("GCP_KMS_KEY", &kms_key),
        ("GCP_WIP_AUDIENCE", &wip_audience),
    ];

    if config.dry_run {
        ui.info("[dry-run] Would update .env.gcp with:");
        for (key, value) in &updates {
            ui.info(&format!("  export {}=\"{}\"", key, value));
        }
        return Ok(());
    }

    update_env_file(&env_path, &updates)?;

    ui.blank();
    ui.info("KMS outputs persisted to .env.gcp:");
    ui.info(&format!("  EPHEMERALML_GCS_BUCKET={}", bucket));
    ui.info(&format!("  EPHEMERALML_GCP_KMS_KEY={}", kms_key));
    ui.info(&format!("  EPHEMERALML_GCP_WIP_AUDIENCE={}", wip_audience));

    Ok(())
}

/// Run `ephemeralml gcp setup-kms`.
pub fn cmd_setup_kms(ui: &mut Ui, flags: GcpFlags) -> Result<()> {
    let project_dir = find_project_dir()?;
    let config = GcpConfig::resolve(&flags, &project_dir)?;
    preflight_or_dry_run(ui, &config)?;

    let args = build_setup_kms_args(&config)?;

    let runner = ScriptRunner::new(project_dir.clone());
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    ui.info("Setting up Cloud KMS + Workload Identity Pool...");
    if config.verbose {
        ui.info(&format!("  Project: {}", config.project));
        ui.info(&format!("  Region:  {}", config.region));
    }
    ui.blank();
    let result = runner.run("setup_kms.sh", &args_refs, &config, config.dry_run);
    if result.is_ok() {
        // Persist KMS outputs to .env.gcp so downstream commands pick them up
        if let Err(e) = persist_kms_outputs(ui, &project_dir, &config) {
            ui.warn(&format!(
                "Setup succeeded but failed to auto-update .env.gcp: {}",
                e
            ));
            ui.warn("You can manually export the values printed above.");
        }
        json_status(&config, "setup-kms", true, "KMS and WIP configured");
        next_step(
            ui,
            "ephemeralml gcp package-model  (encrypt, sign, upload model)",
        );
    }
    result
}

/// Run `ephemeralml gcp package-model`.
pub fn cmd_package_model(ui: &mut Ui, flags: GcpFlags) -> Result<()> {
    let project_dir = find_project_dir()?;
    let config = GcpConfig::resolve(&flags, &project_dir)?;
    preflight_or_dry_run(ui, &config)?;

    let runner = ScriptRunner::new(project_dir);

    // package_model.sh takes: <model_dir> <gcs_prefix> [--model-id ID] [--version VER] [--format FMT] [--dry-run]
    let model_dir = config.model_dir.as_deref().unwrap_or("test_assets/minilm");
    let mut args: Vec<String> = vec![model_dir.to_string(), config.model_prefix.clone()];
    if let Some(ref id) = config.model_id {
        args.push("--model-id".to_string());
        args.push(id.clone());
    }
    if let Some(ref ver) = config.model_version {
        args.push("--version".to_string());
        args.push(ver.clone());
    }
    args.push("--format".to_string());
    args.push(config.model_format.clone());
    if config.dry_run {
        args.push("--dry-run".to_string());
    }
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    ui.info("Packaging model (encrypt, sign, upload)...");
    ui.blank();
    let result = runner.run("package_model.sh", &args_refs, &config, false);
    if result.is_ok() {
        json_status(&config, "package-model", true, "model packaged");
        next_step(
            ui,
            "ephemeralml gcp deploy  (launch Confidential Space CVM)",
        );
    }
    result
}

/// Run `ephemeralml gcp deploy`.
pub fn cmd_deploy(ui: &mut Ui, flags: GcpFlags) -> Result<()> {
    let project_dir = find_project_dir()?;
    let config = GcpConfig::resolve(&flags, &project_dir)?;
    preflight_or_dry_run(ui, &config)?;

    let runner = ScriptRunner::new(project_dir);

    let mut args: Vec<String> = vec![
        "--project".to_string(),
        config.project.clone(),
        "--zone".to_string(),
        config.zone.clone(),
    ];
    if config.gpu {
        args.push("--gpu".to_string());
    }
    if config.debug {
        args.push("--debug".to_string());
    }
    if config.skip_build {
        args.push("--skip-build".to_string());
    }
    if config.yes {
        args.push("--yes".to_string());
    }
    if let Some(ref tag) = config.tag {
        args.push("--tag".to_string());
        args.push(tag.clone());
    }
    args.push("--model-source".to_string());
    args.push(config.model_source.clone());
    if let Some(ref key) = config.kms_key {
        args.push("--kms-key".to_string());
        args.push(key.clone());
    }
    if let Some(ref aud) = config.wip_audience {
        args.push("--wip-audience".to_string());
        args.push(aud.clone());
    }
    args.push("--bucket".to_string());
    args.push(config.bucket.clone());
    args.push("--model-prefix".to_string());
    args.push(config.model_prefix.clone());
    if let Some(ref hash) = config.model_hash {
        args.push("--model-hash".to_string());
        args.push(hash.clone());
    }
    if let Some(ref pk) = config.model_signing_pubkey {
        args.push("--model-signing-pubkey".to_string());
        args.push(pk.clone());
    }
    args.push("--model-format".to_string());
    args.push(config.model_format.clone());
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let mode = if config.gpu { "GPU" } else { "CPU" };
    ui.info(&format!(
        "Deploying Confidential Space CVM ({} mode)...",
        mode
    ));
    if config.verbose {
        ui.info(&format!("  Project: {}", config.project));
        ui.info(&format!("  Zone:    {}", config.zone));
        ui.info(&format!("  Region:  {}", config.region));
    }
    ui.blank();
    let result = runner.run("deploy.sh", &args_refs, &config, config.dry_run);
    if result.is_ok() {
        json_status(&config, "deploy", true, &format!("{} CVM launched", mode));
        next_step(ui, "ephemeralml gcp verify  (smoke test the deployment)");
    }
    result
}

/// Run `ephemeralml gcp verify`.
pub fn cmd_verify(ui: &mut Ui, flags: GcpFlags) -> Result<()> {
    let project_dir = find_project_dir()?;
    let config = GcpConfig::resolve(&flags, &project_dir)?;

    let runner = ScriptRunner::new(project_dir);

    let mut args: Vec<String> = Vec::new();
    if let Some(ref ip) = config.ip {
        args.push("--ip".to_string());
        args.push(ip.clone());
    }
    args.push("--project".to_string());
    args.push(config.project.clone());
    args.push("--zone".to_string());
    args.push(config.zone.clone());
    if config.gpu {
        args.push("--gpu".to_string());
    }
    if config.allow_unpinned_audience {
        args.push("--allow-unpinned-audience".to_string());
    }
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    ui.info("Verifying deployed CVM...");
    ui.blank();
    let result = runner.run("verify.sh", &args_refs, &config, config.dry_run);
    if result.is_ok() {
        json_status(&config, "verify", true, "CVM verified");
        next_step(ui, "ephemeralml gcp teardown  (when done, delete the CVM)");
    }
    result
}

/// Run `ephemeralml gcp teardown`.
pub fn cmd_teardown(ui: &mut Ui, flags: GcpFlags) -> Result<()> {
    let project_dir = find_project_dir()?;
    let config = GcpConfig::resolve(&flags, &project_dir)?;

    let runner = ScriptRunner::new(project_dir);

    let mut args: Vec<String> = vec![
        "--project".to_string(),
        config.project.clone(),
        "--zone".to_string(),
        config.zone.clone(),
    ];
    if config.gpu {
        args.push("--gpu".to_string());
    }
    if config.yes {
        args.push("--yes".to_string());
    }
    if config.delete_image {
        args.push("--delete-image".to_string());
    }
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    ui.info("Tearing down Confidential Space CVM...");
    ui.blank();
    let result = runner.run("teardown.sh", &args_refs, &config, config.dry_run);
    if result.is_ok() {
        json_status(&config, "teardown", true, "CVM deleted");
        next_step(
            ui,
            "deployment cleaned up. Re-deploy with: ephemeralml gcp deploy",
        );
    }
    result
}

/// Run `ephemeralml gcp e2e`.
pub fn cmd_e2e(ui: &mut Ui, flags: GcpFlags) -> Result<()> {
    let project_dir = find_project_dir()?;
    let config = GcpConfig::resolve(&flags, &project_dir)?;
    preflight_or_dry_run(ui, &config)?;

    let runner = ScriptRunner::new(project_dir);

    let mut args: Vec<String> = vec![
        "--project".to_string(),
        config.project.clone(),
        "--zone".to_string(),
        config.zone.clone(),
    ];
    if config.cpu_only {
        args.push("--cpu-only".to_string());
    }
    if config.skip_setup {
        args.push("--skip-setup".to_string());
    }
    if config.skip_teardown {
        args.push("--skip-teardown".to_string());
    }
    if let Some(ref dir) = config.model_dir {
        args.push("--model-dir".to_string());
        args.push(dir.clone());
    }
    args.push("--model-format".to_string());
    args.push(config.model_format.clone());
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    ui.info("Running full end-to-end pipeline...");
    ui.blank();
    let result = runner.run("mvp_gpu_e2e.sh", &args_refs, &config, config.dry_run);
    if result.is_ok() {
        json_status(&config, "e2e", true, "pipeline complete");
        next_step(
            ui,
            "check evidence/ directory for receipts and compliance bundle",
        );
    }
    result
}

/// Run `ephemeralml gcp release-gate`.
pub fn cmd_release_gate(ui: &mut Ui, flags: GcpFlags) -> Result<()> {
    let project_dir = find_project_dir()?;
    let config = GcpConfig::resolve(&flags, &project_dir)?;

    let runner = ScriptRunner::new(project_dir);

    let mut args: Vec<&str> = Vec::new();
    if config.quick {
        args.push("--quick");
    }

    ui.info("Running release gate checks...");
    ui.blank();
    let result = runner.run("release_gate.sh", &args, &config, config.dry_run);
    if result.is_ok() {
        json_status(&config, "release-gate", true, "all checks passed");
        next_step(ui, "ready to tag and release");
    }
    result
}
