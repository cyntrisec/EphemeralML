use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::config::GcpConfig;

/// Runs GCP bash scripts with config-derived environment variables.
pub struct ScriptRunner {
    /// Path to the project root (contains `scripts/gcp/`).
    project_dir: PathBuf,
}

impl ScriptRunner {
    pub fn new(project_dir: PathBuf) -> Self {
        Self { project_dir }
    }

    /// Resolve the full path to a script in `scripts/gcp/`.
    pub fn script_path(&self, script_name: &str) -> PathBuf {
        self.project_dir
            .join("scripts")
            .join("gcp")
            .join(script_name)
    }

    /// Run a GCP script, passing args and injecting config as env vars.
    ///
    /// stdout/stderr are inherited (streamed to terminal).
    /// If `config.dry_run` is true, prints the command without executing.
    pub fn run(
        &self,
        script_name: &str,
        args: &[&str],
        config: &GcpConfig,
        dry_run: bool,
    ) -> Result<()> {
        let path = self.script_path(script_name);
        if !path.exists() {
            bail!(
                "Script not found: {}. Expected at {}",
                script_name,
                path.display()
            );
        }

        if dry_run {
            let args_display = if args.is_empty() {
                String::new()
            } else {
                format!(" {}", args.join(" "))
            };
            println!("[dry-run] bash {}{}", path.display(), args_display);
            println!("[dry-run] Environment:");
            for (k, v) in Self::config_env(config) {
                if !v.is_empty() {
                    println!("[dry-run]   {}={}", k, v);
                }
            }
            return Ok(());
        }

        let mut cmd = Command::new("bash");
        cmd.arg(&path);
        cmd.args(args);
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
        cmd.current_dir(&self.project_dir);

        // Inject config as environment variables
        for (key, value) in Self::config_env(config) {
            cmd.env(key, value);
        }

        let status = cmd
            .status()
            .with_context(|| format!("Failed to execute {}", script_name))?;

        if !status.success() {
            let code = status.code().unwrap_or(-1);
            bail!("{} exited with code {}", script_name, code);
        }

        Ok(())
    }

    /// Build environment variable pairs from GcpConfig.
    fn config_env(config: &GcpConfig) -> Vec<(&'static str, String)> {
        let mut env = vec![
            ("EPHEMERALML_GCP_PROJECT", config.project.clone()),
            ("EPHEMERALML_GCP_REGION", config.region.clone()),
            ("EPHEMERALML_GCP_ZONE", config.zone.clone()),
            ("EPHEMERALML_GCS_BUCKET", config.bucket.clone()),
            ("EPHEMERALML_GCP_MODEL_PREFIX", config.model_prefix.clone()),
            ("EPHEMERALML_MODEL_SOURCE", config.model_source.clone()),
            ("EPHEMERALML_MODEL_FORMAT", config.model_format.clone()),
        ];
        if let Some(ref v) = config.kms_key {
            env.push(("EPHEMERALML_GCP_KMS_KEY", v.clone()));
            env.push(("GCP_KMS_KEY", v.clone()));
        }
        if let Some(ref v) = config.wip_audience {
            env.push(("EPHEMERALML_GCP_WIP_AUDIENCE", v.clone()));
            env.push(("GCP_WIP_AUDIENCE", v.clone()));
        }
        if let Some(ref v) = config.model_hash {
            env.push(("EPHEMERALML_EXPECTED_MODEL_HASH", v.clone()));
        }
        if let Some(ref v) = config.model_signing_pubkey {
            env.push(("EPHEMERALML_MODEL_SIGNING_PUBKEY", v.clone()));
        }
        if let Some(ref v) = config.source_ranges {
            env.push(("EPHEMERALML_FIREWALL_SOURCE_RANGES", v.clone()));
        }
        env.push(("GCP_BUCKET", config.bucket.clone()));
        env
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_project_dir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ephemeralml_runner_test_{}_{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(dir.join("scripts").join("gcp")).unwrap();
        dir
    }

    #[test]
    fn script_path_resolves_correctly() {
        let dir = test_project_dir();
        let runner = ScriptRunner::new(dir.clone());
        let path = runner.script_path("deploy.sh");
        assert_eq!(path, dir.join("scripts").join("gcp").join("deploy.sh"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_script_returns_error() {
        let dir = test_project_dir();
        let runner = ScriptRunner::new(dir.clone());
        let config = GcpConfig::resolve(&super::super::config::GcpFlags::default(), &dir).unwrap();
        let err = runner.run("nonexistent.sh", &[], &config, false);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("Script not found"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dry_run_does_not_execute() {
        let dir = test_project_dir();
        // Create a script that would fail if executed
        let script_path = dir.join("scripts").join("gcp").join("fail.sh");
        std::fs::write(&script_path, "#!/bin/bash\nexit 1").unwrap();

        let runner = ScriptRunner::new(dir.clone());
        let flags = super::super::config::GcpFlags {
            project: Some("test-proj".to_string()),
            dry_run: true,
            ..Default::default()
        };
        let config = GcpConfig::resolve(&flags, &dir).unwrap();
        // dry_run=true should return Ok even though script would fail
        let result = runner.run("fail.sh", &[], &config, true);
        assert!(result.is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }
}
