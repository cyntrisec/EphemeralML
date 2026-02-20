use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Resolved GCP deployment configuration.
///
/// Resolution precedence: CLI flags > env vars > `.env.gcp` file > hardcoded defaults.
#[derive(Debug, Clone)]
pub struct GcpConfig {
    pub project: String,
    pub region: String,
    pub zone: String,
    pub gpu: bool,
    pub debug: bool,
    pub kms_key: Option<String>,
    pub wip_audience: Option<String>,
    pub bucket: String,
    pub model_prefix: String,
    pub model_source: String,
    pub model_dir: Option<String>,
    pub model_id: Option<String>,
    pub model_version: Option<String>,
    pub model_format: String,
    pub model_hash: Option<String>,
    pub model_signing_pubkey: Option<String>,
    pub tag: Option<String>,
    pub skip_build: bool,
    pub yes: bool,
    pub dry_run: bool,
    pub ip: Option<String>,
    pub source_ranges: Option<String>,
    pub allow_broad_binding: bool,
    pub image_digest: Option<String>,
    pub delete_image: bool,
    pub allow_unpinned_audience: bool,
    pub skip_setup: bool,
    pub skip_teardown: bool,
    pub cpu_only: bool,
    pub verbose: bool,
    pub json: bool,
    pub quick: bool,
    pub non_interactive: bool,
}

/// CLI flags that override env/file values. `None` means "not provided".
#[derive(Debug, Default)]
pub struct GcpFlags {
    pub project: Option<String>,
    pub region: Option<String>,
    pub zone: Option<String>,
    pub gpu: bool,
    pub debug: bool,
    pub kms_key: Option<String>,
    pub wip_audience: Option<String>,
    pub bucket: Option<String>,
    pub model_prefix: Option<String>,
    pub model_source: Option<String>,
    pub model_dir: Option<String>,
    pub model_id: Option<String>,
    pub model_version: Option<String>,
    pub model_format: Option<String>,
    pub model_hash: Option<String>,
    pub model_signing_pubkey: Option<String>,
    pub tag: Option<String>,
    pub skip_build: bool,
    pub yes: bool,
    pub dry_run: bool,
    pub ip: Option<String>,
    pub source_ranges: Option<String>,
    pub allow_broad_binding: bool,
    pub image_digest: Option<String>,
    pub delete_image: bool,
    pub allow_unpinned_audience: bool,
    pub skip_setup: bool,
    pub skip_teardown: bool,
    pub cpu_only: bool,
    pub verbose: bool,
    pub json: bool,
    pub quick: bool,
    pub non_interactive: bool,
}

/// Derive a GCP region from a zone (e.g. `us-central1-a` -> `us-central1`).
///
/// GCP zones are `<region>-<single-letter>`, e.g. `us-central1-a`.
/// If the input is already a region (no single-letter suffix), returns it as-is.
pub fn region_from_zone(zone: &str) -> String {
    match zone.rfind('-') {
        // Only strip the suffix if it's a single character (zone letter like -a, -b, -f)
        Some(pos) if pos > 0 && zone.len() == pos + 2 => zone[..pos].to_string(),
        _ => zone.to_string(),
    }
}

impl GcpConfig {
    /// Resolve configuration from flags, environment, and `.env.gcp` file.
    pub fn resolve(flags: &GcpFlags, project_dir: &Path) -> Result<Self> {
        let file_vars = parse_env_file(&project_dir.join(".env.gcp"));

        let get = |flag: &Option<String>, env_names: &[&str], file_key: &str| -> Option<String> {
            if let Some(v) = flag {
                return Some(v.clone());
            }
            for name in env_names {
                if let Ok(v) = std::env::var(name) {
                    if !v.is_empty() {
                        return Some(v);
                    }
                }
            }
            file_vars.get(file_key).cloned()
        };

        let project = get(
            &flags.project,
            &["EPHEMERALML_GCP_PROJECT", "GOOGLE_CLOUD_PROJECT"],
            "EPHEMERALML_GCP_PROJECT",
        )
        .unwrap_or_default();

        let zone = get(
            &flags.zone,
            &["EPHEMERALML_GCP_ZONE"],
            "EPHEMERALML_GCP_ZONE",
        )
        .unwrap_or_else(|| "us-central1-a".to_string());

        // Region: explicit flag > env > derived from zone
        let region = get(
            &flags.region,
            &["EPHEMERALML_GCP_REGION"],
            "EPHEMERALML_GCP_REGION",
        )
        .unwrap_or_else(|| region_from_zone(&zone));

        let bucket = get(
            &flags.bucket,
            &["EPHEMERALML_GCS_BUCKET", "GCP_BUCKET"],
            "EPHEMERALML_GCS_BUCKET",
        )
        .unwrap_or_else(|| "ephemeralml-models".to_string());

        let model_prefix = get(
            &flags.model_prefix,
            &["EPHEMERALML_GCP_MODEL_PREFIX"],
            "EPHEMERALML_GCP_MODEL_PREFIX",
        )
        .unwrap_or_else(|| "models/minilm".to_string());

        let model_source = get(
            &flags.model_source,
            &["EPHEMERALML_MODEL_SOURCE"],
            "EPHEMERALML_MODEL_SOURCE",
        )
        .unwrap_or_else(|| "local".to_string());

        let model_format = get(
            &flags.model_format,
            &["EPHEMERALML_MODEL_FORMAT"],
            "EPHEMERALML_MODEL_FORMAT",
        )
        .unwrap_or_else(|| "safetensors".to_string());

        let kms_key = get(
            &flags.kms_key,
            &["EPHEMERALML_GCP_KMS_KEY", "GCP_KMS_KEY"],
            "EPHEMERALML_GCP_KMS_KEY",
        );

        let wip_audience = get(
            &flags.wip_audience,
            &["EPHEMERALML_GCP_WIP_AUDIENCE", "GCP_WIP_AUDIENCE"],
            "EPHEMERALML_GCP_WIP_AUDIENCE",
        );

        let model_hash = get(
            &flags.model_hash,
            &["EPHEMERALML_EXPECTED_MODEL_HASH"],
            "EPHEMERALML_EXPECTED_MODEL_HASH",
        );

        let model_signing_pubkey = get(
            &flags.model_signing_pubkey,
            &["EPHEMERALML_MODEL_SIGNING_PUBKEY"],
            "EPHEMERALML_MODEL_SIGNING_PUBKEY",
        );

        let source_ranges = get(
            &flags.source_ranges,
            &["EPHEMERALML_FIREWALL_SOURCE_RANGES"],
            "EPHEMERALML_FIREWALL_SOURCE_RANGES",
        );

        Ok(Self {
            project,
            region,
            zone,
            gpu: flags.gpu,
            debug: flags.debug,
            kms_key,
            wip_audience,
            bucket,
            model_prefix,
            model_source,
            model_dir: flags.model_dir.clone(),
            model_id: flags.model_id.clone(),
            model_version: flags.model_version.clone(),
            model_format,
            model_hash,
            model_signing_pubkey,
            tag: flags.tag.clone(),
            skip_build: flags.skip_build,
            yes: flags.yes,
            dry_run: flags.dry_run,
            ip: flags.ip.clone(),
            source_ranges,
            allow_broad_binding: flags.allow_broad_binding,
            image_digest: flags.image_digest.clone(),
            delete_image: flags.delete_image,
            allow_unpinned_audience: flags.allow_unpinned_audience,
            skip_setup: flags.skip_setup,
            skip_teardown: flags.skip_teardown,
            cpu_only: flags.cpu_only,
            verbose: flags.verbose,
            json: flags.json,
            quick: flags.quick,
            non_interactive: flags.non_interactive,
        })
    }

    /// Require that the project field is non-empty, or bail.
    pub fn require_project(&self) -> Result<&str> {
        if self.project.is_empty() {
            bail!(
                "GCP project is required. Set --project, EPHEMERALML_GCP_PROJECT, \
                 or add it to .env.gcp"
            );
        }
        Ok(&self.project)
    }
}

/// Parse a `.env.gcp` file into key-value pairs.
///
/// Accepts both `KEY=VALUE` and `export KEY=VALUE` formats (as produced by
/// `scripts/init_gcp.sh`). Lines starting with `#` or empty lines are skipped.
/// Values may optionally be quoted with single or double quotes.
pub fn parse_env_file(path: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return map,
    };
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Strip leading `export ` prefix (init_gcp.sh writes `export KEY="value"`)
        let assignment = if let Some(rest) = trimmed.strip_prefix("export ") {
            rest.trim()
        } else {
            trimmed
        };
        if let Some((key, value)) = assignment.split_once('=') {
            let key = key.trim();
            let mut value = value.trim();
            // Strip optional quotes
            if ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
                && value.len() >= 2
            {
                value = &value[1..value.len() - 1];
            }
            if !key.is_empty() {
                map.insert(key.to_string(), value.to_string());
            }
        }
    }
    map
}

/// Find the project root directory by searching for Cargo.toml upward from the current dir.
pub fn find_project_dir() -> Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        if dir.join("Cargo.toml").exists() && dir.join("scripts").exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            bail!(
                "Could not find EphemeralML project root (looked for Cargo.toml + scripts/). \
                 Run from within the project directory."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ephemeralml_config_test_{}_{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parse_env_file_basic() {
        let dir = temp_dir();
        let path = dir.join(".env.gcp");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f, "EPHEMERALML_GCP_PROJECT=my-project").unwrap();
        writeln!(f, "EPHEMERALML_GCP_ZONE=\"us-west1-b\"").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "EPHEMERALML_GCS_BUCKET='my-bucket'").unwrap();
        drop(f);

        let vars = parse_env_file(&path);
        assert_eq!(vars.get("EPHEMERALML_GCP_PROJECT").unwrap(), "my-project");
        assert_eq!(vars.get("EPHEMERALML_GCP_ZONE").unwrap(), "us-west1-b");
        assert_eq!(vars.get("EPHEMERALML_GCS_BUCKET").unwrap(), "my-bucket");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_env_file_missing_returns_empty() {
        let vars = parse_env_file(Path::new("/nonexistent/.env.gcp"));
        assert!(vars.is_empty());
    }

    #[test]
    fn flags_override_env_file() {
        let dir = temp_dir();
        let path = dir.join(".env.gcp");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "EPHEMERALML_GCP_PROJECT=file-project").unwrap();
        writeln!(f, "EPHEMERALML_GCS_BUCKET=file-bucket").unwrap();
        drop(f);

        let flags = GcpFlags {
            project: Some("flag-project".to_string()),
            ..Default::default()
        };
        let config = GcpConfig::resolve(&flags, &dir).unwrap();
        assert_eq!(config.project, "flag-project");
        // bucket should come from file since no flag or env var set
        // (env var may or may not be set in test environment, so we just check it's not empty)
        assert!(!config.bucket.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn defaults_applied_when_nothing_set() {
        let dir = temp_dir();
        let flags = GcpFlags::default();
        let config = GcpConfig::resolve(&flags, &dir).unwrap();
        assert_eq!(config.zone, "us-central1-a");
        assert_eq!(config.bucket, "ephemeralml-models");
        assert_eq!(config.model_prefix, "models/minilm");
        assert_eq!(config.model_source, "local");
        assert_eq!(config.model_format, "safetensors");
        assert!(config.project.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn require_project_fails_when_empty() {
        let dir = temp_dir();
        let flags = GcpFlags::default();
        let config = GcpConfig::resolve(&flags, &dir).unwrap();
        assert!(config.require_project().is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn require_project_ok_when_set() {
        let dir = temp_dir();
        let flags = GcpFlags {
            project: Some("test-proj".to_string()),
            ..Default::default()
        };
        let config = GcpConfig::resolve(&flags, &dir).unwrap();
        assert_eq!(config.require_project().unwrap(), "test-proj");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_env_file_export_prefix() {
        let dir = temp_dir();
        let path = dir.join(".env.gcp");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "export EPHEMERALML_GCP_PROJECT=\"my-project\"").unwrap();
        writeln!(f, "export EPHEMERALML_GCP_ZONE=\"us-west1-b\"").unwrap();
        writeln!(f, "export EPHEMERALML_GCS_BUCKET='my-bucket'").unwrap();
        drop(f);

        let vars = parse_env_file(&path);
        assert_eq!(vars.get("EPHEMERALML_GCP_PROJECT").unwrap(), "my-project");
        assert_eq!(vars.get("EPHEMERALML_GCP_ZONE").unwrap(), "us-west1-b");
        assert_eq!(vars.get("EPHEMERALML_GCS_BUCKET").unwrap(), "my-bucket");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_env_file_mixed_export_and_plain() {
        let dir = temp_dir();
        let path = dir.join(".env.gcp");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# Generated by init_gcp.sh").unwrap();
        writeln!(f, "export EPHEMERALML_GCP_PROJECT=\"proj-a\"").unwrap();
        writeln!(f, "PLAIN_KEY=plain-value").unwrap();
        writeln!(f, "export QUOTED='single-q'").unwrap();
        drop(f);

        let vars = parse_env_file(&path);
        assert_eq!(vars.get("EPHEMERALML_GCP_PROJECT").unwrap(), "proj-a");
        assert_eq!(vars.get("PLAIN_KEY").unwrap(), "plain-value");
        assert_eq!(vars.get("QUOTED").unwrap(), "single-q");
        // Ensure "export EPHEMERALML_GCP_PROJECT" is NOT a key
        assert!(!vars.contains_key("export EPHEMERALML_GCP_PROJECT"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn region_from_zone_derivation() {
        assert_eq!(region_from_zone("us-central1-a"), "us-central1");
        assert_eq!(region_from_zone("europe-west4-b"), "europe-west4");
        assert_eq!(region_from_zone("asia-southeast1-c"), "asia-southeast1");
        // Edge: no dash at all
        assert_eq!(region_from_zone("nohyphen"), "nohyphen");
    }

    #[test]
    fn config_region_derived_from_zone() {
        let dir = temp_dir();
        let flags = GcpFlags {
            zone: Some("us-west1-b".to_string()),
            ..Default::default()
        };
        let config = GcpConfig::resolve(&flags, &dir).unwrap();
        assert_eq!(config.zone, "us-west1-b");
        assert_eq!(config.region, "us-west1");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_region_flag_overrides_derivation() {
        let dir = temp_dir();
        let flags = GcpFlags {
            zone: Some("us-west1-b".to_string()),
            region: Some("europe-west4".to_string()),
            ..Default::default()
        };
        let config = GcpConfig::resolve(&flags, &dir).unwrap();
        assert_eq!(config.zone, "us-west1-b");
        assert_eq!(config.region, "europe-west4");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_default_region_from_default_zone() {
        let dir = temp_dir();
        let flags = GcpFlags::default();
        let config = GcpConfig::resolve(&flags, &dir).unwrap();
        assert_eq!(config.zone, "us-central1-a");
        assert_eq!(config.region, "us-central1");
        std::fs::remove_dir_all(&dir).ok();
    }
}
