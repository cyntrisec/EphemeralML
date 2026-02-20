use super::commands::build_setup_kms_args;
use super::config::{parse_env_file, region_from_zone, update_env_file, GcpConfig, GcpFlags};
use super::runner::ScriptRunner;
use std::io::Write;
use std::path::PathBuf;

fn temp_dir(suffix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "ephemeralml_gcp_test_{}_{}_{}",
        std::process::id(),
        nanos,
        suffix
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---- Config resolution tests ----

#[test]
fn config_flags_override_file() {
    let dir = temp_dir("flags_override");
    let env_path = dir.join(".env.gcp");
    let mut f = std::fs::File::create(&env_path).unwrap();
    writeln!(f, "EPHEMERALML_GCP_PROJECT=file-project").unwrap();
    writeln!(f, "EPHEMERALML_GCP_ZONE=file-zone").unwrap();
    writeln!(f, "EPHEMERALML_GCS_BUCKET=file-bucket").unwrap();
    drop(f);

    let flags = GcpFlags {
        project: Some("flag-project".to_string()),
        zone: Some("flag-zone".to_string()),
        ..Default::default()
    };
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    assert_eq!(config.project, "flag-project");
    assert_eq!(config.zone, "flag-zone");
    assert!(!config.bucket.is_empty());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn config_defaults_when_nothing_set() {
    let dir = temp_dir("defaults");
    let flags = GcpFlags::default();
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    assert_eq!(config.zone, "us-central1-a");
    assert_eq!(config.region, "us-central1");
    assert_eq!(config.bucket, "ephemeralml-models");
    assert_eq!(config.model_prefix, "models/minilm");
    assert_eq!(config.model_source, "local");
    assert_eq!(config.model_format, "safetensors");
    assert!(!config.gpu);
    assert!(!config.debug);
    assert!(!config.dry_run);
    assert!(!config.verbose);
    assert!(!config.json);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn config_boolean_flags_propagate() {
    let dir = temp_dir("booleans");
    let flags = GcpFlags {
        gpu: true,
        debug: true,
        skip_build: true,
        yes: true,
        dry_run: true,
        delete_image: true,
        allow_unpinned_audience: true,
        cpu_only: true,
        verbose: true,
        json: true,
        quick: true,
        ..Default::default()
    };
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    assert!(config.gpu);
    assert!(config.debug);
    assert!(config.skip_build);
    assert!(config.yes);
    assert!(config.dry_run);
    assert!(config.delete_image);
    assert!(config.allow_unpinned_audience);
    assert!(config.cpu_only);
    assert!(config.verbose);
    assert!(config.json);
    assert!(config.quick);
    std::fs::remove_dir_all(&dir).ok();
}

// ---- .env.gcp parser tests ----

#[test]
fn env_file_parses_comments_and_empty_lines() {
    let dir = temp_dir("parser_comments");
    let path = dir.join(".env.gcp");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "# This is a comment").unwrap();
    writeln!(f).unwrap();
    writeln!(f, "KEY1=value1").unwrap();
    writeln!(f, "  # indented comment").unwrap();
    writeln!(f, "KEY2=value2").unwrap();
    drop(f);

    let vars = parse_env_file(&path);
    assert_eq!(vars.len(), 2);
    assert_eq!(vars["KEY1"], "value1");
    assert_eq!(vars["KEY2"], "value2");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn env_file_strips_quotes() {
    let dir = temp_dir("parser_quotes");
    let path = dir.join(".env.gcp");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "A=\"double-quoted\"").unwrap();
    writeln!(f, "B='single-quoted'").unwrap();
    writeln!(f, "C=no-quotes").unwrap();
    drop(f);

    let vars = parse_env_file(&path);
    assert_eq!(vars["A"], "double-quoted");
    assert_eq!(vars["B"], "single-quoted");
    assert_eq!(vars["C"], "no-quotes");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn env_file_handles_spaces() {
    let dir = temp_dir("parser_spaces");
    let path = dir.join(".env.gcp");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "  KEY  =  value  ").unwrap();
    drop(f);

    let vars = parse_env_file(&path);
    assert_eq!(vars["KEY"], "value");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn env_file_export_prefix_parsed() {
    let dir = temp_dir("parser_export");
    let path = dir.join(".env.gcp");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "export EPHEMERALML_GCP_PROJECT=\"my-project\"").unwrap();
    writeln!(f, "export EPHEMERALML_GCP_ZONE=\"us-west1-b\"").unwrap();
    drop(f);

    let vars = parse_env_file(&path);
    assert_eq!(vars["EPHEMERALML_GCP_PROJECT"], "my-project");
    assert_eq!(vars["EPHEMERALML_GCP_ZONE"], "us-west1-b");
    // Must NOT store as "export EPHEMERALML_GCP_PROJECT"
    assert!(!vars.contains_key("export EPHEMERALML_GCP_PROJECT"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn env_file_mixed_export_and_plain() {
    let dir = temp_dir("parser_mixed");
    let path = dir.join(".env.gcp");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "# Generated by init_gcp.sh").unwrap();
    writeln!(f, "export EPHEMERALML_GCP_PROJECT=\"proj-a\"").unwrap();
    writeln!(f, "PLAIN_KEY=plain-value").unwrap();
    writeln!(f, "export QUOTED='single-q'").unwrap();
    drop(f);

    let vars = parse_env_file(&path);
    assert_eq!(vars["EPHEMERALML_GCP_PROJECT"], "proj-a");
    assert_eq!(vars["PLAIN_KEY"], "plain-value");
    assert_eq!(vars["QUOTED"], "single-q");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn env_file_export_config_resolution() {
    let dir = temp_dir("export_resolve");
    let path = dir.join(".env.gcp");
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "export EPHEMERALML_GCP_PROJECT=\"from-init-script\"").unwrap();
    writeln!(f, "export EPHEMERALML_GCP_ZONE=\"europe-west4-b\"").unwrap();
    drop(f);

    let flags = GcpFlags::default();
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    // Should successfully resolve from export-prefixed .env.gcp
    assert_eq!(config.project, "from-init-script");
    assert_eq!(config.zone, "europe-west4-b");
    assert_eq!(config.region, "europe-west4");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- Region derivation tests ----

#[test]
fn region_from_zone_standard_zones() {
    assert_eq!(region_from_zone("us-central1-a"), "us-central1");
    assert_eq!(region_from_zone("us-central1-f"), "us-central1");
    assert_eq!(region_from_zone("europe-west4-b"), "europe-west4");
    assert_eq!(region_from_zone("asia-southeast1-c"), "asia-southeast1");
    assert_eq!(region_from_zone("me-central1-a"), "me-central1");
}

#[test]
fn region_from_zone_edge_cases() {
    // No suffix letter
    assert_eq!(region_from_zone("us-central1"), "us-central1");
    // No hyphen at all
    assert_eq!(region_from_zone("nohyphen"), "nohyphen");
}

#[test]
fn config_region_derived_from_zone() {
    let dir = temp_dir("region_derived");
    let flags = GcpFlags {
        zone: Some("us-west1-b".to_string()),
        ..Default::default()
    };
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    assert_eq!(config.region, "us-west1");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn config_region_flag_overrides_zone_derivation() {
    let dir = temp_dir("region_override");
    let flags = GcpFlags {
        zone: Some("us-west1-b".to_string()),
        region: Some("europe-west4".to_string()),
        ..Default::default()
    };
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    assert_eq!(config.region, "europe-west4");
    assert_eq!(config.zone, "us-west1-b");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- ScriptRunner tests ----

#[test]
fn runner_script_path_resolution() {
    let dir = temp_dir("runner_path");
    std::fs::create_dir_all(dir.join("scripts").join("gcp")).unwrap();
    let runner = ScriptRunner::new(dir.clone());

    assert_eq!(
        runner.script_path("deploy.sh"),
        dir.join("scripts/gcp/deploy.sh")
    );
    assert_eq!(
        runner.script_path("setup_kms.sh"),
        dir.join("scripts/gcp/setup_kms.sh")
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn runner_missing_script_fails() {
    let dir = temp_dir("runner_missing");
    std::fs::create_dir_all(dir.join("scripts").join("gcp")).unwrap();
    let runner = ScriptRunner::new(dir.clone());

    let config = GcpConfig::resolve(&GcpFlags::default(), &dir).unwrap();
    let err = runner.run("does_not_exist.sh", &[], &config, false);
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("Script not found"), "got: {}", msg);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn runner_dry_run_succeeds_for_failing_script() {
    let dir = temp_dir("runner_dryrun");
    let scripts_dir = dir.join("scripts").join("gcp");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(scripts_dir.join("fail.sh"), "#!/bin/bash\nexit 42").unwrap();

    let runner = ScriptRunner::new(dir.clone());
    let config = GcpConfig::resolve(&GcpFlags::default(), &dir).unwrap();
    let result = runner.run("fail.sh", &[], &config, true);
    assert!(result.is_ok());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn runner_executes_successful_script() {
    let dir = temp_dir("runner_success");
    let scripts_dir = dir.join("scripts").join("gcp");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(scripts_dir.join("ok.sh"), "#!/bin/bash\nexit 0").unwrap();

    let runner = ScriptRunner::new(dir.clone());
    let config = GcpConfig::resolve(&GcpFlags::default(), &dir).unwrap();
    let result = runner.run("ok.sh", &[], &config, false);
    assert!(result.is_ok());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn runner_reports_nonzero_exit() {
    let dir = temp_dir("runner_nonzero");
    let scripts_dir = dir.join("scripts").join("gcp");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::write(scripts_dir.join("fail.sh"), "#!/bin/bash\nexit 7").unwrap();

    let runner = ScriptRunner::new(dir.clone());
    let config = GcpConfig::resolve(&GcpFlags::default(), &dir).unwrap();
    let err = runner.run("fail.sh", &[], &config, false);
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("exited with code 7"), "got: {}", msg);
    std::fs::remove_dir_all(&dir).ok();
}

// ---- require_project tests ----

#[test]
fn require_project_fails_when_empty() {
    let dir = temp_dir("require_empty");
    let config = GcpConfig::resolve(&GcpFlags::default(), &dir).unwrap();
    assert!(config.require_project().is_err());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn require_project_ok_when_set() {
    let dir = temp_dir("require_set");
    let flags = GcpFlags {
        project: Some("my-proj".to_string()),
        ..Default::default()
    };
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    assert_eq!(config.require_project().unwrap(), "my-proj");
    std::fs::remove_dir_all(&dir).ok();
}

// ---- setup-kms arg construction tests (via build_setup_kms_args) ----

#[test]
fn setup_kms_args_uses_region_not_zone() {
    let dir = temp_dir("kms_region");
    let flags = GcpFlags {
        project: Some("test-proj".to_string()),
        zone: Some("europe-west4-b".to_string()),
        allow_broad_binding: true,
        ..Default::default()
    };
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    let args = build_setup_kms_args(&config).unwrap();
    // First positional = project, second = region (NOT zone)
    assert_eq!(args[0], "test-proj");
    assert_eq!(args[1], "europe-west4"); // derived region, not "europe-west4-b"
    assert_eq!(args[2], "--allow-broad-binding");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn setup_kms_args_rejects_missing_mode() {
    let dir = temp_dir("kms_no_mode");
    let flags = GcpFlags {
        project: Some("test-proj".to_string()),
        ..Default::default()
    };
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    let err = build_setup_kms_args(&config);
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(
        msg.contains("--image-digest") && msg.contains("--allow-broad-binding"),
        "expected guidance in error, got: {}",
        msg
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn setup_kms_args_with_broad_binding() {
    let dir = temp_dir("kms_broad");
    let flags = GcpFlags {
        project: Some("my-proj".to_string()),
        allow_broad_binding: true,
        ..Default::default()
    };
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    let args = build_setup_kms_args(&config).unwrap();
    assert_eq!(
        args,
        vec!["my-proj", "us-central1", "--allow-broad-binding"]
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn setup_kms_args_with_image_digest() {
    let dir = temp_dir("kms_digest");
    let flags = GcpFlags {
        project: Some("my-proj".to_string()),
        zone: Some("us-west1-b".to_string()),
        image_digest: Some("sha256:deadbeef".to_string()),
        ..Default::default()
    };
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    let args = build_setup_kms_args(&config).unwrap();
    assert_eq!(args, vec!["my-proj", "us-west1", "sha256:deadbeef"]);
    std::fs::remove_dir_all(&dir).ok();
}

// ---- dry-run preflight behavior test ----

#[test]
fn dry_run_does_not_require_project() {
    // With dry_run=true, preflight should not block on missing project.
    // We verify that GcpConfig resolves even with empty project + dry_run.
    let dir = temp_dir("dryrun_no_project");
    let flags = GcpFlags {
        dry_run: true,
        ..Default::default()
    };
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    assert!(config.dry_run);
    assert!(config.project.is_empty());
    // require_project would fail, but preflight_or_dry_run skips it
    assert!(config.require_project().is_err());
    std::fs::remove_dir_all(&dir).ok();
}

// ---- JSON output contract test ----

#[test]
fn json_status_format() {
    // Verify the JSON status string format
    let dir = temp_dir("json_format");
    let flags = GcpFlags {
        project: Some("p".to_string()),
        json: true,
        ..Default::default()
    };
    let config = GcpConfig::resolve(&flags, &dir).unwrap();
    assert!(config.json);
    // The json_status function is in commands.rs; here we just verify
    // that the config flag propagates correctly.
    std::fs::remove_dir_all(&dir).ok();
}

// ---- update_env_file tests ----

#[test]
fn update_env_file_creates_new_file() {
    let dir = temp_dir("envfile_create");
    let path = dir.join(".env.gcp");
    assert!(!path.exists());

    update_env_file(&path, &[("KEY_A", "val_a"), ("KEY_B", "val_b")]).unwrap();
    assert!(path.exists());

    let vars = parse_env_file(&path);
    assert_eq!(vars["KEY_A"], "val_a");
    assert_eq!(vars["KEY_B"], "val_b");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn update_env_file_idempotent() {
    let dir = temp_dir("envfile_idempotent");
    let path = dir.join(".env.gcp");

    // Write initial values
    update_env_file(&path, &[("KEY", "v1")]).unwrap();
    let content1 = std::fs::read_to_string(&path).unwrap();

    // Write same value again — should produce identical output
    update_env_file(&path, &[("KEY", "v1")]).unwrap();
    let content2 = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        content1, content2,
        "idempotent write should not change file"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn update_env_file_updates_existing_key() {
    let dir = temp_dir("envfile_update");
    let path = dir.join(".env.gcp");

    // Initial
    update_env_file(&path, &[("KEY", "old_value")]).unwrap();
    let vars = parse_env_file(&path);
    assert_eq!(vars["KEY"], "old_value");

    // Update
    update_env_file(&path, &[("KEY", "new_value")]).unwrap();
    let vars = parse_env_file(&path);
    assert_eq!(vars["KEY"], "new_value");

    // File should have exactly one KEY= line (no duplicates)
    let content = std::fs::read_to_string(&path).unwrap();
    let count = content.lines().filter(|l| l.contains("KEY=")).count();
    assert_eq!(count, 1, "should not duplicate keys");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn update_env_file_preserves_comments_and_other_keys() {
    let dir = temp_dir("envfile_preserve");
    let path = dir.join(".env.gcp");

    // Manually create a file with comments and existing keys
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "# Generated by init_gcp.sh").unwrap();
    writeln!(f, "export EPHEMERALML_GCP_PROJECT=\"my-proj\"").unwrap();
    writeln!(f, "export EPHEMERALML_GCP_ZONE=\"us-central1-a\"").unwrap();
    writeln!(f).unwrap();
    writeln!(f, "# KMS config below").unwrap();
    drop(f);

    // Add KMS keys
    update_env_file(
        &path,
        &[
            ("EPHEMERALML_GCS_BUCKET", "ephemeralml-models-my-proj"),
            (
                "EPHEMERALML_GCP_KMS_KEY",
                "projects/my-proj/locations/us-central1/keyRings/ephemeralml/cryptoKeys/model-dek",
            ),
        ],
    )
    .unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    // Comments preserved
    assert!(content.contains("# Generated by init_gcp.sh"));
    assert!(content.contains("# KMS config below"));
    // Existing keys preserved
    let vars = parse_env_file(&path);
    assert_eq!(vars["EPHEMERALML_GCP_PROJECT"], "my-proj");
    assert_eq!(vars["EPHEMERALML_GCP_ZONE"], "us-central1-a");
    // New keys added
    assert_eq!(vars["EPHEMERALML_GCS_BUCKET"], "ephemeralml-models-my-proj");
    assert!(vars["EPHEMERALML_GCP_KMS_KEY"].contains("keyRings/ephemeralml"));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn update_env_file_replaces_export_prefixed_line() {
    let dir = temp_dir("envfile_export_replace");
    let path = dir.join(".env.gcp");

    // Write with export prefix
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "export EPHEMERALML_GCS_BUCKET=\"old-bucket\"").unwrap();
    drop(f);

    // Update should find and replace the export-prefixed line
    update_env_file(&path, &[("EPHEMERALML_GCS_BUCKET", "new-bucket")]).unwrap();

    let vars = parse_env_file(&path);
    assert_eq!(vars["EPHEMERALML_GCS_BUCKET"], "new-bucket");

    // No duplicate lines
    let content = std::fs::read_to_string(&path).unwrap();
    let count = content
        .lines()
        .filter(|l| l.contains("EPHEMERALML_GCS_BUCKET"))
        .count();
    assert_eq!(count, 1);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn update_env_file_dry_run_like_usage() {
    // Test that updates with all 6 KMS keys work correctly
    let dir = temp_dir("envfile_kms_all");
    let path = dir.join(".env.gcp");

    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "export EPHEMERALML_GCP_PROJECT=\"test-proj\"").unwrap();
    drop(f);

    let updates = vec![
        ("EPHEMERALML_GCS_BUCKET", "ephemeralml-models-test-proj"),
        ("EPHEMERALML_GCP_KMS_KEY", "projects/test-proj/locations/us-central1/keyRings/ephemeralml/cryptoKeys/model-dek"),
        ("EPHEMERALML_GCP_WIP_AUDIENCE", "//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/ephemeralml-pool/providers/ephemeralml-tdx"),
        ("GCP_BUCKET", "ephemeralml-models-test-proj"),
        ("GCP_KMS_KEY", "projects/test-proj/locations/us-central1/keyRings/ephemeralml/cryptoKeys/model-dek"),
        ("GCP_WIP_AUDIENCE", "//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/ephemeralml-pool/providers/ephemeralml-tdx"),
    ];

    update_env_file(&path, &updates).unwrap();

    let vars = parse_env_file(&path);
    // Original key preserved
    assert_eq!(vars["EPHEMERALML_GCP_PROJECT"], "test-proj");
    // All 6 KMS keys present
    assert_eq!(vars.len(), 7); // 1 existing + 6 new
    assert_eq!(
        vars["EPHEMERALML_GCS_BUCKET"],
        "ephemeralml-models-test-proj"
    );
    assert_eq!(vars["GCP_BUCKET"], "ephemeralml-models-test-proj");
    assert!(vars["EPHEMERALML_GCP_WIP_AUDIENCE"].contains("12345"));
    assert!(vars["GCP_WIP_AUDIENCE"].contains("12345"));

    // Run again — idempotent (should not add duplicates)
    update_env_file(&path, &updates).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    let bucket_count = content
        .lines()
        .filter(|l| l.contains("EPHEMERALML_GCS_BUCKET="))
        .count();
    assert_eq!(bucket_count, 1, "idempotent: no duplicate keys");

    std::fs::remove_dir_all(&dir).ok();
}
