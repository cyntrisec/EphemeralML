//! CLI/output integration tests for ephemeralml-smoke-test.
//!
//! Same shape as doctor's: verifies CLI + exit codes + JSON shape that real
//! stage probes must preserve when they land.

use assert_cmd::Command;
use predicates::prelude::*;

fn smoke() -> Command {
    Command::cargo_bin("ephemeralml-smoke-test").expect("binary built by Cargo")
}

#[test]
fn help_exits_zero() {
    smoke()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ephemeralml-smoke-test"))
        .stdout(predicate::str::contains("--json"))
        .stdout(predicate::str::contains("--no-upload"))
        .stdout(predicate::str::contains("--verbose"))
        .stdout(predicate::str::contains("--stack-name"))
        .stdout(predicate::str::contains("--retain-enclave"))
        .stdout(predicate::str::contains("--doctor-bin"))
        .stdout(predicate::str::contains("--doctor-timeout-secs"))
        .stdout(predicate::str::contains("--eif-path"))
        .stdout(predicate::str::contains("--host-bin"))
        .stdout(predicate::str::contains("--verifier-bin"))
        .stdout(predicate::str::contains("--expected-security-mode"));
}

#[test]
fn version_prints() {
    smoke()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ephemeralml-smoke-test"));
}

#[test]
fn json_flag_emits_five_stages_always() {
    let output = smoke().arg("--json").output().expect("should run");

    assert_eq!(
        output.status.code(),
        Some(1),
        "smoke-test should exit 1 until the deployed doctor preflight passes"
    );

    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("--json stdout did not parse: {}\n{}", e, stdout));

    assert_eq!(
        parsed.get("overall_status"),
        Some(&serde_json::json!("fail"))
    );
    assert_eq!(
        parsed.get("failed_stage"),
        Some(&serde_json::json!("doctor"))
    );

    let stages = parsed.get("stages").expect("stages[] present");
    let arr = stages.as_array().expect("stages is array");
    assert_eq!(
        arr.len(),
        5,
        "always 5 entries regardless of where fail occurs"
    );

    let names: Vec<&str> = arr
        .iter()
        .map(|s| s.get("stage").unwrap().as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "doctor",
            "enclave_launch",
            "inference",
            "receipt_verify",
            "s3_write"
        ]
    );
}

#[test]
fn early_fail_marks_later_stages_skipped_in_json() {
    let output = smoke().arg("--json").output().expect("should run");
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let stages = parsed.get("stages").unwrap().as_array().unwrap();

    assert_eq!(stages[0].get("status"), Some(&serde_json::json!("fail")));
    for s in &stages[1..] {
        assert_eq!(s.get("status"), Some(&serde_json::json!("skipped")));
        assert_eq!(
            s.get("reason"),
            Some(&serde_json::json!("prior stage failed"))
        );
    }
}

#[test]
fn fixture_version_appears_in_output() {
    let output = smoke().arg("--json").output().expect("should run");
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed.get("fixture_version"), Some(&serde_json::json!("1")));
}
