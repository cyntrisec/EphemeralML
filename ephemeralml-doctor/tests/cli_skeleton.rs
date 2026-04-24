//! CLI-level integration tests. Originally pinned the skeleton→real
//! transition; now that all 6 checks are real probes, these tests lock
//! the CLI + exit-code + JSON-shape contract they expose. Any future
//! checks added to the registry must satisfy the same CLI contract.

use assert_cmd::Command;
use predicates::prelude::*;

fn doctor() -> Command {
    Command::cargo_bin("ephemeralml-doctor").expect("binary built by Cargo")
}

#[test]
fn help_exits_zero() {
    doctor()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ephemeralml-doctor"))
        .stdout(predicate::str::contains("--json"))
        .stdout(predicate::str::contains("--check"))
        .stdout(predicate::str::contains("--verbose"))
        .stdout(predicate::str::contains("--stack-name"));
}

#[test]
fn version_prints() {
    doctor()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ephemeralml-doctor"));
}

#[test]
fn unknown_check_exits_two() {
    doctor()
        .args(["--check", "no-such-check"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn json_flag_emits_parseable_json() {
    let output = doctor().arg("--json").output().expect("should run");

    // On a development laptop most probes fail; on CI some may pass if their
    // fixtures and tools are present. The CLI contract is that JSON is emitted
    // and the process exits 0 for all-pass, 1 for any failing check.
    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "doctor --json should exit 0 or 1, got {:?}",
        output.status.code()
    );

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("skeleton --json stdout did not parse: {}\n{}", e, stdout));

    let expected_overall = if output.status.success() {
        "pass"
    } else {
        "fail"
    };
    assert_eq!(
        parsed.get("overall_status"),
        Some(&serde_json::json!(expected_overall))
    );
    let checks = parsed.get("checks").expect("checks[] present");
    let arr = checks.as_array().expect("checks is array");
    assert_eq!(
        arr.len(),
        6,
        "always 6 entries regardless of --check filter"
    );

    // All 6 checks are now real probes. Failing checks must fail cleanly with
    // their own specific check_code; passing checks omit check_code.
    for c in arr {
        let name = c.get("check").unwrap().as_str().unwrap();
        let status = c.get("status").unwrap().as_str().unwrap();
        assert!(
            matches!(status, "ok" | "fail"),
            "check {} produced unknown status {:?}",
            name,
            status
        );
        if status == "fail" {
            let code = c.get("check_code").unwrap().as_str().unwrap();
            assert_ne!(
                code, "SKELETON_UNIMPLEMENTED",
                "check {} should report a specific check_code",
                name
            );
            // Every real check uses an uppercased prefix matching its name
            // (ALLOCATOR_*, EIF_*, ROLE_*, BUCKET_*, KMS_*, CLOCK_*).
            let expected_prefix = format!("{}_", name.to_uppercase());
            assert!(
                code.starts_with(&expected_prefix),
                "check {} produced check_code {:?}, expected prefix {:?}",
                name,
                code,
                expected_prefix
            );
        } else {
            assert!(
                c.get("check_code").is_none_or(serde_json::Value::is_null),
                "passing check {} should not include check_code",
                name
            );
        }
    }
}

#[test]
fn single_check_filter_runs_just_that_check() {
    let output = doctor()
        .args(["--check", "clock", "--json"])
        .output()
        .expect("should run");

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("json parse");
    let arr = parsed
        .get("checks")
        .and_then(|v| v.as_array())
        .expect("checks[]");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0].get("check"), Some(&serde_json::json!("clock")));
}
