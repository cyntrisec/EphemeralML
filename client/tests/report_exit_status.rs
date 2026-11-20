//! The report program's exit status, checked on the built program.
//!
//! 0: the report was written and passed. 3: the report was written and did not
//! pass. 1: no report was written. 2: the command line was not understood. The
//! program used to exit 0 whenever it wrote a report, whatever the report
//! said, so a caller that read only the exit status took a rejected receipt
//! for an accepted one.

use std::path::{Path, PathBuf};
use std::process::Command;

use ephemeral_ml_common::air_receipt::{build_air_v1, AirReceiptClaims};
use ephemeral_ml_common::receipt_signing::ReceiptSigningKey;
use ephemeral_ml_common::EnclaveMeasurements;

/// A fresh, correctly signed AIR v1 receipt on disk, with the key that verifies it.
struct Fixture {
    dir: PathBuf,
    receipt: PathBuf,
    public_key_hex: String,
}

fn fixture() -> Fixture {
    let dir = std::env::temp_dir().join(format!(
        "ephemeralml-report-exit-status-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let key = ReceiptSigningKey::generate().unwrap();
    let claims = AirReceiptClaims {
        iss: "cyntrisec.com".to_string(),
        iat: ephemeral_ml_common::current_timestamp().unwrap(),
        cti: *uuid::Uuid::new_v4().as_bytes(),
        eat_nonce: None,
        model_id: "minilm-l6-v2".to_string(),
        model_version: "1.0.0".to_string(),
        model_hash: [0xAA; 32],
        request_hash: [0xBB; 32],
        response_hash: [0xCC; 32],
        attestation_doc_hash: [0xDD; 32],
        enclave_measurements: EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]),
        policy_version: "policy-v1".to_string(),
        sequence_number: 1,
        execution_time_ms: 10,
        memory_peak_mb: 64,
        security_mode: "production".to_string(),
        model_hash_scheme: Some("sha256-single".to_string()),
    };
    let receipt = dir.join("receipt.cbor");
    std::fs::write(&receipt, build_air_v1(&claims, &key).unwrap()).unwrap();

    Fixture {
        dir,
        receipt,
        public_key_hex: hex::encode(key.public_key_bytes()),
    }
}

/// Run the program on `receipt`; return its exit status and where the report would be.
fn run(fixture: &Fixture, receipt: &Path, out: &str, extra: &[&str]) -> (Option<i32>, PathBuf) {
    let out_dir = fixture.dir.join(out);
    let output = Command::new(env!("CARGO_BIN_EXE_ephemeralml-report"))
        .arg("--receipt")
        .arg(receipt)
        .arg("--public-key")
        .arg(&fixture.public_key_hex)
        .arg("--output-dir")
        .arg(&out_dir)
        .args(extra)
        .output()
        .expect("the report program should start");
    (
        output.status.code(),
        out_dir.join("verification-report.json"),
    )
}

fn overall_status(report: &Path) -> String {
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    value["overall_status"].as_str().unwrap().to_string()
}

#[test]
fn exit_status_is_zero_only_when_the_report_passes() {
    let fixture = fixture();

    // A receipt that verifies: status 0, and the report says pass.
    let (code, report) = run(&fixture, &fixture.receipt, "pass", &[]);
    assert_eq!(code, Some(0));
    assert_eq!(overall_status(&report), "pass");

    // The same receipt against a model hash it does not carry: the report is
    // still written, it says fail, and now the exit status says so too.
    let wrong_hash = format!("{}01", "00".repeat(31));
    let (code, report) = run(
        &fixture,
        &fixture.receipt,
        "wrong-model-hash",
        &["--expected-model-hash", wrong_hash.as_str()],
    );
    assert_eq!(code, Some(3));
    assert_eq!(overall_status(&report), "fail");

    // The ledger of accepted receipts: accepted once, refused the second time.
    let ledger = fixture.dir.join("ledger.txt");
    let ledger_arg = ledger.to_str().unwrap();
    let (code, report) = run(
        &fixture,
        &fixture.receipt,
        "ledger-first",
        &["--seen-cti-file", ledger_arg],
    );
    assert_eq!(code, Some(0));
    assert_eq!(overall_status(&report), "pass");
    let (code, report) = run(
        &fixture,
        &fixture.receipt,
        "ledger-replay",
        &["--seen-cti-file", ledger_arg],
    );
    assert_eq!(code, Some(3));
    assert_eq!(overall_status(&report), "fail");

    // No report at all, because the receipt file does not exist: status 1.
    let missing = fixture.dir.join("no-such-receipt.cbor");
    let (code, report) = run(&fixture, &missing, "missing-receipt", &[]);
    assert_eq!(code, Some(1));
    assert!(!report.exists());

    // A command line the program does not understand: the parser's status 2,
    // which is why "did not pass" is not 2.
    let (code, report) = run(
        &fixture,
        &fixture.receipt,
        "bad-flag",
        &["--no-such-option"],
    );
    assert_eq!(code, Some(2));
    assert!(!report.exists());

    let _ = std::fs::remove_dir_all(&fixture.dir);
}
