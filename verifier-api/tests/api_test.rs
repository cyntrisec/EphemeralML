use ephemeral_ml_common::receipt_signing::{
    AttestationReceipt, EnclaveMeasurements, ReceiptSigningKey, SecurityMode,
};
use ephemeralml_verifier_api::{ServerConfig, ServiceMode};

/// Start the verifier on a random port with no auth (for backward-compat tests).
async fn start_server() -> std::io::Result<String> {
    let app = ephemeralml_verifier_api::build_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Ok(format!("http://{}", addr))
}

/// Start the verifier with auth enabled.
async fn start_server_with_auth(api_key: &str) -> std::io::Result<String> {
    let config = ServerConfig {
        mode: ServiceMode::SecuredApi,
        api_key: Some(api_key.to_string()),
        requests_per_minute: 0,
        cors_origins: vec![],
    };
    let app = ephemeralml_verifier_api::build_router_with_config(&config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Ok(format!("http://{}", addr))
}

/// Start the verifier with rate limiting.
async fn start_server_with_rate_limit(rpm: u32) -> std::io::Result<String> {
    let config = ServerConfig {
        mode: ServiceMode::PublicTrustCenter,
        api_key: None,
        requests_per_minute: rpm,
        cors_origins: vec![],
    };
    let app = ephemeralml_verifier_api::build_router_with_config(&config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Ok(format!("http://{}", addr))
}

macro_rules! require_base {
    ($future:expr) => {{
        match $future.await {
            Ok(base) => base,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "skipping verifier-api loopback test: loopback bind not permitted: {}",
                    err
                );
                return;
            }
            Err(err) => panic!(
                "verifier-api test failed to bind loopback listener: {}",
                err
            ),
        }
    }};
}

fn make_signed_receipt(key: &ReceiptSigningKey) -> AttestationReceipt {
    let measurements = EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);
    let mut receipt = AttestationReceipt::new(
        "test-receipt-api".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [4u8; 32],
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        1,
        "minilm-l6-v2".to_string(),
        "v1.0".to_string(),
        100,
        64,
    );
    receipt.sign(key).unwrap();
    receipt
}

fn verify_request_json(receipt: &AttestationReceipt, public_key_hex: &str) -> serde_json::Value {
    serde_json::json!({
        "receipt": serde_json::to_value(receipt).unwrap(),
        "public_key": public_key_hex,
    })
}

/// Helper: extract check status from the new `checks` array by check id.
fn check_status(body: &serde_json::Value, check_id: &str) -> String {
    body["checks"]
        .as_array()
        .expect("checks should be an array")
        .iter()
        .find(|c| c["id"].as_str() == Some(check_id))
        .unwrap_or_else(|| panic!("check '{}' not found in response", check_id))["status"]
        .as_str()
        .unwrap()
        .to_string()
}

fn pcr48_hex(byte: u8) -> String {
    hex::encode([byte; 48])
}

// ==========================================================================
// Original backward-compatible tests
// ==========================================================================

#[tokio::test]
async fn test_health() {
    let base = require_base!(start_server());
    let resp = reqwest::get(format!("{}/health", base)).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn test_landing_page() {
    let base = require_base!(start_server());
    let resp = reqwest::get(format!("{}/", base)).await.unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(
        text.contains("EphemeralML")
            || text.contains("Cyntrisec")
            || text.contains("Verification Center")
    );
    assert!(text.contains("Verif"));
}

#[tokio::test]
async fn test_public_aws_native_poc_evidence_page() {
    let base = require_base!(start_server());
    let resp = reqwest::get(format!("{}/evidence/aws-native-poc", base))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    // Page identity
    assert!(text.contains("AWS-Native Nitro PoC Evidence"));
    assert!(text.contains("PASS"));
    assert!(text.contains("REDACTED EVIDENCE"));
    // 2026-05-03 Verification Center packet, not the old 2026-04-30 benchmark
    assert!(
        text.contains("2026-05-03"),
        "evidence page must reference the 2026-05-03 run"
    );
    assert!(
        text.contains("artifacts/verification-center/aws-native-poc-20260503"),
        "evidence page must reference the current 2026-05-03 artifact path"
    );
    assert!(
        !text.contains("2026-04-30"),
        "evidence page must not reference the stale 2026-04-30 run"
    );
    assert!(
        !text.contains("artifacts/benchmarks/aws-native-poc-20260430"),
        "evidence page must not reference the stale benchmark artifact path"
    );
    // Runtime Passport + Execution Report surfaces are described
    assert!(
        text.contains("Runtime Passport") || text.contains("RUNTIME PASSPORT"),
        "evidence page must describe the Runtime Passport"
    );
    assert!(
        text.contains("Execution Report") || text.contains("EXECUTION REPORT"),
        "evidence page must describe the Execution Report"
    );
    assert!(
        text.contains("tee_provenance"),
        "evidence page must state the tee_provenance assurance level"
    );
    // Unsigned-EIF internal-PoC limitation is prominent
    assert!(
        text.contains("UNSIGNED EIF"),
        "evidence page must lead with the unsigned-EIF limitation"
    );
    assert!(
        text.contains("CYNTRISEC_DOCTOR_ALLOW_UNSIGNED_EIF_FOR_POC"),
        "evidence page must name the explicit override env var"
    );
    // Privacy guardrails: no raw account ID, ARN, instance ID, or live bucket
    assert!(
        !text.contains("272493677165"),
        "evidence page must not contain the real AWS account ID"
    );
    assert!(
        !text.contains("arn:aws"),
        "evidence page must not contain raw arn:aws references"
    );
    assert!(
        !text.contains("ephemeralml-pilot-evidence-272"),
        "evidence page must not contain a live bucket name"
    );
}

#[tokio::test]
async fn test_verify_valid_receipt() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&verify_request_json(&receipt, &public_key_hex))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], true);
    assert_eq!(body["api_version"], "v1");
    assert_eq!(body["format"], "legacy");
    assert_eq!(check_status(&body, "signature"), "pass");
    assert_eq!(check_status(&body, "measurements_present"), "pass");
    assert!(body["verified_at"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_verify_invalid_signature() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let mut receipt = make_signed_receipt(&key);
    receipt.receipt_id = "tampered".to_string();

    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&verify_request_json(&receipt, &public_key_hex))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], false);
    assert_eq!(check_status(&body, "signature"), "fail");
}

#[tokio::test]
async fn test_verify_bad_key_hex() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": serde_json::to_value(&receipt).unwrap(),
            "public_key": "not-valid-hex",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("hex"));
}

#[tokio::test]
async fn test_verify_bad_json() {
    let base = require_base!(start_server());

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .header("content-type", "application/json")
        .body("{invalid json")
        .send()
        .await
        .unwrap();

    assert!(resp.status() == 400 || resp.status() == 422);
}

#[tokio::test]
async fn test_body_limit() {
    let base = require_base!(start_server());

    let client = reqwest::Client::new();
    let big_body = "x".repeat(3 * 1024 * 1024);
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .header("content-type", "application/json")
        .body(big_body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn test_verify_upload_multipart() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let receipt_json = serde_json::to_vec(&receipt).unwrap();
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new()
        .part(
            "receipt_file",
            reqwest::multipart::Part::bytes(receipt_json).file_name("receipt.json"),
        )
        .text("public_key", public_key_hex);

    let resp = client
        .post(format!("{}/api/v1/verify/upload", base))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], true);
    assert_eq!(body["format"], "legacy");
}

#[tokio::test]
async fn test_upload_applies_policy_options() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let receipt_json = serde_json::to_vec(&receipt).unwrap();
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();

    // Wrong expected_model
    let form = reqwest::multipart::Form::new()
        .part(
            "receipt_file",
            reqwest::multipart::Part::bytes(receipt_json.clone()).file_name("receipt.json"),
        )
        .text("public_key", public_key_hex.clone())
        .text("expected_model", "wrong-model");

    let resp = client
        .post(format!("{}/api/v1/verify/upload", base))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], false);
    assert_eq!(check_status(&body, "model_match"), "fail");

    // Correct expected_model
    let form = reqwest::multipart::Form::new()
        .part(
            "receipt_file",
            reqwest::multipart::Part::bytes(receipt_json).file_name("receipt.json"),
        )
        .text("public_key", public_key_hex)
        .text("expected_model", "minilm-l6-v2");

    let resp = client
        .post(format!("{}/api/v1/verify/upload", base))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], true);
    assert_eq!(check_status(&body, "model_match"), "pass");
}

#[tokio::test]
async fn test_fail_check_means_not_verified() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();

    let measurements = EnclaveMeasurements::new(vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]);
    let mut receipt = AttestationReceipt::new(
        "bad-meas".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [4u8; 32],
        [5u8; 32],
        [6u8; 32],
        "policy-v1".to_string(),
        1,
        "model".to_string(),
        "v1".to_string(),
        100,
        64,
    );
    receipt.sign(&key).unwrap();

    let public_key_hex = hex::encode(key.public_key_bytes());
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&verify_request_json(&receipt, &public_key_hex))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], false);
    assert_eq!(check_status(&body, "signature"), "pass");
    assert_eq!(check_status(&body, "measurements_present"), "fail");
}

// ==========================================================================
// Auth tests
// ==========================================================================

#[tokio::test]
async fn test_auth_success_bearer() {
    let base = require_base!(start_server_with_auth("test-secret-key-1234"));
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .header("authorization", "Bearer test-secret-key-1234")
        .json(&verify_request_json(&receipt, &public_key_hex))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], true);
}

#[tokio::test]
async fn test_auth_success_x_api_key() {
    let base = require_base!(start_server_with_auth("test-secret-key-1234"));
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .header("x-api-key", "test-secret-key-1234")
        .json(&verify_request_json(&receipt, &public_key_hex))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], true);
}

#[tokio::test]
async fn test_auth_failure_wrong_key() {
    let base = require_base!(start_server_with_auth("correct-key"));
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .header("authorization", "Bearer wrong-key")
        .json(&verify_request_json(&receipt, &public_key_hex))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("Invalid"));
}

#[tokio::test]
async fn test_auth_failure_missing_key() {
    let base = require_base!(start_server_with_auth("correct-key"));
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&verify_request_json(&receipt, &public_key_hex))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("Missing"));
}

#[tokio::test]
async fn test_auth_skips_health() {
    let base = require_base!(start_server_with_auth("secret"));
    // Health should work without auth
    let resp = reqwest::get(format!("{}/health", base)).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_auth_skips_landing() {
    let base = require_base!(start_server_with_auth("secret"));
    // Landing page should work without auth
    let resp = reqwest::get(format!("{}/", base)).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_auth_skips_samples() {
    let base = require_base!(start_server_with_auth("secret"));
    // Sample endpoints should work without auth (they serve demo data)
    let resp = reqwest::get(format!("{}/api/v1/samples/valid", base))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["receipt_base64"].is_string());

    let resp = reqwest::get(format!("{}/api/v1/samples/legacy", base))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["receipt"].is_object());
}

#[tokio::test]
async fn test_auth_skips_public_evidence() {
    let base = require_base!(start_server_with_auth("secret"));
    let resp = reqwest::get(format!("{}/evidence/aws-native-poc", base))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(text.contains("AWS-Native Nitro PoC Evidence"));
    // Even under auth-protected mode, the redacted evidence page must show
    // the current 2026-05-03 packet, not the stale benchmark artifact.
    assert!(text.contains("2026-05-03"));
    assert!(!text.contains("artifacts/benchmarks/aws-native-poc-20260430"));
}

// ==========================================================================
// Rate limiting tests
// ==========================================================================

#[tokio::test]
async fn test_rate_limit_enforced() {
    // Very low limit: 3 requests per minute
    let base = require_base!(start_server_with_rate_limit(3));

    let client = reqwest::Client::new();
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());
    let body = verify_request_json(&receipt, &public_key_hex);

    // First 3 requests should succeed
    for i in 0..3 {
        let resp = client
            .post(format!("{}/api/v1/verify", base))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "Request {} should succeed", i + 1);
    }

    // 4th request should be rate limited
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
    let err: serde_json::Value = resp.json().await.unwrap();
    assert!(err["error"].as_str().unwrap().contains("Rate limit"));
}

#[tokio::test]
async fn test_rate_limit_skips_health() {
    let base = require_base!(start_server_with_rate_limit(1));

    // Health endpoint should not be rate limited
    for _ in 0..5 {
        let resp = reqwest::get(format!("{}/health", base)).await.unwrap();
        assert_eq!(resp.status(), 200);
    }
}

// ==========================================================================
// New policy field tests
// ==========================================================================

#[tokio::test]
async fn test_new_policy_fields_accepted() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": serde_json::to_value(&receipt).unwrap(),
            "public_key": public_key_hex,
            "expected_attestation_source": "cs-tdx",
            "expected_image_digest": "sha256:abc123",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(check_status(&body, "attestation_source"), "fail");
    assert_eq!(check_status(&body, "image_digest"), "fail");
}

#[tokio::test]
async fn test_new_policy_fields_skipped_when_absent() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&verify_request_json(&receipt, &public_key_hex))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], true);
    assert_eq!(check_status(&body, "attestation_source"), "skip");
    assert_eq!(check_status(&body, "image_digest"), "skip");
}

#[tokio::test]
async fn test_upload_new_policy_fields() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let receipt_json = serde_json::to_vec(&receipt).unwrap();
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new()
        .part(
            "receipt_file",
            reqwest::multipart::Part::bytes(receipt_json).file_name("receipt.json"),
        )
        .text("public_key", public_key_hex)
        .text("expected_attestation_source", "cs-tdx")
        .text("expected_image_digest", "sha256:abc");

    let resp = client
        .post(format!("{}/api/v1/verify/upload", base))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(check_status(&body, "attestation_source"), "fail");
    assert_eq!(check_status(&body, "image_digest"), "fail");
}

#[tokio::test]
async fn test_backward_compat_no_new_fields() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": serde_json::to_value(&receipt).unwrap(),
            "public_key": public_key_hex,
            "expected_model": "minilm-l6-v2",
            "max_age_secs": 0,
            "measurement_type": "any",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], true);
}

// ==========================================================================
// AIR v1 integration tests
// ==========================================================================

fn make_air_v1_receipt(key: &ReceiptSigningKey) -> Vec<u8> {
    make_air_v1_receipt_with_security_mode(key, "production")
}

fn make_air_v1_receipt_with_security_mode(key: &ReceiptSigningKey, security_mode: &str) -> Vec<u8> {
    use ephemeral_ml_common::air_receipt::{build_air_v1, AirReceiptClaims};
    use ephemeral_ml_common::receipt_signing::EnclaveMeasurements;

    let claims = AirReceiptClaims {
        iss: "cyntrisec.com".to_string(),
        iat: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        cti: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
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
        execution_time_ms: 100,
        memory_peak_mb: 64,
        security_mode: security_mode.to_string(),
        model_hash_scheme: None,
    };
    build_air_v1(&claims, key).unwrap()
}

#[tokio::test]
async fn test_air_v1_upload_valid() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt_bytes = make_air_v1_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new()
        .part(
            "receipt_file",
            reqwest::multipart::Part::bytes(receipt_bytes).file_name("receipt.cbor"),
        )
        .text("public_key", public_key_hex);

    let resp = client
        .post(format!("{}/api/v1/verify/upload", base))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], true);
    assert_eq!(body["format"], "air_v1");
    assert_eq!(body["verdict"], "verified");
    assert!(body["receipt"]["model_id"].as_str().unwrap() == "minilm-l6-v2");
    assert!(body["receipt"]["issuer"].as_str().unwrap() == "cyntrisec.com");
}

#[tokio::test]
async fn test_air_v1_upload_tampered() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let mut receipt_bytes = make_air_v1_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    // Tamper: flip a byte in the payload area (after the COSE header).
    if receipt_bytes.len() > 50 {
        receipt_bytes[50] ^= 0xFF;
    }

    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new()
        .part(
            "receipt_file",
            reqwest::multipart::Part::bytes(receipt_bytes).file_name("receipt.cbor"),
        )
        .text("public_key", public_key_hex);

    let resp = client
        .post(format!("{}/api/v1/verify/upload", base))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    // Should fail verification (tampered data)
    assert_eq!(body["verified"], false);
    assert_eq!(body["verdict"], "invalid");
}

#[tokio::test]
async fn test_air_v1_json_base64() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt_bytes = make_air_v1_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    // Encode as base64 for the JSON endpoint
    let receipt_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &receipt_bytes);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": receipt_b64.clone(),
            "public_key": public_key_hex.clone(),
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], true);
    assert_eq!(body["format"], "air_v1");
    assert_eq!(body["assurance_level"], "air_local");
    assert_eq!(body["tee_provenance_verified"], false);
    assert_eq!(check_status(&body, "attestation_doc_hash"), "skip");
    assert_eq!(check_status(&body, "signing_key_binding"), "skip");
    assert_eq!(check_status(&body, "platform_attestation"), "skip");
}

#[tokio::test]
async fn test_air_v1_json_expected_model_hash_enforced() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt_bytes = make_air_v1_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());
    let receipt_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &receipt_bytes);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": receipt_b64,
            "public_key": public_key_hex,
            "expected_model_hash_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], false);
    assert_eq!(check_status(&body, "MHASH"), "fail");
}

#[tokio::test]
async fn test_air_v1_json_expected_request_hash_enforced() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt_bytes = make_air_v1_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());
    let receipt_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &receipt_bytes);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": receipt_b64,
            "public_key": public_key_hex,
            "expected_request_hash_hex": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], false);
    assert_eq!(check_status(&body, "RHASH"), "fail");
}

#[tokio::test]
async fn test_air_v1_evaluation_mode_rejected_by_production_verifier() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt_bytes = make_air_v1_receipt_with_security_mode(&key, "evaluation");
    let public_key_hex = hex::encode(key.public_key_bytes());
    let receipt_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &receipt_bytes);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": receipt_b64,
            "public_key": public_key_hex,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], false);
    assert_eq!(check_status(&body, "SECURITY_MODE_POLICY"), "fail");

    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": receipt_b64,
            "public_key": public_key_hex,
            "expected_security_mode": "evaluation",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("evaluation verifier"));
}

#[tokio::test]
async fn test_verify_rejects_unknown_json_fields() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt_bytes = make_air_v1_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());
    let receipt_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &receipt_bytes);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": receipt_b64,
            "public_key": public_key_hex,
            "expected_model_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        }))
        .send()
        .await
        .unwrap();

    assert!(
        resp.status() == 400 || resp.status() == 422,
        "unexpected status: {}",
        resp.status()
    );
}

#[tokio::test]
async fn test_air_v1_upload_attestation_mismatch_rejects_tee_provenance() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt_bytes = make_air_v1_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new()
        .part(
            "receipt_file",
            reqwest::multipart::Part::bytes(receipt_bytes).file_name("receipt.cbor"),
        )
        .text("public_key", public_key_hex)
        .part(
            "attestation_file",
            reqwest::multipart::Part::bytes(vec![0xA0]).file_name("attestation.cbor"),
        );

    let resp = client
        .post(format!("{}/api/v1/verify/upload", base))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], false);
    assert_eq!(body["format"], "air_v1");
    assert_eq!(body["assurance_level"], "air_local");
    assert_eq!(body["tee_provenance_verified"], false);
    assert_eq!(check_status(&body, "attestation_doc_hash"), "fail");
    assert_eq!(check_status(&body, "platform_attestation"), "fail");
    assert_eq!(check_status(&body, "signing_key_binding"), "fail");
}

#[tokio::test]
async fn test_air_v1_upload_partial_pcr_policy_rejected() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt_bytes = make_air_v1_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new()
        .part(
            "receipt_file",
            reqwest::multipart::Part::bytes(receipt_bytes).file_name("receipt.cbor"),
        )
        .text("public_key", public_key_hex)
        .text("expected_pcr0_hex", pcr48_hex(0xAA));

    let resp = client
        .post(format!("{}/api/v1/verify/upload", base))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("must be supplied together"));
}

#[tokio::test]
async fn test_air_v1_wrong_key() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt_bytes = make_air_v1_receipt(&key);

    // Use a different key for verification
    let wrong_key = ReceiptSigningKey::generate().unwrap();
    let wrong_key_hex = hex::encode(wrong_key.public_key_bytes());

    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new()
        .part(
            "receipt_file",
            reqwest::multipart::Part::bytes(receipt_bytes).file_name("receipt.cbor"),
        )
        .text("public_key", wrong_key_hex);

    let resp = client
        .post(format!("{}/api/v1/verify/upload", base))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], false);
    assert_eq!(body["format"], "air_v1");
    // Should have a signature failure in checks
    assert!(body["errors"].as_array().unwrap().iter().any(|e| {
        e.as_str().unwrap().contains("Signature") || e.as_str().unwrap().contains("SIG")
    }));
}

// ==========================================================================
// Response shape tests (new)
// ==========================================================================

#[tokio::test]
async fn test_response_has_trust_center_shape() {
    let base = require_base!(start_server());
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&verify_request_json(&receipt, &public_key_hex))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    // New trust-center response fields
    assert_eq!(body["verdict"], "verified");
    assert_eq!(body["format"], "legacy");
    assert!(body["receipt"]["receipt_id"].is_string());
    assert!(body["receipt"]["model_id"].is_string());
    assert!(body["checks"].is_array());
    assert!(body["checks"].as_array().unwrap().len() >= 5);

    // Each check has id, label, status
    let first_check = &body["checks"][0];
    assert!(first_check["id"].is_string());
    assert!(first_check["label"].is_string());
    assert!(first_check["status"].is_string());
}

// ==========================================================================
// Sample endpoint tests
// ==========================================================================

#[tokio::test]
async fn test_sample_air_v1_produces_verifiable_receipt() {
    let base = require_base!(start_server());
    let client = reqwest::Client::new();

    // Fetch the AIR v1 sample
    let sample_resp = client
        .get(format!("{}/api/v1/samples/valid", base))
        .send()
        .await
        .unwrap();
    assert_eq!(sample_resp.status(), 200);
    let sample: serde_json::Value = sample_resp.json().await.unwrap();
    assert!(
        sample["receipt_base64"].is_string(),
        "AIR v1 sample must have receipt_base64"
    );
    assert_eq!(sample["format"], "air_v1");
    assert!(sample["public_key"].is_string());

    // Verify it — should pass (send base64 as string value)
    let verify_resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": sample["receipt_base64"],
            "public_key": sample["public_key"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 200);
    let body: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(
        body["verified"], true,
        "AIR v1 sample must verify: {:?}",
        body["errors"]
    );
    assert_eq!(body["verdict"], "verified");
    assert_eq!(body["format"], "air_v1");

    // Tamper the base64 and verify — should fail
    let b64 = sample["receipt_base64"].as_str().unwrap();
    let mid = b64.len() / 2;
    let tampered_b64 = format!("{}TAMPERED{}", &b64[..mid], &b64[mid + 8..]);
    let tamper_resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": tampered_b64,
            "public_key": sample["public_key"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(tamper_resp.status(), 200);
    let tamper_body: serde_json::Value = tamper_resp.json().await.unwrap();
    assert_eq!(tamper_body["verified"], false, "Tampered AIR v1 must fail");
}

#[tokio::test]
async fn test_sample_legacy_produces_verifiable_receipt() {
    let base = require_base!(start_server());
    let client = reqwest::Client::new();

    // Fetch the legacy sample
    let sample_resp = client
        .get(format!("{}/api/v1/samples/legacy", base))
        .send()
        .await
        .unwrap();
    assert_eq!(sample_resp.status(), 200);
    let sample: serde_json::Value = sample_resp.json().await.unwrap();
    assert!(
        sample["receipt"].is_object(),
        "Legacy sample must have receipt object"
    );
    assert_eq!(sample["format"], "legacy");

    // Verify it — should pass
    let verify_resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": sample["receipt"],
            "public_key": sample["public_key"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 200);
    let body: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(
        body["verified"], true,
        "Legacy sample must verify: {:?}",
        body["errors"]
    );
    assert_eq!(body["format"], "legacy");
}
