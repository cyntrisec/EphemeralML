use ephemeral_ml_common::receipt_signing::{
    AttestationReceipt, EnclaveMeasurements, ReceiptSigningKey, SecurityMode,
};
use ephemeralml_verifier_api::ServerConfig;

/// Start the verifier on a random port with no auth (for backward-compat tests).
async fn start_server() -> String {
    let app = ephemeralml_verifier_api::build_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}

/// Start the verifier with auth enabled.
async fn start_server_with_auth(api_key: &str) -> String {
    let config = ServerConfig {
        api_key: Some(api_key.to_string()),
        requests_per_minute: 0,
        cors_origins: vec![],
    };
    let app = ephemeralml_verifier_api::build_router_with_config(&config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}

/// Start the verifier with rate limiting.
async fn start_server_with_rate_limit(rpm: u32) -> String {
    let config = ServerConfig {
        api_key: None,
        requests_per_minute: rpm,
        cors_origins: vec![],
    };
    let app = ephemeralml_verifier_api::build_router_with_config(&config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
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

// ==========================================================================
// Original backward-compatible tests
// ==========================================================================

#[tokio::test]
async fn test_health() {
    let base = start_server().await;
    let resp = reqwest::get(format!("{}/health", base)).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn test_landing_page() {
    let base = start_server().await;
    let resp = reqwest::get(format!("{}/", base)).await.unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert!(text.contains("EphemeralML"));
    assert!(text.contains("Receipt Verifier"));
}

#[tokio::test]
async fn test_verify_valid_receipt() {
    let base = start_server().await;
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
    assert_eq!(body["checks"]["signature"], "pass");
    assert_eq!(body["checks"]["measurements_present"], "pass");
    assert!(body["verified_at"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_verify_invalid_signature() {
    let base = start_server().await;
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
    assert_eq!(body["checks"]["signature"], "fail");
}

#[tokio::test]
async fn test_verify_bad_key_hex() {
    let base = start_server().await;
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
    let base = start_server().await;

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
    let base = start_server().await;

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
    let base = start_server().await;
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
}

#[tokio::test]
async fn test_upload_applies_policy_options() {
    let base = start_server().await;
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
    assert_eq!(body["checks"]["model_match"], "fail");

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
    assert_eq!(body["checks"]["model_match"], "pass");
}

#[tokio::test]
async fn test_fail_check_means_not_verified() {
    let base = start_server().await;
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
    assert_eq!(body["checks"]["signature"], "pass");
    assert_eq!(body["checks"]["measurements_present"], "fail");
}

// ==========================================================================
// Auth tests
// ==========================================================================

#[tokio::test]
async fn test_auth_success_bearer() {
    let base = start_server_with_auth("test-secret-key-1234").await;
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
    let base = start_server_with_auth("test-secret-key-1234").await;
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
    let base = start_server_with_auth("correct-key").await;
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
    let base = start_server_with_auth("correct-key").await;
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
    let base = start_server_with_auth("secret").await;
    // Health should work without auth
    let resp = reqwest::get(format!("{}/health", base)).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_auth_skips_landing() {
    let base = start_server_with_auth("secret").await;
    // Landing page should work without auth
    let resp = reqwest::get(format!("{}/", base)).await.unwrap();
    assert_eq!(resp.status(), 200);
}

// ==========================================================================
// Rate limiting tests
// ==========================================================================

#[tokio::test]
async fn test_rate_limit_enforced() {
    // Very low limit: 3 requests per minute
    let base = start_server_with_rate_limit(3).await;

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
    let base = start_server_with_rate_limit(1).await;

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
    let base = start_server().await;
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();

    // Request with new fields (attestation_source check should skip since
    // the receipt doesn't have one set)
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
    // These should fail since the test receipt has no attestation_source/image_digest
    assert_eq!(body["checks"]["attestation_source"], "fail");
    assert_eq!(body["checks"]["image_digest"], "fail");
}

#[tokio::test]
async fn test_new_policy_fields_skipped_when_absent() {
    let base = start_server().await;
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key);
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();

    // Request without new fields — should skip those checks
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&verify_request_json(&receipt, &public_key_hex))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["verified"], true);
    assert_eq!(body["checks"]["attestation_source"], "skip");
    assert_eq!(body["checks"]["image_digest"], "skip");
}

#[tokio::test]
async fn test_upload_new_policy_fields() {
    let base = start_server().await;
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
    assert_eq!(body["checks"]["attestation_source"], "fail");
    assert_eq!(body["checks"]["image_digest"], "fail");
}

#[tokio::test]
async fn test_backward_compat_no_new_fields() {
    // Old-style request with only the original fields should still work
    let base = start_server().await;
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
