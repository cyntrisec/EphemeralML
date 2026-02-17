use ephemeral_ml_common::receipt_signing::{
    AttestationReceipt, EnclaveMeasurements, ReceiptSigningKey, SecurityMode,
};

/// Start the verifier on a random port and return the base URL.
async fn start_server() -> String {
    let app = ephemeralml_verifier_api::build_router();
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
        .json(&serde_json::json!({
            "receipt": serde_json::to_value(&receipt).unwrap(),
            "public_key": public_key_hex,
        }))
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
    // Tamper with receipt
    receipt.receipt_id = "tampered".to_string();

    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/verify", base))
        .json(&serde_json::json!({
            "receipt": serde_json::to_value(&receipt).unwrap(),
            "public_key": public_key_hex,
        }))
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

    // Axum returns 400 for malformed JSON bodies
    assert!(resp.status() == 400 || resp.status() == 422);
}

#[tokio::test]
async fn test_body_limit() {
    let base = start_server().await;

    let client = reqwest::Client::new();
    // Send >2MB body
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

/// Upload endpoint applies policy options (expected_model) just like the JSON endpoint.
#[tokio::test]
async fn test_upload_applies_policy_options() {
    let base = start_server().await;
    let key = ReceiptSigningKey::generate().unwrap();
    let receipt = make_signed_receipt(&key); // model_id = "minilm-l6-v2"
    let receipt_json = serde_json::to_vec(&receipt).unwrap();
    let public_key_hex = hex::encode(key.public_key_bytes());

    let client = reqwest::Client::new();

    // Upload with wrong expected_model — must fail
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

    // Upload with correct expected_model — must pass
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

/// Any Fail check (even measurements) must produce verified: false.
#[tokio::test]
async fn test_fail_check_means_not_verified() {
    let base = start_server().await;
    let key = ReceiptSigningKey::generate().unwrap();

    // Receipt with invalid measurement lengths (32 bytes instead of 48)
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
        .json(&serde_json::json!({
            "receipt": serde_json::to_value(&receipt).unwrap(),
            "public_key": public_key_hex,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["verified"], false,
        "measurements_present=fail must make verified=false"
    );
    assert_eq!(body["checks"]["signature"], "pass");
    assert_eq!(body["checks"]["measurements_present"], "fail");
}
