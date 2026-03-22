use axum::extract::Multipart;
use axum::http::StatusCode;
use axum::response::{Html, Json};
use ed25519_dalek::VerifyingKey;

use crate::api_types::{ErrorResponse, VerifyRequest};
use crate::templates::LANDING_HTML;
use crate::verify_dispatch::{self, DispatchPolicy};
use crate::view_model::TrustCenterResponse;

/// `GET /` — landing page with paste/upload form.
pub async fn landing_page() -> Html<&'static str> {
    Html(LANDING_HTML)
}

/// `GET /health` — liveness probe.
pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

/// `POST /api/v1/verify` — verify a receipt from JSON body.
///
/// Accepts both AIR v1 (base64 COSE_Sign1) and legacy receipts (JSON object or base64 CBOR).
pub async fn verify_json(
    Json(body): Json<VerifyRequest>,
) -> Result<Json<TrustCenterResponse>, (StatusCode, Json<ErrorResponse>)> {
    let public_key = parse_hex_public_key(&body.public_key)?;

    let policy = DispatchPolicy {
        expected_model: body.expected_model,
        expected_measurement_type: Some(body.measurement_type),
        max_age_secs: body.max_age_secs,
        expected_attestation_source: body.expected_attestation_source,
        expected_image_digest: body.expected_image_digest,
    };

    let response = verify_dispatch::verify_json_value(&body.receipt, &public_key, &policy)
        .map_err(|e| bad_request(e))?;

    Ok(Json(response))
}

/// `POST /api/v1/verify/upload` — verify a receipt from multipart upload.
///
/// Accepts the same policy fields as the JSON endpoint via text parts.
/// Automatically detects AIR v1 vs legacy format from the uploaded bytes.
pub async fn verify_upload(
    mut multipart: Multipart,
) -> Result<Json<TrustCenterResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut receipt_bytes: Option<Vec<u8>> = None;
    let mut public_key_hex: Option<String> = None;
    let mut expected_model: Option<String> = None;
    let mut measurement_type: String = "any".to_string();
    let mut max_age_secs: u64 = 0;
    let mut expected_attestation_source: Option<String> = None;
    let mut expected_image_digest: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "receipt_file" => {
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| bad_request(format!("Failed to read receipt_file: {}", e)))?;
                receipt_bytes = Some(data.to_vec());
            }
            "public_key" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| bad_request(format!("Failed to read public_key field: {}", e)))?;
                public_key_hex = Some(text.trim().to_string());
            }
            "public_key_file" => {
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| bad_request(format!("Failed to read public_key_file: {}", e)))?;
                public_key_hex = Some(hex::encode(&data));
            }
            "expected_model" => {
                let text = field.text().await.map_err(|e| {
                    bad_request(format!("Failed to read expected_model field: {}", e))
                })?;
                let trimmed = text.trim().to_string();
                if !trimmed.is_empty() {
                    expected_model = Some(trimmed);
                }
            }
            "measurement_type" => {
                let text = field.text().await.map_err(|e| {
                    bad_request(format!("Failed to read measurement_type field: {}", e))
                })?;
                let trimmed = text.trim().to_string();
                if !trimmed.is_empty() {
                    measurement_type = trimmed;
                }
            }
            "max_age_secs" => {
                let text = field.text().await.map_err(|e| {
                    bad_request(format!("Failed to read max_age_secs field: {}", e))
                })?;
                max_age_secs = text
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| bad_request("max_age_secs must be a non-negative integer"))?;
            }
            "expected_attestation_source" => {
                let text = field.text().await.map_err(|e| {
                    bad_request(format!(
                        "Failed to read expected_attestation_source field: {}",
                        e
                    ))
                })?;
                let trimmed = text.trim().to_string();
                if !trimmed.is_empty() {
                    expected_attestation_source = Some(trimmed);
                }
            }
            "expected_image_digest" => {
                let text = field.text().await.map_err(|e| {
                    bad_request(format!("Failed to read expected_image_digest field: {}", e))
                })?;
                let trimmed = text.trim().to_string();
                if !trimmed.is_empty() {
                    expected_image_digest = Some(trimmed);
                }
            }
            _ => {} // ignore unknown fields
        }
    }

    let receipt_data = receipt_bytes.ok_or_else(|| bad_request("Missing receipt_file field"))?;
    let key_hex =
        public_key_hex.ok_or_else(|| bad_request("Missing public_key or public_key_file field"))?;

    let public_key = parse_hex_public_key(&key_hex)?;

    let policy = DispatchPolicy {
        expected_model,
        expected_measurement_type: Some(measurement_type),
        max_age_secs,
        expected_attestation_source,
        expected_image_digest,
    };

    let response = verify_dispatch::verify_bytes(&receipt_data, &public_key, &policy)
        .map_err(|e| bad_request(e))?;

    Ok(Json(response))
}

/// `GET /api/v1/samples/valid` — generate a fresh signed sample receipt for demo.
///
/// Returns a JSON object with `receipt` (signed, verifiable) and `public_key` (hex).
/// Uses a deterministic key seed so the key is stable across calls.
pub async fn sample_valid() -> Json<serde_json::Value> {
    use ephemeral_ml_common::receipt_signing::{
        AttestationReceipt, EnclaveMeasurements, ReceiptSigningKey, SecurityMode,
    };

    // Deterministic key from fixed seed for demo stability.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let key = ReceiptSigningKey::from_parts(signing_key, verifying_key);

    let measurements = EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);
    let mut receipt = AttestationReceipt::new(
        "sample-demo-receipt".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [0xAA; 32], // attestation_doc_hash
        [0xBB; 32], // request_hash
        [0xCC; 32], // response_hash
        "policy-v1".to_string(),
        1,
        "minilm-l6-v2".to_string(),
        "v1.0".to_string(),
        95,
        64,
    );
    receipt.sign(&key).unwrap();

    Json(serde_json::json!({
        "receipt": serde_json::to_value(&receipt).unwrap(),
        "public_key": hex::encode(key.public_key_bytes()),
    }))
}

/// Parse a hex-encoded Ed25519 public key.
fn parse_hex_public_key(hex_str: &str) -> Result<VerifyingKey, (StatusCode, Json<ErrorResponse>)> {
    let bytes =
        hex::decode(hex_str.trim()).map_err(|_| bad_request("Invalid hex in public_key"))?;
    if bytes.len() != 32 {
        return Err(bad_request(format!(
            "public_key must be 64 hex chars (32 bytes), got {} bytes",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|_| bad_request("Invalid Ed25519 public key"))
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse { error: msg.into() }),
    )
}
