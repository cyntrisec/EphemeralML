use axum::extract::Multipart;
use axum::http::StatusCode;
use axum::response::{Html, Json};
use ed25519_dalek::VerifyingKey;
use ephemeral_ml_common::receipt_verify::{verify_receipt, VerifyOptions};
use ephemeral_ml_common::AttestationReceipt;

use crate::api_types::{ApiVerifyResponse, ErrorResponse, VerifyRequest};
use crate::templates::LANDING_HTML;

/// `GET /` — landing page with paste/upload form.
pub async fn landing_page() -> Html<&'static str> {
    Html(LANDING_HTML)
}

/// `GET /health` — liveness probe.
pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

/// `POST /api/v1/verify` — verify a receipt from JSON body.
pub async fn verify_json(
    Json(body): Json<VerifyRequest>,
) -> Result<Json<ApiVerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let public_key = parse_hex_public_key(&body.public_key)?;
    let receipt = parse_receipt_value(&body.receipt)?;

    let options = VerifyOptions {
        expected_model: body.expected_model,
        expected_measurement_type: Some(body.measurement_type),
        max_age_secs: body.max_age_secs,
    };

    let result = verify_receipt(&receipt, &public_key, &options);
    Ok(Json(ApiVerifyResponse::from_result(result)))
}

/// `POST /api/v1/verify/upload` — verify a receipt from multipart upload.
///
/// Accepts the same policy fields as the JSON endpoint via text parts:
/// `expected_model`, `measurement_type`, `max_age_secs`.
pub async fn verify_upload(
    mut multipart: Multipart,
) -> Result<Json<ApiVerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut receipt_bytes: Option<Vec<u8>> = None;
    let mut public_key_hex: Option<String> = None;
    let mut expected_model: Option<String> = None;
    let mut measurement_type: String = "any".to_string();
    let mut max_age_secs: u64 = 0;

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
            _ => {} // ignore unknown fields
        }
    }

    let receipt_data = receipt_bytes.ok_or_else(|| bad_request("Missing receipt_file field"))?;
    let key_hex =
        public_key_hex.ok_or_else(|| bad_request("Missing public_key or public_key_file field"))?;

    let public_key = parse_hex_public_key(&key_hex)?;

    // Try CBOR first, then JSON
    let receipt: AttestationReceipt = serde_cbor::from_slice(&receipt_data)
        .or_else(|_| serde_json::from_slice(&receipt_data))
        .map_err(|_| bad_request("Failed to parse receipt (tried CBOR and JSON)"))?;

    let options = VerifyOptions {
        expected_model,
        expected_measurement_type: Some(measurement_type),
        max_age_secs,
    };
    let result = verify_receipt(&receipt, &public_key, &options);
    Ok(Json(ApiVerifyResponse::from_result(result)))
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

/// Parse receipt from a `serde_json::Value`.
///
/// Accepts either a JSON object (deserialized directly) or a base64 string
/// (decoded as CBOR).
fn parse_receipt_value(
    value: &serde_json::Value,
) -> Result<AttestationReceipt, (StatusCode, Json<ErrorResponse>)> {
    match value {
        serde_json::Value::Object(_) => serde_json::from_value(value.clone())
            .map_err(|e| bad_request(format!("Invalid receipt JSON: {}", e))),
        serde_json::Value::String(s) => {
            let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s)
                .map_err(|e| bad_request(format!("Invalid base64 receipt: {}", e)))?;
            serde_cbor::from_slice(&bytes)
                .map_err(|e| bad_request(format!("Invalid CBOR receipt: {}", e)))
        }
        _ => Err(bad_request(
            "receipt must be a JSON object or base64 string",
        )),
    }
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse { error: msg.into() }),
    )
}
