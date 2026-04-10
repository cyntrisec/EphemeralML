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
        .map_err(bad_request)?;

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
    let mut attestation_bytes: Option<Vec<u8>> = None;
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
            "attestation_file" => {
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| bad_request(format!("Failed to read attestation_file: {}", e)))?;
                attestation_bytes = Some(data.to_vec());
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
    let public_key = if let Some(key_hex) = public_key_hex {
        parse_hex_public_key(&key_hex)?
    } else if let Some(attestation) = attestation_bytes {
        parse_attestation_public_key(&attestation)?
    } else {
        return Err(bad_request(
            "Missing verification material: provide public_key, public_key_file, or attestation_file",
        ));
    };

    let policy = DispatchPolicy {
        expected_model,
        expected_measurement_type: Some(measurement_type),
        max_age_secs,
        expected_attestation_source,
        expected_image_digest,
    };

    let response =
        verify_dispatch::verify_bytes(&receipt_data, &public_key, &policy).map_err(bad_request)?;

    Ok(Json(response))
}

fn parse_attestation_public_key(
    attestation: &[u8],
) -> Result<VerifyingKey, (StatusCode, Json<ErrorResponse>)> {
    ephemeral_ml_client::receipt_key::extract_key_from_attestation(attestation, false).map_err(
        |e| {
            bad_request(format!(
                "Failed to extract receipt public key from attestation: {}",
                e
            ))
        },
    )
}

/// `GET /api/v1/samples/valid` — generate a fresh signed AIR v1 sample receipt.
///
/// Returns a JSON object with:
/// - `receipt_base64`: base64-encoded AIR v1 COSE_Sign1 (primary format)
/// - `public_key`: Ed25519 public key hex
/// - `format`: "air_v1"
///
/// Uses a deterministic key seed so the key is stable across calls.
pub async fn sample_valid() -> Json<serde_json::Value> {
    use ephemeral_ml_common::air_receipt::build_air_v1;

    let (key, claims) = sample_key_and_claims();
    let receipt_bytes = build_air_v1(&claims, &key).unwrap();
    let receipt_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &receipt_bytes);

    Json(serde_json::json!({
        "receipt_base64": receipt_b64,
        "public_key": hex::encode(key.public_key_bytes()),
        "format": "air_v1",
    }))
}

/// `GET /api/v1/samples/legacy` — generate a fresh signed legacy sample receipt.
///
/// Returns a JSON object with `receipt` (JSON object) and `public_key` (hex).
pub async fn sample_legacy() -> Json<serde_json::Value> {
    use ephemeral_ml_common::receipt_signing::{
        AttestationReceipt, EnclaveMeasurements, ReceiptSigningKey, SecurityMode,
    };

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let key = ReceiptSigningKey::from_parts(signing_key, verifying_key);

    let measurements = EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);
    let mut receipt = AttestationReceipt::new(
        "sample-legacy-receipt".to_string(),
        1,
        SecurityMode::GatewayOnly,
        measurements,
        [0xAA; 32],
        [0xBB; 32],
        [0xCC; 32],
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
        "format": "legacy",
    }))
}

/// Shared deterministic key and AIR v1 claims for sample endpoints.
fn sample_key_and_claims() -> (
    ephemeral_ml_common::receipt_signing::ReceiptSigningKey,
    ephemeral_ml_common::air_receipt::AirReceiptClaims,
) {
    use ephemeral_ml_common::air_receipt::AirReceiptClaims;
    use ephemeral_ml_common::receipt_signing::{EnclaveMeasurements, ReceiptSigningKey};

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let key = ReceiptSigningKey::from_parts(signing_key, verifying_key);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let claims = AirReceiptClaims {
        iss: "cyntrisec.com".to_string(),
        iat: now,
        cti: [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ],
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
        execution_time_ms: 95,
        memory_peak_mb: 64,
        security_mode: "GatewayOnly".to_string(),
        model_hash_scheme: None,
    };

    (key, claims)
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
