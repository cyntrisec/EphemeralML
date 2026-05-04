use axum::extract::Multipart;
use axum::http::StatusCode;
use axum::response::{Html, Json};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::api_types::{ErrorResponse, VerifyRequest};
use crate::templates::{AWS_NATIVE_POC_HTML, LANDING_HTML};
use crate::verify_dispatch::{self, DispatchPolicy, ExpectedPcrs};
use crate::view_model::{CheckStatus, ReceiptFormat, TrustCenterCheck, TrustCenterResponse};

/// `GET /` — landing page with paste/upload form.
pub async fn landing_page() -> Html<&'static str> {
    Html(LANDING_HTML)
}

/// `GET /evidence/aws-native-poc` — public redacted AWS-native PoC evidence page.
pub async fn aws_native_poc_evidence() -> Html<&'static str> {
    Html(AWS_NATIVE_POC_HTML)
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
    let expected_model_hash = parse_optional_hash32_hex(
        body.expected_model_hash_hex.as_deref(),
        "expected_model_hash_hex",
    )?;
    let expected_request_hash = parse_optional_hash32_hex(
        body.expected_request_hash_hex.as_deref(),
        "expected_request_hash_hex",
    )?;
    let expected_response_hash = parse_optional_hash32_hex(
        body.expected_response_hash_hex.as_deref(),
        "expected_response_hash_hex",
    )?;
    let expected_pcrs = parse_expected_pcrs(
        body.expected_pcr0_hex.as_deref(),
        body.expected_pcr1_hex.as_deref(),
        body.expected_pcr2_hex.as_deref(),
    )?;
    let expected_security_mode =
        parse_expected_security_mode(body.expected_security_mode.as_deref())?;

    let policy = DispatchPolicy {
        expected_model: body.expected_model,
        expected_model_hash,
        expected_request_hash,
        expected_response_hash,
        expected_pcrs,
        expected_security_mode,
        expected_measurement_type: Some(body.measurement_type),
        max_age_secs: body.max_age_secs,
        expected_attestation_source: body.expected_attestation_source,
        expected_image_digest: body.expected_image_digest,
    };

    let mut response = verify_dispatch::verify_json_value(&body.receipt, &public_key, &policy)
        .map_err(bad_request)?;
    annotate_air_provenance(
        &mut response,
        None,
        None,
        None,
        policy.expected_pcrs.as_ref(),
    );

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
    let mut expected_model_hash: Option<[u8; 32]> = None;
    let mut expected_request_hash: Option<[u8; 32]> = None;
    let mut expected_response_hash: Option<[u8; 32]> = None;
    let mut expected_pcr0: Option<[u8; 48]> = None;
    let mut expected_pcr1: Option<[u8; 48]> = None;
    let mut expected_pcr2: Option<[u8; 48]> = None;
    let mut expected_security_mode: Option<String> = None;
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
            "expected_model_hash_hex" => {
                let text = field.text().await.map_err(|e| {
                    bad_request(format!(
                        "Failed to read expected_model_hash_hex field: {}",
                        e
                    ))
                })?;
                expected_model_hash =
                    parse_optional_hash32_hex(Some(text.trim()), "expected_model_hash_hex")?;
            }
            "expected_request_hash_hex" => {
                let text = field.text().await.map_err(|e| {
                    bad_request(format!(
                        "Failed to read expected_request_hash_hex field: {}",
                        e
                    ))
                })?;
                expected_request_hash =
                    parse_optional_hash32_hex(Some(text.trim()), "expected_request_hash_hex")?;
            }
            "expected_response_hash_hex" => {
                let text = field.text().await.map_err(|e| {
                    bad_request(format!(
                        "Failed to read expected_response_hash_hex field: {}",
                        e
                    ))
                })?;
                expected_response_hash =
                    parse_optional_hash32_hex(Some(text.trim()), "expected_response_hash_hex")?;
            }
            "expected_pcr0_hex" => {
                let text = field.text().await.map_err(|e| {
                    bad_request(format!("Failed to read expected_pcr0_hex field: {}", e))
                })?;
                expected_pcr0 = parse_optional_hash48_hex(Some(text.trim()), "expected_pcr0_hex")?;
            }
            "expected_pcr1_hex" => {
                let text = field.text().await.map_err(|e| {
                    bad_request(format!("Failed to read expected_pcr1_hex field: {}", e))
                })?;
                expected_pcr1 = parse_optional_hash48_hex(Some(text.trim()), "expected_pcr1_hex")?;
            }
            "expected_pcr2_hex" => {
                let text = field.text().await.map_err(|e| {
                    bad_request(format!("Failed to read expected_pcr2_hex field: {}", e))
                })?;
                expected_pcr2 = parse_optional_hash48_hex(Some(text.trim()), "expected_pcr2_hex")?;
            }
            "expected_security_mode" => {
                let text = field.text().await.map_err(|e| {
                    bad_request(format!(
                        "Failed to read expected_security_mode field: {}",
                        e
                    ))
                })?;
                let trimmed = text.trim().to_string();
                if !trimmed.is_empty() {
                    expected_security_mode = parse_expected_security_mode(Some(&trimmed))?;
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
            _ => return Err(bad_request(format!("Unknown form field: {}", name))),
        }
    }

    let receipt_data = receipt_bytes.ok_or_else(|| bad_request("Missing receipt_file field"))?;
    let expected_pcrs = parse_expected_pcrs_arrays(expected_pcr0, expected_pcr1, expected_pcr2)?;
    let public_key = if let Some(key_hex) = public_key_hex {
        parse_hex_public_key(&key_hex)?
    } else if let Some(attestation) = attestation_bytes.as_deref() {
        parse_attestation_public_key(attestation)?
    } else {
        return Err(bad_request(
            "Missing verification material: provide public_key, public_key_file, or attestation_file",
        ));
    };

    let policy = DispatchPolicy {
        expected_model,
        expected_model_hash,
        expected_request_hash,
        expected_response_hash,
        expected_pcrs,
        expected_security_mode,
        expected_measurement_type: Some(measurement_type),
        max_age_secs,
        expected_attestation_source,
        expected_image_digest,
    };

    let mut response =
        verify_dispatch::verify_bytes(&receipt_data, &public_key, &policy).map_err(bad_request)?;
    annotate_air_provenance(
        &mut response,
        Some(&receipt_data),
        Some(&public_key),
        attestation_bytes.as_deref(),
        policy.expected_pcrs.as_ref(),
    );

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

fn annotate_air_provenance(
    response: &mut TrustCenterResponse,
    receipt_data: Option<&[u8]>,
    public_key: Option<&VerifyingKey>,
    attestation: Option<&[u8]>,
    expected_pcrs: Option<&ExpectedPcrs>,
) {
    if !matches!(response.format, ReceiptFormat::AirV1) {
        return;
    }

    let Some(attestation) = attestation else {
        response.add_check(provenance_check(
            "attestation_doc_hash",
            "Attestation document hash",
            CheckStatus::Skip,
            "tee_provenance",
            Some("no attestation_file supplied; AIR-local verification only".to_string()),
        ));
        response.add_check(provenance_check(
            "signing_key_binding",
            "Signing key binding",
            CheckStatus::Skip,
            "tee_provenance",
            Some("no attestation_file supplied; cannot bind AIR signing key to a TEE".to_string()),
        ));
        response.add_check(provenance_check(
            "platform_attestation",
            "Platform attestation authenticity",
            CheckStatus::Skip,
            "tee_provenance",
            Some(
                "no attestation_file supplied; platform attestation was not appraised".to_string(),
            ),
        ));
        response.add_warning(
            "AIR-local verification only: no attestation_file was supplied, so TEE provenance was not verified.",
        );
        return;
    };

    let Some(receipt_data) = receipt_data else {
        response.add_warning(
            "TEE provenance was not checked because the verifier did not receive raw AIR receipt bytes.",
        );
        return;
    };
    let Some(public_key) = public_key else {
        response.add_warning(
            "TEE provenance was not checked because the verifier did not receive the AIR signing public key.",
        );
        return;
    };

    let parsed = ephemeral_ml_common::air_receipt::parse_air_v1(receipt_data);
    let mut hash_ok = false;
    match parsed {
        Ok(parsed) => {
            let actual_hash: [u8; 32] = Sha256::digest(attestation).into();
            if actual_hash == parsed.claims.attestation_doc_hash {
                hash_ok = true;
                response.add_check(provenance_check(
                    "attestation_doc_hash",
                    "Attestation document hash",
                    CheckStatus::Pass,
                    "tee_provenance",
                    None,
                ));
            } else {
                response.add_check(provenance_check(
                    "attestation_doc_hash",
                    "Attestation document hash",
                    CheckStatus::Fail,
                    "tee_provenance",
                    Some(format!(
                        "expected {}, got {}",
                        hex::encode(parsed.claims.attestation_doc_hash),
                        hex::encode(actual_hash)
                    )),
                ));
            }
        }
        Err(err) => {
            response.add_check(provenance_check(
                "attestation_doc_hash",
                "Attestation document hash",
                CheckStatus::Fail,
                "tee_provenance",
                Some(format!(
                    "failed to parse AIR receipt for attestation binding: {err}"
                )),
            ));
        }
    }

    let mut platform_ok = false;
    let mut key_binding_ok = false;
    let mut runtime_policy_ok = false;
    match verify_attestation_identity(attestation) {
        Ok(identity) => {
            platform_ok = true;
            response.add_check(provenance_check(
                "platform_attestation",
                "Platform attestation authenticity",
                CheckStatus::Pass,
                "tee_provenance",
                Some("attestation COSE signature and certificate chain accepted".to_string()),
            ));

            if identity.receipt_signing_key == public_key.to_bytes() {
                key_binding_ok = true;
                response.add_check(provenance_check(
                    "signing_key_binding",
                    "Signing key binding",
                    CheckStatus::Pass,
                    "tee_provenance",
                    None,
                ));
            } else {
                response.add_check(provenance_check(
                    "signing_key_binding",
                    "Signing key binding",
                    CheckStatus::Fail,
                    "tee_provenance",
                    Some(format!(
                        "attestation public key {} does not match receipt verification key {}",
                        hex::encode(identity.receipt_signing_key),
                        hex::encode(public_key.to_bytes())
                    )),
                ));
            }

            match expected_pcrs {
                Some(expected) if pcrs_match(&identity.measurements, expected) => {
                    runtime_policy_ok = true;
                    response.add_check(provenance_check(
                        "runtime_measurement_policy",
                        "Runtime measurement policy",
                        CheckStatus::Pass,
                        "tee_provenance",
                        None,
                    ));
                }
                Some(expected) => {
                    response.add_check(provenance_check(
                        "runtime_measurement_policy",
                        "Runtime measurement policy",
                        CheckStatus::Fail,
                        "tee_provenance",
                        Some(format!(
                            "expected PCR0/PCR1/PCR2 {}/{}/{}, got {}/{}/{}",
                            hex::encode(expected.pcr0),
                            hex::encode(expected.pcr1),
                            hex::encode(expected.pcr2),
                            hex::encode(&identity.measurements.pcr0),
                            hex::encode(&identity.measurements.pcr1),
                            hex::encode(&identity.measurements.pcr2)
                        )),
                    ));
                }
                None => {
                    response.add_check(provenance_check(
                        "runtime_measurement_policy",
                        "Runtime measurement policy",
                        CheckStatus::Skip,
                        "tee_provenance",
                        Some(
                            "no expected_pcr0_hex/expected_pcr1_hex/expected_pcr2_hex policy supplied; \
                             platform attestation is verified but the runtime is not allowlisted"
                                .to_string(),
                        ),
                    ));
                }
            }
        }
        Err(err) => {
            response.add_check(provenance_check(
                "platform_attestation",
                "Platform attestation authenticity",
                CheckStatus::Fail,
                "tee_provenance",
                Some(err.to_string()),
            ));
            response.add_check(provenance_check(
                "signing_key_binding",
                "Signing key binding",
                CheckStatus::Fail,
                "tee_provenance",
                Some(
                    "could not extract an authenticated receipt signing key from attestation"
                        .to_string(),
                ),
            ));
        }
    }

    if response.verified && hash_ok && platform_ok && key_binding_ok && runtime_policy_ok {
        response.set_tee_provenance_verified();
    } else if response.verified && hash_ok && platform_ok && key_binding_ok {
        response.set_platform_attested();
        response.add_warning(
            "Platform attestation and signing-key binding were verified, but no runtime measurement policy was supplied; assurance_level is platform_attested, not tee_provenance.",
        );
    } else {
        response.add_warning(
            "TEE provenance was requested but not fully verified; see tee_provenance checks.",
        );
    }
}

fn verify_attestation_identity(
    attestation: &[u8],
) -> Result<ephemeral_ml_client::attestation_verifier::EnclaveIdentity, String> {
    let policy = ephemeral_ml_client::PolicyManager::new();
    let mut verifier = ephemeral_ml_client::attestation_verifier::AttestationVerifier::new(policy);
    verifier
        .verify_attestation_bytes_skip_nonce(attestation)
        .map_err(|err| err.to_string())
}

fn pcrs_match(
    measurements: &ephemeral_ml_common::PcrMeasurements,
    expected: &ExpectedPcrs,
) -> bool {
    measurements.pcr0 == expected.pcr0
        && measurements.pcr1 == expected.pcr1
        && measurements.pcr2 == expected.pcr2
}

fn provenance_check(
    id: &'static str,
    label: &'static str,
    status: CheckStatus,
    layer: &'static str,
    detail: Option<String>,
) -> TrustCenterCheck {
    TrustCenterCheck {
        id,
        label,
        status,
        layer: Some(layer),
        detail,
    }
}

fn parse_optional_hash32_hex(
    value: Option<&str>,
    field_name: &str,
) -> Result<Option<[u8; 32]>, (StatusCode, Json<ErrorResponse>)> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let bytes = hex::decode(value)
        .map_err(|_| bad_request(format!("{field_name} must be a 64-character hex string")))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| bad_request(format!("{field_name} must decode to exactly 32 bytes")))?;
    Ok(Some(array))
}

fn parse_optional_hash48_hex(
    value: Option<&str>,
    field_name: &str,
) -> Result<Option<[u8; 48]>, (StatusCode, Json<ErrorResponse>)> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let bytes = hex::decode(value)
        .map_err(|_| bad_request(format!("{field_name} must be a 96-character hex string")))?;
    let array: [u8; 48] = bytes
        .try_into()
        .map_err(|_| bad_request(format!("{field_name} must decode to exactly 48 bytes")))?;
    Ok(Some(array))
}

fn parse_expected_pcrs(
    pcr0: Option<&str>,
    pcr1: Option<&str>,
    pcr2: Option<&str>,
) -> Result<Option<ExpectedPcrs>, (StatusCode, Json<ErrorResponse>)> {
    let pcr0 = parse_optional_hash48_hex(pcr0, "expected_pcr0_hex")?;
    let pcr1 = parse_optional_hash48_hex(pcr1, "expected_pcr1_hex")?;
    let pcr2 = parse_optional_hash48_hex(pcr2, "expected_pcr2_hex")?;
    parse_expected_pcrs_arrays(pcr0, pcr1, pcr2)
}

fn parse_expected_pcrs_arrays(
    pcr0: Option<[u8; 48]>,
    pcr1: Option<[u8; 48]>,
    pcr2: Option<[u8; 48]>,
) -> Result<Option<ExpectedPcrs>, (StatusCode, Json<ErrorResponse>)> {
    match (pcr0, pcr1, pcr2) {
        (None, None, None) => Ok(None),
        (Some(pcr0), Some(pcr1), Some(pcr2)) => Ok(Some(ExpectedPcrs { pcr0, pcr1, pcr2 })),
        _ => Err(bad_request(
            "expected_pcr0_hex, expected_pcr1_hex, and expected_pcr2_hex must be supplied together",
        )),
    }
}

fn parse_expected_security_mode(
    value: Option<&str>,
) -> Result<Option<String>, (StatusCode, Json<ErrorResponse>)> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    match value {
        "production" => Ok(Some(value.to_string())),
        "evaluation" => Err(bad_request(
            "expected_security_mode=evaluation is not accepted by the production verifier; use an evaluation verifier",
        )),
        _ => Err(bad_request(
            "expected_security_mode must be 'production' for this verifier",
        )),
    }
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
        security_mode: "production".to_string(),
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
