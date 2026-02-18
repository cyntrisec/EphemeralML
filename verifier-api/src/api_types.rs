use ephemeral_ml_common::receipt_verify::VerifyResult;
use serde::{Deserialize, Serialize};

/// JSON request body for `POST /api/v1/verify`.
#[derive(Deserialize)]
pub struct VerifyRequest {
    /// The receipt — either an inline JSON object or a base64-encoded CBOR blob.
    pub receipt: serde_json::Value,
    /// Ed25519 public key as 64-character hex string.
    pub public_key: String,
    /// Optional expected model ID.
    #[serde(default)]
    pub expected_model: Option<String>,
    /// Maximum receipt age in seconds. Default 0 (skip).
    #[serde(default)]
    pub max_age_secs: u64,
    /// Expected measurement type. Default "any" (skip).
    #[serde(default = "default_measurement_type")]
    pub measurement_type: String,
    /// Expected attestation source (e.g. "cs-tdx", "aws-nitro"). Optional.
    #[serde(default)]
    pub expected_attestation_source: Option<String>,
    /// Expected container image digest (e.g. "sha256:abc123"). Optional.
    #[serde(default)]
    pub expected_image_digest: Option<String>,
}

fn default_measurement_type() -> String {
    "any".to_string()
}

/// API response envelope wrapping the core `VerifyResult`.
#[derive(Serialize)]
pub struct ApiVerifyResponse {
    #[serde(flatten)]
    pub result: VerifyResult,
    pub api_version: &'static str,
    pub verified_at: u64,
}

impl ApiVerifyResponse {
    pub fn from_result(result: VerifyResult) -> Self {
        Self {
            result,
            api_version: "v1",
            verified_at: ephemeral_ml_common::current_timestamp(),
        }
    }
}

/// Simple error body returned on 400/422.
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
