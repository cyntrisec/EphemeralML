use serde::{Deserialize, Serialize};

/// JSON request body for `POST /api/v1/verify`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    /// The receipt — either an inline JSON object or a base64-encoded CBOR blob.
    pub receipt: serde_json::Value,
    /// Ed25519 public key as 64-character hex string.
    pub public_key: String,
    /// Optional expected model ID.
    #[serde(default)]
    pub expected_model: Option<String>,
    /// Optional expected model_hash as 64 lowercase/uppercase hex characters.
    #[serde(default)]
    pub expected_model_hash_hex: Option<String>,
    /// Optional expected request_hash as 64 lowercase/uppercase hex characters.
    #[serde(default)]
    pub expected_request_hash_hex: Option<String>,
    /// Optional expected response_hash as 64 lowercase/uppercase hex characters.
    #[serde(default)]
    pub expected_response_hash_hex: Option<String>,
    /// Optional expected AIR security_mode.
    #[serde(default)]
    pub expected_security_mode: Option<String>,
    /// Maximum receipt age in seconds. Default 0 (skip).
    #[serde(default)]
    pub max_age_secs: u64,
    /// Expected measurement type. Default "any" (skip).
    #[serde(default = "default_measurement_type")]
    pub measurement_type: String,
    /// Expected attestation source (e.g. "cs-tdx", "nitro"). Optional.
    #[serde(default)]
    pub expected_attestation_source: Option<String>,
    /// Expected container image digest (e.g. "sha256:abc123"). Optional.
    #[serde(default)]
    pub expected_image_digest: Option<String>,
    /// Expected Nitro PCR0 measurement as 96-character hex. Must be supplied
    /// with expected_pcr1_hex and expected_pcr2_hex to claim tee_provenance.
    #[serde(default)]
    pub expected_pcr0_hex: Option<String>,
    /// Expected Nitro PCR1 measurement as 96-character hex.
    #[serde(default)]
    pub expected_pcr1_hex: Option<String>,
    /// Expected Nitro PCR2 measurement as 96-character hex.
    #[serde(default)]
    pub expected_pcr2_hex: Option<String>,
}

fn default_measurement_type() -> String {
    "any".to_string()
}

/// Simple error body returned on 400/422.
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
