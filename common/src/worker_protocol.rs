//! Cyntrisec worker request/response payloads carried inside SecureChannel.
//!
//! The transport crate owns channel establishment, attestation, framing, and
//! encryption. This module owns the product-level payload schema the local
//! proxy and attested worker exchange after the channel is established.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::AttestationReceipt;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct InferenceHandlerInput {
    pub model_id: String,
    pub input_data: Vec<u8>,
    pub input_shape: Option<Vec<usize>>,
    /// When true, request autoregressive text generation instead of embeddings.
    #[serde(default, skip_serializing_if = "is_false")]
    pub generate: bool,
    /// Maximum tokens to generate (only used when generate=true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<usize>,
    /// Sampling temperature (only used when generate=true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Top-p (nucleus) sampling threshold (only used when generate=true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    /// Development-only request for backend benchmark timings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark_mode: Option<String>,
}

fn is_false(v: &bool) -> bool {
    !v
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct InferenceHandlerOutput {
    pub output_tensor: Vec<f32>,
    pub receipt: AttestationReceipt,
    /// Generated text (only present when generate=true on the server).
    #[serde(default)]
    pub generated_text: Option<String>,
    /// Base64-encoded boot attestation document (raw TEE quote bytes).
    #[serde(default)]
    pub boot_attestation_b64: Option<String>,
    /// Model manifest JSON string.
    #[serde(default)]
    pub model_manifest_json: Option<String>,
    /// Base64-encoded AIR v1 receipt (COSE_Sign1 CBOR bytes).
    #[serde(default)]
    pub air_v1_receipt_b64: Option<String>,
    /// Declares how the AIR v1 model_hash was computed when known.
    #[serde(default)]
    pub air_v1_model_hash_scheme: Option<String>,
    /// Human-readable model identity coverage when a signed manifest is authoritative.
    #[serde(default)]
    pub model_identity_coverage: Option<BTreeMap<String, bool>>,
    /// S3 URL for the per-inference receipt bundle, when egress delivery succeeds.
    #[serde(default)]
    pub bundle_url: Option<String>,
    /// SHA-256 of the compressed per-inference receipt bundle, when emitted.
    #[serde(default)]
    pub bundle_sha256: Option<String>,
    /// Development-only benchmark timings returned by the backend when enabled.
    #[serde(default)]
    pub benchmark: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerInferenceError {
    pub code: String,
    pub message: String,
}

impl WorkerInferenceError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", content = "data", rename_all = "snake_case")]
pub enum WorkerResponse {
    Ok(Box<InferenceHandlerOutput>),
    Err(WorkerInferenceError),
}
