//! OpenAI-compatible request and response types.
//!
//! Implements a minimal subset of the OpenAI API surface sufficient for
//! common SDKs (Python `openai`, LangChain, LiteLLM) to work when pointed
//! at this gateway via `base_url`.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Chat Completions
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub max_tokens: Option<usize>,
    #[serde(default)]
    pub top_p: Option<f64>,
    #[serde(default)]
    pub stream: Option<bool>,
    #[serde(default)]
    pub user: Option<String>,
    /// Unsupported — reject clearly if present (parity with /v1/responses).
    #[serde(default)]
    pub tools: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_choice: Option<serde_json::Value>,
}

impl Drop for ChatCompletionRequest {
    fn drop(&mut self) {
        self.model.zeroize();
        for message in &mut self.messages {
            message.role.zeroize();
            message.content.zeroize();
        }
        if let Some(user) = &mut self.user {
            user.zeroize();
        }
        if let Some(tools) = &mut self.tools {
            zeroize_json_value(tools);
        }
        if let Some(tool_choice) = &mut self.tool_choice {
            zeroize_json_value(tool_choice);
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Serialize, Debug)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: &'static str,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    pub usage: Usage,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "_ephemeralml")]
    pub metadata: Option<EphemeralMetadata>,
}

impl Drop for ChatCompletionResponse {
    fn drop(&mut self) {
        self.model.zeroize();
        for choice in &mut self.choices {
            choice.message.role.zeroize();
            choice.message.content.zeroize();
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: &'static str,
}

// ---------------------------------------------------------------------------
// Responses (OpenAI /v1/responses compatibility)
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
pub struct ResponsesRequest {
    pub model: String,
    pub input: ResponsesInput,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub max_output_tokens: Option<usize>,
    #[serde(default)]
    pub top_p: Option<f64>,
    #[serde(default)]
    pub stream: Option<bool>,
    /// Unsupported fields — reject clearly if present.
    #[serde(default)]
    pub tools: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_choice: Option<serde_json::Value>,
    #[serde(default)]
    pub instructions: Option<String>,
}

impl Drop for ResponsesRequest {
    fn drop(&mut self) {
        self.model.zeroize();
        match &mut self.input {
            ResponsesInput::Text(text) => text.zeroize(),
            ResponsesInput::Messages(messages) => {
                for message in messages {
                    message.role.zeroize();
                    message.content.zeroize();
                }
            }
        }
        if let Some(instructions) = &mut self.instructions {
            instructions.zeroize();
        }
        if let Some(tools) = &mut self.tools {
            zeroize_json_value(tools);
        }
        if let Some(tool_choice) = &mut self.tool_choice {
            zeroize_json_value(tool_choice);
        }
    }
}

/// Input can be a plain string or an array of message objects.
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum ResponsesInput {
    Text(String),
    Messages(Vec<ResponsesInputMessage>),
}

#[derive(Deserialize, Debug)]
pub struct ResponsesInputMessage {
    pub role: String,
    pub content: String,
}

#[derive(Serialize, Debug)]
pub struct ResponsesResponse {
    pub id: String,
    pub object: &'static str,
    pub created_at: u64,
    pub model: String,
    pub output: Vec<ResponsesOutput>,
    pub usage: ResponsesUsage,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "_ephemeralml")]
    pub metadata: Option<EphemeralMetadata>,
}

impl Drop for ResponsesResponse {
    fn drop(&mut self) {
        self.model.zeroize();
        for output in &mut self.output {
            output.id.zeroize();
            for content in &mut output.content {
                content.text.zeroize();
            }
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ResponsesOutput {
    #[serde(rename = "type")]
    pub output_type: &'static str,
    pub id: String,
    pub role: &'static str,
    pub content: Vec<ResponsesContent>,
    pub status: &'static str,
}

#[derive(Serialize, Debug)]
pub struct ResponsesContent {
    #[serde(rename = "type")]
    pub content_type: &'static str,
    pub text: String,
}

#[derive(Serialize, Debug)]
pub struct ResponsesUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
}

// ---------------------------------------------------------------------------
// Embeddings
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
pub struct EmbeddingRequest {
    pub model: String,
    pub input: EmbeddingInput,
    #[serde(default)]
    pub encoding_format: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
}

impl Drop for EmbeddingRequest {
    fn drop(&mut self) {
        self.model.zeroize();
        match &mut self.input {
            EmbeddingInput::Single(text) => text.zeroize(),
            EmbeddingInput::Multiple(texts) => texts.zeroize(),
        }
        if let Some(format) = &mut self.encoding_format {
            format.zeroize();
        }
        if let Some(user) = &mut self.user {
            user.zeroize();
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum EmbeddingInput {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Serialize, Debug)]
pub struct EmbeddingResponse {
    pub object: &'static str,
    pub data: Vec<EmbeddingData>,
    pub model: String,
    pub usage: Usage,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "_ephemeralml")]
    pub metadata: Option<EphemeralMetadata>,
}

impl Drop for EmbeddingResponse {
    fn drop(&mut self) {
        self.model.zeroize();
        for item in &mut self.data {
            item.embedding.zeroize();
        }
    }
}

#[derive(Serialize, Debug)]
pub struct EmbeddingData {
    pub object: &'static str,
    pub embedding: Vec<f32>,
    pub index: usize,
}

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

#[derive(Serialize, Debug)]
pub struct ModelsResponse {
    pub object: &'static str,
    pub data: Vec<ModelObject>,
}

#[derive(Serialize, Debug)]
pub struct ModelObject {
    pub id: String,
    pub object: &'static str,
    pub created: u64,
    pub owned_by: &'static str,
    #[serde(rename = "_ephemeralml")]
    pub ephemeralml: ModelEphemeralMeta,
}

#[derive(Serialize, Debug, Clone)]
pub struct ModelEphemeralMeta {
    pub capabilities: ModelCapabilities,
}

#[derive(Serialize, Debug, Clone)]
pub struct ModelCapabilities {
    pub chat: bool,
    pub embeddings: bool,
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

#[derive(Serialize, Debug)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// EphemeralML-specific metadata, optionally embedded in JSON responses.
#[derive(Serialize, Debug, Clone)]
pub struct EphemeralMetadata {
    pub receipt_id: String,
    pub attestation_mode: String,
    /// The model ID that actually executed the inference on the backend.
    pub executed_model: String,
    /// The model name the caller sent in the request (may differ from executed_model).
    pub requested_model: String,
    /// SHA-256 of the AIR v1 receipt bytes (always present when receipt exists).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_sha256: Option<String>,
    /// Full base64-encoded AIR v1 receipt (COSE_Sign1 CBOR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub air_v1_receipt_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_manifest_sha256: Option<String>,
    /// S3 URL for the per-inference receipt bundle, when emitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_url: Option<String>,
    /// SHA-256 of the compressed per-inference receipt bundle, when emitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_sha256: Option<String>,
    /// Development-only backend timing record. Present only when the gateway
    /// and backend are explicitly run with `EPHEMERALML_BENCHMARK_MODE=development`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub benchmark: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Errors (OpenAI-compatible envelope)
// ---------------------------------------------------------------------------

#[derive(Serialize, Debug)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Serialize, Debug)]
pub struct ErrorBody {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: String,
    pub param: Option<String>,
    pub code: Option<String>,
}

fn zeroize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        serde_json::Value::Object(values) => {
            let values = std::mem::take(values);
            for (mut key, mut value) in values {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

impl ErrorResponse {
    pub fn new(message: impl Into<String>, error_type: &str, code: Option<&str>) -> Self {
        Self {
            error: ErrorBody {
                message: message.into(),
                error_type: error_type.to_string(),
                param: None,
                code: code.map(|s| s.to_string()),
            },
        }
    }

    /// Set the `param` field on this error (builder pattern).
    pub fn with_param(mut self, param: &str) -> Self {
        self.error.param = Some(param.to_string());
        self
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(message, "invalid_request_error", None)
    }

    pub fn server_error(message: impl Into<String>) -> Self {
        Self::new(message, "server_error", Some("internal_error"))
    }

    pub fn auth_error() -> Self {
        Self::new(
            "Invalid API key or missing Authorization header.",
            "invalid_request_error",
            Some("invalid_api_key"),
        )
    }
}
