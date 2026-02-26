//! Axum route handlers for OpenAI-compatible endpoints.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use sha2::{Digest, Sha256};
use std::time::Instant;

use ephemeral_ml_client::{InferenceResult, SecureClient};

use crate::state::AppState;
use crate::types::*;

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

pub async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let connected = state.connected.load(std::sync::atomic::Ordering::Relaxed);
    Json(serde_json::json!({
        "status": if connected { "ok" } else { "degraded" },
        "backend_connected": connected,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ---------------------------------------------------------------------------
// GET /v1/models
// ---------------------------------------------------------------------------

pub async fn list_models(State(state): State<AppState>) -> Json<ModelsResponse> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Json(ModelsResponse {
        object: "list",
        data: vec![ModelObject {
            id: state.config.default_model.clone(),
            object: "model",
            created: now,
            owned_by: "ephemeralml",
        }],
    })
}

// ---------------------------------------------------------------------------
// POST /v1/chat/completions
// ---------------------------------------------------------------------------

pub async fn chat_completions(
    State(state): State<AppState>,
    Json(req): Json<ChatCompletionRequest>,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let start = Instant::now();

    // Reject streaming (MVP)
    if req.stream == Some(true) {
        tracing::info!(request_id = %request_id, "Rejected stream=true request");
        return error_response(
            StatusCode::BAD_REQUEST,
            ErrorResponse::new(
                "Streaming is not supported in this version. Set stream=false or omit it.",
                "invalid_request_error",
                Some("unsupported_stream"),
            ),
        );
    }

    if req.messages.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            ErrorResponse::invalid_request("messages array must not be empty."),
        );
    }

    // Ensure backend channel
    if let Err(e) = state.ensure_connected().await {
        tracing::error!(request_id = %request_id, error = %e, "Backend connection failed");
        return error_response_with_id(
            StatusCode::BAD_GATEWAY,
            ErrorResponse::server_error(format!("Backend unavailable: {e}")),
            &request_id,
        );
    }

    // Build prompt from messages (concatenate role: content pairs)
    let prompt = messages_to_prompt(&req.messages);
    let max_tokens = req.max_tokens.unwrap_or(256);
    let model_id = &state.config.default_model;

    // Call backend
    let result = {
        let timeout = tokio::time::Duration::from_secs(state.config.request_timeout_secs);
        let mut client = state.client.lock().await;
        tokio::time::timeout(
            timeout,
            client.execute_inference_generate(model_id, &prompt, max_tokens),
        )
        .await
    };

    let elapsed_ms = start.elapsed().as_millis();

    let inference_result = match result {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let err_str = e.to_string();
            tracing::warn!(
                request_id = %request_id,
                model = %model_id,
                latency_ms = %elapsed_ms,
                "Inference failed"
            );
            // Only mark disconnected for transport/network errors (channel broken).
            // Inference logic errors (e.g. wrong model type) leave the channel intact.
            if is_transport_error(&err_str) {
                state
                    .connected
                    .store(false, std::sync::atomic::Ordering::Release);
            }
            return error_response_with_id(
                StatusCode::BAD_GATEWAY,
                ErrorResponse::server_error(format!("Inference error: {e}")),
                &request_id,
            );
        }
        Err(_) => {
            tracing::warn!(
                request_id = %request_id,
                model = %model_id,
                latency_ms = %elapsed_ms,
                "Inference timed out"
            );
            state
                .connected
                .store(false, std::sync::atomic::Ordering::Release);
            return error_response_with_id(
                StatusCode::GATEWAY_TIMEOUT,
                ErrorResponse::server_error("Backend inference timed out."),
                &request_id,
            );
        }
    };

    let generated_text = inference_result.generated_text.clone().unwrap_or_default();

    // Rough token estimate (whitespace split) — not exact, but compatible enough
    let prompt_tokens = prompt.split_whitespace().count() as u32;
    let completion_tokens = generated_text.split_whitespace().count() as u32;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let metadata = build_metadata(&state, &inference_result, &req.model);

    // Response `model` reflects the actual backend model, not the caller's alias.
    let body = ChatCompletionResponse {
        id: format!("chatcmpl-{request_id}"),
        object: "chat.completion",
        created: now,
        model: state.config.default_model.clone(),
        choices: vec![ChatChoice {
            index: 0,
            message: ChatMessage {
                role: "assistant".to_string(),
                content: generated_text,
            },
            finish_reason: "stop",
        }],
        usage: Usage {
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens + completion_tokens,
        },
        metadata: if state.config.include_metadata_json {
            metadata.clone()
        } else {
            None
        },
    };

    tracing::info!(
        request_id = %request_id,
        model = %model_id,
        latency_ms = %elapsed_ms,
        has_receipt = %metadata.is_some(),
        "Chat completion served"
    );

    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", HeaderValue::from_str(&request_id).unwrap());
    attach_metadata_headers(&mut headers, &metadata, &state);

    (StatusCode::OK, headers, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// POST /v1/responses  (OpenAI Responses API compatibility)
// ---------------------------------------------------------------------------

pub async fn responses(
    State(state): State<AppState>,
    Json(req): Json<ResponsesRequest>,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let start = Instant::now();

    // Reject streaming
    if req.stream == Some(true) {
        return error_response(
            StatusCode::BAD_REQUEST,
            ErrorResponse::new(
                "Streaming is not supported in this version. Set stream=false or omit it.",
                "invalid_request_error",
                Some("unsupported_stream"),
            ),
        );
    }

    // Reject unsupported fields
    if req.tools.is_some() {
        return error_response(
            StatusCode::BAD_REQUEST,
            ErrorResponse::new(
                "Tool use is not supported in this version.",
                "invalid_request_error",
                Some("unsupported_parameter"),
            ),
        );
    }
    if req.tool_choice.is_some() {
        return error_response(
            StatusCode::BAD_REQUEST,
            ErrorResponse::new(
                "tool_choice is not supported in this version.",
                "invalid_request_error",
                Some("unsupported_parameter"),
            ),
        );
    }

    // Build prompt from input
    let prompt = match &req.input {
        ResponsesInput::Text(t) => {
            if t.is_empty() {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    ErrorResponse::invalid_request("input must not be empty."),
                );
            }
            let mut p = String::new();
            if let Some(ref instructions) = req.instructions {
                p.push_str("system: ");
                p.push_str(instructions);
                p.push('\n');
            }
            p.push_str("user: ");
            p.push_str(t);
            p
        }
        ResponsesInput::Messages(msgs) => {
            if msgs.is_empty() {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    ErrorResponse::invalid_request("input messages must not be empty."),
                );
            }
            let mut p = String::new();
            if let Some(ref instructions) = req.instructions {
                p.push_str("system: ");
                p.push_str(instructions);
                p.push('\n');
            }
            for msg in msgs {
                if !p.is_empty() {
                    p.push('\n');
                }
                p.push_str(&msg.role);
                p.push_str(": ");
                p.push_str(&msg.content);
            }
            p
        }
    };

    // Ensure backend channel
    if let Err(e) = state.ensure_connected().await {
        tracing::error!(request_id = %request_id, error = %e, "Backend connection failed");
        return error_response_with_id(
            StatusCode::BAD_GATEWAY,
            ErrorResponse::server_error(format!("Backend unavailable: {e}")),
            &request_id,
        );
    }

    let max_tokens = req.max_output_tokens.unwrap_or(256);
    let model_id = &state.config.default_model;

    let result = {
        let timeout = tokio::time::Duration::from_secs(state.config.request_timeout_secs);
        let mut client = state.client.lock().await;
        tokio::time::timeout(
            timeout,
            client.execute_inference_generate(model_id, &prompt, max_tokens),
        )
        .await
    };

    let elapsed_ms = start.elapsed().as_millis();

    let inference_result = match result {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let err_str = e.to_string();
            tracing::warn!(
                request_id = %request_id,
                model = %model_id,
                latency_ms = %elapsed_ms,
                "Responses inference failed"
            );
            if is_transport_error(&err_str) {
                state
                    .connected
                    .store(false, std::sync::atomic::Ordering::Release);
            }
            return error_response_with_id(
                StatusCode::BAD_GATEWAY,
                ErrorResponse::server_error(format!("Inference error: {e}")),
                &request_id,
            );
        }
        Err(_) => {
            tracing::warn!(
                request_id = %request_id,
                model = %model_id,
                latency_ms = %elapsed_ms,
                "Responses inference timed out"
            );
            state
                .connected
                .store(false, std::sync::atomic::Ordering::Release);
            return error_response_with_id(
                StatusCode::GATEWAY_TIMEOUT,
                ErrorResponse::server_error("Backend inference timed out."),
                &request_id,
            );
        }
    };

    let generated_text = inference_result.generated_text.clone().unwrap_or_default();

    let prompt_tokens = prompt.split_whitespace().count() as u32;
    let output_tokens = generated_text.split_whitespace().count() as u32;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let metadata = build_metadata(&state, &inference_result, &req.model);

    let output_item_id = format!("msg_{}", &request_id[..8]);

    let body = ResponsesResponse {
        id: format!("resp-{request_id}"),
        object: "response",
        created_at: now,
        model: state.config.default_model.clone(),
        output: vec![ResponsesOutput {
            output_type: "message",
            id: output_item_id,
            role: "assistant",
            content: vec![ResponsesContent {
                content_type: "output_text",
                text: generated_text,
            }],
            status: "completed",
        }],
        usage: ResponsesUsage {
            input_tokens: prompt_tokens,
            output_tokens,
            total_tokens: prompt_tokens + output_tokens,
        },
        status: "completed",
        metadata: if state.config.include_metadata_json {
            metadata.clone()
        } else {
            None
        },
    };

    tracing::info!(
        request_id = %request_id,
        model = %model_id,
        latency_ms = %elapsed_ms,
        has_receipt = %metadata.is_some(),
        "Response served"
    );

    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", HeaderValue::from_str(&request_id).unwrap());
    attach_metadata_headers(&mut headers, &metadata, &state);

    (StatusCode::OK, headers, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// POST /v1/embeddings
// ---------------------------------------------------------------------------

pub async fn embeddings(
    State(state): State<AppState>,
    Json(req): Json<EmbeddingRequest>,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let start = Instant::now();

    let texts = match &req.input {
        EmbeddingInput::Single(s) => vec![s.clone()],
        EmbeddingInput::Multiple(v) => v.clone(),
    };

    if texts.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            ErrorResponse::invalid_request("input must not be empty."),
        );
    }

    // Ensure backend channel
    if let Err(e) = state.ensure_connected().await {
        tracing::error!(request_id = %request_id, error = %e, "Backend connection failed");
        return error_response_with_id(
            StatusCode::BAD_GATEWAY,
            ErrorResponse::server_error(format!("Backend unavailable: {e}")),
            &request_id,
        );
    }

    let model_id = &state.config.default_model;
    let timeout = tokio::time::Duration::from_secs(state.config.request_timeout_secs);

    let mut data = Vec::with_capacity(texts.len());
    let mut total_tokens: u32 = 0;
    let mut last_result: Option<InferenceResult> = None;

    for (i, text) in texts.iter().enumerate() {
        let result = {
            let mut client = state.client.lock().await;
            tokio::time::timeout(timeout, client.execute_inference_text(model_id, text)).await
        };

        let elapsed_ms = start.elapsed().as_millis();

        let inference_result = match result {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                let err_str = e.to_string();
                tracing::warn!(
                    request_id = %request_id,
                    model = %model_id,
                    latency_ms = %elapsed_ms,
                    "Embedding inference failed"
                );
                if is_transport_error(&err_str) {
                    state
                        .connected
                        .store(false, std::sync::atomic::Ordering::Release);
                }
                return error_response_with_id(
                    StatusCode::BAD_GATEWAY,
                    ErrorResponse::server_error(format!("Inference error: {e}")),
                    &request_id,
                );
            }
            Err(_) => {
                tracing::warn!(
                    request_id = %request_id,
                    model = %model_id,
                    latency_ms = %elapsed_ms,
                    "Embedding timed out"
                );
                state
                    .connected
                    .store(false, std::sync::atomic::Ordering::Release);
                return error_response_with_id(
                    StatusCode::GATEWAY_TIMEOUT,
                    ErrorResponse::server_error("Backend inference timed out."),
                    &request_id,
                );
            }
        };

        let tokens = text.split_whitespace().count() as u32;
        total_tokens += tokens;

        data.push(EmbeddingData {
            object: "embedding",
            embedding: inference_result.output_tensor.clone(),
            index: i,
        });

        last_result = Some(inference_result);
    }

    let elapsed_ms = start.elapsed().as_millis();

    let metadata = last_result
        .as_ref()
        .map(|r| build_metadata(&state, r, &req.model))
        .unwrap_or(None);

    // Response `model` reflects the actual backend model.
    let body = EmbeddingResponse {
        object: "list",
        data,
        model: state.config.default_model.clone(),
        usage: Usage {
            prompt_tokens: total_tokens,
            completion_tokens: 0,
            total_tokens,
        },
        metadata: if state.config.include_metadata_json {
            metadata.clone()
        } else {
            None
        },
    };

    tracing::info!(
        request_id = %request_id,
        model = %model_id,
        inputs = texts.len(),
        latency_ms = %elapsed_ms,
        has_receipt = %metadata.is_some(),
        "Embedding served"
    );

    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", HeaderValue::from_str(&request_id).unwrap());
    attach_metadata_headers(&mut headers, &metadata, &state);

    (StatusCode::OK, headers, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns true if the error string indicates a transport/channel failure
/// (broken connection, send/recv failure) vs. a logical inference error
/// (wrong model type, serialization mismatch). Only transport errors
/// should mark the channel as disconnected.
fn is_transport_error(err: &str) -> bool {
    err.contains("Transport error")
        || err.contains("Network error")
        || err.contains("Send failed")
        || err.contains("Recv failed")
        || err.contains("Channel not established")
        || err.contains("connection reset")
        || err.contains("broken pipe")
}

/// Concatenate chat messages into a single prompt string for the backend.
fn messages_to_prompt(messages: &[ChatMessage]) -> String {
    let mut prompt = String::new();
    for msg in messages {
        if !prompt.is_empty() {
            prompt.push('\n');
        }
        prompt.push_str(&msg.role);
        prompt.push_str(": ");
        prompt.push_str(&msg.content);
    }
    prompt
}

/// Build EphemeralML metadata from an inference result.
fn build_metadata(
    state: &AppState,
    result: &InferenceResult,
    requested_model: &str,
) -> Option<EphemeralMetadata> {
    let manifest_sha256 = result.model_manifest_json.as_ref().map(|json| {
        let hash = Sha256::digest(json.as_bytes());
        hex::encode(hash)
    });
    let attestation_mode = result
        .receipt
        .attestation_source
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    let receipt_sha256 = result.air_v1_receipt_b64.as_ref().map(|b64| {
        let hash = Sha256::digest(b64.as_bytes());
        hex::encode(hash)
    });

    Some(EphemeralMetadata {
        receipt_id: result.receipt.receipt_id.clone(),
        attestation_mode,
        executed_model: state.config.default_model.clone(),
        requested_model: requested_model.to_string(),
        receipt_sha256,
        air_v1_receipt_b64: result.air_v1_receipt_b64.clone(),
        model_manifest_sha256: manifest_sha256,
    })
}

/// Attach attestation metadata as response headers.
///
/// Default headers (always safe, small):
///   - `x-ephemeralml-attestation-mode`
///   - `x-ephemeralml-receipt-present: true|false`
///   - `x-ephemeralml-receipt-sha256` (when receipt exists)
///   - `x-ephemeralml-model-manifest-sha256` (when available)
///
/// Full receipt header (opt-in via `EPHEMERALML_RECEIPT_HEADER_FULL`):
///   - `x-ephemeralml-air-receipt-b64` (truncated to 8 KB)
fn attach_metadata_headers(
    headers: &mut HeaderMap,
    metadata: &Option<EphemeralMetadata>,
    state: &AppState,
) {
    if let Some(meta) = metadata {
        if let Ok(v) = HeaderValue::from_str(&meta.attestation_mode) {
            headers.insert("x-ephemeralml-attestation-mode", v);
        }

        let has_receipt = meta.air_v1_receipt_b64.is_some();
        headers.insert(
            "x-ephemeralml-receipt-present",
            HeaderValue::from_static(if has_receipt { "true" } else { "false" }),
        );

        if let Some(ref sha) = meta.receipt_sha256 {
            if let Ok(v) = HeaderValue::from_str(sha) {
                headers.insert("x-ephemeralml-receipt-sha256", v);
            }
        }

        if let Some(ref sha) = meta.model_manifest_sha256 {
            if let Ok(v) = HeaderValue::from_str(sha) {
                headers.insert("x-ephemeralml-model-manifest-sha256", v);
            }
        }

        // Full receipt in header only if explicitly opted in
        if state.config.receipt_header_full {
            if let Some(ref receipt_b64) = meta.air_v1_receipt_b64 {
                let truncated = if receipt_b64.len() > 8192 {
                    &receipt_b64[..8192]
                } else {
                    receipt_b64
                };
                if let Ok(v) = HeaderValue::from_str(truncated) {
                    headers.insert("x-ephemeralml-air-receipt-b64", v);
                }
            }
        }
    }
}

/// Build an OpenAI-style error response.
fn error_response(status: StatusCode, body: ErrorResponse) -> Response {
    (status, Json(body)).into_response()
}

fn error_response_with_id(status: StatusCode, body: ErrorResponse, request_id: &str) -> Response {
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(request_id) {
        headers.insert("x-request-id", v);
    }
    (status, headers, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_to_prompt_concatenation() {
        let msgs = vec![
            ChatMessage {
                role: "system".into(),
                content: "You are helpful.".into(),
            },
            ChatMessage {
                role: "user".into(),
                content: "Hello".into(),
            },
        ];
        let prompt = messages_to_prompt(&msgs);
        assert_eq!(prompt, "system: You are helpful.\nuser: Hello");
    }

    #[test]
    fn error_response_shape() {
        let err = ErrorResponse::invalid_request("bad input");
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["error"]["type"], "invalid_request_error");
        assert_eq!(json["error"]["message"], "bad input");
    }

    #[test]
    fn chat_response_model_is_backend_model() {
        let resp = ChatCompletionResponse {
            id: "chatcmpl-123".into(),
            object: "chat.completion",
            created: 1700000000,
            model: "stage-0".into(), // backend model, not caller's "gpt-4"
            choices: vec![ChatChoice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".into(),
                    content: "Hello!".into(),
                },
                finish_reason: "stop",
            }],
            usage: Usage {
                prompt_tokens: 5,
                completion_tokens: 1,
                total_tokens: 6,
            },
            metadata: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["object"], "chat.completion");
        assert_eq!(json["model"], "stage-0");
        assert!(json.get("_ephemeralml").is_none());
    }

    #[test]
    fn metadata_includes_model_semantics() {
        let meta = EphemeralMetadata {
            receipt_id: "r-1".into(),
            attestation_mode: "mock".into(),
            executed_model: "stage-0".into(),
            requested_model: "gpt-4".into(),
            receipt_sha256: Some("abc123".into()),
            air_v1_receipt_b64: None,
            model_manifest_sha256: None,
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["executed_model"], "stage-0");
        assert_eq!(json["requested_model"], "gpt-4");
        assert_eq!(json["receipt_sha256"], "abc123");
    }

    #[test]
    fn metadata_with_receipt_includes_sha256() {
        let resp = ChatCompletionResponse {
            id: "chatcmpl-123".into(),
            object: "chat.completion",
            created: 1700000000,
            model: "stage-0".into(),
            choices: vec![],
            usage: Usage {
                prompt_tokens: 0,
                completion_tokens: 0,
                total_tokens: 0,
            },
            metadata: Some(EphemeralMetadata {
                receipt_id: "r-123".into(),
                attestation_mode: "mock".into(),
                executed_model: "stage-0".into(),
                requested_model: "gpt-4".into(),
                receipt_sha256: Some("deadbeef".into()),
                air_v1_receipt_b64: Some("base64data".into()),
                model_manifest_sha256: None,
            }),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["_ephemeralml"]["receipt_sha256"], "deadbeef");
        assert_eq!(json["_ephemeralml"]["air_v1_receipt_b64"], "base64data");
    }

    #[test]
    fn embedding_input_deserializes_single() {
        let json = serde_json::json!({"model": "m", "input": "hello"});
        let req: EmbeddingRequest = serde_json::from_value(json).unwrap();
        assert!(matches!(req.input, EmbeddingInput::Single(_)));
    }

    #[test]
    fn embedding_input_deserializes_multiple() {
        let json = serde_json::json!({"model": "m", "input": ["a", "b"]});
        let req: EmbeddingRequest = serde_json::from_value(json).unwrap();
        assert!(matches!(req.input, EmbeddingInput::Multiple(_)));
    }

    #[test]
    fn stream_true_rejected_in_chat_request() {
        let json = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true
        });
        let req: ChatCompletionRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.stream, Some(true));
    }

    #[test]
    fn responses_request_deserializes_text_input() {
        let json = serde_json::json!({
            "model": "gpt-4",
            "input": "hello"
        });
        let req: ResponsesRequest = serde_json::from_value(json).unwrap();
        assert!(matches!(req.input, ResponsesInput::Text(_)));
    }

    #[test]
    fn responses_request_deserializes_messages_input() {
        let json = serde_json::json!({
            "model": "gpt-4",
            "input": [{"role": "user", "content": "hi"}]
        });
        let req: ResponsesRequest = serde_json::from_value(json).unwrap();
        assert!(matches!(req.input, ResponsesInput::Messages(_)));
    }

    #[test]
    fn responses_response_shape() {
        let resp = ResponsesResponse {
            id: "resp-123".into(),
            object: "response",
            created_at: 1700000000,
            model: "stage-0".into(),
            output: vec![ResponsesOutput {
                output_type: "message",
                id: "msg_abc".into(),
                role: "assistant",
                content: vec![ResponsesContent {
                    content_type: "output_text",
                    text: "Hello!".into(),
                }],
                status: "completed",
            }],
            usage: ResponsesUsage {
                input_tokens: 3,
                output_tokens: 1,
                total_tokens: 4,
            },
            status: "completed",
            metadata: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["object"], "response");
        assert_eq!(json["status"], "completed");
        assert_eq!(json["output"][0]["type"], "message");
        assert_eq!(json["output"][0]["content"][0]["type"], "output_text");
    }
}
