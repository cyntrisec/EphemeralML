//! Axum route handlers for OpenAI-compatible endpoints.

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use sha2::{Digest, Sha256};
use std::time::Instant;

use ephemeral_ml_client::{InferenceResult, SecureClient};

use crate::state::AppState;
use crate::streaming;
use crate::types::*;

// ---------------------------------------------------------------------------
// Custom JSON extractor — normalises parse/body-limit errors to OpenAI shape
// ---------------------------------------------------------------------------

/// Wrapper around `axum::Json` that converts framework-level rejections
/// (malformed JSON, missing content-type, body too large) into OpenAI-
/// compatible error envelopes with `x-request-id`.
pub struct OpenAiJson<T>(pub T);

impl<S, T> FromRequest<S> for OpenAiJson<T>
where
    axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(OpenAiJson(value)),
            Err(rejection) => {
                let request_id = uuid::Uuid::new_v4().to_string();
                let status = rejection.status();
                let message = rejection.body_text();

                // Map Axum status to appropriate OpenAI error type/code.
                let (error_type, code) = if status == StatusCode::PAYLOAD_TOO_LARGE {
                    ("invalid_request_error", Some("request_too_large"))
                } else {
                    ("invalid_request_error", Some("invalid_json"))
                };

                let body = ErrorResponse::new(message, error_type, code);
                Err(error_response_with_id(status, body, &request_id))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

pub async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let connected = state.connected.load(std::sync::atomic::Ordering::Relaxed);
    let emb_configured = state.config.embedding_backend_addr.is_some();
    let emb_connected = state
        .embedding_connected
        .load(std::sync::atomic::Ordering::Relaxed);
    let reconnect_enabled = state.config.reconnect_enabled;

    let status = if emb_configured {
        if connected && emb_connected {
            "ok"
        } else if connected || emb_connected {
            if reconnect_enabled {
                "reconnecting"
            } else {
                "degraded"
            }
        } else if reconnect_enabled {
            "reconnecting"
        } else {
            "unavailable"
        }
    } else if connected {
        "ok"
    } else if reconnect_enabled {
        "reconnecting"
    } else {
        "degraded"
    };

    let mut body = serde_json::json!({
        "status": status,
        "backend_connected": connected,
        "version": env!("CARGO_PKG_VERSION"),
    });

    if reconnect_enabled {
        body["reconnect_enabled"] = serde_json::json!(true);
    }

    if emb_configured {
        body["embedding_backend_configured"] = serde_json::json!(true);
        body["embedding_backend_connected"] = serde_json::json!(emb_connected);
    }

    Json(body)
}

// ---------------------------------------------------------------------------
// GET /readyz  (strict readiness — all configured backends must be connected)
// ---------------------------------------------------------------------------

pub async fn readyz(State(state): State<AppState>) -> Response {
    let connected = state.connected.load(std::sync::atomic::Ordering::Relaxed);
    let emb_configured = state.config.embedding_backend_addr.is_some();
    let emb_connected = state
        .embedding_connected
        .load(std::sync::atomic::Ordering::Relaxed);

    let ready = if emb_configured {
        connected && emb_connected
    } else {
        connected
    };

    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let mut body = serde_json::json!({
        "ready": ready,
        "backend_connected": connected,
    });

    if emb_configured {
        body["embedding_backend_configured"] = serde_json::json!(true);
        body["embedding_backend_connected"] = serde_json::json!(emb_connected);
    }

    (status, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// GET /v1/models
// ---------------------------------------------------------------------------

pub async fn list_models(State(state): State<AppState>) -> Json<ModelsResponse> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let has_chat = state.config.has_capability("chat");
    let has_embeddings = state.config.has_capability("embeddings");

    // If a separate embedding backend is configured, the main model only
    // advertises the capabilities it actually supports.
    let has_separate_embedding = state.config.embedding_backend_addr.is_some();

    let main_caps = ModelCapabilities {
        chat: has_chat,
        embeddings: if has_separate_embedding {
            false
        } else {
            has_embeddings
        },
    };

    let mut models = vec![ModelObject {
        id: state.config.default_model.clone(),
        object: "model",
        created: now,
        owned_by: "ephemeralml",
        ephemeralml: ModelEphemeralMeta {
            capabilities: main_caps,
        },
    }];

    // Add separate embedding model entry if configured (skip if ID duplicates default).
    if has_separate_embedding && has_embeddings {
        let emb_model_id = state
            .config
            .embedding_model
            .clone()
            .unwrap_or_else(|| state.config.default_model.clone());
        if emb_model_id == state.config.default_model {
            // Config validation should prevent this, but guard at runtime too.
            tracing::warn!(
                model_id = %emb_model_id,
                "Embedding model ID matches default model — merging capabilities"
            );
            // Upgrade main model's capabilities to include embeddings instead of
            // adding a duplicate entry.
            if let Some(main) = models.first_mut() {
                main.ephemeralml.capabilities.embeddings = true;
            }
        } else {
            models.push(ModelObject {
                id: emb_model_id,
                object: "model",
                created: now,
                owned_by: "ephemeralml",
                ephemeralml: ModelEphemeralMeta {
                    capabilities: ModelCapabilities {
                        chat: false,
                        embeddings: true,
                    },
                },
            });
        }
    }

    Json(ModelsResponse {
        object: "list",
        data: models,
    })
}

// ---------------------------------------------------------------------------
// POST /v1/chat/completions
// ---------------------------------------------------------------------------

pub async fn chat_completions(
    State(state): State<AppState>,
    OpenAiJson(req): OpenAiJson<ChatCompletionRequest>,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let start = Instant::now();

    // Capability gate — reject unless "chat" is enabled.
    if !state.config.has_capability("chat") {
        tracing::info!(request_id = %request_id, "Rejected chat: capability not enabled");
        return error_response_with_id(
            StatusCode::BAD_REQUEST,
            ErrorResponse {
                error: ErrorBody {
                    message: "This model does not support chat completions. Configure \
                        EPHEMERALML_MODEL_CAPABILITIES to include 'chat'."
                        .to_string(),
                    error_type: "invalid_request_error".to_string(),
                    param: Some("model".to_string()),
                    code: Some("unsupported_model_capability".to_string()),
                },
            },
            &request_id,
        );
    }

    if let Some(err) = model_capability_conflict(&state, &req.model, "chat") {
        return error_response_with_id(StatusCode::BAD_REQUEST, err, &request_id);
    }

    let is_streaming = req.stream == Some(true);

    // Reject unsupported fields (parity with /v1/responses)
    if req.tools.is_some() {
        return error_response_with_id(
            StatusCode::BAD_REQUEST,
            ErrorResponse::new(
                "Tool use is not supported in this version.",
                "invalid_request_error",
                Some("unsupported_parameter"),
            )
            .with_param("tools"),
            &request_id,
        );
    }
    if req.tool_choice.is_some() {
        return error_response_with_id(
            StatusCode::BAD_REQUEST,
            ErrorResponse::new(
                "tool_choice is not supported in this version.",
                "invalid_request_error",
                Some("unsupported_parameter"),
            )
            .with_param("tool_choice"),
            &request_id,
        );
    }

    if req.messages.is_empty() {
        return error_response_with_id(
            StatusCode::BAD_REQUEST,
            ErrorResponse::invalid_request("messages array must not be empty.")
                .with_param("messages"),
            &request_id,
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
                state.reconnect_notify.notify_one();
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
            state.reconnect_notify.notify_one();
            return error_response_with_id(
                StatusCode::GATEWAY_TIMEOUT,
                ErrorResponse::server_error("Backend inference timed out."),
                &request_id,
            );
        }
    };

    let generated_text = inference_result.generated_text.clone().unwrap_or_default();

    // Token estimate: chars/4 is a better approximation for English text than
    // whitespace splitting (GPT tokenizers average ~4 chars/token). This is
    // still an estimate — exact counting would require a tokenizer library.
    let prompt_tokens = estimate_tokens(&prompt);
    let completion_tokens = estimate_tokens(&generated_text);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let metadata = build_metadata(&state, &inference_result, &req.model, model_id);

    tracing::info!(
        request_id = %request_id,
        model = %model_id,
        latency_ms = %elapsed_ms,
        streaming = is_streaming,
        has_receipt = %metadata.is_some(),
        "Chat completion served"
    );

    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        headers.insert("x-request-id", v);
    }
    attach_metadata_headers(&mut headers, &metadata, &state);

    // Branch: SSE streaming vs standard JSON response.
    if is_streaming {
        let stream_id = format!("chatcmpl-{request_id}");
        let stream_metadata = if state.config.include_metadata_json {
            metadata.clone()
        } else {
            None
        };
        return streaming::build_sse_response(
            &stream_id,
            &state.config.default_model,
            now,
            &generated_text,
            stream_metadata,
            headers,
        );
    }

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

    (StatusCode::OK, headers, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// POST /v1/responses  (OpenAI Responses API compatibility)
// ---------------------------------------------------------------------------

pub async fn responses(
    State(state): State<AppState>,
    OpenAiJson(req): OpenAiJson<ResponsesRequest>,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let start = Instant::now();

    // Capability gate — reject unless "chat" is enabled.
    if !state.config.has_capability("chat") {
        tracing::info!(request_id = %request_id, "Rejected responses: chat capability not enabled");
        return error_response_with_id(
            StatusCode::BAD_REQUEST,
            ErrorResponse {
                error: ErrorBody {
                    message: "This model does not support chat/responses. Configure \
                        EPHEMERALML_MODEL_CAPABILITIES to include 'chat'."
                        .to_string(),
                    error_type: "invalid_request_error".to_string(),
                    param: Some("model".to_string()),
                    code: Some("unsupported_model_capability".to_string()),
                },
            },
            &request_id,
        );
    }

    if let Some(err) = model_capability_conflict(&state, &req.model, "chat") {
        return error_response_with_id(StatusCode::BAD_REQUEST, err, &request_id);
    }

    // Reject streaming
    if req.stream == Some(true) {
        return error_response_with_id(
            StatusCode::BAD_REQUEST,
            ErrorResponse::new(
                "Streaming is not supported in this version. Set stream=false or omit it.",
                "invalid_request_error",
                Some("unsupported_stream"),
            )
            .with_param("stream"),
            &request_id,
        );
    }

    // Reject unsupported fields
    if req.tools.is_some() {
        return error_response_with_id(
            StatusCode::BAD_REQUEST,
            ErrorResponse::new(
                "Tool use is not supported in this version.",
                "invalid_request_error",
                Some("unsupported_parameter"),
            )
            .with_param("tools"),
            &request_id,
        );
    }
    if req.tool_choice.is_some() {
        return error_response_with_id(
            StatusCode::BAD_REQUEST,
            ErrorResponse::new(
                "tool_choice is not supported in this version.",
                "invalid_request_error",
                Some("unsupported_parameter"),
            )
            .with_param("tool_choice"),
            &request_id,
        );
    }

    // Build prompt from input
    let prompt = match &req.input {
        ResponsesInput::Text(t) => {
            if t.is_empty() {
                return error_response_with_id(
                    StatusCode::BAD_REQUEST,
                    ErrorResponse::invalid_request("input must not be empty.").with_param("input"),
                    &request_id,
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
                return error_response_with_id(
                    StatusCode::BAD_REQUEST,
                    ErrorResponse::invalid_request("input messages must not be empty.")
                        .with_param("input"),
                    &request_id,
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
                state.reconnect_notify.notify_one();
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
            state.reconnect_notify.notify_one();
            return error_response_with_id(
                StatusCode::GATEWAY_TIMEOUT,
                ErrorResponse::server_error("Backend inference timed out."),
                &request_id,
            );
        }
    };

    let generated_text = inference_result.generated_text.clone().unwrap_or_default();

    let prompt_tokens = estimate_tokens(&prompt);
    let output_tokens = estimate_tokens(&generated_text);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let metadata = build_metadata(&state, &inference_result, &req.model, model_id);

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
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        headers.insert("x-request-id", v);
    }
    attach_metadata_headers(&mut headers, &metadata, &state);

    (StatusCode::OK, headers, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// POST /v1/embeddings
// ---------------------------------------------------------------------------

pub async fn embeddings(
    State(state): State<AppState>,
    OpenAiJson(req): OpenAiJson<EmbeddingRequest>,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let start = Instant::now();

    // Capability gate — reject unless "embeddings" is explicitly enabled.
    if !state.config.has_capability("embeddings") {
        tracing::info!(request_id = %request_id, "Rejected embeddings: capability not enabled");
        return error_response_with_id(
            StatusCode::BAD_REQUEST,
            ErrorResponse {
                error: ErrorBody {
                    message: "This model does not support embeddings. Configure \
                        EPHEMERALML_MODEL_CAPABILITIES to include 'embeddings' or set up a \
                        dedicated embedding backend with \
                        EPHEMERALML_EMBEDDING_BACKEND_ADDR."
                        .to_string(),
                    error_type: "invalid_request_error".to_string(),
                    param: Some("model".to_string()),
                    code: Some("unsupported_model_capability".to_string()),
                },
            },
            &request_id,
        );
    }

    if let Some(err) = model_capability_conflict(&state, &req.model, "embeddings") {
        return error_response_with_id(StatusCode::BAD_REQUEST, err, &request_id);
    }

    let texts = match &req.input {
        EmbeddingInput::Single(s) => vec![s.clone()],
        EmbeddingInput::Multiple(v) => v.clone(),
    };

    if texts.is_empty() {
        return error_response_with_id(
            StatusCode::BAD_REQUEST,
            ErrorResponse::invalid_request("input must not be empty.").with_param("input"),
            &request_id,
        );
    }

    // Reject encoding_format="base64" — only "float" is supported.
    if let Some(ref fmt) = req.encoding_format {
        if fmt != "float" {
            return error_response_with_id(
                StatusCode::BAD_REQUEST,
                ErrorResponse::new(
                    format!("encoding_format '{fmt}' is not supported. Only 'float' is supported."),
                    "invalid_request_error",
                    Some("unsupported_parameter"),
                )
                .with_param("encoding_format"),
                &request_id,
            );
        }
    }

    // Determine which client + model to use for embeddings.
    let use_separate = state.embedding_client.is_some();

    if use_separate {
        if let Err(e) = state.ensure_embedding_connected().await {
            tracing::error!(request_id = %request_id, error = %e, "Embedding backend connection failed");
            return error_response_with_id(
                StatusCode::BAD_GATEWAY,
                ErrorResponse::server_error(format!("Embedding backend unavailable: {e}")),
                &request_id,
            );
        }
    } else if let Err(e) = state.ensure_connected().await {
        tracing::error!(request_id = %request_id, error = %e, "Backend connection failed");
        return error_response_with_id(
            StatusCode::BAD_GATEWAY,
            ErrorResponse::server_error(format!("Backend unavailable: {e}")),
            &request_id,
        );
    }

    let model_id = if use_separate {
        state
            .config
            .embedding_model
            .as_deref()
            .unwrap_or(&state.config.default_model)
    } else {
        &state.config.default_model
    };
    let timeout = tokio::time::Duration::from_secs(state.config.request_timeout_secs);

    let mut data = Vec::with_capacity(texts.len());
    let mut total_tokens: u32 = 0;
    let mut last_result: Option<InferenceResult> = None;

    for (i, text) in texts.iter().enumerate() {
        let result = if use_separate {
            let emb = state.embedding_client.as_ref().unwrap();
            let mut client = emb.lock().await;
            tokio::time::timeout(timeout, client.execute_inference_text(model_id, text)).await
        } else {
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
                    if use_separate {
                        state
                            .embedding_connected
                            .store(false, std::sync::atomic::Ordering::Release);
                        state.embedding_reconnect_notify.notify_one();
                    } else {
                        state
                            .connected
                            .store(false, std::sync::atomic::Ordering::Release);
                        state.reconnect_notify.notify_one();
                    }
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
                if use_separate {
                    state
                        .embedding_connected
                        .store(false, std::sync::atomic::Ordering::Release);
                    state.embedding_reconnect_notify.notify_one();
                } else {
                    state
                        .connected
                        .store(false, std::sync::atomic::Ordering::Release);
                    state.reconnect_notify.notify_one();
                }
                return error_response_with_id(
                    StatusCode::GATEWAY_TIMEOUT,
                    ErrorResponse::server_error("Backend inference timed out."),
                    &request_id,
                );
            }
        };

        let tokens = estimate_tokens(text);
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
        .map(|r| build_metadata(&state, r, &req.model, model_id))
        .unwrap_or(None);

    let response_model = if use_separate {
        state
            .config
            .embedding_model
            .clone()
            .unwrap_or_else(|| state.config.default_model.clone())
    } else {
        state.config.default_model.clone()
    };

    let body = EmbeddingResponse {
        object: "list",
        data,
        model: response_model,
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
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        headers.insert("x-request-id", v);
    }
    attach_metadata_headers(&mut headers, &metadata, &state);

    (StatusCode::OK, headers, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Estimate token count from text using chars/4 heuristic.
///
/// GPT-style tokenizers average roughly 4 characters per token for English
/// text. This is more accurate than whitespace splitting (which undercounts
/// tokens in short or punctuation-heavy text). For exact counts, a proper
/// tokenizer (e.g. tiktoken) would be needed, but that adds a heavy dependency.
fn estimate_tokens(text: &str) -> u32 {
    let char_count = text.len();
    // Ensure at least 1 token for non-empty text.
    if char_count == 0 {
        0
    } else {
        ((char_count as f64 / 4.0).ceil() as u32).max(1)
    }
}

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

/// Enforce capability semantics for the concrete backend model IDs exposed by
/// `/v1/models`, while still allowing arbitrary caller aliases like `gpt-4`.
fn model_capability_conflict(
    state: &AppState,
    requested_model: &str,
    required_capability: &str,
) -> Option<ErrorResponse> {
    state.config.embedding_backend_addr.as_ref()?;

    match required_capability {
        "chat" => {
            if state.config.embedding_model.as_deref() == Some(requested_model) {
                Some(
                    ErrorResponse::new(
                        format!(
                            "Model '{requested_model}' is embeddings-only. Use /v1/embeddings or request a chat-capable model."
                        ),
                        "invalid_request_error",
                        Some("unsupported_model_capability"),
                    )
                    .with_param("model"),
                )
            } else {
                None
            }
        }
        "embeddings" => {
            if requested_model == state.config.default_model {
                Some(
                    ErrorResponse::new(
                        format!(
                            "Model '{requested_model}' does not support embeddings. Use the embedding-capable model advertised by /v1/models."
                        ),
                        "invalid_request_error",
                        Some("unsupported_model_capability"),
                    )
                    .with_param("model"),
                )
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Build EphemeralML metadata from an inference result.
///
/// `executed_model` is the model ID that actually ran the inference (may differ
/// from `default_model` when a dedicated embedding backend is in use).
fn build_metadata(
    _state: &AppState,
    result: &InferenceResult,
    requested_model: &str,
    executed_model: &str,
) -> Option<EphemeralMetadata> {
    let manifest_sha256 = result.model_manifest_json.as_ref().map(|json| {
        let hash = Sha256::digest(json.as_bytes());
        hex::encode(hash)
    });
    let attestation_mode = result
        .receipt
        .attestation_source
        .clone()
        .or_else(|| {
            infer_attestation_mode_from_measurements(
                result
                    .receipt
                    .enclave_measurements
                    .measurement_type
                    .as_str(),
            )
            .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string());

    let receipt_sha256 = result.air_v1_receipt_b64.as_ref().map(|b64| {
        let hash = Sha256::digest(b64.as_bytes());
        hex::encode(hash)
    });

    Some(EphemeralMetadata {
        receipt_id: result.receipt.receipt_id.clone(),
        attestation_mode,
        executed_model: executed_model.to_string(),
        requested_model: requested_model.to_string(),
        receipt_sha256,
        air_v1_receipt_b64: result.air_v1_receipt_b64.clone(),
        model_manifest_sha256: manifest_sha256,
    })
}

fn infer_attestation_mode_from_measurements(measurement_type: &str) -> Option<&'static str> {
    match measurement_type {
        "tdx-mrtd-rtmr" => Some("cs-tdx"),
        "nitro-pcr" => Some("nitro-pcr"),
        "sev-snp" => Some("sev-snp"),
        _ => None,
    }
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

/// Build an OpenAI-style error response with x-request-id header.
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
    fn measurement_type_fallback_maps_tdx_to_cs_tdx() {
        assert_eq!(
            infer_attestation_mode_from_measurements("tdx-mrtd-rtmr"),
            Some("cs-tdx")
        );
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
    fn stream_true_parses_in_chat_request() {
        let json = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true
        });
        let req: ChatCompletionRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.stream, Some(true));
    }

    #[test]
    fn stream_false_parses_in_chat_request() {
        let json = serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": false
        });
        let req: ChatCompletionRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.stream, Some(false));
    }

    #[test]
    fn estimate_tokens_empty() {
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn estimate_tokens_short_text() {
        // "hi" = 2 chars -> ceil(2/4) = 1 token
        assert_eq!(estimate_tokens("hi"), 1);
    }

    #[test]
    fn estimate_tokens_longer_text() {
        // "Hello, world!" = 13 chars -> ceil(13/4) = 4 tokens
        assert_eq!(estimate_tokens("Hello, world!"), 4);
    }

    #[test]
    fn estimate_tokens_sentence() {
        // Typical English: ~4 chars per token
        let text = "The quick brown fox jumps over the lazy dog.";
        let tokens = estimate_tokens(text);
        // 44 chars -> ceil(44/4) = 11
        assert_eq!(tokens, 11);
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

    #[test]
    fn rate_limit_error_shape() {
        let err = ErrorResponse::new(
            "Rate limit exceeded.",
            "rate_limit_error",
            Some("rate_limit_exceeded"),
        );
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["error"]["type"], "rate_limit_error");
        assert_eq!(json["error"]["code"], "rate_limit_exceeded");
    }

    #[test]
    fn server_busy_error_shape() {
        let err = ErrorResponse::new("Server is busy.", "server_error", Some("server_busy"));
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["error"]["type"], "server_error");
        assert_eq!(json["error"]["code"], "server_busy");
    }
}
