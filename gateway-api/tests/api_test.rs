//! Integration tests for the OpenAI-compatible gateway.
//!
//! These tests exercise the HTTP layer (request parsing, response shape,
//! auth, error handling) without a live backend — the client is created
//! but never connected, so inference calls will fail with a clear error.

use axum::http::StatusCode;
use axum::Router;
use tower::ServiceExt;

use ephemeral_ml_client::SecureEnclaveClient;
use ephemeralml_gateway::config::GatewayConfig;
use ephemeralml_gateway::state::AppState;

/// Build a test router with a disconnected client.
fn test_router(
    api_key: Option<String>,
    include_metadata_json: bool,
    receipt_header_full: bool,
) -> Router {
    test_router_with_capabilities(api_key, include_metadata_json, receipt_header_full, "chat")
}

fn test_router_with_capabilities(
    api_key: Option<String>,
    include_metadata_json: bool,
    receipt_header_full: bool,
    model_capabilities: &str,
) -> Router {
    let config = GatewayConfig {
        backend_addr: "127.0.0.1:0".to_string(),
        default_model: "test-model".to_string(),
        api_key,
        host: "127.0.0.1".to_string(),
        port: 0,
        request_timeout_secs: 5,
        include_metadata_json,
        receipt_header_full,
        model_capabilities: model_capabilities.to_string(),
        embedding_backend_addr: None,
        embedding_model: None,
    };
    let client = SecureEnclaveClient::new("test-gateway".to_string());
    let state = AppState::new(client, config, None);
    ephemeralml_gateway::build_router(state)
}

/// Build a test router with a dedicated embedding backend (disconnected).
fn test_router_with_embedding_backend(
    model_capabilities: &str,
    embedding_model: &str,
) -> Router {
    let config = GatewayConfig {
        backend_addr: "127.0.0.1:0".to_string(),
        default_model: "test-model".to_string(),
        api_key: None,
        host: "127.0.0.1".to_string(),
        port: 0,
        request_timeout_secs: 5,
        include_metadata_json: false,
        receipt_header_full: false,
        model_capabilities: model_capabilities.to_string(),
        embedding_backend_addr: Some("127.0.0.1:0".to_string()),
        embedding_model: Some(embedding_model.to_string()),
    };
    let client = SecureEnclaveClient::new("test-gateway".to_string());
    let emb_client = SecureEnclaveClient::new("test-gateway-embedding".to_string());
    let state = AppState::new(client, config, Some(emb_client));
    ephemeralml_gateway::build_router(state)
}

fn json_request(
    method: &str,
    uri: &str,
    body: serde_json::Value,
    bearer: Option<&str>,
) -> axum::http::Request<axum::body::Body> {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn body_json(response: axum::http::Response<axum::body::Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// Health endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_returns_status() {
    let app = test_router(None, false, false);
    let req = axum::http::Request::builder()
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["backend_connected"], false);
    // No embedding fields when not configured
    assert!(json.get("embedding_backend_configured").is_none());
}

#[tokio::test]
async fn health_with_embedding_backend_shows_both() {
    let app = test_router_with_embedding_backend("chat,embeddings", "emb-model");
    let req = axum::http::Request::builder()
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["backend_connected"], false);
    assert_eq!(json["embedding_backend_configured"], true);
    assert_eq!(json["embedding_backend_connected"], false);
    // Both backends disconnected → "unavailable"
    assert_eq!(json["status"], "unavailable");
}

// ---------------------------------------------------------------------------
// Readiness endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn readyz_returns_503_when_disconnected() {
    let app = test_router(None, false, false);
    let req = axum::http::Request::builder()
        .uri("/readyz")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json = body_json(resp).await;
    assert_eq!(json["ready"], false);
    assert_eq!(json["backend_connected"], false);
}

#[tokio::test]
async fn readyz_with_embedding_backend_shows_both() {
    let app = test_router_with_embedding_backend("chat,embeddings", "emb-model");
    let req = axum::http::Request::builder()
        .uri("/readyz")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json = body_json(resp).await;
    assert_eq!(json["ready"], false);
    assert_eq!(json["embedding_backend_configured"], true);
    assert_eq!(json["embedding_backend_connected"], false);
}

#[tokio::test]
async fn readyz_skips_auth() {
    let app = test_router(Some("secret-key".into()), false, false);
    let req = axum::http::Request::builder()
        .uri("/readyz")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // 503, not 401 — auth is skipped for /readyz
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ---------------------------------------------------------------------------
// Models endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn models_returns_list() {
    let app = test_router(None, false, false);
    let req = axum::http::Request::builder()
        .uri("/v1/models")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["object"], "list");
    assert_eq!(json["data"][0]["id"], "test-model");
    assert_eq!(json["data"][0]["owned_by"], "ephemeralml");
}

#[tokio::test]
async fn models_with_separate_embedding_backend_no_duplicates() {
    let app = test_router_with_embedding_backend("chat,embeddings", "emb-model");
    let req = axum::http::Request::builder()
        .uri("/v1/models")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let data = json["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);
    // IDs must be distinct
    let ids: Vec<&str> = data.iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert_eq!(ids[0], "test-model");
    assert_eq!(ids[1], "emb-model");
    assert_ne!(ids[0], ids[1]);
    // Main model: chat=true, embeddings=false (separate backend handles embeddings)
    assert_eq!(data[0]["_ephemeralml"]["capabilities"]["chat"], true);
    assert_eq!(data[0]["_ephemeralml"]["capabilities"]["embeddings"], false);
    // Embedding model: chat=false, embeddings=true
    assert_eq!(data[1]["_ephemeralml"]["capabilities"]["chat"], false);
    assert_eq!(data[1]["_ephemeralml"]["capabilities"]["embeddings"], true);
}

// ---------------------------------------------------------------------------
// Chat completions — validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn chat_rejects_stream_true() {
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    });
    let req = json_request("POST", "/v1/chat/completions", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("x-request-id").is_some());
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "unsupported_stream");
}

#[tokio::test]
async fn chat_rejects_empty_messages() {
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": []
    });
    let req = json_request("POST", "/v1/chat/completions", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("x-request-id").is_some());
    let json = body_json(resp).await;
    assert!(json["error"]["message"].as_str().unwrap().contains("empty"));
}

#[tokio::test]
async fn chat_returns_502_when_backend_unavailable() {
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let req = json_request("POST", "/v1/chat/completions", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(resp.headers().get("x-request-id").is_some());
    let json = body_json(resp).await;
    assert_eq!(json["error"]["type"], "server_error");
}

// ---------------------------------------------------------------------------
// Embeddings — validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn embeddings_rejects_empty_input() {
    let app = test_router_with_capabilities(None, false, false, "chat,embeddings");
    let body = serde_json::json!({
        "model": "text-embedding-3-small",
        "input": []
    });
    let req = json_request("POST", "/v1/embeddings", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("x-request-id").is_some());
}

#[tokio::test]
async fn embeddings_returns_502_when_backend_unavailable() {
    let app = test_router_with_capabilities(None, false, false, "chat,embeddings");
    let body = serde_json::json!({
        "model": "text-embedding-3-small",
        "input": "hello world"
    });
    let req = json_request("POST", "/v1/embeddings", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(resp.headers().get("x-request-id").is_some());
}

#[tokio::test]
async fn embeddings_with_separate_backend_returns_502() {
    // Dedicated embedding backend is configured but not connected → 502
    let app = test_router_with_embedding_backend("chat,embeddings", "emb-model");
    let body = serde_json::json!({
        "model": "emb-model",
        "input": "hello world"
    });
    let req = json_request("POST", "/v1/embeddings", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(resp.headers().get("x-request-id").is_some());
}

// ---------------------------------------------------------------------------
// /v1/responses — validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn responses_rejects_stream_true() {
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "gpt-4",
        "input": "hello",
        "stream": true
    });
    let req = json_request("POST", "/v1/responses", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("x-request-id").is_some());
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "unsupported_stream");
}

#[tokio::test]
async fn responses_rejects_tools() {
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "gpt-4",
        "input": "hello",
        "tools": [{"type": "function", "function": {"name": "f"}}]
    });
    let req = json_request("POST", "/v1/responses", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("x-request-id").is_some());
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "unsupported_parameter");
}

#[tokio::test]
async fn responses_rejects_empty_text_input() {
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "gpt-4",
        "input": ""
    });
    let req = json_request("POST", "/v1/responses", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("x-request-id").is_some());
}

#[tokio::test]
async fn responses_rejects_empty_messages_input() {
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "gpt-4",
        "input": []
    });
    let req = json_request("POST", "/v1/responses", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("x-request-id").is_some());
}

#[tokio::test]
async fn responses_returns_502_when_backend_unavailable() {
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "gpt-4",
        "input": "hello world"
    });
    let req = json_request("POST", "/v1/responses", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(resp.headers().get("x-request-id").is_some());
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_rejects_missing_token() {
    let app = test_router(Some("secret-key".into()), false, false);
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let req = json_request("POST", "/v1/chat/completions", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get("x-request-id").is_some());
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "invalid_api_key");
}

#[tokio::test]
async fn auth_rejects_wrong_token() {
    let app = test_router(Some("secret-key".into()), false, false);
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let req = json_request("POST", "/v1/chat/completions", body, Some("wrong-key"));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get("x-request-id").is_some());
}

#[tokio::test]
async fn auth_passes_with_correct_token() {
    let app = test_router(Some("secret-key".into()), false, false);
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let req = json_request("POST", "/v1/chat/completions", body, Some("secret-key"));
    let resp = app.oneshot(req).await.unwrap();
    // Should get 502 (backend unavailable), not 401
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn auth_skips_health_endpoint() {
    let app = test_router(Some("secret-key".into()), false, false);
    let req = axum::http::Request::builder()
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Response shape compatibility
// ---------------------------------------------------------------------------

#[tokio::test]
async fn error_response_has_openai_shape() {
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    });
    let req = json_request("POST", "/v1/chat/completions", body, None);
    let resp = app.oneshot(req).await.unwrap();
    let json = body_json(resp).await;
    assert!(json["error"]["message"].is_string());
    assert!(json["error"]["type"].is_string());
}

// ---------------------------------------------------------------------------
// Capability gating — chat
// ---------------------------------------------------------------------------

#[tokio::test]
async fn chat_rejected_when_chat_capability_missing() {
    // capabilities="embeddings" only — chat should be rejected with 400.
    let app = test_router_with_capabilities(None, false, false, "embeddings");
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}]
    });
    let req = json_request("POST", "/v1/chat/completions", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("x-request-id").is_some());
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "unsupported_model_capability");
    assert_eq!(json["error"]["type"], "invalid_request_error");
    assert_eq!(json["error"]["param"], "model");
}

#[tokio::test]
async fn responses_rejected_when_chat_capability_missing() {
    // capabilities="embeddings" only — /v1/responses should be rejected with 400.
    let app = test_router_with_capabilities(None, false, false, "embeddings");
    let body = serde_json::json!({
        "model": "gpt-4",
        "input": "hello"
    });
    let req = json_request("POST", "/v1/responses", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("x-request-id").is_some());
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "unsupported_model_capability");
}

// ---------------------------------------------------------------------------
// Capability gating — embeddings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn embeddings_rejected_when_capability_missing() {
    // Default config is "chat" only — embeddings should be rejected with 400.
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "text-embedding-3-small",
        "input": "hello world"
    });
    let req = json_request("POST", "/v1/embeddings", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get("x-request-id").is_some());
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "unsupported_model_capability");
    assert_eq!(json["error"]["type"], "invalid_request_error");
    assert_eq!(json["error"]["param"], "model");
}

#[tokio::test]
async fn embeddings_allowed_when_capability_present() {
    // With "chat,embeddings" capability, embeddings should proceed past the
    // gate. Without a live backend it will return 502 (not 400).
    let app = test_router_with_capabilities(None, false, false, "chat,embeddings");
    let body = serde_json::json!({
        "model": "text-embedding-3-small",
        "input": "hello world"
    });
    let req = json_request("POST", "/v1/embeddings", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn models_includes_capabilities() {
    let app = test_router_with_capabilities(None, false, false, "chat,embeddings");
    let req = axum::http::Request::builder()
        .uri("/v1/models")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(
        json["data"][0]["_ephemeralml"]["capabilities"]["chat"],
        true
    );
    assert_eq!(
        json["data"][0]["_ephemeralml"]["capabilities"]["embeddings"],
        true
    );
}

#[tokio::test]
async fn models_chat_only_capabilities() {
    let app = test_router(None, false, false);
    let req = axum::http::Request::builder()
        .uri("/v1/models")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(
        json["data"][0]["_ephemeralml"]["capabilities"]["chat"],
        true
    );
    assert_eq!(
        json["data"][0]["_ephemeralml"]["capabilities"]["embeddings"],
        false
    );
}

#[tokio::test]
async fn error_envelope_shape_for_capability() {
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "text-embedding-3-small",
        "input": "test"
    });
    let req = json_request("POST", "/v1/embeddings", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    // Verify exact OpenAI error envelope structure
    assert!(json["error"].is_object());
    assert!(json["error"]["message"].is_string());
    assert_eq!(json["error"]["type"], "invalid_request_error");
    assert_eq!(json["error"]["param"], "model");
    assert_eq!(json["error"]["code"], "unsupported_model_capability");
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

#[test]
fn config_rejects_embedding_backend_without_model() {
    let config = GatewayConfig {
        backend_addr: "127.0.0.1:0".to_string(),
        default_model: "test-model".to_string(),
        api_key: None,
        host: "127.0.0.1".to_string(),
        port: 0,
        request_timeout_secs: 5,
        include_metadata_json: false,
        receipt_header_full: false,
        model_capabilities: "chat,embeddings".to_string(),
        embedding_backend_addr: Some("127.0.0.1:9999".to_string()),
        embedding_model: None,
    };
    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("EPHEMERALML_EMBEDDING_MODEL"));
}

#[test]
fn config_rejects_unknown_capability() {
    let config = GatewayConfig {
        backend_addr: "127.0.0.1:0".to_string(),
        default_model: "test-model".to_string(),
        api_key: None,
        host: "127.0.0.1".to_string(),
        port: 0,
        request_timeout_secs: 5,
        include_metadata_json: false,
        receipt_header_full: false,
        model_capabilities: "chat,banana".to_string(),
        embedding_backend_addr: None,
        embedding_model: None,
    };
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("banana"));
}

#[test]
fn config_accepts_valid_dual_backend() {
    let config = GatewayConfig {
        backend_addr: "127.0.0.1:0".to_string(),
        default_model: "test-model".to_string(),
        api_key: None,
        host: "127.0.0.1".to_string(),
        port: 0,
        request_timeout_secs: 5,
        include_metadata_json: false,
        receipt_header_full: false,
        model_capabilities: "chat,embeddings".to_string(),
        embedding_backend_addr: Some("127.0.0.1:9999".to_string()),
        embedding_model: Some("emb-model".to_string()),
    };
    assert!(config.validate().is_ok());
}
