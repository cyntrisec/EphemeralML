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
    let config = GatewayConfig {
        backend_addr: "127.0.0.1:0".to_string(),
        default_model: "test-model".to_string(),
        api_key,
        host: "127.0.0.1".to_string(),
        port: 0,
        request_timeout_secs: 5,
        include_metadata_json,
        receipt_header_full,
    };
    let client = SecureEnclaveClient::new("test-gateway".to_string());
    let state = AppState::new(client, config);
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
    let json = body_json(resp).await;
    assert_eq!(json["error"]["type"], "server_error");
}

// ---------------------------------------------------------------------------
// Embeddings — validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn embeddings_rejects_empty_input() {
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "text-embedding-3-small",
        "input": []
    });
    let req = json_request("POST", "/v1/embeddings", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn embeddings_returns_502_when_backend_unavailable() {
    let app = test_router(None, false, false);
    let body = serde_json::json!({
        "model": "text-embedding-3-small",
        "input": "hello world"
    });
    let req = json_request("POST", "/v1/embeddings", body, None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
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
