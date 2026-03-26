//! EphemeralML OpenAI-compatible gateway.
//!
//! Exposes `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, and
//! `/v1/models` backed by `SecureEnclaveClient`. Attestation metadata is
//! returned in response headers (`x-ephemeralml-*`) and optionally in the
//! JSON body.

pub mod auth;
pub mod config;
pub mod rate_limit;
pub mod reconnect;
pub mod routes;
pub mod state;
pub mod streaming;
pub mod types;

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::rate_limit::RateLimitResult;
use crate::state::AppState;
use crate::types::ErrorResponse;

/// Build the Axum router with all routes and middleware.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(routes::chat_completions))
        .route("/v1/responses", post(routes::responses))
        .route("/v1/embeddings", post(routes::embeddings))
        .route("/v1/models", get(routes::list_models))
        .route("/health", get(routes::health))
        .route("/readyz", get(routes::readyz))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024)) // 2 MB
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Rate limiting and concurrency middleware.
///
/// Checks per-IP rate limits, acquires a concurrency semaphore permit,
/// and returns appropriate HTTP 429/503 errors when limits are exceeded.
async fn rate_limit_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = request.uri().path();

    // Skip rate limiting on health/readyz endpoints.
    if path == "/health" || path == "/readyz" {
        return next.run(request).await;
    }

    // Extract client IP from forwarded headers or fall back to "unknown".
    let client_ip = extract_client_ip(&request, state.config.trust_proxy_headers);

    // Per-IP and global rate limit check.
    match state.rate_limiter.check(&client_ip) {
        RateLimitResult::Allowed => {}
        RateLimitResult::Denied { retry_after_secs } => {
            let request_id = uuid::Uuid::new_v4().to_string();
            tracing::warn!(
                request_id = %request_id,
                client_ip = %client_ip,
                retry_after_secs,
                "Rate limit exceeded"
            );
            let body = ErrorResponse::new(
                "Rate limit exceeded. Please retry after the indicated period.",
                "rate_limit_error",
                Some("rate_limit_exceeded"),
            );
            let mut headers = HeaderMap::new();
            if let Ok(v) = HeaderValue::from_str(&request_id) {
                headers.insert("x-request-id", v);
            }
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                headers.insert("retry-after", v);
            }
            return (StatusCode::TOO_MANY_REQUESTS, headers, Json(body)).into_response();
        }
    }

    // Concurrency limit: try to acquire a semaphore permit.
    let permit = state.concurrency_semaphore.clone().try_acquire_owned();
    match permit {
        Ok(_permit) => {
            // Permit acquired — the permit is held until this handler completes
            // (the _permit is dropped at the end of the scope).
            next.run(request).await
        }
        Err(_) => {
            let request_id = uuid::Uuid::new_v4().to_string();
            tracing::warn!(
                request_id = %request_id,
                client_ip = %client_ip,
                max_concurrent = state.config.max_concurrent_requests,
                "Concurrency limit exceeded"
            );
            let body = ErrorResponse::new(
                "Server is busy. All inference slots are currently occupied. Please retry shortly.",
                "server_error",
                Some("server_busy"),
            );
            let mut headers = HeaderMap::new();
            if let Ok(v) = HeaderValue::from_str(&request_id) {
                headers.insert("x-request-id", v);
            }
            headers.insert("retry-after", HeaderValue::from_static("1"));
            (StatusCode::SERVICE_UNAVAILABLE, headers, Json(body)).into_response()
        }
    }
}

/// Extract client IP for rate limiting.
///
/// By default, the gateway uses the socket peer address from `ConnectInfo`.
/// When `trust_proxy_headers` is explicitly enabled, it prefers:
/// 1. `X-Forwarded-For` header (first IP)
/// 2. `X-Real-Ip` header
/// 3. Socket peer address via `ConnectInfo`
/// 4. Falls back to "unknown"
fn extract_client_ip(
    request: &axum::http::Request<axum::body::Body>,
    trust_proxy_headers: bool,
) -> String {
    if trust_proxy_headers {
        // X-Forwarded-For: client, proxy1, proxy2
        if let Some(xff) = request.headers().get("x-forwarded-for") {
            if let Ok(xff_str) = xff.to_str() {
                if let Some(first_ip) = xff_str.split(',').next() {
                    let trimmed = first_ip.trim();
                    if !trimmed.is_empty() {
                        return trimmed.to_string();
                    }
                }
            }
        }

        // X-Real-Ip
        if let Some(real_ip) = request.headers().get("x-real-ip") {
            if let Ok(ip_str) = real_ip.to_str() {
                let trimmed = ip_str.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }

    request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn extract_client_ip_prefers_socket_peer_by_default() {
        let mut req = axum::http::Request::builder()
            .uri("/v1/chat/completions")
            .body(Body::empty())
            .unwrap();
        req.headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.9"));
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from((
                [203, 0, 113, 7],
                1234,
            ))));

        assert_eq!(extract_client_ip(&req, false), "203.0.113.7");
    }

    #[test]
    fn extract_client_ip_uses_forwarded_headers_when_explicitly_trusted() {
        let mut req = axum::http::Request::builder()
            .uri("/v1/chat/completions")
            .body(Body::empty())
            .unwrap();
        req.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.9, 203.0.113.7"),
        );
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from((
                [203, 0, 113, 7],
                1234,
            ))));

        assert_eq!(extract_client_ip(&req, true), "198.51.100.9");
    }
}
