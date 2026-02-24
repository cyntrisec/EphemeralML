use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use subtle::ConstantTimeEq;

use crate::api_types::ErrorResponse;
use crate::AppState;

/// API key authentication middleware.
///
/// Checks `Authorization: Bearer <key>` or `X-API-Key: <key>` headers.
/// Skips auth for health and landing page endpoints.
/// Uses constant-time comparison to prevent timing side-channel attacks.
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let expected = match &state.api_key {
        Some(k) => k,
        None => return next.run(request).await,
    };

    // Skip auth for health check and landing page
    let path = request.uri().path();
    if path == "/health" || path == "/" {
        return next.run(request).await;
    }

    let provided = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            request
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
        });

    match provided {
        Some(key)
            if key.as_bytes().len() == expected.as_bytes().len()
                && key.as_bytes().ct_eq(expected.as_bytes()).into() =>
        {
            next.run(request).await
        }
        Some(_) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid API key".to_string(),
            }),
        )
            .into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing API key. Provide Authorization: Bearer <key> or X-API-Key: <key>"
                    .to_string(),
            }),
        )
            .into_response(),
    }
}
