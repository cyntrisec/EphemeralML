//! Bearer-token authentication middleware.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use subtle::ConstantTimeEq;

use crate::state::AppState;
use crate::types::ErrorResponse;

/// Axum middleware that checks `Authorization: Bearer <token>` when
/// `EPHEMERALML_API_KEY` is configured. Skips auth for `/health` and `/readyz`.
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let api_key = match &state.config.api_key {
        Some(key) if !key.is_empty() => key,
        _ => return next.run(request).await,
    };

    // Skip auth on operational endpoints
    let path = request.uri().path();
    if path == "/health" || path == "/readyz" {
        return next.run(request).await;
    }

    let provided = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(token) if token.as_bytes().ct_eq(api_key.as_bytes()).into() => next.run(request).await,
        _ => {
            let request_id = uuid::Uuid::new_v4().to_string();
            let body = ErrorResponse::auth_error();
            let mut headers = HeaderMap::new();
            if let Ok(v) = HeaderValue::from_str(&request_id) {
                headers.insert("x-request-id", v);
            }
            (StatusCode::UNAUTHORIZED, headers, Json(body)).into_response()
        }
    }
}
