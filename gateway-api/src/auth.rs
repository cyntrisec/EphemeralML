//! Bearer-token authentication middleware.

use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use crate::state::AppState;
use crate::types::ErrorResponse;

/// Axum middleware that checks `Authorization: Bearer <token>` when
/// `EPHEMERALML_API_KEY` is configured. Skips auth for `/health`.
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let api_key = match &state.config.api_key {
        Some(key) => key,
        None => return next.run(request).await,
    };

    // Skip auth on health endpoint
    if request.uri().path() == "/health" {
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
            let body = ErrorResponse::auth_error();
            let mut resp = axum::response::Json(body).into_response();
            *resp.status_mut() = axum::http::StatusCode::UNAUTHORIZED;
            resp
        }
    }
}
