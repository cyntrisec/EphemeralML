//! Bearer-token authentication middleware.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};

use crate::state::AppState;
use crate::types::ErrorResponse;

fn api_key_matches(expected: &str, provided: &str) -> bool {
    let expected_bytes = expected.as_bytes();
    let provided_bytes = provided.as_bytes();
    let mut diff = expected_bytes.len() ^ provided_bytes.len();

    for (index, expected_byte) in expected_bytes.iter().enumerate() {
        let provided_byte = provided_bytes.get(index).copied().unwrap_or(0);
        diff |= usize::from(*expected_byte ^ provided_byte);
    }

    diff == 0
}

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
        Some(token) if api_key_matches(api_key, token) => next.run(request).await,
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

#[cfg(test)]
mod tests {
    use super::api_key_matches;

    #[test]
    fn api_key_matches_accepts_exact_match() {
        assert!(api_key_matches("secret-key", "secret-key"));
    }

    #[test]
    fn api_key_matches_rejects_shorter_and_longer_inputs() {
        assert!(!api_key_matches("secret-key", "secret"));
        assert!(!api_key_matches("secret-key", "secret-key-extra"));
    }

    #[test]
    fn api_key_matches_rejects_same_length_wrong_input() {
        assert!(!api_key_matches("secret-key", "secret-kez"));
    }
}
