use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::api_types::ErrorResponse;
use crate::AppState;

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

/// API key authentication middleware.
///
/// Checks `Authorization: Bearer <key>` or `X-API-Key: <key>` headers.
/// Skips auth for health and landing page endpoints.
/// Uses a fixed-work comparison helper to avoid leaking key length via
/// early return on mismatched-length inputs.
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let expected = match &state.api_key {
        Some(k) => k,
        None => return next.run(request).await,
    };

    // Skip auth only for explicit public routes. Keep this allowlist narrow so
    // future internal evidence paths cannot become public by namespace alone.
    let path = request.uri().path();
    if path == "/health"
        || path == "/"
        || path == "/evidence/aws-native-poc"
        || path.starts_with("/api/v1/samples/")
    {
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
        Some(key) if api_key_matches(expected, key) => next.run(request).await,
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

#[cfg(test)]
mod tests {
    use super::api_key_matches;

    #[test]
    fn api_key_matches_accepts_exact_match() {
        assert!(api_key_matches(
            "test-secret-key-1234",
            "test-secret-key-1234"
        ));
    }

    #[test]
    fn api_key_matches_rejects_different_lengths() {
        assert!(!api_key_matches("test-secret-key-1234", "short"));
        assert!(!api_key_matches(
            "test-secret-key-1234",
            "test-secret-key-1234-extra"
        ));
    }

    #[test]
    fn api_key_matches_rejects_same_length_wrong_input() {
        assert!(!api_key_matches(
            "test-secret-key-1234",
            "test-secret-key-1235"
        ));
    }
}
