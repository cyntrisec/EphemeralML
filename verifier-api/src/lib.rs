pub mod api_types;
pub mod auth;
pub mod rate_limit;
pub mod routes;
pub mod templates;
pub mod verify_dispatch;
pub mod view_model;

use axum::http::HeaderValue;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use std::fmt;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use rate_limit::RateLimiter;

/// Shared application state available to middleware and handlers.
#[derive(Clone)]
pub struct AppState {
    pub api_key: Option<String>,
    pub rate_limiter: Option<RateLimiter>,
}

/// Deployment mode for the verifier service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceMode {
    /// Public Verification Center: no API key, rate-limited, explicit CORS.
    PublicTrustCenter,
    /// Secured API: API key required, explicit CORS.
    SecuredApi,
}

/// Server configuration for production deployments.
pub struct ServerConfig {
    /// Deployment mode.
    pub mode: ServiceMode,
    /// API key for authentication (required in SecuredApi mode).
    pub api_key: Option<String>,
    /// Maximum requests per minute per IP. 0 disables rate limiting.
    pub requests_per_minute: u32,
    /// Allowed CORS origins. Empty = permissive.
    pub cors_origins: Vec<String>,
}

/// Router construction failed because service configuration violates a
/// deployment invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    PublicModeWithApiKey,
    PublicModeWithoutRateLimit,
    SecuredModeWithoutApiKey,
    InvalidCorsOrigin(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicModeWithApiKey => {
                f.write_str("PublicTrustCenter mode must not have an API key")
            }
            Self::PublicModeWithoutRateLimit => {
                f.write_str("PublicTrustCenter mode requires a positive rate limit")
            }
            Self::SecuredModeWithoutApiKey => f.write_str("SecuredApi mode requires an API key"),
            Self::InvalidCorsOrigin(origin) => {
                write!(f, "invalid CORS origin: {origin}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Build the router with permissive defaults (for local dev / tests).
///
/// No auth, no rate limiting, permissive CORS. **Not for production.**
pub fn build_router() -> Router {
    let state = AppState {
        api_key: None,
        rate_limiter: None,
    };
    build_router_inner(CorsLayer::permissive(), state)
}

/// Build the router with full production configuration.
///
/// Enforces mode invariants:
/// - `PublicTrustCenter`: api_key must be None, rate limiting must be active.
/// - `SecuredApi`: api_key must be Some.
pub fn build_router_with_config(config: &ServerConfig) -> Result<Router, ConfigError> {
    // Enforce mode invariants so programmatic callers cannot bypass guardrails.
    match config.mode {
        ServiceMode::PublicTrustCenter => {
            if config.api_key.is_some() {
                return Err(ConfigError::PublicModeWithApiKey);
            }
            if config.requests_per_minute == 0 {
                return Err(ConfigError::PublicModeWithoutRateLimit);
            }
        }
        ServiceMode::SecuredApi => {
            if config.api_key.is_none() {
                return Err(ConfigError::SecuredModeWithoutApiKey);
            }
        }
    }

    let cors = make_cors_layer(&config.cors_origins)?;
    let rate_limiter = if config.requests_per_minute > 0 {
        let limiter = RateLimiter::new(config.requests_per_minute);
        limiter.spawn_cleanup_task();
        Some(limiter)
    } else {
        None
    };
    let state = AppState {
        api_key: config.api_key.clone(),
        rate_limiter,
    };
    Ok(build_router_inner(cors, state))
}

fn make_cors_layer(origins: &[String]) -> Result<CorsLayer, ConfigError> {
    if origins.is_empty() {
        Ok(CorsLayer::permissive())
    } else {
        let parsed: Vec<_> = origins
            .iter()
            .map(|origin| {
                if origin == "*" {
                    return Err(ConfigError::InvalidCorsOrigin(origin.clone()));
                }
                origin
                    .parse::<HeaderValue>()
                    .map_err(|_| ConfigError::InvalidCorsOrigin(origin.clone()))
            })
            .collect::<Result<_, _>>()?;
        Ok(CorsLayer::new()
            .allow_origin(AllowOrigin::list(parsed))
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any))
    }
}

fn build_router_inner(cors: CorsLayer, state: AppState) -> Router {
    Router::new()
        .route("/", get(routes::landing_page))
        .route(
            "/evidence/aws-native-poc",
            get(routes::aws_native_poc_evidence),
        )
        .route("/health", get(routes::health))
        .route("/api/v1/verify", post(routes::verify_json))
        .route("/api/v1/verify/upload", post(routes::verify_upload))
        .route("/api/v1/samples/valid", get(routes::sample_valid))
        .route("/api/v1/samples/legacy", get(routes::sample_legacy))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit::rate_limit_middleware,
        ))
        .with_state(state)
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024)) // 2 MB
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self' 'unsafe-inline'; \
                 style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
                 font-src https://fonts.gstatic.com; \
                 img-src 'self' https://cyntrisec.com; \
                 connect-src 'self'; \
                 object-src 'none'; base-uri 'none'; form-action 'self'; \
                 frame-ancestors 'none'",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        ))
        .layer(TraceLayer::new_for_http())
}
