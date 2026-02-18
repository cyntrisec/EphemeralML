pub mod api_types;
pub mod auth;
pub mod rate_limit;
pub mod routes;
pub mod templates;

use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use rate_limit::RateLimiter;

/// Shared application state available to middleware and handlers.
#[derive(Clone)]
pub struct AppState {
    pub api_key: Option<String>,
    pub rate_limiter: Option<RateLimiter>,
}

/// Server configuration for production deployments.
pub struct ServerConfig {
    /// API key for authentication. `None` disables auth.
    pub api_key: Option<String>,
    /// Maximum requests per minute per IP. 0 disables rate limiting.
    pub requests_per_minute: u32,
    /// Allowed CORS origins. Empty = permissive.
    pub cors_origins: Vec<String>,
}

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

/// Build the router with explicit allowed origins (legacy API, no auth/rate limit).
pub fn build_router_with_origins(origins: &[String]) -> Router {
    let cors = make_cors_layer(origins);
    let state = AppState {
        api_key: None,
        rate_limiter: None,
    };
    build_router_inner(cors, state)
}

/// Build the router with full production configuration.
pub fn build_router_with_config(config: &ServerConfig) -> Router {
    let cors = make_cors_layer(&config.cors_origins);
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
    build_router_inner(cors, state)
}

fn make_cors_layer(origins: &[String]) -> CorsLayer {
    if origins.is_empty() {
        CorsLayer::permissive()
    } else {
        let parsed: Vec<_> = origins.iter().filter_map(|o| o.parse().ok()).collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(parsed))
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    }
}

fn build_router_inner(cors: CorsLayer, state: AppState) -> Router {
    Router::new()
        .route("/", get(routes::landing_page))
        .route("/health", get(routes::health))
        .route("/api/v1/verify", post(routes::verify_json))
        .route("/api/v1/verify/upload", post(routes::verify_upload))
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
        .layer(TraceLayer::new_for_http())
}
