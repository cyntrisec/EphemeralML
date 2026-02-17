pub mod api_types;
pub mod routes;
pub mod templates;

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

/// Build the router with permissive CORS (for local dev / tests).
pub fn build_router() -> Router {
    build_router_with_cors(CorsLayer::permissive())
}

/// Build the router with explicit allowed origins.
///
/// Pass an empty slice to get permissive CORS (not recommended for production).
pub fn build_router_with_origins(origins: &[String]) -> Router {
    let cors = if origins.is_empty() {
        CorsLayer::permissive()
    } else {
        let parsed: Vec<_> = origins.iter().filter_map(|o| o.parse().ok()).collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(parsed))
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    };
    build_router_with_cors(cors)
}

fn build_router_with_cors(cors: CorsLayer) -> Router {
    Router::new()
        .route("/", get(routes::landing_page))
        .route("/health", get(routes::health))
        .route("/api/v1/verify", post(routes::verify_json))
        .route("/api/v1/verify/upload", post(routes::verify_upload))
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024)) // 2 MB
        .layer(TraceLayer::new_for_http())
}
