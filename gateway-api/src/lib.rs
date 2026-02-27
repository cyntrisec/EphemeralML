//! EphemeralML OpenAI-compatible gateway.
//!
//! Exposes `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, and
//! `/v1/models` backed by `SecureEnclaveClient`. Attestation metadata is
//! returned in response headers (`x-ephemeralml-*`) and optionally in the
//! JSON body.

pub mod auth;
pub mod config;
pub mod reconnect;
pub mod routes;
pub mod state;
pub mod types;

use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

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
            auth::auth_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024)) // 2 MB
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
