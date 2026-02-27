use clap::Parser;
use ephemeral_ml_client::SecureEnclaveClient;
use ephemeralml_gateway::config::GatewayConfig;
use ephemeralml_gateway::state::AppState;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // PHI-safe defaults: info level, no prompt/response bodies logged.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("ephemeralml_gateway=info,tower_http=info")),
        )
        .with_target(false)
        .init();

    let config = GatewayConfig::parse();

    // Validate config consistency before proceeding.
    if let Err(e) = config.validate() {
        tracing::error!("Configuration error: {e}");
        anyhow::bail!("Configuration error: {e}");
    }

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;

    tracing::info!(
        listen = %addr,
        backend = %config.backend_addr,
        model = %config.default_model,
        capabilities = %config.model_capabilities,
        auth = config.api_key.as_ref().is_some_and(|k| !k.is_empty()),
        embedding_backend = ?config.embedding_backend_addr,
        embedding_model = ?config.embedding_model,
        "Starting EphemeralML OpenAI-compatible gateway"
    );

    let client = SecureEnclaveClient::new("gateway".to_string());

    let embedding_client = if config.embedding_backend_addr.is_some() {
        tracing::info!(
            embedding_backend = %config.embedding_backend_addr.as_deref().unwrap_or(""),
            embedding_model = %config.embedding_model.as_deref().unwrap_or("(default)"),
            "Separate embedding backend configured"
        );
        Some(SecureEnclaveClient::new("gateway-embedding".to_string()))
    } else {
        None
    };

    // Log active endpoints based on capabilities.
    let mut active = Vec::new();
    if config.has_capability("chat") {
        active.push("/v1/chat/completions");
        active.push("/v1/responses");
    }
    if config.has_capability("embeddings") {
        active.push("/v1/embeddings");
    }
    active.push("/v1/models");
    active.push("/health");
    active.push("/readyz");
    tracing::info!(
        endpoints = %active.join(", "),
        "Active endpoints"
    );

    let state = AppState::new(client, config, embedding_client);
    let app = ephemeralml_gateway::build_router(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Listening on {addr}");
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
