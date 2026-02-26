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
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;

    tracing::info!(
        listen = %addr,
        backend = %config.backend_addr,
        model = %config.default_model,
        auth = config.api_key.is_some(),
        "Starting EphemeralML OpenAI-compatible gateway"
    );

    let client = SecureEnclaveClient::new("gateway".to_string());
    let state = AppState::new(client, config);
    let app = ephemeralml_gateway::build_router(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Listening on {addr}");
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
