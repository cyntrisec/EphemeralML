use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use ephemeral_ml_client::SecureEnclaveClient;
use tracing_subscriber::EnvFilter;

use crate::config::{install_env_aliases, install_local_proxy_defaults, GatewayConfig};
use crate::reconnect::{spawn_reconnect_loop, ReconnectHandle};
use crate::state::AppState;
use crate::worker::PreflightReport;

pub async fn run_gateway() -> anyhow::Result<()> {
    run(false).await
}

pub async fn run_local_proxy() -> anyhow::Result<()> {
    run(true).await
}

async fn run(local_proxy_mode: bool) -> anyhow::Result<()> {
    init_tracing();

    install_env_aliases();
    if local_proxy_mode {
        install_local_proxy_defaults();
    }

    let config = GatewayConfig::parse();

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
        trust_proxy_headers = config.trust_proxy_headers,
        cors_origins = ?config.cors_origins,
        embedding_backend = ?config.embedding_backend_addr,
        embedding_model = ?config.embedding_model,
        worker_channel = ?config.worker_channel_kind,
        local_proxy = local_proxy_mode,
        "Starting Cyntrisec OpenAI-compatible proxy"
    );

    if local_proxy_mode && (config.host != "127.0.0.1" && config.host != "localhost") {
        tracing::warn!(
            listen_host = %config.host,
            "Local proxy is not bound to loopback. Prefer a sidecar in the same network namespace for multi-process deployments."
        );
    }

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

    let state = AppState::new(client, config.clone(), embedding_client);

    if local_proxy_mode && config.preflight_required {
        state
            .worker_channel
            .establish()
            .await
            .map_err(|e| anyhow::anyhow!("local proxy preflight failed: {e}"))?;
        let report = PreflightReport::build_required(
            &config,
            state.worker_channel.attestation_status(),
            state.worker_channel.receipt_signing_pubkey(),
        )?;
        tracing::info!(
            policy_sha256 = %report.policy_loaded,
            manifest_sha256 = %report.manifest_loaded,
            worker_endpoint_sha256 = %report.worker_endpoint_digest,
            worker_channel = ?report.worker_channel_kind,
            attestation_status = ?report.attestation_status,
            has_model_identity = report.model_identity.is_some(),
            has_receipt_signing_pubkey = report.receipt_signing_pubkey.is_some(),
            "Local proxy preflight completed"
        );
    }

    log_active_endpoints(&config);
    spawn_reconnect_tasks(&config, &state);

    let app = crate::build_router(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Listening on {addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn init_tracing() {
    // PHI-safe defaults: info level, no prompt/response bodies logged.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("ephemeralml_gateway=info,tower_http=info")),
        )
        .with_target(false)
        .init();
}

fn log_active_endpoints(config: &GatewayConfig) {
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
}

fn spawn_reconnect_tasks(config: &GatewayConfig, state: &AppState) {
    if !config.reconnect_enabled {
        return;
    }
    if config.worker_channel_kind == crate::config::WorkerChannelKind::Secure {
        tracing::info!(
            worker_channel = ?config.worker_channel_kind,
            "Background reconnect is owned by the secure worker transport"
        );
        return;
    }

    let health_interval = Duration::from_secs(config.reconnect_health_interval_secs);

    let _main_reconnect = spawn_reconnect_loop(
        ReconnectHandle {
            backend_name: "main".to_string(),
            backend_addr: config.backend_addr.clone(),
            backoff_base_ms: config.reconnect_backoff_base_ms,
            backoff_cap_ms: config.reconnect_backoff_cap_ms,
            health_interval,
        },
        state.client.clone(),
        state.connected.clone(),
        state.reconnect_notify.clone(),
    );

    if let (Some(ref emb_addr), Some(ref emb_client)) =
        (&config.embedding_backend_addr, &state.embedding_client)
    {
        let _emb_reconnect = spawn_reconnect_loop(
            ReconnectHandle {
                backend_name: "embedding".to_string(),
                backend_addr: emb_addr.clone(),
                backoff_base_ms: config.reconnect_backoff_base_ms,
                backoff_cap_ms: config.reconnect_backoff_cap_ms,
                health_interval,
            },
            emb_client.clone(),
            state.embedding_connected.clone(),
            state.embedding_reconnect_notify.clone(),
        );
    }

    tracing::info!(
        backoff_base_ms = config.reconnect_backoff_base_ms,
        backoff_cap_ms = config.reconnect_backoff_cap_ms,
        health_interval_secs = config.reconnect_health_interval_secs,
        "Background reconnect enabled"
    );
}
