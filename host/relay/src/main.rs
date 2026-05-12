use clap::Parser;
use cyntrisec_relay::config::{LogFormat, RelayConfig};
use cyntrisec_relay::{run_listener_with_connector, RelayServerConfig};
use tokio::net::TcpListener;
use tokio_vsock::{VsockAddr, VsockStream};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let config = RelayConfig::parse();
    init_tracing(config.log_format);

    if config.max_connections == 0 {
        tracing::error!("CYNTRISEC_RELAY_MAX_CONN must be greater than zero");
        std::process::exit(2);
    }

    match run(config).await {
        Ok(()) => {}
        Err(err) => {
            tracing::error!(error = %err, "relay exited with error");
            std::process::exit(1);
        }
    }
}

async fn run(config: RelayConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(config.tcp_bind).await?;
    tracing::info!(
        tcp_bind = %config.tcp_bind,
        vsock_cid = config.vsock_cid,
        vsock_port = config.vsock_port,
        max_connections = config.max_connections,
        idle_timeout_secs = config.idle_timeout_secs,
        "cyntrisec relay listening"
    );

    let vsock_cid = config.vsock_cid;
    let vsock_port = config.vsock_port;
    let server_config = RelayServerConfig::new(config.max_connections, config.idle_timeout());

    run_listener_with_connector(
        listener,
        move || async move { VsockStream::connect(VsockAddr::new(vsock_cid, vsock_port)).await },
        server_config,
        shutdown_signal(),
    )
    .await?;

    Ok(())
}

fn init_tracing(log_format: LogFormat) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("cyntrisec_relay=info"));
    match log_format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .with_target(false)
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .init();
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %err, "failed to install ctrl-c handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
