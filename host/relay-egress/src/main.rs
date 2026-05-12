use std::sync::Arc;

use aws_config::BehaviorVersion;
use clap::Parser;
use cyntrisec_relay_egress::backend::AwsSdkBackend;
use cyntrisec_relay_egress::config::{EgressConfig, LogFormat};
use cyntrisec_relay_egress::{run_vsock_listener, EgressAllowlist, EgressServerConfig};
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let config = EgressConfig::parse();
    init_tracing(config.log_format);

    if config.max_concurrent == 0 {
        tracing::error!("CYNTRISEC_EGRESS_MAX_CONN must be greater than zero");
        std::process::exit(2);
    }
    if config.max_request_bytes == 0 {
        tracing::error!("CYNTRISEC_EGRESS_MAX_REQUEST_BYTES must be greater than zero");
        std::process::exit(2);
    }

    match run(config).await {
        Ok(()) => {}
        Err(err) => {
            tracing::error!(error = %err, "relay-egress exited with error");
            std::process::exit(1);
        }
    }
}

async fn run(config: EgressConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let allowed_buckets = config.allowed_buckets_set();
    let allowed_kms_keys = config.allowed_kms_keys_set();
    if allowed_buckets.is_empty() {
        tracing::warn!("CYNTRISEC_EGRESS_ALLOWED_BUCKETS is empty; all S3 writes will be denied");
    }
    if allowed_kms_keys.is_empty() {
        tracing::warn!("CYNTRISEC_EGRESS_ALLOWED_KMS_KEYS is empty; all KMS decrypts and SSE-KMS writes will be denied");
    }

    let aws_config = aws_config::defaults(BehaviorVersion::latest())
        .region(aws_config::Region::new(config.aws_region.clone()))
        .load()
        .await;
    let backend = Arc::new(AwsSdkBackend::new(&aws_config));
    let allowlist = EgressAllowlist::new(allowed_buckets, allowed_kms_keys);
    let server_config = EgressServerConfig::new(
        config.max_request_bytes,
        config.max_concurrent,
        config.idle_timeout(),
    );

    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, config.vsock_listen_port))?;
    tracing::info!(
        vsock_port = config.vsock_listen_port,
        aws_region = %config.aws_region,
        max_request_bytes = config.max_request_bytes,
        max_concurrent = config.max_concurrent,
        idle_timeout_secs = config.idle_timeout_secs,
        "cyntrisec relay-egress listening"
    );

    run_vsock_listener(
        listener,
        backend,
        allowlist,
        server_config,
        shutdown_signal(),
    )
    .await?;
    Ok(())
}

fn init_tracing(log_format: LogFormat) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("cyntrisec_relay_egress=info"));
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
