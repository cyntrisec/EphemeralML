use std::path::PathBuf;

use clap::Parser;
use tokio::io::AsyncWriteExt;
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "cyntrisec-worker-config",
    about = "Serve a static Cyntrisec worker boot config over vsock"
)]
struct Args {
    /// Vsock listen port for enclave boot config.
    #[arg(
        long,
        env = "CYNTRISEC_WORKER_CONFIG_VSOCK_PORT",
        default_value_t = 5002
    )]
    vsock_port: u32,

    /// JSON config file to return to each enclave connection.
    #[arg(long, env = "CYNTRISEC_WORKER_CONFIG_PATH")]
    config_path: PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("cyntrisec_worker_config=info")),
        )
        .json()
        .with_target(false)
        .init();

    let args = Args::parse();
    if let Err(err) = run(args).await {
        tracing::error!(error = %err, "worker config service exited");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // The parent instance is the operational trust root for this boot-time
    // configuration channel. The worker still verifies schema_version and keeps
    // attestation/user_data binding inside the enclave protocol.
    let config = std::fs::read(&args.config_path)?;
    serde_json::from_slice::<serde_json::Value>(&config)
        .map_err(|err| format!("worker config file is not valid JSON: {err}"))?;
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, args.vsock_port))?;
    tracing::info!(
        vsock_port = args.vsock_port,
        config_path = %args.config_path.display(),
        config_bytes = config.len(),
        "worker config service listening"
    );

    loop {
        let (mut stream, addr) = listener.accept().await?;
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(err) = stream.write_all(&config).await {
                tracing::warn!(peer_cid = addr.cid(), peer_port = addr.port(), error = %err, "failed to write worker config");
                return;
            }
            if let Err(err) = AsyncWriteExt::shutdown(&mut stream).await {
                tracing::warn!(peer_cid = addr.cid(), peer_port = addr.port(), error = %err, "failed to close worker config stream");
            }
        });
    }
}
