use anyhow::Result;
use ephemeral_ml_common::{
    KmsProxyErrorCode, KmsProxyRequestEnvelope, KmsProxyResponseEnvelope, KmsResponse, MessageType, VSockMessage,
    storage_protocol::{StorageRequest, StorageResponse},
};
use ephemeral_ml_host::kms_proxy_server::KmsProxyServer;
use ephemeral_ml_host::storage::{WeightStorage, InMemoryWeightStorage};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use tracing::{info, warn, instrument};
use std::sync::Arc;

#[cfg(feature = "production")]
use tokio_vsock::VsockListener;
#[cfg(feature = "production")]
use ephemeral_ml_host::storage::S3WeightStorage;

#[tokio::main]
async fn main() -> Result<()> {
    ephemeral_ml_host::otel::init();

    info!(event = "startup", "kms-proxy-host starting");

    let mut kms_server = KmsProxyServer::new();
    let storage: Arc<dyn WeightStorage>;

    let timeouts = ProxyTimeouts::default();

    #[cfg(feature = "production")]
    {
        let config = aws_config::load_from_env().await;
        let kms_client = aws_sdk_kms::Client::new(&config);
        kms_server = kms_server.with_kms_client(kms_client);
        
        let s3_client = aws_sdk_s3::Client::new(&config);
        // In production, bucket name should come from env or config
        let bucket = std::env::var("MODEL_BUCKET").unwrap_or_else(|_| "ephemeral-ml-models".to_string());
        storage = Arc::new(S3WeightStorage::new(s3_client, bucket));
        
        info!(event = "init", mode = "production", "initialized with real AWS clients");
    }

    #[cfg(not(feature = "production"))]
    {
        storage = Arc::new(InMemoryWeightStorage::new());
        info!(event = "mode", mode = "mock", "running in MOCK mode (no AWS calls)");
    }

    #[cfg(feature = "production")]
    {
        let mut listener = VsockListener::bind(libc::VMADDR_CID_ANY, 8082)?;
        info!(event = "listen", transport = "vsock", port = 8082, "listening");

        loop {
            let (mut stream, addr) = listener.accept().await?;
            info!(event = "accept", transport = "vsock", cid = addr.cid(), "accepted connection");
            let kms_server_clone = kms_server.clone();
            let storage_clone = Arc::clone(&storage);
            tokio::spawn(async move {
                let mut kms = kms_server_clone;
                if let Err(e) = serve_one(&mut stream, &mut kms, storage_clone, timeouts).await {
                    warn!(event = "conn_error", transport = "vsock", error = %e, "connection error");
                }
            });
        }
    }

    #[cfg(not(feature = "production"))]
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:8082").await?;
        info!(event = "listen", transport = "tcp", addr = "127.0.0.1:8082", "listening (mock)");

        loop {
            let (mut stream, addr) = listener.accept().await?;
            info!(event = "accept", transport = "tcp", peer = %addr, "accepted connection");
            let kms_server_clone = kms_server.clone();
            let storage_clone = Arc::clone(&storage);
            tokio::spawn(async move {
                let mut kms = kms_server_clone;
                if let Err(e) = serve_one(&mut stream, &mut kms, storage_clone, timeouts).await {
                    warn!(event = "conn_error", transport = "tcp", error = %e, "connection error");
                }
            });
        }
    }
}

async fn serve_one<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    kms_server: &mut KmsProxyServer,
    storage: Arc<dyn WeightStorage>,
    timeouts: ProxyTimeouts,
) -> Result<()> {
    loop {
        let started = Instant::now();
        let remaining = |overall: Duration| -> Duration {
            overall
                .checked_sub(started.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0))
        };

        let mut len_buf = [0u8; 4];
        let read_res = tokio::time::timeout(timeouts.io, stream.read_exact(&mut len_buf)).await;
        if read_res.is_err() || read_res.unwrap().is_err() {
            break; // Connection closed or timeout
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        tokio::time::timeout(timeouts.io, stream.read_exact(&mut body))
            .await
            .map_err(|_| anyhow::anyhow!("timeout reading request body"))??;

        let mut full_msg = len_buf.to_vec();
        full_msg.extend_from_slice(&body);

        let msg = VSockMessage::decode(&full_buf)?;
        match msg.msg_type {
            MessageType::KmsProxy => {
                let req_env: KmsProxyRequestEnvelope = serde_json::from_slice(&msg.payload)?;
                let resp_env = kms_server.handle_envelope(req_env).await;
                let resp_payload = serde_json::to_vec(&resp_env)?;
                let resp_msg = VSockMessage::new(MessageType::KmsProxy, msg.sequence, resp_payload)?;
                stream.write_all(&resp_msg.encode()).await?;
            }
            MessageType::Storage => {
                let req: StorageRequest = serde_json::from_slice(&msg.payload)?;
                info!(event = "storage_request", model_id = %req.model_id, "fetching model data");
                
                let resp = match storage.retrieve(&req.model_id).await {
                    Ok(data) => StorageResponse::Data {
                        payload: data,
                        is_last: true, // For v1 we send the whole model at once
                    },
                    Err(e) => StorageResponse::Error { message: e.to_string() },
                };
                
                let resp_payload = serde_json::to_vec(&resp)?;
                let resp_msg = VSockMessage::new(MessageType::Storage, msg.sequence, resp_payload)?;
                stream.write_all(&resp_msg.encode()).await?;
            }
            _ => {
                warn!(event = "unknown_msg_type", msg_type = ?msg.msg_type, "ignoring message");
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct ProxyTimeouts {
    io: Duration,
    handle: Duration,
    overall: Duration,
}

impl Default for ProxyTimeouts {
    fn default() -> Self {
        Self {
            io: Duration::from_secs(30),
            handle: Duration::from_secs(60),
            overall: Duration::from_secs(120),
        }
    }
}
