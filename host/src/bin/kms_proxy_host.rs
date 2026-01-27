use anyhow::Result;
use ephemeral_ml_common::{
    KmsProxyErrorCode, KmsProxyRequestEnvelope, KmsProxyResponseEnvelope, KmsResponse, MessageType, VSockMessage,
};
use ephemeral_ml_host::kms_proxy_server::KmsProxyServer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};

#[cfg(feature = "production")]
use tokio_vsock::VsockListener;

#[tokio::main]
async fn main() -> Result<()> {
    println!("[kms-proxy-host] starting...");

    let mut kms_server = KmsProxyServer::new();

    let timeouts = ProxyTimeouts::default();

    #[cfg(feature = "production")]
    {
        let config = aws_config::load_from_env().await;
        let kms_client = aws_sdk_kms::Client::new(&config);
        kms_server = kms_server.with_kms_client(kms_client);
        println!("[kms-proxy-host] initialized with real AWS KMS client");
    }

    #[cfg(not(feature = "production"))]
    println!("[kms-proxy-host] running in MOCK mode (no AWS calls)");

    // Listen on Port 8082 (standard for our KMS proxy)
    #[cfg(feature = "production")]
    {
        let mut listener = VsockListener::bind(libc::VMADDR_CID_ANY, 8082)?;
        println!("[kms-proxy-host] listening on VSOCK port 8082");

        loop {
            let (mut stream, addr) = listener.accept().await?;
            println!("[kms-proxy-host] accepted connection from CID {}", addr.cid());
            if let Err(e) = serve_one(&mut stream, &mut kms_server, timeouts).await {
                eprintln!("[kms-proxy-host] connection error: {e}");
                continue;
            };
        }
    }

    #[cfg(not(feature = "production"))]
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:8082").await?;
        println!("[kms-proxy-host] listening on TCP port 8082 (MOCK)");

        loop {
            let (mut stream, addr) = listener.accept().await?;
            println!("[kms-proxy-host] accepted TCP connection from {}", addr);
            if let Err(e) = serve_one(&mut stream, &mut kms_server, timeouts).await {
                eprintln!("[kms-proxy-host] connection error: {e}");
                continue;
            };
        }
    }

    Ok(())
}

async fn serve_one<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    kms_server: &mut KmsProxyServer,
    timeouts: ProxyTimeouts,
) -> Result<()> {
    let started = Instant::now();
    let remaining = |overall: Duration| -> Duration {
        overall
            .checked_sub(started.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0))
    };

    // Read length prefix
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(timeouts.io.min(remaining(timeouts.overall)), stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| anyhow::anyhow!("timeout reading length prefix"))??;

    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    tokio::time::timeout(timeouts.io.min(remaining(timeouts.overall)), stream.read_exact(&mut body))
        .await
        .map_err(|_| anyhow::anyhow!("timeout reading request body"))??;

    let mut full_msg = len_buf.to_vec();
    full_msg.extend_from_slice(&body);

    let msg = VSockMessage::decode(&full_msg)?;
    if msg.msg_type != MessageType::KmsProxy {
        return Ok(());
    }

    let req_env: KmsProxyRequestEnvelope = match serde_json::from_slice(&msg.payload) {
        Ok(v) => v,
        Err(_) => {
            let err_msg = VSockMessage::new(
                MessageType::Error,
                msg.sequence,
                b"invalid KMS proxy request".to_vec(),
            )?;
            tokio::time::timeout(timeouts.io.min(remaining(timeouts.overall)), stream.write_all(&err_msg.encode()))
                .await
                .map_err(|_| anyhow::anyhow!("timeout writing error response"))??;
            return Ok(());
        }
    };

    log_request_redacted(&req_env);

    let timeout_resp = KmsProxyResponseEnvelope {
        request_id: req_env.request_id.clone(),
        trace_id: req_env.trace_id.clone(),
        kms_request_id: None,
        response: KmsResponse::Error {
            code: KmsProxyErrorCode::Timeout,
            message: "Operation timed out".to_string(),
        },
    };

    let resp_env = tokio::time::timeout(
        timeouts.handle.min(remaining(timeouts.overall)),
        kms_server.handle_envelope(req_env),
    )
    .await
    .unwrap_or(timeout_resp);

    let resp_payload = serde_json::to_vec(&resp_env)?;
    let resp_msg = VSockMessage::new(MessageType::KmsProxy, msg.sequence, resp_payload)?;
    tokio::time::timeout(timeouts.io.min(remaining(timeouts.overall)), stream.write_all(&resp_msg.encode()))
        .await
        .map_err(|_| anyhow::anyhow!("timeout writing response"))??;

    Ok(())
}

fn log_request_redacted(req: &KmsProxyRequestEnvelope) {
    let (op, recipient, ciphertext_len) = match &req.request {
        ephemeral_ml_common::KmsRequest::Decrypt { ciphertext_blob, recipient, .. } => {
            ("Decrypt", recipient.is_some(), ciphertext_blob.len())
        }
        ephemeral_ml_common::KmsRequest::GenerateDataKey { .. } => ("GenerateDataKey", false, 0usize),
    };

    // Redacted: never log payload bytes, attestation docs, or plaintext.
    println!(
        "[kms-proxy-host] request_id={} trace_id={} op={} recipient={} ciphertext_len={}",
        req.request_id,
        req.trace_id.as_deref().unwrap_or("-"),
        op,
        recipient,
        ciphertext_len
    );
}

#[derive(Clone, Copy, Debug)]
struct ProxyTimeouts {
    io: Duration,
    handle: Duration,
    overall: Duration,
}

impl Default for ProxyTimeouts {
    fn default() -> Self {
        // v1 defaults aligned with DoD/SLO:
        // hard deadline 800ms for the full request.
        Self {
            io: Duration::from_millis(200),
            handle: Duration::from_millis(700),
            overall: Duration::from_millis(800),
        }
    }
}
