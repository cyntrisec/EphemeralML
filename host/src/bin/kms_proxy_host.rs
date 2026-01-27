use anyhow::Result;
use ephemeral_ml_common::{MessageType, VSockMessage};
use ephemeral_ml_host::kms_proxy_server::KmsProxyServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "production")]
use tokio_vsock::VsockListener;

#[tokio::main]
async fn main() -> Result<()> {
    println!("[kms-proxy-host] starting...");

    let mut kms_server = KmsProxyServer::new();

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
        let listener = VsockListener::bind(libc::VMADDR_CID_ANY, 8082)?;
        println!("[kms-proxy-host] listening on VSOCK port 8082");

        loop {
            let (mut stream, addr) = listener.accept().await?;
            println!("[kms-proxy-host] accepted connection from CID {}", addr.cid());

            let mut server_clone = kms_server.clone_mock(); // I need to handle state or clone if possible.
            // For now, let's just use the server directly if it's not stateful or handle connections sequentially.
            
            // To make this simple for the test, we handle one request per connection.
            let mut len_buf = [0u8; 4];
            if let Err(e) = stream.read_exact(&mut len_buf).await {
                eprintln!("[kms-proxy-host] read error: {}", e);
                continue;
            }

            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await?;

            let mut full_msg = len_buf.to_vec();
            full_msg.extend_from_slice(&body);

            let msg = VSockMessage::decode(&full_msg)?;
            if msg.msg_type == MessageType::KmsProxy {
                let req = serde_json::from_slice(&msg.payload)?;
                let resp = kms_server.handle_request(req).await;
                let resp_payload = serde_json::to_vec(&resp)?;
                let resp_msg = VSockMessage::new(MessageType::KmsProxy, msg.sequence, resp_payload)?;
                stream.write_all(&resp_msg.encode()).await?;
            }
        }
    }

    #[cfg(not(feature = "production"))]
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:8082").await?;
        println!("[kms-proxy-host] listening on TCP port 8082 (MOCK)");
        // ... similar logic for TCP ...
    }

    Ok(())
}

impl KmsProxyServer {
    // Helper for simple sequential handling
    #[cfg(not(feature = "production"))]
    fn clone_mock(&self) -> Self {
        Self::new()
    }
}
