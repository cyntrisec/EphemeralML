use ephemeral_ml_enclave::{Result, EphemeralError, EnclaveError};
use ephemeral_ml_common::{MessageType, VSockMessage};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::VsockListener;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = 8083;
    let mut listener = VsockListener::bind(libc::VMADDR_CID_ANY, port)
        .map_err(|e| format!("Failed to bind VSock: {}", e))?;

    println!("[vsock-echo] Listening on port {}", port);

    loop {
        let (mut stream, addr) = listener.accept().await?;
        println!("[vsock-echo] Connection from CID {}", addr.cid());

        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024 * 1024]; // 1MB buffer
            loop {
                // Read length prefix
                let mut len_bytes = [0u8; 4];
                if stream.read_exact(&mut len_bytes).await.is_err() { break; }
                let len = u32::from_be_bytes(len_bytes) as usize;

                // Read body
                let mut body = vec![0u8; len];
                if stream.read_exact(&mut body).await.is_err() { break; }

                // Echo back immediately
                let total_len = (len as u32).to_be_bytes();
                if stream.write_all(&total_len).await.is_err() { break; }
                if stream.write_all(&body).await.is_err() { break; }
                if stream.flush().await.is_err() { break; }
            }
        });
    }
}
