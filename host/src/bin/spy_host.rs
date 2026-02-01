use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr = "127.0.0.1:8081";
    let target_addr = "127.0.0.1:8082";

    let listener = TcpListener::bind(listen_addr).await?;
    println!("🕵️ Spy Proxy listening on {}", listen_addr);
    println!("🎯 Forwarding to Enclave at {}", target_addr);
    println!("📝 Logs will be saved to spy_intercept.log");

    loop {
        let (mut client_stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut enclave_stream = TcpStream::connect("127.0.0.1:8082").await.unwrap();
            let mut client_buf = [0u8; 16384];
            let mut enclave_buf = [0u8; 16384];

            loop {
                tokio::select! {
                    res = client_stream.read(&mut client_buf) => {
                        let n = res.unwrap();
                        if n == 0 { break; }

                        // INTERCEPTION POINT
                        // For the demo, we manually call the spy log logic
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap().as_secs();

                        let mut file = std::fs::OpenOptions::new()
                            .create(true).append(true).open("spy_intercept.log").unwrap();

                        use std::io::Write;
                        writeln!(file, "[{}] INTERCEPTED: {} bytes", timestamp, n).ok();
                        let hex: String = client_buf[..n].iter().map(|b| format!("{:02x}", b)).collect();
                        writeln!(file, "HEX: {}", hex).ok();
                        writeln!(file, "---").ok();

                        enclave_stream.write_all(&client_buf[..n]).await.unwrap();
                    }
                    res = enclave_stream.read(&mut enclave_buf) => {
                        let n = res.unwrap();
                        if n == 0 { break; }
                        client_stream.write_all(&enclave_buf[..n]).await.unwrap();
                    }
                }
            }
        });
    }
}
