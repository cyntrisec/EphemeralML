//! Shared test utilities for the enclave crate.
//!
//! Provides a queue-based mock HTTP server for testing network clients
//! (GcpKmsClient, GcsModelLoader) without real HTTP endpoints.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A queue-based mock HTTP server for testing.
///
/// Responses are consumed in FIFO order: each incoming HTTP request
/// receives the next `(status_code, body)` from the queue.
pub struct MockHttpServer {
    pub base_url: String,
    _handle: tokio::task::JoinHandle<()>,
}

impl MockHttpServer {
    /// Start a mock server that returns responses in order.
    ///
    /// Each element is `(HTTP status code, JSON response body)`.
    pub async fn start(responses: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let queue = Arc::new(Mutex::new(VecDeque::from(responses)));

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        let queue = queue.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 16384];
                            let _ = stream.read(&mut buf).await;

                            let (status, body) = queue
                                .lock()
                                .unwrap()
                                .pop_front()
                                .unwrap_or((500, r#"{"error":"queue empty"}"#.to_string()));

                            let status_text = match status {
                                200 => "OK",
                                400 => "Bad Request",
                                401 => "Unauthorized",
                                403 => "Forbidden",
                                404 => "Not Found",
                                500 => "Internal Server Error",
                                _ => "Error",
                            };

                            let resp = format!(
                                "HTTP/1.1 {} {}\r\n\
                                 Content-Type: application/json\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: close\r\n\
                                 \r\n\
                                 {}",
                                status,
                                status_text,
                                body.len(),
                                body
                            );
                            let _ = stream.write_all(resp.as_bytes()).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            base_url,
            _handle: handle,
        }
    }
}
