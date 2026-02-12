use crate::{EphemeralError, HostError, Result, WeightStorage};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Mock KMS proxy server for local development
pub struct MockKmsProxyServer {
    pub tcp_port: u16,
}

impl MockKmsProxyServer {
    pub fn new(tcp_port: u16) -> Self {
        Self { tcp_port }
    }

    /// Start a mock TCP server that handles KMS proxy requests
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.tcp_port))
            .await
            .map_err(|e| {
                HostError::Host(EphemeralError::ProxyError(format!(
                    "Failed to bind TCP listener: {}",
                    e
                )))
            })?;

        println!("Mock KMS proxy listening on TCP port {}", self.tcp_port);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    println!("Mock KMS connection from {}", addr);
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_mock_connection(stream).await {
                            eprintln!("Error handling mock connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_mock_connection(mut stream: TcpStream) -> Result<()> {
        use crate::kms_proxy_server::KmsProxyServer;
        use ephemeral_ml_common::transport_types::simple_frame::{self, TAG_KMS};
        use ephemeral_ml_common::KmsProxyRequestEnvelope;

        let (tag, payload) = simple_frame::read_frame(&mut stream).await.map_err(|e| {
            HostError::Host(EphemeralError::Validation(
                ephemeral_ml_common::ValidationError::InvalidFormat(e.to_string()),
            ))
        })?;

        if tag == TAG_KMS {
            let request: KmsProxyRequestEnvelope = serde_json::from_slice(&payload)
                .map_err(|e| HostError::Host(EphemeralError::SerializationError(e.to_string())))?;

            let mut server = KmsProxyServer::new();
            let response = server.handle_envelope(request).await;

            let response_payload = serde_json::to_vec(&response)
                .map_err(|e| HostError::Host(EphemeralError::SerializationError(e.to_string())))?;

            simple_frame::write_frame(&mut stream, TAG_KMS, &response_payload)
                .await
                .map_err(|e| {
                    HostError::Host(EphemeralError::CommunicationError(format!(
                        "write_frame error: {}",
                        e
                    )))
                })?;
        } else {
            simple_frame::write_frame(&mut stream, tag, &payload)
                .await
                .map_err(|e| {
                    HostError::Host(EphemeralError::CommunicationError(format!(
                        "write_frame error: {}",
                        e
                    )))
                })?;
        }

        stream
            .flush()
            .await
            .map_err(|e| HostError::Host(EphemeralError::IoError(e.to_string())))?;
        Ok(())
    }
}

/// Mock weight storage for testing
pub struct MockWeightStorage {
    storage: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MockWeightStorage {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for MockWeightStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl WeightStorage for MockWeightStorage {
    async fn store(&self, model_id: &str, weights: &[u8]) -> Result<()> {
        let mut storage = self.storage.lock().await;
        storage.insert(model_id.to_string(), weights.to_vec());
        println!(
            "Mock storage: Stored {} bytes of weights for model {}",
            weights.len(),
            model_id
        );
        Ok(())
    }

    async fn retrieve(&self, model_id: &str) -> Result<Vec<u8>> {
        let storage = self.storage.lock().await;
        storage.get(model_id).cloned().ok_or_else(|| {
            HostError::Host(EphemeralError::StorageError(format!(
                "Weights not found for model {}",
                model_id
            )))
        })
    }

    async fn exists(&self, model_id: &str) -> bool {
        let storage = self.storage.lock().await;
        storage.contains_key(model_id)
    }

    async fn remove(&self, model_id: &str) -> Result<()> {
        let mut storage = self.storage.lock().await;
        storage.remove(model_id);
        println!("Mock storage: Removed weights for model {}", model_id);
        Ok(())
    }
}
