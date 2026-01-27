use crate::{HostError, Result, VSockProxy, WeightStorage, EphemeralError};
use std::collections::HashMap;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Helper function to convert std::io::Error to HostError
fn io_error_to_host_error(err: std::io::Error) -> HostError {
    HostError::Host(EphemeralError::IoError(err.to_string()))
}

/// Mock VSock proxy that uses TCP for local development
pub struct MockVSockProxy {
    pub tcp_port: u16,
    pub weight_storage: HashMap<String, Vec<u8>>,
}

impl MockVSockProxy {
    pub fn new(tcp_port: u16) -> Self {
        Self {
            tcp_port,
            weight_storage: HashMap::new(),
        }
    }

    /// Start a mock TCP server that simulates enclave communication
    pub async fn start_mock_server(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.tcp_port))
            .await
            .map_err(|e| HostError::Host(EphemeralError::ProxyError(format!("Failed to bind TCP listener: {}", e))))?;

        println!("Mock VSock proxy listening on TCP port {}", self.tcp_port);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    println!("Mock connection from {}", addr);
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
        use ephemeral_ml_common::{KmsProxyRequestEnvelope, MessageType, VSockMessage};
        use crate::kms_proxy_server::KmsProxyServer;

        // Read length prefix
        let mut len_buf = [0u8; 4];
        // If we can't read 4 bytes, assume connection closed or empty
        if stream.read_exact(&mut len_buf).await.is_err() {
            return Ok(());
        }
        
        let total_len = u32::from_be_bytes(len_buf) as usize;
        
        // Safety check
        if total_len > ephemeral_ml_common::vsock::MAX_MESSAGE_SIZE + 100 {
            return Err(HostError::Host(EphemeralError::Validation(
                ephemeral_ml_common::ValidationError::SizeLimitExceeded("Message too large".to_string())
            )));
        }

        let mut body = vec![0u8; total_len];
        stream.read_exact(&mut body).await.map_err(io_error_to_host_error)?;
        
        let mut full_buf = Vec::with_capacity(4 + total_len);
        full_buf.extend_from_slice(&len_buf);
        full_buf.extend_from_slice(&body);
        
        let msg = VSockMessage::decode(&full_buf)
            .map_err(|e| HostError::Host(EphemeralError::Validation(ephemeral_ml_common::ValidationError::InvalidFormat(e.to_string()))))?;

        if msg.msg_type == MessageType::KmsProxy {
             let request: KmsProxyRequestEnvelope = serde_json::from_slice(&msg.payload)
                 .map_err(|e| HostError::Host(EphemeralError::SerializationError(e.to_string())))?;
                 
             let mut server = KmsProxyServer::new();
             let response = server.handle_envelope(request).await;
             
             let response_payload = serde_json::to_vec(&response)
                 .map_err(|e| HostError::Host(EphemeralError::SerializationError(e.to_string())))?;
                 
             let response_msg = VSockMessage::new(MessageType::KmsProxy, msg.sequence, response_payload)
                 .map_err(|e| HostError::Host(EphemeralError::Validation(ephemeral_ml_common::ValidationError::InvalidFormat(e.to_string()))))?;
                 
             let encoded = response_msg.encode();
             stream.write_all(&encoded).await.map_err(io_error_to_host_error)?;
        } else {
             // Default echo behavior for other types (or Data)
             // Just echo back for now if it's Data, or ignore
             if msg.msg_type == MessageType::Data {
                let response = format!("MOCK_RESPONSE:{}", String::from_utf8_lossy(&msg.payload));
                // We need to wrap it in VSockMessage
                let response_msg = VSockMessage::new(MessageType::Data, msg.sequence, response.as_bytes().to_vec())
                    .map_err(|e| HostError::Host(EphemeralError::Validation(ephemeral_ml_common::ValidationError::InvalidFormat(e.to_string()))))?;
                
                stream.write_all(&response_msg.encode()).await.map_err(io_error_to_host_error)?;
             }
        }
        
        stream.flush().await.map_err(io_error_to_host_error)?;
        Ok(())
    }
}

impl VSockProxy for MockVSockProxy {
    async fn forward_to_enclave(&self, payload: &[u8]) -> Result<Vec<u8>> {
        // Mock TCP communication instead of VSock
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", self.tcp_port))
            .await
            .map_err(|e| HostError::Host(EphemeralError::VSockError(format!("Failed to connect to mock enclave: {}", e))))?;

        // Send payload
        stream.write_all(payload).await.map_err(io_error_to_host_error)?;
        stream.flush().await.map_err(io_error_to_host_error)?;

        // Read response
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.map_err(io_error_to_host_error)?;

        Ok(response)
    }

    fn store_weights(&mut self, model_id: &str, weights: &[u8]) -> Result<()> {
        self.weight_storage.insert(model_id.to_string(), weights.to_vec());
        println!("Mock: Stored {} bytes of weights for model {}", weights.len(), model_id);
        Ok(())
    }

    fn retrieve_weights(&self, model_id: &str) -> Result<Vec<u8>> {
        self.weight_storage
            .get(model_id)
            .cloned()
            .ok_or_else(|| HostError::Host(EphemeralError::StorageError(format!("Weights not found for model {}", model_id))))
    }
}

/// Mock weight storage for testing
pub struct MockWeightStorage {
    storage: HashMap<String, Vec<u8>>,
}

impl MockWeightStorage {
    pub fn new() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }
}

impl Default for MockWeightStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl WeightStorage for MockWeightStorage {
    fn store(&mut self, model_id: &str, weights: &[u8]) -> Result<()> {
        self.storage.insert(model_id.to_string(), weights.to_vec());
        println!("Mock storage: Stored {} bytes of weights for model {}", weights.len(), model_id);
        Ok(())
    }

    fn retrieve(&self, model_id: &str) -> Result<Vec<u8>> {
        self.storage
            .get(model_id)
            .cloned()
            .ok_or_else(|| HostError::Host(EphemeralError::StorageError(format!("Weights not found for model {}", model_id))))
    }

    fn exists(&self, model_id: &str) -> bool {
        self.storage.contains_key(model_id)
    }

    fn remove(&mut self, model_id: &str) -> Result<()> {
        self.storage.remove(model_id);
        println!("Mock storage: Removed weights for model {}", model_id);
        Ok(())
    }
}
