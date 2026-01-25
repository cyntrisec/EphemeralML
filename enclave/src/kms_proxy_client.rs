use crate::{Result, EnclaveError, EphemeralError};
use ephemeral_ml_common::{KmsRequest, KmsResponse, VSockMessage, MessageType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct KmsProxyClient {
    #[cfg(feature = "mock")]
    host_addr: String,
}

impl KmsProxyClient {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "mock")]
            host_addr: "127.0.0.1:8082".to_string(),
        }
    }

    #[cfg(feature = "mock")]
    pub fn with_addr(mut self, addr: String) -> Self {
        self.host_addr = addr;
        self
    }

    pub async fn send_request(&self, request: KmsRequest) -> Result<KmsResponse> {
        let payload = serde_json::to_vec(&request)
            .map_err(|e| EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string())))?;

        let msg = VSockMessage::new(MessageType::KmsProxy, 0, payload)?; // Seq 0 for simple request/response
        let encoded = msg.encode();

        // Connect (one-off for simplicity for now)
        #[cfg(feature = "mock")]
        let mut stream = tokio::net::TcpStream::connect(&self.host_addr).await
            .map_err(|e| EnclaveError::Enclave(EphemeralError::NetworkError(format!("Failed to connect to host proxy: {}", e))))?;
        
        #[cfg(not(feature = "mock"))]
        return Err(EnclaveError::Enclave(EphemeralError::NotImplemented("VSock transport not implemented yet".to_string())));

        stream.write_all(&encoded).await
            .map_err(|e| EnclaveError::Enclave(EphemeralError::NetworkError(format!("Failed to write to stream: {}", e))))?;

        // Read response
        // We need to read length prefix first (4 bytes)
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await
            .map_err(|e| EnclaveError::Enclave(EphemeralError::NetworkError(format!("Failed to read length prefix: {}", e))))?;
        
        let total_len = u32::from_be_bytes(len_buf) as usize;
        
        // Safety check for size
        if total_len > ephemeral_ml_common::vsock::MAX_MESSAGE_SIZE + 100 {
             return Err(EnclaveError::Enclave(EphemeralError::Validation(
                ephemeral_ml_common::ValidationError::SizeLimitExceeded("Response too large".to_string())
            )));
        }

        let mut body = vec![0u8; total_len];
        stream.read_exact(&mut body).await
             .map_err(|e| EnclaveError::Enclave(EphemeralError::NetworkError(format!("Failed to read body: {}", e))))?;
             
        // Reconstruct full buffer for decode (length prefix + body)
        let mut full_buf = Vec::with_capacity(4 + total_len);
        full_buf.extend_from_slice(&len_buf);
        full_buf.extend_from_slice(&body);
        
        let response_msg = VSockMessage::decode(&full_buf)?;
        
        if response_msg.msg_type != MessageType::KmsProxy {
             // If we got Error type, maybe it's a protocol error
             if response_msg.msg_type == MessageType::Error {
                 let err_msg = String::from_utf8_lossy(&response_msg.payload);
                 return Err(EnclaveError::Enclave(EphemeralError::ProtocolError(format!("Host returned error: {}", err_msg))));
             }
             return Err(EnclaveError::Enclave(EphemeralError::ProtocolError(
                format!("Expected KmsProxy message, got {:?}", response_msg.msg_type)
            )));
        }
        
        let response: KmsResponse = serde_json::from_slice(&response_msg.payload)
            .map_err(|e| EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string())))?;
            
        Ok(response)
    }
}
