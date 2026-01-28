use crate::{Result, EnclaveError, EphemeralError};
use ephemeral_ml_common::{
    KmsProxyRequestEnvelope, KmsProxyResponseEnvelope, KmsRequest, KmsResponse, MessageType, VSockMessage,
    storage_protocol::{StorageRequest, StorageResponse},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct KmsProxyClientTimeouts {
    pub connect: Duration,
    pub io: Duration,
    pub overall: Duration,
}

impl Default for KmsProxyClientTimeouts {
    fn default() -> Self {
        // v1 defaults aligned with DoD/SLO:
        // hard deadline 800ms for end-to-end (enclave→proxy→KMS→proxy→enclave).
        Self {
            connect: Duration::from_millis(200),
            io: Duration::from_millis(300),
            overall: Duration::from_millis(800),
        }
    }
}

pub struct KmsProxyClient {
    #[cfg(feature = "mock")]
    host_addr: String,
    #[cfg(feature = "production")]
    cid: u32,
    #[cfg(feature = "production")]
    port: u32,
    timeouts: KmsProxyClientTimeouts,
}

impl KmsProxyClient {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "mock")]
            host_addr: "127.0.0.1:8082".to_string(),
            #[cfg(feature = "production")]
            cid: 3, // Parent CID is always 3 in Nitro
            #[cfg(feature = "production")]
            port: 8082,
            timeouts: KmsProxyClientTimeouts::default(),
        }
    }

    #[cfg(feature = "mock")]
    pub fn with_addr(mut self, addr: String) -> Self {
        self.host_addr = addr;
        self
    }

    #[cfg(feature = "production")]
    pub fn with_vsock(mut self, cid: u32, port: u32) -> Self {
        self.cid = cid;
        self.port = port;
        self
    }

    pub fn with_timeouts(mut self, timeouts: KmsProxyClientTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    pub async fn send_request(&self, request: KmsRequest) -> Result<KmsProxyResponseEnvelope> {
        self.send_request_with_trace(request, None).await
    }

    pub async fn send_request_with_trace(
        &self,
        request: KmsRequest,
        trace_id: Option<String>,
    ) -> Result<KmsProxyResponseEnvelope> {
        let request_id = ephemeral_ml_common::generate_id();
        let env = KmsProxyRequestEnvelope {
            request_id: request_id.clone(),
            trace_id,
            request,
        };

        let payload = serde_json::to_vec(&env)
            .map_err(|e| EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string())))?;

        let msg = VSockMessage::new(MessageType::KmsProxy, 0, payload)?; // Seq 0 for simple request/response
        let encoded = msg.encode();

        let started = Instant::now();
        let remaining = |overall: Duration| -> Duration {
            overall
                .checked_sub(started.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0))
        };

        // Connect
        #[cfg(feature = "mock")]
        let mut stream = tokio::time::timeout(
            self.timeouts.connect.min(remaining(self.timeouts.overall)),
            tokio::net::TcpStream::connect(&self.host_addr),
        )
        .await
        .map_err(|_| EnclaveError::Enclave(EphemeralError::Timeout("KMS proxy connect timeout".to_string())))?
        .map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to connect to host proxy (TCP): {}",
                e
            )))
        })?;
        
        #[cfg(feature = "production")]
        let mut stream = tokio::time::timeout(
            self.timeouts.connect.min(remaining(self.timeouts.overall)),
            tokio_vsock::VsockStream::connect(self.cid, self.port),
        )
        .await
        .map_err(|_| EnclaveError::Enclave(EphemeralError::Timeout("KMS proxy connect timeout".to_string())))?
        .map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to connect to host proxy (VSock): {}",
                e
            )))
        })?;

        tokio::time::timeout(
            self.timeouts.io.min(remaining(self.timeouts.overall)),
            stream.write_all(&encoded),
        )
        .await
        .map_err(|_| EnclaveError::Enclave(EphemeralError::Timeout("KMS proxy write timeout".to_string())))?
        .map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to write to stream: {}",
                e
            )))
        })?;

        // Read response
        // We need to read length prefix first (4 bytes)
        let mut len_buf = [0u8; 4];
        tokio::time::timeout(
            self.timeouts.io.min(remaining(self.timeouts.overall)),
            stream.read_exact(&mut len_buf),
        )
        .await
        .map_err(|_| EnclaveError::Enclave(EphemeralError::Timeout("KMS proxy read timeout".to_string())))?
        .map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to read length prefix: {}",
                e
            )))
        })?;
        
        let total_len = u32::from_be_bytes(len_buf) as usize;
        
        // Safety check for size
        if total_len > ephemeral_ml_common::vsock::MAX_MESSAGE_SIZE + 100 {
             return Err(EnclaveError::Enclave(EphemeralError::Validation(
                ephemeral_ml_common::ValidationError::SizeLimitExceeded("Response too large".to_string())
            )));
        }

        let mut body = vec![0u8; total_len];
        tokio::time::timeout(
            self.timeouts.io.min(remaining(self.timeouts.overall)),
            stream.read_exact(&mut body),
        )
        .await
        .map_err(|_| EnclaveError::Enclave(EphemeralError::Timeout("KMS proxy read timeout".to_string())))?
        .map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to read body: {}",
                e
            )))
        })?;
             
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
        
        let response: KmsProxyResponseEnvelope = serde_json::from_slice(&response_msg.payload)
            .map_err(|e| EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string())))?;

        if response.request_id != request_id {
            return Err(EnclaveError::Enclave(EphemeralError::ProtocolError(
                "KMS proxy response request_id mismatch".to_string(),
            )));
        }

        Ok(response)
    }

    pub async fn fetch_model(&self, model_id: &str) -> Result<Vec<u8>> {
        let req = StorageRequest {
            model_id: model_id.to_string(),
            part_index: 0,
        };

        let payload = serde_json::to_vec(&req)
            .map_err(|e| EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string())))?;

        let msg = VSockMessage::new(MessageType::Storage, 0, payload)?;
        let encoded = msg.encode();

        let started = Instant::now();
        let remaining = |overall: Duration| -> Duration {
            overall
                .checked_sub(started.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0))
        };

        // Connect and send (reusing the logic or just making a new connection)
        // For simplicity, let's just implement the connection here too
        #[cfg(feature = "mock")]
        let mut stream = tokio::time::timeout(
            self.timeouts.connect.min(remaining(self.timeouts.overall)),
            tokio::net::TcpStream::connect(&self.host_addr),
        )
        .await
        .map_err(|_| EnclaveError::Enclave(EphemeralError::Timeout("Storage proxy connect timeout".to_string())))?
        .map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to connect to host proxy (TCP): {}",
                e
            )))
        })?;
        
        #[cfg(feature = "production")]
        let mut stream = tokio::time::timeout(
            self.timeouts.connect.min(remaining(self.timeouts.overall)),
            tokio_vsock::VsockStream::connect(self.cid, self.port),
        )
        .await
        .map_err(|_| EnclaveError::Enclave(EphemeralError::Timeout("Storage proxy connect timeout".to_string())))?
        .map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to connect to host proxy (VSock): {}",
                e
            )))
        })?;

        stream.write_all(&encoded).await.map_err(|e| EnclaveError::Enclave(EphemeralError::NetworkError(e.to_string())))?;

        // Read response
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.map_err(|e| EnclaveError::Enclave(EphemeralError::NetworkError(e.to_string())))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.map_err(|e| EnclaveError::Enclave(EphemeralError::NetworkError(e.to_string())))?;

        let mut full_buf = Vec::with_capacity(4 + len);
        full_buf.extend_from_slice(&len_buf);
        full_buf.extend_from_slice(&body);
        let response_msg = VSockMessage::decode(&full_buf)?;

        if response_msg.msg_type != MessageType::Storage {
            return Err(EnclaveError::Enclave(EphemeralError::ProtocolError("Expected Storage response".to_string())));
        }

        let response: StorageResponse = serde_json::from_slice(&response_msg.payload)
            .map_err(|e| EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string())))?;

        match response {
            StorageResponse::Data { payload, .. } => Ok(payload),
            StorageResponse::Error { message } => Err(EnclaveError::Enclave(EphemeralError::StorageError(message))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_correlation_fields_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let trace_id = "trace-test-1".to_string();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut len_buf = [0u8; 4];
            socket.read_exact(&mut len_buf).await.unwrap();
            let total_len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; total_len];
            socket.read_exact(&mut body).await.unwrap();

            let mut full_buf = Vec::with_capacity(4 + total_len);
            full_buf.extend_from_slice(&len_buf);
            full_buf.extend_from_slice(&body);

            let msg = VSockMessage::decode(&full_buf).unwrap();
            assert_eq!(msg.msg_type, MessageType::KmsProxy);

            let req_env: KmsProxyRequestEnvelope = serde_json::from_slice(&msg.payload).unwrap();
            assert!(!req_env.request_id.is_empty());
            assert_eq!(req_env.trace_id.as_deref(), Some("trace-test-1"));

            let resp_env = KmsProxyResponseEnvelope {
                request_id: req_env.request_id,
                trace_id: req_env.trace_id,
                kms_request_id: Some("aws-req-123".to_string()),
                response: KmsResponse::Decrypt {
                    ciphertext_for_recipient: Some(vec![1, 2, 3]),
                    plaintext: None,
                    key_id: None,
                },
            };

            let resp_payload = serde_json::to_vec(&resp_env).unwrap();
            let resp_msg = VSockMessage::new(MessageType::KmsProxy, msg.sequence, resp_payload).unwrap();
            socket.write_all(&resp_msg.encode()).await.unwrap();
        });

        let client = KmsProxyClient::new().with_addr(format!("127.0.0.1:{port}"));
        let response = client
            .send_request_with_trace(
                KmsRequest::Decrypt {
                    ciphertext_blob: vec![9, 9, 9],
                    key_id: None,
                    encryption_context: None,
                    grant_tokens: None,
                    recipient: Some(vec![1, 2, 3]),
                },
                Some(trace_id),
            )
            .await
            .unwrap();

        assert_eq!(response.trace_id.as_deref(), Some("trace-test-1"));
        assert_eq!(response.kms_request_id.as_deref(), Some("aws-req-123"));
    }

    #[tokio::test]
    async fn test_timeout_path_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let client = KmsProxyClient::new()
            .with_addr(format!("127.0.0.1:{port}"))
            .with_timeouts(KmsProxyClientTimeouts {
                connect: Duration::from_millis(200),
                io: Duration::from_millis(50),
                overall: Duration::from_millis(200),
            });

        let err = client
            .send_request(KmsRequest::GenerateDataKey {
                key_id: "k".to_string(),
                key_spec: "AES_256".to_string(),
            })
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            EnclaveError::Enclave(EphemeralError::Timeout(_))
        ));
    }
}
