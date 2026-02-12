use crate::{EnclaveError, EphemeralError, Result};
use ephemeral_ml_common::{
    storage_protocol::{StorageRequest, StorageResponse},
    transport_types::simple_frame::{self, TAG_KMS, TAG_STORAGE},
    KmsProxyRequestEnvelope, KmsProxyResponseEnvelope, KmsRequest,
};
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

#[derive(Debug, Clone)]
pub struct KmsProxyClient {
    #[cfg(not(feature = "production"))]
    host_addr: String,
    #[cfg(feature = "production")]
    cid: u32,
    #[cfg(feature = "production")]
    port: u32,
    timeouts: KmsProxyClientTimeouts,
}

impl Default for KmsProxyClient {
    fn default() -> Self {
        Self::new()
    }
}

impl KmsProxyClient {
    pub fn new() -> Self {
        Self {
            #[cfg(not(feature = "production"))]
            host_addr: "127.0.0.1:8082".to_string(),
            #[cfg(feature = "production")]
            cid: 3, // Parent CID is always 3 in Nitro
            #[cfg(feature = "production")]
            port: 8082,
            timeouts: KmsProxyClientTimeouts::default(),
        }
    }

    #[cfg(not(feature = "production"))]
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

        let payload = serde_json::to_vec(&env).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
        })?;

        let response_payload = self.send_tagged(TAG_KMS, &payload).await?;

        let response: KmsProxyResponseEnvelope = serde_json::from_slice(&response_payload)
            .map_err(|e| {
                EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
            })?;

        if response.request_id != request_id {
            return Err(EnclaveError::Enclave(EphemeralError::ProtocolError(
                "KMS proxy response request_id mismatch".to_string(),
            )));
        }

        Ok(response)
    }

    /// Send a tagged frame and read the response. Returns the response payload.
    async fn send_tagged(&self, tag: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let started = Instant::now();
        let remaining = |overall: Duration| -> Duration {
            overall
                .checked_sub(started.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0))
        };

        // Connect
        #[cfg(not(feature = "production"))]
        let mut stream = tokio::time::timeout(
            self.timeouts.connect.min(remaining(self.timeouts.overall)),
            tokio::net::TcpStream::connect(&self.host_addr),
        )
        .await
        .map_err(|_| {
            EnclaveError::Enclave(EphemeralError::Timeout("Proxy connect timeout".to_string()))
        })?
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
        .map_err(|_| {
            EnclaveError::Enclave(EphemeralError::Timeout("Proxy connect timeout".to_string()))
        })?
        .map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to connect to host proxy (VSock): {}",
                e
            )))
        })?;

        // Write tagged frame
        tokio::time::timeout(
            self.timeouts.io.min(remaining(self.timeouts.overall)),
            simple_frame::write_frame(&mut stream, tag, payload),
        )
        .await
        .map_err(|_| {
            EnclaveError::Enclave(EphemeralError::Timeout("Proxy write timeout".to_string()))
        })?
        .map_err(|e| EnclaveError::Enclave(e))?;

        // Read response frame
        let (resp_tag, resp_payload) = tokio::time::timeout(
            self.timeouts.io.min(remaining(self.timeouts.overall)),
            simple_frame::read_frame(&mut stream),
        )
        .await
        .map_err(|_| {
            EnclaveError::Enclave(EphemeralError::Timeout("Proxy read timeout".to_string()))
        })?
        .map_err(|e| EnclaveError::Enclave(e))?;

        if resp_tag != tag {
            return Err(EnclaveError::Enclave(EphemeralError::ProtocolError(
                format!("Expected tag 0x{:02x}, got 0x{:02x}", tag, resp_tag),
            )));
        }

        Ok(resp_payload)
    }

    /// Send an audit frame and read the response.
    pub async fn send_audit(&self, payload: &[u8]) -> Result<Vec<u8>> {
        self.send_tagged(simple_frame::TAG_AUDIT, payload).await
    }

    pub async fn fetch_model(&self, model_id: &str) -> Result<Vec<u8>> {
        let req = StorageRequest {
            model_id: model_id.to_string(),
            part_index: 0,
        };

        let payload = serde_cbor::to_vec(&req).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
        })?;

        let response_payload = self.send_tagged(TAG_STORAGE, &payload).await?;

        let response: StorageResponse =
            serde_cbor::from_slice(&response_payload).map_err(|e| {
                EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
            })?;

        match response {
            StorageResponse::Data { payload, .. } => Ok(payload),
            StorageResponse::Error { message } => {
                Err(EnclaveError::Enclave(EphemeralError::StorageError(message)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_ml_common::KmsResponse;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_correlation_fields_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let trace_id = "trace-test-1".to_string();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Read simple_frame
            let (tag, payload) = simple_frame::read_frame(&mut socket).await.unwrap();
            assert_eq!(tag, TAG_KMS);

            let req_env: KmsProxyRequestEnvelope =
                serde_json::from_slice(&payload).unwrap();
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
            simple_frame::write_frame(&mut socket, TAG_KMS, &resp_payload)
                .await
                .unwrap();
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
                encryption_context: None,
                recipient: None,
            })
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            EnclaveError::Enclave(EphemeralError::Timeout(_))
        ));
    }
}
