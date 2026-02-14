use crate::policy::PolicyManager;
use crate::{ClientError, EphemeralError, Result};
use confidential_ml_transport::session::channel::Message;
use confidential_ml_transport::{SecureChannel, SessionConfig};
use ephemeral_ml_common::transport_types::EphemeralUserData;
use ephemeral_ml_common::{AttestationReceipt, ReceiptVerifier};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

#[derive(Serialize, Deserialize, Debug)]
pub struct InferenceHandlerInput {
    pub model_id: String,
    pub input_data: Vec<u8>,
    pub input_shape: Option<Vec<usize>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InferenceHandlerOutput {
    pub output_tensor: Vec<f32>,
    pub receipt: AttestationReceipt,
}

/// Result of an inference request, including the output tensor and the signed receipt.
pub struct InferenceResult {
    pub output_tensor: Vec<f32>,
    pub receipt: AttestationReceipt,
}

/// Trait for secure client communication
#[async_trait::async_trait]
pub trait SecureClient {
    /// Establish an attested secure channel with the enclave
    async fn establish_channel(&mut self, addr: &str) -> Result<()>;

    /// Execute inference on a model
    async fn execute_inference(
        &mut self,
        model_id: &str,
        input_tensor: Vec<f32>,
    ) -> Result<InferenceResult>;

    /// Execute inference by sending raw text (UTF-8 bytes).
    ///
    /// The server tokenizes internally — this avoids the lossy `(f32 * 255) as u8`
    /// conversion used by `execute_inference`.
    async fn execute_inference_text(
        &mut self,
        model_id: &str,
        text: &str,
    ) -> Result<InferenceResult>;
}

/// Default implementation of secure enclave client using SecureChannel.
///
/// The `SecureChannel` handles all encryption/decryption and handshake.
/// This client only needs to send/receive plaintext and verify receipts.
pub struct SecureEnclaveClient {
    #[allow(dead_code)]
    client_id: String,
    channel: Option<SecureChannel<TcpStream>>,
    policy_manager: PolicyManager,
    pub receipt_verifier: ReceiptVerifier,
    server_receipt_signing_key: Option<[u8; 32]>,
    server_attestation_hash: Option<[u8; 32]>,
    /// Tracks the last seen sequence number for replay detection
    last_sequence_number: u64,
    /// Maximum allowed receipt age in seconds (default: 5 minutes)
    max_receipt_age_secs: u64,
}

impl SecureEnclaveClient {
    pub fn new(client_id: String) -> Self {
        Self {
            client_id,
            channel: None,
            policy_manager: PolicyManager::new(),
            receipt_verifier: ReceiptVerifier::new(vec![]),
            server_receipt_signing_key: None,
            server_attestation_hash: None,
            last_sequence_number: u64::MAX, // sentinel: no receipts seen yet
            max_receipt_age_secs: 300, // 5 minutes
        }
    }

    /// Create a client with a pre-configured policy manager.
    ///
    /// Preferred for production use — ensures PCR validation has an allowlist
    /// loaded before attestation verification is attempted.
    pub fn with_policy(client_id: String, policy_manager: PolicyManager) -> Self {
        Self {
            client_id,
            channel: None,
            policy_manager,
            receipt_verifier: ReceiptVerifier::new(vec![]),
            server_receipt_signing_key: None,
            server_attestation_hash: None,
            last_sequence_number: u64::MAX, // sentinel: no receipts seen yet
            max_receipt_age_secs: 300,
        }
    }

    /// Check whether a policy is loaded.
    pub fn has_policy(&self) -> bool {
        self.policy_manager.current_policy().is_some()
    }

    /// Returns the server's Ed25519 receipt signing public key, if available.
    pub fn server_receipt_signing_key(&self) -> Option<[u8; 32]> {
        self.server_receipt_signing_key
    }
}

#[async_trait::async_trait]
impl SecureClient for SecureEnclaveClient {
    async fn establish_channel(&mut self, addr: &str) -> Result<()> {
        // In production mode, fail fast if no policy is loaded
        #[cfg(all(feature = "production", not(feature = "mock")))]
        if !self.has_policy() {
            return Err(ClientError::Client(EphemeralError::InvalidInput(
                "No attestation policy loaded. Call with_policy() or load a policy before establishing a channel.".to_string(),
            )));
        }

        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| ClientError::Client(EphemeralError::NetworkError(e.to_string())))?;

        // Build verifier bridge based on mode
        #[cfg(feature = "mock")]
        let verifier = crate::attestation_bridge::MockVerifierBridge::new();
        #[cfg(feature = "gcp")]
        let verifier = crate::attestation_bridge::TdxEnvelopeVerifierBridge::new(None);
        #[cfg(not(any(feature = "mock", feature = "gcp")))]
        let verifier =
            crate::attestation_bridge::CoseVerifierBridge::new(self.policy_manager.clone());

        // Client-side attestation provider for mutual attestation.
        // The client is not in an enclave, so it uses MockProvider —
        // the server's verifier is configured to accept this.
        let provider = confidential_ml_transport::MockProvider::new();

        let config = SessionConfig::builder()
            .build()
            .map_err(|e| ClientError::Client(EphemeralError::TransportError(e.to_string())))?;

        let channel = SecureChannel::connect_with_attestation(stream, &provider, &verifier, config)
            .await
            .map_err(|e| {
                ClientError::Client(EphemeralError::TransportError(format!(
                    "Handshake failed: {}",
                    e
                )))
            })?;

        // Extract server's receipt signing key and attestation hash from peer attestation
        if let Some(attestation) = channel.peer_attestation() {
            self.server_attestation_hash = Some(attestation.document_hash);

            if let Some(ref user_data_bytes) = attestation.user_data {
                if let Ok(user_data) = EphemeralUserData::from_cbor(user_data_bytes) {
                    self.server_receipt_signing_key = Some(user_data.receipt_signing_key);
                }
            }
        }

        self.channel = Some(channel);
        Ok(())
    }

    async fn execute_inference(
        &mut self,
        model_id: &str,
        input_tensor: Vec<f32>,
    ) -> Result<InferenceResult> {
        let channel = self.channel.as_mut().ok_or_else(|| {
            ClientError::Client(EphemeralError::InvalidInput(
                "Channel not established".to_string(),
            ))
        })?;

        // 1. Build plaintext request
        let input_data: Vec<u8> = input_tensor.iter().map(|&x| (x * 255.0) as u8).collect();
        let input = InferenceHandlerInput {
            model_id: model_id.to_string(),
            input_data,
            input_shape: None,
        };
        let plaintext = serde_json::to_vec(&input)
            .map_err(|e| ClientError::Client(EphemeralError::SerializationError(e.to_string())))?;

        // 2. Send over SecureChannel (encryption handled by channel)
        channel
            .send(bytes::Bytes::from(plaintext))
            .await
            .map_err(|e| {
                ClientError::Client(EphemeralError::TransportError(format!(
                    "Send failed: {}",
                    e
                )))
            })?;

        // 3. Receive response
        let msg = channel.recv().await.map_err(|e| {
            ClientError::Client(EphemeralError::TransportError(format!(
                "Recv failed: {}",
                e
            )))
        })?;

        let response_bytes = match msg {
            Message::Data(data) => data,
            Message::Error(err) => {
                return Err(ClientError::Client(EphemeralError::InferenceError(
                    format!("Server error: {}", err),
                )));
            }
            other => {
                return Err(ClientError::Client(EphemeralError::ProtocolError(format!(
                    "Expected Data response, got {:?}",
                    other
                ))));
            }
        };

        // 4. Parse response
        let output: InferenceHandlerOutput = serde_json::from_slice(&response_bytes)
            .map_err(|e| ClientError::Client(EphemeralError::SerializationError(e.to_string())))?;

        // 5. Verify receipt signature
        let signing_pk = self.server_receipt_signing_key.ok_or_else(|| {
            ClientError::Client(EphemeralError::ValidationError(
                "Missing receipt signing key".to_string(),
            ))
        })?;

        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&signing_pk).map_err(|e| {
            ClientError::Client(EphemeralError::ValidationError(format!(
                "Invalid receipt public key: {}",
                e
            )))
        })?;

        if !output
            .receipt
            .verify_signature(&public_key)
            .map_err(ClientError::Client)?
        {
            return Err(ClientError::Client(EphemeralError::ValidationError(
                "Invalid receipt signature".to_string(),
            )));
        }

        // 6. Verify binding to attestation
        // Skip when receipt has [0; 32] sentinel (direct mode: server's own
        // attestation hash is unavailable; identity proven by receipt signature).
        if let Some(attestation_hash) = self.server_attestation_hash {
            if output.receipt.attestation_doc_hash != [0u8; 32]
                && output.receipt.attestation_doc_hash != attestation_hash
            {
                return Err(ClientError::Client(EphemeralError::ValidationError(
                    "Receipt not bound to current attestation".to_string(),
                )));
            }
        }

        // 7. Verify model_id matches the requested model
        if output.receipt.model_id != model_id {
            return Err(ClientError::Client(EphemeralError::ValidationError(
                format!(
                    "Receipt model_id mismatch: expected '{}', got '{}'",
                    model_id, output.receipt.model_id
                ),
            )));
        }

        // 8. Verify timestamp freshness (reject stale receipts)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let receipt_age = now.saturating_sub(output.receipt.execution_timestamp);
        if receipt_age > self.max_receipt_age_secs {
            return Err(ClientError::Client(EphemeralError::ValidationError(
                format!(
                    "Receipt too old: {}s (max {}s)",
                    receipt_age, self.max_receipt_age_secs
                ),
            )));
        }

        // 9. Verify sequence number is monotonically increasing (replay detection)
        // First receipt (when no_receipts_seen) is always accepted.
        let no_receipts_seen = self.last_sequence_number == u64::MAX;
        if !no_receipts_seen && output.receipt.sequence_number <= self.last_sequence_number {
            return Err(ClientError::Client(EphemeralError::ValidationError(
                format!(
                    "Receipt sequence replay: got {}, last seen {}",
                    output.receipt.sequence_number, self.last_sequence_number
                ),
            )));
        }
        self.last_sequence_number = output.receipt.sequence_number;

        // 10. Verify request/response hash binding (computation integrity)
        {
            use sha2::{Digest, Sha256};
            let expected_response_hash: [u8; 32] = {
                let output_bytes: Vec<u8> = output
                    .output_tensor
                    .iter()
                    .flat_map(|f| f.to_le_bytes())
                    .collect();
                Sha256::digest(&output_bytes).into()
            };
            if output.receipt.response_hash != expected_response_hash {
                return Err(ClientError::Client(EphemeralError::ValidationError(
                    "Receipt response_hash does not match output data".to_string(),
                )));
            }
        }

        Ok(InferenceResult {
            output_tensor: output.output_tensor,
            receipt: output.receipt,
        })
    }

    async fn execute_inference_text(
        &mut self,
        model_id: &str,
        text: &str,
    ) -> Result<InferenceResult> {
        let channel = self.channel.as_mut().ok_or_else(|| {
            ClientError::Client(EphemeralError::InvalidInput(
                "Channel not established".to_string(),
            ))
        })?;

        // Send raw UTF-8 bytes — the server tokenizes internally
        let input = InferenceHandlerInput {
            model_id: model_id.to_string(),
            input_data: text.as_bytes().to_vec(),
            input_shape: None,
        };
        let plaintext = serde_json::to_vec(&input)
            .map_err(|e| ClientError::Client(EphemeralError::SerializationError(e.to_string())))?;

        channel
            .send(bytes::Bytes::from(plaintext))
            .await
            .map_err(|e| {
                ClientError::Client(EphemeralError::TransportError(format!(
                    "Send failed: {}",
                    e
                )))
            })?;

        let msg = channel.recv().await.map_err(|e| {
            ClientError::Client(EphemeralError::TransportError(format!(
                "Recv failed: {}",
                e
            )))
        })?;

        let response_bytes = match msg {
            Message::Data(data) => data,
            Message::Error(err) => {
                return Err(ClientError::Client(EphemeralError::InferenceError(
                    format!("Server error: {}", err),
                )));
            }
            other => {
                return Err(ClientError::Client(EphemeralError::ProtocolError(format!(
                    "Expected Data response, got {:?}",
                    other
                ))));
            }
        };

        let output: InferenceHandlerOutput = serde_json::from_slice(&response_bytes)
            .map_err(|e| ClientError::Client(EphemeralError::SerializationError(e.to_string())))?;

        // Verify receipt (same checks as execute_inference)
        let signing_pk = self.server_receipt_signing_key.ok_or_else(|| {
            ClientError::Client(EphemeralError::ValidationError(
                "Missing receipt signing key".to_string(),
            ))
        })?;

        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&signing_pk).map_err(|e| {
            ClientError::Client(EphemeralError::ValidationError(format!(
                "Invalid receipt public key: {}",
                e
            )))
        })?;

        if !output
            .receipt
            .verify_signature(&public_key)
            .map_err(ClientError::Client)?
        {
            return Err(ClientError::Client(EphemeralError::ValidationError(
                "Invalid receipt signature".to_string(),
            )));
        }

        if let Some(attestation_hash) = self.server_attestation_hash {
            if output.receipt.attestation_doc_hash != [0u8; 32]
                && output.receipt.attestation_doc_hash != attestation_hash
            {
                return Err(ClientError::Client(EphemeralError::ValidationError(
                    "Receipt not bound to current attestation".to_string(),
                )));
            }
        }

        if output.receipt.model_id != model_id {
            return Err(ClientError::Client(EphemeralError::ValidationError(
                format!(
                    "Receipt model_id mismatch: expected '{}', got '{}'",
                    model_id, output.receipt.model_id
                ),
            )));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let receipt_age = now.saturating_sub(output.receipt.execution_timestamp);
        if receipt_age > self.max_receipt_age_secs {
            return Err(ClientError::Client(EphemeralError::ValidationError(
                format!(
                    "Receipt too old: {}s (max {}s)",
                    receipt_age, self.max_receipt_age_secs
                ),
            )));
        }

        let no_receipts_seen = self.last_sequence_number == u64::MAX;
        if !no_receipts_seen && output.receipt.sequence_number <= self.last_sequence_number {
            return Err(ClientError::Client(EphemeralError::ValidationError(
                format!(
                    "Receipt sequence replay: got {}, last seen {}",
                    output.receipt.sequence_number, self.last_sequence_number
                ),
            )));
        }
        self.last_sequence_number = output.receipt.sequence_number;

        {
            use sha2::{Digest, Sha256};
            let expected_response_hash: [u8; 32] = {
                let output_bytes: Vec<u8> = output
                    .output_tensor
                    .iter()
                    .flat_map(|f| f.to_le_bytes())
                    .collect();
                Sha256::digest(&output_bytes).into()
            };
            if output.receipt.response_hash != expected_response_hash {
                return Err(ClientError::Client(EphemeralError::ValidationError(
                    "Receipt response_hash does not match output data".to_string(),
                )));
            }
        }

        Ok(InferenceResult {
            output_tensor: output.output_tensor,
            receipt: output.receipt,
        })
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use crate::attestation_bridge::MockVerifierBridge;
    use bytes::Bytes;
    use confidential_ml_transport::session::channel::Message;
    use confidential_ml_transport::{SecureChannel, SessionConfig};
    use ephemeral_ml_common::{EnclaveMeasurements, ReceiptSigningKey, SecurityMode};

    #[tokio::test]
    async fn test_full_secure_inference_mock() {
        // Start a mock server that uses SecureChannel
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{}", port);

        // Generate receipt signing key for the server
        let receipt_key = ReceiptSigningKey::generate().unwrap();
        let _receipt_pk_bytes = receipt_key.public_key_bytes();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();

            // Use mock attestation provider/verifier from cml-transport
            let mock_provider = confidential_ml_transport::MockProvider;
            let mock_verifier = confidential_ml_transport::MockVerifier;
            let config = SessionConfig::builder().build().unwrap();

            let mut channel = SecureChannel::accept_with_attestation(
                stream,
                &mock_provider,
                &mock_verifier,
                config,
            )
            .await
            .unwrap();

            // Receive inference request
            let msg = channel.recv().await.unwrap();
            if let Message::Data(data) = msg {
                let input: InferenceHandlerInput = serde_json::from_slice(&data).unwrap();
                let output_tensor: Vec<f32> =
                    input.input_data.iter().map(|&x| (x as f32) + 0.1).collect();

                // Compute response hash matching what client will verify
                let output_bytes: Vec<u8> =
                    output_tensor.iter().flat_map(|f| f.to_le_bytes()).collect();
                let response_hash: [u8; 32] = {
                    use sha2::{Digest, Sha256};
                    Sha256::digest(&output_bytes).into()
                };

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let mut signed_receipt = ephemeral_ml_common::AttestationReceipt::new(
                    input.model_id.clone(), // model_id must match request
                    1,
                    SecurityMode::GatewayOnly,
                    EnclaveMeasurements::new(vec![0x01; 48], vec![0x02; 48], vec![0x03; 48]),
                    [0u8; 32], // attestation_doc_hash — matches mock
                    [0u8; 32],
                    response_hash,
                    "v1".to_string(),
                    now,
                    input.model_id.clone(),
                    "v1".to_string(),
                    0,
                    0,
                );

                signed_receipt.sign(&receipt_key).unwrap();

                let output = InferenceHandlerOutput {
                    output_tensor,
                    receipt: signed_receipt,
                };
                let response_bytes = serde_json::to_vec(&output).unwrap();
                channel.send(Bytes::from(response_bytes)).await.unwrap();
            }
        });

        // Client side
        let verifier = MockVerifierBridge::new();
        let client_provider = confidential_ml_transport::MockProvider;
        let stream = TcpStream::connect(&addr).await.unwrap();
        let config = SessionConfig::builder().build().unwrap();
        let mut channel =
            SecureChannel::connect_with_attestation(stream, &client_provider, &verifier, config)
                .await
                .unwrap();

        // Send inference request
        let input = InferenceHandlerInput {
            model_id: "test-model".to_string(),
            input_data: vec![1, 2, 3],
            input_shape: Some(vec![3]),
        };
        let input_bytes = serde_json::to_vec(&input).unwrap();
        channel.send(Bytes::from(input_bytes)).await.unwrap();

        // Receive response
        let msg = channel.recv().await.unwrap();
        if let Message::Data(data) = msg {
            let output: InferenceHandlerOutput = serde_json::from_slice(&data).unwrap();
            assert_eq!(output.output_tensor, vec![1.1, 2.1, 3.1]);
            assert!(output.receipt.signature.is_some());
        } else {
            panic!("Expected Data message");
        }
    }
}
