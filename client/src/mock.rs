use crate::{
    ClientError, Result, SecureChannel, EncryptedPayload, TopologyKey, AttestationDocument,
    PcrMeasurements, ModelDecomposer, SecureClient, WeightArrays, ModelMetadata, GraphNode,
    GraphEdge, TensorShape, OperationType, WeightIndex, WeightType, EphemeralError, PayloadType,
    current_timestamp, generate_nonce
};
use std::path::Path;
use uuid::Uuid;
use sha2::{Sha256, Digest};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Mock model decomposer for local development and testing
pub struct MockModelDecomposer;

impl ModelDecomposer for MockModelDecomposer {
    fn decompose_model(&self, onnx_path: &Path) -> Result<(TopologyKey, WeightArrays)> {
        // Create a mock topology key
        let topology = TopologyKey {
            graph_id: Uuid::new_v4().to_string(),
            nodes: vec![
                GraphNode {
                    node_id: "input".to_string(),
                    operation: OperationType::Linear,
                    parameters: std::collections::HashMap::new(),
                    weight_indices: vec![WeightIndex {
                        start_idx: 0,
                        length: 100,
                        shape: TensorShape { dimensions: vec![10, 10] },
                        weight_type: WeightType::Weights,
                    }],
                },
                GraphNode {
                    node_id: "output".to_string(),
                    operation: OperationType::Softmax,
                    parameters: std::collections::HashMap::new(),
                    weight_indices: vec![],
                },
            ],
            edges: vec![GraphEdge {
                from_node: "input".to_string(),
                to_node: "output".to_string(),
                tensor_shape: TensorShape { dimensions: vec![1, 10] },
            }],
            input_shapes: vec![TensorShape { dimensions: vec![1, 10] }],
            output_shapes: vec![TensorShape { dimensions: vec![1, 10] }],
            metadata: ModelMetadata {
                name: format!("mock_model_{}", onnx_path.file_name().unwrap_or_default().to_string_lossy()),
                version: "1.0.0".to_string(),
                description: Some("Mock model for testing".to_string()),
                created_at: current_timestamp(),
                checksum: "mock_checksum_hash".to_string(),
            },
        };

        // Create mock weight arrays using the constructor
        let weight_data = (0..100).map(|i| i as f32 * 0.01).collect();
        let weights = WeightArrays::new(topology.graph_id.clone(), weight_data);

        Ok((topology, weights))
    }

    fn validate_onnx_compatibility(&self, _model_path: &Path) -> Result<()> {
        // Mock validation always passes
        Ok(())
    }

    fn check_candle_operator_support(&self, operators: &[String]) -> Result<()> {
        // Mock check - reject operators containing "unsupported"
        for op in operators {
            if op.to_lowercase().contains("unsupported") {
                return Err(ClientError::Client(EphemeralError::UnsupportedOperatorError(format!("Operator {} not supported", op))));
            }
        }
        Ok(())
    }
}

/// Mock secure client for local development and testing
pub struct MockSecureClient {
    pub mock_attestation_valid: bool,
    pub tcp_host: String,
    pub tcp_port: u16,
}

impl MockSecureClient {
    pub fn new() -> Self {
        Self {
            mock_attestation_valid: true,
            tcp_host: "127.0.0.1".to_string(),
            tcp_port: 8080,
        }
    }
    
    pub fn with_tcp_endpoint(host: String, port: u16) -> Self {
        Self {
            mock_attestation_valid: true,
            tcp_host: host,
            tcp_port: port,
        }
    }

    pub fn with_invalid_attestation() -> Self {
        Self {
            mock_attestation_valid: false,
            tcp_host: "127.0.0.1".to_string(),
            tcp_port: 8080,
        }
    }

    /// Generate a mock attestation document for testing with embedded keys
    pub fn generate_mock_attestation() -> AttestationDocument {
        let mut hasher = Sha256::new();
        hasher.update(b"mock_enclave_image");
        let digest_bytes = hasher.finalize();
        
        let mut digest = vec![0u8; 48];
        digest[..32].copy_from_slice(&digest_bytes);
        
        // Use consistent PCR measurements that match the policy
        let pcr0 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr2 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        
        AttestationDocument {
            module_id: "mock-enclave".to_string(),
            digest,
            timestamp: current_timestamp(),
            pcrs: PcrMeasurements {
                pcr0: hex::decode(pcr0).unwrap_or_else(|_| vec![0x01; 48]),
                pcr1: hex::decode(pcr1).unwrap_or_else(|_| vec![0x02; 48]),
                pcr2: hex::decode(pcr2).unwrap_or_else(|_| vec![0x03; 48]),
            },
            certificate: b"mock_certificate".to_vec(),
            signature: b"mock_signature".to_vec(),
            nonce: Some(b"mock_nonce".to_vec()),
        }
    }
    
    /// Send TCP request to mock host/enclave
    pub async fn send_tcp_request(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut stream = TcpStream::connect(format!("{}:{}", self.tcp_host, self.tcp_port))
            .await
            .map_err(|e| ClientError::Client(EphemeralError::CommunicationError(format!("Failed to connect to mock endpoint: {}", e))))?;
        
        // Send payload
        stream.write_all(payload).await
            .map_err(|e| ClientError::Client(EphemeralError::CommunicationError(format!("Failed to send data: {}", e))))?;
        stream.flush().await
            .map_err(|e| ClientError::Client(EphemeralError::CommunicationError(format!("Failed to flush stream: {}", e))))?;
        
        // Read response
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await
            .map_err(|e| ClientError::Client(EphemeralError::CommunicationError(format!("Failed to read response: {}", e))))?;
        
        Ok(response)
    }
}

impl Default for MockSecureClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureClient for MockSecureClient {
    fn establish_attested_channel(&mut self, enclave_endpoint: &str) -> Result<SecureChannel> {
        if !self.mock_attestation_valid {
            return Err(ClientError::Client(EphemeralError::AttestationError("Mock attestation failed".to_string())));
        }

        let mut channel = SecureChannel::new(
            enclave_endpoint.to_string(),
            b"mock_session_key_32_bytes_long!!".to_vec(),
            3600, // 1 hour TTL
        );
        channel.mark_attestation_verified();
        Ok(channel)
    }

    fn encrypt_inference_request(&self, topology: &TopologyKey, data: &[f32]) -> Result<EncryptedPayload> {
        // Mock encryption - just serialize and "encrypt" with XOR
        let mut payload_data = Vec::new();
        let topology_bytes = serde_json::to_vec(topology)
            .map_err(|e| ClientError::Client(EphemeralError::SerializationError(e.to_string())))?;
        payload_data.extend_from_slice(&topology_bytes);
        payload_data.extend_from_slice(&data.iter().flat_map(|f| f.to_le_bytes()).collect::<Vec<u8>>());
        
        // Mock encryption with simple XOR
        let key = 0x42u8;
        let encrypted_data: Vec<u8> = payload_data.iter().map(|b| b ^ key).collect();
        
        Ok(EncryptedPayload {
            data: encrypted_data,
            nonce: generate_nonce(),
            key_id: "mock-kms-key".to_string(),
            payload_type: PayloadType::InferenceRequest,
        })
    }

    fn verify_enclave_attestation(&self, _attestation_doc: &[u8]) -> Result<bool> {
        Ok(self.mock_attestation_valid)
    }
}