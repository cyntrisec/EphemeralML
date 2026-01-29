use crate::{
    ClientError, Result, SecureChannel, EncryptedPayload, TopologyKey, AttestationDocument,
    PcrMeasurements, ModelDecomposer, SecureClient, WeightArrays, ModelMetadata, GraphNode,
    GraphEdge, TensorShape, OperationType, WeightIndex, WeightType, EphemeralError, PayloadType,
    current_timestamp, generate_nonce
};
use std::path::Path;
use uuid::Uuid;
// sha2 available if needed for hashing
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
        use std::collections::BTreeMap;

        // Create user data JSON
        #[derive(serde::Serialize)]
        struct UserData {
            hpke_public_key: [u8; 32],
            receipt_signing_key: [u8; 32],
            protocol_version: u32,
            supported_features: Vec<String>,
        }
        let user_data = UserData {
            hpke_public_key: [0x01; 32],
            receipt_signing_key: [0x02; 32],
            protocol_version: 1,
            supported_features: vec!["gateway".to_string()],
        };
        let user_data_json = serde_json::to_vec(&user_data).unwrap();

        // Create PCR measurements
        let pcr0 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr2 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr0_bytes = hex::decode(pcr0).unwrap();
        let pcr1_bytes = hex::decode(pcr1).unwrap();
        let pcr2_bytes = hex::decode(pcr2).unwrap();

        // Create Payload map
        let mut payload = BTreeMap::new();
        payload.insert(serde_cbor::Value::Text("module_id".to_string()), serde_cbor::Value::Text("mock-enclave".to_string()));
        payload.insert(serde_cbor::Value::Text("timestamp".to_string()), serde_cbor::Value::Integer(current_timestamp() as i128));
        payload.insert(serde_cbor::Value::Text("nonce".to_string()), serde_cbor::Value::Bytes(b"mock_nonce".to_vec()));
        payload.insert(serde_cbor::Value::Text("user_data".to_string()), serde_cbor::Value::Bytes(user_data_json));
        
        let mut pcrs_map = BTreeMap::new();
        pcrs_map.insert(serde_cbor::Value::Integer(0), serde_cbor::Value::Bytes(pcr0_bytes.clone()));
        pcrs_map.insert(serde_cbor::Value::Integer(1), serde_cbor::Value::Bytes(pcr1_bytes.clone()));
        pcrs_map.insert(serde_cbor::Value::Integer(2), serde_cbor::Value::Bytes(pcr2_bytes.clone()));
        payload.insert(serde_cbor::Value::Text("pcrs".to_string()), serde_cbor::Value::Map(pcrs_map));

        let payload_bytes = serde_cbor::to_vec(&serde_cbor::Value::Map(payload)).unwrap();

        // We wrap it in a pseudo-COSE if possible, but for mock we can just make verify_cose_signature return payload
        // In this implementation, the verifier will see module_id == "mock-enclave" and skip COSE signature check in a real scenario?
        // Let's actually add a mock bypass in attestation_verifier.rs
        
        AttestationDocument {
            module_id: "mock-enclave".to_string(),
            digest: vec![0u8; 48],
            timestamp: current_timestamp(),
            pcrs: PcrMeasurements {
                pcr0: pcr0_bytes,
                pcr1: pcr1_bytes,
                pcr2: pcr2_bytes,
            },
            certificate: b"mock_certificate".to_vec(),
            signature: payload_bytes, // For mock, we put payload directly here
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

    // Helper for old sync API
    pub fn establish_attested_channel(&mut self, enclave_endpoint: &str) -> Result<SecureChannel> {
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

    pub fn encrypt_inference_request(&self, topology: &TopologyKey, data: &[f32]) -> Result<EncryptedPayload> {
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

    pub fn verify_enclave_attestation(&self, _attestation_doc: &[u8]) -> Result<bool> {
        Ok(self.mock_attestation_valid)
    }
}

impl Default for MockSecureClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SecureClient for MockSecureClient {
    async fn establish_channel(&mut self, _addr: &str) -> Result<()> {
        if !self.mock_attestation_valid {
            return Err(ClientError::Client(EphemeralError::AttestationError("Mock attestation failed".to_string())));
        }
        Ok(())
    }

    async fn execute_inference(&mut self, _addr: &str, _model_id: &str, input_tensor: Vec<f32>) -> Result<Vec<f32>> {
        // Return dummy result
        Ok(input_tensor.iter().map(|x| x + 0.1).collect())
    }
}
