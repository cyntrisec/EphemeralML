use crate::{
    current_timestamp, AttestationDocument, ClientError, EphemeralError, PcrMeasurements, Result,
    SecureClient,
};

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

        let pcr_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr0_bytes = hex::decode(pcr_hex).unwrap();
        let pcr1_bytes = pcr0_bytes.clone();
        let pcr2_bytes = pcr0_bytes.clone();

        let mut payload = BTreeMap::new();
        payload.insert(
            serde_cbor::Value::Text("module_id".to_string()),
            serde_cbor::Value::Text("mock-enclave".to_string()),
        );
        payload.insert(
            serde_cbor::Value::Text("timestamp".to_string()),
            serde_cbor::Value::Integer(current_timestamp() as i128),
        );
        payload.insert(
            serde_cbor::Value::Text("nonce".to_string()),
            serde_cbor::Value::Bytes(b"mock_nonce".to_vec()),
        );
        payload.insert(
            serde_cbor::Value::Text("user_data".to_string()),
            serde_cbor::Value::Bytes(user_data_json),
        );

        let mut pcrs_map = BTreeMap::new();
        pcrs_map.insert(
            serde_cbor::Value::Integer(0),
            serde_cbor::Value::Bytes(pcr0_bytes.clone()),
        );
        pcrs_map.insert(
            serde_cbor::Value::Integer(1),
            serde_cbor::Value::Bytes(pcr1_bytes.clone()),
        );
        pcrs_map.insert(
            serde_cbor::Value::Integer(2),
            serde_cbor::Value::Bytes(pcr2_bytes.clone()),
        );
        payload.insert(
            serde_cbor::Value::Text("pcrs".to_string()),
            serde_cbor::Value::Map(pcrs_map),
        );

        let payload_bytes = serde_cbor::to_vec(&serde_cbor::Value::Map(payload)).unwrap();

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
            signature: payload_bytes,
            nonce: Some(b"mock_nonce".to_vec()),
        }
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
            return Err(ClientError::Client(EphemeralError::AttestationError(
                "Mock attestation failed".to_string(),
            )));
        }
        Ok(())
    }

    async fn execute_inference(
        &mut self,
        _model_id: &str,
        input_tensor: Vec<f32>,
    ) -> Result<Vec<f32>> {
        Ok(input_tensor.iter().map(|x| x + 0.1).collect())
    }
}
