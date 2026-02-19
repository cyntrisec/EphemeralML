use crate::{
    current_timestamp, AttestationDocument, ClientError, EphemeralError, InferenceResult,
    PcrMeasurements, Result, SecureClient,
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
        use ciborium::Value;

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

        let pcrs_map = vec![
            (Value::Integer(0.into()), Value::Bytes(pcr0_bytes.clone())),
            (Value::Integer(1.into()), Value::Bytes(pcr1_bytes.clone())),
            (Value::Integer(2.into()), Value::Bytes(pcr2_bytes.clone())),
        ];

        let payload = vec![
            (
                Value::Text("module_id".to_string()),
                Value::Text("mock-enclave".to_string()),
            ),
            (
                Value::Text("timestamp".to_string()),
                Value::Integer((current_timestamp() as i64).into()),
            ),
            (
                Value::Text("nonce".to_string()),
                Value::Bytes(b"mock_nonce".to_vec()),
            ),
            (
                Value::Text("user_data".to_string()),
                Value::Bytes(user_data_json),
            ),
            (Value::Text("pcrs".to_string()), Value::Map(pcrs_map)),
        ];

        let payload_bytes = ephemeral_ml_common::cbor::to_vec(&Value::Map(payload)).unwrap();

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
        model_id: &str,
        input_tensor: Vec<f32>,
    ) -> Result<InferenceResult> {
        use crate::{AttestationReceipt, EnclaveMeasurements, SecurityMode};
        let output_tensor: Vec<f32> = input_tensor.iter().map(|x| x + 0.1).collect();
        let now = current_timestamp();
        let receipt = AttestationReceipt::new(
            model_id.to_string(),
            1,
            SecurityMode::GatewayOnly,
            EnclaveMeasurements::new(vec![0u8; 48], vec![0u8; 48], vec![0u8; 48]),
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            "mock".to_string(),
            now,
            model_id.to_string(),
            "mock".to_string(),
            0,
            0,
        );
        Ok(InferenceResult {
            output_tensor,
            receipt,
            generated_text: None,
            boot_attestation_b64: None,
            model_manifest_json: None,
        })
    }

    async fn execute_inference_text(
        &mut self,
        model_id: &str,
        text: &str,
    ) -> Result<InferenceResult> {
        use crate::{AttestationReceipt, EnclaveMeasurements, SecurityMode};
        // Mock: generate a fake 384-dim embedding from text length
        let dim = 384;
        let seed = text.len() as f32;
        let output_tensor: Vec<f32> = (0..dim).map(|i| ((i as f32 + seed) * 0.01).sin()).collect();
        let now = current_timestamp();
        let receipt = AttestationReceipt::new(
            model_id.to_string(),
            1,
            SecurityMode::GatewayOnly,
            EnclaveMeasurements::new(vec![0u8; 48], vec![0u8; 48], vec![0u8; 48]),
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            "mock".to_string(),
            now,
            model_id.to_string(),
            "mock".to_string(),
            0,
            0,
        );
        Ok(InferenceResult {
            output_tensor,
            receipt,
            generated_text: None,
            boot_attestation_b64: None,
            model_manifest_json: None,
        })
    }

    async fn execute_inference_generate(
        &mut self,
        model_id: &str,
        text: &str,
        max_tokens: usize,
    ) -> Result<InferenceResult> {
        use crate::{AttestationReceipt, EnclaveMeasurements, SecurityMode};
        // Mock: return a canned response
        let token_count = max_tokens.min(10);
        let output_tensor: Vec<f32> = (0..token_count).map(|i| i as f32).collect();
        let generated_text = format!(
            "[mock generation for '{}', {} tokens]",
            &text[..text.len().min(50)],
            token_count
        );
        let now = current_timestamp();
        let receipt = AttestationReceipt::new(
            model_id.to_string(),
            1,
            SecurityMode::GatewayOnly,
            EnclaveMeasurements::new(vec![0u8; 48], vec![0u8; 48], vec![0u8; 48]),
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            "mock".to_string(),
            now,
            model_id.to_string(),
            "mock".to_string(),
            0,
            0,
        );
        Ok(InferenceResult {
            output_tensor,
            receipt,
            generated_text: Some(generated_text),
            boot_attestation_b64: None,
            model_manifest_json: None,
        })
    }
}
