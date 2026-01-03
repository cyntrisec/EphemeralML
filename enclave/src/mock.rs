use crate::{
    EnclaveError, Result, AttestationProvider, EphemeralAssembler, InferenceEngine,
    EphemeralError, current_timestamp,
};
// Re-export common types
pub use ephemeral_ml_common::{AttestationDocument, PcrMeasurements};
use crate::assembly::{TopologyKey, CandleModel};
use sha2::{Sha256, Digest};
use uuid::Uuid;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};

/// Mock attestation document with user data for key binding
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MockAttestationUserData {
    pub hpke_public_key: [u8; 32],      // X25519 public key for HPKE
    pub receipt_signing_key: [u8; 32],  // Ed25519 public key for receipts
    pub protocol_version: u32,          // Fixed to 1 for v1
    pub supported_features: Vec<String>,
}

/// Mock key pair for testing
#[derive(Clone, Debug)]
pub struct MockKeyPair {
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

impl MockKeyPair {
    pub fn generate() -> Self {
        // Generate deterministic keys for testing
        let mut hasher = Sha256::new();
        hasher.update(uuid::Uuid::new_v4().as_bytes());
        let hash = hasher.finalize();
        
        let mut public_key = [0u8; 32];
        let mut private_key = [0u8; 32];
        
        public_key.copy_from_slice(&hash[..32]);
        
        // Generate private key from public key for deterministic testing
        let mut hasher2 = Sha256::new();
        hasher2.update(&public_key);
        let hash2 = hasher2.finalize();
        private_key.copy_from_slice(&hash2[..32]);
        
        Self { public_key, private_key }
    }
}

// Helper functions to convert errors
fn io_error_to_enclave_error(err: std::io::Error) -> EnclaveError {
    EnclaveError::Enclave(EphemeralError::IoError(err.to_string()))
}

fn serde_error_to_enclave_error(err: serde_json::Error) -> EnclaveError {
    EnclaveError::Enclave(EphemeralError::SerializationError(err.to_string()))
}

/// Mock attestation provider for local development
pub struct MockAttestationProvider {
    pub valid_attestation: bool,
    pub hpke_keypair: MockKeyPair,
    pub receipt_keypair: MockKeyPair,
}

impl MockAttestationProvider {
    pub fn new() -> Self {
        Self {
            valid_attestation: true,
            hpke_keypair: MockKeyPair::generate(),
            receipt_keypair: MockKeyPair::generate(),
        }
    }

    pub fn with_invalid_attestation() -> Self {
        Self {
            valid_attestation: false,
            hpke_keypair: MockKeyPair::generate(),
            receipt_keypair: MockKeyPair::generate(),
        }
    }
    
    /// Generate mock attestation document with embedded keys
    pub fn generate_attestation_with_keys(&self, nonce: &[u8]) -> Result<AttestationDocument> {
        if !self.valid_attestation {
            return Err(EnclaveError::Enclave(EphemeralError::AttestationError("Mock attestation configured to fail".to_string())));
        }

        // Create user data with embedded keys
        let user_data = MockAttestationUserData {
            hpke_public_key: self.hpke_keypair.public_key,
            receipt_signing_key: self.receipt_keypair.public_key,
            protocol_version: 1,
            supported_features: vec!["gateway".to_string()], // v1 only supports Gateway mode
        };
        
        let user_data_bytes = serde_json::to_vec(&user_data)
            .map_err(|e| EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string())))?;

        let mut hasher = Sha256::new();
        hasher.update(b"mock_enclave_image");
        hasher.update(nonce);
        hasher.update(&user_data_bytes);
        let digest_bytes = hasher.finalize();
        
        let mut digest = vec![0u8; 48];
        digest[..32].copy_from_slice(&digest_bytes);
        
        // Create deterministic PCR measurements for mock mode
        let pcr0 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr2 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        
        Ok(AttestationDocument {
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
            nonce: Some(nonce.to_vec()),
        })
    }
    
    /// Get HPKE public key for session establishment
    pub fn get_hpke_public_key(&self) -> [u8; 32] {
        self.hpke_keypair.public_key
    }
    
    /// Get receipt signing public key
    pub fn get_receipt_public_key(&self) -> [u8; 32] {
        self.receipt_keypair.public_key
    }
}

impl Default for MockAttestationProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationProvider for MockAttestationProvider {
    fn generate_attestation(&self, nonce: &[u8]) -> Result<AttestationDocument> {
        self.generate_attestation_with_keys(nonce)
    }

    fn get_pcr_measurements(&self) -> Result<PcrMeasurements> {
        // Return consistent mock measurements
        let pcr0 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr2 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        
        Ok(PcrMeasurements {
            pcr0: hex::decode(pcr0).unwrap_or_else(|_| vec![0x01; 48]),
            pcr1: hex::decode(pcr1).unwrap_or_else(|_| vec![0x02; 48]),
            pcr2: hex::decode(pcr2).unwrap_or_else(|_| vec![0x03; 48]),
        })
    }
}

/// Mock ephemeral assembler for local development
pub struct MockEphemeralAssembler {
    pub assembled_models: std::collections::HashMap<String, CandleModel>,
}

impl MockEphemeralAssembler {
    pub fn new() -> Self {
        Self {
            assembled_models: std::collections::HashMap::new(),
        }
    }
}

impl Default for MockEphemeralAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl EphemeralAssembler for MockEphemeralAssembler {
    fn assemble_model(&mut self, topology: &TopologyKey, weights: &[f32]) -> Result<CandleModel> {
        let model = CandleModel {
            id: Uuid::new_v4().to_string(),
            topology: topology.clone(),
            weights: weights.to_vec(),
        };
        
        self.assembled_models.insert(model.id.clone(), model.clone());
        println!("Mock: Assembled model {} with {} weights", model.id, weights.len());
        
        Ok(model)
    }

    fn execute_inference(&self, model: &CandleModel, input: &[f32]) -> Result<Vec<f32>> {
        // Mock inference - just return a simple transformation of input
        let output: Vec<f32> = input.iter().map(|x| x * 2.0 + 1.0).collect();
        println!("Mock: Executed inference on model {} with {} inputs, got {} outputs", 
                 model.id, input.len(), output.len());
        Ok(output)
    }

    fn destroy_model(&mut self, model: CandleModel) -> Result<()> {
        self.assembled_models.remove(&model.id);
        println!("Mock: Destroyed model {}", model.id);
        
        // Mock secure memory clearing
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn secure_memory_clear(&mut self) -> Result<()> {
        self.assembled_models.clear();
        println!("Mock: Cleared all models from memory");
        
        // Mock memory fence
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// Mock inference engine for local development
pub struct MockInferenceEngine;

impl MockInferenceEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockInferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl InferenceEngine for MockInferenceEngine {
    fn execute(&self, model: &CandleModel, input: &[f32]) -> Result<Vec<f32>> {
        // Mock inference execution
        let output: Vec<f32> = input.iter().enumerate().map(|(i, x)| {
            let weight_factor = model.weights.get(i % model.weights.len()).unwrap_or(&1.0);
            x * weight_factor + 0.1
        }).collect();
        
        println!("Mock inference: processed {} inputs to {} outputs", input.len(), output.len());
        Ok(output)
    }

    fn validate_input(&self, model: &CandleModel, input: &[f32]) -> Result<()> {
        if input.is_empty() {
            return Err(EnclaveError::Enclave(EphemeralError::InferenceError("Input cannot be empty".to_string())));
        }
        
        // Mock validation based on model input shapes
        if let Some(input_shape) = model.topology.input_shapes.first() {
            let expected_size: usize = input_shape.dimensions.iter().product();
            if input.len() != expected_size {
                return Err(EnclaveError::Enclave(EphemeralError::InferenceError(
                    format!("Input size {} doesn't match expected size {}", input.len(), expected_size)
                )));
            }
        }
        
        Ok(())
    }
}

/// Mock enclave server for TCP communication
pub struct MockEnclaveServer {
    pub port: u16,
    pub attestation_provider: MockAttestationProvider,
    pub assembler: MockEphemeralAssembler,
    pub inference_engine: MockInferenceEngine,
}

impl MockEnclaveServer {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            attestation_provider: MockAttestationProvider::new(),
            assembler: MockEphemeralAssembler::new(),
            inference_engine: MockInferenceEngine::new(),
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port))
            .await
            .map_err(|e| EnclaveError::Enclave(EphemeralError::CommunicationError(format!("Failed to bind: {}", e))))?;

        println!("Mock enclave server listening on port {}", self.port);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    println!("Mock enclave: Connection from {}", addr);
                    if let Err(e) = self.handle_connection(stream).await {
                        eprintln!("Error handling connection: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_connection(&mut self, mut stream: TcpStream) -> Result<()> {
        let mut buffer = vec![0u8; 4096];
        let bytes_read = stream.read(&mut buffer).await.map_err(io_error_to_enclave_error)?;
        
        if bytes_read == 0 {
            return Ok(());
        }

        let request = String::from_utf8_lossy(&buffer[..bytes_read]);
        println!("Mock enclave received: {}", request);

        // Generate mock attestation
        let attestation = self.attestation_provider.generate_attestation(b"mock_nonce")?;
        let response = serde_json::to_string(&attestation).map_err(serde_error_to_enclave_error)?;
        
        stream.write_all(response.as_bytes()).await.map_err(io_error_to_enclave_error)?;
        stream.flush().await.map_err(io_error_to_enclave_error)?;
        
        Ok(())
    }
}