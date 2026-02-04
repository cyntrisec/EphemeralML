use crate::{
    current_timestamp, AttestationProvider, EnclaveError, EphemeralAssembler, EphemeralError,
    InferenceEngine, Result,
};
// Re-export common types
use crate::assembly::{CandleModel, TopologyKey};
use crate::inference_handler::InferenceHandler;
use crate::session_manager::{EnclaveSession, SessionManager};
pub use ephemeral_ml_common::{AttestationDocument, MessageType, PcrMeasurements, VSockMessage};
use rsa::{pkcs8::EncodePublicKey, Oaep, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

/// Mock attestation document with user data for key binding
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MockAttestationUserData {
    pub hpke_public_key: [u8; 32],     // X25519 public key for HPKE
    pub receipt_signing_key: [u8; 32], // Ed25519 public key for receipts
    pub protocol_version: u32,         // Fixed to 1 for v1
    pub supported_features: Vec<String>,
}

use zeroize::ZeroizeOnDrop;

/// Mock key pair for testing
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct MockKeyPair {
    #[zeroize(skip)]
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

impl MockKeyPair {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        Self {
            public_key: *public.as_bytes(),
            private_key: *secret.as_bytes(),
        }
    }
}

// Helper functions to convert errors
fn io_error_to_enclave_error(err: std::io::Error) -> EnclaveError {
    EnclaveError::Enclave(EphemeralError::IoError(err.to_string()))
}

/// Mock attestation provider for local development
#[derive(Clone)]
pub struct MockAttestationProvider {
    pub valid_attestation: bool,
    pub hpke_keypair: MockKeyPair,
    pub kms_keypair: RsaPrivateKey,
}

impl MockAttestationProvider {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let kms_keypair = RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen failed");

        Self {
            valid_attestation: true,
            hpke_keypair: MockKeyPair::generate(),
            kms_keypair,
        }
    }

    pub fn with_invalid_attestation() -> Self {
        let mut rng = rand::thread_rng();
        let kms_keypair = RsaPrivateKey::new(&mut rng, 2048).expect("RSA keygen failed");

        Self {
            valid_attestation: false,
            hpke_keypair: MockKeyPair::generate(),
            kms_keypair,
        }
    }

    pub fn new_copy(&self) -> Self {
        Self {
            valid_attestation: self.valid_attestation,
            hpke_keypair: self.hpke_keypair.clone(),
            kms_keypair: self.kms_keypair.clone(),
        }
    }

    /// Generate mock attestation document with embedded keys
    pub fn generate_attestation_with_keys(
        &self,
        nonce: &[u8],
        receipt_public_key: [u8; 32],
    ) -> Result<AttestationDocument> {
        if !self.valid_attestation {
            return Err(EnclaveError::Enclave(EphemeralError::AttestationError(
                "Mock attestation configured to fail".to_string(),
            )));
        }

        // Create user data with embedded keys
        let user_data = MockAttestationUserData {
            hpke_public_key: self.hpke_keypair.public_key,
            receipt_signing_key: receipt_public_key,
            protocol_version: 1,
            supported_features: vec!["gateway".to_string()], // v1 only supports Gateway mode
        };

        let user_data_bytes = serde_json::to_vec(&user_data).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
        })?;

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

        let pcr0_bytes = hex::decode(pcr0).unwrap_or_else(|_| vec![0x01; 48]);
        let pcr1_bytes = hex::decode(pcr1).unwrap_or_else(|_| vec![0x02; 48]);
        let pcr2_bytes = hex::decode(pcr2).unwrap_or_else(|_| vec![0x03; 48]);

        // Export RSA public key as SPKI DER for KMS
        let kms_pub_key = self.kms_keypair.to_public_key();
        let kms_pub_der = kms_pub_key.to_public_key_der().expect("RSA export failed");

        // Create a mock CBOR document that resembles the real one for the host to verify
        use std::collections::BTreeMap;
        let mut map = BTreeMap::new();
        map.insert(
            serde_cbor::Value::Text("module_id".to_string()),
            serde_cbor::Value::Text("mock-enclave".to_string()),
        );
        map.insert(
            serde_cbor::Value::Text("user_data".to_string()),
            serde_cbor::Value::Bytes(user_data_bytes),
        );
        map.insert(
            serde_cbor::Value::Text("public_key".to_string()),
            serde_cbor::Value::Bytes(kms_pub_der.as_bytes().to_vec()),
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
        map.insert(
            serde_cbor::Value::Text("pcrs".to_string()),
            serde_cbor::Value::Map(pcrs_map),
        );

        let signature_bytes = serde_cbor::to_vec(&serde_cbor::Value::Map(map)).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
        })?;

        Ok(AttestationDocument {
            module_id: "mock-enclave".to_string(),
            digest,
            timestamp: current_timestamp(),
            pcrs: PcrMeasurements {
                pcr0: pcr0_bytes,
                pcr1: pcr1_bytes,
                pcr2: pcr2_bytes,
            },
            certificate: b"mock_certificate".to_vec(),
            signature: signature_bytes,
            nonce: Some(nonce.to_vec()),
        })
    }
}

impl Default for MockAttestationProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationProvider for MockAttestationProvider {
    fn generate_attestation(
        &self,
        nonce: &[u8],
        receipt_public_key: [u8; 32],
    ) -> Result<AttestationDocument> {
        self.generate_attestation_with_keys(nonce, receipt_public_key)
    }

    fn get_pcr_measurements(&self) -> Result<PcrMeasurements> {
        let pcr0 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        let pcr2 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

        Ok(PcrMeasurements {
            pcr0: hex::decode(pcr0).unwrap_or_else(|_| vec![0x01; 48]),
            pcr1: hex::decode(pcr1).unwrap_or_else(|_| vec![0x02; 48]),
            pcr2: hex::decode(pcr2).unwrap_or_else(|_| vec![0x03; 48]),
        })
    }

    fn get_hpke_public_key(&self) -> [u8; 32] {
        self.hpke_keypair.public_key
    }

    fn get_hpke_private_key(&self) -> [u8; 32] {
        self.hpke_keypair.private_key
    }

    fn decrypt_hpke(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use hpke::{aead::ChaCha20Poly1305, kem::X25519HkdfSha256, Deserializable, OpModeR};

        if ciphertext.len() < 32 {
            return Err(EnclaveError::Enclave(EphemeralError::DecryptionError(
                "Ciphertext too short".to_string(),
            )));
        }

        let (encapped_key_bytes, cipher_text) = ciphertext.split_at(32);

        let kem_priv =
            <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&self.hpke_keypair.private_key)
                .map_err(|e| {
                    EnclaveError::Enclave(EphemeralError::DecryptionError(format!(
                        "Invalid private key: {}",
                        e
                    )))
                })?;

        let encapped_key = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(
            encapped_key_bytes,
        )
        .map_err(|e| {
            EnclaveError::Enclave(EphemeralError::DecryptionError(format!(
                "Invalid encapped key: {}",
                e
            )))
        })?;

        let mut receiver_ctx = hpke::setup_receiver::<
            ChaCha20Poly1305,
            hpke::kdf::HkdfSha256,
            X25519HkdfSha256,
        >(&OpModeR::Base, &kem_priv, &encapped_key, b"KMS_DEK")
        .map_err(|e| {
            EnclaveError::Enclave(EphemeralError::DecryptionError(format!(
                "HPKE setup failed: {}",
                e
            )))
        })?;

        let plaintext = receiver_ctx.open(cipher_text, b"").map_err(|e| {
            EnclaveError::Enclave(EphemeralError::DecryptionError(format!(
                "HPKE open failed: {}",
                e
            )))
        })?;

        Ok(plaintext)
    }

    fn decrypt_kms(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // In unit tests, if ciphertext matches the HPKE-encrypted DEK we returned in the mock server,
        // we can't actually decrypt it with RSA-OAEP.
        // The mock server in `model_loader.rs` returns an HPKE-encrypted DEK.
        // But `ModelLoader` calls `kms_client.decrypt()`, which calls `attestation_provider.decrypt_kms()`.
        // Real KMS RecipientInfo flow uses RSA-OAEP.
        // Our mock server in the TEST (not the one in mock.rs) is using HPKE.
        // Let's fix the mock server in the test to use RSA-OAEP if that's what `decrypt_kms` expects,
        // OR fix `decrypt_kms` to be more flexible for mocks.

        // Actually, the `MockAttestationProvider` in `mock.rs` is used by the test.
        // Let's make it try HPKE if RSA fails, or just make the test server use RSA.

        let padding = Oaep::new::<Sha256>();
        match self.kms_keypair.decrypt(padding, ciphertext) {
            Ok(pt) => Ok(pt),
            Err(_) => {
                // Fallback for tests that might use HPKE-encrypted blobs in the mock server
                self.decrypt_hpke(ciphertext)
            }
        }
    }
}

/// Mock ephemeral assembler for local development
pub struct MockEphemeralAssembler {
    pub assembled_models: HashMap<String, CandleModel>,
}

impl MockEphemeralAssembler {
    pub fn new() -> Self {
        Self {
            assembled_models: HashMap::new(),
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

        self.assembled_models
            .insert(model.id.clone(), model.clone());
        Ok(model)
    }

    fn execute_inference(&self, _model: &CandleModel, input: &[u8]) -> Result<Vec<f32>> {
        let output: Vec<f32> = input.iter().map(|&x| (x as f32) * 2.0 + 1.0).collect();
        Ok(output)
    }

    fn destroy_model(&mut self, model: CandleModel) -> Result<()> {
        self.assembled_models.remove(&model.id);
        Ok(())
    }

    fn secure_memory_clear(&mut self) -> Result<()> {
        self.assembled_models.clear();
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
    fn execute(&self, model: &CandleModel, input: &[u8]) -> Result<Vec<f32>> {
        // Interpret input bytes as f32s for mock backwards compatibility if needed,
        // or just treat as raw data.
        if model.weights.is_empty() {
            return Err(EnclaveError::Enclave(EphemeralError::Internal(
                "Model weights are empty".to_string(),
            )));
        }
        let output: Vec<f32> = input
            .iter()
            .enumerate()
            .map(|(i, &x)| {
                let weight_factor = model.weights.get(i % model.weights.len()).unwrap_or(&1.0);
                (x as f32) * weight_factor + 0.1
            })
            .collect();
        Ok(output)
    }

    fn validate_input(&self, _model: &CandleModel, input: &[u8]) -> Result<()> {
        if input.is_empty() {
            return Err(EnclaveError::Enclave(EphemeralError::InferenceError(
                "Input cannot be empty".to_string(),
            )));
        }
        Ok(())
    }
}

/// Mock enclave server for TCP communication with full secure protocol
pub struct MockEnclaveServer {
    pub port: u16,
    pub session_manager: SessionManager,
    pub inference_handler: InferenceHandler<MockAttestationProvider, MockInferenceEngine>,
    pub attestation_provider: MockAttestationProvider,
}

impl MockEnclaveServer {
    pub fn new(port: u16) -> Self {
        let session_manager = SessionManager::new(100);
        let attestation_provider = MockAttestationProvider::new();
        let inference_engine = MockInferenceEngine::new();
        let inference_handler = InferenceHandler::new(
            session_manager.clone(),
            attestation_provider.new_copy(),
            inference_engine,
        );

        Self {
            port,
            session_manager,
            inference_handler,
            attestation_provider,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port))
            .await
            .map_err(|e| {
                EnclaveError::Enclave(EphemeralError::CommunicationError(format!(
                    "Failed to bind: {}",
                    e
                )))
            })?;

        println!("Mock secure enclave server listening on port {}", self.port);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let handler = self.inference_handler.clone();
                    let attestation = self.attestation_provider.new_copy();
                    let session_mgr = self.session_manager.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_secure_connection(
                            stream,
                            handler,
                            attestation,
                            session_mgr,
                        )
                        .await
                        {
                            eprintln!("Error handling connection from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_secure_connection(
        mut stream: TcpStream,
        handler: InferenceHandler<MockAttestationProvider, MockInferenceEngine>,
        attestation_provider: MockAttestationProvider,
        session_manager: SessionManager,
    ) -> Result<()> {
        use ephemeral_ml_common::protocol::{ClientHello, ServerHello};
        use ephemeral_ml_common::{HPKESession, ReceiptSigningKey};

        loop {
            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).await.is_err() {
                break; // Connection closed
            }
            let total_len = u32::from_be_bytes(len_buf) as usize;

            // FIX: Enforce MAX_MESSAGE_SIZE limit before allocation to prevent OOM
            if total_len > ephemeral_ml_common::vsock::MAX_MESSAGE_SIZE {
                eprintln!(
                    "Message too large: {} bytes (max {})",
                    total_len,
                    ephemeral_ml_common::vsock::MAX_MESSAGE_SIZE
                );
                break;
            }

            let mut body = vec![0u8; total_len];
            stream
                .read_exact(&mut body)
                .await
                .map_err(io_error_to_enclave_error)?;

            let mut full_buf = Vec::with_capacity(4 + total_len);
            full_buf.extend_from_slice(&len_buf);
            full_buf.extend_from_slice(&body);

            let msg = VSockMessage::decode(&full_buf).map_err(EnclaveError::Enclave)?;

            match msg.msg_type {
                MessageType::Hello => {
                    let client_hello: ClientHello =
                        serde_json::from_slice(&msg.payload).map_err(|e| {
                            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
                        })?;

                    client_hello.validate().map_err(EnclaveError::Enclave)?;

                    // Establish Session with per-session ephemeral keys (forward secrecy)
                    let session_id = "session-id".to_string();
                    let session_keypair = attestation_provider.generate_ephemeral_keypair();
                    let ephemeral_public_key = session_keypair.public_key;

                    // Generate per-session receipt signing key BEFORE attestation,
                    // so its public key can be embedded in the attestation user_data
                    let receipt_key =
                        ReceiptSigningKey::generate().map_err(EnclaveError::Enclave)?;
                    let receipt_pk = receipt_key.public_key_bytes();

                    let attestation_doc = attestation_provider
                        .generate_attestation(&client_hello.client_nonce, receipt_pk)?;

                    let mut hasher = Sha256::new();
                    hasher.update(&attestation_doc.signature);
                    let attestation_hash = hasher.finalize().into();

                    let mut hpke = HPKESession::new(
                        session_id.clone(),
                        1,
                        attestation_hash,
                        ephemeral_public_key, // Per-session ephemeral PK
                        client_hello.ephemeral_public_key, // Peer PK
                        client_hello.client_nonce,
                        3600,
                    )
                    .map_err(EnclaveError::Enclave)?;

                    hpke.establish(&session_keypair.private_key)
                        .map_err(EnclaveError::Enclave)?;
                    drop(session_keypair);

                    let session = EnclaveSession::new(
                        session_id.clone(),
                        hpke,
                        receipt_key,
                        attestation_hash,
                        client_hello.client_id,
                    );
                    session_manager.add_session(session)?;

                    let server_hello = ServerHello::new(
                        session_id,
                        vec!["gateway".to_string()],
                        attestation_doc.signature.clone(),
                        ephemeral_public_key.to_vec(),
                        receipt_pk.to_vec(),
                    )
                    .map_err(EnclaveError::Enclave)?;

                    let response_payload = serde_json::to_vec(&server_hello).map_err(|e| {
                        EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
                    })?;
                    let response_msg =
                        VSockMessage::new(MessageType::Hello, msg.sequence, response_payload)
                            .map_err(EnclaveError::Enclave)?;

                    stream
                        .write_all(&response_msg.encode())
                        .await
                        .map_err(io_error_to_enclave_error)?;
                }
                MessageType::Data => {
                    let encrypted_request: ephemeral_ml_common::EncryptedMessage =
                        serde_json::from_slice(&msg.payload).map_err(|e| {
                            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
                        })?;

                    let encrypted_response = handler.handle_request(&encrypted_request).await?;

                    let response_payload =
                        serde_json::to_vec(&encrypted_response).map_err(|e| {
                            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
                        })?;
                    let response_msg =
                        VSockMessage::new(MessageType::Data, msg.sequence, response_payload)
                            .map_err(EnclaveError::Enclave)?;

                    stream
                        .write_all(&response_msg.encode())
                        .await
                        .map_err(io_error_to_enclave_error)?;
                }
                MessageType::Ping => {
                    let encrypted_req: ephemeral_ml_common::EncryptedMessage =
                        serde_json::from_slice(&msg.payload).map_err(|e| {
                            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
                        })?;

                    let session_id = &encrypted_req.session_id;
                    let ping_result = session_manager.with_session(session_id, |session| {
                        let plaintext = session.decrypt(&encrypted_req)?;
                        let encrypted_resp = session.encrypt(&plaintext)?;
                        Ok(encrypted_resp)
                    });

                    match ping_result {
                        Ok(encrypted_resp) => {
                            let response_payload =
                                serde_json::to_vec(&encrypted_resp).map_err(|e| {
                                    EnclaveError::Enclave(EphemeralError::SerializationError(
                                        e.to_string(),
                                    ))
                                })?;
                            let response_msg = VSockMessage::new(
                                MessageType::Ping,
                                msg.sequence,
                                response_payload,
                            )
                            .map_err(EnclaveError::Enclave)?;
                            stream
                                .write_all(&response_msg.encode())
                                .await
                                .map_err(io_error_to_enclave_error)?;
                        }
                        Err(e) => {
                            eprintln!("[mock] Ping error: {}", e);
                            let err_payload = format!("Ping error: {}", e).into_bytes();
                            let err_msg =
                                VSockMessage::new(MessageType::Error, msg.sequence, err_payload)
                                    .map_err(EnclaveError::Enclave)?;
                            stream
                                .write_all(&err_msg.encode())
                                .await
                                .map_err(io_error_to_enclave_error)?;
                        }
                    }
                }
                _ => {
                    return Err(EnclaveError::Enclave(EphemeralError::ProtocolError(
                        format!("Unsupported message type: {:?}", msg.msg_type),
                    )));
                }
            }
            stream.flush().await.map_err(io_error_to_enclave_error)?;
        }
        Ok(())
    }
}

impl Clone for MockInferenceEngine {
    fn clone(&self) -> Self {
        Self
    }
}
