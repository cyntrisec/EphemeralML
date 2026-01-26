use crate::{ClientError, Result, EphemeralError};
use ephemeral_ml_common::{
    HPKESession, ReceiptVerifier, VSockMessage, MessageType, EncryptedMessage,
    AttestationReceipt, AttestationDocument
};
use ephemeral_ml_common::protocol::{ClientHello, ServerHello};
use crate::policy::PolicyManager;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};

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

/// Trait for secure client communication
#[async_trait::async_trait]
pub trait SecureClient {
    /// Establish an attested secure channel with the enclave
    async fn establish_channel(&mut self, addr: &str) -> Result<()>;
    
    /// Execute inference on a model
    async fn execute_inference(&mut self, addr: &str, model_id: &str, input_tensor: Vec<f32>) -> Result<Vec<f32>>;
}

use zeroize::ZeroizeOnDrop;

/// Default implementation of secure enclave client
#[derive(ZeroizeOnDrop)]
pub struct SecureEnclaveClient {
    #[zeroize(skip)]
    client_id: String,
    #[zeroize(skip)]
    hpke_session: Option<HPKESession>,
    #[zeroize(skip)]
    policy_manager: PolicyManager,
    #[zeroize(skip)]
    pub receipt_verifier: ReceiptVerifier,
    client_private_key: Option<[u8; 32]>,
    #[zeroize(skip)]
    server_receipt_signing_key: Option<[u8; 32]>,
    #[zeroize(skip)]
    server_attestation_doc: Option<Vec<u8>>,
}

impl SecureEnclaveClient {
    pub fn new(client_id: String) -> Self {
        Self {
            client_id,
            hpke_session: None,
            policy_manager: PolicyManager::new(),
            receipt_verifier: ReceiptVerifier::new(vec![]), // Empty roots for mock
            client_private_key: None,
            server_receipt_signing_key: None,
            server_attestation_doc: None,
        }
    }
}

#[async_trait::async_trait]
impl SecureClient for SecureEnclaveClient {
    /// Establish attested secure channel with enclave
    async fn establish_channel(&mut self, addr: &str) -> Result<()> {
        use x25519_dalek::{StaticSecret, PublicKey};
        use rand::rngs::OsRng;

        let mut stream = TcpStream::connect(addr).await
            .map_err(|e| ClientError::Client(EphemeralError::NetworkError(e.to_string())))?;

        // 1. Generate client ephemeral keypair and send ClientHello
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);
        let client_public_bytes = *client_public.as_bytes();
        self.client_private_key = Some(*client_secret.as_bytes());

        let client_hello = ClientHello::new(self.client_id.clone(), vec!["gateway".to_string()], client_public_bytes)
            .map_err(|e| ClientError::Client(e))?;
        
        let hello_payload = serde_json::to_vec(&client_hello).unwrap();
        let hello_msg = VSockMessage::new(MessageType::Hello, 0, hello_payload)
            .map_err(|e| ClientError::Client(e))?;
        
        stream.write_all(&hello_msg.encode()).await
            .map_err(|e| ClientError::Client(EphemeralError::NetworkError(e.to_string())))?;

        // 2. Receive ServerHello
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await
            .map_err(|e| ClientError::Client(EphemeralError::NetworkError(e.to_string())))?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; total_len];
        stream.read_exact(&mut body).await
            .map_err(|e| ClientError::Client(EphemeralError::NetworkError(e.to_string())))?;
        
        let mut full_buf = Vec::with_capacity(4 + total_len);
        full_buf.extend_from_slice(&len_buf);
        full_buf.extend_from_slice(&body);
        
        let response_msg = VSockMessage::decode(&full_buf)
            .map_err(|e| ClientError::Client(e))?;
        
        if response_msg.msg_type != MessageType::Hello {
             return Err(ClientError::Client(EphemeralError::ProtocolError("Expected ServerHello".to_string())));
        }

        let server_hello: ServerHello = serde_json::from_slice(&response_msg.payload)
            .map_err(|e| ClientError::Client(EphemeralError::SerializationError(e.to_string())))?;
        
        server_hello.validate().map_err(|e| ClientError::Client(e))?;
        self.server_receipt_signing_key = Some(server_hello.receipt_signing_key.as_slice().try_into().unwrap());
        self.server_attestation_doc = Some(server_hello.attestation_document.clone());

        // 3. Verify Attestation
        let attestation_doc: AttestationDocument = serde_json::from_slice(&server_hello.attestation_document)
            .map_err(|e| ClientError::Client(EphemeralError::SerializationError(e.to_string())))?;
        
        // Mock verification
        let pcr0 = hex::encode(&attestation_doc.pcrs.pcr0);
        let pcr1 = hex::encode(&attestation_doc.pcrs.pcr1);
        let pcr2 = hex::encode(&attestation_doc.pcrs.pcr2);
        
        // Load default policy for mock
        let default_policy = PolicyManager::create_default_policy();
        self.policy_manager.load_policy(&serde_json::to_vec(&default_policy).unwrap())
            .map_err(|e| ClientError::Client(EphemeralError::AttestationError(e.to_string())))?;

        if !self.policy_manager.is_measurement_allowed(&pcr0, &pcr1, &pcr2)
            .map_err(|e| ClientError::Client(EphemeralError::AttestationError(e.to_string())))? {
            return Err(ClientError::Client(EphemeralError::AttestationError("Enclave measurements not allowed by policy".to_string())));
        }

        // 4. Establish HPKE Session
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&attestation_doc.signature);
        let attestation_hash = hasher.finalize().into();

        let server_public_key_bytes: [u8; 32] = server_hello.ephemeral_public_key.as_slice().try_into()
            .map_err(|_| ClientError::Client(EphemeralError::InvalidInput("Invalid pubkey length".to_string())))?;

        let mut hpke = HPKESession::new(
            "session-id".to_string(),
            1,
            attestation_hash,
            client_public_bytes,      // Local PK
            server_public_key_bytes, // Peer PK
            client_hello.client_nonce,
            3600,
        ).map_err(|e| ClientError::Client(e))?;

        hpke.establish(&self.client_private_key.unwrap()).map_err(|e| ClientError::Client(e))?;

        self.hpke_session = Some(hpke);
        Ok(())
    }

    async fn execute_inference(
        &mut self,
        addr: &str,
        model_id: &str,
        input_tensor: Vec<f32>,
    ) -> Result<Vec<f32>> {
        let hpke = self.hpke_session.as_mut()
            .ok_or_else(|| ClientError::Client(EphemeralError::InvalidInput("Channel not established".to_string())))?;

        // 1. Encrypt Request
        // Convert f32 tensor back to bytes for the mock server which expects Vec<u8>
        // In a real scenario, this would likely serialize the tensor properly
        let input_data: Vec<u8> = input_tensor.iter().map(|&x| (x * 255.0) as u8).collect();
        
        let input = InferenceHandlerInput {
            model_id: model_id.to_string(),
            input_data,
            input_shape: None,
        };
        let plaintext = serde_json::to_vec(&input).unwrap();
        let encrypted_request = hpke.encrypt(&plaintext).map_err(|e| ClientError::Client(e))?;

        // 2. Send over VSock (TCP Mock)
        let mut stream = TcpStream::connect(addr).await
            .map_err(|e| ClientError::Client(EphemeralError::NetworkError(e.to_string())))?;
        
        let payload = serde_json::to_vec(&encrypted_request).unwrap();
        let msg = VSockMessage::new(MessageType::Data, 1, payload).map_err(|e| ClientError::Client(e))?;
        
        stream.write_all(&msg.encode()).await
            .map_err(|e| ClientError::Client(EphemeralError::NetworkError(e.to_string())))?;

        // 3. Receive Response
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await
            .map_err(|e| ClientError::Client(EphemeralError::NetworkError(e.to_string())))?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; total_len];
        stream.read_exact(&mut body).await
            .map_err(|e| ClientError::Client(EphemeralError::NetworkError(e.to_string())))?;
        
        let mut full_buf = Vec::with_capacity(4 + total_len);
        full_buf.extend_from_slice(&len_buf);
        full_buf.extend_from_slice(&body);
        
        let response_msg = VSockMessage::decode(&full_buf).map_err(|e| ClientError::Client(e))?;
        
        if response_msg.msg_type != MessageType::Data {
             return Err(ClientError::Client(EphemeralError::ProtocolError("Expected Data response".to_string())));
        }

        let encrypted_response: EncryptedMessage = serde_json::from_slice(&response_msg.payload)
            .map_err(|e| ClientError::Client(EphemeralError::SerializationError(e.to_string())))?;

        // 4. Decrypt Response
        let response_bytes = hpke.decrypt(&encrypted_response).map_err(|e| ClientError::Client(e))?;
        let output: InferenceHandlerOutput = serde_json::from_slice(&response_bytes)
            .map_err(|e| ClientError::Client(EphemeralError::SerializationError(e.to_string())))?;

        // 5. Verify Receipt
        let signing_pk = self.server_receipt_signing_key
            .ok_or_else(|| ClientError::Client(EphemeralError::ValidationError("Missing receipt signing key".to_string())))?;
        
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&signing_pk)
            .map_err(|e| ClientError::Client(EphemeralError::ValidationError(format!("Invalid receipt public key: {}", e))))?;
        
        if !output.receipt.verify_signature(&public_key).map_err(|e| ClientError::Client(e))? {
            return Err(ClientError::Client(EphemeralError::ValidationError("Invalid receipt signature".to_string())));
        }

        // Verify binding to attestation
        let attestation_doc_bytes = self.server_attestation_doc.as_ref().unwrap();
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(attestation_doc_bytes);
        let attestation_hash: [u8; 32] = hasher.finalize().into();

        if output.receipt.attestation_doc_hash != attestation_hash {
            return Err(ClientError::Client(EphemeralError::ValidationError("Receipt not bound to current attestation".to_string())));
        }

        Ok(output.output_tensor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use ephemeral_ml_common::{AttestationDocument, PcrMeasurements, EnclaveMeasurements, SecurityMode, ReceiptSigningKey};
    use sha2::{Sha256, Digest};

    #[tokio::test]
    async fn test_full_secure_inference_mock() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{}", port);

        tokio::spawn(async move {
            // Handle Hello Connection
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
            let client_hello: ClientHello = serde_json::from_slice(&msg.payload).unwrap();
            
            let pcr_val = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f").unwrap();
            let attestation = AttestationDocument {
                module_id: "mock".to_string(),
                digest: vec![0u8; 32],
                timestamp: 0,
                pcrs: PcrMeasurements::new(pcr_val.clone(), pcr_val.clone(), pcr_val),
                certificate: vec![],
                signature: vec![0u8; 64],
                nonce: Some(client_hello.client_nonce.to_vec()),
            };

            let mut hasher = Sha256::new();
            hasher.update(&attestation.signature);
            let attestation_hash: [u8; 32] = hasher.finalize().into();

            use x25519_dalek::{StaticSecret, PublicKey};
            let server_secret = StaticSecret::from([0u8; 32]);
            let server_public = PublicKey::from(&server_secret);
            let server_pub_key = server_public.to_bytes().to_vec();
            let server_pub_key_fixed = *server_public.as_bytes();

            // Generate real signature
            use ed25519_dalek::SigningKey;
            let signing_key = SigningKey::from_bytes(&[0u8; 32]);
            let verifying_key = signing_key.verifying_key();

            let server_hello = ServerHello {
                version: 1,
                chosen_features: vec!["gateway".to_string()],
                attestation_document: serde_json::to_vec(&attestation).unwrap(),
                ephemeral_public_key: server_pub_key,
                receipt_signing_key: verifying_key.to_bytes().to_vec(),
                timestamp: 0,
            };
            
            let resp_payload = serde_json::to_vec(&server_hello).unwrap();
            let resp_msg = VSockMessage::new(MessageType::Hello, 0, resp_payload).unwrap();
            socket.write_all(&resp_msg.encode()).await.unwrap();
            drop(socket);

            // Handle Data Connection
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.read_exact(&mut len_buf).await.unwrap();
            let total_len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; total_len];
            socket.read_exact(&mut body).await.unwrap();
            full_buf.clear();
            full_buf.extend_from_slice(&len_buf);
            full_buf.extend_from_slice(&body);
            let msg = VSockMessage::decode(&full_buf).unwrap();

            let encrypted_request: EncryptedMessage = serde_json::from_slice(&msg.payload).unwrap();
            
            let mut server_hpke = HPKESession::new(
                "session-id".to_string(),
                1,
                attestation_hash,
                server_pub_key_fixed,          // Local PK
                client_hello.ephemeral_public_key, // Peer PK
                client_hello.client_nonce,
                3600,
            ).unwrap();
            server_hpke.establish(server_secret.as_bytes()).unwrap();
            
            let req_plaintext = server_hpke.decrypt(&encrypted_request).unwrap();
            let input: InferenceHandlerInput = serde_json::from_slice(&req_plaintext).unwrap();
            
            // In the mock, we treat input_data as the tensor for the test
            let output_tensor: Vec<f32> = input.input_data.iter().map(|&x| (x as f32) + 0.1).collect();
            
            let attestation_doc_bytes = serde_json::to_vec(&attestation).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&attestation_doc_bytes);
            let attestation_doc_hash: [u8; 32] = hasher.finalize().into();

            let mut signed_receipt = AttestationReceipt::new(
                "receipt".to_string(), 1, SecurityMode::GatewayOnly,
                EnclaveMeasurements::new(vec![0x01; 48], vec![0x02; 48], vec![0x03; 48]),
                attestation_doc_hash, [0u8; 32], [0u8; 32], "v1".to_string(), 0, "model".to_string(), "v1".to_string(), 0, 0
            );
            
            signed_receipt.sign(&ReceiptSigningKey::from_parts(signing_key, verifying_key)).unwrap();

            let output = InferenceHandlerOutput {
                output_tensor,
                receipt: signed_receipt,
            };
            let resp_plaintext = serde_json::to_vec(&output).unwrap();
            let encrypted_response = server_hpke.encrypt(&resp_plaintext).unwrap();
            
            let resp_payload = serde_json::to_vec(&encrypted_response).unwrap();
            let resp_msg = VSockMessage::new(MessageType::Data, 1, resp_payload).unwrap();
            socket.write_all(&resp_msg.encode()).await.unwrap();
        });
        
        let mut client = SecureEnclaveClient::new("test-client".to_string());
        client.establish_channel(&addr).await.expect("Failed to establish channel");
        let input = vec![1.0, 2.0, 3.0];
        let result = client.execute_inference(&addr, "test-model", input.clone()).await.unwrap();
        assert!(result[0] > 1.0);
    }
}