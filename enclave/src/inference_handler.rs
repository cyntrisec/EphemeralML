use crate::{EnclaveError, Result, EphemeralError, AttestationProvider, InferenceEngine};
use crate::session_manager::SessionManager;
use crate::receipt::ReceiptBuilder;
use ephemeral_ml_common::{EncryptedMessage, AttestationReceipt};
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

#[derive(Clone)]
pub struct InferenceHandler<A: AttestationProvider, I: InferenceEngine> {
    pub session_manager: SessionManager,
    pub attestation_provider: A,
    pub inference_engine: I,
}

impl<A: AttestationProvider, I: InferenceEngine> InferenceHandler<A, I> {
    pub fn new(
        session_manager: SessionManager,
        attestation_provider: A,
        inference_engine: I,
    ) -> Self {
        Self {
            session_manager,
            attestation_provider,
            inference_engine,
        }
    }

    pub fn handle_request(
        &self,
        encrypted_request: &EncryptedMessage,
    ) -> Result<EncryptedMessage> {
        let session_id = &encrypted_request.session_id;

        self.session_manager.with_session(session_id, |session| {
            // 1. Decrypt Request
            let plaintext = session.decrypt(encrypted_request)?;
            
            // 2. Parse Input
            let input: InferenceHandlerInput = serde_json::from_slice(&plaintext)
                .map_err(|e| EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string())))?;

            // 3. Execute Inference (Mock or Real)
            // For now, we construct a dummy CandleModel reference or similar
            // In real impl, we'd load the model from storage/memory using model_id
            use crate::assembly::{CandleModel, TopologyKey};
            let dummy_model = CandleModel {
                id: input.model_id.clone(),
                topology: TopologyKey { // Minimal dummy topology
                    graph_id: "dummy".to_string(),
                    nodes: vec![],
                    edges: vec![],
                    input_shapes: vec![],
                    output_shapes: vec![],
                    metadata: ephemeral_ml_common::ModelMetadata {
                        name: "dummy".to_string(),
                        version: "v1".to_string(),
                        description: None,
                        created_at: 0,
                        checksum: "dummy".to_string(),
                    }
                },
                weights: vec![0.5],
            };

            let start_time = std::time::Instant::now();
            let output_tensor = self.inference_engine.execute(&dummy_model, &input.input_data)?;
            let duration = start_time.elapsed().as_millis() as u64;

            // 4. Generate Receipt
            // We need to serialize response payload *without* the receipt to include in the receipt hash?
            // Usually receipt covers the request and the data response.
            // But the receipt is part of the response structure.
            // Circular dependency if receipt includes hash of response which includes receipt.
            // Solution: Receipt includes hash of `output_tensor` (the actual result), not the container.
            
            let output_bytes = serde_json::to_vec(&output_tensor)
                .map_err(|e| EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string())))?;

            let mut receipt = ReceiptBuilder::build(
                session,
                &self.attestation_provider,
                &plaintext,
                &output_bytes,
                input.model_id,
                "v1.0".to_string(),
                duration,
                0, // Memory peak placeholder
            )?;

            // 5. Sign Receipt
            session.sign_receipt(&mut receipt)?;

            // 6. Construct Response
            let response = InferenceHandlerOutput {
                output_tensor,
                receipt,
            };

            let response_bytes = serde_json::to_vec(&response)
                .map_err(|e| EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string())))?;

            // 7. Encrypt Response
            session.encrypt(&response_bytes)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::DefaultAttestationProvider;
    use crate::inference::DefaultInferenceEngine;
    use ephemeral_ml_common::{HPKESession, ReceiptSigningKey};
    
    #[test]
    fn test_inference_lifecycle() {
        use crate::session_manager::EnclaveSession;
        // Setup components
        let provider = DefaultAttestationProvider::new().unwrap();
        let _engine = DefaultInferenceEngine; // Note: Default implementation returns Error currently
        
        // Use MockInferenceEngine for success path
        struct MockInferenceEngine;
        impl InferenceEngine for MockInferenceEngine {
            fn execute(&self, _model: &crate::assembly::CandleModel, input: &[u8]) -> Result<Vec<f32>> {
                Ok(input.iter().map(|&x| x as f32 * 2.0).collect())
            }
            fn validate_input(&self, _model: &crate::assembly::CandleModel, _input: &[u8]) -> Result<()> {
                Ok(())
            }
        }
        
        let session_manager = SessionManager::new(10);
        let handler = InferenceHandler::new(session_manager.clone(), provider, MockInferenceEngine);
        
        // Create Session
        let session_id = "test-session".to_string();
        let hpke = HPKESession::new(
            session_id.clone(),
            1,
            [1u8; 32],
            [2u8; 32], // local
            [2u8; 32], // peer
            [3u8; 12],
            3600
        ).unwrap();
        // Manually establish for test
        let mut established_hpke = hpke;
        // Hack: we need to establish it to encrypt/decrypt.
        // In real flow, client and enclave do exchange.
        // Here we just want to test the handler logic given an established session.
        // We can't easily reach into HPKE session to set keys without establishment.
        // So we simulate establishment.
        let enclave_private = [4u8; 32]; // Mock enclave private
        established_hpke.establish(&enclave_private).unwrap();
        
        let receipt_key = ReceiptSigningKey::generate().unwrap();
        let session = EnclaveSession::new(
            session_id.clone(),
            established_hpke,
            receipt_key,
            [0u8; 32],
            "client".to_string(),
        );
        session_manager.add_session(session).unwrap();
        
        // Prepare Request
        let input = InferenceHandlerInput {
            model_id: "test-model".to_string(),
            input_data: vec![1, 2, 3],
            input_shape: Some(vec![3]),
        };
        let input_bytes = serde_json::to_vec(&input).unwrap();
        
        // Encrypt Request (simulate client)
        let mut _client_hpke = HPKESession::new(
            session_id.clone(),
            1,
            [1u8; 32],
            [2u8; 32], // Local pub
            [2u8; 32], // Enclave pub
            [3u8; 12], // Client nonce
            3600
        ).unwrap();
        // Client derives SAME session key if inputs match.
        // BUT `derive_session_key` uses `enclave_private_key`.
        // Client uses `enclave_public_key` and `client_private_key`.
        // Our HPKESession implementation in `common` currently simulates "Establish" with `enclave_private_key`.
        // It doesn't fully implement the Client-side KEM (Encap) logic yet in `HPKESession` struct itself?
        // Let's check `common/src/hpke_session.rs`.
        // `derive_session_key` takes `enclave_private_key`. 
        // This suggests `HPKESession` as written is server-side oriented or symmetric for mock.
        // For this test, we can just use the SAME session object (cloned? No, it has state).
        // We'll create another session and "establish" it with the SAME key to simulate client having same key.
        let mut client_session = HPKESession::new(
            session_id.clone(),
            1,
            [1u8; 32],
            [2u8; 32],
            [2u8; 32],
            [3u8; 12],
            3600
        ).unwrap();
        client_session.establish(&enclave_private).unwrap();
        
        let encrypted_request = client_session.encrypt(&input_bytes).unwrap();
        
        // Handle Request
        let encrypted_response = handler.handle_request(&encrypted_request).unwrap();
        
        // Decrypt Response (simulate client)
        // Note: client_session state (sequence number) needs to match
        // The handler decrypts request (seq 0 -> 1).
        // The handler encrypts response (seq 0 -> 1).
        // Client sent request (seq 0 -> 1).
        // Client receives response.
        // `client_session` next_sequence_number is 1 (after encrypt).
        // `client_session` next_incoming_sequence is 0.
        // The response will have sequence number 0 (from EnclaveSession which is fresh).
        // Wait, `EnclaveSession` was created fresh. `hpke` seq is 0.
        // Handler decrypts request (seq 0). EnclaveSession incoming seq 0 -> 1.
        // Handler encrypts response (seq 0). EnclaveSession outgoing seq 0 -> 1.
        // Client expects incoming seq 0.
        
        let response_bytes = client_session.decrypt(&encrypted_response).unwrap();
        let response: InferenceHandlerOutput = serde_json::from_slice(&response_bytes).unwrap();
        
        assert_eq!(response.output_tensor, vec![2.0, 4.0, 6.0]);
        assert_eq!(response.receipt.model_id, "test-model");
        assert!(response.receipt.signature.is_some());
    }
}
