use ephemeral_ml_common::{KmsRequest, KmsResponse};
use std::collections::HashMap;
use hpke::{aead::ChaCha20Poly1305, kem::X25519HkdfSha256, OpModeS, Serializable, Deserializable};
use rand::rngs::OsRng;
use rand::RngCore;

/// Mock KMS Proxy Server
pub struct KmsProxyServer {
    // Mock key storage
    keys: HashMap<String, Vec<u8>>,
}

impl KmsProxyServer {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub fn handle_request(&mut self, request: KmsRequest) -> KmsResponse {
        match request {
            KmsRequest::GenerateDataKey { key_id, key_spec: _ } => {
                let mut key = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut key);
                
                // Store key? For now, stateless mock.
                // self.keys.insert(key_id.clone(), key.to_vec());
                
                KmsResponse::GenerateDataKey {
                    key_id: key_id,
                    ciphertext_blob: key.to_vec(),
                    plaintext: key.to_vec(),
                }
            }
            KmsRequest::Decrypt { ciphertext_blob, recipient, .. } => {
                let key_material = ciphertext_blob;
                
                if let Some(attestation_bytes) = recipient {
                    match self.process_attestation(&attestation_bytes, &key_material) {
                        Ok(wrapped_key) => KmsResponse::Decrypt {
                            ciphertext_for_recipient: Some(wrapped_key),
                            plaintext: None,
                            key_id: None,
                        },
                        Err(e) => KmsResponse::Error(e),
                    }
                } else {
                    KmsResponse::Decrypt {
                        ciphertext_for_recipient: None,
                        plaintext: Some(key_material),
                        key_id: None,
                    }
                }
            }
        }
    }
    
    fn process_attestation(&self, attestation_bytes: &[u8], key_material: &[u8]) -> Result<Vec<u8>, String> {
        // Parse CBOR
        let value: serde_cbor::Value = serde_cbor::from_slice(attestation_bytes)
            .map_err(|e| format!("Failed to parse attestation doc: {}", e))?;
            
        let map = match value {
            serde_cbor::Value::Map(m) => m,
            _ => return Err("Attestation doc is not a map".to_string()),
        };
        
        // Validate PCRs (Mock Allowlist)
        if let Some(serde_cbor::Value::Map(pcrs)) = map.get(&serde_cbor::Value::Text("pcrs".to_string())) {
            // Check PCR0 existence and length as a basic check
            if let Some(serde_cbor::Value::Bytes(pcr0)) = pcrs.get(&serde_cbor::Value::Integer(0)) {
                if pcr0.len() != 48 {
                     return Err(format!("Invalid PCR0 length: {}", pcr0.len()));
                }
            }
        }
        
        // Extract User Data
        let user_data_bytes = match map.get(&serde_cbor::Value::Text("user_data".to_string())) {
             Some(serde_cbor::Value::Bytes(b)) => b,
             _ => return Err("Missing user_data in attestation".to_string()),
        };
        
        // Parse User Data (JSON)
        #[derive(serde::Deserialize)]
        struct UserData {
            hpke_public_key: [u8; 32],
        }
        
        let user_data: UserData = serde_json::from_slice(user_data_bytes)
            .map_err(|e| format!("Failed to parse user_data: {}", e))?;
            
        // Encrypt key_material with HPKE public key
        let mut rng = OsRng;
        
        let kem_pub = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&user_data.hpke_public_key)
            .map_err(|e| format!("Invalid HPKE public key: {}", e))?;
            
        let (encapped_key, mut sender_ctx) = hpke::setup_sender::<
            ChaCha20Poly1305,
            hpke::kdf::HkdfSha256,
            X25519HkdfSha256,
            _,
        >(&OpModeS::Base, &kem_pub, b"KMS_DEK", &mut rng)
        .map_err(|e| format!("HPKE setup failed: {}", e))?;
        
        let ciphertext = sender_ctx.seal(key_material, b"")
            .map_err(|e| format!("HPKE seal failed: {}", e))?;
            
        // Return: encapped_key || ciphertext
        let mut result = encapped_key.to_bytes().to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_ml_common::KmsRequest;

    #[test]
    fn test_host_blindness_enforced() {
        let mut server = KmsProxyServer::new();
        
        // Generate a valid HPKE public key
        use hpke::{kem::X25519HkdfSha256, Kem, Serializable};
        let (_, public_key_obj) = X25519HkdfSha256::derive_keypair(&[0u8; 32]);
        let pk_bytes = public_key_obj.to_bytes();

        // Setup a mock attestation with a dummy HPKE public key
        use std::collections::BTreeMap;
        let mut map = BTreeMap::new();
        
        // Create user data JSON with real PK bytes
        #[derive(serde::Serialize)]
        struct UserData {
            hpke_public_key: [u8; 32],
        }
        let user_data = UserData {
            hpke_public_key: pk_bytes.into(),
        };
        let user_data_json = serde_json::to_vec(&user_data).unwrap();

        map.insert(serde_cbor::Value::Text("user_data".to_string()), serde_cbor::Value::Bytes(user_data_json));
        
        let attestation_cbor = serde_cbor::to_vec(&serde_cbor::Value::Map(map)).unwrap();
        
        let request = KmsRequest::Decrypt {
            ciphertext_blob: vec![1, 2, 3, 4],
            key_id: None,
            encryption_context: None,
            grant_tokens: None,
            recipient: Some(attestation_cbor),
        };

        let response = server.handle_request(request);
        
        match response {
            KmsResponse::Decrypt { ciphertext_for_recipient, plaintext, .. } => {
                // MUST have ciphertext for recipient
                assert!(ciphertext_for_recipient.is_some());
                // MUST NOT have plaintext
                assert!(plaintext.is_none());
            }
            KmsResponse::Error(e) => panic!("KMS Error: {}", e),
            _ => panic!("Expected Decrypt response"),
        }
    }
}
