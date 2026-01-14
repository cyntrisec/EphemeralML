use crate::{EnclaveError, Result, EphemeralError};
use serde::{Deserialize, Serialize};

/// KMS Request types (matching Host definition)
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", content = "payload")]
pub enum KmsRequest {
    Decrypt {
         ciphertext_blob: Vec<u8>,
         key_id: Option<String>,
         encryption_context: Option<std::collections::HashMap<String, String>>,
         grant_tokens: Option<Vec<String>>,
         recipient: Option<Vec<u8>>,
    },
    GenerateDataKey {
        key_id: String,
        key_spec: String,
    }
}

/// KMS Stub Client for Enclave
pub struct KmsClient<A: crate::attestation::AttestationProvider> {
    attestation_provider: A,
}

impl<A: crate::attestation::AttestationProvider> KmsClient<A> {
    pub fn new(attestation_provider: A) -> Self {
         Self { attestation_provider }
    }

    /// Request decryption of a ciphertext using attestation binding
    pub async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // 1. Generate attestation document (nonce usually comes from KMS challenge, but for static decrypt we generate one)
        // In real flow, we might need a fresh nonce. For DEK decrypt, the nonce is less critical than the public key binding.
        // We use a zero nonce or random one for now as the goal is to get the Public Key into the document.
        let nonce = [0u8; 16]; 
        let attestation_doc = self.attestation_provider.generate_attestation(&nonce)?;
        
        let recipient_bytes = attestation_doc.signature; // In our impl, signature holds the CBOR bytes

        // 2. Construct request
        let request = KmsRequest::Decrypt {
            ciphertext_blob: ciphertext.to_vec(),
            key_id: None,
            encryption_context: None,
            grant_tokens: None,
            recipient: Some(recipient_bytes),
        };

        // 3. Serialize
        let _request_bytes = serde_json::to_vec(&request)
            .map_err(|e| EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string())))?;

        // MOCK: In production, send over VSock and await response
        // In our Host Mock, if recipient is set, it reverses the ciphertext bytes
        // In a real scenario, this response would be HPKE encrypted
        
        // 4. Decrypt response
        // Since we are mocking, we just assume the response body is the "plaintext" which is actually "encrypted key"
        // And our mock just reverses it directly.
        // In real logic:
        // let response_payload = vsock_send(request_bytes).await?;
        // let hpke_ciphertext = response_payload.ciphertext;
        // let dek = self.attestation_provider.decrypt_hpke(hpke_ciphertext)?;
        
        // Simulating the reversal done by Host Mock:
        let deferred_mock_kms_response: Vec<u8> = ciphertext.iter().rev().cloned().collect();
        
        // Validating that we could indeed perform HPKE if we had real data
        let _my_pub_key = self.attestation_provider.get_hpke_public_key();
        
        Ok(deferred_mock_kms_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_decrypt() {
        let provider = crate::attestation::DefaultAttestationProvider::new().unwrap();
        let client = KmsClient::new(provider);
        let ciphertext = vec![1, 2, 3, 4];
        let plaintext = client.decrypt(&ciphertext).await.unwrap();
        
        // Our mock reverses the input
        assert_eq!(plaintext, vec![4, 3, 2, 1]);
    }

    #[test]
    fn test_request_serialization() {
        let req = KmsRequest::Decrypt {
            ciphertext_blob: vec![10, 20],
            key_id: Some("key-id".to_string()),
            encryption_context: None,
            grant_tokens: None,
            recipient: Some(vec![1, 2, 3]),
        };
        
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("Decrypt"));
        assert!(json.contains("payload"));
        assert!(json.contains("recipient"));
    }
}
