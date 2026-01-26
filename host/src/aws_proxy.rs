use crate::{HostError, Result, EphemeralError};
use serde::{Deserialize, Serialize};

/// KMS Request types that the Enclave can send
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", content = "payload")]
pub enum KmsRequest {
    /// Decrypt data using KMS
    Decrypt {
         ciphertext_blob: Vec<u8>,
         key_id: Option<String>,
         encryption_context: Option<std::collections::HashMap<String, String>>,
         grant_tokens: Option<Vec<String>>,
         recipient: Option<Vec<u8>>, // Attestation Document
    },
    /// Use this for other ops later
    GenerateDataKey {
        key_id: String,
        key_spec: String,
    }
}

/// KMS Response types
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", content = "result")]
pub enum KmsResponse {
    Success(Vec<u8>), // JSON serialized response
    Error(String),
}

/// AWS API Proxy
pub struct AwsApiProxy {
    /// Region
    pub region: String,
}

impl AwsApiProxy {
    pub fn new(region: String) -> Self {
        Self { region }
    }

    /// Handle a generic request based on raw bytes (assumed JSON)
    pub async fn handle_request(&self, request_data: &[u8]) -> Result<Vec<u8>> {
        // Parse request
        let request: KmsRequest = serde_json::from_slice(request_data)
            .map_err(|e| HostError::Host(EphemeralError::SerializationError(e.to_string())))?;

        let response = match request {
            KmsRequest::Decrypt { ciphertext_blob, key_id, encryption_context, grant_tokens, recipient } => {
                self.handle_decrypt(ciphertext_blob, key_id, encryption_context, grant_tokens, recipient).await
            },
            KmsRequest::GenerateDataKey { .. } => {
                 // Stub
                 Ok(KmsResponse::Error("Not implemented".to_string()))
            }
        };

        // Serialize response
        match response {
            Ok(resp) => serde_json::to_vec(&resp)
                .map_err(|e| HostError::Host(EphemeralError::SerializationError(e.to_string()))),
            Err(e) => {
                let error_resp = KmsResponse::Error(e.to_string());
                serde_json::to_vec(&error_resp)
                    .map_err(|e| HostError::Host(EphemeralError::SerializationError(e.to_string())))
            }
        }
    }

    async fn handle_decrypt(
        &self,
        ciphertext_blob: Vec<u8>,
        _key_id: Option<String>,
        _encryption_context: Option<std::collections::HashMap<String, String>>,
        _grant_tokens: Option<Vec<String>>,
        recipient: Option<Vec<u8>>,
    ) -> Result<KmsResponse> {
        // MOCK IMPLEMENTATION
        // In real implementation, this would use `aws_sdk_kms::Client`
        
        // For now, return a mock success response
        // In production, KMS Decrypt response contains Plaintext
        
        let plaintext_bytes = if recipient.is_some() {
             // If recipient is provided, the plaintext IS ENCRYPTED with the enclave's public key (HPKE)
             // Since we are mocking, we just return a "Ciphertext" that the client mock knows how to decrypt
             // For simplicity in mock, we reverse the input ciphertext and pretend that's the "encrypted key"
             ciphertext_blob.iter().rev().cloned().collect() 
        } else {
             // Standard decrypt (plaintext is actually plaintext)
             // Usually not allowed for this proxy in production for security
             b"MOCK_PLAINTEXT_BYTES_BASE64_ENCODED".to_vec()
        };
        
        // AWS KMS returns base64 string usually in JSON if using CLI, but SDK returns blob.
        // We will return JSON payload mimic
        use base64::{Engine as _, engine::general_purpose};
        let dummy_response = serde_json::json!({
            "KeyId": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            "Plaintext": general_purpose::STANDARD.encode(plaintext_bytes),
             "CiphertextBlob": if recipient.is_some() { "some_encrypted_blob" } else { "null" }
        });
        
        Ok(KmsResponse::Success(serde_json::to_vec(&dummy_response).unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_decrypt_request() {
        let proxy = AwsApiProxy::new("us-east-1".to_string());
        
        // Create a fake decrypt request
        let request = KmsRequest::Decrypt {
            ciphertext_blob: vec![1, 2, 3],
            key_id: Some("key-1".to_string()),
            encryption_context: None,
            grant_tokens: None,
            recipient: None,
        };
        
        let request_bytes = serde_json::to_vec(&request).unwrap();
        
        // Handle it
        let response_bytes = proxy.handle_request(&request_bytes).await.unwrap();
        
        // Parse response
        let response: KmsResponse = serde_json::from_slice(&response_bytes).unwrap();
        
        match response {
            KmsResponse::Success(payload) => {
                let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                let plaintext_b64 = json["Plaintext"].as_str().unwrap();
                use base64::{Engine as _, engine::general_purpose};
                let plaintext_bytes = general_purpose::STANDARD.decode(plaintext_b64).unwrap();
                assert_eq!(String::from_utf8(plaintext_bytes).unwrap(), "MOCK_PLAINTEXT_BYTES_BASE64_ENCODED");
            },
            _ => panic!("Expected success"),
        }
    }
}
