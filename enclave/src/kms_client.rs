use crate::{EnclaveError, Result, EphemeralError};
use crate::kms_proxy_client::KmsProxyClient;
use ephemeral_ml_common::{KmsProxyErrorCode, KmsRequest, KmsResponse};

/// KMS Stub Client for Enclave
pub struct KmsClient<A: crate::attestation::AttestationProvider> {
    attestation_provider: A,
    proxy_client: KmsProxyClient,
}

impl<A: crate::attestation::AttestationProvider> KmsClient<A> {
    pub fn new(attestation_provider: A) -> Self {
         Self { 
             attestation_provider,
             proxy_client: KmsProxyClient::new(),
         }
    }

    pub fn new_with_proxy(attestation_provider: A, proxy_client: KmsProxyClient) -> Self {
        Self {
            attestation_provider,
            proxy_client,
        }
    }

    /// Mock decryption for benchmarking
    pub async fn decrypt_mock(&self, _ciphertext: &[u8], fixed_key: [u8; 32]) -> Result<Vec<u8>> {
        Ok(fixed_key.to_vec())
    }

    pub fn proxy_client(&self) -> &KmsProxyClient {
        &self.proxy_client
    }

    /// Request decryption of a ciphertext using attestation binding
    pub async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // 1. Generate attestation document
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

        // 3. Send via Proxy
        let response = self.proxy_client.send_request(request).await?;
        
        // 4. Handle response
        match response.response {
            KmsResponse::Decrypt { ciphertext_for_recipient, plaintext, .. } => {
                if let Some(enc_key) = ciphertext_for_recipient {
                    // Decrypt using our RSA private key (RecipientInfo flow)
                    self.attestation_provider.decrypt_kms(&enc_key)
                } else if plaintext.is_some() {
                    // Fail-closed: if we asked for Recipient-bound decrypt, plaintext must never be returned.
                    Err(EnclaveError::Enclave(EphemeralError::KmsError(
                        "KMS proxy returned plaintext for Recipient-bound decrypt".to_string(),
                    )))
                } else {
                    Err(EnclaveError::Enclave(EphemeralError::KmsError("No key returned in response".to_string())))
                }
            }
            KmsResponse::Error { code, message } => {
                let prefix = match code {
                    KmsProxyErrorCode::Timeout => "kms_proxy_timeout",
                    KmsProxyErrorCode::InvalidRequest => "kms_proxy_invalid_request",
                    KmsProxyErrorCode::UpstreamAccessDenied => "kms_proxy_access_denied",
                    KmsProxyErrorCode::UpstreamThrottled => "kms_proxy_throttled",
                    KmsProxyErrorCode::UpstreamUnavailable => "kms_proxy_unavailable",
                    KmsProxyErrorCode::Internal => "kms_proxy_internal",
                };
                Err(EnclaveError::Enclave(EphemeralError::KmsError(format!(
                    "{}: {}",
                    prefix, message
                ))))
            }
            _ => Err(EnclaveError::Enclave(EphemeralError::KmsError("Unexpected response type".to_string()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
