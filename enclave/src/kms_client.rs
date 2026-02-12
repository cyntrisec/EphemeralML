use crate::kms_proxy_client::KmsProxyClient;
use crate::{EnclaveError, EphemeralError, Result};
use ephemeral_ml_common::{KmsProxyErrorCode, KmsRequest, KmsResponse};
use std::collections::HashMap;

/// KMS Stub Client for Enclave
pub struct KmsClient<A: crate::attestation::AttestationProvider> {
    attestation_provider: A,
    proxy_client: KmsProxyClient,
    /// Receipt signing public key embedded in attestation user_data for KMS binding.
    /// Must be set to the actual session receipt key, not a placeholder.
    receipt_signing_pubkey: [u8; 32],
}

impl<A: crate::attestation::AttestationProvider> KmsClient<A> {
    pub fn new(attestation_provider: A, receipt_signing_pubkey: [u8; 32]) -> Self {
        assert!(
            receipt_signing_pubkey.iter().any(|&b| b != 0),
            "KmsClient receipt_signing_pubkey must not be all zeros"
        );
        Self {
            attestation_provider,
            proxy_client: KmsProxyClient::new(),
            receipt_signing_pubkey,
        }
    }

    pub fn new_with_proxy(
        attestation_provider: A,
        proxy_client: KmsProxyClient,
        receipt_signing_pubkey: [u8; 32],
    ) -> Self {
        Self {
            attestation_provider,
            proxy_client,
            receipt_signing_pubkey,
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
    ///
    /// `encryption_context` binds the decrypt call to a specific model/tenant,
    /// preventing ciphertext replay across different KMS encryption contexts.
    pub async fn decrypt(
        &self,
        ciphertext: &[u8],
        encryption_context: Option<HashMap<String, String>>,
    ) -> Result<Vec<u8>> {
        // 1. Generate attestation document with random nonce and receipt signing key binding
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let attestation_doc = self
            .attestation_provider
            .generate_attestation(&nonce, self.receipt_signing_pubkey)?;

        let recipient_bytes = attestation_doc.signature; // In our impl, signature holds the CBOR bytes

        // 2. Construct request
        let request = KmsRequest::Decrypt {
            ciphertext_blob: ciphertext.to_vec(),
            key_id: None,
            encryption_context,
            grant_tokens: None,
            recipient: Some(recipient_bytes),
        };

        // 3. Send via Proxy
        let response = self.proxy_client.send_request(request).await?;

        // 4. Handle response
        match response.response {
            KmsResponse::Decrypt {
                ciphertext_for_recipient,
                plaintext,
                ..
            } => {
                if let Some(enc_key) = ciphertext_for_recipient {
                    // Decrypt using our RSA private key (RecipientInfo flow)
                    self.attestation_provider.decrypt_kms(&enc_key)
                } else if plaintext.is_some() {
                    // Fail-closed: if we asked for Recipient-bound decrypt, plaintext must never be returned.
                    Err(EnclaveError::Enclave(EphemeralError::KmsError(
                        "KMS proxy returned plaintext for Recipient-bound decrypt".to_string(),
                    )))
                } else {
                    Err(EnclaveError::Enclave(EphemeralError::KmsError(
                        "No key returned in response".to_string(),
                    )))
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
            _ => Err(EnclaveError::Enclave(EphemeralError::KmsError(
                "Unexpected response type".to_string(),
            ))),
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
            encryption_context: Some(HashMap::from([
                ("model_id".to_string(), "test-model".to_string()),
                ("version".to_string(), "v1".to_string()),
            ])),
            grant_tokens: None,
            recipient: Some(vec![1, 2, 3]),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("Decrypt"));
        assert!(json.contains("payload"));
        assert!(json.contains("recipient"));
        assert!(json.contains("model_id"));
    }
}
