use crate::{EphemeralError, HostError, Result};
use aws_config::SdkConfig;
use aws_sdk_kms::Client as KmsClient;
use ephemeral_ml_common::KmsResponse;

/// AWS API Proxy
#[derive(Clone)]
pub struct AWSApiProxy {
    client: KmsClient,
}

impl AWSApiProxy {
    pub fn new(config: &SdkConfig) -> Self {
        Self {
            client: KmsClient::new(config),
        }
    }

    pub async fn decrypt(
        &self,
        ciphertext_blob: Vec<u8>,
        key_id: Option<String>,
        encryption_context: Option<std::collections::HashMap<String, String>>,
        grant_tokens: Option<Vec<String>>,
        recipient: Option<Vec<u8>>,
    ) -> Result<KmsResponse> {
        let mut builder = self
            .client
            .decrypt()
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext_blob))
            .encryption_algorithm(aws_sdk_kms::types::EncryptionAlgorithmSpec::SymmetricDefault);

        if let Some(kid) = key_id {
            builder = builder.key_id(kid);
        }

        if let Some(ctx) = encryption_context {
            for (k, v) in ctx {
                builder = builder.encryption_context(k, v);
            }
        }

        if let Some(tokens) = grant_tokens {
            for token in tokens {
                builder = builder.grant_tokens(token);
            }
        }

        if let Some(attestation_doc) = recipient {
            builder = builder.recipient(
                aws_sdk_kms::types::RecipientInfo::builder()
                    .key_encryption_algorithm(
                        aws_sdk_kms::types::KeyEncryptionMechanism::RsaesOaepSha256,
                    )
                    .attestation_document(aws_sdk_kms::primitives::Blob::new(attestation_doc))
                    .build(),
            );
        }

        let resp = builder.send().await.map_err(|e| {
            HostError::Host(EphemeralError::Internal(format!(
                "KMS Decrypt failed: {}",
                e
            )))
        })?;

        Ok(KmsResponse::Decrypt {
            plaintext: resp.plaintext().map(|b| b.as_ref().to_vec()),
            key_id: resp.key_id().map(|s| s.to_string()),
            ciphertext_for_recipient: resp.ciphertext_for_recipient().map(|b| b.as_ref().to_vec()),
        })
    }

    pub async fn generate_data_key(
        &self,
        key_id: String,
        key_spec: String,
        _encryption_context: Option<std::collections::HashMap<String, String>>,
        _grant_tokens: Option<Vec<String>>,
        _recipient: Option<Vec<u8>>,
    ) -> Result<KmsResponse> {
        let ks = match key_spec.as_str() {
            "AES_256" => aws_sdk_kms::types::DataKeySpec::Aes256,
            "AES_128" => aws_sdk_kms::types::DataKeySpec::Aes128,
            _ => aws_sdk_kms::types::DataKeySpec::Aes256,
        };

        let resp = self
            .client
            .generate_data_key()
            .key_id(key_id)
            .key_spec(ks)
            .send()
            .await
            .map_err(|e| {
                HostError::Host(EphemeralError::Internal(format!(
                    "KMS GenerateDataKey failed: {}",
                    e
                )))
            })?;

        Ok(KmsResponse::GenerateDataKey {
            key_id: resp.key_id().unwrap_or_default().to_string(),
            ciphertext_blob: resp
                .ciphertext_blob()
                .map(|b| b.as_ref().to_vec())
                .unwrap_or_default(),
            plaintext: resp
                .plaintext()
                .map(|b| b.as_ref().to_vec())
                .unwrap_or_default(),
        })
    }
}
