use crate::{EphemeralError, HostError, Result};
use aws_config::SdkConfig;
use aws_sdk_kms::Client as KmsClient;
use ephemeral_ml_common::KmsResponse;

/// Extract a meaningful error string from an AWS SDK error, preserving the
/// service error code (e.g. `AccessDeniedException`) so that downstream
/// classification via `classify_aws_error()` works correctly.
/// Extract a meaningful error string from an AWS SDK error, preserving the
/// service error code (e.g. `AccessDeniedException`) so that downstream
/// classification via `classify_aws_error()` works correctly.
fn format_sdk_error<E: std::fmt::Debug, R: std::fmt::Debug>(
    err: &aws_sdk_kms::error::SdkError<E, R>,
) -> String {
    match err {
        aws_sdk_kms::error::SdkError::ServiceError(ctx) => {
            // Debug format includes the error variant name (e.g. AccessDeniedException)
            format!("{:?}", ctx.err())
        }
        other => format!("{}", other),
    }
}

/// Extract the AWS request ID from a successful SDK response.
fn extract_request_id(resp: &impl aws_types::request_id::RequestId) -> Option<String> {
    resp.request_id().map(|s| s.to_string())
}

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

    /// Decrypt via KMS. Returns `(KmsResponse, Option<aws_request_id>)`.
    pub async fn decrypt(
        &self,
        ciphertext_blob: Vec<u8>,
        key_id: Option<String>,
        encryption_context: Option<std::collections::HashMap<String, String>>,
        grant_tokens: Option<Vec<String>>,
        recipient: Option<Vec<u8>>,
    ) -> Result<(KmsResponse, Option<String>)> {
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

        let has_recipient = recipient.is_some();
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
            let error_detail = format_sdk_error(&e);
            HostError::Host(EphemeralError::Internal(format!(
                "KMS Decrypt failed: {}",
                error_detail
            )))
        })?;

        let aws_req_id = extract_request_id(&resp);

        // When recipient-based encryption is used, plaintext MUST NOT be returned
        // to the host — only ciphertext_for_recipient (encrypted to the enclave's
        // RSA key from the attestation document). Suppress plaintext as defense-in-depth.
        let plaintext = if has_recipient {
            None
        } else {
            resp.plaintext().map(|b| b.as_ref().to_vec())
        };

        Ok((
            KmsResponse::Decrypt {
                plaintext,
                key_id: resp.key_id().map(|s| s.to_string()),
                ciphertext_for_recipient: resp
                    .ciphertext_for_recipient()
                    .map(|b| b.as_ref().to_vec()),
            },
            aws_req_id,
        ))
    }

    /// Generate a data key via KMS. Returns `(KmsResponse, Option<aws_request_id>)`.
    pub async fn generate_data_key(
        &self,
        key_id: String,
        key_spec: String,
        encryption_context: Option<std::collections::HashMap<String, String>>,
        _grant_tokens: Option<Vec<String>>,
        recipient: Option<Vec<u8>>,
    ) -> Result<(KmsResponse, Option<String>)> {
        let ks = match key_spec.as_str() {
            "AES_256" => aws_sdk_kms::types::DataKeySpec::Aes256,
            "AES_128" => aws_sdk_kms::types::DataKeySpec::Aes128,
            _ => aws_sdk_kms::types::DataKeySpec::Aes256,
        };

        let mut builder = self.client.generate_data_key().key_id(key_id).key_spec(ks);

        if let Some(ctx) = encryption_context {
            for (k, v) in ctx {
                builder = builder.encryption_context(k, v);
            }
        }

        let has_recipient = recipient.is_some();
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
            let error_detail = format_sdk_error(&e);
            HostError::Host(EphemeralError::Internal(format!(
                "KMS GenerateDataKey failed: {}",
                error_detail
            )))
        })?;

        let aws_req_id = extract_request_id(&resp);

        // Suppress plaintext when recipient was provided —
        // even if KMS unexpectedly returns it.
        let plaintext = if has_recipient {
            None
        } else {
            resp.plaintext().map(|b| b.as_ref().to_vec())
        };

        Ok((
            KmsResponse::GenerateDataKey {
                key_id: resp.key_id().unwrap_or_default().to_string(),
                ciphertext_blob: resp
                    .ciphertext_blob()
                    .map(|b| b.as_ref().to_vec())
                    .unwrap_or_default(),
                plaintext,
                ciphertext_for_recipient: resp
                    .ciphertext_for_recipient()
                    .map(|b| b.as_ref().to_vec()),
            },
            aws_req_id,
        ))
    }
}
