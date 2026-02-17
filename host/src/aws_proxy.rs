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

        let ciphertext_for_recipient = resp.ciphertext_for_recipient().map(|b| b.as_ref().to_vec());

        // A1: When recipient encryption was requested, ciphertext_for_recipient MUST
        // be present. If KMS silently drops it, the key material is unrecoverable.
        if has_recipient && ciphertext_for_recipient.is_none() {
            return Err(HostError::Host(EphemeralError::KmsError(
                "KMS Decrypt: recipient was provided but ciphertext_for_recipient is missing \
                 from response — key material is unrecoverable"
                    .to_string(),
            )));
        }

        Ok((
            KmsResponse::Decrypt {
                plaintext,
                key_id: resp.key_id().map(|s| s.to_string()),
                ciphertext_for_recipient,
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

        // A2: Reject empty/missing key_id and ciphertext_blob — these indicate a
        // malformed KMS response and must not be silently swallowed.
        let key_id = resp
            .key_id()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                HostError::Host(EphemeralError::KmsError(
                    "KMS GenerateDataKey: response missing key_id".to_string(),
                ))
            })?;

        let ciphertext_blob = resp
            .ciphertext_blob()
            .map(|b| b.as_ref().to_vec())
            .filter(|b| !b.is_empty())
            .ok_or_else(|| {
                HostError::Host(EphemeralError::KmsError(
                    "KMS GenerateDataKey: response missing ciphertext_blob".to_string(),
                ))
            })?;

        let ciphertext_for_recipient = resp.ciphertext_for_recipient().map(|b| b.as_ref().to_vec());

        // A1: When recipient encryption was requested, ciphertext_for_recipient MUST
        // be present. If KMS silently drops it, the key material is unrecoverable.
        if has_recipient && ciphertext_for_recipient.is_none() {
            return Err(HostError::Host(EphemeralError::KmsError(
                "KMS GenerateDataKey: recipient was provided but ciphertext_for_recipient \
                 is missing from response — key material is unrecoverable"
                    .to_string(),
            )));
        }

        // A3: Validate plaintext key size when available (non-recipient mode).
        if let Some(ref pt) = plaintext {
            let expected_len = match key_spec.as_str() {
                "AES_128" => 16,
                _ => 32, // AES_256 default
            };
            if pt.len() != expected_len {
                return Err(HostError::Host(EphemeralError::KmsError(format!(
                    "KMS GenerateDataKey: plaintext key size {} bytes, expected {} for {}",
                    pt.len(),
                    expected_len,
                    key_spec
                ))));
            }
        }

        Ok((
            KmsResponse::GenerateDataKey {
                key_id,
                ciphertext_blob,
                plaintext,
                ciphertext_for_recipient,
            },
            aws_req_id,
        ))
    }
}
