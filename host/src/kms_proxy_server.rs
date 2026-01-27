use crate::circuit_breaker::{CircuitBreaker, Config as CircuitConfig};
use crate::limits::{ConcurrencyLimiter, DEFAULT_MAX_IN_FLIGHT};
use crate::rate_limit::{Config as RateLimitConfig, RateLimiter};
use crate::retry::RetryPolicy;
use ephemeral_ml_common::{
    KmsProxyErrorCode, KmsProxyRequestEnvelope, KmsProxyResponseEnvelope, KmsRequest, KmsResponse,
};
use hpke::{aead::ChaCha20Poly1305, kem::X25519HkdfSha256, Deserializable, OpModeS, Serializable};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use std::time::Instant;
use tokio::time::{sleep, timeout, Duration};

#[cfg(feature = "production")]
use aws_sdk_kms::Client;

/// KMS Proxy Server
pub struct KmsProxyServer {
    // Mock key storage
    _keys: HashMap<String, Vec<u8>>,
    retry: RetryPolicy,
    limiter: ConcurrencyLimiter,
    rate_limiter: RateLimiter,
    circuit: CircuitBreaker,
    #[cfg(feature = "production")]
    kms_client: Option<Client>,
}

impl Clone for KmsProxyServer {
    fn clone(&self) -> Self {
        Self {
            _keys: self._keys.clone(),
            retry: self.retry,
            limiter: self.limiter.clone(),
            rate_limiter: self.rate_limiter.clone(),
            circuit: self.circuit.clone(),
            #[cfg(feature = "production")]
            kms_client: self.kms_client.clone(),
        }
    }
}

impl KmsProxyServer {
    pub fn new() -> Self {
        Self {
            _keys: HashMap::new(),
            retry: RetryPolicy::default(),
            limiter: ConcurrencyLimiter::new(DEFAULT_MAX_IN_FLIGHT),
            rate_limiter: RateLimiter::new(RateLimitConfig::default()),
            circuit: CircuitBreaker::new(CircuitConfig::default()),
            #[cfg(feature = "production")]
            kms_client: None,
        }
    }

    #[cfg(feature = "production")]
    pub fn with_kms_client(mut self, client: aws_sdk_kms::Client) -> Self {
        self.kms_client = Some(client);
        self
    }

    pub async fn handle_envelope(&mut self, env: KmsProxyRequestEnvelope) -> KmsProxyResponseEnvelope {
        let request_id = env.request_id;
        let trace_id = env.trace_id;

        // Hard deadline (end-to-end budget) for the whole operation.
        let deadline = Duration::from_millis(800);
        let started = Instant::now();

        let (response, kms_request_id) = self.handle_request_with_deadline(env.request, started, deadline).await;

        KmsProxyResponseEnvelope {
            request_id,
            trace_id,
            kms_request_id,
            response,
        }
    }

    async fn handle_request_with_deadline(
        &mut self,
        request: KmsRequest,
        started: Instant,
        deadline: Duration,
    ) -> (KmsResponse, Option<String>) {
        match request {
            KmsRequest::GenerateDataKey { key_id, key_spec } => {
                // If we have a real KMS client, use it.
                #[cfg(feature = "production")]
                if let Some(client) = &self.kms_client {
                    // Circuit breaker + caps for upstream KMS calls.
                    self.circuit.before_request().await;
                    let _permit = self.limiter.acquire().await;
                    self.rate_limiter.acquire(1.0).await;
                    let mut rng = rand::thread_rng();

                    for attempt in 1..=self.retry.max_attempts {
                        let elapsed = started.elapsed();
                        if elapsed >= deadline {
                            return (
                                KmsResponse::Error {
                                    code: KmsProxyErrorCode::Timeout,
                                    message: "Operation timed out".to_string(),
                                },
                                None,
                            );
                        }

                        let remaining = deadline - elapsed;
                        // Per-attempt timeout budget (v1 defaults).
                        let per_attempt = if attempt == 1 {
                            Duration::from_millis(250)
                        } else {
                            Duration::from_millis(300)
                        }
                        .min(remaining);

                        // Build request fresh each attempt.
                        let ks_norm = key_spec.trim().to_ascii_uppercase();
                        let mut builder = client.generate_data_key().key_id(key_id.clone());
                        builder = match ks_norm.as_str() {
                            "AES_256" | "AES256" => builder.key_spec(aws_sdk_kms::types::DataKeySpec::Aes256),
                            "AES_128" | "AES128" => builder.key_spec(aws_sdk_kms::types::DataKeySpec::Aes128),
                            _ => builder.number_of_bytes(32),
                        };

                        match timeout(per_attempt, builder.send()).await {
                            Ok(Ok(output)) => {
                                self.circuit.record_result(true).await;
                                let kms_request_id = aws_request_id(&output);
                                return (
                                    KmsResponse::GenerateDataKey {
                                        key_id: output.key_id().unwrap_or(&key_id).to_string(),
                                        ciphertext_blob: output
                                            .ciphertext_blob()
                                            .map(|b| b.as_ref().to_vec())
                                            .unwrap_or_default(),
                                        plaintext: output
                                            .plaintext()
                                            .map(|b| b.as_ref().to_vec())
                                            .unwrap_or_default(),
                                    },
                                    kms_request_id,
                                );
                            }
                            Ok(Err(e)) => {
                                self.circuit.record_result(false).await;
                                let code = classify_aws_error(&format!("{e:?}"));
                                if !is_retryable(code) || attempt == self.retry.max_attempts {
                                    return (
                                        KmsResponse::Error {
                                            code,
                                            message: "Upstream KMS error".to_string(),
                                        },
                                        None,
                                    );
                                }
                            }
                            Err(_) => {
                                self.circuit.record_result(false).await;
                                if attempt == self.retry.max_attempts {
                                    return (
                                        KmsResponse::Error {
                                            code: KmsProxyErrorCode::Timeout,
                                            message: "Operation timed out".to_string(),
                                        },
                                        None,
                                    );
                                }
                            }
                        }

                        // Backoff (full jitter), but never exceed remaining budget.
                        let sleep_for = self.retry.compute_backoff(attempt, &mut rng).min(deadline - started.elapsed());
                        if sleep_for.is_zero() {
                            continue;
                        }
                        sleep(sleep_for).await;
                    }

                    return (
                        KmsResponse::Error {
                            code: KmsProxyErrorCode::UpstreamUnavailable,
                            message: "Upstream KMS error".to_string(),
                        },
                        None,
                    );
                }

                // Mock implementation
                let mut key = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut key);
                
                (
                KmsResponse::GenerateDataKey {
                    key_id: key_id,
                    ciphertext_blob: key.to_vec(),
                    plaintext: key.to_vec(),
                },
                None,
                )
            }
            KmsRequest::Decrypt { ciphertext_blob, key_id, recipient, encryption_context, .. } => {
                // If we have a real KMS client and a recipient (attestation doc), use real KMS.
                #[cfg(feature = "production")]
                if let Some(client) = &self.kms_client {
                    if let Some(attestation_doc) = &recipient {
                        // Circuit breaker + caps for upstream KMS calls.
                        self.circuit.before_request().await;
                        let _permit = self.limiter.acquire().await;
                        self.rate_limiter.acquire(1.0).await;
                        let mut rng = rand::thread_rng();

                        for attempt in 1..=self.retry.max_attempts {
                            let elapsed = started.elapsed();
                            if elapsed >= deadline {
                                return (
                                    KmsResponse::Error {
                                        code: KmsProxyErrorCode::Timeout,
                                        message: "Operation timed out".to_string(),
                                    },
                                    None,
                                );
                            }

                            let remaining = deadline - elapsed;
                            let per_attempt = if attempt == 1 {
                                Duration::from_millis(200)
                            } else {
                                Duration::from_millis(250)
                            }
                            .min(remaining);

                            // Build request fresh each attempt.
                            let mut builder = client
                                .decrypt()
                                .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext_blob.clone()))
                                .encryption_algorithm(aws_sdk_kms::types::EncryptionAlgorithmSpec::SymmetricDefault)
                                .recipient(
                                    aws_sdk_kms::types::RecipientInfo::builder()
                                        .key_encryption_algorithm(
                                            aws_sdk_kms::types::KeyEncryptionMechanism::RsaesOaepSha256,
                                        )
                                        .attestation_document(aws_sdk_kms::primitives::Blob::new(
                                            attestation_doc.clone(),
                                        ))
                                        .build(),
                                );

                            if let Some(kid) = &key_id {
                                builder = builder.key_id(kid);
                            }

                            // Add encryption context if provided
                            if let Some(ctx) = encryption_context.clone() {
                                for (k, v) in ctx {
                                    builder = builder.encryption_context(k, v);
                                }
                            }

                            match timeout(per_attempt, builder.send()).await {
                                Ok(Ok(output)) => {
                                    self.circuit.record_result(true).await;
                                    let kms_request_id = aws_request_id(&output);
                                    let ciphertext_for_recipient =
                                        output.ciphertext_for_recipient().map(|b| b.as_ref().to_vec());

                                    // Fail-closed: when using RecipientInfo, never forward plaintext.
                                    if ciphertext_for_recipient.is_none() {
                                        return (
                                            KmsResponse::Error {
                                                code: KmsProxyErrorCode::Internal,
                                                message: "Recipient-bound decrypt returned no ciphertext".to_string(),
                                            },
                                            kms_request_id,
                                        );
                                    }

                                    return (
                                        KmsResponse::Decrypt {
                                            ciphertext_for_recipient,
                                            plaintext: None,
                                            key_id: output.key_id().map(|s| s.to_string()),
                                        },
                                        kms_request_id,
                                    );
                                }
                                Ok(Err(e)) => {
                                    self.circuit.record_result(false).await;
                                    let code = classify_aws_error(&format!("{e:?}"));
                                    if !is_retryable(code) || attempt == self.retry.max_attempts {
                                        return (
                                            KmsResponse::Error {
                                                code,
                                                message: "Upstream KMS error".to_string(),
                                            },
                                            None,
                                        );
                                    }
                                }
                                Err(_) => {
                                    self.circuit.record_result(false).await;
                                    if attempt == self.retry.max_attempts {
                                        return (
                                            KmsResponse::Error {
                                                code: KmsProxyErrorCode::Timeout,
                                                message: "Operation timed out".to_string(),
                                            },
                                            None,
                                        );
                                    }
                                }
                            }

                            let sleep_for =
                                self.retry.compute_backoff(attempt, &mut rng).min(deadline - started.elapsed());
                            if !sleep_for.is_zero() {
                                sleep(sleep_for).await;
                            }
                        }

                        return (
                            KmsResponse::Error {
                                code: KmsProxyErrorCode::UpstreamUnavailable,
                                message: "Upstream KMS error".to_string(),
                            },
                            None,
                        );
                    }
                }

                // Mock implementation or fallback
                let key_material = ciphertext_blob;
                
                if let Some(attestation_bytes) = recipient {
                    match self.process_attestation(&attestation_bytes, &key_material) {
                        Ok(wrapped_key) => (
                            KmsResponse::Decrypt {
                                ciphertext_for_recipient: Some(wrapped_key),
                                plaintext: None,
                                key_id: None,
                            },
                            None,
                        ),
                        Err(_e) => (
                            KmsResponse::Error {
                                code: KmsProxyErrorCode::InvalidRequest,
                                message: "Invalid attestation document".to_string(),
                            },
                            None,
                        ),
                    }
                } else {
                    (
                        KmsResponse::Decrypt {
                            ciphertext_for_recipient: None,
                            plaintext: Some(key_material),
                            key_id: None,
                        },
                        None,
                    )
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

fn is_retryable(code: KmsProxyErrorCode) -> bool {
    matches!(
        code,
        KmsProxyErrorCode::Timeout | KmsProxyErrorCode::UpstreamThrottled | KmsProxyErrorCode::UpstreamUnavailable
    )
}

fn classify_aws_error(msg: &str) -> KmsProxyErrorCode {
    let m = msg.to_ascii_lowercase();
    if m.contains("accessdenied") || m.contains("notauthorized") || m.contains("unauthorized") {
        return KmsProxyErrorCode::UpstreamAccessDenied;
    }
    if m.contains("throttling") || m.contains("too many requests") || m.contains("ratelimit") {
        return KmsProxyErrorCode::UpstreamThrottled;
    }
    if m.contains("invalid") || m.contains("validation") || m.contains("notfound") {
        return KmsProxyErrorCode::InvalidRequest;
    }
    KmsProxyErrorCode::UpstreamUnavailable
}

#[cfg(feature = "production")]
fn aws_request_id<T: aws_types::request_id::RequestId>(output: &T) -> Option<String> {
    output.request_id().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_ml_common::{KmsProxyRequestEnvelope, KmsRequest};

    #[tokio::test]
    async fn test_host_blindness_enforced() {
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

        let response = server
            .handle_envelope(KmsProxyRequestEnvelope {
                request_id: "test-request".to_string(),
                trace_id: Some("trace-1".to_string()),
                request,
            })
            .await;
        
        match response.response {
            KmsResponse::Decrypt { ciphertext_for_recipient, plaintext, .. } => {
                // MUST have ciphertext for recipient
                assert!(ciphertext_for_recipient.is_some());
                // MUST NOT have plaintext
                assert!(plaintext.is_none());
            }
            KmsResponse::Error { code, message } => panic!("KMS Error: {:?} {}", code, message),
            _ => panic!("Expected Decrypt response"),
        }
    }
}
