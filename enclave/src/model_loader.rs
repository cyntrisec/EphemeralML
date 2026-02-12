use crate::attestation::AttestationProvider;
use crate::kms_client::KmsClient;
use crate::{EnclaveError, EphemeralError, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use ephemeral_ml_common::ModelManifest;
use safetensors::SafeTensors;
use sha2::{Digest, Sha256};

pub struct ModelLoader<A: AttestationProvider> {
    kms_client: KmsClient<A>,
    trusted_signing_key: [u8; 32],
}

impl<A: AttestationProvider> ModelLoader<A> {
    pub fn new(kms_client: KmsClient<A>, trusted_signing_key: [u8; 32]) -> Self {
        Self {
            kms_client,
            trusted_signing_key,
        }
    }

    pub fn kms_client(&self) -> &KmsClient<A> {
        &self.kms_client
    }

    /// Load and verify a model from an encrypted artifact
    /// Returns the decrypted plaintext bytes. Caller must parse as SafeTensors.
    pub async fn load_model(
        &self,
        manifest: &ModelManifest,
        wrapped_dek: &[u8],
    ) -> Result<Vec<u8>> {
        // 1. Verify Manifest Signature
        manifest.verify(&self.trusted_signing_key).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::Validation(
                crate::ValidationError::InvalidSignature(format!(
                    "Manifest verification failed: {}",
                    e
                )),
            ))
        })?;

        // 2. Fetch Encrypted Artifact from Host
        let encrypted_artifact = self
            .kms_client
            .proxy_client()
            .fetch_model(&manifest.model_id)
            .await?;

        // 3. Unwrap DEK using KMS with encryption context binding
        let encryption_context = Some(std::collections::HashMap::from([
            ("model_id".to_string(), manifest.model_id.clone()),
            ("version".to_string(), manifest.version.clone()),
        ]));
        let dek_bytes = self
            .kms_client
            .decrypt(wrapped_dek, encryption_context)
            .await?;

        if dek_bytes.len() != 32 {
            return Err(EnclaveError::Enclave(EphemeralError::KmsError(format!(
                "Invalid DEK length: expected 32, got {}",
                dek_bytes.len()
            ))));
        }

        // 3. Decrypt Artifact
        if encrypted_artifact.len() < 12 + 16 {
            return Err(EnclaveError::Enclave(EphemeralError::DecryptionError(
                "Artifact too short".to_string(),
            )));
        }

        let (nonce_bytes, ciphertext) = encrypted_artifact.split_at(12);
        use std::convert::TryInto;
        let key_array: [u8; 32] = dek_bytes.as_slice().try_into().map_err(|_| {
            EnclaveError::Enclave(EphemeralError::KmsError("Invalid DEK length".to_string()))
        })?;
        let key: &Key = (&key_array).into();
        let cipher = ChaCha20Poly1305::new(key);
        let nonce_array: [u8; 12] = nonce_bytes.try_into().map_err(|_| {
            EnclaveError::Enclave(EphemeralError::DecryptionError(
                "Invalid nonce length".to_string(),
            ))
        })?;
        let nonce: &Nonce = (&nonce_array).into();

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::DecryptionError(format!(
                "Model decryption failed: {}",
                e
            )))
        })?;

        // 4. Verify Hash
        let mut hasher = Sha256::new();
        hasher.update(&plaintext);
        let calculated_hash = hasher.finalize();

        if calculated_hash.as_slice() != manifest.model_hash.as_slice() {
            return Err(EnclaveError::Enclave(EphemeralError::Validation(
                crate::ValidationError::IntegrityCheckFailed("Model hash mismatch".to_string()),
            )));
        }

        // 5. Validate Safetensors format
        let st = SafeTensors::deserialize(&plaintext).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::DecompositionError(format!(
                "Safetensors parse failed: {}",
                e
            )))
        })?;

        // 6. Enforce dtype constraints (Task 18.2)
        Self::validate_model_format(&st)?;

        Ok(plaintext)
    }

    fn validate_model_format(st: &SafeTensors) -> Result<()> {
        for (name, view) in st.tensors() {
            let dtype = view.dtype();
            // We only support F32, F16, and BF16 for v1
            match dtype {
                safetensors::Dtype::F32 | safetensors::Dtype::F16 | safetensors::Dtype::BF16 => {
                    // Allowed
                }
                _ => {
                    return Err(EnclaveError::Enclave(EphemeralError::ValidationError(
                        format!("Unsupported dtype {:?} for tensor {}", dtype, name),
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::DefaultAttestationProvider;
    use crate::kms_proxy_client::KmsProxyClient;
    use chacha20poly1305::aead::Aead;
    use ed25519_dalek::{Signer, SigningKey};
    use ephemeral_ml_common::transport_types::simple_frame::{self, TAG_KMS, TAG_STORAGE};
    use ephemeral_ml_common::KmsResponse;
    use hpke::{kem::X25519HkdfSha256, Deserializable, OpModeS, Serializable};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use serde::Serialize;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_load_model_mock() {
        // Setup Keys
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let dek = [0x42u8; 32]; // Mock DEK

        // Setup Provider and get HPKE public key
        let provider = DefaultAttestationProvider::new().unwrap();
        let hpke_pk_bytes = provider.get_hpke_public_key();

        // Create Mock Safetensors Artifact
        let json_header = r#"{"test": {"dtype":"F32", "shape":[1], "data_offsets":[0, 4]}}"#;
        let json_bytes = json_header.as_bytes();
        let n: u64 = json_bytes.len() as u64;
        let mut plaintext_model = Vec::new();
        plaintext_model.extend_from_slice(&n.to_le_bytes());
        plaintext_model.extend_from_slice(json_bytes);
        plaintext_model.extend_from_slice(&[0u8; 4]); // 4 bytes of data

        // Hash it
        let mut hasher = Sha256::new();
        hasher.update(&plaintext_model);
        let model_hash = hasher.finalize().to_vec();

        // Encrypt it
        let mut nonce_bytes = [0u8; 12];
        csprng.fill_bytes(&mut nonce_bytes);
        use chacha20poly1305::{Key as CKey, Nonce as CNonce};
        use std::convert::TryInto;
        let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
        let nonce = CNonce::from_slice(&nonce_array);
        let key_array: [u8; 32] = dek.try_into().unwrap();
        let key = CKey::from_slice(&key_array);
        let cipher = ChaCha20Poly1305::new(key);
        let ciphertext = cipher.encrypt(nonce, plaintext_model.as_slice()).unwrap();

        let mut encrypted_artifact = nonce_bytes.to_vec();
        encrypted_artifact.extend_from_slice(&ciphertext);

        let dek_clone = dek.clone();
        let encrypted_artifact_clone = encrypted_artifact.clone();

        // FIX: defined before tokio::spawn
        let hpke_pk_bytes_clone = hpke_pk_bytes.clone();

        // Start Mock KMS Server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let (tag, payload) = match simple_frame::read_frame(&mut socket).await {
                    Ok(f) => f,
                    Err(_) => break,
                };

                match tag {
                    TAG_KMS => {
                        let request_env: ephemeral_ml_common::KmsProxyRequestEnvelope =
                            serde_json::from_slice(&payload).unwrap();

                        let mut rng = OsRng;
                        let kem_pub = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(
                            &hpke_pk_bytes_clone,
                        )
                        .unwrap();

                        let (encapped_key, mut sender_ctx) =
                            hpke::setup_sender::<
                                hpke::aead::ChaCha20Poly1305,
                                hpke::kdf::HkdfSha256,
                                X25519HkdfSha256,
                                _,
                            >(
                                &OpModeS::Base, &kem_pub, b"KMS_DEK", &mut rng
                            )
                            .unwrap();

                        let ciphertext = sender_ctx.seal(&dek_clone, b"").unwrap();
                        let mut encrypted_dek = encapped_key.to_bytes().to_vec();
                        encrypted_dek.extend_from_slice(&ciphertext);

                        let response = KmsResponse::Decrypt {
                            ciphertext_for_recipient: Some(encrypted_dek),
                            plaintext: None,
                            key_id: None,
                        };

                        let response_env = ephemeral_ml_common::KmsProxyResponseEnvelope {
                            request_id: request_env.request_id,
                            trace_id: request_env.trace_id,
                            kms_request_id: None,
                            response,
                        };

                        let response_payload = serde_json::to_vec(&response_env).unwrap();
                        simple_frame::write_frame(&mut socket, TAG_KMS, &response_payload)
                            .await
                            .unwrap();
                    }
                    TAG_STORAGE => {
                        use ephemeral_ml_common::storage_protocol::StorageResponse;
                        let response = StorageResponse::Data {
                            payload: encrypted_artifact_clone.clone(),
                            is_last: true,
                        };
                        let resp_payload = serde_cbor::to_vec(&response).unwrap();
                        simple_frame::write_frame(&mut socket, TAG_STORAGE, &resp_payload)
                            .await
                            .unwrap();
                    }
                    _ => panic!("Unexpected tag: 0x{:02x}", tag),
                }
            }
        });

        // Setup Client with Proxy
        let proxy_client = KmsProxyClient::new().with_addr(format!("127.0.0.1:{}", port));
        let kms_client =
            KmsClient::new_with_proxy(provider, proxy_client, verifying_key.to_bytes());
        let loader = ModelLoader::new(kms_client, verifying_key.to_bytes());

        // Mock KMS Wrapped DEK (dummy for this test since our mock server ignores input and returns `dek` encrypted)
        let wrapped_dek = vec![0u8; 32];

        // Create Manifest
        #[derive(Serialize)]
        struct Payload {
            model_id: String,
            version: String,
            #[serde(with = "serde_bytes")]
            model_hash: Vec<u8>,
            hash_algorithm: String,
            key_id: String,
        }
        let payload = Payload {
            model_id: "test".to_string(),
            version: "v1".to_string(),
            model_hash: model_hash.clone(),
            hash_algorithm: "sha256".to_string(),
            key_id: "key".to_string(),
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = signing_key.sign(&payload_bytes);

        let manifest = ModelManifest {
            model_id: "test".to_string(),
            version: "v1".to_string(),
            model_hash: model_hash,
            hash_algorithm: "sha256".to_string(),
            key_id: "key".to_string(),
            signature: signature.to_bytes().to_vec(),
        };

        // Test Load
        let loaded_bytes = loader.load_model(&manifest, &wrapped_dek).await.unwrap();
        assert_eq!(loaded_bytes, plaintext_model);
    }
}
