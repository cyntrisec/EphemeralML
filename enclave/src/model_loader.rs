use crate::attestation::AttestationProvider;
use crate::kms_client::KmsClient;
use crate::{EnclaveError, EphemeralError, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use ephemeral_ml_common::{KmsReleaseEvidence, ModelManifest};
use safetensors::SafeTensors;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

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
        self.load_model_with_evidence(manifest, wrapped_dek)
            .await
            .map(|(plaintext, _)| plaintext)
    }

    /// Load and verify a model and return the attestation-bound KMS release
    /// evidence produced while unwrapping the model DEK.
    pub async fn load_model_with_evidence(
        &self,
        manifest: &ModelManifest,
        wrapped_dek: &[u8],
    ) -> Result<(Vec<u8>, KmsReleaseEvidence)> {
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
        let (mut dek_bytes, kms_release_evidence) = self
            .kms_client
            .decrypt_with_evidence(wrapped_dek, encryption_context)
            .await?;

        if dek_bytes.len() != 32 {
            dek_bytes.zeroize();
            return Err(EnclaveError::Enclave(EphemeralError::KmsError(format!(
                "Invalid DEK length: expected 32, got {}",
                dek_bytes.len()
            ))));
        }

        // 3. Decrypt Artifact
        if encrypted_artifact.len() < 12 + 16 {
            dek_bytes.zeroize();
            return Err(EnclaveError::Enclave(EphemeralError::DecryptionError(
                "Artifact too short".to_string(),
            )));
        }

        let (nonce_bytes, ciphertext) = encrypted_artifact.split_at(12);
        use std::convert::TryInto;
        let mut key_array: [u8; 32] = dek_bytes.as_slice().try_into().map_err(|_| {
            EnclaveError::Enclave(EphemeralError::KmsError("Invalid DEK length".to_string()))
        })?;
        // DEK heap copy no longer needed — zeroize immediately.
        dek_bytes.zeroize();

        let key: &Key = (&key_array).into();
        let cipher = ChaCha20Poly1305::new(key);
        // DEK stack copy no longer needed — zeroize after cipher construction.
        key_array.zeroize();

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

        Ok((plaintext, kms_release_evidence))
    }

    fn validate_model_format(st: &SafeTensors) -> Result<()> {
        for (name, view) in st.tensors() {
            let dtype = view.dtype();
            // Model weights must stay in the supported floating-point set, but
            // HuggingFace safetensors commonly include non-trainable integer
            // buffers such as `embeddings.position_ids`.
            match dtype {
                safetensors::Dtype::F32
                | safetensors::Dtype::F16
                | safetensors::Dtype::BF16
                | safetensors::Dtype::I64 => {}
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

#[cfg(all(test, feature = "mock"))]
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

    fn safetensors_with_dtype(
        dtype: &str,
        element_count: usize,
        byte_len: usize,
    ) -> SafeTensors<'static> {
        let json_header = format!(
            r#"{{"embeddings.position_ids": {{"dtype":"{}", "shape":[{}], "data_offsets":[0, {}]}}}}"#,
            dtype, element_count, byte_len
        );
        let json_bytes = json_header.as_bytes();
        let n: u64 = json_bytes.len() as u64;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&n.to_le_bytes());
        bytes.extend_from_slice(json_bytes);
        bytes.extend(std::iter::repeat(0u8).take(byte_len));
        let leaked: &'static [u8] = Box::leak(bytes.into_boxed_slice());
        SafeTensors::deserialize(leaked).unwrap()
    }

    #[test]
    fn model_format_accepts_i64_constant_buffers() {
        let st = safetensors_with_dtype("I64", 1, 8);

        ModelLoader::<DefaultAttestationProvider>::validate_model_format(&st).unwrap();
    }

    #[test]
    fn model_format_rejects_unsupported_u8_tensors() {
        let st = safetensors_with_dtype("U8", 1, 1);

        let err = ModelLoader::<DefaultAttestationProvider>::validate_model_format(&st)
            .expect_err("U8 tensors should remain unsupported by the enclave loader");

        assert!(
            err.to_string().contains("Unsupported dtype U8"),
            "unexpected error: {}",
            err
        );
    }

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
        let nonce = CNonce::from_slice(&nonce_bytes);
        let key = CKey::from_slice(&dek);
        let cipher = ChaCha20Poly1305::new(key);
        let ciphertext = cipher.encrypt(nonce, plaintext_model.as_slice()).unwrap();

        let mut encrypted_artifact = nonce_bytes.to_vec();
        encrypted_artifact.extend_from_slice(&ciphertext);

        let dek_clone = dek;
        let encrypted_artifact_clone = encrypted_artifact.clone();

        let hpke_pk_bytes_clone = hpke_pk_bytes;

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

                        let info = ephemeral_ml_common::kms_hpke_info(&hpke_pk_bytes_clone);

                        let (encapped_key, mut sender_ctx) =
                            hpke::setup_sender::<
                                hpke::aead::ChaCha20Poly1305,
                                hpke::kdf::HkdfSha256,
                                X25519HkdfSha256,
                                _,
                            >(&OpModeS::Base, &kem_pub, &info, &mut rng)
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
                        let resp_payload = ephemeral_ml_common::cbor::to_vec(&response).unwrap();
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

        // Create Manifest — use canonical_payload_bytes() via a temporary manifest
        // to ensure the signing bytes match verify()'s canonical serialization.
        let mut manifest = ModelManifest {
            model_id: "test".to_string(),
            version: "v1".to_string(),
            model_hash,
            hash_algorithm: "sha256".to_string(),
            key_id: "key".to_string(),
            tokenizer_hash: None,
            config_hash: None,
            gcs_uris: Default::default(),
            created_at: String::new(),
            signature: vec![],
        };
        // ModelManifest::canonical_payload_bytes is private, so replicate:
        // serialize to Value (BTreeMap-backed) then to bytes for sorted keys.
        #[derive(Serialize)]
        struct Payload {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            config_hash: Option<Vec<u8>>,
            #[serde(default)]
            created_at: String,
            #[serde(default)]
            gcs_uris: std::collections::BTreeMap<String, String>,
            hash_algorithm: String,
            key_id: String,
            #[serde(with = "serde_bytes")]
            model_hash: Vec<u8>,
            model_id: String,
            version: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            tokenizer_hash: Option<Vec<u8>>,
        }
        let payload = Payload {
            config_hash: manifest.config_hash.clone(),
            created_at: String::new(),
            gcs_uris: Default::default(),
            hash_algorithm: manifest.hash_algorithm.clone(),
            key_id: manifest.key_id.clone(),
            model_hash: manifest.model_hash.clone(),
            model_id: manifest.model_id.clone(),
            version: manifest.version.clone(),
            tokenizer_hash: manifest.tokenizer_hash.clone(),
        };
        let value = serde_json::to_value(&payload).unwrap();
        let payload_bytes = serde_json::to_vec(&value).unwrap();
        let signature = signing_key.sign(&payload_bytes);
        manifest.signature = signature.to_bytes().to_vec();

        // Test Load
        let loaded_bytes = loader.load_model(&manifest, &wrapped_dek).await.unwrap();
        assert_eq!(loaded_bytes, plaintext_model);
    }
}
