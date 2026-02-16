use crate::error::{EphemeralError, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Signed Model Manifest
///
/// Represents the integrity and authenticity metadata for a model artifact.
/// Used to verify model provenance before loading.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ModelManifest {
    /// Unique identifier for the model
    pub model_id: String,

    /// Version string (e.g., "v1.0.0")
    pub version: String,

    /// SHA-256 hash of the PLAINTEXT model artifact (safetensors file)
    /// This ensures we are loading exactly what was signed.
    #[serde(with = "serde_bytes")]
    pub model_hash: Vec<u8>,

    /// The algorithm used for the hash (e.g., "sha256")
    pub hash_algorithm: String,

    /// Metadata about the encryption key (e.g., Key ID in KMS)
    pub key_id: String,

    /// GCS URIs for model artifacts (config, tokenizer, weights_enc, wrapped_dek).
    /// Keys: "config", "tokenizer", "weights_enc", "wrapped_dek"
    #[serde(default)]
    pub gcs_uris: BTreeMap<String, String>,

    /// ISO 8601 timestamp of manifest creation.
    #[serde(default)]
    pub created_at: String,

    /// Ed25519 signature of the canonical JSON representation of the fields above
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Payload used for signing (excludes the signature itself)
#[derive(Debug, Serialize, Deserialize)]
struct ManifestSigningPayload {
    model_id: String,
    version: String,
    #[serde(with = "serde_bytes")]
    model_hash: Vec<u8>,
    hash_algorithm: String,
    key_id: String,
    #[serde(default)]
    gcs_uris: BTreeMap<String, String>,
    #[serde(default)]
    created_at: String,
}

impl ModelManifest {
    /// Deserialize a manifest from JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| {
            EphemeralError::SerializationError(format!("manifest.json parse error: {}", e))
        })
    }

    /// Validate the model hash against an actual computed hash.
    pub fn validate_hash(&self, actual_hash: &[u8; 32]) -> Result<()> {
        if self.model_hash.len() != 32 {
            return Err(EphemeralError::Validation(
                crate::ValidationError::IntegrityCheckFailed(format!(
                    "Manifest model_hash has invalid length: {} (expected 32)",
                    self.model_hash.len()
                )),
            ));
        }
        if self.model_hash.as_slice() != actual_hash.as_slice() {
            return Err(EphemeralError::Validation(
                crate::ValidationError::IntegrityCheckFailed(format!(
                    "Manifest model hash mismatch: manifest={}, actual={}",
                    hex::encode(&self.model_hash),
                    hex::encode(actual_hash),
                )),
            ));
        }
        Ok(())
    }

    /// Produce the canonical JSON bytes for signing/verification.
    ///
    /// Serializes the signing payload through `serde_json::Value` to guarantee
    /// alphabetically-sorted keys (BTreeMap-backed Map). This matches Python's
    /// `json.dumps(sort_keys=True, separators=(',', ':'))` output, ensuring
    /// cross-language signature compatibility.
    fn canonical_payload_bytes(&self) -> Result<Vec<u8>> {
        let payload = ManifestSigningPayload {
            model_id: self.model_id.clone(),
            version: self.version.clone(),
            model_hash: self.model_hash.clone(),
            hash_algorithm: self.hash_algorithm.clone(),
            key_id: self.key_id.clone(),
            gcs_uris: self.gcs_uris.clone(),
            created_at: self.created_at.clone(),
        };

        // Two-step serialization: struct → Value (normalizes key order via BTreeMap)
        // → compact JSON bytes. This ensures alphabetical key order matching Python.
        let value = serde_json::to_value(&payload)
            .map_err(|e| EphemeralError::SerializationError(e.to_string()))?;
        serde_json::to_vec(&value).map_err(|e| EphemeralError::SerializationError(e.to_string()))
    }

    /// Verify the manifest signature against a trusted public key
    pub fn verify(&self, public_key_bytes: &[u8]) -> Result<()> {
        if public_key_bytes.len() != 32 {
            return Err(EphemeralError::Validation(
                crate::ValidationError::InvalidFormat(
                    "Invalid Ed25519 public key length".to_string(),
                ),
            ));
        }

        let verifying_key = VerifyingKey::from_bytes(public_key_bytes.try_into().unwrap())
            .map_err(|e| {
                EphemeralError::Validation(crate::ValidationError::InvalidSignature(e.to_string()))
            })?;

        let signature =
            Signature::from_bytes(self.signature.as_slice().try_into().map_err(|_| {
                EphemeralError::Validation(crate::ValidationError::InvalidSignature(
                    "Invalid signature length".to_string(),
                ))
            })?);

        let payload_bytes = self.canonical_payload_bytes()?;

        verifying_key
            .verify(&payload_bytes, &signature)
            .map_err(|e| {
                EphemeralError::Validation(crate::ValidationError::InvalidSignature(e.to_string()))
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn create_signed_manifest(signing_key: &SigningKey) -> ModelManifest {
        let mut gcs_uris = BTreeMap::new();
        gcs_uris.insert(
            "config".to_string(),
            "gs://bucket/model/config.json".to_string(),
        );
        gcs_uris.insert(
            "tokenizer".to_string(),
            "gs://bucket/model/tokenizer.json".to_string(),
        );
        gcs_uris.insert(
            "weights_enc".to_string(),
            "gs://bucket/model/model.safetensors.enc".to_string(),
        );
        gcs_uris.insert(
            "wrapped_dek".to_string(),
            "gs://bucket/model/wrapped_dek.bin".to_string(),
        );

        let mut manifest = ModelManifest {
            model_id: "test-model".to_string(),
            version: "v1".to_string(),
            model_hash: vec![1, 2, 3, 4],
            hash_algorithm: "sha256".to_string(),
            key_id: "alias/test-key".to_string(),
            gcs_uris,
            created_at: "2026-02-16T00:00:00Z".to_string(),
            signature: vec![],
        };

        // Sign using the same canonical_payload_bytes() as verify()
        let payload_bytes = manifest.canonical_payload_bytes().unwrap();
        let signature = signing_key.sign(&payload_bytes);
        manifest.signature = signature.to_bytes().to_vec();
        manifest
    }

    #[test]
    fn test_manifest_verification() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let manifest = create_signed_manifest(&signing_key);

        // Should pass
        assert!(manifest.verify(verifying_key.as_bytes()).is_ok());

        // Tamper with data
        let mut bad_manifest = manifest.clone();
        bad_manifest.model_hash = vec![1, 2, 3, 5];
        assert!(bad_manifest.verify(verifying_key.as_bytes()).is_err());

        // Tamper with signature
        let mut bad_sig_manifest = manifest.clone();
        bad_sig_manifest.signature[0] ^= 0xFF;
        assert!(bad_sig_manifest.verify(verifying_key.as_bytes()).is_err());
    }

    #[test]
    fn test_manifest_from_json() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let manifest = create_signed_manifest(&signing_key);

        let json = serde_json::to_vec(&manifest).unwrap();
        let parsed = ModelManifest::from_json(&json).unwrap();

        assert_eq!(parsed.model_id, manifest.model_id);
        assert_eq!(parsed.version, manifest.version);
        assert_eq!(parsed.model_hash, manifest.model_hash);
        assert_eq!(parsed.gcs_uris.len(), 4);
        assert_eq!(parsed.created_at, "2026-02-16T00:00:00Z");
    }

    #[test]
    fn test_manifest_from_json_invalid() {
        let result = ModelManifest::from_json(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_validate_hash() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let manifest = create_signed_manifest(&signing_key);

        // model_hash is [1,2,3,4] which is not 32 bytes — should fail
        let hash = [0u8; 32];
        assert!(manifest.validate_hash(&hash).is_err());
    }

    #[test]
    fn test_manifest_validate_hash_match() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut manifest = create_signed_manifest(&signing_key);
        let expected = [0xABu8; 32];
        manifest.model_hash = expected.to_vec();

        assert!(manifest.validate_hash(&expected).is_ok());
    }

    #[test]
    fn test_manifest_validate_hash_mismatch() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut manifest = create_signed_manifest(&signing_key);
        manifest.model_hash = vec![0xAB; 32];

        let different = [0xCD; 32];
        let err = manifest.validate_hash(&different).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("hash mismatch"), "Error: {}", msg);
    }

    #[test]
    fn test_canonical_payload_alphabetical_order() {
        let manifest = ModelManifest {
            model_id: "m".to_string(),
            version: "v".to_string(),
            model_hash: vec![1],
            hash_algorithm: "sha256".to_string(),
            key_id: "k".to_string(),
            gcs_uris: BTreeMap::new(),
            created_at: "t".to_string(),
            signature: vec![],
        };
        let bytes = manifest.canonical_payload_bytes().unwrap();
        let json_str = String::from_utf8(bytes).unwrap();

        // Keys must appear in alphabetical order (matching Python sort_keys=True)
        let created_at_pos = json_str.find("\"created_at\"").unwrap();
        let gcs_uris_pos = json_str.find("\"gcs_uris\"").unwrap();
        let hash_alg_pos = json_str.find("\"hash_algorithm\"").unwrap();
        let key_id_pos = json_str.find("\"key_id\"").unwrap();
        let model_hash_pos = json_str.find("\"model_hash\"").unwrap();
        let model_id_pos = json_str.find("\"model_id\"").unwrap();
        let version_pos = json_str.find("\"version\"").unwrap();

        assert!(
            created_at_pos < gcs_uris_pos
                && gcs_uris_pos < hash_alg_pos
                && hash_alg_pos < key_id_pos
                && key_id_pos < model_hash_pos
                && model_hash_pos < model_id_pos
                && model_id_pos < version_pos,
            "Keys not in alphabetical order: {}",
            json_str
        );
    }

    #[test]
    fn test_manifest_backwards_compat_no_gcs_uris() {
        // Old manifests without gcs_uris/created_at should still parse
        let json = r#"{
            "model_id": "old-model",
            "version": "v0.1",
            "model_hash": [1, 2, 3],
            "hash_algorithm": "sha256",
            "key_id": "key1",
            "signature": [0, 0, 0]
        }"#;

        let manifest = ModelManifest::from_json(json.as_bytes()).unwrap();
        assert_eq!(manifest.model_id, "old-model");
        assert!(manifest.gcs_uris.is_empty());
        assert!(manifest.created_at.is_empty());
    }
}
