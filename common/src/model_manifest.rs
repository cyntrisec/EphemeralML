use serde::{Deserialize, Serialize};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use crate::error::{EphemeralError, Result};

/// Signed Model Manifest
/// 
/// Represents the integrity and authenticity metadata for a model artifact.
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
}

impl ModelManifest {
    /// Verify the manifest signature against a trusted public key
    pub fn verify(&self, public_key_bytes: &[u8]) -> Result<()> {
        if public_key_bytes.len() != 32 {
            return Err(EphemeralError::Validation(crate::ValidationError::InvalidFormat(
                "Invalid Ed25519 public key length".to_string()
            )));
        }

        let verifying_key = VerifyingKey::from_bytes(public_key_bytes.try_into().unwrap())
            .map_err(|e| EphemeralError::Validation(crate::ValidationError::InvalidSignature(e.to_string())))?;

        let signature = Signature::from_bytes(self.signature.as_slice().try_into().map_err(|_| 
            EphemeralError::Validation(crate::ValidationError::InvalidSignature("Invalid signature length".to_string()))
        )?);

        // Reconstruct the signing payload
        let payload = ManifestSigningPayload {
            model_id: self.model_id.clone(),
            version: self.version.clone(),
            model_hash: self.model_hash.clone(),
            hash_algorithm: self.hash_algorithm.clone(),
            key_id: self.key_id.clone(),
        };

        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| EphemeralError::SerializationError(e.to_string()))?;

        verifying_key.verify(&payload_bytes, &signature)
            .map_err(|e| EphemeralError::Validation(crate::ValidationError::InvalidSignature(e.to_string())))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use rand::rngs::OsRng;

    #[test]
    fn test_manifest_verification() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let payload = ManifestSigningPayload {
            model_id: "test-model".to_string(),
            version: "v1".to_string(),
            model_hash: vec![1, 2, 3, 4], // Mock hash
            hash_algorithm: "sha256".to_string(),
            key_id: "alias/test-key".to_string(),
        };

        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = signing_key.sign(&payload_bytes);

        let manifest = ModelManifest {
            model_id: payload.model_id,
            version: payload.version,
            model_hash: payload.model_hash,
            hash_algorithm: payload.hash_algorithm,
            key_id: payload.key_id,
            signature: signature.to_bytes().to_vec(),
        };

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
}
