//! GCS Model Loader for GCP Confidential VMs.
//!
//! On a GCP CVM, the VM has direct network access (unlike Nitro Enclaves which
//! need a vsock proxy). This module fetches model artifacts directly from GCS
//! using the metadata server for authentication.
//!
//! Requires feature: `gcp`

use crate::{EnclaveError, EphemeralError, Result};
use sha2::{Digest, Sha256};

/// GCS model loader that fetches artifacts directly from Google Cloud Storage.
///
/// Authentication uses the GCP metadata server token, which is available on
/// any GCE instance (including Confidential VMs).
pub struct GcsModelLoader {
    client: reqwest::Client,
    bucket: String,
}

/// Metadata about a fetched model artifact.
#[derive(Debug)]
pub struct FetchedArtifact {
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
    pub size: usize,
}

/// GCP metadata server URL for access tokens.
const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

/// GCS JSON API base URL.
const GCS_API_BASE: &str = "https://storage.googleapis.com/storage/v1/b";

impl GcsModelLoader {
    /// Create a new GCS loader for the given bucket.
    pub fn new(bucket: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            bucket: bucket.to_string(),
        }
    }

    /// Create a loader with a custom reqwest client (for testing with mock servers).
    #[cfg(test)]
    pub fn with_client(bucket: &str, client: reqwest::Client) -> Self {
        Self {
            client,
            bucket: bucket.to_string(),
        }
    }

    /// Fetch an access token from the GCP metadata server.
    ///
    /// Returns the bearer token string. Only works on GCE/GKE instances.
    async fn metadata_token(&self) -> Result<String> {
        let resp = self
            .client
            .get(METADATA_TOKEN_URL)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|e| {
                EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                    "Metadata server unreachable: {}",
                    e
                )))
            })?;

        if !resp.status().is_success() {
            return Err(EnclaveError::Enclave(EphemeralError::NetworkError(
                format!("Metadata server returned {}", resp.status()),
            )));
        }

        let body: serde_json::Value = resp.json().await.map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(format!(
                "Metadata token parse error: {}",
                e
            )))
        })?;

        body["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                EnclaveError::Enclave(EphemeralError::NetworkError(
                    "No access_token in metadata response".to_string(),
                ))
            })
    }

    /// Fetch a model artifact from GCS.
    ///
    /// `object_path` is the GCS object name, e.g. `"models/minilm/model.safetensors"`.
    ///
    /// Returns the raw bytes along with their SHA-256 hash.
    pub async fn fetch_object(&self, object_path: &str) -> Result<FetchedArtifact> {
        let token = self.metadata_token().await?;

        // URL-encode the object path for the GCS JSON API media download
        let encoded_path = object_path.replace('/', "%2F");
        let url = format!(
            "{}/{}/o/{}?alt=media",
            GCS_API_BASE, self.bucket, encoded_path
        );

        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| {
                EnclaveError::Enclave(EphemeralError::StorageError(format!(
                    "GCS fetch failed: {}",
                    e
                )))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(EnclaveError::Enclave(EphemeralError::StorageError(
                format!("GCS returned {} for {}: {}", status, object_path, body),
            )));
        }

        let bytes = resp.bytes().await.map_err(|e| {
            EnclaveError::Enclave(EphemeralError::StorageError(format!(
                "GCS read error: {}",
                e
            )))
        })?;

        let bytes = bytes.to_vec();
        let size = bytes.len();

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let sha256: [u8; 32] = hasher.finalize().into();

        Ok(FetchedArtifact {
            bytes,
            sha256,
            size,
        })
    }

    /// Fetch a model file and verify its SHA-256 hash.
    ///
    /// Returns the raw bytes if the hash matches. Errors if the hash doesn't match.
    pub async fn fetch_verified(
        &self,
        object_path: &str,
        expected_sha256: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let artifact = self.fetch_object(object_path).await?;

        if &artifact.sha256 != expected_sha256 {
            return Err(EnclaveError::Enclave(EphemeralError::Validation(
                crate::ValidationError::IntegrityCheckFailed(format!(
                    "GCS object {} hash mismatch: expected {}, got {}",
                    object_path,
                    hex::encode(expected_sha256),
                    hex::encode(artifact.sha256),
                )),
            )));
        }

        Ok(artifact.bytes)
    }

    /// Fetch model files (config.json, tokenizer.json, model.safetensors) from a GCS prefix.
    ///
    /// `prefix` is the folder path in GCS, e.g. `"models/minilm"`.
    /// Returns (config_bytes, tokenizer_bytes, weights_bytes).
    pub async fn fetch_model_files(&self, prefix: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let config_path = format!("{}/config.json", prefix);
        let tokenizer_path = format!("{}/tokenizer.json", prefix);
        let weights_path = format!("{}/model.safetensors", prefix);

        // Fetch all three in parallel
        let (config_result, tokenizer_result, weights_result) = tokio::join!(
            self.fetch_object(&config_path),
            self.fetch_object(&tokenizer_path),
            self.fetch_object(&weights_path),
        );

        let config = config_result?;
        let tokenizer = tokenizer_result?;
        let weights = weights_result?;

        Ok((config.bytes, tokenizer.bytes, weights.bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetched_artifact_hash_is_correct() {
        let data = b"hello world";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let expected: [u8; 32] = hasher.finalize().into();

        let artifact = FetchedArtifact {
            bytes: data.to_vec(),
            sha256: expected,
            size: data.len(),
        };

        assert_eq!(artifact.sha256, expected);
        assert_eq!(artifact.size, 11);
    }

    #[test]
    fn gcs_loader_creation() {
        let loader = GcsModelLoader::new("my-bucket");
        assert_eq!(loader.bucket, "my-bucket");
    }
}
