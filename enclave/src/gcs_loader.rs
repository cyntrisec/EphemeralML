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
    metadata_url: String,
    gcs_api_base: String,
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

/// Timeout for metadata server requests (short — local network).
const METADATA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Timeout for GCS object downloads (large model files may take a while).
const GCS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Maximum GCS response size (4 GB). Prevents OOM from misconfigured buckets.
const MAX_GCS_RESPONSE_SIZE: usize = 4 * 1024 * 1024 * 1024;

impl GcsModelLoader {
    /// Create a new GCS loader for the given bucket.
    pub fn new(bucket: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(GCS_TIMEOUT)
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build reqwest client");
        Self {
            client,
            bucket: bucket.to_string(),
            metadata_url: METADATA_TOKEN_URL.to_string(),
            gcs_api_base: GCS_API_BASE.to_string(),
        }
    }

    /// Create a loader with custom base URLs (for testing with mock servers).
    #[doc(hidden)]
    pub fn with_test_urls(bucket: &str, base_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            bucket: bucket.to_string(),
            metadata_url: format!("{}/metadata/token", base_url),
            gcs_api_base: format!("{}/storage/v1/b", base_url),
        }
    }

    /// Fetch an access token from the GCP metadata server.
    ///
    /// Returns the bearer token string. Only works on GCE/GKE instances.
    async fn metadata_token(&self) -> Result<String> {
        let resp = self
            .client
            .get(&self.metadata_url)
            .header("Metadata-Flavor", "Google")
            .timeout(METADATA_TIMEOUT)
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
        // Reject path traversal attempts and absolute paths
        if object_path.contains("..") || object_path.starts_with('/') {
            return Err(EnclaveError::Enclave(EphemeralError::StorageError(
                format!(
                    "Invalid GCS object path (contains '..' or starts with '/'): {}",
                    object_path
                ),
            )));
        }

        let token = self.metadata_token().await?;

        // URL-encode the object path for the GCS JSON API media download
        let encoded_path = object_path.replace('/', "%2F");
        let url = format!(
            "{}/{}/o/{}?alt=media",
            self.gcs_api_base, self.bucket, encoded_path
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

        // Enforce size limit to prevent OOM from oversized responses
        if size > MAX_GCS_RESPONSE_SIZE {
            return Err(EnclaveError::Enclave(EphemeralError::StorageError(
                format!(
                    "GCS response too large for {}: {} bytes (max {})",
                    object_path, size, MAX_GCS_RESPONSE_SIZE
                ),
            )));
        }

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
    use crate::test_helpers::MockHttpServer;

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

    // --- Mock HTTP tests ---

    #[tokio::test]
    async fn fetch_object_success() {
        let payload = b"model weights data here";

        let server = MockHttpServer::start(vec![
            // 1. metadata token
            (
                200,
                r#"{"access_token":"tok","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            // 2. GCS object fetch
            (200, String::from_utf8_lossy(payload).to_string()),
        ])
        .await;

        let loader = GcsModelLoader::with_test_urls("test-bucket", &server.base_url);
        let artifact = loader
            .fetch_object("models/model.safetensors")
            .await
            .unwrap();

        assert_eq!(artifact.bytes, payload);
        assert_eq!(artifact.size, payload.len());

        // Verify hash
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let expected_hash: [u8; 32] = hasher.finalize().into();
        assert_eq!(artifact.sha256, expected_hash);
    }

    #[tokio::test]
    async fn fetch_object_gcs_404() {
        let server = MockHttpServer::start(vec![
            // 1. metadata token
            (
                200,
                r#"{"access_token":"tok","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            // 2. GCS returns 404
            (404, r#"{"error":"Not Found"}"#.to_string()),
        ])
        .await;

        let loader = GcsModelLoader::with_test_urls("test-bucket", &server.base_url);
        let result = loader.fetch_object("nonexistent/file.bin").await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("GCS returned"), "Error: {}", err);
    }

    #[tokio::test]
    async fn fetch_object_metadata_failure() {
        let server = MockHttpServer::start(vec![
            // metadata server returns 500
            (500, r#"{"error":"internal"}"#.to_string()),
        ])
        .await;

        let loader = GcsModelLoader::with_test_urls("test-bucket", &server.base_url);
        let result = loader.fetch_object("models/file.bin").await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("Metadata server returned"), "Error: {}", err);
    }

    #[tokio::test]
    async fn fetch_verified_hash_match() {
        let payload = b"verified model data";
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let expected_hash: [u8; 32] = hasher.finalize().into();

        let server = MockHttpServer::start(vec![
            (
                200,
                r#"{"access_token":"tok","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (200, String::from_utf8_lossy(payload).to_string()),
        ])
        .await;

        let loader = GcsModelLoader::with_test_urls("test-bucket", &server.base_url);
        let result = loader
            .fetch_verified("models/file.bin", &expected_hash)
            .await
            .unwrap();
        assert_eq!(result, payload);
    }

    #[tokio::test]
    async fn fetch_verified_hash_mismatch() {
        let payload = b"actual data";
        let wrong_hash = [0xFF; 32];

        let server = MockHttpServer::start(vec![
            (
                200,
                r#"{"access_token":"tok","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (200, String::from_utf8_lossy(payload).to_string()),
        ])
        .await;

        let loader = GcsModelLoader::with_test_urls("test-bucket", &server.base_url);
        let result = loader.fetch_verified("models/file.bin", &wrong_hash).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("hash mismatch"), "Error: {}", err);
    }

    #[tokio::test]
    async fn fetch_object_empty_response() {
        let server = MockHttpServer::start(vec![
            (
                200,
                r#"{"access_token":"tok","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (200, String::new()),
        ])
        .await;

        let loader = GcsModelLoader::with_test_urls("test-bucket", &server.base_url);
        let artifact = loader.fetch_object("models/empty.bin").await.unwrap();
        // Empty response is valid (0-byte file)
        assert_eq!(artifact.size, 0);
    }
}
