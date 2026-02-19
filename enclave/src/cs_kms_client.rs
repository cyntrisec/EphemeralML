//! Confidential Space KMS client.
//!
//! Simpler alternative to `GcpKmsClient` for workloads running inside
//! Confidential Space. Instead of the 5-step Cloud Attestation API flow
//! (metadata token → challenge → TDX quote → verify → STS → KMS), this
//! uses the Launcher-provided OIDC token directly:
//!
//! 1. Get OIDC token from Launcher socket (via `CsTokenClient`)
//! 2. STS token exchange → federated access token
//! 3. Cloud KMS Decrypt
//!
//! Auto-detection: if `/run/container_launcher/teeserver.sock` exists,
//! `main.rs` uses `CsKmsClient`; otherwise falls back to `GcpKmsClient`.
//!
//! Requires feature: `gcp`

use crate::cs_token_client::CsTokenClient;
use crate::{EnclaveError, EphemeralError, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Google STS (Security Token Service) endpoint.
const STS_ENDPOINT: &str = "https://sts.googleapis.com/v1/token";

/// Google Cloud KMS API base URL.
const KMS_API_BASE: &str = "https://cloudkms.googleapis.com/v1";

/// Timeout for GCP API requests (STS, KMS).
const API_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Deserialize)]
struct StsTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct KmsDecryptResponse {
    plaintext: String, // base64
}

/// KMS client that uses Confidential Space Launcher tokens for authentication.
///
/// This is the preferred path when running inside Confidential Space, as it
/// avoids quote generation and the Cloud Attestation API entirely — the
/// Launcher has already attested the workload and issues OIDC tokens directly.
pub struct CsKmsClient {
    http: reqwest::Client,
    cs_token: CsTokenClient,
    wip_audience: String,
    sts_endpoint: String,
    kms_api_base: String,
}

impl CsKmsClient {
    /// Create a new CsKmsClient.
    ///
    /// - `wip_audience`: Full Workload Identity Pool audience string for STS exchange.
    ///   Format: `//iam.googleapis.com/projects/{number}/locations/global/workloadIdentityPools/{pool}/providers/{provider}`
    pub fn new(wip_audience: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(API_TIMEOUT)
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build reqwest client");

        Self {
            http,
            cs_token: CsTokenClient::new(),
            wip_audience: wip_audience.to_string(),
            sts_endpoint: STS_ENDPOINT.to_string(),
            kms_api_base: KMS_API_BASE.to_string(),
        }
    }

    /// Create a client with custom endpoints and token client (for testing).
    #[doc(hidden)]
    pub fn with_test_config(wip_audience: &str, cs_token: CsTokenClient, base_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            cs_token,
            wip_audience: wip_audience.to_string(),
            sts_endpoint: format!("{}/sts/token", base_url),
            kms_api_base: format!("{}/kms/v1", base_url),
        }
    }

    /// Get a federated access token via CS Launcher → STS exchange.
    ///
    /// - `audience`: Token audience for the Launcher OIDC token request.
    /// - `nonces`: Session-binding nonces embedded in the OIDC token's `eat_nonce`.
    pub async fn get_access_token(&self, audience: &str, nonces: Vec<String>) -> Result<String> {
        let oidc_token = self.cs_token.get_token(audience, nonces).await?;
        self.exchange_token(&oidc_token).await
    }

    /// Exchange an OIDC token for a federated access token via STS.
    async fn exchange_token(&self, oidc_token: &str) -> Result<String> {
        let body = [
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", oidc_token),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("audience", &self.wip_audience),
            ("scope", "https://www.googleapis.com/auth/cloud-platform"),
        ];

        let resp = self
            .http
            .post(&self.sts_endpoint)
            .form(&body)
            .send()
            .await
            .map_err(|e| {
                EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                    "STS exchange failed: {}",
                    e
                )))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let resp_body = resp.text().await.unwrap_or_default();
            return Err(EnclaveError::Enclave(EphemeralError::KmsError(format!(
                "STS returned {}: {}",
                status, resp_body
            ))));
        }

        let body: StsTokenResponse = resp.json().await.map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(format!(
                "STS response parse: {}",
                e
            )))
        })?;

        Ok(body.access_token)
    }

    /// Decrypt ciphertext using Cloud KMS with Confidential Space credentials.
    ///
    /// `key_name` is the full Cloud KMS key resource name, e.g.:
    /// `projects/my-project/locations/global/keyRings/my-kr/cryptoKeys/my-key`
    pub async fn decrypt(&self, key_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Derive a session-binding nonce from the ciphertext hash.
        // This binds the OIDC token's eat_nonce to the specific DEK being decrypted,
        // preventing token replay across different model keys.
        let ciphertext_hash = Sha256::digest(ciphertext);
        let nonce = hex::encode(&ciphertext_hash[..16]);
        let access_token = self
            .get_access_token(&self.wip_audience, vec![nonce])
            .await?;

        let url = format!("{}/{}:decrypt", self.kms_api_base, key_name);

        let request = serde_json::json!({
            "ciphertext": BASE64.encode(ciphertext),
        });

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                EnclaveError::Enclave(EphemeralError::KmsError(format!(
                    "KMS decrypt request failed: {}",
                    e
                )))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(EnclaveError::Enclave(EphemeralError::KmsError(format!(
                "KMS decrypt returned {}: {}",
                status, body
            ))));
        }

        let body: KmsDecryptResponse = resp.json().await.map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(format!(
                "KMS decrypt response parse: {}",
                e
            )))
        })?;

        BASE64.decode(&body.plaintext).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::KmsError(format!(
                "KMS plaintext decode: {}",
                e
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_creation() {
        let _client = CsKmsClient::new(
            "//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/pool/providers/prov",
        );
    }

    #[tokio::test]
    async fn exchange_token_success() {
        use crate::test_helpers::MockHttpServer;

        let server = MockHttpServer::start(vec![(
            200,
            r#"{"access_token":"cs-fed-token","token_type":"Bearer","expires_in":3600}"#
                .to_string(),
        )])
        .await;

        let cs_token = CsTokenClient::with_socket_path("/nonexistent/test.sock");
        let client = CsKmsClient::with_test_config(
            "//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/pool/providers/prov",
            cs_token,
            &server.base_url,
        );

        let token = client.exchange_token("oidc-token-123").await.unwrap();
        assert_eq!(token, "cs-fed-token");
    }

    #[tokio::test]
    async fn exchange_token_sts_error() {
        use crate::test_helpers::MockHttpServer;

        let server =
            MockHttpServer::start(vec![(400, r#"{"error":"invalid_grant"}"#.to_string())]).await;

        let cs_token = CsTokenClient::with_socket_path("/nonexistent/test.sock");
        let client = CsKmsClient::with_test_config(
            "//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/pool/providers/prov",
            cs_token,
            &server.base_url,
        );

        let result = client.exchange_token("bad-oidc").await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("STS returned"), "Error: {}", err);
    }

    /// Full CS decrypt flow: Launcher token + STS succeed, KMS returns 403
    /// (attestation-based deny) → decrypt() fails closed.
    #[tokio::test]
    async fn decrypt_kms_403_fails_closed() {
        use crate::test_helpers::MockHttpServer;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        // --- Set up mock Launcher socket returning a synthetic JWT ---
        let dir = std::env::temp_dir().join(format!("cs_kms_403_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let socket_path = dir.join("launcher.sock");
        let socket_str = socket_path.to_str().unwrap().to_string();

        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let claims = serde_json::json!({
            "aud": "//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/pool/providers/prov",
            "eat_nonce": ["test-nonce"],
            "iss": "https://confidentialcomputing.googleapis.com",
            "exp": 9999999999u64,
            "iat": 1000000000u64,
            "swname": "CONFIDENTIAL_SPACE",
        });
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap().as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"fake-sig");
        let jwt = format!("{}.{}.{}", header, payload, sig);

        let jwt_clone = jwt.clone();
        let socket_str_clone = socket_str.clone();
        let _socket_handle = tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_str_clone).unwrap();
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let _ = stream.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    jwt_clone.len(),
                    jwt_clone
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // --- Set up mock HTTP server: STS succeeds, KMS returns 403 ---
        let http_server = MockHttpServer::start(vec![
            // STS exchange → success
            (
                200,
                r#"{"access_token":"fed-tok","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            // KMS decrypt → 403 attestation deny
            (
                403,
                r#"{"error":{"code":403,"message":"Request denied: attestation claims do not satisfy key access policy"}}"#
                    .to_string(),
            ),
        ])
        .await;

        let cs_token = CsTokenClient::with_socket_path(&socket_str);
        let client = CsKmsClient::with_test_config(
            "//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/pool/providers/prov",
            cs_token,
            &http_server.base_url,
        );

        let result = client
            .decrypt(
                "projects/p/locations/l/keyRings/kr/cryptoKeys/k",
                b"wrapped-dek",
            )
            .await;

        assert!(result.is_err(), "KMS 403 must cause decrypt to fail");
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("KMS decrypt returned"),
            "Error should mention KMS denial: {}",
            err
        );

        // Cleanup
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir(&dir);
    }
}
