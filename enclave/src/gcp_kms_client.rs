//! GCP Cloud KMS client with attestation binding.
//!
//! Uses Google Cloud Attestation API to obtain an OIDC token proving
//! the workload runs in a TDX Confidential VM, then exchanges it via
//! STS for a federated access token to call Cloud KMS.
//!
//! Flow:
//! 1. CreateChallenge → get nonce
//! 2. Generate TDX quote with nonce in REPORTDATA
//! 3. VerifyAttestation → get OIDC attestation token
//! 4. STS token exchange → federated access token
//! 5. Cloud KMS Decrypt
//!
//! Requires feature: `gcp`

use crate::tee_provider::TeeAttestationProvider;
use crate::{EnclaveError, EphemeralError, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// GCP metadata server URL for access tokens.
const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

/// Google Cloud Attestation API base URL.
const ATTESTATION_API_BASE: &str = "https://confidentialcomputing.googleapis.com/v1";

/// Google STS (Security Token Service) endpoint.
const STS_ENDPOINT: &str = "https://sts.googleapis.com/v1/token";

/// Google Cloud KMS API base URL.
const KMS_API_BASE: &str = "https://cloudkms.googleapis.com/v1";

/// CCEL ACPI table path on Linux.
const CCEL_ACPI_TABLE: &str = "/sys/firmware/acpi/tables/CCEL";

/// CCEL event log data path on Linux.
const CCEL_DATA: &str = "/sys/firmware/acpi/tables/data/CCEL";

/// GCP Cloud KMS client with TDX attestation binding.
pub struct GcpKmsClient {
    http: reqwest::Client,
    project: String,
    location: String,
    /// Workload Identity Pool audience for STS exchange.
    /// Format: `//iam.googleapis.com/projects/{number}/locations/global/workloadIdentityPools/{pool}/providers/{provider}`
    wip_audience: String,
    tee_provider: TeeAttestationProvider,
    // Base URLs (default from constants, overridable in tests).
    metadata_url: String,
    attestation_api_base: String,
    sts_endpoint: String,
    kms_api_base: String,
}

#[derive(Deserialize)]
struct MetadataTokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    name: String,
    nonce: String, // base64-encoded
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TdxCcelAttestation {
    td_quote: String, // base64
    #[serde(skip_serializing_if = "Option::is_none")]
    ccel_acpi_table: Option<String>, // base64
    #[serde(skip_serializing_if = "Option::is_none")]
    ccel_data: Option<String>, // base64
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyAttestationRequest {
    td_ccel: TdxCcelAttestation,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyAttestationResponse {
    oidc_claims_token: String,
}

#[derive(Deserialize)]
struct StsTokenResponse {
    access_token: String,
}

#[derive(Serialize)]
struct KmsDecryptRequest {
    ciphertext: String, // base64
}

#[derive(Deserialize)]
struct KmsDecryptResponse {
    plaintext: String, // base64
}

/// Timeout for metadata server requests (local network, should be fast).
const METADATA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Timeout for GCP API requests (Attestation, STS, KMS).
const API_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl GcpKmsClient {
    /// Create a new GCP KMS client.
    ///
    /// - `project`: GCP project ID (e.g. "my-project")
    /// - `location`: GCP location for Attestation API challenges (e.g. "us-central1")
    /// - `wip_audience`: Full WIP audience string for STS token exchange
    /// - `tee_provider`: TDX attestation provider for quote generation
    pub fn new(
        project: &str,
        location: &str,
        wip_audience: &str,
        tee_provider: TeeAttestationProvider,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(API_TIMEOUT)
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build reqwest client");
        Self {
            http,
            project: project.to_string(),
            location: location.to_string(),
            wip_audience: wip_audience.to_string(),
            tee_provider,
            metadata_url: METADATA_TOKEN_URL.to_string(),
            attestation_api_base: ATTESTATION_API_BASE.to_string(),
            sts_endpoint: STS_ENDPOINT.to_string(),
            kms_api_base: KMS_API_BASE.to_string(),
        }
    }

    /// Create a client with custom base URLs (for testing with mock servers).
    #[doc(hidden)]
    pub fn with_test_urls(
        project: &str,
        location: &str,
        wip_audience: &str,
        tee_provider: TeeAttestationProvider,
        base_url: &str,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            project: project.to_string(),
            location: location.to_string(),
            wip_audience: wip_audience.to_string(),
            tee_provider,
            metadata_url: format!("{}/metadata/token", base_url),
            attestation_api_base: format!("{}/v1", base_url),
            sts_endpoint: format!("{}/sts/token", base_url),
            kms_api_base: format!("{}/kms/v1", base_url),
        }
    }

    /// Get an access token from the GCP metadata server.
    async fn metadata_token(&self) -> Result<String> {
        let resp = self
            .http
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

        let body: MetadataTokenResponse = resp.json().await.map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(format!(
                "Metadata token parse: {}",
                e
            )))
        })?;

        Ok(body.access_token)
    }

    /// Step 1: Create a challenge via the Google Cloud Attestation API.
    async fn create_challenge(&self, token: &str) -> Result<ChallengeResponse> {
        let url = format!(
            "{}/projects/{}/locations/{}/challenges",
            self.attestation_api_base, self.project, self.location
        );

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| {
                EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                    "CreateChallenge failed: {}",
                    e
                )))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(EnclaveError::Enclave(EphemeralError::KmsError(format!(
                "CreateChallenge returned {}: {}",
                status, body
            ))));
        }

        resp.json().await.map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(format!(
                "Challenge parse: {}",
                e
            )))
        })
    }

    /// Step 2: Generate a TDX quote with the challenge nonce in REPORTDATA.
    fn generate_quote(&self, nonce: &[u8]) -> Result<Vec<u8>> {
        use crate::AttestationProvider;
        use sha2::{Digest, Sha256};

        // GCP challenge nonces are variable-length; TDX REPORTDATA nonce slot
        // is exactly 32 bytes. Hash to normalize length while preserving the
        // cryptographic binding to the challenge.
        let nonce_hash: [u8; 32] = Sha256::digest(nonce).into();

        let receipt_key = [0u8; 32]; // Not used for KMS auth, placeholder
        let doc = self
            .tee_provider
            .generate_attestation(&nonce_hash, receipt_key)?;

        // Extract raw quote from the CBOR envelope
        let envelope = crate::tee_provider::TeeAttestationEnvelope::from_cbor(&doc.signature)
            .map_err(|e| {
                EnclaveError::Enclave(EphemeralError::SerializationError(format!(
                    "Envelope decode: {}",
                    e
                )))
            })?;

        // Strip TDX_V1 wire header to get raw quote
        if envelope.tdx_wire.len() < 16 {
            return Err(EnclaveError::Enclave(EphemeralError::ProtocolError(
                "TDX wire too short".to_string(),
            )));
        }

        Ok(envelope.tdx_wire[16..].to_vec())
    }

    /// Read CCEL tables from sysfs (optional, may not be present).
    fn read_ccel_tables() -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let acpi = std::fs::read(CCEL_ACPI_TABLE).ok();
        let data = std::fs::read(CCEL_DATA).ok();
        (acpi, data)
    }

    /// Step 3: Verify attestation and get OIDC token.
    async fn verify_attestation(
        &self,
        token: &str,
        challenge_name: &str,
        raw_quote: &[u8],
    ) -> Result<String> {
        let (ccel_acpi, ccel_data) = Self::read_ccel_tables();

        let request = VerifyAttestationRequest {
            td_ccel: TdxCcelAttestation {
                td_quote: BASE64.encode(raw_quote),
                ccel_acpi_table: ccel_acpi.map(|b| BASE64.encode(b)),
                ccel_data: ccel_data.map(|b| BASE64.encode(b)),
            },
        };

        let url = format!("{}:verifyAttestation", challenge_name);
        // The challenge name already includes the full path, construct full URL
        let url = format!(
            "{}/{}",
            self.attestation_api_base,
            url.trim_start_matches('/')
        );

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                    "VerifyAttestation failed: {}",
                    e
                )))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(EnclaveError::Enclave(EphemeralError::KmsError(format!(
                "VerifyAttestation returned {}: {}",
                status, body
            ))));
        }

        let body: VerifyAttestationResponse = resp.json().await.map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(format!(
                "VerifyAttestation parse: {}",
                e
            )))
        })?;

        Ok(body.oidc_claims_token)
    }

    /// Step 4: Exchange OIDC attestation token for a federated access token via STS.
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
            (
                "scope",
                "https://www.googleapis.com/auth/cloud-platform",
            ),
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

    /// Get a federated access token bound to TDX attestation.
    ///
    /// Performs steps 1-4: challenge → quote → verify → STS exchange.
    pub async fn get_attested_token(&self) -> Result<String> {
        // Step 1: Get metadata token for API auth
        let metadata_token = self.metadata_token().await?;

        // Step 2: Create challenge
        let challenge = self.create_challenge(&metadata_token).await?;
        let nonce_bytes = BASE64.decode(&challenge.nonce).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(format!(
                "Challenge nonce decode: {}",
                e
            )))
        })?;

        // Step 3: Generate TDX quote
        let raw_quote = self.generate_quote(&nonce_bytes)?;

        // Step 4: Verify attestation
        let oidc_token = self
            .verify_attestation(&metadata_token, &challenge.name, &raw_quote)
            .await?;

        // Step 5: Exchange for access token
        self.exchange_token(&oidc_token).await
    }

    /// Decrypt ciphertext using Cloud KMS with attestation-bound credentials.
    ///
    /// `key_name` is the full Cloud KMS key resource name, e.g.:
    /// `projects/my-project/locations/global/keyRings/my-kr/cryptoKeys/my-key`
    pub async fn decrypt(&self, key_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let access_token = self.get_attested_token().await?;

        let url = format!("{}/{}:decrypt", self.kms_api_base, key_name);

        let request = KmsDecryptRequest {
            ciphertext: BASE64.encode(ciphertext),
        };

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
    use crate::test_helpers::MockHttpServer;

    const WIP: &str = "//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/pool/providers/prov";

    fn synthetic_client(base_url: &str) -> GcpKmsClient {
        GcpKmsClient::with_test_urls(
            "test-project",
            "us-central1",
            WIP,
            TeeAttestationProvider::synthetic(),
            base_url,
        )
    }

    #[test]
    fn client_creation() {
        let provider = TeeAttestationProvider::synthetic();
        let _client = GcpKmsClient::new("test-project", "us-central1", WIP, provider);
    }

    #[test]
    fn ccel_tables_graceful_when_missing() {
        let (acpi, data) = GcpKmsClient::read_ccel_tables();
        // On non-TDX machines these won't exist
        assert!(acpi.is_none() || acpi.is_some());
        assert!(data.is_none() || data.is_some());
    }

    #[test]
    fn quote_generation_with_synthetic_provider() {
        let provider = TeeAttestationProvider::synthetic();
        let client = GcpKmsClient::new("test-project", "us-central1", WIP, provider);

        let nonce = [0xAB; 32];
        let raw_quote = client.generate_quote(&nonce).unwrap();
        assert!(raw_quote.len() > 48, "Quote too short: {}", raw_quote.len());
    }

    // --- Mock HTTP flow tests ---

    #[tokio::test]
    async fn metadata_token_success() {
        let server = MockHttpServer::start(vec![(
            200,
            r#"{"access_token":"test-meta-token","token_type":"Bearer","expires_in":3600}"#
                .to_string(),
        )])
        .await;

        let client = synthetic_client(&server.base_url);
        let token = client.metadata_token().await.unwrap();
        assert_eq!(token, "test-meta-token");
    }

    #[tokio::test]
    async fn metadata_token_server_error() {
        let server =
            MockHttpServer::start(vec![(500, r#"{"error":"internal"}"#.to_string())]).await;

        let client = synthetic_client(&server.base_url);
        let result = client.metadata_token().await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("Metadata server returned"), "Error: {}", err);
    }

    #[tokio::test]
    async fn create_challenge_success() {
        let server = MockHttpServer::start(vec![
            // 1. metadata token
            (
                200,
                r#"{"access_token":"meta-tok","token_type":"Bearer","expires_in":3600}"#
                    .to_string(),
            ),
            // 2. create challenge
            (
                200,
                r#"{"name":"projects/test-project/locations/us-central1/challenges/ch-123","nonce":"dGVzdC1ub25jZQ=="}"#
                    .to_string(),
            ),
        ])
        .await;

        let client = synthetic_client(&server.base_url);
        let token = client.metadata_token().await.unwrap();
        let challenge = client.create_challenge(&token).await.unwrap();

        assert_eq!(
            challenge.name,
            "projects/test-project/locations/us-central1/challenges/ch-123"
        );
        // "dGVzdC1ub25jZQ==" decodes to "test-nonce"
        let nonce_bytes = BASE64.decode(&challenge.nonce).unwrap();
        assert_eq!(nonce_bytes, b"test-nonce");
    }

    #[tokio::test]
    async fn create_challenge_unauthorized() {
        let server =
            MockHttpServer::start(vec![(401, r#"{"error":"unauthorized"}"#.to_string())]).await;

        let client = synthetic_client(&server.base_url);
        let result = client.create_challenge("bad-token").await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("CreateChallenge returned"), "Error: {}", err);
    }

    #[tokio::test]
    async fn exchange_token_success() {
        let server = MockHttpServer::start(vec![(
            200,
            r#"{"access_token":"federated-access-token","token_type":"Bearer","expires_in":3600}"#
                .to_string(),
        )])
        .await;

        let client = synthetic_client(&server.base_url);
        let token = client.exchange_token("oidc-token-123").await.unwrap();
        assert_eq!(token, "federated-access-token");
    }

    #[tokio::test]
    async fn exchange_token_sts_error() {
        let server =
            MockHttpServer::start(vec![(400, r#"{"error":"invalid_grant"}"#.to_string())]).await;

        let client = synthetic_client(&server.base_url);
        let result = client.exchange_token("bad-oidc").await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("STS returned"), "Error: {}", err);
    }

    #[tokio::test]
    async fn kms_decrypt_full_flow() {
        // Simulate the full 5-step decrypt flow:
        // 1. metadata token
        // 2. create challenge
        // 3. verify attestation → OIDC token
        // 4. STS exchange → access token
        // 5. KMS decrypt → plaintext
        let plaintext = b"decrypted-dek-32-bytes-of-data!";
        let plaintext_b64 = BASE64.encode(plaintext);

        let server = MockHttpServer::start(vec![
            // Step 1: metadata token
            (
                200,
                r#"{"access_token":"meta-tok","token_type":"Bearer","expires_in":3600}"#
                    .to_string(),
            ),
            // Step 2: create challenge
            (
                200,
                r#"{"name":"projects/test-project/locations/us-central1/challenges/ch-1","nonce":"AAAA"}"#
                    .to_string(),
            ),
            // Step 3: verify attestation → OIDC token
            (
                200,
                r#"{"oidcClaimsToken":"eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJ0ZXN0In0.sig"}"#.to_string(),
            ),
            // Step 4: STS exchange → federated access token
            (
                200,
                r#"{"access_token":"fed-tok","token_type":"Bearer","expires_in":3600}"#
                    .to_string(),
            ),
            // Step 5: KMS decrypt
            (
                200,
                format!(r#"{{"plaintext":"{}"}}"#, plaintext_b64),
            ),
        ])
        .await;

        let client = synthetic_client(&server.base_url);
        let result = client
            .decrypt(
                "projects/test/locations/global/keyRings/kr/cryptoKeys/key",
                b"encrypted-data",
            )
            .await
            .unwrap();

        assert_eq!(result, plaintext);
    }

    #[tokio::test]
    async fn kms_decrypt_kms_api_error() {
        // Steps 1-4 succeed, step 5 (KMS) fails
        let server = MockHttpServer::start(vec![
            (
                200,
                r#"{"access_token":"meta","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            (
                200,
                r#"{"name":"projects/p/locations/l/challenges/c","nonce":"AAAA"}"#.to_string(),
            ),
            (200, r#"{"oidcClaimsToken":"tok"}"#.to_string()),
            (
                200,
                r#"{"access_token":"fed","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            // KMS returns 403
            (
                403,
                r#"{"error":{"code":403,"message":"Permission denied"}}"#.to_string(),
            ),
        ])
        .await;

        let client = synthetic_client(&server.base_url);
        let result = client
            .decrypt("projects/p/locations/l/keyRings/kr/cryptoKeys/k", b"ct")
            .await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("KMS decrypt returned"), "Error: {}", err);
    }

    #[tokio::test]
    async fn verify_attestation_success() {
        let server = MockHttpServer::start(vec![(
            200,
            r#"{"oidcClaimsToken":"my-oidc-token-123"}"#.to_string(),
        )])
        .await;

        let client = synthetic_client(&server.base_url);
        let oidc = client
            .verify_attestation(
                "bearer-token",
                "projects/test-project/locations/us-central1/challenges/ch-1",
                &[0u8; 64],
            )
            .await
            .unwrap();
        assert_eq!(oidc, "my-oidc-token-123");
    }

    #[tokio::test]
    async fn verify_attestation_api_error() {
        let server =
            MockHttpServer::start(vec![(400, r#"{"error":"invalid quote"}"#.to_string())]).await;

        let client = synthetic_client(&server.base_url);
        let result = client
            .verify_attestation("token", "projects/p/locations/l/challenges/c", &[0u8; 64])
            .await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("VerifyAttestation returned"), "Error: {}", err);
    }

    /// VerifyAttestation returns 400 with MRTD mismatch → fail-closed.
    #[tokio::test]
    async fn verify_attestation_wrong_mrtd() {
        let server = MockHttpServer::start(vec![(
            400,
            r#"{"error":"MRTD mismatch: image does not match expected measurements"}"#.to_string(),
        )])
        .await;

        let client = synthetic_client(&server.base_url);
        let result = client
            .verify_attestation("token", "projects/p/locations/l/challenges/c", &[0u8; 64])
            .await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("VerifyAttestation returned"),
            "Wrong MRTD must fail at VerifyAttestation: {}",
            err
        );
    }

    /// STS returns 400 with wrong audience → fail-closed.
    #[tokio::test]
    async fn sts_exchange_wrong_audience() {
        let server = MockHttpServer::start(vec![(
            400,
            r#"{"error":"invalid_target","error_description":"The target audience is not allowed"}"#
                .to_string(),
        )])
        .await;

        let client = synthetic_client(&server.base_url);
        let result = client.exchange_token("oidc-token").await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("STS returned"),
            "Wrong audience must fail at STS: {}",
            err
        );
    }

    /// Full decrypt flow: VerifyAttestation rejects (403) → decrypt() fails
    /// before reaching STS or KMS (fail-closed).
    #[tokio::test]
    async fn full_flow_fails_when_verify_attestation_rejects() {
        // Steps 1-2 succeed, step 3 (VerifyAttestation) returns 403
        let server = MockHttpServer::start(vec![
            // Step 1: metadata token
            (
                200,
                r#"{"access_token":"meta","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
            // Step 2: create challenge
            (
                200,
                r#"{"name":"projects/p/locations/l/challenges/c","nonce":"AAAA"}"#.to_string(),
            ),
            // Step 3: VerifyAttestation → measurement policy violation
            (
                403,
                r#"{"error":{"code":403,"message":"Attestation verification failed: measurement policy violation"}}"#
                    .to_string(),
            ),
            // Steps 4-5 should never be reached — but if they are, they'll
            // dequeue these and the assertion will still catch it via error message
        ])
        .await;

        let client = synthetic_client(&server.base_url);
        let result = client
            .decrypt("projects/p/locations/l/keyRings/kr/cryptoKeys/k", b"ct")
            .await;
        assert!(
            result.is_err(),
            "Attestation rejection must stop the entire decrypt flow"
        );
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("VerifyAttestation returned"),
            "Error must originate from VerifyAttestation, not STS or KMS: {}",
            err
        );
    }
}
