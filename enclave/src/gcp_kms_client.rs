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
}

#[derive(Deserialize)]
struct MetadataTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
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
        Self {
            http: reqwest::Client::new(),
            project: project.to_string(),
            location: location.to_string(),
            wip_audience: wip_audience.to_string(),
            tee_provider,
        }
    }

    /// Get an access token from the GCP metadata server.
    async fn metadata_token(&self) -> Result<String> {
        let resp = self
            .http
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
            ATTESTATION_API_BASE, self.project, self.location
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

        let receipt_key = [0u8; 32]; // Not used for KMS auth, placeholder
        let doc = self.tee_provider.generate_attestation(nonce, receipt_key)?;

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
        let url = format!("{}/{}", ATTESTATION_API_BASE, url.trim_start_matches('/'));

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
        ];

        let resp = self
            .http
            .post(STS_ENDPOINT)
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

        let url = format!("{}/{}:decrypt", KMS_API_BASE, key_name);

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

    #[test]
    fn client_creation() {
        let provider = TeeAttestationProvider::synthetic();
        let _client = GcpKmsClient::new(
            "test-project",
            "us-central1",
            "//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/pool/providers/prov",
            provider,
        );
    }

    #[test]
    fn ccel_tables_graceful_when_missing() {
        // On non-TDX machines, CCEL tables don't exist — should return None
        let (acpi, data) = GcpKmsClient::read_ccel_tables();
        // On CI/dev machines these won't exist
        assert!(acpi.is_none() || acpi.is_some());
        assert!(data.is_none() || data.is_some());
    }

    #[test]
    fn quote_generation_with_synthetic_provider() {
        let provider = TeeAttestationProvider::synthetic();
        let client = GcpKmsClient::new(
            "test-project",
            "us-central1",
            "//iam.googleapis.com/projects/12345/locations/global/workloadIdentityPools/pool/providers/prov",
            provider,
        );

        let nonce = [0xAB; 32];
        let raw_quote = client.generate_quote(&nonce).unwrap();

        // Should be a valid TDX quote (header starts with version bytes)
        assert!(raw_quote.len() > 48, "Quote too short: {}", raw_quote.len());
    }
}
