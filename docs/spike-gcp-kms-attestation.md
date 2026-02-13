# Spike: GCP Cloud KMS Attestation-Binding Flow

**Date:** 2026-02-12
**Status:** COMPLETE - NOT BLOCKED
**Verdict:** Standard REST APIs, no proprietary SDK required. Our `TeeAttestationProvider` already handles quote generation. Remaining work is HTTP calls.

---

## Architecture Difference: AWS vs GCP

| Aspect | AWS Nitro | GCP TDX CVM |
|--------|-----------|-------------|
| Trust boundary | Nested VM (enclave inside host) | Whole VM is trusted |
| Network | No network in enclave; needs vsock proxy | Direct network access |
| KMS path | Enclave -> vsock -> Host Proxy -> AWS KMS | CVM -> Attestation API -> STS -> Cloud KMS |
| Attestation | NSM device -> COSE_Sign1 document | configfs-tsm -> TDX quote -> Google Cloud Attestation API |
| Key release | AWS KMS `Recipient` field in Decrypt API | OIDC token + Workload Identity Pool federation |

**Key insight:** On GCP, the proxy-based `KmsProxyClient` is unnecessary. The CVM can call Cloud KMS directly after obtaining an attestation-bound credential.

---

## The 5-Step Flow

### Step 1: Create Challenge

```
POST https://confidentialcomputing.googleapis.com/v1/projects/{project}/locations/{location}/challenges

Authorization: Bearer {metadata-server-token}
Content-Type: application/json

Body: {}   (server generates nonce)

Response: {
  "name": "projects/{project}/locations/{location}/challenges/{uuid}",
  "createTime": "...",
  "expireTime": "...",
  "nonce": "<base64-encoded-nonce>"
}
```

Auth: Use GCP metadata server token (`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`).

### Step 2: Generate TDX Quote

Already implemented in `TeeAttestationProvider::generate_attestation()`.

```
Write nonce to /sys/kernel/config/tsm/report/report0/inblob
Read quote from /sys/kernel/config/tsm/report/report0/outblob
```

REPORTDATA layout: `hpke_pubkey[0..32] || challenge_nonce[32..64]`

### Step 3: Verify Attestation (Get OIDC Token)

```
POST https://confidentialcomputing.googleapis.com/v1/{challenge_name}:verifyAttestation

Authorization: Bearer {metadata-server-token}
Content-Type: application/json

Body: {
  "tdCcel": {
    "tdQuote": "<base64-raw-tdx-quote>",
    "ccelAcpiTable": "<base64-ccel-acpi>",    // from /sys/firmware/acpi/tables/CCEL
    "ccelData": "<base64-ccel-data>"           // from /sys/firmware/acpi/tables/data/CCEL
  }
}

Response: {
  "oidcClaimsToken": "<JWT attestation token>"
}
```

The JWT contains claims including `hwmodel`, `dbgstat`, `secboot`, TDX measurements, and `sub` (VM identity).

### Step 4: Exchange OIDC Token for GCP Access Token

```
POST https://sts.googleapis.com/v1/token

Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token={oidc_attestation_token}
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=//iam.googleapis.com/projects/{project_number}/locations/global/workloadIdentityPools/{pool}/providers/{provider}

Response: {
  "access_token": "ya29...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Step 5: Cloud KMS Decrypt

```
POST https://cloudkms.googleapis.com/v1/projects/{project}/locations/{location}/keyRings/{kr}/cryptoKeys/{key}:decrypt

Authorization: Bearer {federated-access-token}
Content-Type: application/json

Body: {
  "ciphertext": "<base64-encrypted-model-key>"
}

Response: {
  "plaintext": "<base64-decrypted-key>"
}
```

---

## Infrastructure Setup (One-Time)

### 1. Create Workload Identity Pool + OIDC Provider

```bash
# Create pool
gcloud iam workload-identity-pools create ephemeralml-attestation-pool \
  --location=global \
  --display-name="EphemeralML Attestation Pool"

# Create OIDC provider pointing to Google Cloud Attestation
gcloud iam workload-identity-pools providers create-oidc attestation-verifier \
  --location=global \
  --workload-identity-pool=ephemeralml-attestation-pool \
  --issuer-uri="https://confidentialcomputing.googleapis.com/" \
  --allowed-audiences="https://sts.googleapis.com" \
  --attribute-mapping="google.subject=assertion.sub"
```

### 2. Create KMS Key + IAM Binding

```bash
# Create keyring + key
gcloud kms keyrings create ephemeralml-models --location=global
gcloud kms keys create model-encryption-key \
  --keyring=ephemeralml-models --location=global \
  --purpose=encryption

# Bind: only attested CVMs from our pool can decrypt
gcloud kms keys add-iam-policy-binding model-encryption-key \
  --keyring=ephemeralml-models --location=global \
  --member="principalSet://iam.googleapis.com/projects/{PROJECT_NUMBER}/locations/global/workloadIdentityPools/ephemeralml-attestation-pool/*" \
  --role=roles/cloudkms.cryptoKeyDecrypter
```

### 3. Enable the Confidential Computing API

```bash
gcloud services enable confidentialcomputing.googleapis.com
```

---

## Implementation Plan for EphemeralML

### New file: `enclave/src/gcp_kms_client.rs`

```rust
/// GCP Cloud KMS client with attestation binding.
/// Uses Google Cloud Attestation API to get an OIDC token,
/// exchanges it via STS for a federated access token,
/// then calls Cloud KMS decrypt.
pub struct GcpKmsClient {
    http: reqwest::Client,
    project: String,
    location: String,
    tee_provider: TeeAttestationProvider,
}

impl GcpKmsClient {
    /// Get a GCP access token from the metadata server
    async fn metadata_token(&self) -> Result<String>;

    /// Step 1+3: Create challenge, generate quote, verify attestation
    async fn get_attestation_token(&self) -> Result<String>;

    /// Step 4: Exchange OIDC token for federated access token
    async fn exchange_for_access_token(&self, oidc_token: &str) -> Result<String>;

    /// Step 5: Decrypt with Cloud KMS
    pub async fn decrypt(&self, key_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
```

### Dependencies to add

```toml
reqwest = { version = "0.12", features = ["json"], optional = true }
base64 = { version = "0.22", optional = true }
```

Feature: `gcp = ["reqwest", "base64"]`

### What we already have

- `TeeAttestationProvider` generates TDX quotes via configfs-tsm (Day 1)
- `TeeAttestationProvider::parse_measurements()` extracts MRTD/RTMRs
- `TeeAttestationEnvelope` wraps user_data alongside the quote

### What's new

1. HTTP client for Google Cloud Attestation API (challenge + verify)
2. STS token exchange
3. Cloud KMS decrypt call
4. Read CCEL tables from `/sys/firmware/acpi/tables/CCEL` and `/sys/firmware/acpi/tables/data/CCEL`

### Testing strategy

- **Unit tests:** Mock HTTP responses for all 5 steps
- **Integration test:** On real c3-standard-4 TDX VM, full flow
- **Synthetic fallback:** For CI, skip steps 1/3/4 (no metadata server), test step 5 with a mock KMS

---

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| CCEL table format unknown | LOW | Read from `/sys/firmware/acpi/tables/CCEL` on real VM; optional field |
| Attestation API requires enabled API + IAM | LOW | One-time setup, documented above |
| Token expiry (1 hour) | LOW | Cache + refresh before expiry |
| No Rust SDK for Confidential Computing API | NONE | REST API is simple, reqwest is sufficient |
| WIP setup complexity | LOW | gcloud commands documented above |

---

## Conclusion

**NOT BLOCKED.** The GCP Cloud KMS attestation-binding flow is well-documented, uses standard REST APIs, and integrates cleanly with our existing `TeeAttestationProvider`. The main difference from AWS is the elimination of the proxy — the CVM calls APIs directly. Implementation is ~300 lines of HTTP client code.

**Next step:** Implement `GcpKmsClient` on Day 3 using the flow documented above.
