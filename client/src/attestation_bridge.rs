//! Bridge between EphemeralML's COSE attestation verifier and cml-transport's
//! `AttestationVerifier` trait.
//!
//! `CoseVerifierBridge` wraps the existing 630-line COSE_Sign1 + cert chain +
//! PCR validation into cml-transport's `AttestationVerifier::verify()`.
//!
//! `MockVerifierBridge` delegates to cml-transport's `MockVerifier` for mock mode.

#[cfg(feature = "gcp")]
use crate::error::ClientError;
#[cfg(feature = "gcp")]
use ciborium::Value as CborValue;
use confidential_ml_transport::attestation::types::{
    AttestationDocument as CmlAttestationDocument, VerifiedAttestation,
};
use confidential_ml_transport::error::AttestError;
use confidential_ml_transport::AttestationVerifier as CmlAttestationVerifier;
use ephemeral_ml_common::transport_types::EphemeralUserData;
#[cfg(feature = "gcp")]
use ephemeral_ml_common::EphemeralError;
use ephemeral_ml_common::PcrMeasurements;
use std::collections::BTreeMap;
#[cfg(feature = "gcp")]
use std::collections::HashMap;
use std::sync::Mutex;
#[cfg(feature = "gcp")]
use std::sync::RwLock;

use crate::attestation_verifier::{AttestationVerifier, EnclaveIdentity};
use crate::PolicyManager;

/// Wraps the production COSE verifier as cml-transport's `AttestationVerifier`.
///
/// Nonce checking is handled by cml-transport's handshake, so this bridge
/// does NOT call `FreshnessEnforcer`. It only verifies the COSE signature,
/// cert chain, and PCR policy.
pub struct CoseVerifierBridge {
    verifier: Mutex<AttestationVerifier>,
}

impl CoseVerifierBridge {
    pub fn new(policy_manager: PolicyManager) -> Self {
        Self {
            verifier: Mutex::new(AttestationVerifier::new(policy_manager)),
        }
    }

    fn identity_to_verified(identity: &EnclaveIdentity, _raw_doc: &[u8]) -> VerifiedAttestation {
        // Convert PCR measurements to BTreeMap
        let mut measurements = BTreeMap::new();
        measurements.insert(0, identity.measurements.pcr0.clone());
        measurements.insert(1, identity.measurements.pcr1.clone());
        measurements.insert(2, identity.measurements.pcr2.clone());

        // Serialize EphemeralUserData for the user_data field
        let user_data = EphemeralUserData::new(
            identity.receipt_signing_key,
            identity.protocol_version,
            identity.supported_features.clone(),
        );
        let ud_cbor = user_data.to_cbor().ok();

        VerifiedAttestation {
            document_hash: identity.attestation_hash,
            public_key: Some(identity.hpke_public_key.to_vec()),
            user_data: ud_cbor,
            nonce: None, // nonce checked by cml-transport handshake
            measurements,
        }
    }
}

#[async_trait::async_trait]
impl CmlAttestationVerifier for CoseVerifierBridge {
    async fn verify(
        &self,
        doc: &CmlAttestationDocument,
    ) -> std::result::Result<VerifiedAttestation, AttestError> {
        let mut verifier = self.verifier.lock().map_err(|e| {
            AttestError::VerificationFailed(format!("Verifier lock poisoned: {}", e))
        })?;

        // Reconstruct EphemeralML's AttestationDocument from raw bytes
        let ephemeral_doc = ephemeral_ml_common::AttestationDocument {
            module_id: String::new(), // will be extracted from payload
            digest: vec![],
            timestamp: 0,
            pcrs: PcrMeasurements::new(vec![], vec![], vec![]),
            certificate: vec![],
            signature: doc.raw.clone(), // raw COSE_Sign1 bytes
            nonce: None,
        };

        // Use verify_attestation_no_pcr_policy to skip PCR allowlist check
        // for now, since the bridge is used during handshake where we may
        // not have the nonce yet. PCR policy can be enforced at app level.
        //
        // Pass an empty nonce — cml-transport handles nonce verification.
        // We skip freshness validation since it's handled by the handshake.
        let identity = verify_attestation_for_bridge(&mut verifier, &ephemeral_doc)
            .map_err(|e| AttestError::VerificationFailed(format!("{}", e)))?;

        Ok(Self::identity_to_verified(&identity, &doc.raw))
    }
}

/// Internal helper that performs COSE verification without nonce checks.
///
/// In mock mode, this parses the CBOR map directly.
/// In production mode, this verifies COSE_Sign1 + cert chain but skips nonce
/// validation (cml-transport's handshake handles nonce verification).
fn verify_attestation_for_bridge(
    verifier: &mut AttestationVerifier,
    doc: &ephemeral_ml_common::AttestationDocument,
) -> crate::Result<EnclaveIdentity> {
    verifier.verify_attestation_skip_nonce(doc)
}

/// Policy pins for CS envelope verification.
///
/// When set, each field is validated against the corresponding JWT claim.
/// Fail-closed: any mismatch causes verification to fail.
#[cfg(feature = "gcp")]
#[derive(Clone, Debug, Default)]
pub struct CsPolicy {
    /// Expected container image digest (e.g., "sha256:abc123...").
    /// Validated against JWT claim `submods.container.image_digest`.
    pub expected_image_digest: Option<String>,
    /// Expected GCE project ID (e.g., "my-project-123").
    /// Validated against JWT claim `submods.gce.project_id`.
    pub expected_project: Option<String>,
    /// Expected GCE zone (e.g., "us-central1-a").
    /// Validated against JWT claim `submods.gce.zone`.
    pub expected_zone: Option<String>,
    /// Expected JWT audience (e.g., the WIP audience URI).
    /// Validated against JWT claim `aud`. When set, tokens with a
    /// different audience are rejected (fail-closed).
    pub expected_audience: Option<String>,
}

#[cfg(feature = "gcp")]
impl CsPolicy {
    /// Load policy pins from environment variables.
    ///
    /// - `EPHEMERALML_EXPECTED_IMAGE_DIGEST` — container image digest
    /// - `EPHEMERALML_EXPECTED_PROJECT` — GCE project ID
    /// - `EPHEMERALML_EXPECTED_ZONE` — GCE zone
    /// - `EPHEMERALML_EXPECTED_AUDIENCE` — JWT audience (WIP audience URI)
    pub fn from_env() -> Self {
        Self {
            expected_image_digest: std::env::var("EPHEMERALML_EXPECTED_IMAGE_DIGEST").ok(),
            expected_project: std::env::var("EPHEMERALML_EXPECTED_PROJECT").ok(),
            expected_zone: std::env::var("EPHEMERALML_EXPECTED_ZONE").ok(),
            expected_audience: std::env::var("EPHEMERALML_EXPECTED_AUDIENCE").ok(),
        }
    }
}

/// JWKS key cache for CS JWT signature verification.
#[cfg(feature = "gcp")]
struct JwksCache {
    keys: HashMap<String, jsonwebtoken::DecodingKey>,
    fetched_at: Option<std::time::Instant>,
}

#[cfg(feature = "gcp")]
impl JwksCache {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            fetched_at: None,
        }
    }

    fn is_stale(&self) -> bool {
        match self.fetched_at {
            Some(t) => t.elapsed() > std::time::Duration::from_secs(3600),
            None => true,
        }
    }
}

/// Combined TDX + CS envelope verifier bridge for GCP Confidential Space.
///
/// Handles two envelope formats:
/// - `TeeAttestationEnvelope` (platform: "tdx") — inner TDX quote verified via `TdxVerifier`
/// - `CsTransportAttestation` (platform: "cs-tdx") — Launcher JWT with nonce/key binding
///
/// Falls back to plain TDX wire format if the document is not an envelope.
///
/// Measurement pinning (TDX only): reads `EPHEMERALML_EXPECTED_MRTD` env var.
/// CS policy pins: image digest, project, zone via `CsPolicy` or env vars.
#[cfg(feature = "gcp")]
pub struct TdxEnvelopeVerifierBridge {
    inner: confidential_ml_transport::attestation::tdx::TdxVerifier,
    /// Expected JWT issuer for CS envelopes.
    cs_expected_issuer: String,
    /// Policy pins for CS envelope validation.
    cs_policy: CsPolicy,
    /// Cached JWKS keys for RS256 signature verification.
    jwks_cache: RwLock<JwksCache>,
    /// HTTP client for fetching OIDC discovery and JWKS.
    http_client: reqwest::Client,
}

#[cfg(feature = "gcp")]
impl TdxEnvelopeVerifierBridge {
    /// Expected issuer for Confidential Space Launcher JWTs.
    const CS_ISSUER: &'static str = "https://confidentialcomputing.googleapis.com";

    /// Create a new TDX/CS envelope verifier bridge.
    ///
    /// `expected_mrtd`: optional 48-byte MRTD to validate against (TDX mode only).
    /// Pass `None` to accept any MRTD (useful for development).
    ///
    /// If `expected_mrtd` is `None`, also checks the `EPHEMERALML_EXPECTED_MRTD`
    /// environment variable (hex-encoded, 48 bytes = 96 hex chars).
    ///
    /// Returns `Err(ClientError)` if required security pins are missing.
    pub fn new(expected_mrtd: Option<Vec<u8>>) -> std::result::Result<Self, ClientError> {
        let mrtd = expected_mrtd.or_else(|| {
            std::env::var("EPHEMERALML_EXPECTED_MRTD")
                .ok()
                .and_then(|hex_str| hex::decode(hex_str).ok())
                .filter(|bytes| bytes.len() == 48)
        });

        if mrtd.is_none() {
            // Default to requiring MRTD pinning. Opt out for development by
            // setting EPHEMERALML_REQUIRE_MRTD=false explicitly.
            let require = std::env::var("EPHEMERALML_REQUIRE_MRTD")
                .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
                .unwrap_or(true);
            if require {
                return Err(ClientError::Client(EphemeralError::ConfigurationError(
                    "No expected MRTD configured and MRTD pinning is required (default). \
                     Set EPHEMERALML_EXPECTED_MRTD (96 hex chars) for production use, \
                     or set EPHEMERALML_REQUIRE_MRTD=false for development."
                        .to_string(),
                )));
            }
            eprintln!(
                "[client] WARNING: No expected MRTD configured (EPHEMERALML_REQUIRE_MRTD=false). \
                 TDX peer measurements are NOT pinned. This is unsafe for production."
            );
        }

        let cs_policy = CsPolicy::from_env();

        // Audience pinning: fail-closed by default in GCP mode.
        // Opt out for development by setting EPHEMERALML_ALLOW_UNPINNED_AUDIENCE=true.
        if cs_policy.expected_audience.is_none() {
            let allow_unpinned = std::env::var("EPHEMERALML_ALLOW_UNPINNED_AUDIENCE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !allow_unpinned {
                return Err(ClientError::Client(EphemeralError::ConfigurationError(
                    "No expected audience configured and audience pinning is required (default). \
                     Set EPHEMERALML_EXPECTED_AUDIENCE to the WIP audience URI for production use, \
                     or set EPHEMERALML_ALLOW_UNPINNED_AUDIENCE=true for development."
                        .to_string(),
                )));
            }
            eprintln!(
                "[client] WARNING: No expected audience configured \
                 (EPHEMERALML_ALLOW_UNPINNED_AUDIENCE=true). \
                 JWT audience is NOT validated. This is unsafe for production."
            );
        }

        Ok(Self {
            inner: confidential_ml_transport::attestation::tdx::TdxVerifier::new(mrtd),
            cs_expected_issuer: Self::CS_ISSUER.to_string(),
            cs_policy,
            jwks_cache: RwLock::new(JwksCache::new()),
            http_client: reqwest::Client::new(),
        })
    }

    /// Set CS policy pins explicitly (overrides env vars).
    pub fn with_cs_policy(mut self, policy: CsPolicy) -> Self {
        self.cs_policy = policy;
        self
    }

    /// Create a verifier with a pre-populated JWKS cache (for testing).
    #[cfg(test)]
    fn with_jwks_cache(mut self, cache: JwksCache) -> Self {
        self.jwks_cache = RwLock::new(cache);
        self
    }

    /// Fetch JWKS keys from Google's OIDC discovery endpoint.
    async fn fetch_jwks(
        &self,
    ) -> std::result::Result<HashMap<String, jsonwebtoken::DecodingKey>, AttestError> {
        // 1. OIDC discovery
        let discovery_url = format!("{}/.well-known/openid-configuration", Self::CS_ISSUER);
        let discovery: serde_json::Value = self
            .http_client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| {
                AttestError::VerificationFailed(format!(
                    "JWKS fetch failed: OIDC discovery request error: {}",
                    e
                ))
            })?
            .json()
            .await
            .map_err(|e| {
                AttestError::VerificationFailed(format!(
                    "JWKS fetch failed: OIDC discovery parse error: {}",
                    e
                ))
            })?;

        let jwks_uri = discovery["jwks_uri"].as_str().ok_or_else(|| {
            AttestError::VerificationFailed(
                "JWKS fetch failed: no jwks_uri in OIDC discovery".to_string(),
            )
        })?;

        // 2. Fetch JWKS
        let jwks: serde_json::Value = self
            .http_client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| AttestError::VerificationFailed(format!("JWKS fetch failed: {}", e)))?
            .json()
            .await
            .map_err(|e| {
                AttestError::VerificationFailed(format!(
                    "JWKS fetch failed: JWKS parse error: {}",
                    e
                ))
            })?;

        // 3. Parse RSA keys
        let mut keys = HashMap::new();
        if let Some(key_array) = jwks["keys"].as_array() {
            for key in key_array {
                let kid = match key["kid"].as_str() {
                    Some(k) => k.to_string(),
                    None => continue,
                };
                let n = match key["n"].as_str() {
                    Some(v) => v,
                    None => continue,
                };
                let e = match key["e"].as_str() {
                    Some(v) => v,
                    None => continue,
                };
                if let Ok(dk) = jsonwebtoken::DecodingKey::from_rsa_components(n, e) {
                    keys.insert(kid, dk);
                }
            }
        }

        if keys.is_empty() {
            return Err(AttestError::VerificationFailed(
                "JWKS fetch failed: no usable RSA keys in JWKS".to_string(),
            ));
        }

        Ok(keys)
    }

    /// Build a `jsonwebtoken::Validation` configured for CS JWT verification.
    fn jwt_validation(&self) -> jsonwebtoken::Validation {
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        v.set_issuer(&[&self.cs_expected_issuer]);
        v.validate_exp = true;
        // Audience: validate when policy specifies one, skip otherwise.
        if let Some(ref aud) = self.cs_policy.expected_audience {
            v.set_audience(&[aud]);
        } else {
            v.validate_aud = false;
        }
        v
    }

    /// Verify JWT RS256 signature using cached JWKS keys.
    ///
    /// Returns verified claims. Fetches JWKS on cache miss or staleness.
    /// On transient JWKS fetch failure, falls back to stale cache keys
    /// if the kid is present (graceful degradation).
    async fn verify_jwt_signature(
        &self,
        jwt: &str,
    ) -> std::result::Result<CsJwtClaims, AttestError> {
        // 1. Decode header to get kid
        let header = jsonwebtoken::decode_header(jwt).map_err(|e| {
            AttestError::VerificationFailed(format!(
                "JWT signature verification failed: header decode: {}",
                e
            ))
        })?;

        let kid = header.kid.ok_or_else(|| {
            AttestError::VerificationFailed("JWT header missing key ID (kid)".to_string())
        })?;

        let validation = self.jwt_validation();

        // 2. Try cache (fresh hit = immediate return)
        {
            let cache = self.jwks_cache.read().map_err(|e| {
                AttestError::VerificationFailed(format!("JWKS cache lock poisoned: {}", e))
            })?;
            if !cache.is_stale() {
                if let Some(key) = cache.keys.get(&kid) {
                    let token_data = jsonwebtoken::decode::<CsJwtClaims>(jwt, key, &validation)
                        .map_err(|e| {
                            AttestError::VerificationFailed(format!(
                                "JWT signature verification failed: {}",
                                e
                            ))
                        })?;
                    return Ok(token_data.claims);
                }
            }
        }

        // 3. Cache miss or stale — try to fetch fresh JWKS
        match self.fetch_jwks().await {
            Ok(new_keys) => {
                let key = new_keys.get(&kid).ok_or_else(|| {
                    AttestError::VerificationFailed(format!(
                        "JWT key ID '{}' not found in JWKS",
                        kid
                    ))
                })?;

                let token_data = jsonwebtoken::decode::<CsJwtClaims>(jwt, key, &validation)
                    .map_err(|e| {
                        AttestError::VerificationFailed(format!(
                            "JWT signature verification failed: {}",
                            e
                        ))
                    })?;

                // Update cache on successful fetch
                if let Ok(mut cache) = self.jwks_cache.write() {
                    cache.keys = new_keys;
                    cache.fetched_at = Some(std::time::Instant::now());
                }

                Ok(token_data.claims)
            }
            Err(fetch_err) => {
                // 4. Fetch failed — fall back to stale cache if kid is present.
                // This handles transient network outages gracefully.
                let cache = self.jwks_cache.read().map_err(|e| {
                    AttestError::VerificationFailed(format!("JWKS cache lock poisoned: {}", e))
                })?;
                if let Some(key) = cache.keys.get(&kid) {
                    let token_data = jsonwebtoken::decode::<CsJwtClaims>(jwt, key, &validation)
                        .map_err(|e| {
                            AttestError::VerificationFailed(format!(
                                "JWT signature verification failed: {}",
                                e
                            ))
                        })?;
                    return Ok(token_data.claims);
                }
                // No stale key either — propagate the original fetch error
                Err(fetch_err)
            }
        }
    }

    /// Verify a CS transport attestation envelope.
    ///
    /// Validates:
    /// 1. Envelope structure (platform, key sizes, nonce non-empty)
    /// 2. JWT RS256 signature via JWKS
    /// 3. JWT claims: issuer, expiry
    /// 4. Nonce binding (eat_nonce matches envelope nonce)
    async fn verify_cs_envelope(
        &self,
        envelope: &ephemeral_ml_common::CsTransportAttestation,
        raw_bytes: &[u8],
    ) -> std::result::Result<VerifiedAttestation, AttestError> {
        // 1. Structural validation
        envelope.validate_structure().map_err(|e| {
            AttestError::VerificationFailed(format!("CS envelope structure invalid: {}", e))
        })?;

        // 2. Verify JWT RS256 signature via JWKS and extract verified claims.
        // jsonwebtoken validates issuer and expiry during decode.
        let claims = self.verify_jwt_signature(&envelope.launcher_jwt).await?;

        // 3. Validate nonce binding (eat_nonce must contain the envelope nonce hex)
        let expected_nonce_hex = hex::encode(&envelope.nonce);
        if !expected_nonce_hex.is_empty() && !claims.eat_nonce.contains(&expected_nonce_hex) {
            return Err(AttestError::VerificationFailed(format!(
                "CS JWT eat_nonce does not contain expected handshake nonce. \
                 Expected: {}, Got: {:?}",
                expected_nonce_hex, claims.eat_nonce
            )));
        }

        // 4. Validate policy pins (fail-closed on mismatch)
        if let Some(ref expected) = self.cs_policy.expected_image_digest {
            if claims.submods.container.image_digest != *expected {
                return Err(AttestError::VerificationFailed(format!(
                    "CS image digest mismatch: got '{}', expected '{}'",
                    claims.submods.container.image_digest, expected
                )));
            }
        }
        if let Some(ref expected) = self.cs_policy.expected_project {
            if claims.submods.gce.project_id != *expected {
                return Err(AttestError::VerificationFailed(format!(
                    "CS project mismatch: got '{}', expected '{}'",
                    claims.submods.gce.project_id, expected
                )));
            }
        }
        if let Some(ref expected) = self.cs_policy.expected_zone {
            if claims.submods.gce.zone != *expected {
                return Err(AttestError::VerificationFailed(format!(
                    "CS zone mismatch: got '{}', expected '{}'",
                    claims.submods.gce.zone, expected
                )));
            }
        }

        // 5. Build VerifiedAttestation
        let document_hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(raw_bytes).into()
        };

        // Convert receipt signing key to EphemeralUserData for cml-transport compatibility
        let mut receipt_key = [0u8; 32];
        if envelope.receipt_signing_key.len() == 32 {
            receipt_key.copy_from_slice(&envelope.receipt_signing_key);
        } else {
            return Err(AttestError::VerificationFailed(format!(
                "CS envelope receipt_signing_key wrong length: {}",
                envelope.receipt_signing_key.len()
            )));
        }
        let ud = EphemeralUserData::new(
            receipt_key,
            envelope.protocol_version,
            vec!["cs-tdx".to_string()],
        );
        let ud_cbor = ud.to_cbor().map_err(|e| {
            AttestError::VerificationFailed(format!("CS user_data CBOR encode failed: {}", e))
        })?;

        Ok(VerifiedAttestation {
            document_hash,
            public_key: Some(envelope.handshake_public_key.clone()),
            user_data: Some(ud_cbor),
            nonce: if envelope.nonce.is_empty() {
                None
            } else {
                Some(envelope.nonce.clone())
            },
            measurements: BTreeMap::new(), // CS mode: no TDX measurements in envelope
        })
    }
}

#[cfg(feature = "gcp")]
#[async_trait::async_trait]
impl CmlAttestationVerifier for TdxEnvelopeVerifierBridge {
    async fn verify(
        &self,
        doc: &CmlAttestationDocument,
    ) -> std::result::Result<VerifiedAttestation, AttestError> {
        // First: try to detect envelope format by checking the "platform" field.
        // This avoids deserializing the full document twice.
        if let Ok(CborValue::Map(ref m)) =
            ephemeral_ml_common::cbor::from_slice::<CborValue>(&doc.raw)
        {
            let platform_key = CborValue::Text("platform".to_string());
            if let Some(CborValue::Text(ref platform)) =
                ephemeral_ml_common::cbor::map_get(m, &platform_key)
            {
                match platform.as_str() {
                    // CS Launcher JWT envelope
                    "cs-tdx" => {
                        let envelope =
                            ephemeral_ml_common::CsTransportAttestation::from_cbor(&doc.raw)
                                .map_err(|e| {
                                    AttestError::VerificationFailed(format!(
                                        "CS envelope decode failed: {}",
                                        e
                                    ))
                                })?;
                        return self.verify_cs_envelope(&envelope, &doc.raw).await;
                    }
                    // TDX quote envelope
                    "tdx" => {
                        let envelope =
                            ephemeral_ml_common::cbor::from_slice::<TdxEnvelopeHelper>(&doc.raw)
                                .map_err(|e| {
                                    AttestError::VerificationFailed(format!(
                                        "TDX envelope decode failed: {}",
                                        e
                                    ))
                                })?;
                        return self.verify_tdx_envelope(&envelope, &doc.raw).await;
                    }
                    other => {
                        return Err(AttestError::VerificationFailed(format!(
                            "Unknown attestation envelope platform: '{}'",
                            other
                        )));
                    }
                }
            }
        }

        // No "platform" key: genuine plain TDX wire format
        self.inner.verify(doc).await
    }
}

#[cfg(feature = "gcp")]
impl TdxEnvelopeVerifierBridge {
    /// Verify a TDX envelope (platform: "tdx").
    async fn verify_tdx_envelope(
        &self,
        envelope: &TdxEnvelopeHelper,
        raw_bytes: &[u8],
    ) -> std::result::Result<VerifiedAttestation, AttestError> {
        let tdx_doc = CmlAttestationDocument::new(envelope.tdx_wire.clone());
        let mut verified = self.inner.verify(&tdx_doc).await?;

        // Override document_hash to match the full envelope bytes,
        // not just the inner tdx_wire.
        verified.document_hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(raw_bytes).into()
        };

        // Attach the user_data from the envelope (fail-closed: reject if missing/invalid)
        if envelope.user_data.is_empty() {
            return Err(AttestError::VerificationFailed(
                "TDX envelope user_data is empty — cannot extract receipt signing key".to_string(),
            ));
        }
        let ud = serde_json::from_slice::<EphemeralUserData>(&envelope.user_data).map_err(|e| {
            AttestError::VerificationFailed(format!("TDX envelope user_data parse failed: {}", e))
        })?;
        let cbor = ud.to_cbor().map_err(|e| {
            AttestError::VerificationFailed(format!(
                "TDX envelope user_data CBOR encode failed: {}",
                e
            ))
        })?;
        verified.user_data = Some(cbor);

        Ok(verified)
    }
}

/// Minimal JWT claims for CS envelope verification.
///
/// `iss` and `exp` are validated by `jsonwebtoken::decode()` during signature
/// verification but retained here for serde deserialization.
#[cfg(feature = "gcp")]
#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct CsJwtClaims {
    #[serde(default)]
    iss: String,
    #[serde(default)]
    exp: u64,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    eat_nonce: Vec<String>,
    /// Submodule claims (container image, GCE instance, etc.).
    #[serde(default)]
    submods: CsJwtSubmods,
}

/// JWT submods claims for policy pin validation.
#[cfg(feature = "gcp")]
#[derive(serde::Deserialize, Debug, Default)]
struct CsJwtSubmods {
    #[serde(default)]
    container: CsContainerClaims,
    #[serde(default)]
    gce: CsGceClaims,
}

/// Container-level JWT claims.
#[cfg(feature = "gcp")]
#[derive(serde::Deserialize, Debug, Default)]
struct CsContainerClaims {
    #[serde(default)]
    image_digest: String,
}

/// GCE instance-level JWT claims.
#[cfg(feature = "gcp")]
#[derive(serde::Deserialize, Debug, Default)]
struct CsGceClaims {
    #[serde(default)]
    project_id: String,
    #[serde(default)]
    zone: String,
}

/// Deserialize a JSON value that may be a single string or an array of strings.
#[cfg(feature = "gcp")]
fn deserialize_string_or_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrVec;

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or an array of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Vec<String>, A::Error> {
            let mut vec = Vec::new();
            while let Some(s) = seq.next_element()? {
                vec.push(s);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

/// Helper struct for deserializing TeeAttestationEnvelope on the client side.
/// Mirrors enclave's TeeAttestationEnvelope without requiring the enclave crate.
#[cfg(feature = "gcp")]
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct TdxEnvelopeHelper {
    platform: String,
    #[serde(with = "serde_bytes")]
    tdx_wire: Vec<u8>,
    #[serde(with = "serde_bytes")]
    user_data: Vec<u8>,
}

/// Mock verifier bridge that wraps cml-transport's MockVerifier.
///
/// For use in mock/test mode — delegates directly to cml-transport.
#[cfg(feature = "mock")]
pub struct MockVerifierBridge {
    inner: confidential_ml_transport::MockVerifier,
}

#[cfg(feature = "mock")]
impl MockVerifierBridge {
    pub fn new() -> Self {
        Self {
            inner: confidential_ml_transport::MockVerifier,
        }
    }
}

#[cfg(feature = "mock")]
impl Default for MockVerifierBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "mock")]
#[async_trait::async_trait]
impl CmlAttestationVerifier for MockVerifierBridge {
    async fn verify(
        &self,
        doc: &CmlAttestationDocument,
    ) -> std::result::Result<VerifiedAttestation, AttestError> {
        self.inner.verify(doc).await
    }
}

#[cfg(test)]
#[cfg(feature = "gcp")]
mod tests {
    use super::*;
    use confidential_ml_transport::AttestationVerifier as CmlAttestationVerifier;
    use ephemeral_ml_common::CsTransportAttestation;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};

    const TEST_KID: &str = "test-key-1";

    /// Generate an RSA keypair for test JWT signing.
    fn test_rsa_keys() -> (EncodingKey, jsonwebtoken::DecodingKey) {
        // Use a pre-generated 2048-bit RSA key (PEM) for deterministic tests.
        // This avoids slow key generation on every test run.
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let private_pem = rsa.private_key_to_pem().unwrap();
        let public_pem = rsa.public_key_to_pem().unwrap();
        let encoding = EncodingKey::from_rsa_pem(&private_pem).unwrap();
        let decoding = jsonwebtoken::DecodingKey::from_rsa_pem(&public_pem).unwrap();
        (encoding, decoding)
    }

    /// Build a pre-populated JwksCache with the test decoding key.
    fn test_jwks_cache(decoding_key: jsonwebtoken::DecodingKey) -> JwksCache {
        let mut keys = HashMap::new();
        keys.insert(TEST_KID.to_string(), decoding_key);
        JwksCache {
            keys,
            fetched_at: Some(std::time::Instant::now()),
        }
    }

    fn make_test_jwt(
        encoding_key: &EncodingKey,
        issuer: &str,
        exp: u64,
        nonces: &[&str],
    ) -> String {
        make_test_jwt_with_submods(encoding_key, issuer, exp, nonces, "", "", "")
    }

    fn make_test_jwt_with_submods(
        encoding_key: &EncodingKey,
        issuer: &str,
        exp: u64,
        nonces: &[&str],
        image_digest: &str,
        project_id: &str,
        zone: &str,
    ) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());

        let nonce_value = if nonces.len() == 1 {
            serde_json::Value::String(nonces[0].to_string())
        } else {
            serde_json::Value::Array(
                nonces
                    .iter()
                    .map(|n| serde_json::Value::String(n.to_string()))
                    .collect(),
            )
        };

        let claims = serde_json::json!({
            "iss": issuer,
            "exp": exp,
            "eat_nonce": nonce_value,
            "aud": "test",
            "submods": {
                "container": { "image_digest": image_digest },
                "gce": { "project_id": project_id, "zone": zone }
            }
        });

        jsonwebtoken::encode(&header, &claims, encoding_key).unwrap()
    }

    fn make_cs_envelope(jwt: &str, nonce: &[u8]) -> CsTransportAttestation {
        CsTransportAttestation::new(jwt.to_string(), [0xAA; 32], vec![0xBB; 32], nonce.to_vec())
    }

    fn make_verifier(decoding_key: jsonwebtoken::DecodingKey) -> TdxEnvelopeVerifierBridge {
        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        std::env::set_var("EPHEMERALML_ALLOW_UNPINNED_AUDIENCE", "true");
        TdxEnvelopeVerifierBridge::new(None)
            .unwrap()
            .with_jwks_cache(test_jwks_cache(decoding_key))
    }

    #[tokio::test]
    async fn test_cs_envelope_verify_valid() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"test-nonce-value";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_ok(), "Expected OK, got: {:?}", result.err());

        let verified = result.unwrap();
        assert!(verified.user_data.is_some());
        assert_eq!(verified.public_key, Some(vec![0xBB; 32]));
        assert_eq!(verified.nonce, Some(nonce.to_vec()));
        assert!(verified.measurements.is_empty());
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_wrong_issuer() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt(
            &enc_key,
            "https://evil.example.com",
            9999999999,
            &[&nonce_hex],
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("InvalidIssuer") || err.contains("issuer"),
            "Error: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_expired() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            1577836800,
            &[&nonce_hex],
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("ExpiredSignature") || err.contains("expired"),
            "Error: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_nonce_mismatch() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"correct-nonce";
        let jwt = make_test_jwt(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &["wrong-nonce-hex"],
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("eat_nonce"), "Error: {}", err);
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_unknown_platform() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
        );
        let mut envelope = make_cs_envelope(&jwt, nonce);
        envelope.platform = "unknown-platform".to_string();
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("Unknown attestation envelope platform"),
            "Error: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_cs_policy_pin_image_digest_match() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt_with_submods(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
            "sha256:abc123",
            "my-project",
            "us-central1-a",
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let policy = CsPolicy {
            expected_image_digest: Some("sha256:abc123".to_string()),
            expected_project: Some("my-project".to_string()),
            expected_zone: Some("us-central1-a".to_string()),
            ..Default::default()
        };
        let verifier = make_verifier(dec_key).with_cs_policy(policy);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_ok(), "Expected OK, got: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_cs_policy_pin_image_digest_mismatch() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt_with_submods(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
            "sha256:wrong",
            "my-project",
            "us-central1-a",
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let policy = CsPolicy {
            expected_image_digest: Some("sha256:abc123".to_string()),
            ..Default::default()
        };
        let verifier = make_verifier(dec_key).with_cs_policy(policy);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("image digest mismatch"), "Error: {}", err);
    }

    #[tokio::test]
    async fn test_cs_policy_pin_project_mismatch() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt_with_submods(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
            "sha256:abc123",
            "wrong-project",
            "us-central1-a",
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let policy = CsPolicy {
            expected_project: Some("my-project".to_string()),
            ..Default::default()
        };
        let verifier = make_verifier(dec_key).with_cs_policy(policy);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("project mismatch"), "Error: {}", err);
    }

    #[tokio::test]
    async fn test_cs_policy_pin_zone_mismatch() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt_with_submods(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
            "",
            "",
            "europe-west1-b",
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let policy = CsPolicy {
            expected_zone: Some("us-central1-a".to_string()),
            ..Default::default()
        };
        let verifier = make_verifier(dec_key).with_cs_policy(policy);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("zone mismatch"), "Error: {}", err);
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_malformed_cbor() {
        let (_enc_key, dec_key) = test_rsa_keys();
        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(vec![0xFF, 0xFE, 0xFD, 0x00]);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err(), "Expected error for malformed CBOR");
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_empty_document() {
        let (_enc_key, dec_key) = test_rsa_keys();
        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(vec![]);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err(), "Expected error for empty document");
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_cbor_integer() {
        let (_enc_key, dec_key) = test_rsa_keys();
        let verifier = make_verifier(dec_key);

        let cbor = ephemeral_ml_common::cbor::to_vec(&ciborium::Value::Integer(42.into())).unwrap();
        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err(), "Expected error for CBOR integer");
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_truncated_cbor() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let truncated = cbor[..cbor.len() / 2].to_vec();

        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(truncated);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err(), "Expected error for truncated CBOR");
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_jwt_missing_eat_nonce() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";

        // JWT with no eat_nonce field
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        let claims = serde_json::json!({
            "iss": "https://confidentialcomputing.googleapis.com",
            "exp": 9999999999u64,
        });
        let jwt = jsonwebtoken::encode(&header, &claims, &enc_key).unwrap();

        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("eat_nonce"),
            "Expected eat_nonce error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_jwt_empty_nonce_array() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        let claims = serde_json::json!({
            "iss": "https://confidentialcomputing.googleapis.com",
            "exp": 9999999999u64,
            "eat_nonce": [],
        });
        let jwt = jsonwebtoken::encode(&header, &claims, &enc_key).unwrap();

        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("eat_nonce"),
            "Expected eat_nonce error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_cs_policy_all_three_pins_mismatch_reports_first() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt_with_submods(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
            "sha256:wrong-digest",
            "wrong-project",
            "wrong-zone",
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let policy = CsPolicy {
            expected_image_digest: Some("sha256:correct-digest".to_string()),
            expected_project: Some("correct-project".to_string()),
            expected_zone: Some("correct-zone".to_string()),
            ..Default::default()
        };
        let verifier = make_verifier(dec_key).with_cs_policy(policy);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("mismatch"),
            "Expected mismatch error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_cs_policy_no_pins_accepts_any() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt_with_submods(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
            "sha256:anything",
            "any-project",
            "any-zone",
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let verifier = make_verifier(dec_key).with_cs_policy(CsPolicy::default());

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_ok(), "Expected OK, got: {:?}", result.err());
    }

    // --- New tests for JWKS signature verification ---

    #[tokio::test]
    async fn test_cs_envelope_reject_invalid_signature() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
        );

        // Tamper with the payload (flip a character in the middle)
        let parts: Vec<&str> = jwt.split('.').collect();
        let mut payload_bytes = parts[1].as_bytes().to_vec();
        if let Some(b) = payload_bytes.get_mut(10) {
            *b = if *b == b'A' { b'B' } else { b'A' };
        }
        let tampered_jwt = format!(
            "{}.{}.{}",
            parts[0],
            String::from_utf8(payload_bytes).unwrap(),
            parts[2]
        );

        let envelope = make_cs_envelope(&tampered_jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("signature verification failed") || err.contains("InvalidSignature"),
            "Expected signature error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_wrong_signing_key() {
        let (enc_key, _dec_key) = test_rsa_keys();
        let (_wrong_enc_key, wrong_dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);

        // Sign with enc_key, but verifier has wrong_dec_key
        let jwt = make_test_jwt(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        // Use the wrong decoding key in the verifier
        let verifier = make_verifier(wrong_dec_key);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("signature verification failed") || err.contains("InvalidSignature"),
            "Expected signature error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_missing_kid() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);

        // Create JWT without kid in header
        let mut header = Header::new(Algorithm::RS256);
        header.kid = None; // No kid
        let claims = serde_json::json!({
            "iss": "https://confidentialcomputing.googleapis.com",
            "exp": 9999999999u64,
            "eat_nonce": nonce_hex,
        });
        let jwt = jsonwebtoken::encode(&header, &claims, &enc_key).unwrap();

        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("missing key ID (kid)"),
            "Expected missing kid error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_unknown_kid() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);

        // Create JWT with a kid that's NOT in the cache
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("unknown-key-id".to_string());
        let claims = serde_json::json!({
            "iss": "https://confidentialcomputing.googleapis.com",
            "exp": 9999999999u64,
            "eat_nonce": nonce_hex,
        });
        let jwt = jsonwebtoken::encode(&header, &claims, &enc_key).unwrap();

        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        // Pre-populate cache with the correct key under TEST_KID,
        // but JWT uses "unknown-key-id" — should fail on cache lookup,
        // then fail on JWKS fetch (no network in tests).
        let verifier = make_verifier(dec_key);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("not found in JWKS") || err.contains("JWKS fetch failed"),
            "Expected unknown kid error, got: {}",
            err
        );
    }

    // --- Audience validation tests ---

    #[tokio::test]
    async fn test_cs_envelope_audience_match() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let policy = CsPolicy {
            expected_audience: Some("test".to_string()),
            ..Default::default()
        };
        let verifier = make_verifier(dec_key).with_cs_policy(policy);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_ok(), "Expected OK, got: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_cs_envelope_audience_mismatch() {
        let (enc_key, dec_key) = test_rsa_keys();
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        // JWT audience is "test" (set by make_test_jwt)
        let jwt = make_test_jwt(
            &enc_key,
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        let policy = CsPolicy {
            expected_audience: Some("//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/prov".to_string()),
            ..Default::default()
        };
        let verifier = make_verifier(dec_key).with_cs_policy(policy);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("InvalidAudience") || err.contains("audience"),
            "Expected audience error, got: {}",
            err
        );
    }
}
