//! Bridge between EphemeralML's COSE attestation verifier and cml-transport's
//! `AttestationVerifier` trait.
//!
//! `CoseVerifierBridge` wraps the existing 630-line COSE_Sign1 + cert chain +
//! PCR validation into cml-transport's `AttestationVerifier::verify()`.
//!
//! `MockVerifierBridge` delegates to cml-transport's `MockVerifier` for mock mode.

#[cfg(feature = "gcp")]
use ciborium::Value as CborValue;
use confidential_ml_transport::attestation::types::{
    AttestationDocument as CmlAttestationDocument, VerifiedAttestation,
};
use confidential_ml_transport::error::AttestError;
use confidential_ml_transport::AttestationVerifier as CmlAttestationVerifier;
use ephemeral_ml_common::transport_types::EphemeralUserData;
use ephemeral_ml_common::PcrMeasurements;
use std::collections::BTreeMap;
use std::sync::Mutex;

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
}

#[cfg(feature = "gcp")]
impl CsPolicy {
    /// Load policy pins from environment variables.
    ///
    /// - `EPHEMERALML_EXPECTED_IMAGE_DIGEST` — container image digest
    /// - `EPHEMERALML_EXPECTED_PROJECT` — GCE project ID
    /// - `EPHEMERALML_EXPECTED_ZONE` — GCE zone
    pub fn from_env() -> Self {
        Self {
            expected_image_digest: std::env::var("EPHEMERALML_EXPECTED_IMAGE_DIGEST").ok(),
            expected_project: std::env::var("EPHEMERALML_EXPECTED_PROJECT").ok(),
            expected_zone: std::env::var("EPHEMERALML_EXPECTED_ZONE").ok(),
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
    pub fn new(expected_mrtd: Option<Vec<u8>>) -> Self {
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
                panic!(
                    "No expected MRTD configured and MRTD pinning is required (default). \
                     Set EPHEMERALML_EXPECTED_MRTD (96 hex chars) for production use, \
                     or set EPHEMERALML_REQUIRE_MRTD=false for development."
                );
            }
            eprintln!(
                "[client] WARNING: No expected MRTD configured (EPHEMERALML_REQUIRE_MRTD=false). \
                 TDX peer measurements are NOT pinned. This is unsafe for production."
            );
        }

        Self {
            inner: confidential_ml_transport::attestation::tdx::TdxVerifier::new(mrtd),
            cs_expected_issuer: Self::CS_ISSUER.to_string(),
            cs_policy: CsPolicy::from_env(),
        }
    }

    /// Set CS policy pins explicitly (overrides env vars).
    pub fn with_cs_policy(mut self, policy: CsPolicy) -> Self {
        self.cs_policy = policy;
        self
    }

    /// Verify a CS transport attestation envelope.
    ///
    /// Validates:
    /// 1. Envelope structure (platform, key sizes, nonce non-empty)
    /// 2. JWT structure (3 dot-separated parts)
    /// 3. JWT claims: issuer, expiry
    /// 4. Nonce binding (eat_nonce matches envelope nonce)
    ///
    /// NOTE: JWT cryptographic signature verification (against Google OIDC JWKS)
    /// is not yet implemented. The JWT is trusted based on the CS Launcher
    /// socket being a local trusted path. Full JWKS verification is planned
    /// for a future release.
    fn verify_cs_envelope(
        &self,
        envelope: &ephemeral_ml_common::CsTransportAttestation,
        raw_bytes: &[u8],
    ) -> std::result::Result<VerifiedAttestation, AttestError> {
        // 1. Structural validation
        envelope.validate_structure().map_err(|e| {
            AttestError::VerificationFailed(format!("CS envelope structure invalid: {}", e))
        })?;

        // 2. Parse JWT claims (without cryptographic signature verification)
        let claims = parse_jwt_claims(&envelope.launcher_jwt).map_err(|e| {
            AttestError::VerificationFailed(format!("CS JWT claims parse failed: {}", e))
        })?;

        // 3. Validate issuer
        if claims.iss != self.cs_expected_issuer {
            return Err(AttestError::VerificationFailed(format!(
                "CS JWT issuer mismatch: got '{}', expected '{}'",
                claims.iss, self.cs_expected_issuer
            )));
        }

        // 4. Validate expiry (fail-closed: reject expired tokens)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if claims.exp > 0 && now >= claims.exp {
            return Err(AttestError::VerificationFailed(format!(
                "CS JWT expired: exp={}, now={}",
                claims.exp, now
            )));
        }

        // 5. Validate nonce binding (eat_nonce must contain the envelope nonce hex)
        let expected_nonce_hex = hex::encode(&envelope.nonce);
        if !expected_nonce_hex.is_empty() && !claims.eat_nonce.contains(&expected_nonce_hex) {
            return Err(AttestError::VerificationFailed(format!(
                "CS JWT eat_nonce does not contain expected handshake nonce. \
                 Expected: {}, Got: {:?}",
                expected_nonce_hex, claims.eat_nonce
            )));
        }

        // 6. Validate policy pins (fail-closed on mismatch)
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

        // 7. Build VerifiedAttestation
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
                        return self.verify_cs_envelope(&envelope, &doc.raw);
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
        let ud =
            serde_json::from_slice::<EphemeralUserData>(&envelope.user_data).map_err(|e| {
                AttestError::VerificationFailed(format!(
                    "TDX envelope user_data parse failed: {}",
                    e
                ))
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
#[cfg(feature = "gcp")]
#[derive(serde::Deserialize, Debug)]
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

/// Parse JWT claims from a JWT string (without signature verification).
///
/// Decodes the base64url payload and extracts issuer, expiry, and eat_nonce.
/// Does NOT verify the JWT signature — the caller is responsible for that.
#[cfg(feature = "gcp")]
fn parse_jwt_claims(jwt: &str) -> std::result::Result<CsJwtClaims, String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("Invalid JWT: expected 3 parts, got {}", parts.len()));
    }

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("JWT payload base64 decode failed: {}", e))?;

    serde_json::from_slice(&payload).map_err(|e| format!("JWT claims parse failed: {}", e))
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

    fn make_test_jwt(issuer: &str, exp: u64, nonces: &[&str]) -> String {
        make_test_jwt_with_submods(issuer, exp, nonces, "", "", "")
    }

    fn make_test_jwt_with_submods(
        issuer: &str,
        exp: u64,
        nonces: &[&str],
        image_digest: &str,
        project_id: &str,
        zone: &str,
    ) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let nonce_json = if nonces.len() == 1 {
            format!("\"{}\"", nonces[0])
        } else {
            let items: Vec<String> = nonces.iter().map(|n| format!("\"{}\"", n)).collect();
            format!("[{}]", items.join(","))
        };
        let claims = format!(
            "{{\"iss\":\"{}\",\"exp\":{},\"eat_nonce\":{},\"aud\":\"test\",\
             \"submods\":{{\"container\":{{\"image_digest\":\"{}\"}},\
             \"gce\":{{\"project_id\":\"{}\",\"zone\":\"{}\"}}}}}}",
            issuer, exp, nonce_json, image_digest, project_id, zone
        );
        let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"fake-signature");
        format!("{}.{}.{}", header, payload, sig)
    }

    fn make_cs_envelope(jwt: &str, nonce: &[u8]) -> CsTransportAttestation {
        CsTransportAttestation::new(jwt.to_string(), [0xAA; 32], vec![0xBB; 32], nonce.to_vec())
    }

    #[tokio::test]
    async fn test_cs_envelope_verify_valid() {
        let nonce = b"test-nonce-value";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt(
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        // Create verifier (MRTD not needed for CS mode)
        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let verifier = TdxEnvelopeVerifierBridge::new(None);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_ok(), "Expected OK, got: {:?}", result.err());

        let verified = result.unwrap();
        // Should have user_data with receipt signing key
        assert!(verified.user_data.is_some());
        // Should have handshake public key
        assert_eq!(verified.public_key, Some(vec![0xBB; 32]));
        // Nonce should be set
        assert_eq!(verified.nonce, Some(nonce.to_vec()));
        // Measurements should be empty for CS mode
        assert!(verified.measurements.is_empty());
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_wrong_issuer() {
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt("https://evil.example.com", 9999999999, &[&nonce_hex]);
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let verifier = TdxEnvelopeVerifierBridge::new(None);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("issuer mismatch"), "Error: {}", err);
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_expired() {
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        // Expired in 2020
        let jwt = make_test_jwt(
            "https://confidentialcomputing.googleapis.com",
            1577836800,
            &[&nonce_hex],
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let verifier = TdxEnvelopeVerifierBridge::new(None);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("expired"), "Error: {}", err);
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_nonce_mismatch() {
        let nonce = b"correct-nonce";
        // JWT has a different nonce
        let jwt = make_test_jwt(
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &["wrong-nonce-hex"],
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let verifier = TdxEnvelopeVerifierBridge::new(None);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("eat_nonce"), "Error: {}", err);
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_unknown_platform() {
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt(
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
        );
        let mut envelope = make_cs_envelope(&jwt, nonce);
        envelope.platform = "unknown-platform".to_string();
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let verifier = TdxEnvelopeVerifierBridge::new(None);

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

    #[test]
    fn test_parse_jwt_claims_valid() {
        let jwt = make_test_jwt(
            "https://confidentialcomputing.googleapis.com",
            1721330075,
            &["nonce-1", "nonce-2"],
        );
        let claims = parse_jwt_claims(&jwt).unwrap();
        assert_eq!(claims.iss, "https://confidentialcomputing.googleapis.com");
        assert_eq!(claims.exp, 1721330075);
        assert_eq!(claims.eat_nonce, vec!["nonce-1", "nonce-2"]);
    }

    #[test]
    fn test_parse_jwt_claims_single_nonce() {
        let jwt = make_test_jwt(
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &["single-nonce"],
        );
        let claims = parse_jwt_claims(&jwt).unwrap();
        assert_eq!(claims.eat_nonce, vec!["single-nonce"]);
    }

    #[test]
    fn test_parse_jwt_claims_invalid() {
        assert!(parse_jwt_claims("not-a-jwt").is_err());
        assert!(parse_jwt_claims("a.b").is_err());
    }

    #[tokio::test]
    async fn test_cs_policy_pin_image_digest_match() {
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt_with_submods(
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
            "sha256:abc123",
            "my-project",
            "us-central1-a",
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let policy = CsPolicy {
            expected_image_digest: Some("sha256:abc123".to_string()),
            expected_project: Some("my-project".to_string()),
            expected_zone: Some("us-central1-a".to_string()),
        };
        let verifier = TdxEnvelopeVerifierBridge::new(None).with_cs_policy(policy);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_ok(), "Expected OK, got: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_cs_policy_pin_image_digest_mismatch() {
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt_with_submods(
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
            "sha256:wrong",
            "my-project",
            "us-central1-a",
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let policy = CsPolicy {
            expected_image_digest: Some("sha256:abc123".to_string()),
            ..Default::default()
        };
        let verifier = TdxEnvelopeVerifierBridge::new(None).with_cs_policy(policy);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("image digest mismatch"), "Error: {}", err);
    }

    #[tokio::test]
    async fn test_cs_policy_pin_project_mismatch() {
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt_with_submods(
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
            "sha256:abc123",
            "wrong-project",
            "us-central1-a",
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let policy = CsPolicy {
            expected_project: Some("my-project".to_string()),
            ..Default::default()
        };
        let verifier = TdxEnvelopeVerifierBridge::new(None).with_cs_policy(policy);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("project mismatch"), "Error: {}", err);
    }

    #[tokio::test]
    async fn test_cs_policy_pin_zone_mismatch() {
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt_with_submods(
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
            "",
            "",
            "europe-west1-b",
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let policy = CsPolicy {
            expected_zone: Some("us-central1-a".to_string()),
            ..Default::default()
        };
        let verifier = TdxEnvelopeVerifierBridge::new(None).with_cs_policy(policy);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("zone mismatch"), "Error: {}", err);
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_malformed_cbor() {
        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let verifier = TdxEnvelopeVerifierBridge::new(None);

        // Random bytes — not valid CBOR
        let doc = CmlAttestationDocument::new(vec![0xFF, 0xFE, 0xFD, 0x00]);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err(), "Expected error for malformed CBOR");
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_empty_document() {
        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let verifier = TdxEnvelopeVerifierBridge::new(None);

        let doc = CmlAttestationDocument::new(vec![]);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err(), "Expected error for empty document");
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_cbor_integer() {
        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let verifier = TdxEnvelopeVerifierBridge::new(None);

        // CBOR integer (not a map)
        let cbor = ephemeral_ml_common::cbor::to_vec(&ciborium::Value::Integer(42.into())).unwrap();
        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err(), "Expected error for CBOR integer");
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_truncated_cbor() {
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt(
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        // Truncate to half
        let truncated = cbor[..cbor.len() / 2].to_vec();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let verifier = TdxEnvelopeVerifierBridge::new(None);

        let doc = CmlAttestationDocument::new(truncated);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err(), "Expected error for truncated CBOR");
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_jwt_missing_iss() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);

        // JWT with no `iss` field
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let claims = format!(
            "{{\"exp\":9999999999,\"eat_nonce\":\"{}\"}}",
            nonce_hex
        );
        let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"fake");
        let jwt = format!("{}.{}.{}", header, payload, sig);

        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let verifier = TdxEnvelopeVerifierBridge::new(None);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        // Should fail because issuer is empty/missing
        assert!(
            err.contains("issuer mismatch") || err.contains("iss"),
            "Error: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_cs_envelope_reject_jwt_missing_eat_nonce() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let nonce = b"nonce";

        // JWT with no `eat_nonce` field
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let claims = "{\"iss\":\"https://confidentialcomputing.googleapis.com\",\"exp\":9999999999}";
        let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"fake");
        let jwt = format!("{}.{}.{}", header, payload, sig);

        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let verifier = TdxEnvelopeVerifierBridge::new(None);

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
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let nonce = b"nonce";

        // JWT with empty eat_nonce array
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        let claims = "{\"iss\":\"https://confidentialcomputing.googleapis.com\",\"exp\":9999999999,\"eat_nonce\":[]}";
        let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"fake");
        let jwt = format!("{}.{}.{}", header, payload, sig);

        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let verifier = TdxEnvelopeVerifierBridge::new(None);

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
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt_with_submods(
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
            "sha256:wrong-digest",
            "wrong-project",
            "wrong-zone",
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        let policy = CsPolicy {
            expected_image_digest: Some("sha256:correct-digest".to_string()),
            expected_project: Some("correct-project".to_string()),
            expected_zone: Some("correct-zone".to_string()),
        };
        let verifier = TdxEnvelopeVerifierBridge::new(None).with_cs_policy(policy);

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_err());
        // Should fail on first policy check (image_digest)
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("mismatch"),
            "Expected mismatch error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_cs_policy_no_pins_accepts_any() {
        let nonce = b"nonce";
        let nonce_hex = hex::encode(nonce);
        let jwt = make_test_jwt_with_submods(
            "https://confidentialcomputing.googleapis.com",
            9999999999,
            &[&nonce_hex],
            "sha256:anything",
            "any-project",
            "any-zone",
        );
        let envelope = make_cs_envelope(&jwt, nonce);
        let cbor = envelope.to_cbor_deterministic().unwrap();

        std::env::set_var("EPHEMERALML_REQUIRE_MRTD", "false");
        // No policy pins set — should accept any values
        let verifier = TdxEnvelopeVerifierBridge::new(None)
            .with_cs_policy(CsPolicy::default());

        let doc = CmlAttestationDocument::new(cbor);
        let result = verifier.verify(&doc).await;
        assert!(result.is_ok(), "Expected OK, got: {:?}", result.err());
    }
}
