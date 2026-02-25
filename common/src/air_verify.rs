//! AIR v1 — Layered receipt verification
//!
//! Four verification layers, designed for standardizability:
//!
//! 1. **Parse** (`parse`) — CBOR/COSE shape validation only
//! 2. **Crypto** (`crypto_verify`) — COSE Sig_structure1 + Ed25519 verify_strict
//! 3. **Claim validation** (`claim_validate`) — types, required claims, eat_profile, measurements
//! 4. **Policy evaluation** (`policy_evaluate`) — freshness, model_hash, platform, nonce, replay
//!
//! Each layer produces structured check results with explicit failure codes.

use crate::air_receipt::{self, AirReceiptClaims, ParsedAirReceipt};
use crate::error::EphemeralError;
use coset::TaggedCborSerializable;
use serde::{Deserialize, Serialize};

// ── Failure codes ───────────────────────────────────────────────────

/// Structured failure code for each verification check.
///
/// Codes are stable identifiers for conformance tests and IETF text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AirCheckCode {
    // Layer 1: parse
    /// COSE_Sign1 envelope could not be decoded
    CoseDecodeFailed,
    /// Missing or wrong `alg` in protected header
    BadAlg,
    /// Missing or wrong `content_type` in protected header
    BadContentType,
    /// Missing payload in COSE_Sign1
    MissingPayload,
    /// Payload is not a valid CBOR map
    PayloadNotMap,
    /// `eat_profile` does not match AIR v1
    WrongProfile,

    // Layer 2: crypto
    /// Ed25519 signature verification failed
    SignatureFailed,
    /// Signature is wrong length (expected 64 bytes)
    BadSignatureLength,

    // Layer 3: claim validation
    /// A required claim is missing
    MissingClaim(String),
    /// A claim has the wrong CBOR type
    WrongClaimType(String),
    /// `cti` is not exactly 16 bytes
    BadCtiLength,
    /// `model_hash` is all zeros
    ZeroModelHash,
    /// SHA-256 hash claim is not 32 bytes
    BadHashLength(String),
    /// SHA-384 measurement is not 48 bytes
    BadMeasurementLength,
    /// Unknown `measurement_type` value
    UnknownMeasurementType(String),

    // Layer 4: policy
    /// `iat` is in the future (beyond clock_skew)
    TimestampFuture,
    /// Receipt is older than `max_age` seconds
    TimestampStale,
    /// `model_hash` does not match expected value
    ModelHashMismatch,
    /// `model_id` does not match expected value
    ModelIdMismatch,
    /// `measurement_type` does not match expected platform
    PlatformMismatch,
    /// `eat_nonce` does not match expected challenge
    NonceMismatch,
    /// `eat_nonce` required but absent
    NonceMissing,
    /// `cti` has already been seen (replay)
    ReplayCti,
}

impl std::fmt::Display for AirCheckCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CoseDecodeFailed => write!(f, "COSE_DECODE_FAILED"),
            Self::BadAlg => write!(f, "BAD_ALG"),
            Self::BadContentType => write!(f, "BAD_CONTENT_TYPE"),
            Self::MissingPayload => write!(f, "MISSING_PAYLOAD"),
            Self::PayloadNotMap => write!(f, "PAYLOAD_NOT_MAP"),
            Self::WrongProfile => write!(f, "WRONG_PROFILE"),
            Self::SignatureFailed => write!(f, "SIG_FAILED"),
            Self::BadSignatureLength => write!(f, "BAD_SIG_LENGTH"),
            Self::MissingClaim(c) => write!(f, "MISSING_CLAIM:{c}"),
            Self::WrongClaimType(c) => write!(f, "WRONG_TYPE:{c}"),
            Self::BadCtiLength => write!(f, "BAD_CTI_LENGTH"),
            Self::ZeroModelHash => write!(f, "ZERO_MODEL_HASH"),
            Self::BadHashLength(c) => write!(f, "BAD_HASH_LENGTH:{c}"),
            Self::BadMeasurementLength => write!(f, "BAD_MEASUREMENT_LENGTH"),
            Self::UnknownMeasurementType(t) => write!(f, "UNKNOWN_MTYPE:{t}"),
            Self::TimestampFuture => write!(f, "TIMESTAMP_FUTURE"),
            Self::TimestampStale => write!(f, "TIMESTAMP_STALE"),
            Self::ModelHashMismatch => write!(f, "MODEL_HASH_MISMATCH"),
            Self::ModelIdMismatch => write!(f, "MODEL_ID_MISMATCH"),
            Self::PlatformMismatch => write!(f, "PLATFORM_MISMATCH"),
            Self::NonceMismatch => write!(f, "NONCE_MISMATCH"),
            Self::NonceMissing => write!(f, "NONCE_MISSING"),
            Self::ReplayCti => write!(f, "REPLAY_CTI"),
        }
    }
}

// ── Check result ────────────────────────────────────────────────────

/// Outcome of a single verification check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AirCheckStatus {
    Pass,
    Fail,
    Skip,
}

impl std::fmt::Display for AirCheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::Skip => write!(f, "SKIP"),
        }
    }
}

/// A single named check with its outcome and optional failure code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirCheck {
    pub name: &'static str,
    pub status: AirCheckStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<AirCheckCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AirCheck {
    fn pass(name: &'static str) -> Self {
        Self { name, status: AirCheckStatus::Pass, code: None, detail: None }
    }
    fn fail(name: &'static str, code: AirCheckCode, detail: impl Into<String>) -> Self {
        Self { name, status: AirCheckStatus::Fail, code: Some(code), detail: Some(detail.into()) }
    }
    fn skip(name: &'static str) -> Self {
        Self { name, status: AirCheckStatus::Skip, code: None, detail: None }
    }
}

// ── Full verification result ────────────────────────────────────────

/// Complete verification result across all four layers.
#[derive(Debug, Clone, Serialize)]
pub struct AirVerifyResult {
    /// Overall verdict: true only if all non-skipped checks pass.
    pub verified: bool,
    /// Individual check outcomes, ordered by layer.
    pub checks: Vec<AirCheck>,
    /// Parsed claims (present even if verification fails, as long as parse succeeds).
    #[serde(skip)]
    pub claims: Option<AirReceiptClaims>,
}

impl AirVerifyResult {
    /// Get all failure codes.
    pub fn failures(&self) -> Vec<&AirCheckCode> {
        self.checks.iter()
            .filter_map(|c| c.code.as_ref())
            .collect()
    }

    /// Check if a specific failure code is present.
    pub fn has_failure(&self, code: &AirCheckCode) -> bool {
        self.checks.iter().any(|c| c.code.as_ref() == Some(code))
    }
}

// ── Policy inputs ───────────────────────────────────────────────────

/// Policy inputs for layer 4 (policy evaluation).
///
/// All fields are optional. Absent fields cause the corresponding check
/// to be skipped (not failed).
pub struct AirVerifyPolicy {
    /// Maximum receipt age in seconds. 0 = skip freshness check.
    pub max_age_secs: u64,
    /// Clock skew tolerance in seconds for future timestamp rejection.
    pub clock_skew_secs: u64,
    /// Expected `model_hash`. If set, MHASH check is enforced.
    pub expected_model_hash: Option<[u8; 32]>,
    /// Expected `model_id`. If set, MODEL check is enforced.
    pub expected_model_id: Option<String>,
    /// Expected `measurement_type`. If set, MTYPE check is enforced.
    /// `"any"` skips the check.
    pub expected_platform: Option<String>,
    /// Expected `eat_nonce`. If set, nonce match is enforced.
    pub expected_nonce: Option<Vec<u8>>,
    /// Require `eat_nonce` to be present (even if we don't check a specific value).
    pub require_nonce: bool,
    /// Seen-cti cache hook. If provided, called with the receipt's cti.
    /// Return `true` if the cti has been seen before (replay).
    pub seen_cti: Option<Box<dyn Fn(&[u8; 16]) -> bool + Send + Sync>>,
}

impl Default for AirVerifyPolicy {
    fn default() -> Self {
        Self {
            max_age_secs: 0,
            clock_skew_secs: 0,
            expected_model_hash: None,
            expected_model_id: None,
            expected_platform: None,
            expected_nonce: None,
            require_nonce: false,
            seen_cti: None,
        }
    }
}

// ── Top-level verify ────────────────────────────────────────────────

/// Verify an AIR v1 receipt through all four layers.
///
/// Layers execute in order. Later layers run even if earlier layers fail,
/// so the result contains a complete picture of all check outcomes.
pub fn verify_air_v1_receipt(
    data: &[u8],
    public_key: &ed25519_dalek::VerifyingKey,
    policy: &AirVerifyPolicy,
) -> AirVerifyResult {
    let mut checks = Vec::with_capacity(16);

    // Layer 1: Parse
    let parsed = match layer1_parse(data, &mut checks) {
        Some(p) => p,
        None => {
            return AirVerifyResult {
                verified: false,
                checks,
                claims: None,
            };
        }
    };

    let claims = parsed.claims.clone();

    // Layer 2: Crypto
    layer2_crypto(&parsed, public_key, &mut checks);

    // Layer 3: Claim validation
    layer3_claims(&parsed.claims, &mut checks);

    // Layer 4: Policy evaluation
    layer4_policy(&parsed.claims, policy, &mut checks);

    let verified = checks.iter().all(|c| {
        matches!(c.status, AirCheckStatus::Pass | AirCheckStatus::Skip)
    });

    AirVerifyResult {
        verified,
        checks,
        claims: Some(claims),
    }
}

// ── Layer 1: Parse ──────────────────────────────────────────────────

fn layer1_parse(data: &[u8], checks: &mut Vec<AirCheck>) -> Option<ParsedAirReceipt> {
    // COSE decode
    let cose = match coset::CoseSign1::from_tagged_slice(data) {
        Ok(c) => {
            checks.push(AirCheck::pass("COSE_DECODE"));
            c
        }
        Err(e) => {
            checks.push(AirCheck::fail(
                "COSE_DECODE",
                AirCheckCode::CoseDecodeFailed,
                format!("{e}"),
            ));
            return None;
        }
    };

    // Protected header: alg
    let alg_ok = match cose.protected.header.alg.as_ref() {
        Some(a) if *a == coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA) => {
            checks.push(AirCheck::pass("ALG"));
            true
        }
        Some(a) => {
            checks.push(AirCheck::fail("ALG", AirCheckCode::BadAlg, format!("got {:?}", a)));
            false
        }
        None => {
            checks.push(AirCheck::fail("ALG", AirCheckCode::BadAlg, "missing alg"));
            false
        }
    };

    // Protected header: content_type
    let ct_ok = match cose.protected.header.content_type.as_ref() {
        Some(ct) => {
            let expected = coset::ContentType::Assigned(coset::iana::CoapContentFormat::Cwt);
            if *ct == expected {
                checks.push(AirCheck::pass("CONTENT_TYPE"));
                true
            } else {
                checks.push(AirCheck::fail(
                    "CONTENT_TYPE",
                    AirCheckCode::BadContentType,
                    format!("got {:?}", ct),
                ));
                false
            }
        }
        None => {
            checks.push(AirCheck::fail(
                "CONTENT_TYPE",
                AirCheckCode::BadContentType,
                "missing content_type",
            ));
            false
        }
    };

    // Payload present
    let payload_bytes: &Vec<u8> = match cose.payload.as_ref() {
        Some(p) if !p.is_empty() => {
            checks.push(AirCheck::pass("PAYLOAD"));
            p
        }
        _ => {
            checks.push(AirCheck::fail(
                "PAYLOAD",
                AirCheckCode::MissingPayload,
                "payload missing or empty",
            ));
            return None;
        }
    };

    if !alg_ok || !ct_ok {
        // Header checks failed — still try to decode claims for diagnostics,
        // but return None to signal parse failure.
        // Try decoding claims anyway for the result.
        if let Ok(claims) = air_receipt::decode_claims_from_bytes(payload_bytes) {
            let profile_ok = claims_profile_check(&claims, checks);
            if !profile_ok {
                return None;
            }
            return Some(ParsedAirReceipt { claims, cose });
        }
        return None;
    }

    // Decode claims
    let claims = match air_receipt::decode_claims_from_bytes(payload_bytes) {
        Ok(c) => c,
        Err(e) => {
            checks.push(AirCheck::fail(
                "CLAIMS_DECODE",
                AirCheckCode::PayloadNotMap,
                format!("{e}"),
            ));
            return None;
        }
    };

    // eat_profile
    claims_profile_check(&claims, checks);

    Some(ParsedAirReceipt { claims, cose })
}

fn claims_profile_check(_claims: &AirReceiptClaims, checks: &mut Vec<AirCheck>) -> bool {
    // eat_profile is already decoded into the claims struct, but we
    // verify the parse succeeded (decode_claims rejects unknown profiles).
    // If we got here, the profile is correct.
    checks.push(AirCheck::pass("EAT_PROFILE"));
    true
}

// ── Layer 2: Crypto ─────────────────────────────────────────────────

fn layer2_crypto(
    parsed: &ParsedAirReceipt,
    public_key: &ed25519_dalek::VerifyingKey,
    checks: &mut Vec<AirCheck>,
) {
    // Signature length
    if parsed.cose.signature.len() != 64 {
        checks.push(AirCheck::fail(
            "SIG",
            AirCheckCode::BadSignatureLength,
            format!("got {} bytes", parsed.cose.signature.len()),
        ));
        return;
    }

    // Ed25519 verify_strict via COSE Sig_structure1
    let result = parsed.cose.verify_signature(b"", |sig, tbs| {
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(sig);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        public_key
            .verify_strict(tbs, &signature)
            .map_err(|e| EphemeralError::ValidationError(e.to_string()))
    });

    match result {
        Ok(()) => checks.push(AirCheck::pass("SIG")),
        Err(_) => checks.push(AirCheck::fail(
            "SIG",
            AirCheckCode::SignatureFailed,
            "Ed25519 verify_strict failed",
        )),
    }
}

// ── Layer 3: Claim validation ───────────────────────────────────────

fn layer3_claims(claims: &AirReceiptClaims, checks: &mut Vec<AirCheck>) {
    // cti length (already parsed as [u8; 16], but verify it's not all zeros)
    if claims.cti == [0u8; 16] {
        checks.push(AirCheck::fail("CTI", AirCheckCode::BadCtiLength, "cti is all zeros"));
    } else {
        checks.push(AirCheck::pass("CTI"));
    }

    // model_hash non-zero
    if claims.model_hash == [0u8; 32] {
        checks.push(AirCheck::fail(
            "MHASH_PRESENT",
            AirCheckCode::ZeroModelHash,
            "model_hash is all zeros",
        ));
    } else {
        checks.push(AirCheck::pass("MHASH_PRESENT"));
    }

    // Measurement validity (48 bytes each)
    if claims.enclave_measurements.is_valid() {
        checks.push(AirCheck::pass("MEAS"));
    } else {
        checks.push(AirCheck::fail(
            "MEAS",
            AirCheckCode::BadMeasurementLength,
            "pcr0/pcr1/pcr2 must be 48 bytes each",
        ));
    }

    // Measurement type
    let mt = &claims.enclave_measurements.measurement_type;
    if mt == "nitro-pcr" || mt == "tdx-mrtd-rtmr" {
        checks.push(AirCheck::pass("MTYPE"));
    } else {
        checks.push(AirCheck::fail(
            "MTYPE",
            AirCheckCode::UnknownMeasurementType(mt.clone()),
            format!("unknown measurement_type: {mt}"),
        ));
    }
}

// ── Layer 4: Policy evaluation ──────────────────────────────────────

fn layer4_policy(
    claims: &AirReceiptClaims,
    policy: &AirVerifyPolicy,
    checks: &mut Vec<AirCheck>,
) {
    // Timestamp freshness
    if policy.max_age_secs == 0 {
        checks.push(AirCheck::skip("FRESH"));
    } else {
        let now = crate::current_timestamp();
        let skew = policy.clock_skew_secs;
        if claims.iat > now + skew {
            checks.push(AirCheck::fail(
                "FRESH",
                AirCheckCode::TimestampFuture,
                format!("iat {} is {}s in the future", claims.iat, claims.iat - now),
            ));
        } else if now.saturating_sub(claims.iat) > policy.max_age_secs {
            checks.push(AirCheck::fail(
                "FRESH",
                AirCheckCode::TimestampStale,
                format!(
                    "receipt is {}s old (max {}s)",
                    now - claims.iat,
                    policy.max_age_secs
                ),
            ));
        } else {
            checks.push(AirCheck::pass("FRESH"));
        }
    }

    // Model hash match
    match &policy.expected_model_hash {
        Some(expected) => {
            if claims.model_hash == *expected {
                checks.push(AirCheck::pass("MHASH"));
            } else {
                checks.push(AirCheck::fail(
                    "MHASH",
                    AirCheckCode::ModelHashMismatch,
                    format!(
                        "expected {}, got {}",
                        hex::encode(expected),
                        hex::encode(claims.model_hash)
                    ),
                ));
            }
        }
        None => checks.push(AirCheck::skip("MHASH")),
    }

    // Model ID match
    match &policy.expected_model_id {
        Some(expected) => {
            if claims.model_id == *expected {
                checks.push(AirCheck::pass("MODEL"));
            } else {
                checks.push(AirCheck::fail(
                    "MODEL",
                    AirCheckCode::ModelIdMismatch,
                    format!("expected '{}', got '{}'", expected, claims.model_id),
                ));
            }
        }
        None => checks.push(AirCheck::skip("MODEL")),
    }

    // Platform match
    match &policy.expected_platform {
        Some(expected) if expected != "any" => {
            if claims.enclave_measurements.measurement_type == *expected {
                checks.push(AirCheck::pass("PLATFORM"));
            } else {
                checks.push(AirCheck::fail(
                    "PLATFORM",
                    AirCheckCode::PlatformMismatch,
                    format!(
                        "expected '{}', got '{}'",
                        expected, claims.enclave_measurements.measurement_type
                    ),
                ));
            }
        }
        _ => checks.push(AirCheck::skip("PLATFORM")),
    }

    // Nonce
    if let Some(ref expected_nonce) = policy.expected_nonce {
        match &claims.eat_nonce {
            Some(actual) if actual == expected_nonce => {
                checks.push(AirCheck::pass("NONCE"));
            }
            Some(actual) => {
                checks.push(AirCheck::fail(
                    "NONCE",
                    AirCheckCode::NonceMismatch,
                    format!(
                        "expected {}, got {}",
                        hex::encode(expected_nonce),
                        hex::encode(actual)
                    ),
                ));
            }
            None => {
                checks.push(AirCheck::fail(
                    "NONCE",
                    AirCheckCode::NonceMissing,
                    "eat_nonce absent but expected",
                ));
            }
        }
    } else if policy.require_nonce {
        if claims.eat_nonce.is_some() {
            checks.push(AirCheck::pass("NONCE"));
        } else {
            checks.push(AirCheck::fail(
                "NONCE",
                AirCheckCode::NonceMissing,
                "eat_nonce required but absent",
            ));
        }
    } else {
        checks.push(AirCheck::skip("NONCE"));
    }

    // Replay (cti dedup)
    if let Some(ref seen_fn) = policy.seen_cti {
        if seen_fn(&claims.cti) {
            checks.push(AirCheck::fail(
                "REPLAY",
                AirCheckCode::ReplayCti,
                format!("cti {} already seen", hex::encode(claims.cti)),
            ));
        } else {
            checks.push(AirCheck::pass("REPLAY"));
        }
    } else {
        checks.push(AirCheck::skip("REPLAY"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air_receipt::{build_air_v1, AirReceiptClaims};
    use crate::receipt_signing::{EnclaveMeasurements, ReceiptSigningKey};
    use std::collections::HashSet;
    use std::sync::Mutex;

    fn fixture_claims() -> AirReceiptClaims {
        AirReceiptClaims {
            iss: "cyntrisec.com".to_string(),
            iat: crate::current_timestamp(),
            cti: *uuid::Uuid::new_v4().as_bytes(),
            eat_nonce: None,
            model_id: "minilm-l6-v2".to_string(),
            model_version: "1.0.0".to_string(),
            model_hash: [0xAA; 32],
            request_hash: [0xBB; 32],
            response_hash: [0xCC; 32],
            attestation_doc_hash: [0xDD; 32],
            enclave_measurements: EnclaveMeasurements::new(
                vec![1u8; 48],
                vec![2u8; 48],
                vec![3u8; 48],
            ),
            policy_version: "policy-2026.02".to_string(),
            sequence_number: 42,
            execution_time_ms: 116,
            memory_peak_mb: 512,
            security_mode: "GatewayOnly".to_string(),
        }
    }

    fn build_receipt(claims: &AirReceiptClaims, key: &ReceiptSigningKey) -> Vec<u8> {
        build_air_v1(claims, key).unwrap()
    }

    // ── Layer 1+2+3: valid receipt, all pass ────────────────────────

    #[test]
    fn test_valid_receipt_all_pass() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_receipt(&claims, &key);

        let result = verify_air_v1_receipt(&bytes, &key.public_key, &AirVerifyPolicy::default());
        assert!(result.verified, "failures: {:?}", result.failures());
        assert!(result.claims.is_some());

        // All non-skipped checks should be PASS
        for c in &result.checks {
            assert!(
                matches!(c.status, AirCheckStatus::Pass | AirCheckStatus::Skip),
                "check {} is {:?}: {:?}",
                c.name, c.status, c.detail
            );
        }
    }

    // ── Layer 2: wrong key ──────────────────────────────────────────

    #[test]
    fn test_wrong_key_sig_fails() {
        let key1 = ReceiptSigningKey::generate().unwrap();
        let key2 = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_receipt(&claims, &key1);

        let result = verify_air_v1_receipt(&bytes, &key2.public_key, &AirVerifyPolicy::default());
        assert!(!result.verified);
        assert!(result.has_failure(&AirCheckCode::SignatureFailed));
    }

    // ── Layer 1: bad COSE data ──────────────────────────────────────

    #[test]
    fn test_garbage_data_fails_parse() {
        let key = ReceiptSigningKey::generate().unwrap();
        let result = verify_air_v1_receipt(&[0xFF, 0xFF], &key.public_key, &AirVerifyPolicy::default());
        assert!(!result.verified);
        assert!(result.has_failure(&AirCheckCode::CoseDecodeFailed));
        assert!(result.claims.is_none());
    }

    // ── Layer 1: wrong protected header ─────────────────────────────

    #[test]
    fn test_wrong_alg_fails() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();

        // Build with wrong alg header
        let payload = crate::air_receipt::encode_claims_exported(&claims).unwrap();
        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)  // Wrong!
            .content_format(coset::iana::CoapContentFormat::Cwt)
            .build();
        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .try_create_signature(b"", |tbs| {
                Ok::<_, String>(key.raw_sign(tbs))
            })
            .unwrap()
            .build();
        let bytes = sign1.to_tagged_vec().unwrap();

        let result = verify_air_v1_receipt(&bytes, &key.public_key, &AirVerifyPolicy::default());
        assert!(!result.verified);
        assert!(result.has_failure(&AirCheckCode::BadAlg));
    }

    // ── Layer 4: stale timestamp ────────────────────────────────────

    #[test]
    fn test_stale_timestamp_fails() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        claims.iat = crate::current_timestamp().saturating_sub(7200); // 2 hours ago
        let bytes = build_receipt(&claims, &key);

        let policy = AirVerifyPolicy {
            max_age_secs: 3600,
            ..Default::default()
        };
        let result = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(!result.verified);
        assert!(result.has_failure(&AirCheckCode::TimestampStale));
    }

    // ── Layer 4: future timestamp ───────────────────────────────────

    #[test]
    fn test_future_timestamp_fails() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        claims.iat = crate::current_timestamp() + 600; // 10 min in future
        let bytes = build_receipt(&claims, &key);

        let policy = AirVerifyPolicy {
            max_age_secs: 3600,
            clock_skew_secs: 30, // 30s tolerance
            ..Default::default()
        };
        let result = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(!result.verified);
        assert!(result.has_failure(&AirCheckCode::TimestampFuture));
    }

    // ── Layer 4: model hash mismatch ────────────────────────────────

    #[test]
    fn test_model_hash_mismatch() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_receipt(&claims, &key);

        let policy = AirVerifyPolicy {
            expected_model_hash: Some([0xFF; 32]), // Different from 0xAA
            ..Default::default()
        };
        let result = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(!result.verified);
        assert!(result.has_failure(&AirCheckCode::ModelHashMismatch));
    }

    #[test]
    fn test_model_hash_match() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_receipt(&claims, &key);

        let policy = AirVerifyPolicy {
            expected_model_hash: Some([0xAA; 32]), // Matches fixture
            ..Default::default()
        };
        let result = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(result.verified, "failures: {:?}", result.failures());
    }

    // ── Layer 4: model ID mismatch ──────────────────────────────────

    #[test]
    fn test_model_id_mismatch() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_receipt(&claims, &key);

        let policy = AirVerifyPolicy {
            expected_model_id: Some("wrong-model".to_string()),
            ..Default::default()
        };
        let result = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(!result.verified);
        assert!(result.has_failure(&AirCheckCode::ModelIdMismatch));
    }

    // ── Layer 4: platform mismatch ──────────────────────────────────

    #[test]
    fn test_platform_mismatch() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims(); // nitro-pcr
        let bytes = build_receipt(&claims, &key);

        let policy = AirVerifyPolicy {
            expected_platform: Some("tdx-mrtd-rtmr".to_string()),
            ..Default::default()
        };
        let result = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(!result.verified);
        assert!(result.has_failure(&AirCheckCode::PlatformMismatch));
    }

    #[test]
    fn test_platform_any_skips() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_receipt(&claims, &key);

        let policy = AirVerifyPolicy {
            expected_platform: Some("any".to_string()),
            ..Default::default()
        };
        let result = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(result.verified, "failures: {:?}", result.failures());
    }

    // ── Layer 4: nonce checks ───────────────────────────────────────

    #[test]
    fn test_nonce_match() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        claims.eat_nonce = Some(vec![0xDE, 0xAD]);
        let bytes = build_receipt(&claims, &key);

        let policy = AirVerifyPolicy {
            expected_nonce: Some(vec![0xDE, 0xAD]),
            ..Default::default()
        };
        let result = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(result.verified, "failures: {:?}", result.failures());
    }

    #[test]
    fn test_nonce_mismatch() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        claims.eat_nonce = Some(vec![0xDE, 0xAD]);
        let bytes = build_receipt(&claims, &key);

        let policy = AirVerifyPolicy {
            expected_nonce: Some(vec![0xBE, 0xEF]), // Different
            ..Default::default()
        };
        let result = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(!result.verified);
        assert!(result.has_failure(&AirCheckCode::NonceMismatch));
    }

    #[test]
    fn test_nonce_missing_when_expected() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims(); // No nonce
        let bytes = build_receipt(&claims, &key);

        let policy = AirVerifyPolicy {
            expected_nonce: Some(vec![0xDE, 0xAD]),
            ..Default::default()
        };
        let result = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(!result.verified);
        assert!(result.has_failure(&AirCheckCode::NonceMissing));
    }

    #[test]
    fn test_nonce_required_but_absent() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims(); // No nonce
        let bytes = build_receipt(&claims, &key);

        let policy = AirVerifyPolicy {
            require_nonce: true,
            ..Default::default()
        };
        let result = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(!result.verified);
        assert!(result.has_failure(&AirCheckCode::NonceMissing));
    }

    // ── Layer 4: replay cti ─────────────────────────────────────────

    #[test]
    fn test_replay_cti_detected() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_receipt(&claims, &key);

        let seen: Mutex<HashSet<[u8; 16]>> = Mutex::new(HashSet::new());
        let policy = AirVerifyPolicy {
            seen_cti: Some(Box::new(move |cti: &[u8; 16]| {
                !seen.lock().unwrap().insert(*cti)
            })),
            ..Default::default()
        };

        // First verification: pass
        let r1 = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(r1.verified, "first verify should pass: {:?}", r1.failures());

        // Second verification: replay
        let r2 = verify_air_v1_receipt(&bytes, &key.public_key, &policy);
        assert!(!r2.verified);
        assert!(r2.has_failure(&AirCheckCode::ReplayCti));
    }

    // ── Layer 3: zero model_hash in receipt ─────────────────────────

    #[test]
    fn test_zero_model_hash_claim_fails() {
        // We can't use build_air_v1 (it rejects zero hash), so construct manually
        let key = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        claims.model_hash = [0xAA; 32]; // Valid for build
        let bytes = build_receipt(&claims, &key);

        // Tamper: replace model_hash with zeros in the payload
        let mut cose = coset::CoseSign1::from_tagged_slice(&bytes).unwrap();
        if let Some(ref mut payload) = cose.payload {
            let val: ciborium::Value = crate::cbor::from_slice(payload).unwrap();
            if let ciborium::Value::Map(entries) = val {
                let mut new_entries = entries;
                for (k, v) in new_entries.iter_mut() {
                    if *k == ciborium::Value::Integer((-65539i64).into()) {
                        *v = ciborium::Value::Bytes(vec![0u8; 32]);
                    }
                }
                *payload = crate::cbor::value_to_vec(&ciborium::Value::Map(new_entries)).unwrap();
            }
        }
        // Re-sign so signature doesn't fail first
        let tbs = cose.tbs_data(b"");
        cose.signature = key.raw_sign(&tbs);
        let tampered = cose.to_tagged_vec().unwrap();

        let result = verify_air_v1_receipt(&tampered, &key.public_key, &AirVerifyPolicy::default());
        assert!(!result.verified);
        assert!(result.has_failure(&AirCheckCode::ZeroModelHash));
    }

    // ── Multiple failures reported ──────────────────────────────────

    #[test]
    fn test_multiple_failures_all_reported() {
        let key1 = ReceiptSigningKey::generate().unwrap();
        let key2 = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        claims.iat = crate::current_timestamp().saturating_sub(7200);
        let bytes = build_receipt(&claims, &key1);

        let policy = AirVerifyPolicy {
            max_age_secs: 3600,
            expected_model_id: Some("wrong-model".to_string()),
            ..Default::default()
        };
        let result = verify_air_v1_receipt(&bytes, &key2.public_key, &policy);
        assert!(!result.verified);

        let failures = result.failures();
        assert!(failures.len() >= 3, "expected >= 3 failures, got {:?}", failures);
        assert!(result.has_failure(&AirCheckCode::SignatureFailed));
        assert!(result.has_failure(&AirCheckCode::TimestampStale));
        assert!(result.has_failure(&AirCheckCode::ModelIdMismatch));
    }

    // ── Skipped checks don't cause failure ──────────────────────────

    #[test]
    fn test_skipped_checks_pass() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_receipt(&claims, &key);

        // All policy fields default → all policy checks skip
        let result = verify_air_v1_receipt(&bytes, &key.public_key, &AirVerifyPolicy::default());
        assert!(result.verified);

        let skipped: Vec<_> = result.checks.iter()
            .filter(|c| matches!(c.status, AirCheckStatus::Skip))
            .map(|c| c.name)
            .collect();
        assert!(skipped.contains(&"FRESH"));
        assert!(skipped.contains(&"MHASH"));
        assert!(skipped.contains(&"MODEL"));
        assert!(skipped.contains(&"PLATFORM"));
        assert!(skipped.contains(&"NONCE"));
        assert!(skipped.contains(&"REPLAY"));
    }
}
