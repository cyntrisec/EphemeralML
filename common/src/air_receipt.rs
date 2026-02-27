//! AIR v1 — Attested Inference Receipt (COSE_Sign1 / CWT / EAT)
//!
//! Implements the AIR v1 receipt format as defined in `spec/v1/`.
//! Receipts are COSE_Sign1 envelopes (RFC 9052, tag 18) carrying CWT
//! claims (RFC 8392) with EAT profile identification (RFC 9711).
//!
//! This module provides:
//! - `AirReceiptClaims`: typed claim set for building receipts
//! - `build_air_v1`: sign claims → COSE_Sign1 bytes
//! - `parse_air_v1`: COSE_Sign1 bytes → parsed claims
//! - `verify_air_v1`: signature verification
//! - `AirReceiptClaims::from_legacy`: convert v0.1 `AttestationReceipt`

use crate::error::{EphemeralError, Result};
use crate::receipt_signing::{AttestationReceipt, EnclaveMeasurements, ReceiptSigningKey};
use ciborium::Value;
use coset::iana;
use coset::TaggedCborSerializable;

// ── CWT / EAT claim keys ────────────────────────────────────────────

const CWT_ISS: i64 = 1;
const CWT_IAT: i64 = 6;
const CWT_CTI: i64 = 7;
const EAT_NONCE: i64 = 10;
const EAT_PROFILE: i64 = 265;

// ── AIR private claim keys ──────────────────────────────────────────

const AIR_MODEL_ID: i64 = -65537;
const AIR_MODEL_VERSION: i64 = -65538;
const AIR_MODEL_HASH: i64 = -65539;
const AIR_REQUEST_HASH: i64 = -65540;
const AIR_RESPONSE_HASH: i64 = -65541;
const AIR_ATTESTATION_DOC_HASH: i64 = -65542;
const AIR_ENCLAVE_MEASUREMENTS: i64 = -65543;
const AIR_POLICY_VERSION: i64 = -65544;
const AIR_SEQUENCE_NUMBER: i64 = -65545;
const AIR_EXECUTION_TIME_MS: i64 = -65546;
const AIR_MEMORY_PEAK_MB: i64 = -65547;
const AIR_SECURITY_MODE: i64 = -65548;
const AIR_MODEL_HASH_SCHEME: i64 = -65549;

/// AIR v1 eat_profile URI
pub const AIR_V1_PROFILE: &str = "https://spec.cyntrisec.com/air/v1";

/// Maximum allowed receipt size (64 KB). Golden vectors are ~600 bytes;
/// 64 KB is generous but prevents DoS via oversized input.
pub const MAX_RECEIPT_BYTES: usize = 65_536;

const MODEL_HASH_SCHEME_SHA256_SINGLE: &str = "sha256-single";
const MODEL_HASH_SCHEME_SHA256_CONCAT: &str = "sha256-concat";
const MODEL_HASH_SCHEME_SHA256_MANIFEST: &str = "sha256-manifest";

pub(crate) fn is_known_model_hash_scheme(s: &str) -> bool {
    matches!(
        s,
        MODEL_HASH_SCHEME_SHA256_SINGLE
            | MODEL_HASH_SCHEME_SHA256_CONCAT
            | MODEL_HASH_SCHEME_SHA256_MANIFEST
    )
}

/// Typed claim set for an AIR v1 receipt.
#[derive(Debug, Clone)]
pub struct AirReceiptClaims {
    // CWT/EAT standard claims
    pub iss: String,
    pub iat: u64,
    /// Receipt ID as raw UUID v4 bytes (16 bytes).
    pub cti: [u8; 16],
    /// Optional challenge nonce for replay resistance.
    pub eat_nonce: Option<Vec<u8>>,

    // AIR private claims
    pub model_id: String,
    pub model_version: String,
    /// SHA-256 of model weights — required.
    pub model_hash: [u8; 32],
    pub request_hash: [u8; 32],
    pub response_hash: [u8; 32],
    pub attestation_doc_hash: [u8; 32],
    pub enclave_measurements: EnclaveMeasurements,
    pub policy_version: String,
    pub sequence_number: u64,
    pub execution_time_ms: u64,
    pub memory_peak_mb: u64,
    pub security_mode: String,
    /// How model_hash was computed (optional, Issue #80).
    /// Defined values: "sha256-single", "sha256-concat", "sha256-manifest".
    pub model_hash_scheme: Option<String>,
}

impl AirReceiptClaims {
    /// Validate that all required fields meet AIR v1 constraints.
    pub fn validate(&self) -> Result<()> {
        if self.cti.iter().all(|&b| b == 0) {
            return Err(EphemeralError::ValidationError(
                "cti must not be all zeros".to_string(),
            ));
        }
        if self.model_hash.iter().all(|&b| b == 0) {
            return Err(EphemeralError::ValidationError(
                "model_hash must not be all zeros".to_string(),
            ));
        }
        if !self.enclave_measurements.is_valid() {
            return Err(EphemeralError::ValidationError(
                "enclave measurements must be 48 bytes each (SHA-384)".to_string(),
            ));
        }
        let mt = &self.enclave_measurements.measurement_type;
        if mt != "nitro-pcr" && mt != "tdx-mrtd-rtmr" {
            return Err(EphemeralError::ValidationError(format!(
                "unknown measurement_type: {}",
                mt
            )));
        }
        // Fix 6: pcr8 is only allowed for Nitro measurements (CDDL `tdx-measurements` omits it)
        if mt == "tdx-mrtd-rtmr" && self.enclave_measurements.pcr8.is_some() {
            return Err(EphemeralError::ValidationError(
                "pcr8 is not allowed for TDX measurements (tdx-mrtd-rtmr)".to_string(),
            ));
        }
        // Fix 4: security_mode must be a known value on the build path
        const KNOWN_SECURITY_MODES: &[&str] = &["GatewayOnly", "ShieldMode"];
        if !KNOWN_SECURITY_MODES.contains(&self.security_mode.as_str()) {
            return Err(EphemeralError::ValidationError(format!(
                "unknown security_mode: {}",
                self.security_mode
            )));
        }
        // RFC 9711 §4.1: eat_nonce must be 8-64 bytes when present
        if let Some(ref nonce) = self.eat_nonce {
            if nonce.len() < 8 || nonce.len() > 64 {
                return Err(EphemeralError::ValidationError(format!(
                    "eat_nonce must be 8-64 bytes per RFC 9711, got {}",
                    nonce.len()
                )));
            }
        }
        if let Some(ref scheme) = self.model_hash_scheme {
            if !is_known_model_hash_scheme(scheme) {
                return Err(EphemeralError::ValidationError(format!(
                    "unknown model_hash_scheme: {}",
                    scheme
                )));
            }
        }
        Ok(())
    }

    /// Convert a legacy v0.1 `AttestationReceipt` to AIR v1 claims.
    ///
    /// `model_hash` and `iss` must be supplied separately since the legacy
    /// format does not include them.
    pub fn from_legacy(
        receipt: &AttestationReceipt,
        iss: String,
        model_hash: [u8; 32],
    ) -> Result<Self> {
        // Parse UUID string to raw bytes
        let uuid = uuid::Uuid::parse_str(&receipt.receipt_id).map_err(|e| {
            EphemeralError::ValidationError(format!("invalid receipt_id UUID: {}", e))
        })?;
        let cti = *uuid.as_bytes();

        let security_mode = match receipt.security_mode {
            crate::receipt_signing::SecurityMode::GatewayOnly => "GatewayOnly".to_string(),
            crate::receipt_signing::SecurityMode::ShieldMode => "ShieldMode".to_string(),
        };

        Ok(Self {
            iss,
            iat: receipt.execution_timestamp,
            cti,
            eat_nonce: None,
            model_id: receipt.model_id.clone(),
            model_version: receipt.model_version.clone(),
            model_hash,
            request_hash: receipt.request_hash,
            response_hash: receipt.response_hash,
            attestation_doc_hash: receipt.attestation_doc_hash,
            enclave_measurements: receipt.enclave_measurements.clone(),
            policy_version: receipt.policy_version.clone(),
            sequence_number: receipt.sequence_number,
            execution_time_ms: receipt.execution_time_ms,
            memory_peak_mb: receipt.memory_peak_mb,
            security_mode,
            model_hash_scheme: None,
        })
    }
}

// ── CBOR payload encoding ───────────────────────────────────────────

/// Encode claims to a deterministic CBOR map (sorted integer keys).
fn encode_claims(claims: &AirReceiptClaims) -> Result<Vec<u8>> {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(18);

    // Keys sorted per RFC 8949 §4.2.1 (shorter encoded form first, then bytewise lexicographic)
    if let Some(ref scheme) = claims.model_hash_scheme {
        entries.push((
            Value::Integer(AIR_MODEL_HASH_SCHEME.into()),
            Value::Text(scheme.clone()),
        ));
    }
    entries.push((
        Value::Integer(AIR_SECURITY_MODE.into()),
        Value::Text(claims.security_mode.clone()),
    ));
    entries.push((
        Value::Integer(AIR_MEMORY_PEAK_MB.into()),
        Value::Integer(claims.memory_peak_mb.into()),
    ));
    entries.push((
        Value::Integer(AIR_EXECUTION_TIME_MS.into()),
        Value::Integer(claims.execution_time_ms.into()),
    ));
    entries.push((
        Value::Integer(AIR_SEQUENCE_NUMBER.into()),
        Value::Integer(claims.sequence_number.into()),
    ));
    entries.push((
        Value::Integer(AIR_POLICY_VERSION.into()),
        Value::Text(claims.policy_version.clone()),
    ));
    entries.push((
        Value::Integer(AIR_ENCLAVE_MEASUREMENTS.into()),
        encode_measurements(&claims.enclave_measurements),
    ));
    entries.push((
        Value::Integer(AIR_ATTESTATION_DOC_HASH.into()),
        Value::Bytes(claims.attestation_doc_hash.to_vec()),
    ));
    entries.push((
        Value::Integer(AIR_RESPONSE_HASH.into()),
        Value::Bytes(claims.response_hash.to_vec()),
    ));
    entries.push((
        Value::Integer(AIR_REQUEST_HASH.into()),
        Value::Bytes(claims.request_hash.to_vec()),
    ));
    entries.push((
        Value::Integer(AIR_MODEL_HASH.into()),
        Value::Bytes(claims.model_hash.to_vec()),
    ));
    entries.push((
        Value::Integer(AIR_MODEL_VERSION.into()),
        Value::Text(claims.model_version.clone()),
    ));
    entries.push((
        Value::Integer(AIR_MODEL_ID.into()),
        Value::Text(claims.model_id.clone()),
    ));

    // Positive keys (sorted ascending)
    entries.push((
        Value::Integer(CWT_ISS.into()),
        Value::Text(claims.iss.clone()),
    ));
    entries.push((
        Value::Integer(CWT_IAT.into()),
        Value::Integer(claims.iat.into()),
    ));
    entries.push((
        Value::Integer(CWT_CTI.into()),
        Value::Bytes(claims.cti.to_vec()),
    ));
    if let Some(ref nonce) = claims.eat_nonce {
        entries.push((
            Value::Integer(EAT_NONCE.into()),
            Value::Bytes(nonce.clone()),
        ));
    }
    entries.push((
        Value::Integer(EAT_PROFILE.into()),
        Value::Text(AIR_V1_PROFILE.to_string()),
    ));

    // Sort by CBOR deterministic encoding rules (RFC 8949 §4.2.1):
    // shorter encoded key sorts first, then bytewise lexicographic comparison.
    // For integer keys: positive (major type 0) sorts before negative (major type 1).
    entries.sort_by(|(k1, _), (k2, _)| crate::cbor::cmp_cbor_keys(k1, k2));

    let map = Value::Map(entries);
    crate::cbor::value_to_vec(&map)
        .map_err(|e| EphemeralError::SerializationError(format!("claims CBOR encoding: {e}")))
}

/// Encode enclave measurements as a CBOR map.
fn encode_measurements(m: &EnclaveMeasurements) -> Value {
    let mut entries = vec![
        (
            Value::Text("measurement_type".to_string()),
            Value::Text(m.measurement_type.clone()),
        ),
        (
            Value::Text("pcr0".to_string()),
            Value::Bytes(m.pcr0.clone()),
        ),
        (
            Value::Text("pcr1".to_string()),
            Value::Bytes(m.pcr1.clone()),
        ),
        (
            Value::Text("pcr2".to_string()),
            Value::Bytes(m.pcr2.clone()),
        ),
    ];
    if let Some(ref pcr8) = m.pcr8 {
        entries.push((Value::Text("pcr8".to_string()), Value::Bytes(pcr8.clone())));
    }
    // Sort text keys lexicographically for determinism
    entries.sort_by(|(k1, _), (k2, _)| crate::cbor::cmp_cbor_keys(k1, k2));
    Value::Map(entries)
}

// ── Build ───────────────────────────────────────────────────────────

/// Build a signed AIR v1 receipt (COSE_Sign1 tagged bytes).
///
/// Returns the CBOR-encoded COSE_Sign1 with tag 18.
pub fn build_air_v1(claims: &AirReceiptClaims, signing_key: &ReceiptSigningKey) -> Result<Vec<u8>> {
    claims.validate()?;

    if signing_key.is_expired() {
        return Err(EphemeralError::EncryptionError(
            "Signing key expired".to_string(),
        ));
    }

    let payload = encode_claims(claims)?;

    let protected = coset::HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .content_format(coset::iana::CoapContentFormat::Cwt)
        .build();

    let sign1 = coset::CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .try_create_signature(b"", |tbs| {
            let sig = signing_key.raw_sign(tbs);
            Ok(sig)
        })
        .map_err(|e: EphemeralError| e)?
        .build();

    sign1
        .to_tagged_vec()
        .map_err(|e| EphemeralError::SerializationError(format!("COSE_Sign1 encoding failed: {e}")))
}

/// Parsed AIR v1 receipt (claims + raw envelope for re-verification).
#[derive(Debug)]
pub struct ParsedAirReceipt {
    pub claims: AirReceiptClaims,
    /// The raw COSE_Sign1 structure for signature verification.
    pub cose: coset::CoseSign1,
}

/// Decode claims from raw CBOR payload bytes.
///
/// Exposed for the verifier layer to decode claims independently of COSE parsing.
pub fn decode_claims_from_bytes(payload: &[u8]) -> Result<AirReceiptClaims> {
    decode_claims(payload)
}

/// Encode claims to deterministic CBOR bytes (for test/verifier use).
pub fn encode_claims_exported(claims: &AirReceiptClaims) -> Result<Vec<u8>> {
    encode_claims(claims)
}

/// Parse AIR v1 COSE_Sign1 bytes into claims. Does NOT verify the signature.
pub fn parse_air_v1(data: &[u8]) -> Result<ParsedAirReceipt> {
    // Fix 1: Pre-parse receipt size limit
    if data.len() > MAX_RECEIPT_BYTES {
        return Err(EphemeralError::ValidationError(format!(
            "receipt too large: {} bytes (max {})",
            data.len(),
            MAX_RECEIPT_BYTES
        )));
    }

    let cose = coset::CoseSign1::from_tagged_slice(data)
        .map_err(|e| EphemeralError::SerializationError(format!("COSE_Sign1 parse failed: {e}")))?;

    // Fix 2: Reject non-empty unprotected headers.
    // AIR v1 requires all header parameters in the protected bucket.
    // Unprotected headers are NOT signed and can be tampered with.
    // This is stricter than the CDDL (which allows `? 4 => bstr` for kid)
    // because AIR v1 does not use unprotected kid.
    if !cose.unprotected.is_empty() {
        return Err(EphemeralError::ValidationError(
            "non-empty unprotected header (AIR v1 requires all headers in protected bucket)"
                .to_string(),
        ));
    }

    // Check protected header
    let alg = cose.protected.header.alg.as_ref().ok_or_else(|| {
        EphemeralError::ValidationError("missing alg in protected header".to_string())
    })?;
    if *alg != coset::RegisteredLabelWithPrivate::Assigned(iana::Algorithm::EdDSA) {
        return Err(EphemeralError::ValidationError(format!(
            "unexpected alg: expected EdDSA (-8), got {:?}",
            alg
        )));
    }

    let payload_bytes = cose.payload.as_ref().ok_or_else(|| {
        EphemeralError::ValidationError("missing payload in COSE_Sign1".to_string())
    })?;

    let claims = decode_claims(payload_bytes)?;

    Ok(ParsedAirReceipt { claims, cose })
}

/// Verify an AIR v1 receipt signature.
///
/// Returns `Ok(true)` if signature is valid, `Ok(false)` if invalid.
pub fn verify_air_v1(
    parsed: &ParsedAirReceipt,
    public_key: &ed25519_dalek::VerifyingKey,
) -> Result<bool> {
    let result = parsed.cose.verify_signature(b"", |sig, tbs| {
        if sig.len() != 64 {
            return Err(EphemeralError::ValidationError(format!(
                "invalid signature length: {} (expected 64)",
                sig.len()
            )));
        }
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(sig);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        // Use verify_strict per AIR v1 spec
        public_key
            .verify_strict(tbs, &signature)
            .map_err(|e| EphemeralError::ValidationError(format!("Ed25519 verify failed: {e}")))
    });

    match result {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ── Claim decoding ──────────────────────────────────────────────────

/// All known AIR v1 claim keys (closed-map enforcement).
const KNOWN_CLAIM_KEYS: &[i64] = &[
    CWT_ISS,
    CWT_IAT,
    CWT_CTI,
    EAT_NONCE,
    EAT_PROFILE,
    AIR_MODEL_ID,
    AIR_MODEL_VERSION,
    AIR_MODEL_HASH,
    AIR_REQUEST_HASH,
    AIR_RESPONSE_HASH,
    AIR_ATTESTATION_DOC_HASH,
    AIR_ENCLAVE_MEASUREMENTS,
    AIR_POLICY_VERSION,
    AIR_SEQUENCE_NUMBER,
    AIR_EXECUTION_TIME_MS,
    AIR_MEMORY_PEAK_MB,
    AIR_SECURITY_MODE,
    AIR_MODEL_HASH_SCHEME,
];

fn decode_claims(payload: &[u8]) -> Result<AirReceiptClaims> {
    let value: Value = crate::cbor::from_slice(payload)
        .map_err(|e| EphemeralError::SerializationError(format!("payload CBOR decode: {e}")))?;

    let entries = match &value {
        Value::Map(m) => m,
        _ => {
            return Err(EphemeralError::ValidationError(
                "payload is not a CBOR map".to_string(),
            ))
        }
    };

    // Closed-map enforcement: reject unknown claims per CDDL schema
    // Fix 3: Also detect duplicate keys (max 18 known claim keys)
    let mut seen_keys: Vec<i64> = Vec::with_capacity(18);
    for (k, _) in entries {
        if let Value::Integer(n) = k {
            let key_val: i128 = (*n).into();
            if key_val < i64::MIN as i128 || key_val > i64::MAX as i128 {
                return Err(EphemeralError::ValidationError(format!(
                    "claim key out of i64 range: {key_val}"
                )));
            }
            let key_i64 = key_val as i64;
            if !KNOWN_CLAIM_KEYS.contains(&key_i64) {
                return Err(EphemeralError::ValidationError(format!(
                    "unknown claim key: {key_i64}"
                )));
            }
            if seen_keys.contains(&key_i64) {
                return Err(EphemeralError::ValidationError(format!(
                    "duplicate claim key: {key_i64}"
                )));
            }
            seen_keys.push(key_i64);
        } else {
            return Err(EphemeralError::ValidationError(format!(
                "non-integer claim key: {:?}",
                k
            )));
        }
    }

    // Check eat_profile
    let profile = get_text(entries, EAT_PROFILE)?;
    if profile != AIR_V1_PROFILE {
        return Err(EphemeralError::ValidationError(format!(
            "unknown eat_profile: {profile}"
        )));
    }

    // Fix 7: Use bounded text getters for all text claims
    let iss = get_text_bounded(entries, CWT_ISS, 256)?;
    let iat = get_uint(entries, CWT_IAT)?;
    // Fix 5: iat = 0 (Unix epoch) is not a valid timestamp for a receipt
    if iat == 0 {
        return Err(EphemeralError::ValidationError(
            "iat must not be zero (Unix epoch)".to_string(),
        ));
    }
    let cti_bytes = get_bstr(entries, CWT_CTI)?;
    if cti_bytes.len() != 16 {
        return Err(EphemeralError::ValidationError(format!(
            "cti must be 16 bytes, got {}",
            cti_bytes.len()
        )));
    }
    let mut cti = [0u8; 16];
    cti.copy_from_slice(&cti_bytes);

    let eat_nonce = get_bstr_opt(entries, EAT_NONCE)?;
    // RFC 9711 §4.1: eat_nonce must be 8-64 bytes when present
    if let Some(ref nonce) = eat_nonce {
        if nonce.len() < 8 || nonce.len() > 64 {
            return Err(EphemeralError::ValidationError(format!(
                "eat_nonce must be 8-64 bytes per RFC 9711, got {}",
                nonce.len()
            )));
        }
    }

    let model_id = get_text_bounded(entries, AIR_MODEL_ID, 256)?;
    let model_version = get_text_bounded(entries, AIR_MODEL_VERSION, 128)?;
    let model_hash = get_hash32(entries, AIR_MODEL_HASH, "model_hash")?;
    let request_hash = get_hash32(entries, AIR_REQUEST_HASH, "request_hash")?;
    let response_hash = get_hash32(entries, AIR_RESPONSE_HASH, "response_hash")?;
    let attestation_doc_hash =
        get_hash32(entries, AIR_ATTESTATION_DOC_HASH, "attestation_doc_hash")?;
    let enclave_measurements = decode_measurements(entries)?;
    let policy_version = get_text_bounded(entries, AIR_POLICY_VERSION, 256)?;
    let sequence_number = get_uint(entries, AIR_SEQUENCE_NUMBER)?;
    let execution_time_ms = get_uint(entries, AIR_EXECUTION_TIME_MS)?;
    let memory_peak_mb = get_uint(entries, AIR_MEMORY_PEAK_MB)?;
    let security_mode = get_text_bounded(entries, AIR_SECURITY_MODE, 64)?;
    let model_hash_scheme = get_text_opt_bounded(entries, AIR_MODEL_HASH_SCHEME, 64)?;

    Ok(AirReceiptClaims {
        iss,
        iat,
        cti,
        eat_nonce,
        model_id,
        model_version,
        model_hash,
        request_hash,
        response_hash,
        attestation_doc_hash,
        enclave_measurements,
        policy_version,
        sequence_number,
        execution_time_ms,
        memory_peak_mb,
        security_mode,
        model_hash_scheme,
    })
}

fn decode_measurements(entries: &[(Value, Value)]) -> Result<EnclaveMeasurements> {
    let key = Value::Integer(AIR_ENCLAVE_MEASUREMENTS.into());
    let meas_val = crate::cbor::map_get(entries, &key).ok_or_else(|| {
        EphemeralError::ValidationError("missing enclave_measurements claim".to_string())
    })?;
    let meas_entries = match meas_val {
        Value::Map(m) => m,
        _ => {
            return Err(EphemeralError::ValidationError(
                "enclave_measurements is not a map".to_string(),
            ))
        }
    };

    // Fix 3: Duplicate key check for nested measurements map (max 5 keys)
    let mut seen_meas_keys: Vec<String> = Vec::with_capacity(5);
    for (mk, _) in meas_entries {
        if let Value::Text(t) = mk {
            if seen_meas_keys.contains(t) {
                return Err(EphemeralError::ValidationError(format!(
                    "duplicate key in enclave_measurements: {t}"
                )));
            }
            seen_meas_keys.push(t.clone());
        }
    }

    let mt_key = Value::Text("measurement_type".to_string());
    let measurement_type = match crate::cbor::map_get(meas_entries, &mt_key) {
        Some(Value::Text(t)) => t.clone(),
        _ => {
            return Err(EphemeralError::ValidationError(
                "missing measurement_type in enclave_measurements".to_string(),
            ))
        }
    };

    let pcr0 = get_text_bstr(meas_entries, "pcr0")?;
    let pcr1 = get_text_bstr(meas_entries, "pcr1")?;
    let pcr2 = get_text_bstr(meas_entries, "pcr2")?;
    let pcr8 = get_text_bstr_opt(meas_entries, "pcr8")?;

    // Fix 6: pcr8 is not allowed for TDX measurements (CDDL `tdx-measurements` omits it)
    if measurement_type == "tdx-mrtd-rtmr" && pcr8.is_some() {
        return Err(EphemeralError::ValidationError(
            "pcr8 is not allowed for TDX measurements (tdx-mrtd-rtmr)".to_string(),
        ));
    }

    Ok(EnclaveMeasurements {
        pcr0,
        pcr1,
        pcr2,
        pcr8,
        measurement_type,
    })
}

// ── CBOR map helpers ────────────────────────────────────────────────

fn get_by_int(entries: &[(Value, Value)], key: i64) -> Option<&Value> {
    let k = Value::Integer(key.into());
    crate::cbor::map_get(entries, &k)
}

fn get_text(entries: &[(Value, Value)], key: i64) -> Result<String> {
    match get_by_int(entries, key) {
        Some(Value::Text(s)) => Ok(s.clone()),
        Some(_) => Err(EphemeralError::ValidationError(format!(
            "claim {key} is not a text string"
        ))),
        None => Err(EphemeralError::ValidationError(format!(
            "missing required claim {key}"
        ))),
    }
}

fn get_uint(entries: &[(Value, Value)], key: i64) -> Result<u64> {
    match get_by_int(entries, key) {
        Some(Value::Integer(n)) => {
            let v: i128 = (*n).into();
            if v < 0 || v > u64::MAX as i128 {
                return Err(EphemeralError::ValidationError(format!(
                    "claim {key} out of u64 range: {v}"
                )));
            }
            Ok(v as u64)
        }
        Some(_) => Err(EphemeralError::ValidationError(format!(
            "claim {key} is not an integer"
        ))),
        None => Err(EphemeralError::ValidationError(format!(
            "missing required claim {key}"
        ))),
    }
}

fn get_bstr(entries: &[(Value, Value)], key: i64) -> Result<Vec<u8>> {
    match get_by_int(entries, key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(EphemeralError::ValidationError(format!(
            "claim {key} is not a byte string"
        ))),
        None => Err(EphemeralError::ValidationError(format!(
            "missing required claim {key}"
        ))),
    }
}

fn get_text_opt(entries: &[(Value, Value)], key: i64) -> Result<Option<String>> {
    match get_by_int(entries, key) {
        Some(Value::Text(s)) => Ok(Some(s.clone())),
        Some(_) => Err(EphemeralError::ValidationError(format!(
            "claim {key} is not a text string"
        ))),
        None => Ok(None),
    }
}

/// Fix 7: Get a required text claim with min-length=1 and max-length bounds.
fn get_text_bounded(entries: &[(Value, Value)], key: i64, max_len: usize) -> Result<String> {
    let s = get_text(entries, key)?;
    if s.is_empty() {
        return Err(EphemeralError::ValidationError(format!(
            "claim {key} must not be empty"
        )));
    }
    if s.len() > max_len {
        return Err(EphemeralError::ValidationError(format!(
            "claim {key} exceeds max length ({} > {max_len})",
            s.len()
        )));
    }
    Ok(s)
}

/// Fix 7: Get an optional text claim with min-length=1 and max-length bounds.
fn get_text_opt_bounded(
    entries: &[(Value, Value)],
    key: i64,
    max_len: usize,
) -> Result<Option<String>> {
    match get_text_opt(entries, key)? {
        Some(s) => {
            if s.is_empty() {
                return Err(EphemeralError::ValidationError(format!(
                    "claim {key} must not be empty"
                )));
            }
            if s.len() > max_len {
                return Err(EphemeralError::ValidationError(format!(
                    "claim {key} exceeds max length ({} > {max_len})",
                    s.len()
                )));
            }
            Ok(Some(s))
        }
        None => Ok(None),
    }
}

fn get_bstr_opt(entries: &[(Value, Value)], key: i64) -> Result<Option<Vec<u8>>> {
    match get_by_int(entries, key) {
        Some(Value::Bytes(b)) => Ok(Some(b.clone())),
        Some(_) => Err(EphemeralError::ValidationError(format!(
            "claim {key} is not a byte string"
        ))),
        None => Ok(None),
    }
}

fn get_hash32(entries: &[(Value, Value)], key: i64, name: &str) -> Result<[u8; 32]> {
    let bytes = get_bstr(entries, key)?;
    if bytes.len() != 32 {
        return Err(EphemeralError::ValidationError(format!(
            "{name} must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn get_text_bstr(entries: &[(Value, Value)], name: &str) -> Result<Vec<u8>> {
    let key = Value::Text(name.to_string());
    match crate::cbor::map_get(entries, &key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(EphemeralError::ValidationError(format!(
            "{name} is not a byte string"
        ))),
        None => Err(EphemeralError::ValidationError(format!(
            "missing {name} in enclave_measurements"
        ))),
    }
}

fn get_text_bstr_opt(entries: &[(Value, Value)], name: &str) -> Result<Option<Vec<u8>>> {
    let key = Value::Text(name.to_string());
    match crate::cbor::map_get(entries, &key) {
        Some(Value::Bytes(b)) => Ok(Some(b.clone())),
        Some(_) => Err(EphemeralError::ValidationError(format!(
            "{name} is not a byte string in enclave_measurements"
        ))),
        None => Ok(None),
    }
}

// ── Golden vector helpers (test-only, crate-visible) ─────────────

#[cfg(test)]
pub(crate) mod golden {
    use super::*;
    use crate::receipt_signing::{EnclaveMeasurements, ReceiptSigningKey};

    /// Fixed signing key seed for golden vectors.
    pub fn key() -> ReceiptSigningKey {
        let private = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        ReceiptSigningKey::from_parts(private.clone(), private.verifying_key())
    }

    /// Fixed claims for golden vector 1 (Nitro, no nonce).
    pub fn claims_v1() -> AirReceiptClaims {
        AirReceiptClaims {
            iss: "cyntrisec.com".to_string(),
            iat: 1740500000,
            cti: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ],
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
            model_hash_scheme: None,
        }
    }

    /// Fixed claims for golden vector 2 (TDX, with nonce).
    pub fn claims_v2() -> AirReceiptClaims {
        AirReceiptClaims {
            iss: "cyntrisec.com".to_string(),
            iat: 1740500100,
            cti: [
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20,
            ],
            eat_nonce: Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]),
            model_id: "llama-7b".to_string(),
            model_version: "2.0.0".to_string(),
            model_hash: [0x55; 32],
            request_hash: [0x66; 32],
            response_hash: [0x77; 32],
            attestation_doc_hash: [0x88; 32],
            enclave_measurements: EnclaveMeasurements::new_tdx(
                vec![0x10; 48],
                vec![0x20; 48],
                vec![0x30; 48],
            ),
            policy_version: "policy-2026.03".to_string(),
            sequence_number: 1,
            execution_time_ms: 2500,
            memory_peak_mb: 8192,
            security_mode: "ShieldMode".to_string(),
            model_hash_scheme: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt_signing::{EnclaveMeasurements, ReceiptSigningKey};

    fn fixture_claims() -> AirReceiptClaims {
        AirReceiptClaims {
            iss: "cyntrisec.com".to_string(),
            iat: 1740500000,
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
            model_hash_scheme: None,
        }
    }

    #[test]
    fn test_build_parse_roundtrip() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_air_v1(&claims, &key).unwrap();

        let parsed = parse_air_v1(&bytes).unwrap();
        assert_eq!(parsed.claims.iss, claims.iss);
        assert_eq!(parsed.claims.iat, claims.iat);
        assert_eq!(parsed.claims.cti, claims.cti);
        assert_eq!(parsed.claims.model_id, claims.model_id);
        assert_eq!(parsed.claims.model_version, claims.model_version);
        assert_eq!(parsed.claims.model_hash, claims.model_hash);
        assert_eq!(parsed.claims.request_hash, claims.request_hash);
        assert_eq!(parsed.claims.response_hash, claims.response_hash);
        assert_eq!(
            parsed.claims.attestation_doc_hash,
            claims.attestation_doc_hash
        );
        assert_eq!(parsed.claims.policy_version, claims.policy_version);
        assert_eq!(parsed.claims.sequence_number, claims.sequence_number);
        assert_eq!(parsed.claims.execution_time_ms, claims.execution_time_ms);
        assert_eq!(parsed.claims.memory_peak_mb, claims.memory_peak_mb);
        assert_eq!(parsed.claims.security_mode, claims.security_mode);
        assert_eq!(parsed.claims.model_hash_scheme, claims.model_hash_scheme);
        assert_eq!(
            parsed.claims.enclave_measurements.measurement_type,
            claims.enclave_measurements.measurement_type
        );
        assert_eq!(
            parsed.claims.enclave_measurements.pcr0,
            claims.enclave_measurements.pcr0
        );
    }

    #[test]
    fn test_signature_verifies() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_air_v1(&claims, &key).unwrap();
        let parsed = parse_air_v1(&bytes).unwrap();

        assert!(verify_air_v1(&parsed, &key.public_key).unwrap());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = ReceiptSigningKey::generate().unwrap();
        let key2 = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_air_v1(&claims, &key1).unwrap();
        let parsed = parse_air_v1(&bytes).unwrap();

        assert!(!verify_air_v1(&parsed, &key2.public_key).unwrap());
    }

    #[test]
    fn test_deterministic_output() {
        let private = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let key = ReceiptSigningKey::from_parts(private.clone(), private.verifying_key());

        let mut claims = fixture_claims();
        claims.cti = [0x01; 16]; // Fixed cti for determinism
        claims.iat = 1740500000;

        let bytes1 = build_air_v1(&claims, &key).unwrap();
        let bytes2 = build_air_v1(&claims, &key).unwrap();
        assert_eq!(
            bytes1, bytes2,
            "output must be byte-stable for fixed inputs"
        );
    }

    #[test]
    fn test_tampered_payload_fails() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_air_v1(&claims, &key).unwrap();

        // Parse, modify a claim, re-encode without re-signing
        let mut cose = coset::CoseSign1::from_tagged_slice(&bytes).unwrap();
        // Corrupt the payload by flipping a byte
        if let Some(ref mut payload) = cose.payload {
            if !payload.is_empty() {
                let last = payload.len() - 1;
                payload[last] ^= 0xFF;
            }
        }
        let tampered = cose.to_tagged_vec().unwrap();

        // Re-parse and verify — should fail
        if let Ok(parsed) = parse_air_v1(&tampered) {
            assert!(!verify_air_v1(&parsed, &key.public_key).unwrap());
        }
        // If parse itself fails (due to corrupted CBOR), that's also acceptable
    }

    #[test]
    fn test_missing_model_hash_rejected() {
        let mut claims = fixture_claims();
        claims.model_hash = [0u8; 32]; // All zeros
        let key = ReceiptSigningKey::generate().unwrap();
        let result = build_air_v1(&claims, &key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("model_hash must not be all zeros"));
    }

    #[test]
    fn test_invalid_measurements_rejected() {
        let mut claims = fixture_claims();
        claims.enclave_measurements = EnclaveMeasurements::new(
            vec![1u8; 32], // Wrong length
            vec![2u8; 48],
            vec![3u8; 48],
        );
        let key = ReceiptSigningKey::generate().unwrap();
        let result = build_air_v1(&claims, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_measurement_type_rejected() {
        let mut claims = fixture_claims();
        claims.enclave_measurements.measurement_type = "sev-snp-vcek".to_string();
        let key = ReceiptSigningKey::generate().unwrap();
        let result = build_air_v1(&claims, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_eat_nonce_roundtrip() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        // RFC 9711 §4.1: minimum 8 bytes
        claims.eat_nonce = Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
        let bytes = build_air_v1(&claims, &key).unwrap();
        let parsed = parse_air_v1(&bytes).unwrap();
        assert_eq!(
            parsed.claims.eat_nonce,
            Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
        );
    }

    #[test]
    fn test_eat_nonce_too_short_rejected() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        claims.eat_nonce = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]); // 4 bytes < 8 minimum
        let result = build_air_v1(&claims, &key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("eat_nonce must be 8-64 bytes"));
    }

    #[test]
    fn test_eat_nonce_too_long_rejected() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        claims.eat_nonce = Some(vec![0xAA; 65]); // 65 bytes > 64 maximum
        let result = build_air_v1(&claims, &key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("eat_nonce must be 8-64 bytes"));
    }

    #[test]
    fn test_eat_nonce_absent_roundtrip() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        assert!(claims.eat_nonce.is_none());
        let bytes = build_air_v1(&claims, &key).unwrap();
        let parsed = parse_air_v1(&bytes).unwrap();
        assert!(parsed.claims.eat_nonce.is_none());
    }

    #[test]
    fn test_model_hash_scheme_roundtrip() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        claims.model_hash_scheme = Some("sha256-single".to_string());
        let bytes = build_air_v1(&claims, &key).unwrap();
        let parsed = parse_air_v1(&bytes).unwrap();
        assert_eq!(
            parsed.claims.model_hash_scheme,
            Some("sha256-single".to_string())
        );
    }

    #[test]
    fn test_model_hash_scheme_absent_roundtrip() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        assert!(claims.model_hash_scheme.is_none());
        let bytes = build_air_v1(&claims, &key).unwrap();
        let parsed = parse_air_v1(&bytes).unwrap();
        assert!(parsed.claims.model_hash_scheme.is_none());
    }

    #[test]
    fn test_unknown_model_hash_scheme_rejected() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        claims.model_hash_scheme = Some("sha256-custom".to_string());
        let err = build_air_v1(&claims, &key).unwrap_err();
        assert!(err.to_string().contains("unknown model_hash_scheme"));
    }

    #[test]
    fn test_tdx_measurements_roundtrip() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        claims.enclave_measurements =
            EnclaveMeasurements::new_tdx(vec![10u8; 48], vec![20u8; 48], vec![30u8; 48]);
        let bytes = build_air_v1(&claims, &key).unwrap();
        let parsed = parse_air_v1(&bytes).unwrap();
        assert_eq!(
            parsed.claims.enclave_measurements.measurement_type,
            "tdx-mrtd-rtmr"
        );
        assert_eq!(parsed.claims.enclave_measurements.pcr0, vec![10u8; 48]);
    }

    #[test]
    fn test_nitro_pcr8_roundtrip() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut claims = fixture_claims();
        claims.enclave_measurements.pcr8 = Some(vec![8u8; 48]);
        let bytes = build_air_v1(&claims, &key).unwrap();
        let parsed = parse_air_v1(&bytes).unwrap();
        assert_eq!(parsed.claims.enclave_measurements.pcr8, Some(vec![8u8; 48]));
    }

    #[test]
    fn test_cose_tag_18_present() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_air_v1(&claims, &key).unwrap();
        // CBOR tag 18 = 0xD2 as first byte
        assert_eq!(bytes[0], 0xD2, "first byte must be CBOR tag 18");
    }

    #[test]
    fn test_reject_unknown_eat_profile() {
        let key = ReceiptSigningKey::generate().unwrap();
        let claims = fixture_claims();
        let bytes = build_air_v1(&claims, &key).unwrap();

        // Manually build a receipt with wrong eat_profile
        let mut cose = coset::CoseSign1::from_tagged_slice(&bytes).unwrap();
        if let Some(ref payload) = cose.payload {
            let val: Value = crate::cbor::from_slice(payload).unwrap();
            if let Value::Map(mut entries) = val {
                // Find and replace eat_profile
                for (k, v) in entries.iter_mut() {
                    if *k == Value::Integer(EAT_PROFILE.into()) {
                        *v = Value::Text("https://example.com/wrong".to_string());
                    }
                }
                let new_payload = crate::cbor::value_to_vec(&Value::Map(entries)).unwrap();
                cose.payload = Some(new_payload);
            }
        }
        let tampered = cose.to_tagged_vec().unwrap();
        let result = parse_air_v1(&tampered);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("eat_profile"));
    }

    #[test]
    fn generate_golden_vectors() {
        use super::golden;
        use coset::TaggedCborSerializable;

        let key = golden::key();

        // Vector 1: Nitro, no nonce
        let c1 = golden::claims_v1();
        let bytes1 = build_air_v1(&c1, &key).unwrap();
        let payload1 = encode_claims(&c1).unwrap();

        // Vector 2: TDX, with nonce
        let c2 = golden::claims_v2();
        let bytes2 = build_air_v1(&c2, &key).unwrap();
        let payload2 = encode_claims(&c2).unwrap();

        // Wrong key for invalid vector
        let wrong_private = ed25519_dalek::SigningKey::from_bytes(&[0x01; 32]);
        let wrong_public = wrong_private.verifying_key();

        // Wrong alg receipt (ES256 instead of EdDSA)
        let protected_wrong_alg = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .content_format(coset::iana::CoapContentFormat::Cwt)
            .build();
        let sign1_wrong_alg = coset::CoseSign1Builder::new()
            .protected(protected_wrong_alg)
            .payload(payload1.clone())
            .try_create_signature(b"", |tbs| Ok::<_, String>(key.raw_sign(tbs)))
            .unwrap()
            .build();
        let wrong_alg_bytes = sign1_wrong_alg.to_tagged_vec().unwrap();

        // Print for capture
        eprintln!("=== GOLDEN VECTOR 1 (Nitro, no nonce) ===");
        eprintln!("receipt_hex: {}", hex::encode(&bytes1));
        eprintln!("payload_hex: {}", hex::encode(&payload1));
        eprintln!("public_key_hex: {}", hex::encode(key.public_key.as_bytes()));
        eprintln!("receipt_len: {}", bytes1.len());
        eprintln!("");
        eprintln!("=== GOLDEN VECTOR 2 (TDX, with nonce) ===");
        eprintln!("receipt_hex: {}", hex::encode(&bytes2));
        eprintln!("payload_hex: {}", hex::encode(&payload2));
        eprintln!("receipt_len: {}", bytes2.len());
        eprintln!("");
        eprintln!("=== WRONG KEY ===");
        eprintln!(
            "wrong_public_key_hex: {}",
            hex::encode(wrong_public.as_bytes())
        );
        eprintln!("");
        eprintln!("=== WRONG ALG ===");
        eprintln!("wrong_alg_receipt_hex: {}", hex::encode(&wrong_alg_bytes));
        eprintln!("wrong_alg_receipt_len: {}", wrong_alg_bytes.len());

        // Verify determinism
        let bytes1b = build_air_v1(&c1, &key).unwrap();
        assert_eq!(bytes1, bytes1b, "Vector 1 not deterministic");
        let bytes2b = build_air_v1(&c2, &key).unwrap();
        assert_eq!(bytes2, bytes2b, "Vector 2 not deterministic");
    }

    /// Helper: build a tampered COSE_Sign1 receipt by modifying the payload CBOR.
    ///
    /// `modifier` receives mutable payload entries and can tamper them.
    /// The result is re-signed with the golden key so crypto passes.
    fn build_tampered_receipt(
        base_claims: &AirReceiptClaims,
        modifier: impl FnOnce(&mut Vec<(Value, Value)>),
    ) -> Vec<u8> {
        use coset::TaggedCborSerializable;

        let key = super::golden::key();
        let payload_bytes = encode_claims(base_claims).unwrap();

        // Decode payload CBOR, apply tamper
        let val: Value = crate::cbor::from_slice(&payload_bytes).unwrap();
        let mut entries = match val {
            Value::Map(m) => m,
            _ => panic!("payload is not a map"),
        };
        modifier(&mut entries);
        let tampered_payload = crate::cbor::value_to_vec(&Value::Map(entries)).unwrap();

        // Build COSE_Sign1 with correct header but tampered payload
        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .content_format(coset::iana::CoapContentFormat::Cwt)
            .build();
        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(tampered_payload)
            .try_create_signature(b"", |tbs| Ok::<_, String>(key.raw_sign(tbs)))
            .unwrap()
            .build();
        sign1.to_tagged_vec().unwrap()
    }

    #[test]
    fn generate_structural_invalid_vectors() {
        let c1 = super::golden::claims_v1();

        // Zero model_hash: replace model_hash (-65539) with all-zero bytes
        let zero_mhash = build_tampered_receipt(&c1, |entries| {
            for (k, v) in entries.iter_mut() {
                if *k == Value::Integer((-65539i64).into()) {
                    *v = Value::Bytes(vec![0u8; 32]);
                }
            }
        });

        // Bad measurement length: replace pcr0 with 32-byte value
        let bad_meas = build_tampered_receipt(&c1, |entries| {
            for (k, v) in entries.iter_mut() {
                if *k == Value::Integer((-65543i64).into()) {
                    if let Value::Map(ref mut meas_entries) = v {
                        for (mk, mv) in meas_entries.iter_mut() {
                            if *mk == Value::Text("pcr0".to_string()) {
                                *mv = Value::Bytes(vec![0xAA; 32]); // 32 instead of 48
                            }
                        }
                    }
                }
            }
        });

        eprintln!("=== ZERO MODEL HASH ===");
        eprintln!("receipt_hex: {}", hex::encode(&zero_mhash));
        eprintln!("receipt_len: {}", zero_mhash.len());
        eprintln!();
        eprintln!("=== BAD MEASUREMENT LENGTH ===");
        eprintln!("receipt_hex: {}", hex::encode(&bad_meas));
        eprintln!("receipt_len: {}", bad_meas.len());
    }

    #[test]
    fn test_from_legacy_conversion() {
        let measurements = EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);
        let receipt_id = uuid::Uuid::new_v4().to_string();

        let legacy = AttestationReceipt::new(
            receipt_id.clone(),
            1,
            crate::receipt_signing::SecurityMode::GatewayOnly,
            measurements,
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            "policy-v1".to_string(),
            7,
            "test-model".to_string(),
            "v1.0".to_string(),
            100,
            64,
        );

        let model_hash = [0xFF; 32];
        let air_claims =
            AirReceiptClaims::from_legacy(&legacy, "cyntrisec.com".to_string(), model_hash)
                .unwrap();

        assert_eq!(air_claims.model_id, "test-model");
        assert_eq!(air_claims.model_hash, model_hash);
        assert_eq!(air_claims.security_mode, "GatewayOnly");

        // cti should be the raw UUID bytes
        let expected_uuid = uuid::Uuid::parse_str(&receipt_id).unwrap();
        assert_eq!(air_claims.cti, *expected_uuid.as_bytes());

        // Build and verify
        let key = ReceiptSigningKey::generate().unwrap();
        let bytes = build_air_v1(&air_claims, &key).unwrap();
        let parsed = parse_air_v1(&bytes).unwrap();
        assert!(verify_air_v1(&parsed, &key.public_key).unwrap());
    }

    // ── Closed-map / type-safety regression tests ────────────────

    #[test]
    fn test_unknown_claim_key_rejected() {
        let claims = fixture_claims();
        let tampered = build_tampered_receipt(&claims, |entries| {
            entries.push((
                Value::Integer(999.into()), // unknown key
                Value::Text("injected".to_string()),
            ));
        });
        let result = parse_air_v1(&tampered);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown claim key"));
    }

    #[test]
    fn test_non_integer_claim_key_rejected() {
        let claims = fixture_claims();
        let tampered = build_tampered_receipt(&claims, |entries| {
            entries.push((
                Value::Text("rogue".to_string()), // text key, not integer
                Value::Integer(42.into()),
            ));
        });
        let result = parse_air_v1(&tampered);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("non-integer claim key"));
    }

    #[test]
    fn test_eat_nonce_wrong_type_rejected() {
        let claims = fixture_claims();
        let tampered = build_tampered_receipt(&claims, |entries| {
            // Add eat_nonce as text instead of bstr
            entries.push((
                Value::Integer(EAT_NONCE.into()),
                Value::Text("not-bytes".to_string()),
            ));
        });
        let result = parse_air_v1(&tampered);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("is not a byte string"));
    }

    #[test]
    fn test_model_hash_scheme_wrong_type_rejected() {
        let mut claims = fixture_claims();
        claims.model_hash_scheme = Some("sha256-single".to_string());
        let tampered = build_tampered_receipt(&claims, |entries| {
            // Replace model_hash_scheme text with integer
            for (k, v) in entries.iter_mut() {
                if *k == Value::Integer(AIR_MODEL_HASH_SCHEME.into()) {
                    *v = Value::Integer(42.into());
                }
            }
        });
        let result = parse_air_v1(&tampered);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("is not a text string"));
    }

    #[test]
    fn test_pcr8_wrong_type_rejected() {
        let mut claims = fixture_claims();
        claims.enclave_measurements.pcr8 = Some(vec![8u8; 48]);
        let tampered = build_tampered_receipt(&claims, |entries| {
            // Find enclave_measurements and replace pcr8 bytes with text
            for (k, v) in entries.iter_mut() {
                if *k == Value::Integer(AIR_ENCLAVE_MEASUREMENTS.into()) {
                    if let Value::Map(ref mut meas) = v {
                        for (mk, mv) in meas.iter_mut() {
                            if *mk == Value::Text("pcr8".to_string()) {
                                *mv = Value::Text("not-bytes".to_string());
                            }
                        }
                    }
                }
            }
        });
        let result = parse_air_v1(&tampered);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("is not a byte string"));
    }

    #[test]
    fn test_pcr8_wrong_length_rejected() {
        let mut claims = fixture_claims();
        claims.enclave_measurements.pcr8 = Some(vec![8u8; 32]); // 32 instead of 48
        let key = ReceiptSigningKey::generate().unwrap();
        let result = build_air_v1(&claims, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("48 bytes"));
    }

    // ── Tier 1+2 hardening tests ────────────────────────────────────

    #[test]
    fn test_oversized_receipt_rejected() {
        // Fix 1: 70 KB random bytes → parse_air_v1 errors
        let oversized = vec![0xAA; 70_000];
        let result = parse_air_v1(&oversized);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("receipt too large"));
    }

    #[test]
    fn test_non_empty_unprotected_header_rejected() {
        // Fix 2: Build valid receipt, inject key_id in unprotected header
        let key = super::golden::key();
        let claims = fixture_claims();
        let payload_bytes = encode_claims(&claims).unwrap();

        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .content_format(coset::iana::CoapContentFormat::Cwt)
            .build();
        let unprotected = coset::HeaderBuilder::new()
            .key_id(b"rogue-kid".to_vec())
            .build();
        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload_bytes)
            .try_create_signature(b"", |tbs| Ok::<_, String>(key.raw_sign(tbs)))
            .unwrap()
            .build();
        let bytes = sign1.to_tagged_vec().unwrap();
        let result = parse_air_v1(&bytes);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("non-empty unprotected header"));
    }

    #[test]
    fn test_duplicate_claim_key_rejected() {
        // Fix 3: Inject duplicate iss key
        let claims = fixture_claims();
        let tampered = build_tampered_receipt(&claims, |entries| {
            entries.push((
                Value::Integer(CWT_ISS.into()),
                Value::Text("duplicate-iss".to_string()),
            ));
        });
        let result = parse_air_v1(&tampered);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("duplicate claim key"));
    }

    #[test]
    fn test_duplicate_measurement_key_rejected() {
        // Fix 3: Tamper enclave_measurements with duplicate "pcr0"
        let claims = fixture_claims();
        let tampered = build_tampered_receipt(&claims, |entries| {
            for (k, v) in entries.iter_mut() {
                if *k == Value::Integer(AIR_ENCLAVE_MEASUREMENTS.into()) {
                    if let Value::Map(ref mut meas) = v {
                        meas.push((
                            Value::Text("pcr0".to_string()),
                            Value::Bytes(vec![0xFF; 48]),
                        ));
                    }
                }
            }
        });
        let result = parse_air_v1(&tampered);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("duplicate key in enclave_measurements"));
    }

    #[test]
    fn test_unknown_security_mode_rejected_on_build() {
        // Fix 4: Unknown security_mode fails build
        let mut claims = fixture_claims();
        claims.security_mode = "FooMode".to_string();
        let key = ReceiptSigningKey::generate().unwrap();
        let result = build_air_v1(&claims, &key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown security_mode"));
    }

    #[test]
    fn test_iat_zero_rejected() {
        // Fix 5: iat=0 is rejected on parse
        let claims = fixture_claims();
        let tampered = build_tampered_receipt(&claims, |entries| {
            for (k, v) in entries.iter_mut() {
                if *k == Value::Integer(CWT_IAT.into()) {
                    *v = Value::Integer(0.into());
                }
            }
        });
        let result = parse_air_v1(&tampered);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("iat must not be zero"));
    }

    #[test]
    fn test_tdx_with_pcr8_rejected_on_build() {
        // Fix 6: TDX claims with pcr8 set → build fails
        let mut claims = fixture_claims();
        claims.enclave_measurements =
            EnclaveMeasurements::new_tdx(vec![10u8; 48], vec![20u8; 48], vec![30u8; 48]);
        claims.enclave_measurements.pcr8 = Some(vec![8u8; 48]);
        let key = ReceiptSigningKey::generate().unwrap();
        let result = build_air_v1(&claims, &key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("pcr8 is not allowed for TDX"));
    }

    #[test]
    fn test_tdx_with_pcr8_rejected_on_parse() {
        // Fix 6: Inject pcr8 into TDX measurements via tampered receipt
        let mut claims = fixture_claims();
        claims.enclave_measurements =
            EnclaveMeasurements::new_tdx(vec![10u8; 48], vec![20u8; 48], vec![30u8; 48]);
        let tampered = build_tampered_receipt(&claims, |entries| {
            for (k, v) in entries.iter_mut() {
                if *k == Value::Integer(AIR_ENCLAVE_MEASUREMENTS.into()) {
                    if let Value::Map(ref mut meas) = v {
                        meas.push((Value::Text("pcr8".to_string()), Value::Bytes(vec![8u8; 48])));
                    }
                }
            }
        });
        let result = parse_air_v1(&tampered);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("pcr8 is not allowed for TDX"));
    }

    #[test]
    fn test_empty_model_id_rejected() {
        // Fix 7: Empty model_id fails parse
        let claims = fixture_claims();
        let tampered = build_tampered_receipt(&claims, |entries| {
            for (k, v) in entries.iter_mut() {
                if *k == Value::Integer(AIR_MODEL_ID.into()) {
                    *v = Value::Text(String::new());
                }
            }
        });
        let result = parse_air_v1(&tampered);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must not be empty"));
    }

    #[test]
    fn test_oversized_model_id_rejected() {
        // Fix 7: 300-byte model_id exceeds max 256
        let claims = fixture_claims();
        let tampered = build_tampered_receipt(&claims, |entries| {
            for (k, v) in entries.iter_mut() {
                if *k == Value::Integer(AIR_MODEL_ID.into()) {
                    *v = Value::Text("x".repeat(300));
                }
            }
        });
        let result = parse_air_v1(&tampered);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds max length"));
    }

    #[test]
    fn test_current_timestamp_returns_result() {
        // Fix 8: current_timestamp() returns Result
        let ts = crate::current_timestamp().unwrap();
        assert!(ts > 0);
    }
}
