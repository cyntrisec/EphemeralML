use crate::{ClientError, FreshnessEnforcer, PolicyManager, Result};
use coset::{CborSerializable, CoseSign1};
use ephemeral_ml_common::{AttestationDocument, PcrMeasurements};
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use x509_parser::prelude::FromDer;

/// Attestation verification errors
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("Invalid certificate chain: {reason}")]
    InvalidCertificateChain { reason: String },

    #[error("PCR measurement validation failed: {reason}")]
    PcrValidationFailed { reason: String },

    #[error("Nonce validation failed: expected {expected}, got {actual}")]
    NonceValidationFailed { expected: String, actual: String },

    #[error("Attestation document expired: {timestamp}")]
    AttestationExpired { timestamp: u64 },

    #[error("Failed to extract ephemeral keys: {reason}")]
    KeyExtractionFailed { reason: String },

    #[error("Attestation document format invalid: {reason}")]
    InvalidFormat { reason: String },

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("COSE error: {0}")]
    CoseError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),
}

/// Extracted enclave identity from verified attestation
#[derive(Debug, Clone)]
pub struct EnclaveIdentity {
    pub module_id: String,
    pub measurements: PcrMeasurements,
    pub hpke_public_key: [u8; 32],
    pub receipt_signing_key: [u8; 32],
    pub protocol_version: u32,
    pub supported_features: Vec<String>,
    pub attestation_hash: [u8; 32],
    pub kms_public_key: Option<Vec<u8>>, // RSA SPKI DER
}

/// Attestation user data structure for key extraction
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttestationUserData {
    pub hpke_public_key: [u8; 32],
    pub receipt_signing_key: [u8; 32],
    pub protocol_version: u32,
    pub supported_features: Vec<String>,
}

/// AWS Nitro Enclaves Root CA (G1)
const AWS_NITRO_ROOT_CA: &[u8] = include_bytes!("aws_nitro_root_ca.der");

/// Helper to extract a map from serde_cbor::Value
fn cbor_as_map(val: &serde_cbor::Value) -> Option<&BTreeMap<serde_cbor::Value, serde_cbor::Value>> {
    match val {
        serde_cbor::Value::Map(m) => Some(m),
        _ => None,
    }
}

/// Attestation verifier for client-side verification
pub struct AttestationVerifier {
    policy_manager: PolicyManager,
    freshness_enforcer: FreshnessEnforcer,
}

impl AttestationVerifier {
    /// Create a new attestation verifier
    pub fn new(policy_manager: PolicyManager) -> Self {
        Self {
            policy_manager,
            freshness_enforcer: FreshnessEnforcer::new(),
        }
    }

    /// Generate a challenge nonce for attestation
    pub fn generate_challenge_nonce(&mut self) -> Result<Vec<u8>> {
        self.freshness_enforcer.generate_attestation_challenge()
    }

    /// Verify attestation document and extract enclave identity
    pub fn verify_attestation(
        &mut self,
        doc: &AttestationDocument,
        expected_nonce: &[u8],
    ) -> Result<EnclaveIdentity> {
        // Mock Bypass — skip COSE/cert verification but parse the CBOR payload
        // to extract real keys and PCRs from the mock attestation document.
        // SECURITY: This bypass is ONLY allowed in mock mode AND when production feature is disabled
        #[cfg(all(feature = "mock", not(feature = "production")))]
        if doc.module_id == "mock-enclave" || doc.module_id == "mock" {
            let attestation_hash = self.calculate_attestation_hash(doc)?;

            // Try to parse the CBOR payload in doc.signature to extract real keys
            let (hpke_public_key, receipt_signing_key, measurements, kms_public_key) =
                if let Ok(parsed) = serde_cbor::from_slice::<serde_cbor::Value>(&doc.signature) {
                    if let Some(map) = cbor_as_map(&parsed) {
                        // Extract user_data containing keys — reject if missing or unparseable
                        let ud_bytes = get_bytes_field(map, "user_data").map_err(|_| {
                            ClientError::Client(crate::EphemeralError::AttestationError(
                                "Mock attestation missing user_data field".to_string(),
                            ))
                        })?;
                        let ud = serde_json::from_slice::<AttestationUserData>(&ud_bytes).map_err(
                            |e| {
                                ClientError::Client(crate::EphemeralError::AttestationError(
                                    format!("Mock attestation user_data parse failed: {}", e),
                                ))
                            },
                        )?;

                        // Extract PCRs
                        let pcrs = self.extract_pcrs(map).unwrap_or_else(|_| doc.pcrs.clone());

                        // Extract KMS public key
                        let kms_pk = get_bytes_field(map, "public_key").ok();

                        (ud.hpke_public_key, ud.receipt_signing_key, pcrs, kms_pk)
                    } else {
                        return Err(ClientError::Client(
                            crate::EphemeralError::AttestationError(
                                "Mock attestation payload is not a CBOR map".to_string(),
                            ),
                        ));
                    }
                } else {
                    return Err(ClientError::Client(
                        crate::EphemeralError::AttestationError(
                            "Mock attestation signature is not valid CBOR".to_string(),
                        ),
                    ));
                };

            return Ok(EnclaveIdentity {
                module_id: "mock-enclave".to_string(),
                measurements,
                hpke_public_key,
                receipt_signing_key,
                protocol_version: 1,
                supported_features: vec![],
                attestation_hash,
                kms_public_key,
            });
        }

        // 1. Parse and verify the COSE structure and signature
        let (payload, cert_chain) = self.verify_cose_signature(&doc.signature)?;

        // 2. Validate certificate chain against AWS Nitro root
        self.validate_certificate_chain(&cert_chain)?;

        self.parse_and_validate_payload(payload, expected_nonce, doc)
    }

    /// Verify attestation document without nonce or PCR policy enforcement.
    ///
    /// Performs full COSE_Sign1 signature verification and certificate chain
    /// validation, but skips nonce comparison (caller handles nonce separately)
    /// and does NOT check PCR values against the policy allowlist.
    ///
    /// This is intended for use by the attestation bridge, where cml-transport's
    /// handshake already validates the nonce and PCR policy is enforced at
    /// the application layer.
    pub fn verify_attestation_skip_nonce(
        &mut self,
        doc: &AttestationDocument,
    ) -> Result<EnclaveIdentity> {
        // Mock bypass
        #[cfg(all(feature = "mock", not(feature = "production")))]
        if doc.module_id == "mock-enclave" || doc.module_id == "mock" {
            // Delegate to verify_attestation with dummy nonce (mock skips nonce check)
            return self.verify_attestation(doc, &[0u8; 32]);
        }

        // 1. Parse and verify the COSE structure and signature
        let (payload, cert_chain) = self.verify_cose_signature(&doc.signature)?;

        // 2. Validate certificate chain against AWS Nitro root
        self.validate_certificate_chain(&cert_chain)?;

        // 3. Parse payload — skip nonce, skip PCR policy
        self.parse_payload_core(payload, None, doc, false)
    }

    /// Verify attestation document without enforcing PCR policy.
    ///
    /// Performs full COSE_Sign1 signature verification and certificate chain
    /// validation, but does NOT check PCR values against the policy allowlist.
    /// This is intended for smoke tests and initial deployments where PCR values
    /// are being discovered for the first time.
    ///
    /// The returned `EnclaveIdentity` contains the real PCR measurements from
    /// the attestation document — callers should log/record them.
    pub fn verify_attestation_no_pcr_policy(
        &mut self,
        doc: &AttestationDocument,
        expected_nonce: &[u8],
    ) -> Result<EnclaveIdentity> {
        // 1. Parse and verify the COSE structure and signature
        let (payload, cert_chain) = self.verify_cose_signature(&doc.signature)?;

        // 2. Validate certificate chain against AWS Nitro root
        self.validate_certificate_chain(&cert_chain)?;

        // 3. Parse payload but skip PCR policy validation
        self.parse_and_validate_payload_inner(payload, expected_nonce, doc, false)
    }

    fn parse_and_validate_payload(
        &mut self,
        payload: Vec<u8>,
        expected_nonce: &[u8],
        doc: &AttestationDocument,
    ) -> Result<EnclaveIdentity> {
        self.parse_and_validate_payload_inner(payload, expected_nonce, doc, true)
    }

    fn parse_and_validate_payload_inner(
        &mut self,
        payload: Vec<u8>,
        expected_nonce: &[u8],
        doc: &AttestationDocument,
        enforce_pcr_policy: bool,
    ) -> Result<EnclaveIdentity> {
        self.parse_payload_core(payload, Some(expected_nonce), doc, enforce_pcr_policy)
    }

    fn parse_payload_core(
        &mut self,
        payload: Vec<u8>,
        expected_nonce: Option<&[u8]>,
        doc: &AttestationDocument,
        enforce_pcr_policy: bool,
    ) -> Result<EnclaveIdentity> {
        // 3. Parse attestation payload (CBOR)
        let attestation_payload: serde_cbor::Value =
            serde_cbor::from_slice(&payload).map_err(|e| {
                ClientError::Client(crate::EphemeralError::AttestationError(format!(
                    "Failed to parse attestation payload: {}",
                    e
                )))
            })?;

        let payload_map = cbor_as_map(&attestation_payload).ok_or_else(|| {
            ClientError::Client(crate::EphemeralError::AttestationError(
                "Payload is not a map".to_string(),
            ))
        })?;

        // 4. Validate nonce (skipped when expected_nonce is None — bridge mode)
        if let Some(expected) = expected_nonce {
            let doc_nonce = get_bytes_field(payload_map, "nonce")?;
            if doc_nonce != expected {
                return Err(ClientError::Client(
                    crate::EphemeralError::AttestationError(format!(
                        "Nonce mismatch: expected {}, got {}",
                        hex::encode(expected),
                        hex::encode(&doc_nonce)
                    )),
                ));
            }
        }

        // 5. Validate freshness timestamp (skipped when nonce is None — bridge mode)
        // NSM timestamps are in milliseconds; convert to seconds for FreshnessEnforcer
        // which uses current_timestamp() (seconds since epoch).
        if let Some(nonce) = expected_nonce {
            let timestamp_raw = get_int_field(payload_map, "timestamp")? as u64;
            let timestamp = if timestamp_raw > 1_000_000_000_000 {
                // Value is in milliseconds (> year 2001 in ms)
                timestamp_raw / 1000
            } else {
                timestamp_raw
            };
            self.freshness_enforcer
                .validate_attestation_response(nonce, timestamp)?;
        }

        // 6. Extract and validate PCRs
        let pcrs = self.extract_pcrs(payload_map)?;
        if enforce_pcr_policy {
            self.validate_pcr_measurements(&pcrs)?;
        }

        // 7. Extract module_id
        let module_id = get_str_field(payload_map, "module_id")?;

        // 8. Extract user_data and keys
        let user_data_bytes = get_bytes_field(payload_map, "user_data")?;
        let user_data: AttestationUserData =
            serde_json::from_slice(&user_data_bytes).map_err(|e| {
                ClientError::Client(crate::EphemeralError::AttestationError(format!(
                    "Failed to parse user data: {}",
                    e
                )))
            })?;

        // 9. Extract optional KMS public key
        let kms_public_key = get_bytes_field(payload_map, "public_key").ok();

        // 10. Calculate attestation hash for binding
        let attestation_hash = self.calculate_attestation_hash(doc)?;

        Ok(EnclaveIdentity {
            module_id,
            measurements: pcrs,
            hpke_public_key: user_data.hpke_public_key,
            receipt_signing_key: user_data.receipt_signing_key,
            protocol_version: user_data.protocol_version,
            supported_features: user_data.supported_features,
            attestation_hash,
            kms_public_key,
        })
    }

    fn verify_cose_signature(&self, cose_data: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
        let cose_sign1 = CoseSign1::from_slice(cose_data).map_err(|e| {
            ClientError::Client(crate::EphemeralError::AttestationError(format!(
                "COSE parse error: {:?}",
                e
            )))
        })?;

        let payload_bytes = cose_sign1.payload.as_deref().ok_or_else(|| {
            ClientError::Client(crate::EphemeralError::AttestationError(
                "COSE payload missing".to_string(),
            ))
        })?;

        // AWS Nitro NSM attestation documents store the certificate chain inside
        // the CBOR payload (fields "certificate" and "cabundle"), NOT in the COSE
        // headers (x5chain / label 33). Parse the payload first to extract them.
        let payload_value: serde_cbor::Value =
            serde_cbor::from_slice(payload_bytes).map_err(|e| {
                ClientError::Client(crate::EphemeralError::AttestationError(format!(
                    "Failed to parse CBOR payload for cert extraction: {}",
                    e
                )))
            })?;

        let payload_map = cbor_as_map(&payload_value).ok_or_else(|| {
            ClientError::Client(crate::EphemeralError::AttestationError(
                "CBOR payload is not a map".to_string(),
            ))
        })?;

        // Extract leaf certificate from "certificate" field
        let leaf_cert_der = get_bytes_field(payload_map, "certificate")?;

        // Extract CA bundle from "cabundle" field (array of DER-encoded certs)
        let cabundle_val = get_field(payload_map, "cabundle")?;
        let cabundle_certs = match cabundle_val {
            serde_cbor::Value::Array(arr) => {
                let mut certs = Vec::new();
                for v in arr {
                    if let serde_cbor::Value::Bytes(b) = v {
                        certs.push(b.clone());
                    }
                }
                certs
            }
            _ => {
                return Err(ClientError::Client(
                    crate::EphemeralError::AttestationError("cabundle is not an array".to_string()),
                ));
            }
        };

        // Build cert chain: leaf cert first, then intermediates ordered
        // closest-to-leaf first, closest-to-root last.
        // NSM cabundle is ordered root-to-leaf, so reverse it.
        let mut intermediates = cabundle_certs;
        intermediates.reverse();
        let mut cert_chain = vec![leaf_cert_der.clone()];
        cert_chain.extend(intermediates);

        let leaf_cert = X509::from_der(&leaf_cert_der).map_err(|e| {
            ClientError::Client(crate::EphemeralError::AttestationError(format!(
                "Invalid leaf cert: {}",
                e
            )))
        })?;

        let pubkey = leaf_cert.public_key().map_err(|e| {
            ClientError::Client(crate::EphemeralError::AttestationError(format!(
                "Failed to get pubkey: {}",
                e
            )))
        })?;

        // Verify COSE_Sign1 signature using coset's built-in tbs_data computation.
        // This ensures the Sig_structure CBOR encoding matches exactly what NSM signed.
        cose_sign1
            .verify_signature(&[], |sig, tbs_data| {
                // COSE uses raw (r || s) format for ECDSA signatures, but OpenSSL
                // expects DER-encoded signatures. Convert before verification.
                let der_sig = ecdsa_raw_to_der(sig).map_err(|e| {
                    ClientError::Client(crate::EphemeralError::AttestationError(format!(
                        "ECDSA signature format conversion failed: {}",
                        e
                    )))
                })?;

                let mut verifier =
                    Verifier::new(MessageDigest::sha384(), &pubkey).map_err(|e| {
                        ClientError::Client(crate::EphemeralError::AttestationError(format!(
                            "Verifier init failed: {}",
                            e
                        )))
                    })?;
                verifier.update(tbs_data).map_err(|e| {
                    ClientError::Client(crate::EphemeralError::AttestationError(format!(
                        "Verifier update failed: {}",
                        e
                    )))
                })?;
                if !verifier.verify(&der_sig).unwrap_or(false) {
                    return Err(ClientError::Client(
                        crate::EphemeralError::AttestationError(
                            "COSE signature verification failed".to_string(),
                        ),
                    ));
                }
                Ok(())
            })
            .map_err(|e: ClientError| e)?;

        let payload = cose_sign1.payload.ok_or_else(|| {
            ClientError::Client(crate::EphemeralError::AttestationError(
                "COSE payload missing".to_string(),
            ))
        })?;

        Ok((payload, cert_chain))
    }

    /// Validate AWS certificate chain: signatures, validity periods, and basic constraints.
    fn validate_certificate_chain(&self, cert_chain: &[Vec<u8>]) -> Result<()> {
        let root_ca = X509::from_der(AWS_NITRO_ROOT_CA).map_err(|e| {
            ClientError::Client(crate::EphemeralError::AttestationError(format!(
                "Invalid root CA: {}",
                e
            )))
        })?;

        let now = openssl::asn1::Asn1Time::days_from_now(0).map_err(|e| {
            ClientError::Client(crate::EphemeralError::AttestationError(format!(
                "Failed to get current time: {}",
                e
            )))
        })?;

        let mut last_cert = root_ca;

        for i in (0..cert_chain.len()).rev() {
            let cert_der = &cert_chain[i];
            let cert = X509::from_der(cert_der).map_err(|e| {
                ClientError::Client(crate::EphemeralError::AttestationError(format!(
                    "Invalid cert in chain: {}",
                    e
                )))
            })?;

            // Verify signature against parent cert's public key
            let pubkey = last_cert.public_key().map_err(|e| {
                ClientError::Client(crate::EphemeralError::AttestationError(format!(
                    "Failed to extract public key from cert at index {}: {}",
                    i, e
                )))
            })?;
            let verified = cert.verify(&pubkey).map_err(|e| {
                ClientError::Client(crate::EphemeralError::AttestationError(format!(
                    "Certificate verification failed at index {}: {}",
                    i, e
                )))
            })?;
            if !verified {
                return Err(ClientError::Client(
                    crate::EphemeralError::AttestationError(format!(
                        "Certificate signature mismatch at index {}",
                        i
                    )),
                ));
            }

            // Verify validity period (NotBefore <= now <= NotAfter)
            if cert.not_before() > now {
                return Err(ClientError::Client(
                    crate::EphemeralError::AttestationError(format!(
                        "Certificate at index {} is not yet valid (NotBefore: {})",
                        i,
                        cert.not_before()
                    )),
                ));
            }
            if cert.not_after() < now {
                return Err(ClientError::Client(
                    crate::EphemeralError::AttestationError(format!(
                        "Certificate at index {} has expired (NotAfter: {})",
                        i,
                        cert.not_after()
                    )),
                ));
            }

            // Verify BasicConstraints: non-leaf certs must have CA:TRUE
            // (i > 0 means it's an intermediate, not the leaf at index 0)
            if i > 0 {
                let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert_der)
                    .map_err(|e| {
                        ClientError::Client(crate::EphemeralError::AttestationError(format!(
                            "x509 parse error at index {}: {}",
                            i, e
                        )))
                    })?;
                match parsed.basic_constraints() {
                    Ok(Some(bc)) => {
                        if !bc.value.ca {
                            return Err(ClientError::Client(
                                crate::EphemeralError::AttestationError(format!(
                                    "Intermediate cert at index {} does not have CA:TRUE",
                                    i
                                )),
                            ));
                        }
                    }
                    _ => {
                        return Err(ClientError::Client(
                            crate::EphemeralError::AttestationError(format!(
                                "Intermediate cert at index {} is missing BasicConstraints extension",
                                i
                            )),
                        ));
                    }
                }
            }

            last_cert = cert;
        }

        Ok(())
    }

    /// Validate PCR measurements against client allowlist
    fn validate_pcr_measurements(&self, pcrs: &PcrMeasurements) -> Result<()> {
        let pcr0_hex = hex::encode(&pcrs.pcr0);
        let pcr1_hex = hex::encode(&pcrs.pcr1);
        let pcr2_hex = hex::encode(&pcrs.pcr2);

        let is_allowed = self
            .policy_manager
            .is_measurement_allowed(&pcr0_hex, &pcr1_hex, &pcr2_hex)
            .map_err(|e| {
                ClientError::Client(crate::EphemeralError::AttestationError(format!(
                    "Policy validation failed: {}",
                    e
                )))
            })?;

        if !is_allowed {
            return Err(ClientError::Client(
                crate::EphemeralError::AttestationError(format!(
                    "PCR measurements not in allowlist: PCR0={}, PCR1={}, PCR2={}",
                    pcr0_hex, pcr1_hex, pcr2_hex
                )),
            ));
        }

        Ok(())
    }

    fn extract_pcrs(
        &self,
        payload_map: &BTreeMap<serde_cbor::Value, serde_cbor::Value>,
    ) -> Result<PcrMeasurements> {
        let pcrs_val = get_field(payload_map, "pcrs")?;
        let pcrs_map = cbor_as_map(pcrs_val).ok_or_else(|| {
            ClientError::Client(crate::EphemeralError::AttestationError(
                "PCRs is not a map".to_string(),
            ))
        })?;

        let mut pcr0 = vec![];
        let mut pcr1 = vec![];
        let mut pcr2 = vec![];

        for (k, v) in pcrs_map {
            if let serde_cbor::Value::Integer(idx) = k {
                let bytes = match v {
                    serde_cbor::Value::Bytes(b) => b.clone(),
                    _ => {
                        return Err(ClientError::Client(
                            crate::EphemeralError::AttestationError(format!(
                                "PCR {} is not bytes",
                                idx
                            )),
                        ))
                    }
                };
                match idx {
                    0 => pcr0 = bytes,
                    1 => pcr1 = bytes,
                    2 => pcr2 = bytes,
                    _ => {}
                }
            }
        }

        if pcr0.is_empty() || pcr1.is_empty() || pcr2.is_empty() {
            return Err(ClientError::Client(
                crate::EphemeralError::AttestationError(
                    "Missing required PCRs (0, 1, or 2)".to_string(),
                ),
            ));
        }

        Ok(PcrMeasurements::new(pcr0, pcr1, pcr2))
    }

    /// Calculate attestation hash for session binding
    ///
    /// Uses SHA-256 of the raw attestation bytes (`doc.signature`) which contains
    /// either COSE_Sign1 (production) or CBOR map (mock). This ensures both server
    /// and client compute the same hash from the same wire bytes.
    fn calculate_attestation_hash(&self, doc: &AttestationDocument) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        Ok(Sha256::digest(&doc.signature).into())
    }
}

// Free-standing CBOR map helpers (work with BTreeMap)
fn get_field<'a>(
    map: &'a BTreeMap<serde_cbor::Value, serde_cbor::Value>,
    key: &str,
) -> Result<&'a serde_cbor::Value> {
    let key_val = serde_cbor::Value::Text(key.to_string());
    map.get(&key_val).ok_or_else(|| {
        ClientError::Client(crate::EphemeralError::AttestationError(format!(
            "Missing field: {}",
            key
        )))
    })
}

fn get_bytes_field(
    map: &BTreeMap<serde_cbor::Value, serde_cbor::Value>,
    key: &str,
) -> Result<Vec<u8>> {
    match get_field(map, key)? {
        serde_cbor::Value::Bytes(b) => Ok(b.clone()),
        _ => Err(ClientError::Client(
            crate::EphemeralError::AttestationError(format!("Field {} is not bytes", key)),
        )),
    }
}

fn get_str_field(
    map: &BTreeMap<serde_cbor::Value, serde_cbor::Value>,
    key: &str,
) -> Result<String> {
    match get_field(map, key)? {
        serde_cbor::Value::Text(s) => Ok(s.clone()),
        _ => Err(ClientError::Client(
            crate::EphemeralError::AttestationError(format!("Field {} is not text", key)),
        )),
    }
}

fn get_int_field(map: &BTreeMap<serde_cbor::Value, serde_cbor::Value>, key: &str) -> Result<i128> {
    match get_field(map, key)? {
        serde_cbor::Value::Integer(i) => Ok(*i),
        _ => Err(ClientError::Client(
            crate::EphemeralError::AttestationError(format!("Field {} is not integer", key)),
        )),
    }
}

/// Convert an ECDSA signature from COSE raw (r || s) format to DER encoding.
///
/// COSE encodes ECDSA signatures as fixed-length concatenation of r and s
/// (each component is half the total length). OpenSSL expects DER-encoded
/// ASN.1 SEQUENCE { INTEGER r, INTEGER s }.
fn ecdsa_raw_to_der(raw: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if !raw.len().is_multiple_of(2) || raw.is_empty() {
        return Err(format!(
            "Invalid ECDSA signature length: {} (expected even)",
            raw.len()
        ));
    }

    let half = raw.len() / 2;
    let r = &raw[..half];
    let s = &raw[half..];

    // Encode each integer component as ASN.1 INTEGER
    fn encode_integer(bytes: &[u8]) -> Vec<u8> {
        // Strip leading zeros (but keep at least one byte)
        let stripped = match bytes.iter().position(|&b| b != 0) {
            Some(pos) => &bytes[pos..],
            None => &[0u8],
        };
        // If high bit is set, prepend a 0x00 to keep it positive
        if stripped[0] & 0x80 != 0 {
            let mut result = vec![0x02, (stripped.len() + 1) as u8, 0x00];
            result.extend_from_slice(stripped);
            result
        } else {
            let mut result = vec![0x02, stripped.len() as u8];
            result.extend_from_slice(stripped);
            result
        }
    }

    let r_der = encode_integer(r);
    let s_der = encode_integer(s);

    let total_len = r_der.len() + s_der.len();
    let mut der = vec![0x30]; // SEQUENCE tag
    if total_len < 128 {
        der.push(total_len as u8);
    } else {
        der.push(0x81);
        der.push(total_len as u8);
    }
    der.extend_from_slice(&r_der);
    der.extend_from_slice(&s_der);

    Ok(der)
}
