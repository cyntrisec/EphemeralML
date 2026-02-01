use crate::{ClientError, FreshnessEnforcer, PolicyManager, Result};
use coset::{CborSerializable, CoseSign1, Label};
use ephemeral_ml_common::{current_timestamp, AttestationDocument, PcrMeasurements};
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

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
        // Mock Bypass — skip COSE/CBOR parsing entirely in mock mode
        // SECURITY: This bypass is ONLY allowed in mock mode AND when production feature is disabled
        #[cfg(all(feature = "mock", not(feature = "production")))]
        if doc.module_id == "mock-enclave" || doc.module_id == "mock" {
            let attestation_hash = self.calculate_attestation_hash(doc)?;
            return Ok(EnclaveIdentity {
                module_id: "mock-enclave".to_string(),
                measurements: doc.pcrs.clone(),
                hpke_public_key: [0u8; 32],
                receipt_signing_key: [0u8; 32],
                protocol_version: 1,
                supported_features: vec![],
                attestation_hash,
                kms_public_key: None,
            });
        }

        // 1. Parse and verify the COSE structure and signature
        let (payload, cert_chain) = self.verify_cose_signature(&doc.signature)?;

        // 2. Validate certificate chain against AWS Nitro root
        self.validate_certificate_chain(&cert_chain)?;

        self.parse_and_validate_payload(payload, expected_nonce, doc)
    }

    fn parse_and_validate_payload(
        &mut self,
        payload: Vec<u8>,
        expected_nonce: &[u8],
        doc: &AttestationDocument,
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

        // 4. Validate nonce
        let doc_nonce = get_bytes_field(payload_map, "nonce")?;
        if doc_nonce != expected_nonce {
            return Err(ClientError::Client(
                crate::EphemeralError::AttestationError(format!(
                    "Nonce mismatch: expected {}, got {}",
                    hex::encode(expected_nonce),
                    hex::encode(&doc_nonce)
                )),
            ));
        }

        // 5. Validate freshness timestamp
        let timestamp = get_int_field(payload_map, "timestamp")? as u64;
        self.freshness_enforcer
            .validate_attestation_response(expected_nonce, timestamp)?;

        // 6. Extract and validate PCRs
        let pcrs = self.extract_pcrs(payload_map)?;
        self.validate_pcr_measurements(&pcrs)?;

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

        // Extract certificate chain from unprotected header
        // In COSE, label 33 is "x5chain" (certificate chain)
        let mut cert_chain = Vec::new();
        for (label, value) in &cose_sign1.unprotected.rest {
            if *label == Label::Int(33) {
                match value {
                    ciborium::Value::Bytes(b) => {
                        cert_chain.push(b.clone());
                    }
                    ciborium::Value::Array(a) => {
                        for v in a {
                            if let ciborium::Value::Bytes(b) = v {
                                cert_chain.push(b.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if cert_chain.is_empty() {
            return Err(ClientError::Client(
                crate::EphemeralError::AttestationError(
                    "No certificate chain found in COSE header".to_string(),
                ),
            ));
        }

        let leaf_cert_der = &cert_chain[0];
        let leaf_cert = X509::from_der(leaf_cert_der).map_err(|e| {
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

        // Verify COSE_Sign1 signature
        // The signature is over the Sig_structure: ["Signature1", protected, external_aad, payload]
        let protected_bytes = cose_sign1
            .protected
            .original_data
            .clone()
            .unwrap_or_default();
        let payload_bytes = cose_sign1.payload.as_deref().unwrap_or(&[]);

        // Build Sig_structure manually
        let sig_structure = serde_cbor::Value::Array(vec![
            serde_cbor::Value::Text("Signature1".to_string()),
            serde_cbor::Value::Bytes(protected_bytes),
            serde_cbor::Value::Bytes(vec![]), // external_aad
            serde_cbor::Value::Bytes(payload_bytes.to_vec()),
        ]);
        let sig_data = serde_cbor::to_vec(&sig_structure).map_err(|e| {
            ClientError::Client(crate::EphemeralError::AttestationError(format!(
                "Failed to encode Sig_structure: {}",
                e
            )))
        })?;

        let mut verifier = Verifier::new(MessageDigest::sha384(), &pubkey).map_err(|e| {
            ClientError::Client(crate::EphemeralError::AttestationError(format!(
                "Verifier init failed: {}",
                e
            )))
        })?;
        verifier.update(&sig_data).map_err(|e| {
            ClientError::Client(crate::EphemeralError::AttestationError(format!(
                "Verifier update failed: {}",
                e
            )))
        })?;

        if !verifier.verify(&cose_sign1.signature).unwrap_or(false) {
            return Err(ClientError::Client(
                crate::EphemeralError::AttestationError(
                    "COSE signature verification failed".to_string(),
                ),
            ));
        }

        let payload = cose_sign1.payload.ok_or_else(|| {
            ClientError::Client(crate::EphemeralError::AttestationError(
                "COSE payload missing".to_string(),
            ))
        })?;

        Ok((payload, cert_chain))
    }

    /// Validate AWS certificate chain
    fn validate_certificate_chain(&self, cert_chain: &[Vec<u8>]) -> Result<()> {
        let root_ca = X509::from_der(AWS_NITRO_ROOT_CA).map_err(|e| {
            ClientError::Client(crate::EphemeralError::AttestationError(format!(
                "Invalid root CA: {}",
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

            let pubkey = last_cert.public_key().unwrap();
            if !cert.verify(&pubkey).unwrap() {
                return Err(ClientError::Client(
                    crate::EphemeralError::AttestationError(format!(
                        "Cert verification failed at index {}",
                        i
                    )),
                ));
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
    fn calculate_attestation_hash(&self, doc: &AttestationDocument) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(doc.module_id.as_bytes());
        hasher.update(&doc.digest);
        hasher.update(&doc.timestamp.to_be_bytes());
        hasher.update(&doc.pcrs.pcr0);
        hasher.update(&doc.pcrs.pcr1);
        hasher.update(&doc.pcrs.pcr2);
        hasher.update(&doc.certificate);

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        Ok(result)
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
