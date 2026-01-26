use crate::{ClientError, Result, PolicyManager, FreshnessEnforcer};
use ephemeral_ml_common::{AttestationDocument, PcrMeasurements, current_timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
}

/// Attestation user data structure for key extraction
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttestationUserData {
    pub hpke_public_key: [u8; 32],
    pub receipt_signing_key: [u8; 32],
    pub protocol_version: u32,
    pub supported_features: Vec<String>,
}

/// Freshness tracker for nonce-based replay protection
#[derive(Debug)]
pub struct FreshnessTracker {
    used_nonces: HashMap<Vec<u8>, u64>, // nonce -> timestamp
    max_nonce_age: u64, // seconds
    max_entries: usize,
}

impl FreshnessTracker {
    /// Create a new freshness tracker
    pub fn new(max_nonce_age: u64, max_entries: usize) -> Self {
        Self {
            used_nonces: HashMap::new(),
            max_nonce_age,
            max_entries,
        }
    }
    
    /// Validate freshness of a nonce
    pub fn validate_freshness(&mut self, nonce: &[u8]) -> Result<()> {
        let current_time = current_timestamp();
        
        // Check if nonce was recently used
        if let Some(&timestamp) = self.used_nonces.get(nonce) {
            return Err(ClientError::Client(crate::EphemeralError::AttestationError(
                format!("Nonce replay detected: nonce was used at timestamp {}", timestamp)
            )));
        }
        
        // Check capacity and fail closed if over limit
        if self.used_nonces.len() >= self.max_entries {
            return Err(ClientError::Client(crate::EphemeralError::AttestationError(
                "Nonce tracker capacity exceeded - potential DoS attack".to_string()
            )));
        }
        
        // Add to tracking with current timestamp
        self.used_nonces.insert(nonce.to_vec(), current_time);
        
        // Cleanup expired entries
        self.cleanup_expired();
        
        Ok(())
    }
    
    /// Clean up expired nonces
    pub fn cleanup_expired(&mut self) {
        let current_time = current_timestamp();
        self.used_nonces.retain(|_, &mut timestamp| {
            current_time.saturating_sub(timestamp) < self.max_nonce_age
        });
    }
    
    /// Get the number of tracked nonces
    pub fn tracked_count(&self) -> usize {
        self.used_nonces.len()
    }
}

/// Attestation verifier for client-side verification
pub struct AttestationVerifier {
    policy_manager: PolicyManager,
    freshness_enforcer: FreshnessEnforcer,
    _aws_root_certificates: Vec<Vec<u8>>, // AWS Nitro root certificates
}

impl AttestationVerifier {
    /// Create a new attestation verifier
    pub fn new(policy_manager: PolicyManager) -> Self {
        Self {
            policy_manager,
            freshness_enforcer: FreshnessEnforcer::new(),
            _aws_root_certificates: Self::load_aws_root_certificates(),
        }
    }
    
    /// Generate a challenge nonce for attestation
    pub fn generate_challenge_nonce(&mut self) -> Result<Vec<u8>> {
        self.freshness_enforcer.generate_attestation_challenge()
    }
    
    /// Verify attestation document and extract enclave identity
    pub fn verify_attestation(&mut self, doc: &AttestationDocument, expected_nonce: &[u8]) -> Result<EnclaveIdentity> {
        // 1. Validate nonce freshness and timestamp
        self.validate_freshness(doc, expected_nonce)?;
        
        // 2. Validate certificate chain
        self.validate_certificate_chain(&doc.certificate)?;
        
        // 3. Validate PCR measurements against allowlist
        self.validate_pcr_measurements(&doc.pcrs)?;
        
        // 4. Extract ephemeral keys from user data
        let (hpke_key, receipt_key, protocol_version, features) = self.extract_ephemeral_keys(doc)?;
        
        // 5. Calculate attestation hash for binding
        let attestation_hash = self.calculate_attestation_hash(doc)?;
        
        Ok(EnclaveIdentity {
            module_id: doc.module_id.clone(),
            measurements: doc.pcrs.clone(),
            hpke_public_key: hpke_key,
            receipt_signing_key: receipt_key,
            protocol_version,
            supported_features: features,
            attestation_hash,
        })
    }
    
    /// Validate freshness using both nonce and timestamp
    fn validate_freshness(&mut self, doc: &AttestationDocument, expected_nonce: &[u8]) -> Result<()> {
        // Check if nonce is present
        let doc_nonce = doc.nonce.as_ref()
            .ok_or_else(|| ClientError::Client(crate::EphemeralError::AttestationError(
                "Attestation document missing nonce".to_string()
            )))?;
        
        // Verify nonce matches expected value
        if doc_nonce != expected_nonce {
            return Err(ClientError::Client(crate::EphemeralError::AttestationError(
                format!("Nonce mismatch: expected {:?}, got {:?}", 
                    hex::encode(expected_nonce), hex::encode(doc_nonce))
            )));
        }
        
        // Validate freshness using the enforcer
        self.freshness_enforcer.validate_attestation_response(expected_nonce, doc.timestamp)?;
        
        Ok(())
    }
    
    /// Validate AWS certificate chain
    fn validate_certificate_chain(&self, certificate: &[u8]) -> Result<()> {
        // In mock mode, skip certificate validation
        #[cfg(feature = "mock")]
        {
            if certificate == b"mock_certificate" {
                return Ok(());
            }
        }
        
        // Production certificate validation
        #[cfg(not(feature = "mock"))]
        {
            // Parse certificate chain
            let cert_chain = self.parse_certificate_chain(certificate)?;
            
            // Validate against AWS root certificates
            self.validate_against_aws_roots(&cert_chain)?;
            
            // Validate certificate validity periods
            self.validate_certificate_validity(&cert_chain)?;
        }
        
        // For v1, implement basic validation
        if certificate.is_empty() {
            return Err(ClientError::Client(crate::EphemeralError::AttestationError(
                "Certificate chain is empty".to_string()
            )));
        }
        
        Ok(())
    }
    
    /// Validate PCR measurements against client allowlist
    fn validate_pcr_measurements(&self, pcrs: &PcrMeasurements) -> Result<()> {
        // Get current policy
        let _policy = self.policy_manager.current_policy()
            .ok_or_else(|| ClientError::Client(crate::EphemeralError::AttestationError(
                "No active policy loaded".to_string()
            )))?;
        
        // Convert PCR measurements to hex strings for comparison
        let pcr0_hex = hex::encode(&pcrs.pcr0);
        let pcr1_hex = hex::encode(&pcrs.pcr1);
        let pcr2_hex = hex::encode(&pcrs.pcr2);
        
        // Check against measurement allowlist
        let is_allowed = self.policy_manager.is_measurement_allowed(&pcr0_hex, &pcr1_hex, &pcr2_hex)
            .map_err(|e| ClientError::Client(crate::EphemeralError::AttestationError(
                format!("Policy validation failed: {}", e)
            )))?;
        
        if !is_allowed {
            return Err(ClientError::Client(crate::EphemeralError::AttestationError(
                format!("PCR measurements not in allowlist: PCR0={}, PCR1={}, PCR2={}", 
                    pcr0_hex, pcr1_hex, pcr2_hex)
            )));
        }
        
        Ok(())
    }
    
    /// Extract ephemeral keys from attestation user data
    fn extract_ephemeral_keys(&self, doc: &AttestationDocument) -> Result<([u8; 32], [u8; 32], u32, Vec<String>)> {
        // For mock mode, extract from signature field (which contains the full CBOR document)
        #[cfg(feature = "mock")]
        {
            if doc.module_id == "mock-enclave" {
                // Return mock keys for testing
                let hpke_key = [0x01; 32];
                let receipt_key = [0x02; 32];
                return Ok((hpke_key, receipt_key, 1, vec!["gateway".to_string()]));
            }
        }
        
        // Production mode: parse CBOR attestation document
        let parsed_doc: serde_cbor::Value = serde_cbor::from_slice(&doc.signature)
            .map_err(|e| ClientError::Client(crate::EphemeralError::AttestationError(
                format!("Failed to parse CBOR attestation document: {}", e)
            )))?;
        
        // Extract user_data field
        let doc_map = match parsed_doc {
            serde_cbor::Value::Map(map) => map,
            _ => return Err(ClientError::Client(crate::EphemeralError::AttestationError(
                "Attestation document is not a CBOR map".to_string()
            ))),
        };
        
        let user_data_bytes = doc_map.get(&serde_cbor::Value::Text("user_data".to_string()))
            .and_then(|v| match v {
                serde_cbor::Value::Bytes(bytes) => Some(bytes.as_slice()),
                _ => None,
            })
            .ok_or_else(|| ClientError::Client(crate::EphemeralError::AttestationError(
                "No user_data field in attestation document".to_string()
            )))?;
        
        // Parse user data as JSON
        let user_data: AttestationUserData = serde_json::from_slice(user_data_bytes)
            .map_err(|e| ClientError::Client(crate::EphemeralError::AttestationError(
                format!("Failed to parse user data: {}", e)
            )))?;
        
        // Validate protocol version
        if user_data.protocol_version != 1 {
            return Err(ClientError::Client(crate::EphemeralError::AttestationError(
                format!("Unsupported protocol version: {}", user_data.protocol_version)
            )));
        }
        
        Ok((
            user_data.hpke_public_key,
            user_data.receipt_signing_key,
            user_data.protocol_version,
            user_data.supported_features,
        ))
    }
    
    /// Calculate attestation hash for session binding
    fn calculate_attestation_hash(&self, doc: &AttestationDocument) -> Result<[u8; 32]> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&doc.module_id.as_bytes());
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
    
    /// Load AWS Nitro root certificates (placeholder for v1)
    fn load_aws_root_certificates() -> Vec<Vec<u8>> {
        // In production, this would load actual AWS Nitro root certificates
        // For v1, return empty list as certificate validation is simplified
        vec![]
    }
    
    /// Parse certificate chain (production implementation)
    #[cfg(not(feature = "mock"))]
    fn parse_certificate_chain(&self, _certificate: &[u8]) -> Result<Vec<Vec<u8>>> {
        // TODO: Implement X.509 certificate chain parsing
        // This would use a crate like `x509-parser` or `rustls`
        todo!("Implement certificate chain parsing for production")
    }
    
    /// Validate certificate chain against AWS roots (production implementation)
    #[cfg(not(feature = "mock"))]
    fn validate_against_aws_roots(&self, _cert_chain: &[Vec<u8>]) -> Result<()> {
        // TODO: Implement certificate chain validation against AWS roots
        todo!("Implement certificate chain validation for production")
    }
    
    /// Validate certificate validity periods (production implementation)
    #[cfg(not(feature = "mock"))]
    fn validate_certificate_validity(&self, _cert_chain: &[Vec<u8>]) -> Result<()> {
        // TODO: Implement certificate validity period checking
        todo!("Implement certificate validity checking for production")
    }
    
    /// Update policy bundle
    pub fn update_policy(&mut self, policy_data: &[u8]) -> Result<()> {
        self.policy_manager.load_policy(policy_data)
            .map_err(|e| ClientError::Client(crate::EphemeralError::AttestationError(
                format!("Failed to update policy: {}", e)
            )))
    }
    
    /// Get freshness tracker statistics
    pub fn get_freshness_stats(&self) -> crate::FreshnessStats {
        self.freshness_enforcer.get_stats()
    }
    
    /// Perform cleanup of expired nonces
    pub fn cleanup_expired(&mut self) {
        self.freshness_enforcer.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyManager;

    #[test]
    fn test_freshness_tracker() {
        let mut tracker = FreshnessTracker::new(300, 10); // 5 minutes, 10 entries
        
        let nonce1 = b"nonce1";
        let nonce2 = b"nonce2";
        
        // First use should succeed
        assert!(tracker.validate_freshness(nonce1).is_ok());
        assert_eq!(tracker.tracked_count(), 1);
        
        // Replay should fail
        assert!(tracker.validate_freshness(nonce1).is_err());
        
        // Different nonce should succeed
        assert!(tracker.validate_freshness(nonce2).is_ok());
        assert_eq!(tracker.tracked_count(), 2);
    }
    
    #[test]
    fn test_freshness_tracker_capacity() {
        let mut tracker = FreshnessTracker::new(300, 2); // Small capacity
        
        assert!(tracker.validate_freshness(b"nonce1").is_ok());
        assert!(tracker.validate_freshness(b"nonce2").is_ok());
        
        // Should fail when capacity exceeded
        assert!(tracker.validate_freshness(b"nonce3").is_err());
    }
    
    #[test]
    #[cfg(feature = "mock")]
    fn test_attestation_verifier_mock_mode() {
        let mut policy_manager = PolicyManager::new();
        let policy = PolicyManager::create_default_policy();
        let policy_data = serde_json::to_vec(&policy).unwrap();
        policy_manager.load_policy(&policy_data).unwrap();
        
        let mut verifier = AttestationVerifier::new(policy_manager);
        
        // Generate challenge nonce
        let nonce = verifier.generate_challenge_nonce().unwrap();
        
        // Create mock attestation document
        let mut doc = crate::mock::MockSecureClient::generate_mock_attestation();
        doc.nonce = Some(nonce.clone());
        
        // Should succeed in mock mode
        let identity = verifier.verify_attestation(&doc, &nonce).unwrap();
        assert_eq!(identity.module_id, "mock-enclave");
        assert_eq!(identity.protocol_version, 1);
    }
    
    #[test]
    fn test_attestation_user_data_serialization() {
        let user_data = AttestationUserData {
            hpke_public_key: [1u8; 32],
            receipt_signing_key: [2u8; 32],
            protocol_version: 1,
            supported_features: vec!["gateway".to_string()],
        };
        
        let serialized = serde_json::to_vec(&user_data).unwrap();
        let deserialized: AttestationUserData = serde_json::from_slice(&serialized).unwrap();
        
        assert_eq!(user_data.hpke_public_key, deserialized.hpke_public_key);
        assert_eq!(user_data.receipt_signing_key, deserialized.receipt_signing_key);
        assert_eq!(user_data.protocol_version, deserialized.protocol_version);
        assert_eq!(user_data.supported_features, deserialized.supported_features);
    }
}