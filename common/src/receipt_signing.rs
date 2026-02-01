//! Ed25519 receipt signing keys and Attested Execution Receipt (AER) generation
//!
//! This module implements separate Ed25519 keypairs for AER signature generation,
//! binding both HPKE and receipt keys in attestation user data, and canonical
//! encoding for receipt fields.

use crate::error::{EphemeralError, Result};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Ed25519 receipt signing keypair with secure memory management
#[derive(ZeroizeOnDrop)]
pub struct ReceiptSigningKey {
    /// Ed25519 private key (zeroized on drop)
    private_key: ed25519_dalek::SigningKey,
    /// Ed25519 public key (public keys don't need zeroization)
    #[zeroize(skip)]
    pub public_key: ed25519_dalek::VerifyingKey,
    /// Key generation timestamp
    pub created_at: u64,
    /// Key expiration (for per-session keys)
    pub expires_at: Option<u64>,
}

impl ReceiptSigningKey {
    /// Generate new Ed25519 keypair for receipt signing
    pub fn generate() -> Result<Self> {
        use rand::rngs::OsRng;

        let private_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let public_key = private_key.verifying_key();
        let created_at = crate::current_timestamp();

        Ok(Self {
            private_key,
            public_key,
            created_at,
            expires_at: None,
        })
    }

    /// Generate new Ed25519 keypair with expiration (for per-session keys)
    pub fn generate_with_expiry(ttl_seconds: u64) -> Result<Self> {
        let mut key = Self::generate()?;
        key.expires_at = Some(key.created_at + ttl_seconds);
        Ok(key)
    }

    /// Create from existing keys (for testing)
    pub fn from_parts(
        private_key: ed25519_dalek::SigningKey,
        public_key: ed25519_dalek::VerifyingKey,
    ) -> Self {
        Self {
            private_key,
            public_key,
            created_at: crate::current_timestamp(),
            expires_at: None,
        }
    }

    /// Get public key bytes for embedding in attestation user data
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    /// Sign receipt with canonical encoding
    pub fn sign_receipt(&self, receipt: &AttestationReceipt) -> Result<Vec<u8>> {
        if let Some(expires_at) = self.expires_at {
            if crate::current_timestamp() >= expires_at {
                return Err(EphemeralError::EncryptionError(
                    "Signing key expired".to_string(),
                ));
            }
        }

        let canonical_encoding = receipt.canonical_encoding()?;
        let signature = self.private_key.sign(&canonical_encoding);
        Ok(signature.to_bytes().to_vec())
    }

    /// Check if key is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            crate::current_timestamp() >= expires_at
        } else {
            false
        }
    }
}

/// Attestation user data structure containing both HPKE and receipt keys
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestationUserData {
    /// X25519 public key for HPKE session establishment
    pub hpke_public_key: [u8; 32],
    /// Ed25519 public key for receipt signature verification
    pub receipt_signing_key: [u8; 32],
    /// Protocol version (fixed to 1 for v1)
    pub protocol_version: u32,
    /// Supported features for negotiation
    pub supported_features: Vec<String>,
    /// Timestamp when keys were generated
    pub key_generation_timestamp: u64,
}

impl AttestationUserData {
    /// Create new attestation user data with both key types
    pub fn new(
        hpke_public_key: [u8; 32],
        receipt_signing_key: [u8; 32],
        protocol_version: u32,
        supported_features: Vec<String>,
    ) -> Self {
        Self {
            hpke_public_key,
            receipt_signing_key,
            protocol_version,
            supported_features,
            key_generation_timestamp: crate::current_timestamp(),
        }
    }

    /// Serialize to CBOR for embedding in attestation document
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        serde_cbor::to_vec(self)
            .map_err(|e| EphemeralError::SerializationError(format!("CBOR encoding failed: {}", e)))
    }

    /// Deserialize from CBOR attestation user data
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        serde_cbor::from_slice(data)
            .map_err(|e| EphemeralError::SerializationError(format!("CBOR decoding failed: {}", e)))
    }

    /// Validate user data constraints (≤ 1KB for Nitro)
    pub fn validate_size(&self) -> Result<()> {
        let cbor_data = self.to_cbor()?;
        if cbor_data.len() > 1024 {
            return Err(EphemeralError::ValidationError(format!(
                "User data too large: {} bytes (max 1024)",
                cbor_data.len()
            )));
        }
        Ok(())
    }
}

/// Attested Execution Receipt (AER) with comprehensive metadata
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestationReceipt {
    /// Unique receipt identifier
    pub receipt_id: String,
    /// Protocol version for compatibility
    pub protocol_version: u32,
    /// Security mode (Gateway-only for v1)
    pub security_mode: SecurityMode,
    /// Enclave measurements from attestation
    pub enclave_measurements: EnclaveMeasurements,
    /// Hash of the attestation document
    pub attestation_doc_hash: [u8; 32],
    /// Hash of the inference request (plaintext)
    pub request_hash: [u8; 32],
    /// Hash of the inference response/output
    pub response_hash: [u8; 32],
    /// Policy version used for this inference
    pub policy_version: String,
    /// Monotonic sequence number within session
    pub sequence_number: u64,
    /// Execution timestamp (informational only)
    pub execution_timestamp: u64,
    /// Model identifier and version
    pub model_id: String,
    pub model_version: String,
    /// Execution metadata
    pub execution_time_ms: u64,
    pub memory_peak_mb: u64,
    /// Ed25519 signature (set after signing)
    pub signature: Option<Vec<u8>>,
}

/// Security mode for the inference execution
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SecurityMode {
    /// Layer 1 (Gateway) security only
    GatewayOnly,
    /// Layer 2 (Shield Mode) - reserved for v2
    #[allow(dead_code)]
    ShieldMode,
}

/// Enclave measurements for receipt binding
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EnclaveMeasurements {
    /// Enclave image measurement (PCR0 equivalent)
    #[serde(with = "serde_bytes")]
    pub pcr0: Vec<u8>,
    /// Linux kernel measurement (PCR1 equivalent)
    #[serde(with = "serde_bytes")]
    pub pcr1: Vec<u8>,
    /// Application measurement (PCR2 equivalent)
    #[serde(with = "serde_bytes")]
    pub pcr2: Vec<u8>,
    /// Additional measurements (PCR8 equivalent)
    #[serde(with = "serde_bytes")]
    pub pcr8: Option<Vec<u8>>,
}

impl EnclaveMeasurements {
    /// Create new enclave measurements
    pub fn new(pcr0: Vec<u8>, pcr1: Vec<u8>, pcr2: Vec<u8>) -> Self {
        Self {
            pcr0,
            pcr1,
            pcr2,
            pcr8: None,
        }
    }

    /// Validate measurement lengths (should be 48 bytes each for SHA-384)
    pub fn is_valid(&self) -> bool {
        self.pcr0.len() == 48 && self.pcr1.len() == 48 && self.pcr2.len() == 48
    }
}

impl AttestationReceipt {
    /// Create new attestation receipt
    pub fn new(
        receipt_id: String,
        protocol_version: u32,
        security_mode: SecurityMode,
        enclave_measurements: EnclaveMeasurements,
        attestation_doc_hash: [u8; 32],
        request_hash: [u8; 32],
        response_hash: [u8; 32],
        policy_version: String,
        sequence_number: u64,
        model_id: String,
        model_version: String,
        execution_time_ms: u64,
        memory_peak_mb: u64,
    ) -> Self {
        Self {
            receipt_id,
            protocol_version,
            security_mode,
            enclave_measurements,
            attestation_doc_hash,
            request_hash,
            response_hash,
            policy_version,
            sequence_number,
            execution_timestamp: crate::current_timestamp(),
            model_id,
            model_version,
            execution_time_ms,
            memory_peak_mb,
            signature: None,
        }
    }

    /// Generate canonical encoding for signature (deterministic CBOR)
    pub fn canonical_encoding(&self) -> Result<Vec<u8>> {
        // Create a copy without the signature for canonical encoding
        let mut receipt_for_signing = self.clone();
        receipt_for_signing.signature = None;

        // Use deterministic CBOR encoding with sorted keys
        let cbor_data = serde_cbor::to_vec(&receipt_for_signing).map_err(|e| {
            EphemeralError::SerializationError(format!("CBOR encoding failed: {}", e))
        })?;

        // Ensure deterministic encoding by sorting map keys
        // Note: serde_cbor should handle this, but we document the requirement
        Ok(cbor_data)
    }

    /// Sign the receipt with Ed25519 key
    pub fn sign(&mut self, signing_key: &ReceiptSigningKey) -> Result<()> {
        let signature = signing_key.sign_receipt(self)?;
        self.signature = Some(signature);
        Ok(())
    }

    /// Verify receipt signature
    pub fn verify_signature(&self, public_key: &ed25519_dalek::VerifyingKey) -> Result<bool> {
        let signature_bytes = self
            .signature
            .as_ref()
            .ok_or_else(|| EphemeralError::ValidationError("Receipt not signed".to_string()))?;

        if signature_bytes.len() != 64 {
            return Err(EphemeralError::ValidationError(
                "Invalid signature length".to_string(),
            ));
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(signature_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        let canonical_encoding = self.canonical_encoding()?;

        match public_key.verify_strict(&canonical_encoding, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Receipt binding for linking receipts to attestation documents
#[derive(Debug, Clone)]
pub struct ReceiptBinding {
    /// HPKE public key from attestation user data
    pub hpke_public_key: [u8; 32],
    /// Receipt signing public key from attestation user data
    pub receipt_signing_key: [u8; 32],
    /// Hash of the attestation document
    pub attestation_hash: [u8; 32],
    /// Session ID for linking to specific session
    pub session_id: String,
    /// Protocol version
    pub protocol_version: u32,
}

impl ReceiptBinding {
    /// Create new receipt binding from attestation document
    pub fn from_attestation(
        attestation_doc: &[u8],
        user_data: &AttestationUserData,
        session_id: String,
    ) -> Result<Self> {
        use sha2::{Digest, Sha256};

        // Hash the attestation document
        let mut hasher = Sha256::new();
        hasher.update(attestation_doc);
        let attestation_hash_vec = hasher.finalize();
        let mut attestation_hash = [0u8; 32];
        attestation_hash.copy_from_slice(&attestation_hash_vec);

        Ok(Self {
            hpke_public_key: user_data.hpke_public_key,
            receipt_signing_key: user_data.receipt_signing_key,
            attestation_hash,
            session_id,
            protocol_version: user_data.protocol_version,
        })
    }

    /// Verify that a receipt is bound to this attestation
    pub fn verify_receipt_binding(&self, receipt: &AttestationReceipt) -> Result<bool> {
        // Check protocol version match
        if receipt.protocol_version != self.protocol_version {
            return Ok(false);
        }

        // Check attestation document hash match
        if receipt.attestation_doc_hash != self.attestation_hash {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Receipt verifier for client-side verification
pub struct ReceiptVerifier {
    /// Trusted attestation root certificates
    _trusted_roots: Vec<Vec<u8>>,
}

impl ReceiptVerifier {
    /// Create new receipt verifier with trusted roots
    pub fn new(trusted_roots: Vec<Vec<u8>>) -> Self {
        Self {
            _trusted_roots: trusted_roots,
        }
    }

    /// Verify receipt authenticity and binding
    pub fn verify_receipt(
        &self,
        receipt: &AttestationReceipt,
        attestation_doc: &[u8],
    ) -> Result<bool> {
        // Parse user data from attestation document
        let user_data = self.extract_user_data(attestation_doc)?;

        // Create Ed25519 verifying key from user data
        let public_key_bytes = user_data.receipt_signing_key;
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| EphemeralError::ValidationError(format!("Invalid public key: {}", e)))?;

        // Verify receipt signature
        let signature_valid = receipt.verify_signature(&public_key)?;
        if !signature_valid {
            return Ok(false);
        }

        // Verify receipt binding to attestation
        let binding = ReceiptBinding::from_attestation(
            attestation_doc,
            &user_data,
            "session".to_string(), // Session ID not available in this context
        )?;

        binding.verify_receipt_binding(receipt)
    }

    /// Extract user data from attestation document (simplified for v1)
    fn extract_user_data(&self, _attestation_doc: &[u8]) -> Result<AttestationUserData> {
        // In production, this would parse the actual attestation document
        // For v1, we return a placeholder
        Err(EphemeralError::Internal(
            "Attestation parsing not implemented".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_signing_key_generation() {
        let key = ReceiptSigningKey::generate().unwrap();
        assert_eq!(key.public_key_bytes().len(), 32);
        assert!(!key.is_expired());
    }

    #[test]
    fn test_receipt_signing_key_with_expiry() {
        let key = ReceiptSigningKey::generate_with_expiry(1).unwrap();
        assert!(!key.is_expired());

        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(key.is_expired());
    }

    #[test]
    fn test_attestation_user_data() {
        let hpke_key = [1u8; 32];
        let receipt_key = [2u8; 32];
        let features = vec!["feature1".to_string(), "feature2".to_string()];

        let user_data = AttestationUserData::new(hpke_key, receipt_key, 1, features.clone());

        assert_eq!(user_data.hpke_public_key, hpke_key);
        assert_eq!(user_data.receipt_signing_key, receipt_key);
        assert_eq!(user_data.protocol_version, 1);
        assert_eq!(user_data.supported_features, features);

        // Test CBOR serialization
        let cbor_data = user_data.to_cbor().unwrap();
        let decoded = AttestationUserData::from_cbor(&cbor_data).unwrap();
        assert_eq!(user_data.hpke_public_key, decoded.hpke_public_key);
        assert_eq!(user_data.receipt_signing_key, decoded.receipt_signing_key);
    }

    #[test]
    fn test_attestation_receipt_creation() {
        let measurements = EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);

        let receipt = AttestationReceipt::new(
            "test-receipt".to_string(),
            1,
            SecurityMode::GatewayOnly,
            measurements,
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            "policy-v1".to_string(),
            42,
            "test-model".to_string(),
            "v1.0".to_string(),
            1000,
            512,
        );

        assert_eq!(receipt.receipt_id, "test-receipt");
        assert_eq!(receipt.protocol_version, 1);
        assert_eq!(receipt.security_mode, SecurityMode::GatewayOnly);
        assert_eq!(receipt.sequence_number, 42);
        assert!(receipt.signature.is_none());
    }

    #[test]
    fn test_receipt_signing_and_verification() {
        let signing_key = ReceiptSigningKey::generate().unwrap();
        let measurements = EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);

        let mut receipt = AttestationReceipt::new(
            "test-receipt".to_string(),
            1,
            SecurityMode::GatewayOnly,
            measurements,
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            "policy-v1".to_string(),
            42,
            "test-model".to_string(),
            "v1.0".to_string(),
            1000,
            512,
        );

        // Sign the receipt
        receipt.sign(&signing_key).unwrap();
        assert!(receipt.signature.is_some());

        // Verify the signature
        let is_valid = receipt.verify_signature(&signing_key.public_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_canonical_encoding() {
        let measurements = EnclaveMeasurements::new(vec![1u8; 48], vec![2u8; 48], vec![3u8; 48]);

        let receipt = AttestationReceipt::new(
            "test-receipt".to_string(),
            1,
            SecurityMode::GatewayOnly,
            measurements,
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            "policy-v1".to_string(),
            42,
            "test-model".to_string(),
            "v1.0".to_string(),
            1000,
            512,
        );

        let encoding1 = receipt.canonical_encoding().unwrap();
        let encoding2 = receipt.canonical_encoding().unwrap();

        // Canonical encoding should be deterministic
        assert_eq!(encoding1, encoding2);
    }

    mod prop_tests {
        use super::*;
        use proptest::prelude::*;

        // Helper to generate a random enclave measurement
        fn any_measurements() -> impl Strategy<Value = EnclaveMeasurements> {
            (any::<Vec<u8>>(), any::<Vec<u8>>(), any::<Vec<u8>>())
                .prop_map(|(p0, p1, p2)| EnclaveMeasurements::new(p0, p1, p2))
        }

        // Helper to generate a random receipt
        fn any_receipt() -> impl Strategy<Value = AttestationReceipt> {
            (
                ".*",         // receipt_id
                any::<u32>(), // protocol_version
                any_measurements(),
                any::<[u8; 32]>(), // attestation_doc_hash
                any::<[u8; 32]>(), // request_hash
                any::<[u8; 32]>(), // response_hash
                ".*",              // policy_version
                any::<u64>(),      // sequence_number
                ".*",              // model_id
                ".*",              // model_version
                any::<u64>(),      // execution_time_ms
                any::<u64>(),      // memory_peak_mb
            )
                .prop_map(|(id, v, m, ah, rqh, rsh, pv, sn, mid, mv, et, mp)| {
                    AttestationReceipt::new(
                        id,
                        v,
                        SecurityMode::GatewayOnly,
                        m,
                        ah,
                        rqh,
                        rsh,
                        pv,
                        sn,
                        mid,
                        mv,
                        et,
                        mp,
                    )
                })
        }

        proptest! {
            #[test]
            fn test_receipt_sign_verify_prop(receipt in any_receipt()) {
                let signing_key = ReceiptSigningKey::generate().unwrap();
                let mut signed_receipt = receipt;
                signed_receipt.sign(&signing_key).unwrap();

                prop_assert!(signed_receipt.verify_signature(&signing_key.public_key).unwrap());
            }

            #[test]
            fn test_receipt_tamper_prop(
                receipt in any_receipt(),
                tampered_id in ".*"
            ) {
                let signing_key = ReceiptSigningKey::generate().unwrap();
                let mut signed_receipt = receipt;
                signed_receipt.sign(&signing_key).unwrap();

                prop_assume!(signed_receipt.receipt_id != tampered_id);

                let mut tampered_receipt = signed_receipt.clone();
                tampered_receipt.receipt_id = tampered_id;

                prop_assert!(!tampered_receipt.verify_signature(&signing_key.public_key).unwrap());
            }

            #[test]
            fn test_receipt_wrong_key_prop(receipt in any_receipt()) {
                let signing_key1 = ReceiptSigningKey::generate().unwrap();
                let signing_key2 = ReceiptSigningKey::generate().unwrap();

                let mut signed_receipt = receipt;
                signed_receipt.sign(&signing_key1).unwrap();

                prop_assert!(!signed_receipt.verify_signature(&signing_key2.public_key).unwrap());
            }

            #[test]
            fn test_canonical_encoding_stable_prop(receipt in any_receipt()) {
                let enc1 = receipt.canonical_encoding().unwrap();
                let enc2 = receipt.canonical_encoding().unwrap();
                prop_assert_eq!(enc1, enc2);
            }
        }
    }
}
