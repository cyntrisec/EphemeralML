use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Static policy root public key for Ed25519 policy signature verification.
///
/// This is a real Ed25519 public key. The corresponding private key is stored
/// offline for policy signing (keys/policy_root_private.hex, git-ignored).
/// All policy bundles must be signed with the matching private key.
pub const POLICY_ROOT_PUBLIC_KEY: &str = "ed25519:EnQLTy/x+drFLKxtt386V5UPsVE0yFgClcmL2AlnNEQ=";

/// Policy root key management errors
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Invalid policy signature")]
    InvalidSignature,

    #[error("Policy expired at {expired_at}, current time: {current_time}")]
    PolicyExpired { expired_at: u64, current_time: u64 },

    #[error("Policy version {version} not supported")]
    UnsupportedVersion { version: u32 },

    #[error("Invalid policy format: {reason}")]
    InvalidFormat { reason: String },

    #[error("Policy root key not found")]
    RootKeyNotFound,

    #[error("Measurement allowlist validation failed: {reason}")]
    AllowlistValidation { reason: String },

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(String),
}

/// Policy bundle containing signed measurement allowlists and configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PolicyBundle {
    /// Policy version for compatibility tracking
    pub version: u32,
    /// Minimum compatible version for upgrade compatibility checks
    #[serde(default = "default_min_compatible_version")]
    pub min_compatible_version: u32,
    /// Unix timestamp when policy was created
    pub created_at: u64,
    /// Unix timestamp when policy expires
    pub expires_at: u64,
    /// Measurement allowlist for enclave verification
    pub measurement_allowlist: MeasurementAllowlist,
    /// Key release policies
    pub key_release_policies: Vec<KeyReleasePolicy>,
    /// Additional policy configuration
    pub config: PolicyConfig,
    /// Ed25519 signature over canonical encoding of policy data
    pub signature: Vec<u8>,
}

/// Measurement allowlist for enclave verification
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MeasurementAllowlist {
    /// Allowed PCR0 values (enclave image measurements)
    pub allowed_pcr0: Vec<String>,
    /// Allowed PCR1 values (kernel measurements)
    pub allowed_pcr1: Vec<String>,
    /// Allowed PCR2 values (application measurements)
    pub allowed_pcr2: Vec<String>,
    /// Minimum required measurements (all must be present)
    pub required_measurements: Vec<String>,
}

/// Key release policy for specific models or contexts
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyReleasePolicy {
    /// Policy identifier
    pub policy_id: String,
    /// Model IDs this policy applies to
    pub model_ids: Vec<String>,
    /// Required enclave measurements
    pub required_measurements: Vec<String>,
    /// Maximum session duration in seconds
    pub max_session_duration: u64,
    /// Additional encryption context requirements
    pub encryption_context: HashMap<String, String>,
}

/// Additional policy configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PolicyConfig {
    /// Maximum concurrent sessions allowed
    pub max_concurrent_sessions: u32,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Additional feature flags
    pub feature_flags: HashMap<String, bool>,
}

/// Policy manager for handling policy verification and updates
#[derive(Clone)]
pub struct PolicyManager {
    /// Current active policy bundle
    current_policy: Option<PolicyBundle>,
    /// Policy root public key for signature verification
    root_public_key: String,
}

impl PolicyManager {
    /// Create a new policy manager with the default root key.
    ///
    /// Panics at startup if the compiled-in root key is all zeros (placeholder).
    pub fn new() -> Self {
        // Startup assertion: reject placeholder zero-byte keys
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        if let Some(key_b64) = POLICY_ROOT_PUBLIC_KEY.strip_prefix("ed25519:") {
            if let Ok(bytes) = STANDARD.decode(key_b64) {
                assert!(
                    bytes.iter().any(|&b| b != 0),
                    "POLICY_ROOT_PUBLIC_KEY is all zeros — this is a placeholder and must be replaced with a real key"
                );
            }
        }

        Self {
            current_policy: None,
            root_public_key: POLICY_ROOT_PUBLIC_KEY.to_string(),
        }
    }

    /// Create a policy manager with a custom root key
    pub fn with_root_key(root_key: String) -> Self {
        Self {
            current_policy: None,
            root_public_key: root_key,
        }
    }

    /// Load and verify a policy bundle
    pub fn load_policy(&mut self, policy_data: &[u8]) -> Result<(), PolicyError> {
        let policy: PolicyBundle = serde_json::from_slice(policy_data)?;

        // Verify policy signature
        self.verify_policy_signature(&policy)?;

        // Check policy expiration
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if policy.expires_at <= current_time {
            return Err(PolicyError::PolicyExpired {
                expired_at: policy.expires_at,
                current_time,
            });
        }

        // Validate policy version (support version 1+)
        if policy.version < 1 {
            return Err(PolicyError::UnsupportedVersion {
                version: policy.version,
            });
        }

        // Validate measurement allowlist format
        self.validate_measurement_allowlist(&policy.measurement_allowlist)?;

        self.current_policy = Some(policy);
        Ok(())
    }

    /// Get the current active policy
    pub fn current_policy(&self) -> Option<&PolicyBundle> {
        self.current_policy.as_ref()
    }

    /// Check if a set of measurements is allowed by the current policy
    pub fn is_measurement_allowed(
        &self,
        pcr0: &str,
        pcr1: &str,
        pcr2: &str,
    ) -> Result<bool, PolicyError> {
        let policy = self
            .current_policy
            .as_ref()
            .ok_or(PolicyError::RootKeyNotFound)?;

        let allowlist = &policy.measurement_allowlist;

        // Check if all measurements are in the allowlist
        let pcr0_allowed = allowlist.allowed_pcr0.contains(&pcr0.to_string());
        let pcr1_allowed = allowlist.allowed_pcr1.contains(&pcr1.to_string());
        let pcr2_allowed = allowlist.allowed_pcr2.contains(&pcr2.to_string());

        Ok(pcr0_allowed && pcr1_allowed && pcr2_allowed)
    }

    /// Get key release policy for a specific model
    pub fn get_key_release_policy(
        &self,
        model_id: &str,
    ) -> Result<Option<&KeyReleasePolicy>, PolicyError> {
        let policy = self
            .current_policy
            .as_ref()
            .ok_or(PolicyError::RootKeyNotFound)?;

        let matching_policy = policy
            .key_release_policies
            .iter()
            .find(|p| p.model_ids.contains(&model_id.to_string()));

        Ok(matching_policy)
    }

    /// Create a default policy bundle for development/testing
    pub fn create_default_policy() -> PolicyBundle {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        PolicyBundle {
            version: 1,
            min_compatible_version: 1,
            created_at: current_time,
            expires_at: current_time + (30 * 24 * 60 * 60), // 30 days
            measurement_allowlist: MeasurementAllowlist {
                allowed_pcr0: vec![
                    // Development/mock measurements
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f".to_string(),
                ],
                allowed_pcr1: vec![
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f".to_string(),
                ],
                allowed_pcr2: vec![
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f".to_string(),
                ],
                required_measurements: vec!["pcr0".to_string(), "pcr1".to_string(), "pcr2".to_string()],
            },
            key_release_policies: vec![
                KeyReleasePolicy {
                    policy_id: "default-policy".to_string(),
                    model_ids: vec!["*".to_string()], // Allow all models for development
                    required_measurements: vec![
                        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f".to_string(),
                    ],
                    max_session_duration: 15 * 60, // 15 minutes
                    encryption_context: HashMap::new(),
                },
            ],
            config: PolicyConfig {
                max_concurrent_sessions: 100,
                session_timeout: 15 * 60,
                feature_flags: HashMap::new(),
            },
            signature: vec![], // Will be filled by signing process
        }
    }

    /// Verify policy signature using the root public key.
    ///
    /// All policies MUST have a valid Ed25519 signature regardless of build mode.
    /// Empty signatures and invalid root keys are rejected.
    fn verify_policy_signature(&self, policy: &PolicyBundle) -> Result<(), PolicyError> {
        if policy.signature.is_empty() {
            return Err(PolicyError::InvalidSignature);
        }

        // Create canonical encoding for signature verification
        let canonical_data = self.create_canonical_policy_data(policy)?;

        // Parse the root public key
        // Format expected: "ed25519:<base64_encoded_key>"
        let key_parts: Vec<&str> = self.root_public_key.split(':').collect();
        if key_parts.len() != 2 || key_parts[0] != "ed25519" {
            return Err(PolicyError::InvalidFormat {
                reason: "Root key must be in format 'ed25519:<base64_key>'".to_string(),
            });
        }

        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let public_key_bytes =
            STANDARD
                .decode(key_parts[1])
                .map_err(|_| PolicyError::InvalidFormat {
                    reason: "Invalid base64 in root key".to_string(),
                })?;

        use ed25519_dalek::{Signature, VerifyingKey};

        if public_key_bytes.len() != 32 {
            return Err(PolicyError::InvalidFormat {
                reason: format!("Root key must be 32 bytes, got {}", public_key_bytes.len()),
            });
        }

        // For tests where we use a placeholder key that isn't valid, we might want to skip logic if mock
        // BUT if we want to test the VERIFICATION logic, we need a valid key.
        // We will try to verify. If it fails and we are in mock mode, maybe we allow it?
        // Better: Make the test provide a valid key.

        let verifying_key = VerifyingKey::from_bytes(
            public_key_bytes.as_slice().try_into().unwrap(),
        )
        .map_err(|_| PolicyError::InvalidFormat {
            reason: "Invalid public key bytes".to_string(),
        })?;

        let signature = Signature::from_bytes(
            policy
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| PolicyError::InvalidSignature)?,
        );

        verifying_key
            .verify_strict(&canonical_data, &signature)
            .map_err(|_| PolicyError::InvalidSignature)
    }

    /// Create canonical encoding of policy data for signature verification
    fn create_canonical_policy_data(&self, policy: &PolicyBundle) -> Result<Vec<u8>, PolicyError> {
        // Create a copy without the signature field for canonical encoding
        let policy_for_signing = PolicyBundleForSigning {
            version: policy.version,
            min_compatible_version: policy.min_compatible_version,
            created_at: policy.created_at,
            expires_at: policy.expires_at,
            measurement_allowlist: policy.measurement_allowlist.clone(),
            key_release_policies: policy.key_release_policies.clone(),
            config: policy.config.clone(),
        };

        // Use deterministic JSON encoding for signature verification
        let canonical_json = serde_json::to_vec(&policy_for_signing)?;
        Ok(canonical_json)
    }

    /// Validate measurement allowlist format
    fn validate_measurement_allowlist(
        &self,
        allowlist: &MeasurementAllowlist,
    ) -> Result<(), PolicyError> {
        // Check that all measurement lists are non-empty
        if allowlist.allowed_pcr0.is_empty() {
            return Err(PolicyError::AllowlistValidation {
                reason: "PCR0 allowlist cannot be empty".to_string(),
            });
        }

        if allowlist.allowed_pcr1.is_empty() {
            return Err(PolicyError::AllowlistValidation {
                reason: "PCR1 allowlist cannot be empty".to_string(),
            });
        }

        if allowlist.allowed_pcr2.is_empty() {
            return Err(PolicyError::AllowlistValidation {
                reason: "PCR2 allowlist cannot be empty".to_string(),
            });
        }

        // Validate measurement format (should be hex strings of correct length)
        for pcr in &allowlist.allowed_pcr0 {
            self.validate_measurement_format(pcr, "PCR0")?;
        }

        for pcr in &allowlist.allowed_pcr1 {
            self.validate_measurement_format(pcr, "PCR1")?;
        }

        for pcr in &allowlist.allowed_pcr2 {
            self.validate_measurement_format(pcr, "PCR2")?;
        }

        Ok(())
    }

    /// Validate individual measurement format
    fn validate_measurement_format(
        &self,
        measurement: &str,
        pcr_name: &str,
    ) -> Result<(), PolicyError> {
        // PCR measurements should be 48 bytes (96 hex characters) for SHA-384
        if measurement.len() != 96 {
            return Err(PolicyError::AllowlistValidation {
                reason: format!(
                    "{} measurement must be 96 hex characters, got {}",
                    pcr_name,
                    measurement.len()
                ),
            });
        }

        // Check that it's valid hex
        if !measurement.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(PolicyError::AllowlistValidation {
                reason: format!("{} measurement must be valid hex", pcr_name),
            });
        }

        Ok(())
    }
}

fn default_min_compatible_version() -> u32 {
    1
}

/// Policy bundle structure for signing (without signature field)
#[derive(Serialize, Deserialize)]
struct PolicyBundleForSigning {
    pub version: u32,
    #[serde(default = "default_min_compatible_version")]
    pub min_compatible_version: u32,
    pub created_at: u64,
    pub expires_at: u64,
    pub measurement_allowlist: MeasurementAllowlist,
    pub key_release_policies: Vec<KeyReleasePolicy>,
    pub config: PolicyConfig,
}

impl Default for PolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_default_policy() {
        let policy = PolicyManager::create_default_policy();
        assert_eq!(policy.version, 1);
        assert!(!policy.measurement_allowlist.allowed_pcr0.is_empty());
        assert!(!policy.key_release_policies.is_empty());
    }

    #[test]
    fn test_policy_manager_creation() {
        let manager = PolicyManager::new();
        assert!(manager.current_policy.is_none());
        assert_eq!(manager.root_public_key, POLICY_ROOT_PUBLIC_KEY);
        // Verify root key is not the old all-zeros placeholder
        assert!(!POLICY_ROOT_PUBLIC_KEY.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    }

    #[test]
    fn test_measurement_validation() {
        let manager = PolicyManager::new();

        // Valid measurement (96 hex characters)
        let valid_measurement = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        assert!(manager
            .validate_measurement_format(valid_measurement, "PCR0")
            .is_ok());

        // Invalid length
        let invalid_length = "00010203";
        assert!(manager
            .validate_measurement_format(invalid_length, "PCR0")
            .is_err());

        // Invalid hex
        let invalid_hex = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        assert!(manager
            .validate_measurement_format(invalid_hex, "PCR0")
            .is_err());
    }

    #[test]
    fn test_policy_loading_requires_valid_signature() {
        let mut manager = PolicyManager::new();
        let policy = PolicyManager::create_default_policy();
        let policy_data = serde_json::to_vec(&policy).unwrap();

        // Unsigned policy must be rejected even in mock builds
        assert!(manager.load_policy(&policy_data).is_err());
        assert!(manager.current_policy().is_none());
    }

    #[test]
    fn test_policy_loading_with_signed_policy() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let root_key_str = format!("ed25519:{}", STANDARD.encode(verifying_key.to_bytes()));

        let mut manager = PolicyManager::with_root_key(root_key_str);
        let mut policy = PolicyManager::create_default_policy();

        let canonical_bytes = manager.create_canonical_policy_data(&policy).unwrap();
        let signature = signing_key.sign(&canonical_bytes);
        policy.signature = signature.to_bytes().to_vec();

        let policy_data = serde_json::to_vec(&policy).unwrap();
        assert!(manager.load_policy(&policy_data).is_ok());
        assert!(manager.current_policy().is_some());
    }

    #[test]
    fn test_signed_policy_verification() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        // Generate key pair
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let root_key_str = format!("ed25519:{}", STANDARD.encode(verifying_key.to_bytes()));

        let mut manager = PolicyManager::with_root_key(root_key_str);
        let mut policy = PolicyManager::create_default_policy();

        // Canonicalize and sign
        let canonical_bytes = manager.create_canonical_policy_data(&policy).unwrap();
        let signature = signing_key.sign(&canonical_bytes);
        policy.signature = signature.to_bytes().to_vec();

        let policy_data = serde_json::to_vec(&policy).unwrap();

        // Load should succeed
        assert!(manager.load_policy(&policy_data).is_ok());

        // Tamper with created_at instead of version (version=2 is now allowed)
        let mut bad_policy = policy.clone();
        bad_policy.created_at = 999;
        let bad_policy_data = serde_json::to_vec(&bad_policy).unwrap();

        // Verification should fail (signature mismatch with data)
        assert!(manager.load_policy(&bad_policy_data).is_err());
    }

    #[test]
    fn test_min_compatible_version_default() {
        // Test backward compatibility: deserialize a PolicyBundle without min_compatible_version
        let json = r#"{
            "version": 1,
            "created_at": 1000000,
            "expires_at": 9999999999,
            "measurement_allowlist": {
                "allowed_pcr0": ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"],
                "allowed_pcr1": ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"],
                "allowed_pcr2": ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"],
                "required_measurements": ["pcr0"]
            },
            "key_release_policies": [],
            "config": {
                "max_concurrent_sessions": 10,
                "session_timeout": 900,
                "feature_flags": {}
            },
            "signature": []
        }"#;
        let bundle: PolicyBundle = serde_json::from_str(json).unwrap();
        assert_eq!(bundle.min_compatible_version, 1);
    }
}
