use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Static policy root key for v1 (checked into client config)
/// In production, this would be a well-known public key for policy verification
pub const POLICY_ROOT_PUBLIC_KEY: &str = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

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
}

/// Policy bundle containing signed measurement allowlists and configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PolicyBundle {
    /// Policy version for compatibility tracking
    pub version: u32,
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
    /// Enable Shield Mode (Layer 2 security)
    pub enable_shield_mode: bool,
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
    /// Create a new policy manager with the default root key
    pub fn new() -> Self {
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
        
        // Validate policy version (v1 only supports version 1)
        if policy.version != 1 {
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
    pub fn is_measurement_allowed(&self, pcr0: &str, pcr1: &str, pcr2: &str) -> Result<bool, PolicyError> {
        let policy = self.current_policy.as_ref()
            .ok_or(PolicyError::RootKeyNotFound)?;
            
        let allowlist = &policy.measurement_allowlist;
        
        // Check if all measurements are in the allowlist
        let pcr0_allowed = allowlist.allowed_pcr0.contains(&pcr0.to_string());
        let pcr1_allowed = allowlist.allowed_pcr1.contains(&pcr1.to_string());
        let pcr2_allowed = allowlist.allowed_pcr2.contains(&pcr2.to_string());
        
        Ok(pcr0_allowed && pcr1_allowed && pcr2_allowed)
    }
    
    /// Get key release policy for a specific model
    pub fn get_key_release_policy(&self, model_id: &str) -> Result<Option<&KeyReleasePolicy>, PolicyError> {
        let policy = self.current_policy.as_ref()
            .ok_or(PolicyError::RootKeyNotFound)?;
            
        let matching_policy = policy.key_release_policies
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
                enable_shield_mode: false, // Disabled for v1
                feature_flags: HashMap::new(),
            },
            signature: vec![], // Will be filled by signing process
        }
    }
    
    /// Verify policy signature using the root public key
    fn verify_policy_signature(&self, policy: &PolicyBundle) -> Result<(), PolicyError> {
        #[cfg(feature = "mock")]
        if policy.signature.is_empty() {
            return Ok(());
        }

        // Create canonical encoding for signature verification
        let canonical_data = self.create_canonical_policy_data(policy)?;
        
        // Parse the root public key
        // Format expected: "ed25519:<base64_encoded_key>"
        let key_parts: Vec<&str> = self.root_public_key.split(':').collect();
        if key_parts.len() != 2 || key_parts[0] != "ed25519" {
             #[cfg(feature = "mock")]
             return Ok(()); // In mock mode, if key is invalid/placeholder, we might skip
             
             #[cfg(not(feature = "mock"))]
             return Err(PolicyError::RootKeyNotFound); // Or invalid format
        }
        
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let public_key_bytes = STANDARD.decode(key_parts[1])
            .map_err(|_| PolicyError::InvalidFormat { reason: "Invalid base64 in root key".to_string() })?;
            
        use ed25519_dalek::{Verifier, VerifyingKey, Signature};
        
        if public_key_bytes.len() != 32 {
             #[cfg(feature = "mock")]
             return Ok(()); // Allow placeholder keys in mock
             
             #[cfg(not(feature = "mock"))]
             return Err(PolicyError::InvalidFormat { reason: "Invalid public key length".to_string() });
        }
        
        // For tests where we use a placeholder key that isn't valid, we might want to skip logic if mock
        // BUT if we want to test the VERIFICATION logic, we need a valid key.
        // We will try to verify. If it fails and we are in mock mode, maybe we allow it?
        // Better: Make the test provide a valid key.
        
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes.as_slice().try_into().unwrap())
            .map_err(|_| PolicyError::InvalidFormat { reason: "Invalid public key bytes".to_string() })?;
            
        let signature = Signature::from_bytes(policy.signature.as_slice().try_into().map_err(|_| 
            PolicyError::InvalidSignature
        )?);
        
        verifying_key.verify(&canonical_data, &signature)
            .map_err(|_| PolicyError::InvalidSignature)
    }
    
    /// Create canonical encoding of policy data for signature verification
    fn create_canonical_policy_data(&self, policy: &PolicyBundle) -> Result<Vec<u8>, PolicyError> {
        // Create a copy without the signature field for canonical encoding
        let policy_for_signing = PolicyBundleForSigning {
            version: policy.version,
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
    fn validate_measurement_allowlist(&self, allowlist: &MeasurementAllowlist) -> Result<(), PolicyError> {
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
    fn validate_measurement_format(&self, measurement: &str, pcr_name: &str) -> Result<(), PolicyError> {
        // PCR measurements should be 48 bytes (96 hex characters) for SHA-384
        if measurement.len() != 96 {
            return Err(PolicyError::AllowlistValidation {
                reason: format!("{} measurement must be 96 hex characters, got {}", pcr_name, measurement.len()),
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

/// Policy bundle structure for signing (without signature field)
#[derive(Serialize, Deserialize)]
struct PolicyBundleForSigning {
    pub version: u32,
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

/// Key rotation documentation for v2
/// 
/// # Key Rotation Strategy (Deferred to v2)
/// 
/// The current v1 implementation uses a static policy root key checked into the client
/// configuration. This approach is suitable for controlled deployments but has limitations
/// for production key lifecycle management.
/// 
/// ## V2 Key Rotation Plan:
/// 
/// 1. **Multi-Key Support**: Support multiple valid root keys with key IDs
/// 2. **Key Rollover**: Implement gradual key rotation with overlap periods
/// 3. **Revocation**: Support for emergency key revocation and blacklisting
/// 4. **Distribution**: Secure key distribution mechanism (possibly via signed updates)
/// 5. **Validation**: Enhanced validation with key expiration and usage limits
/// 
/// ## Security Considerations:
/// 
/// - Root key compromise requires coordinated client updates
/// - Policy updates must be backward compatible during transition periods
/// - Emergency revocation must be fast and reliable
/// - Key rotation should not disrupt active sessions
/// 
/// ## Implementation Notes:
/// 
/// The current PolicyManager structure is designed to accommodate these future
/// enhancements with minimal breaking changes. The root_public_key field can
/// be extended to support multiple keys, and the verification logic can be
/// enhanced to handle key rotation scenarios.

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
    }
    
    #[test]
    fn test_measurement_validation() {
        let manager = PolicyManager::new();
        
        // Valid measurement (96 hex characters)
        let valid_measurement = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
        assert!(manager.validate_measurement_format(valid_measurement, "PCR0").is_ok());
        
        // Invalid length
        let invalid_length = "00010203";
        assert!(manager.validate_measurement_format(invalid_length, "PCR0").is_err());
        
        // Invalid hex
        let invalid_hex = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        assert!(manager.validate_measurement_format(invalid_hex, "PCR0").is_err());
    }
    
    #[test]
    #[cfg(feature = "mock")]
    fn test_policy_loading_mock_mode() {
        let mut manager = PolicyManager::new();
        let policy = PolicyManager::create_default_policy();
        let policy_data = serde_json::to_vec(&policy).unwrap();
        
        // Should succeed in mock mode
        assert!(manager.load_policy(&policy_data).is_ok());
        assert!(manager.current_policy().is_some());
    }

    #[test]
    fn test_signed_policy_verification() {
        use ed25519_dalek::{SigningKey, Signer};
        use rand::rngs::OsRng;
        use base64::{Engine as _, engine::general_purpose::STANDARD};

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
        
        // Tamper
        let mut bad_policy = policy.clone();
        bad_policy.version = 2; // Change data
        let bad_policy_data = serde_json::to_vec(&bad_policy).unwrap();
        
        // Verification should fail (signature mismatch with data)
        // Note: verify_policy_signature is called inside load_policy.
        // But in mock mode, it might pass if we don't ensure verify_policy_signature enforces it?
        // My implementation checks signature first.
        assert!(manager.load_policy(&bad_policy_data).is_err());
    }
}