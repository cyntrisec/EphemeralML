use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
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

    #[error("Version downgrade rejected: new version {new} < current version {current}")]
    VersionDowngrade { new: u32, current: u32 },

    #[error("Version incompatible: current version {current} < new policy min_compatible_version {min_compatible}")]
    VersionIncompatible { current: u32, min_compatible: u32 },

    #[error("No previous policy available for rollback")]
    NoPreviousPolicy,

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

        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let public_key_bytes =
            STANDARD
                .decode(key_parts[1])
                .map_err(|_| PolicyError::InvalidFormat {
                    reason: "Invalid base64 in root key".to_string(),
                })?;

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        if public_key_bytes.len() != 32 {
            #[cfg(feature = "mock")]
            return Ok(()); // Allow placeholder keys in mock

            #[cfg(not(feature = "mock"))]
            return Err(PolicyError::InvalidFormat {
                reason: "Invalid public key length".to_string(),
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
            .verify(&canonical_data, &signature)
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

/// Record of a policy version transition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyVersionTransition {
    /// Previous version (0 if first policy)
    pub from_version: u32,
    /// New version
    pub to_version: u32,
    /// Timestamp of transition (unix seconds)
    pub timestamp: u64,
    /// Reason for transition
    pub reason: String,
}

/// Tracks policy version history for audit and compatibility
#[derive(Clone, Debug, Default)]
pub struct PolicyVersionHistory {
    /// History of version transitions
    pub transitions: Vec<PolicyVersionTransition>,
}

impl PolicyVersionHistory {
    pub fn new() -> Self {
        Self {
            transitions: Vec::new(),
        }
    }

    pub fn record_transition(&mut self, from: u32, to: u32, reason: &str) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.transitions.push(PolicyVersionTransition {
            from_version: from,
            to_version: to,
            timestamp,
            reason: reason.to_string(),
        });
    }

    pub fn current_version(&self) -> Option<u32> {
        self.transitions.last().map(|t| t.to_version)
    }
}

/// Policy update manager with atomic swap, rollback, version tracking, and file watching.
pub struct PolicyUpdateManager {
    inner: Arc<RwLock<PolicyUpdateManagerInner>>,
}

struct PolicyUpdateManagerInner {
    manager: PolicyManager,
    /// Previous policies for rollback (most recent last)
    history: Vec<PolicyBundle>,
    /// Maximum history entries to keep
    max_history: usize,
    /// Version history for audit
    version_history: PolicyVersionHistory,
    /// Last observed mtime for file watching
    last_mtime: Option<std::time::SystemTime>,
}

impl PolicyUpdateManager {
    /// Create a new PolicyUpdateManager wrapping a PolicyManager
    pub fn new(manager: PolicyManager) -> Self {
        Self {
            inner: Arc::new(RwLock::new(PolicyUpdateManagerInner {
                manager,
                history: Vec::new(),
                max_history: 10,
                version_history: PolicyVersionHistory::new(),
                last_mtime: None,
            })),
        }
    }

    /// Create with a custom history limit
    pub fn with_max_history(manager: PolicyManager, max_history: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(PolicyUpdateManagerInner {
                manager,
                history: Vec::new(),
                max_history,
                version_history: PolicyVersionHistory::new(),
                last_mtime: None,
            })),
        }
    }

    /// Apply a policy update with signature verification and version checks.
    /// Atomic: on failure the old policy is preserved.
    pub fn apply_update(&self, new_policy_data: &[u8]) -> Result<(), PolicyError> {
        let mut inner = self.inner.write().unwrap();

        // Parse new policy first (before touching state)
        let new_policy: PolicyBundle = serde_json::from_slice(new_policy_data)?;

        // Version checks against current policy
        if let Some(current) = inner.manager.current_policy() {
            let current_version = current.version;

            // New version must be >= current
            if new_policy.version < current_version {
                return Err(PolicyError::VersionDowngrade {
                    new: new_policy.version,
                    current: current_version,
                });
            }

            // Current version must be >= new policy's min_compatible_version
            if current_version < new_policy.min_compatible_version {
                return Err(PolicyError::VersionIncompatible {
                    current: current_version,
                    min_compatible: new_policy.min_compatible_version,
                });
            }
        }

        // Save old policy for rollback
        let old_policy = inner.manager.current_policy().cloned();
        let old_version = old_policy.as_ref().map(|p| p.version).unwrap_or(0);

        // Try to load the new policy (validates signature, expiration, measurements)
        match inner.manager.load_policy(new_policy_data) {
            Ok(()) => {
                // Success — push old policy to history
                if let Some(old) = old_policy {
                    inner.history.push(old);
                    // Trim history if needed
                    while inner.history.len() > inner.max_history {
                        inner.history.remove(0);
                    }
                }
                let new_version = inner
                    .manager
                    .current_policy()
                    .map(|p| p.version)
                    .unwrap_or(0);
                inner
                    .version_history
                    .record_transition(old_version, new_version, "policy_update");
                Ok(())
            }
            Err(e) => {
                // Rollback: restore old policy if we had one
                // Since load_policy failed, the manager's current_policy should be unchanged
                // (load_policy only sets current_policy on success), so no explicit rollback needed.
                Err(e)
            }
        }
    }

    /// Rollback to the previous policy
    pub fn rollback(&self) -> Result<(), PolicyError> {
        let mut inner = self.inner.write().unwrap();
        let previous = inner.history.pop().ok_or(PolicyError::NoPreviousPolicy)?;
        let old_version = inner
            .manager
            .current_policy()
            .map(|p| p.version)
            .unwrap_or(0);
        let new_version = previous.version;
        inner.manager.current_policy = Some(previous);
        inner
            .version_history
            .record_transition(old_version, new_version, "rollback");
        Ok(())
    }

    /// Get the current policy
    pub fn current_policy(&self) -> Option<PolicyBundle> {
        let inner = self.inner.read().unwrap();
        inner.manager.current_policy().cloned()
    }

    /// Get version history
    pub fn version_history(&self) -> PolicyVersionHistory {
        let inner = self.inner.read().unwrap();
        inner.version_history.clone()
    }

    /// Get history depth
    pub fn history_depth(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.history.len()
    }

    /// One-shot load from file
    pub fn load_from_file(&self, path: &std::path::Path) -> Result<(), PolicyError> {
        let data = std::fs::read(path).map_err(|e| PolicyError::Io(e.to_string()))?;
        self.apply_update(&data)?;
        // Update mtime
        if let Ok(meta) = std::fs::metadata(path) {
            if let Ok(mtime) = meta.modified() {
                let mut inner = self.inner.write().unwrap();
                inner.last_mtime = Some(mtime);
            }
        }
        Ok(())
    }

    /// Check if file has changed and reload if so (poll-based).
    /// Returns Ok(true) if reloaded, Ok(false) if unchanged.
    pub fn poll_file(&self, path: &std::path::Path) -> Result<bool, PolicyError> {
        let meta = std::fs::metadata(path).map_err(|e| PolicyError::Io(e.to_string()))?;
        let mtime = meta
            .modified()
            .map_err(|e| PolicyError::Io(e.to_string()))?;

        let should_reload = {
            let inner = self.inner.read().unwrap();
            match inner.last_mtime {
                Some(last) => mtime > last,
                None => true,
            }
        };

        if should_reload {
            let data = std::fs::read(path).map_err(|e| PolicyError::Io(e.to_string()))?;
            self.apply_update(&data)?;
            let mut inner = self.inner.write().unwrap();
            inner.last_mtime = Some(mtime);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Start a background file watcher (polling every `interval`).
    /// Returns a handle that stops watching when dropped.
    pub fn watch_file(
        &self,
        path: std::path::PathBuf,
        interval: std::time::Duration,
    ) -> FileWatchHandle {
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let running_clone = running.clone();
        let inner = self.inner.clone();

        let handle = std::thread::spawn(move || {
            let mut last_mtime: Option<std::time::SystemTime> = None;
            while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(meta) = std::fs::metadata(&path) {
                    if let Ok(mtime) = meta.modified() {
                        let should_reload = match last_mtime {
                            Some(last) => mtime > last,
                            None => true,
                        };
                        if should_reload {
                            if let Ok(data) = std::fs::read(&path) {
                                let new_policy: Result<PolicyBundle, _> =
                                    serde_json::from_slice(&data);
                                if let Ok(new_policy) = new_policy {
                                    let mut guard = inner.write().unwrap();
                                    let old_policy = guard.manager.current_policy().cloned();
                                    let old_version =
                                        old_policy.as_ref().map(|p| p.version).unwrap_or(0);

                                    // Version checks
                                    let version_ok = if let Some(ref current) = old_policy {
                                        new_policy.version >= current.version
                                            && current.version >= new_policy.min_compatible_version
                                    } else {
                                        true
                                    };

                                    if version_ok {
                                        if guard.manager.load_policy(&data).is_ok() {
                                            if let Some(old) = old_policy {
                                                guard.history.push(old);
                                                while guard.history.len() > guard.max_history {
                                                    guard.history.remove(0);
                                                }
                                            }
                                            let new_ver = guard
                                                .manager
                                                .current_policy()
                                                .map(|p| p.version)
                                                .unwrap_or(0);
                                            guard.version_history.record_transition(
                                                old_version,
                                                new_ver,
                                                "file_watch",
                                            );
                                            last_mtime = Some(mtime);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                std::thread::sleep(interval);
            }
        });

        FileWatchHandle {
            running,
            _handle: Some(handle),
        }
    }
}

/// Handle for stopping file watching. Stops when dropped.
pub struct FileWatchHandle {
    running: Arc<std::sync::atomic::AtomicBool>,
    _handle: Option<std::thread::JoinHandle<()>>,
}

impl FileWatchHandle {
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Drop for FileWatchHandle {
    fn drop(&mut self) {
        self.stop();
        // Don't join — the thread will exit on its next loop iteration
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

    // ==================== Task 17 Tests ====================

    /// Helper: create a signed policy with the given version
    fn make_signed_policy(
        signing_key: &ed25519_dalek::SigningKey,
        version: u32,
        min_compat: u32,
    ) -> (Vec<u8>, PolicyBundle) {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::Signer;

        let verifying_key = signing_key.verifying_key();
        let root_key_str = format!("ed25519:{}", STANDARD.encode(verifying_key.to_bytes()));
        let temp_manager = PolicyManager::with_root_key(root_key_str);

        let mut policy = PolicyManager::create_default_policy();
        policy.version = version;
        policy.min_compatible_version = min_compat;

        let canonical_bytes = temp_manager.create_canonical_policy_data(&policy).unwrap();
        let signature = signing_key.sign(&canonical_bytes);
        policy.signature = signature.to_bytes().to_vec();

        let data = serde_json::to_vec(&policy).unwrap();
        (data, policy)
    }

    #[test]
    fn test_policy_update_valid_signature() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let root_key_str = format!("ed25519:{}", STANDARD.encode(verifying_key.to_bytes()));

        let manager = PolicyManager::with_root_key(root_key_str);
        let update_mgr = PolicyUpdateManager::new(manager);

        let (data_v1, _) = make_signed_policy(&signing_key, 1, 1);
        assert!(update_mgr.apply_update(&data_v1).is_ok());
        assert!(update_mgr.current_policy().is_some());
        assert_eq!(update_mgr.current_policy().unwrap().version, 1);
    }

    #[test]
    fn test_policy_update_invalid_signature_preserves_old() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let root_key_str = format!("ed25519:{}", STANDARD.encode(verifying_key.to_bytes()));

        let manager = PolicyManager::with_root_key(root_key_str);
        let update_mgr = PolicyUpdateManager::new(manager);

        // Load valid v1
        let (data_v1, _) = make_signed_policy(&signing_key, 1, 1);
        assert!(update_mgr.apply_update(&data_v1).is_ok());

        // Attempt update with a different signing key (invalid sig for our manager)
        let bad_key = SigningKey::generate(&mut OsRng);
        let (bad_data, _) = make_signed_policy(&bad_key, 2, 1);
        assert!(update_mgr.apply_update(&bad_data).is_err());

        // Old policy preserved
        assert_eq!(update_mgr.current_policy().unwrap().version, 1);
    }

    #[test]
    fn test_version_downgrade_rejected() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let root_key_str = format!("ed25519:{}", STANDARD.encode(verifying_key.to_bytes()));

        let manager = PolicyManager::with_root_key(root_key_str);
        let update_mgr = PolicyUpdateManager::new(manager);

        // Load v2 first
        let (data_v2, _) = make_signed_policy(&signing_key, 2, 1);
        assert!(update_mgr.apply_update(&data_v2).is_ok());

        // Try to downgrade to v1
        let (data_v1, _) = make_signed_policy(&signing_key, 1, 1);
        let result = update_mgr.apply_update(&data_v1);
        assert!(result.is_err());
        match result.unwrap_err() {
            PolicyError::VersionDowngrade { new: 1, current: 2 } => {}
            e => panic!("Expected VersionDowngrade, got: {:?}", e),
        }

        // v2 still active
        assert_eq!(update_mgr.current_policy().unwrap().version, 2);
    }

    #[test]
    fn test_version_compatibility_validation() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let root_key_str = format!("ed25519:{}", STANDARD.encode(verifying_key.to_bytes()));

        let manager = PolicyManager::with_root_key(root_key_str);
        let update_mgr = PolicyUpdateManager::new(manager);

        // Load v1
        let (data_v1, _) = make_signed_policy(&signing_key, 1, 1);
        assert!(update_mgr.apply_update(&data_v1).is_ok());

        // Try to update to v3 with min_compatible_version=2 (current=1 < 2 → reject)
        let (data_v3, _) = make_signed_policy(&signing_key, 3, 2);
        let result = update_mgr.apply_update(&data_v3);
        assert!(result.is_err());
        match result.unwrap_err() {
            PolicyError::VersionIncompatible {
                current: 1,
                min_compatible: 2,
            } => {}
            e => panic!("Expected VersionIncompatible, got: {:?}", e),
        }

        // But v2 with min_compatible_version=1 should work
        let (data_v2, _) = make_signed_policy(&signing_key, 2, 1);
        assert!(update_mgr.apply_update(&data_v2).is_ok());
        assert_eq!(update_mgr.current_policy().unwrap().version, 2);
    }

    #[test]
    fn test_rollback() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let root_key_str = format!("ed25519:{}", STANDARD.encode(verifying_key.to_bytes()));

        let manager = PolicyManager::with_root_key(root_key_str);
        let update_mgr = PolicyUpdateManager::new(manager);

        // No rollback possible initially
        assert!(update_mgr.rollback().is_err());

        // Load v1 then v2
        let (data_v1, _) = make_signed_policy(&signing_key, 1, 1);
        assert!(update_mgr.apply_update(&data_v1).is_ok());

        let (data_v2, _) = make_signed_policy(&signing_key, 2, 1);
        assert!(update_mgr.apply_update(&data_v2).is_ok());
        assert_eq!(update_mgr.current_policy().unwrap().version, 2);

        // Rollback to v1
        assert!(update_mgr.rollback().is_ok());
        assert_eq!(update_mgr.current_policy().unwrap().version, 1);

        // Rollback again → no previous
        assert!(update_mgr.rollback().is_err());
    }

    #[test]
    fn test_measurement_allowlist_hot_update() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let root_key_str = format!("ed25519:{}", STANDARD.encode(verifying_key.to_bytes()));

        let manager = PolicyManager::with_root_key(root_key_str.clone());
        let update_mgr = PolicyUpdateManager::new(manager);

        // Load v1
        let (data_v1, _) = make_signed_policy(&signing_key, 1, 1);
        assert!(update_mgr.apply_update(&data_v1).is_ok());

        let old_pcr0 = update_mgr
            .current_policy()
            .unwrap()
            .measurement_allowlist
            .allowed_pcr0
            .clone();

        // Create v2 with updated measurement allowlist
        use ed25519_dalek::Signer;
        let temp_manager = PolicyManager::with_root_key(root_key_str);
        let mut policy_v2 = PolicyManager::create_default_policy();
        policy_v2.version = 2;
        policy_v2.min_compatible_version = 1;
        policy_v2.measurement_allowlist.allowed_pcr0.push(
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string()
        );
        let canonical = temp_manager
            .create_canonical_policy_data(&policy_v2)
            .unwrap();
        let sig = signing_key.sign(&canonical);
        policy_v2.signature = sig.to_bytes().to_vec();
        let data_v2 = serde_json::to_vec(&policy_v2).unwrap();

        assert!(update_mgr.apply_update(&data_v2).is_ok());
        let new_pcr0 = update_mgr
            .current_policy()
            .unwrap()
            .measurement_allowlist
            .allowed_pcr0
            .clone();
        assert!(new_pcr0.len() > old_pcr0.len());
        assert!(new_pcr0.contains(
            &"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string()
        ));
    }

    #[test]
    fn test_version_history_tracking() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let root_key_str = format!("ed25519:{}", STANDARD.encode(verifying_key.to_bytes()));

        let manager = PolicyManager::with_root_key(root_key_str);
        let update_mgr = PolicyUpdateManager::new(manager);

        let (data_v1, _) = make_signed_policy(&signing_key, 1, 1);
        assert!(update_mgr.apply_update(&data_v1).is_ok());

        let (data_v2, _) = make_signed_policy(&signing_key, 2, 1);
        assert!(update_mgr.apply_update(&data_v2).is_ok());

        let history = update_mgr.version_history();
        assert_eq!(history.transitions.len(), 2);
        assert_eq!(history.transitions[0].from_version, 0);
        assert_eq!(history.transitions[0].to_version, 1);
        assert_eq!(history.transitions[1].from_version, 1);
        assert_eq!(history.transitions[1].to_version, 2);
        assert_eq!(history.current_version(), Some(2));
    }

    #[test]
    #[cfg(feature = "mock")]
    fn test_load_from_file() {
        let manager = PolicyManager::new();
        let update_mgr = PolicyUpdateManager::new(manager);

        let policy = PolicyManager::create_default_policy();
        let data = serde_json::to_vec(&policy).unwrap();

        let dir = std::env::temp_dir().join("ephemeral_ml_test_policy");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_policy.json");
        std::fs::write(&path, &data).unwrap();

        assert!(update_mgr.load_from_file(&path).is_ok());
        assert!(update_mgr.current_policy().is_some());

        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
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
                "enable_shield_mode": false,
                "feature_flags": {}
            },
            "signature": []
        }"#;
        let bundle: PolicyBundle = serde_json::from_str(json).unwrap();
        assert_eq!(bundle.min_compatible_version, 1);
    }
}
