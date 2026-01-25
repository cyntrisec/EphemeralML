use crate::{ClientError, Result};
use ephemeral_ml_common::{current_timestamp, generate_nonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Freshness enforcement errors
#[derive(Error, Debug)]
pub enum FreshnessError {
    #[error("Nonce replay detected: nonce was used at timestamp {timestamp}")]
    NonceReused { timestamp: u64 },
    
    #[error("Nonce tracker capacity exceeded - potential DoS attack")]
    CapacityExceeded,
    
    #[error("Nonce expired: age {age_seconds}s exceeds limit {max_age_seconds}s")]
    NonceExpired { age_seconds: u64, max_age_seconds: u64 },
    
    #[error("Invalid nonce format: {reason}")]
    InvalidNonceFormat { reason: String },
    
    #[error("Freshness validation failed: {reason}")]
    ValidationFailed { reason: String },
}

/// Nonce generation and tracking system
#[derive(Debug)]
pub struct NonceManager {
    /// Generated nonces awaiting response
    pending_nonces: HashMap<Vec<u8>, NonceEntry>,
    /// Used nonces for replay detection
    used_nonces: HashMap<Vec<u8>, u64>,
    /// Maximum age for nonces in seconds
    max_nonce_age: u64,
    /// Maximum number of tracked nonces
    max_entries: usize,
    /// Nonce size in bytes
    nonce_size: usize,
}

/// Entry for tracking pending nonces
#[derive(Debug, Clone)]
struct NonceEntry {
    timestamp: u64,
    context: String, // Context for debugging (e.g., "attestation_challenge")
}

impl NonceManager {
    /// Create a new nonce manager
    pub fn new(max_nonce_age: u64, max_entries: usize) -> Self {
        Self {
            pending_nonces: HashMap::new(),
            used_nonces: HashMap::new(),
            max_nonce_age,
            max_entries,
            nonce_size: 12, // 96-bit nonces for ChaCha20Poly1305
        }
    }
    
    /// Generate a new nonce for a specific context
    pub fn generate_nonce(&mut self, context: &str) -> Result<Vec<u8>> {
        // Check capacity before generating
        if self.pending_nonces.len() + self.used_nonces.len() >= self.max_entries {
            // Try cleanup first
            self.cleanup_expired();
            
            // If still over capacity, fail
            if self.pending_nonces.len() + self.used_nonces.len() >= self.max_entries {
                return Err(ClientError::Client(crate::EphemeralError::AttestationError(
                    "Nonce manager capacity exceeded".to_string()
                )));
            }
        }
        
        // Generate cryptographically secure nonce
        let nonce = generate_nonce();
        let nonce_vec = nonce.to_vec();
        
        // Track as pending
        let entry = NonceEntry {
            timestamp: current_timestamp(),
            context: context.to_string(),
        };
        
        self.pending_nonces.insert(nonce_vec.clone(), entry);
        
        Ok(nonce_vec)
    }
    
    /// Validate a nonce response and mark as used
    pub fn validate_nonce_response(&mut self, nonce: &[u8]) -> Result<()> {
        // Check if nonce is in pending list
        let entry = self.pending_nonces.remove(nonce)
            .ok_or_else(|| ClientError::Client(crate::EphemeralError::AttestationError(
                "Nonce not found in pending list - possible replay or invalid nonce".to_string()
            )))?;
        
        // Check nonce age
        let current_time = current_timestamp();
        let age = current_time.saturating_sub(entry.timestamp);
        
        if age > self.max_nonce_age {
            return Err(ClientError::Client(crate::EphemeralError::AttestationError(
                format!("Nonce expired: age {}s exceeds limit {}s", age, self.max_nonce_age)
            )));
        }
        
        // Check for replay in used nonces
        if self.used_nonces.contains_key(nonce) {
            return Err(ClientError::Client(crate::EphemeralError::AttestationError(
                "Nonce replay detected in used nonces".to_string()
            )));
        }
        
        // Mark as used
        self.used_nonces.insert(nonce.to_vec(), current_time);
        
        Ok(())
    }
    
    /// Check if a nonce is valid without consuming it
    pub fn is_nonce_valid(&self, nonce: &[u8]) -> bool {
        // Must be in pending list and not in used list
        self.pending_nonces.contains_key(nonce) && !self.used_nonces.contains_key(nonce)
    }
    
    /// Clean up expired nonces
    pub fn cleanup_expired(&mut self) {
        let current_time = current_timestamp();
        
        // Remove expired pending nonces
        self.pending_nonces.retain(|_, entry| {
            current_time.saturating_sub(entry.timestamp) < self.max_nonce_age
        });
        
        // Remove expired used nonces
        self.used_nonces.retain(|_, &mut timestamp| {
            current_time.saturating_sub(timestamp) < self.max_nonce_age
        });
    }
    
    /// Get statistics about nonce tracking
    pub fn get_stats(&self) -> NonceStats {
        NonceStats {
            pending_count: self.pending_nonces.len(),
            used_count: self.used_nonces.len(),
            total_capacity: self.max_entries,
            max_age_seconds: self.max_nonce_age,
        }
    }
    
    /// Force cleanup of all nonces (for testing or reset)
    pub fn clear_all(&mut self) {
        self.pending_nonces.clear();
        self.used_nonces.clear();
    }
}

/// Statistics about nonce tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceStats {
    pub pending_count: usize,
    pub used_count: usize,
    pub total_capacity: usize,
    pub max_age_seconds: u64,
}

/// Time-based freshness validator
#[derive(Debug)]
pub struct FreshnessValidator {
    /// Maximum allowed time skew in seconds
    max_time_skew: u64,
    /// Minimum required freshness in seconds
    min_freshness: u64,
}

impl FreshnessValidator {
    /// Create a new freshness validator
    pub fn new(max_time_skew: u64, min_freshness: u64) -> Self {
        Self {
            max_time_skew,
            min_freshness,
        }
    }
    
    /// Validate timestamp freshness
    pub fn validate_timestamp(&self, timestamp: u64) -> Result<()> {
        let current_time = current_timestamp();
        
        // Check for future timestamps (clock skew)
        if timestamp > current_time + self.max_time_skew {
            return Err(ClientError::Client(crate::EphemeralError::AttestationError(
                format!("Timestamp too far in future: {} vs current {}", timestamp, current_time)
            )));
        }
        
        // Check for stale timestamps
        let age = current_time.saturating_sub(timestamp);
        if age > self.min_freshness {
            return Err(ClientError::Client(crate::EphemeralError::AttestationError(
                format!("Timestamp too old: age {}s exceeds freshness limit {}s", age, self.min_freshness)
            )));
        }
        
        Ok(())
    }
    
    /// Get current timestamp for comparison
    pub fn current_timestamp(&self) -> u64 {
        current_timestamp()
    }
}

/// Combined freshness enforcement system
#[derive(Debug)]
pub struct FreshnessEnforcer {
    nonce_manager: NonceManager,
    timestamp_validator: FreshnessValidator,
}

impl FreshnessEnforcer {
    /// Create a new freshness enforcer with default settings
    pub fn new() -> Self {
        Self {
            nonce_manager: NonceManager::new(300, 50000), // 5 minutes, 50k entries
            timestamp_validator: FreshnessValidator::new(60, 300), // 1 minute skew, 5 minute freshness
        }
    }
    
    /// Create a freshness enforcer with custom settings
    pub fn with_settings(
        max_nonce_age: u64,
        max_entries: usize,
        max_time_skew: u64,
        min_freshness: u64,
    ) -> Self {
        Self {
            nonce_manager: NonceManager::new(max_nonce_age, max_entries),
            timestamp_validator: FreshnessValidator::new(max_time_skew, min_freshness),
        }
    }
    
    /// Generate a challenge nonce for attestation
    pub fn generate_attestation_challenge(&mut self) -> Result<Vec<u8>> {
        self.nonce_manager.generate_nonce("attestation_challenge")
    }
    
    /// Validate attestation response freshness
    pub fn validate_attestation_response(&mut self, nonce: &[u8], timestamp: u64) -> Result<()> {
        // Validate nonce
        self.nonce_manager.validate_nonce_response(nonce)?;
        
        // Validate timestamp
        self.timestamp_validator.validate_timestamp(timestamp)?;
        
        Ok(())
    }
    
    /// Generate a session nonce
    pub fn generate_session_nonce(&mut self) -> Result<Vec<u8>> {
        self.nonce_manager.generate_nonce("session_establishment")
    }
    
    /// Validate session response
    pub fn validate_session_response(&mut self, nonce: &[u8], timestamp: u64) -> Result<()> {
        self.nonce_manager.validate_nonce_response(nonce)?;
        self.timestamp_validator.validate_timestamp(timestamp)?;
        Ok(())
    }
    
    /// Perform periodic cleanup
    pub fn cleanup(&mut self) {
        self.nonce_manager.cleanup_expired();
    }
    
    /// Get comprehensive statistics
    pub fn get_stats(&self) -> FreshnessStats {
        FreshnessStats {
            nonce_stats: self.nonce_manager.get_stats(),
            current_timestamp: self.timestamp_validator.current_timestamp(),
            max_time_skew: self.timestamp_validator.max_time_skew,
            min_freshness: self.timestamp_validator.min_freshness,
        }
    }
}

/// Comprehensive freshness statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshnessStats {
    pub nonce_stats: NonceStats,
    pub current_timestamp: u64,
    pub max_time_skew: u64,
    pub min_freshness: u64,
}

impl Default for FreshnessEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_nonce_manager_basic() {
        let mut manager = NonceManager::new(300, 100);
        
        // Generate nonce
        let nonce = manager.generate_nonce("test").unwrap();
        assert_eq!(nonce.len(), 12);
        
        // Should be valid
        assert!(manager.is_nonce_valid(&nonce));
        
        // Validate response
        assert!(manager.validate_nonce_response(&nonce).is_ok());
        
        // Should not be valid after use
        assert!(!manager.is_nonce_valid(&nonce));
        
        // Replay should fail
        assert!(manager.validate_nonce_response(&nonce).is_err());
    }
    
    #[test]
    fn test_nonce_manager_capacity() {
        let mut manager = NonceManager::new(300, 3); // Capacity of 3 to allow for pending + used
        
        let nonce1 = manager.generate_nonce("test1").unwrap();
        let nonce2 = manager.generate_nonce("test2").unwrap();
        
        // Should still be able to generate one more
        let nonce3 = manager.generate_nonce("test3").unwrap();
        
        // Now should fail when capacity exceeded
        assert!(manager.generate_nonce("test4").is_err());
        
        // Use one nonce to move it from pending to used
        manager.validate_nonce_response(&nonce1).unwrap();
        
        // Should still be at capacity (2 pending + 1 used = 3)
        assert!(manager.generate_nonce("test5").is_err());
        
        // Use another nonce
        manager.validate_nonce_response(&nonce2).unwrap();
        
        // Now we have 1 pending + 2 used = 3, still at capacity
        assert!(manager.generate_nonce("test6").is_err());
        
        // Use the last pending nonce
        manager.validate_nonce_response(&nonce3).unwrap();
        
        // Now we have 0 pending + 3 used = 3, still at capacity
        assert!(manager.generate_nonce("test7").is_err());
        
        // Cleanup to make room
        manager.clear_all();
        
        // Should be able to generate again after clearing
        assert!(manager.generate_nonce("test8").is_ok());
    }
    
    #[test]
    fn test_timestamp_validator() {
        let validator = FreshnessValidator::new(60, 300); // 1 min skew, 5 min freshness
        
        let current = validator.current_timestamp();
        
        // Current timestamp should be valid
        assert!(validator.validate_timestamp(current).is_ok());
        
        // Recent timestamp should be valid
        assert!(validator.validate_timestamp(current - 100).is_ok());
        
        // Future timestamp within skew should be valid
        assert!(validator.validate_timestamp(current + 30).is_ok());
        
        // Too far in future should fail
        assert!(validator.validate_timestamp(current + 120).is_err());
        
        // Too old should fail
        assert!(validator.validate_timestamp(current - 400).is_err());
    }
    
    #[test]
    fn test_freshness_enforcer_integration() {
        let mut enforcer = FreshnessEnforcer::new();
        
        // Generate attestation challenge
        let nonce = enforcer.generate_attestation_challenge().unwrap();
        let timestamp = enforcer.timestamp_validator.current_timestamp();
        
        // Validate response
        assert!(enforcer.validate_attestation_response(&nonce, timestamp).is_ok());
        
        // Replay should fail
        let nonce2 = nonce.clone();
        assert!(enforcer.validate_attestation_response(&nonce2, timestamp).is_err());
    }
    
    #[test]
    fn test_cleanup_functionality() {
        let mut manager = NonceManager::new(1, 100); // 1 second expiry
        
        let _nonce = manager.generate_nonce("test").unwrap();
        assert_eq!(manager.get_stats().pending_count, 1);
        
        // Wait for expiry
        thread::sleep(Duration::from_secs(2));
        
        // Cleanup should remove expired nonce
        manager.cleanup_expired();
        assert_eq!(manager.get_stats().pending_count, 0);
    }
    
    #[test]
    fn test_stats_collection() {
        let mut enforcer = FreshnessEnforcer::new();
        
        let _nonce1 = enforcer.generate_attestation_challenge().unwrap();
        let _nonce2 = enforcer.generate_session_nonce().unwrap();
        
        let stats = enforcer.get_stats();
        assert_eq!(stats.nonce_stats.pending_count, 2);
        assert_eq!(stats.nonce_stats.used_count, 0);
        assert!(stats.current_timestamp > 0);
    }
}