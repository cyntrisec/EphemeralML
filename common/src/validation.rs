use thiserror::Error;

/// System-wide validation limits for security boundary enforcement
#[derive(Debug, Clone)]
pub struct ValidationLimits {
    /// Maximum ciphertext size (16MB VSock limit)
    pub max_ciphertext_size: usize,
    /// Maximum model_id length (256 chars)
    pub max_model_id_length: usize,
    /// Maximum manifest size (1MB)
    pub max_manifest_size: usize,
    /// Maximum payload size for decompression bomb protection
    pub max_payload_size: usize,
    /// Maximum memory allocation per operation
    pub max_allocation_size: usize,
    /// Maximum number of concurrent sessions
    pub max_concurrent_sessions: usize,
    /// Maximum session duration in seconds
    pub max_session_duration: u64,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            max_ciphertext_size: 16 * 1024 * 1024, // 16MB VSock limit
            max_model_id_length: 256,              // 256 characters
            max_manifest_size: 1024 * 1024,        // 1MB
            max_payload_size: 32 * 1024 * 1024,    // 32MB for decompression protection
            max_allocation_size: 64 * 1024 * 1024, // 64MB per allocation
            max_concurrent_sessions: 100,          // 100 concurrent sessions
            max_session_duration: 15 * 60,         // 15 minutes
        }
    }
}

/// Validation errors for input validation
#[derive(Error, Debug, Clone)]
pub enum ValidationError {
    #[error("Ciphertext size {size} exceeds maximum {max}")]
    CiphertextTooLarge { size: usize, max: usize },

    #[error("Model ID length {length} exceeds maximum {max}")]
    ModelIdTooLong { length: usize, max: usize },

    #[error("Manifest size {size} exceeds maximum {max}")]
    ManifestTooLarge { size: usize, max: usize },

    #[error("Payload size {size} exceeds maximum {max}")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("Allocation size {size} exceeds maximum {max}")]
    AllocationTooLarge { size: usize, max: usize },

    #[error("Too many concurrent sessions: {current}, maximum: {max}")]
    TooManySessions { current: usize, max: usize },

    #[error("Session duration {duration} exceeds maximum {max}")]
    SessionTooLong { duration: u64, max: u64 },

    #[error("Invalid model ID: {reason}")]
    InvalidModelId { reason: String },

    #[error("Invalid payload format: {reason}")]
    InvalidPayloadFormat { reason: String },

    #[error("Decompression bomb detected: {reason}")]
    DecompressionBomb { reason: String },

    #[error("Excessive allocation detected: {reason}")]
    ExcessiveAllocation { reason: String },

    #[error("Message size limit exceeded: {0}")]
    SizeLimitExceeded(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Integrity check failed: {0}")]
    IntegrityCheckFailed(String),
}

/// Input validator for enforcing security limits
pub struct InputValidator {
    limits: ValidationLimits,
}

impl InputValidator {
    /// Create a new input validator with default limits
    pub fn new() -> Self {
        Self {
            limits: ValidationLimits::default(),
        }
    }

    /// Create a new input validator with custom limits
    pub fn with_limits(limits: ValidationLimits) -> Self {
        Self { limits }
    }

    /// Validate ciphertext size
    pub fn validate_ciphertext_size(&self, size: usize) -> Result<(), ValidationError> {
        if size > self.limits.max_ciphertext_size {
            return Err(ValidationError::CiphertextTooLarge {
                size,
                max: self.limits.max_ciphertext_size,
            });
        }
        Ok(())
    }

    /// Validate model ID
    pub fn validate_model_id(&self, model_id: &str) -> Result<(), ValidationError> {
        if model_id.len() > self.limits.max_model_id_length {
            return Err(ValidationError::ModelIdTooLong {
                length: model_id.len(),
                max: self.limits.max_model_id_length,
            });
        }

        // Check for valid characters (alphanumeric, hyphens, underscores)
        if !model_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ValidationError::InvalidModelId {
                reason: "Model ID contains invalid characters".to_string(),
            });
        }

        // Check for empty or whitespace-only
        if model_id.trim().is_empty() {
            return Err(ValidationError::InvalidModelId {
                reason: "Model ID cannot be empty".to_string(),
            });
        }

        Ok(())
    }

    /// Validate manifest size
    pub fn validate_manifest_size(&self, size: usize) -> Result<(), ValidationError> {
        if size > self.limits.max_manifest_size {
            return Err(ValidationError::ManifestTooLarge {
                size,
                max: self.limits.max_manifest_size,
            });
        }
        Ok(())
    }

    /// Validate payload size for decompression bomb protection
    pub fn validate_payload_size(&self, size: usize) -> Result<(), ValidationError> {
        if size > self.limits.max_payload_size {
            return Err(ValidationError::PayloadTooLarge {
                size,
                max: self.limits.max_payload_size,
            });
        }
        Ok(())
    }

    /// Validate allocation size to prevent excessive memory usage
    pub fn validate_allocation_size(&self, size: usize) -> Result<(), ValidationError> {
        if size > self.limits.max_allocation_size {
            return Err(ValidationError::AllocationTooLarge {
                size,
                max: self.limits.max_allocation_size,
            });
        }
        Ok(())
    }

    /// Validate number of concurrent sessions
    pub fn validate_session_count(&self, current: usize) -> Result<(), ValidationError> {
        if current >= self.limits.max_concurrent_sessions {
            return Err(ValidationError::TooManySessions {
                current,
                max: self.limits.max_concurrent_sessions,
            });
        }
        Ok(())
    }

    /// Validate session duration
    pub fn validate_session_duration(&self, duration: u64) -> Result<(), ValidationError> {
        if duration > self.limits.max_session_duration {
            return Err(ValidationError::SessionTooLong {
                duration,
                max: self.limits.max_session_duration,
            });
        }
        Ok(())
    }

    /// Detect potential decompression bombs by checking compression ratio
    pub fn validate_compression_ratio(
        &self,
        compressed_size: usize,
        uncompressed_size: usize,
    ) -> Result<(), ValidationError> {
        if compressed_size == 0 {
            return Err(ValidationError::DecompressionBomb {
                reason: "Zero-sized compressed data".to_string(),
            });
        }

        let ratio = uncompressed_size / compressed_size;
        const MAX_COMPRESSION_RATIO: usize = 1000; // 1000:1 ratio limit

        if ratio > MAX_COMPRESSION_RATIO {
            return Err(ValidationError::DecompressionBomb {
                reason: format!(
                    "Compression ratio {} exceeds maximum {}",
                    ratio, MAX_COMPRESSION_RATIO
                ),
            });
        }

        Ok(())
    }

    /// Validate tensor shape to prevent excessive allocations
    pub fn validate_tensor_shape(&self, dimensions: &[usize]) -> Result<(), ValidationError> {
        if dimensions.is_empty() {
            return Err(ValidationError::InvalidPayloadFormat {
                reason: "Tensor shape cannot be empty".to_string(),
            });
        }

        // Check for zero dimensions
        if dimensions.contains(&0) {
            return Err(ValidationError::InvalidPayloadFormat {
                reason: "Tensor dimensions cannot be zero".to_string(),
            });
        }

        // Calculate total elements and check for overflow
        let total_elements = dimensions.iter().try_fold(1usize, |acc, &dim| {
            acc.checked_mul(dim)
                .ok_or_else(|| ValidationError::ExcessiveAllocation {
                    reason: "Tensor size calculation overflow".to_string(),
                })
        })?;

        // Check against allocation limits (assuming f32 elements)
        let total_bytes =
            total_elements
                .checked_mul(4)
                .ok_or_else(|| ValidationError::ExcessiveAllocation {
                    reason: "Tensor byte size calculation overflow".to_string(),
                })?;

        self.validate_allocation_size(total_bytes)?;

        Ok(())
    }

    /// Get current validation limits
    pub fn limits(&self) -> &ValidationLimits {
        &self.limits
    }
}

impl Default for InputValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ciphertext_size() {
        let validator = InputValidator::new();

        // Valid size
        assert!(validator.validate_ciphertext_size(1024).is_ok());

        // Too large
        assert!(validator
            .validate_ciphertext_size(20 * 1024 * 1024)
            .is_err());
    }

    #[test]
    fn test_validate_model_id() {
        let validator = InputValidator::new();

        // Valid model IDs
        assert!(validator.validate_model_id("model-123").is_ok());
        assert!(validator.validate_model_id("my_model_v2").is_ok());
        assert!(validator.validate_model_id("ModelABC123").is_ok());

        // Invalid model IDs
        assert!(validator.validate_model_id("").is_err());
        assert!(validator.validate_model_id("   ").is_err());
        assert!(validator.validate_model_id("model with spaces").is_err());
        assert!(validator.validate_model_id("model@domain.com").is_err());

        // Too long
        let long_id = "a".repeat(300);
        assert!(validator.validate_model_id(&long_id).is_err());
    }

    #[test]
    fn test_validate_compression_ratio() {
        let validator = InputValidator::new();

        // Valid compression
        assert!(validator.validate_compression_ratio(1000, 10000).is_ok());

        // Decompression bomb
        assert!(validator.validate_compression_ratio(1, 2000).is_err());
        assert!(validator.validate_compression_ratio(0, 1000).is_err());
    }

    #[test]
    fn test_validate_tensor_shape() {
        let validator = InputValidator::new();

        // Valid shapes
        assert!(validator.validate_tensor_shape(&[10, 20, 30]).is_ok());
        assert!(validator.validate_tensor_shape(&[1]).is_ok());

        // Invalid shapes
        assert!(validator.validate_tensor_shape(&[]).is_err());
        assert!(validator.validate_tensor_shape(&[10, 0, 30]).is_err());

        // Too large (would cause overflow)
        assert!(validator.validate_tensor_shape(&[usize::MAX, 2]).is_err());
    }
}
