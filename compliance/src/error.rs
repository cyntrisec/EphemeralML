//! Compliance-specific error types with reason codes.

use thiserror::Error;

/// Reason codes for compliance errors, providing machine-readable context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    /// Bundle failed structural validation.
    BundleStructure = 100,
    /// A policy rule was violated.
    PolicyRuleViolated = 200,
    /// Ed25519 signature verification failed.
    SignatureInvalid = 300,
    /// Serialization or deserialization failed.
    SerializationFailed = 400,
    /// File I/O failed.
    IoFailed = 500,
    /// Schema validation failed (version, field constraints).
    SchemaInvalid = 600,
}

/// Errors that can occur during compliance operations.
#[derive(Error, Debug)]
pub enum ComplianceError {
    /// The evidence bundle is structurally invalid.
    #[error("Invalid bundle (reason {reason}): {message}")]
    InvalidBundle { reason: u32, message: String },

    /// A policy rule was violated.
    #[error("Policy violation (reason {reason}): {message}")]
    PolicyViolation { reason: u32, message: String },

    /// Signature verification failed.
    #[error("Signature error (reason {reason}): {message}")]
    SignatureError { reason: u32, message: String },

    /// Serialization or deserialization failed.
    #[error("Serialization error (reason {reason}): {message}")]
    SerializationError { reason: u32, message: String },

    /// File I/O error.
    #[error("I/O error (reason {reason}): {message}")]
    IoError { reason: u32, message: String },

    /// Schema validation error.
    #[error("Schema error (reason {reason}): {message}")]
    SchemaError { reason: u32, message: String },
}

impl ComplianceError {
    pub fn invalid_bundle(message: impl Into<String>) -> Self {
        Self::InvalidBundle {
            reason: ReasonCode::BundleStructure as u32,
            message: message.into(),
        }
    }

    pub fn policy_violation(message: impl Into<String>) -> Self {
        Self::PolicyViolation {
            reason: ReasonCode::PolicyRuleViolated as u32,
            message: message.into(),
        }
    }

    pub fn signature_error(message: impl Into<String>) -> Self {
        Self::SignatureError {
            reason: ReasonCode::SignatureInvalid as u32,
            message: message.into(),
        }
    }

    pub fn serialization_error(message: impl Into<String>) -> Self {
        Self::SerializationError {
            reason: ReasonCode::SerializationFailed as u32,
            message: message.into(),
        }
    }

    pub fn io_error(message: impl Into<String>) -> Self {
        Self::IoError {
            reason: ReasonCode::IoFailed as u32,
            message: message.into(),
        }
    }

    pub fn schema_error(message: impl Into<String>) -> Self {
        Self::SchemaError {
            reason: ReasonCode::SchemaInvalid as u32,
            message: message.into(),
        }
    }
}

impl From<std::io::Error> for ComplianceError {
    fn from(err: std::io::Error) -> Self {
        Self::io_error(err.to_string())
    }
}

impl From<serde_json::Error> for ComplianceError {
    fn from(err: serde_json::Error) -> Self {
        Self::serialization_error(err.to_string())
    }
}

impl From<serde_cbor::Error> for ComplianceError {
    fn from(err: serde_cbor::Error) -> Self {
        Self::serialization_error(err.to_string())
    }
}

/// Result type for compliance operations.
pub type ComplianceResult<T> = std::result::Result<T, ComplianceError>;
