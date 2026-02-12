use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Attestation document for enclave verification
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AttestationDocument {
    pub module_id: String,
    pub digest: Vec<u8>, // SHA-384 hash (48 bytes)
    pub timestamp: u64,
    pub pcrs: PcrMeasurements,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
    pub nonce: Option<Vec<u8>>, // Optional nonce for freshness
}

/// PCR measurements for attestation
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PcrMeasurements {
    pub pcr0: Vec<u8>, // Enclave image measurement (48 bytes)
    pub pcr1: Vec<u8>, // Linux kernel measurement (48 bytes)
    pub pcr2: Vec<u8>, // Application measurement (48 bytes)
}

impl PcrMeasurements {
    /// Create new PCR measurements
    pub fn new(pcr0: Vec<u8>, pcr1: Vec<u8>, pcr2: Vec<u8>) -> Self {
        Self { pcr0, pcr1, pcr2 }
    }

    /// Validate PCR measurement lengths (should be 48 bytes each for SHA-384)
    pub fn is_valid(&self) -> bool {
        self.pcr0.len() == 48 && self.pcr1.len() == 48 && self.pcr2.len() == 48
    }
}

/// Session information for tracking inference sessions
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SessionInfo {
    pub session_id: String,
    pub client_id: String,
    pub model_id: String,
    pub created_at: u64,
    pub last_activity: u64,
    pub status: SessionStatus,
}

/// Status of an inference session
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SessionStatus {
    Initializing,
    AttestationPending,
    AttestationVerified,
    InferenceInProgress,
    Completed,
    Failed,
    Expired,
}

/// Audit log entry for security events
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditLogEntry {
    pub entry_id: String,
    pub timestamp: u64,
    pub event_type: AuditEventType,
    pub session_id: Option<String>,
    pub client_id: Option<String>,
    pub model_id: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
    pub severity: AuditSeverity,
    pub is_metric: bool,
}

/// Types of audit events
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AuditEventType {
    SessionCreated,
    AttestationRequested,
    AttestationVerified,
    AttestationFailed,
    ModelDecomposed,
    ModelAssembled,
    InferenceStarted,
    InferenceCompleted,
    InferenceFailed,
    ModelDestroyed,
    SecurityViolation,
    SystemError,
    SessionExpired,
}

/// Severity levels for audit events
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}
