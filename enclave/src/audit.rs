use ephemeral_ml_common::{AuditLogEntry, AuditEventType, AuditSeverity};
use std::collections::HashMap;
use serde_json::Value;

pub struct AuditLogger;

impl AuditLogger {
    /// Log an audit event to stdout (secure logging channel for Nitro Enclaves)
    pub fn log(
        event_type: AuditEventType,
        severity: AuditSeverity,
        session_id: Option<String>,
        client_id: Option<String>,
        model_id: Option<String>,
        mut details: HashMap<String, Value>,
    ) {
        // Sanitize sensitive details
        details.remove("input_data");
        details.remove("output_data");
        details.remove("weights");
        
        let entry = AuditLogEntry {
            entry_id: uuid::Uuid::new_v4().to_string(),
            timestamp: ephemeral_ml_common::current_timestamp(),
            event_type,
            session_id,
            client_id,
            model_id,
            details,
            severity,
        };

        // In a real system, this might write to a ring buffer or vsock channel.
        // For Nitro Enclaves, stdout is captured by the host securely if configured.
        if let Ok(json) = serde_json::to_string(&entry) {
            println!("{}", json);
        } else {
            eprintln!("Failed to serialize audit log entry");
        }
    }

    /// Helper for quick INFO logging
    pub fn info(event_type: AuditEventType, details: HashMap<String, Value>) {
        Self::log(event_type, AuditSeverity::Info, None, None, None, details);
    }

    pub fn log_event(entry: AuditLogEntry) {
        if let Ok(json) = serde_json::to_string(&entry) {
            println!("{}", json);
        }
    }
}
