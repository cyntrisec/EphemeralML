use serde::{Deserialize, Serialize};
use crate::{AuditLogEntry, AuditEventType, AuditSeverity, current_timestamp, generate_id};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditLogRequest {
    pub entry: AuditLogEntry,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditLogResponse {
    pub success: bool,
    pub error: Option<String>,
}

impl AuditLogEntry {
    pub fn new(
        event_type: AuditEventType,
        severity: AuditSeverity,
        session_id: Option<String>,
        client_id: Option<String>,
        model_id: Option<String>,
    ) -> Self {
        Self {
            entry_id: generate_id(),
            timestamp: current_timestamp(),
            event_type,
            session_id,
            client_id,
            model_id,
            details: HashMap::new(),
            severity,
            is_metric: false,
        }
    }

    pub fn metric(
        event_type: AuditEventType,
        session_id: Option<String>,
    ) -> Self {
        Self {
            entry_id: generate_id(),
            timestamp: current_timestamp(),
            event_type,
            session_id,
            client_id: None,
            model_id: None,
            details: HashMap::new(),
            severity: AuditSeverity::Info,
            is_metric: true,
        }
    }

    pub fn with_detail<S: Into<String>, V: Into<serde_json::Value>>(mut self, key: S, value: V) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}
