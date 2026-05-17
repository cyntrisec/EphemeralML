use crate::{current_timestamp, generate_id, AuditEventType, AuditLogEntry, AuditSeverity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn timestamp_with_details() -> (u64, HashMap<String, serde_json::Value>) {
    match current_timestamp() {
        Ok(timestamp) => (timestamp, HashMap::new()),
        Err(err) => {
            let mut details = HashMap::new();
            details.insert(
                "timestamp_error".to_string(),
                serde_json::json!(err.to_string()),
            );
            (0, details)
        }
    }
}

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
        let (timestamp, details) = timestamp_with_details();
        Self {
            entry_id: generate_id(),
            timestamp,
            event_type,
            session_id,
            client_id,
            model_id,
            details,
            severity,
            is_metric: false,
        }
    }

    pub fn metric(event_type: AuditEventType, session_id: Option<String>) -> Self {
        let (timestamp, details) = timestamp_with_details();
        Self {
            entry_id: generate_id(),
            timestamp,
            event_type,
            session_id,
            client_id: None,
            model_id: None,
            details,
            severity: AuditSeverity::Info,
            is_metric: true,
        }
    }

    pub fn with_detail<S: Into<String>, V: Into<serde_json::Value>>(
        mut self,
        key: S,
        value: V,
    ) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}
