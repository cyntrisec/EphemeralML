use crate::kms_proxy_client::KmsProxyClient;
use ephemeral_ml_common::{audit::AuditLogRequest, AuditEventType, AuditLogEntry, AuditSeverity};
use serde_json::Value;
use std::collections::HashMap;

/// Async logger that sends structured audit events to the host via VSock
#[derive(Clone)]
pub struct AuditLogger {
    proxy_client: KmsProxyClient,
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            proxy_client: KmsProxyClient::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send(
        &self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        session_id: Option<String>,
        client_id: Option<String>,
        model_id: Option<String>,
        details: Vec<(&str, Value)>,
        is_metric: bool,
    ) {
        let mut entry = AuditLogEntry {
            entry_id: uuid::Uuid::new_v4().to_string(),
            timestamp: ephemeral_ml_common::current_timestamp(),
            event_type: event_type.clone(),
            session_id: session_id.clone(),
            client_id,
            model_id,
            details: HashMap::new(),
            severity: severity.clone(),
            is_metric,
        };

        for (key, value) in details {
            // Sanitize - never include raw data
            if !["input_data", "output_data", "weights", "plaintext"].contains(&key) {
                entry.details.insert(key.to_string(), value);
            }
        }

        // Always print to stdout as backup (captured by nitro-cli console)
        if let Ok(json) = serde_json::to_string(&entry) {
            println!("[AUDIT] {}", json);
        }

        // Try to send via simple_frame
        let request = AuditLogRequest { entry };
        match serde_json::to_vec(&request) {
            Ok(payload) => {
                if let Err(e) = self.proxy_client.send_audit(&payload).await {
                    eprintln!("[audit] send failed (non-fatal): {:?}", e);
                }
            }
            Err(e) => eprintln!("[audit] Serialize failed: {}", e),
        }
    }

    /// Quick helpers
    pub async fn info(&self, event_type: AuditEventType, details: Vec<(&str, Value)>) {
        self.send(
            event_type,
            AuditSeverity::Info,
            None,
            None,
            None,
            details,
            false,
        )
        .await;
    }

    pub async fn metric(
        &self,
        event_type: AuditEventType,
        session_id: Option<String>,
        details: Vec<(&str, Value)>,
    ) {
        self.send(
            event_type,
            AuditSeverity::Info,
            session_id,
            None,
            None,
            details,
            true,
        )
        .await;
    }

    pub async fn warn(
        &self,
        event_type: AuditEventType,
        session_id: Option<String>,
        details: Vec<(&str, Value)>,
    ) {
        self.send(
            event_type,
            AuditSeverity::Warning,
            session_id,
            None,
            None,
            details,
            false,
        )
        .await;
    }

    pub async fn error(
        &self,
        event_type: AuditEventType,
        session_id: Option<String>,
        details: Vec<(&str, Value)>,
    ) {
        self.send(
            event_type,
            AuditSeverity::Error,
            session_id,
            None,
            None,
            details,
            false,
        )
        .await;
    }

    pub async fn critical(
        &self,
        event_type: AuditEventType,
        session_id: Option<String>,
        details: Vec<(&str, Value)>,
    ) {
        self.send(
            event_type,
            AuditSeverity::Critical,
            session_id,
            None,
            None,
            details,
            false,
        )
        .await;
    }
}

/// Sync fallback for contexts where async isn't available
pub fn log_sync(
    event_type: AuditEventType,
    severity: AuditSeverity,
    session_id: Option<String>,
    details: HashMap<String, Value>,
) {
    let entry = AuditLogEntry {
        entry_id: uuid::Uuid::new_v4().to_string(),
        timestamp: ephemeral_ml_common::current_timestamp(),
        event_type,
        session_id,
        client_id: None,
        model_id: None,
        details,
        severity,
        is_metric: false,
    };

    if let Ok(json) = serde_json::to_string(&entry) {
        println!("[AUDIT] {}", json);
    }
}
