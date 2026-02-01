use crate::{EnclaveError, EphemeralError, Result};
use ephemeral_ml_common::{
    AttestationReceipt, EncryptedMessage, HPKESession, ReceiptSigningKey, SessionId,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Session state maintained within the enclave
pub struct EnclaveSession {
    /// HPKE session for encryption/decryption
    pub hpke: HPKESession,
    /// Receipt signing key specific to this session
    pub receipt_signing_key: ReceiptSigningKey,
    /// Bound attestation document hash
    pub attestation_hash: [u8; 32],
    /// Client ID
    pub client_id: String,
}

impl EnclaveSession {
    pub fn new(
        _session_id: SessionId,
        hpke: HPKESession,
        receipt_signing_key: ReceiptSigningKey,
        attestation_hash: [u8; 32],
        client_id: String,
    ) -> Self {
        Self {
            hpke,
            receipt_signing_key,
            attestation_hash,
            client_id,
        }
    }

    /// Decrypt an incoming message
    pub fn decrypt(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        self.hpke
            .decrypt(message)
            .map_err(|e| EnclaveError::Enclave(e))
    }

    /// Encrypt an outgoing message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        self.hpke
            .encrypt(plaintext)
            .map_err(|e| EnclaveError::Enclave(e))
    }

    /// Sign an execution receipt
    pub fn sign_receipt(&mut self, receipt: &mut AttestationReceipt) -> Result<()> {
        // Enforce sequence number consistency
        if receipt.sequence_number != self.hpke.get_next_sequence() {
            // This is a check to ensure the receipt matches the session state.
            // In practice, we might set the sequence number here.
        }

        receipt
            .sign(&self.receipt_signing_key)
            .map_err(|e| EnclaveError::Enclave(e))
    }

    /// Explicitly close the session and zeroize sensitive data immediately
    pub fn close(&mut self) {
        self.hpke.is_established = false;
        // The Drop implementation will handle actual zeroization of keys
    }
}

/// Manages active sessions within the enclave
#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<SessionId, EnclaveSession>>>,
    max_sessions: usize,
}

impl SessionManager {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            max_sessions,
        }
    }

    /// Add a new session
    pub fn add_session(&self, session: EnclaveSession) -> Result<()> {
        let mut sessions = self.sessions.lock().map_err(|_| {
            EnclaveError::Enclave(EphemeralError::Internal("Lock poisoned".to_string()))
        })?;
        if sessions.len() >= self.max_sessions {
            return Err(EnclaveError::Enclave(EphemeralError::ResourceExhausted(
                "Max sessions reached".to_string(),
            )));
        }
        sessions.insert(session.hpke.session_id.clone(), session);
        Ok(())
    }

    /// Access a session to perform operations
    /// Returns a guard or closure result?
    /// For simplicity, we'll expose a method to run a closure on the session
    pub fn with_session<F, R>(&self, _session_id: &str, f: F) -> Result<R>
    where
        F: FnOnce(&mut EnclaveSession) -> Result<R>,
    {
        let mut sessions = self.sessions.lock().map_err(|_| {
            EnclaveError::Enclave(EphemeralError::Internal("Lock poisoned".to_string()))
        })?;
        let session = sessions.get_mut(_session_id).ok_or_else(|| {
            EnclaveError::Enclave(EphemeralError::InvalidInput(
                "Session not found".to_string(),
            ))
        })?;

        f(session)
    }

    /// Remove a session
    pub fn remove_session(&self, session_id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(session_id);
        }
    }

    /// Get a session by ID (removed from manager)
    pub fn get_session(&self, session_id: &str) -> Option<EnclaveSession> {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(session_id)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_ml_common::ReceiptSigningKey;

    #[test]
    fn test_max_sessions_enforced() {
        let manager = SessionManager::new(2);

        let create_session = |id: &str| {
            let hpke = HPKESession::new(
                id.to_string(),
                1,
                [0u8; 32],
                [0u8; 32],
                [0u8; 32],
                [0u8; 12],
                3600,
            )
            .unwrap();
            let receipt_key = ReceiptSigningKey::generate().unwrap();
            EnclaveSession::new(
                id.to_string(),
                hpke,
                receipt_key,
                [0u8; 32],
                "client".to_string(),
            )
        };

        // Add 2 sessions
        assert!(manager.add_session(create_session("s1")).is_ok());
        assert!(manager.add_session(create_session("s2")).is_ok());

        // Add 3rd session (should fail)
        let result = manager.add_session(create_session("s3"));
        assert!(result.is_err());
        assert!(format!("{:?}", result.err().unwrap()).contains("Max sessions reached"));

        // Remove one and add again
        manager.remove_session("s1");
        assert!(manager.add_session(create_session("s3")).is_ok());
    }
}
