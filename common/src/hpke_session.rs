//! HPKE session management with X25519 keys and attestation binding
//! 
//! This module implements HPKE (Hybrid Public Key Encryption) session establishment
//! bound to enclave attestation documents with replay protection.

use crate::error::{EphemeralError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::ZeroizeOnDrop;

/// Session ID type for tracking HPKE sessions
pub type SessionId = String;

/// HPKE session configuration using fixed cipher suite for v1
#[derive(Debug, Clone)]
pub struct HPKEConfig {
    /// KEM: X25519
    pub kem_id: u16,
    /// KDF: HKDF-SHA256  
    pub kdf_id: u16,
    /// AEAD: ChaCha20-Poly1305
    pub aead_id: u16,
}

impl Default for HPKEConfig {
    fn default() -> Self {
        Self {
            kem_id: 0x0020, // X25519
            kdf_id: 0x0001, // HKDF-SHA256
            aead_id: 0x0003, // ChaCha20-Poly1305
        }
    }
}

/// HPKE session state with secure memory management
#[derive(ZeroizeOnDrop)]
pub struct HPKESession {
    pub session_id: SessionId,
    pub protocol_version: u32,
    pub attestation_hash: [u8; 32],
    pub local_public_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub client_nonce: [u8; 12],
    pub transcript_hash: [u8; 32],
    
    // Session keys (zeroized on drop)
    session_key: [u8; 32],
    next_sequence_number: u64,
    next_incoming_sequence: u64,
    
    // Session metadata
    pub created_at: u64,
    pub expires_at: u64,
    pub is_established: bool,
}

impl HPKESession {
    /// Create a new HPKE session with attestation binding
    pub fn new(
        session_id: SessionId,
        protocol_version: u32,
        attestation_hash: [u8; 32],
        local_public_key: [u8; 32],
        peer_public_key: [u8; 32],
        client_nonce: [u8; 12],
        ttl_seconds: u64,
    ) -> Result<Self> {
        let now = crate::current_timestamp();
        
        // Derive transcript hash: attestation_hash || local_public_key || peer_public_key || client_nonce || protocol_version
        let transcript_hash = Self::derive_transcript_hash(
            &attestation_hash,
            &local_public_key,
            &peer_public_key,
            &client_nonce,
            protocol_version,
        )?;
        
        Ok(Self {
            session_id,
            protocol_version,
            attestation_hash,
            local_public_key,
            peer_public_key,
            client_nonce,
            transcript_hash,
            session_key: [0u8; 32], // Will be derived during establishment
            next_sequence_number: 0,
            next_incoming_sequence: 0,
            created_at: now,
            expires_at: now + ttl_seconds,
            is_established: false,
        })
    }
    
    /// Derive canonical transcript hash for session binding
    fn derive_transcript_hash(
        attestation_hash: &[u8; 32],
        local_public_key: &[u8; 32],
        peer_public_key: &[u8; 32],
        client_nonce: &[u8; 12],
        protocol_version: u32,
    ) -> Result<[u8; 32]> {
        use sha2::{Sha256, Digest};
        
        // Canonical order for public keys to ensure both sides reach same transcript hash
        let mut keys = [*local_public_key, *peer_public_key];
        keys.sort();
        
        let mut hasher = Sha256::new();
        hasher.update(attestation_hash);
        hasher.update(&keys[0]);
        hasher.update(&keys[1]);
        hasher.update(client_nonce);
        hasher.update(&protocol_version.to_be_bytes());
        
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        Ok(result)
    }
    
    /// Establish HPKE session using local private key and peer public key
    pub fn establish(&mut self, local_private_key: &[u8; 32]) -> Result<()> {
        use x25519_dalek::{StaticSecret, PublicKey};
        
        let secret = StaticSecret::from(*local_private_key);
        let peer_pub = PublicKey::from(self.peer_public_key);
        let shared_secret = secret.diffie_hellman(&peer_pub);
        
        // Derive session key from shared secret and transcript binding
        self.session_key = Self::derive_session_key(
            shared_secret.as_bytes(),
            &self.transcript_hash,
        )?;
        
        self.is_established = true;
        Ok(())
    }
    
    /// Derive session key using HKDF-SHA256 per RFC 5869
    /// 
    /// Uses extract-then-expand pattern with shared_secret as IKM and
    /// transcript_hash as context info for domain separation.
    fn derive_session_key(
        shared_secret: &[u8; 32],
        transcript_hash: &[u8; 32],
    ) -> Result<[u8; 32]> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        // HKDF-Extract + Expand per RFC 5869
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut key = [0u8; 32];
        
        // Domain separation with protocol identifier
        hkdf.expand(transcript_hash, &mut key)
            .map_err(|e| EphemeralError::EncryptionError(
                format!("HKDF key derivation failed: {:?}", e)
            ))?;
        
        Ok(key)
    }
    
    /// Encrypt payload with replay protection
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        if !self.is_established {
            return Err(EphemeralError::EncryptionError("Session not established".to_string()));
        }
        
        if self.is_expired() {
            return Err(EphemeralError::EncryptionError("Session expired".to_string()));
        }
        
        let sequence_number = self.next_sequence_number;
        self.next_sequence_number += 1;
        
        // Create message frame: version || session_id || seq_no || plaintext
        let message_frame = self.create_message_frame(plaintext, sequence_number)?;
        
        // Encrypt using ChaCha20-Poly1305 AEAD with the specific sequence number
        let ciphertext = self.encrypt_frame_with_sequence(&message_frame, sequence_number)?;
        
        // Extract authentication tag from the end of ciphertext (last 16 bytes)
        if ciphertext.len() < 16 {
            return Err(EphemeralError::EncryptionError("Ciphertext too short for auth tag".to_string()));
        }
        
        let (encrypted_data, auth_tag_slice) = ciphertext.split_at(ciphertext.len() - 16);
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(auth_tag_slice);
        
        Ok(EncryptedMessage {
            session_id: self.session_id.clone(),
            protocol_version: self.protocol_version,
            sequence_number,
            ciphertext: encrypted_data.to_vec(),
            auth_tag,
        })
    }
    
    /// Decrypt payload with replay protection
    pub fn decrypt(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        if !self.is_established {
            return Err(EphemeralError::DecryptionError("Session not established".to_string()));
        }
        
        if message.session_id != self.session_id {
            return Err(EphemeralError::DecryptionError("Session ID mismatch".to_string()));
        }
        
        if message.protocol_version != self.protocol_version {
            return Err(EphemeralError::DecryptionError("Protocol version mismatch".to_string()));
        }
        
        // Enforce strict monotonic sequence
        if message.sequence_number != self.next_incoming_sequence {
             return Err(EphemeralError::DecryptionError(format!(
                "Replay or out-of-order packet detected: expected sequence {}, got {}", 
                self.next_incoming_sequence, message.sequence_number
            )));
        }

        // Reconstruct full ciphertext with authentication tag for ChaCha20-Poly1305
        let mut full_ciphertext = message.ciphertext.clone();
        full_ciphertext.extend_from_slice(&message.auth_tag);
        
        // Decrypt and verify message frame using the sequence number from the message
        let message_frame = self.decrypt_frame(&full_ciphertext, message.sequence_number)?;
        let plaintext = self.parse_message_frame(&message_frame, message.sequence_number)?;
        
        // Increment sequence only after success
        self.next_incoming_sequence += 1;
        
        Ok(plaintext)
    }
    
    /// Create canonical message frame
    fn create_message_frame(&self, plaintext: &[u8], sequence_number: u64) -> Result<Vec<u8>> {
        let mut frame = Vec::new();
        
        // version (4 bytes)
        frame.extend_from_slice(&self.protocol_version.to_be_bytes());
        
        // session_id length + session_id
        let session_id_bytes = self.session_id.as_bytes();
        frame.extend_from_slice(&(session_id_bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(session_id_bytes);
        
        // sequence_number (8 bytes)
        frame.extend_from_slice(&sequence_number.to_be_bytes());
        
        // plaintext length + plaintext
        frame.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        frame.extend_from_slice(plaintext);
        
        Ok(frame)
    }
    
    /// Parse message frame and extract plaintext
    fn parse_message_frame(&self, frame: &[u8], expected_sequence: u64) -> Result<Vec<u8>> {
        if frame.len() < 16 {
            return Err(EphemeralError::DecryptionError("Frame too short".to_string()));
        }
        
        let mut offset = 0;
        
        // Parse version
        let version = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        if version != self.protocol_version {
            return Err(EphemeralError::DecryptionError("Version mismatch in frame".to_string()));
        }
        offset += 4;
        
        // Parse session_id
        let session_id_len = u32::from_be_bytes([
            frame[offset], frame[offset + 1], frame[offset + 2], frame[offset + 3]
        ]) as usize;
        offset += 4;
        
        if offset + session_id_len > frame.len() {
            return Err(EphemeralError::DecryptionError("Invalid session ID length".to_string()));
        }
        
        let session_id = String::from_utf8(frame[offset..offset + session_id_len].to_vec())
            .map_err(|_| EphemeralError::DecryptionError("Invalid session ID encoding".to_string()))?;
        
        if session_id != self.session_id {
            return Err(EphemeralError::DecryptionError("Session ID mismatch in frame".to_string()));
        }
        offset += session_id_len;
        
        // Parse sequence number
        if offset + 8 > frame.len() {
            return Err(EphemeralError::DecryptionError("Frame too short for sequence".to_string()));
        }
        
        let sequence = u64::from_be_bytes([
            frame[offset], frame[offset + 1], frame[offset + 2], frame[offset + 3],
            frame[offset + 4], frame[offset + 5], frame[offset + 6], frame[offset + 7],
        ]);
        
        if sequence != expected_sequence {
            return Err(EphemeralError::DecryptionError("Sequence number mismatch".to_string()));
        }
        offset += 8;
        
        // Parse plaintext
        if offset + 4 > frame.len() {
            return Err(EphemeralError::DecryptionError("Frame too short for plaintext length".to_string()));
        }
        
        let plaintext_len = u32::from_be_bytes([
            frame[offset], frame[offset + 1], frame[offset + 2], frame[offset + 3]
        ]) as usize;
        offset += 4;
        
        if offset + plaintext_len != frame.len() {
            return Err(EphemeralError::DecryptionError("Invalid plaintext length".to_string()));
        }
        
        Ok(frame[offset..].to_vec())
    }
    
    /// Encrypt message frame using ChaCha20-Poly1305 AEAD with specific sequence number
    fn encrypt_frame_with_sequence(&self, frame: &[u8], sequence_number: u64) -> Result<Vec<u8>> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305,
        };
        
        // Create cipher from session key
        let cipher = ChaCha20Poly1305::new_from_slice(&self.session_key)
            .map_err(|e| EphemeralError::EncryptionError(format!("Failed to create cipher: {}", e)))?;
        
        // Generate nonce from the specific sequence number
        let nonce = self.derive_nonce_for_sequence(sequence_number)?;
        
        // Encrypt with authenticated encryption
        let ciphertext = cipher.encrypt(&nonce.into(), frame)
            .map_err(|e| EphemeralError::EncryptionError(format!("Encryption failed: {}", e)))?;
        
        Ok(ciphertext)
    }
    
    /// Decrypt message frame using ChaCha20-Poly1305 AEAD
    fn decrypt_frame(&self, ciphertext: &[u8], sequence_number: u64) -> Result<Vec<u8>> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305,
        };
        
        // Create cipher from session key
        let cipher = ChaCha20Poly1305::new_from_slice(&self.session_key)
            .map_err(|e| EphemeralError::DecryptionError(format!("Failed to create cipher: {}", e)))?;
        
        // Generate nonce from the specific sequence number used for encryption
        let nonce = self.derive_nonce_for_sequence(sequence_number)?;
        
        // Decrypt with authentication verification
        let plaintext = cipher.decrypt(&nonce.into(), ciphertext)
            .map_err(|e| EphemeralError::DecryptionError(format!("Decryption failed: {}", e)))?;
        
        Ok(plaintext)
    }
    
    /// Derive nonce for ChaCha20-Poly1305 from session state and sequence number
    fn derive_nonce_for_sequence(&self, sequence_number: u64) -> Result<[u8; 12]> {
        use sha2::{Sha256, Digest};
        
        // Derive nonce from session key, specific sequence number, and transcript hash
        let mut hasher = Sha256::new();
        hasher.update(&self.session_key);
        hasher.update(&sequence_number.to_be_bytes());
        hasher.update(&self.transcript_hash);
        hasher.update(b"ChaCha20Poly1305-Nonce");
        
        let hash = hasher.finalize();
        
        // Take first 12 bytes for ChaCha20-Poly1305 nonce
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&hash[..12]);
        
        Ok(nonce_bytes)
    }
    
    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        crate::current_timestamp() >= self.expires_at
    }
    
    /// Get next sequence number for replay protection
    pub fn get_next_sequence(&self) -> u64 {
        self.next_sequence_number
    }
}

/// Encrypted message with replay protection
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedMessage {
    pub session_id: SessionId,
    pub protocol_version: u32,
    pub sequence_number: u64,
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
}

/// HPKE session manager for handling multiple sessions
pub struct HPKESessionManager {
    sessions: HashMap<SessionId, HPKESession>,
    _config: HPKEConfig,
    max_sessions: usize,
}

impl HPKESessionManager {
    /// Create new session manager
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            _config: HPKEConfig::default(),
            max_sessions,
        }
    }
    
    /// Create new HPKE session with attestation binding
    pub fn create_session(
        &mut self,
        session_id: SessionId,
        protocol_version: u32,
        attestation_hash: [u8; 32],
        local_public_key: [u8; 32],
        peer_public_key: [u8; 32],
        client_nonce: [u8; 12],
        ttl_seconds: u64,
    ) -> Result<()> {
        if self.sessions.len() >= self.max_sessions {
            return Err(EphemeralError::ResourceExhausted("Too many sessions".to_string()));
        }
        
        let session = HPKESession::new(
            session_id.clone(),
            protocol_version,
            attestation_hash,
            local_public_key,
            peer_public_key,
            client_nonce,
            ttl_seconds,
        )?;
        
        self.sessions.insert(session_id, session);
        Ok(())
    }
    
    /// Establish session with enclave private key
    pub fn establish_session(
        &mut self,
        session_id: &SessionId,
        local_private_key: &[u8; 32],
    ) -> Result<()> {
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| EphemeralError::InvalidInput("Session not found".to_string()))?;
        
        session.establish(local_private_key)
    }
    
    /// Encrypt payload for session
    pub fn encrypt(
        &mut self,
        session_id: &SessionId,
        plaintext: &[u8],
    ) -> Result<EncryptedMessage> {
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| EphemeralError::InvalidInput("Session not found".to_string()))?;
        
        session.encrypt(plaintext)
    }
    
    /// Decrypt payload for session
    pub fn decrypt(
        &mut self,
        message: &EncryptedMessage,
    ) -> Result<Vec<u8>> {
        let session = self.sessions.get_mut(&message.session_id)
            .ok_or_else(|| EphemeralError::InvalidInput("Session not found".to_string()))?;
        
        session.decrypt(message)
    }
    
    /// Remove expired sessions
    pub fn cleanup_expired(&mut self) {
        self.sessions.retain(|_, session| !session.is_expired());
    }
    
    /// Terminate session
    pub fn terminate_session(&mut self, session_id: &SessionId) -> Result<()> {
        self.sessions.remove(session_id)
            .ok_or_else(|| EphemeralError::InvalidInput("Session not found".to_string()))?;
        Ok(())
    }
    
    /// Get session info
    pub fn get_session_info(&self, session_id: &SessionId) -> Option<SessionInfo> {
        self.sessions.get(session_id).map(|session| SessionInfo {
            session_id: session.session_id.clone(),
            protocol_version: session.protocol_version,
            is_established: session.is_established,
            created_at: session.created_at,
            expires_at: session.expires_at,
            next_sequence: session.next_sequence_number,
        })
    }
}

/// Session information for external queries
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: SessionId,
    pub protocol_version: u32,
    pub is_established: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub next_sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hpke_session_creation() {
        let session_id = "test-session".to_string();
        let protocol_version = 1;
        let attestation_hash = [1u8; 32];
        let local_public_key = [2u8; 32];
        let peer_public_key = [3u8; 32];
        let client_nonce = [4u8; 12];
        let ttl_seconds = 3600;
        
        let session = HPKESession::new(
            session_id.clone(),
            protocol_version,
            attestation_hash,
            local_public_key,
            peer_public_key,
            client_nonce,
            ttl_seconds,
        ).unwrap();
        
        assert_eq!(session.session_id, session_id);
        assert_eq!(session.protocol_version, protocol_version);
        assert!(!session.is_established);
        assert!(!session.is_expired());
    }
    
    #[test]
    fn test_session_establishment() {
        use x25519_dalek::{StaticSecret, PublicKey};
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = PublicKey::from(&client_secret);
        
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let mut session = HPKESession::new(
            "test".to_string(),
            1,
            [1u8; 32],
            *client_public.as_bytes(),
            *server_public.as_bytes(),
            [3u8; 12],
            3600,
        ).unwrap();
        
        session.establish(client_secret.as_bytes()).unwrap();
        
        assert!(session.is_established);
    }
    
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        use x25519_dalek::{StaticSecret, PublicKey};
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = PublicKey::from(&client_secret);
        
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let mut client_session = HPKESession::new(
            "test".to_string(),
            1,
            [1u8; 32],
            *client_public.as_bytes(),
            *server_public.as_bytes(),
            [3u8; 12],
            3600,
        ).unwrap();
        client_session.establish(client_secret.as_bytes()).unwrap();

        let mut server_session = HPKESession::new(
            "test".to_string(),
            1,
            [1u8; 32],
            *server_public.as_bytes(),
            *client_public.as_bytes(),
            [3u8; 12],
            3600,
        ).unwrap();
        server_session.establish(server_secret.as_bytes()).unwrap();
        
        let plaintext = b"Hello, HPKE!";
        let encrypted = client_session.encrypt(plaintext).unwrap();
        let decrypted = server_session.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_chacha20_poly1305_encryption() {
        use x25519_dalek::{StaticSecret, PublicKey};
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = PublicKey::from(&client_secret);
        
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let mut session = HPKESession::new(
            "test-chacha20".to_string(),
            1,
            [1u8; 32],
            *client_public.as_bytes(),
            *server_public.as_bytes(),
            [3u8; 12],
            3600,
        ).unwrap();
        
        session.establish(client_secret.as_bytes()).unwrap();
        
        let plaintext = b"Test ChaCha20-Poly1305 encryption";
        let encrypted1 = session.encrypt(plaintext).unwrap();
        let encrypted2 = session.encrypt(plaintext).unwrap();
        
        // Verify that the same plaintext produces different ciphertext due to sequence numbers
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        assert_ne!(encrypted1.sequence_number, encrypted2.sequence_number);
        
        // Verify that ciphertext is not just XOR (would be predictable pattern)
        let mut xor_result = plaintext.to_vec();
        for (i, byte) in xor_result.iter_mut().enumerate() {
            *byte ^= session.session_key[i % 32];
        }
        
        // ChaCha20-Poly1305 ciphertext should be different from simple XOR
        assert_ne!(encrypted1.ciphertext, xor_result);
        
        // Reset sequence for decryption test (or create a receiver session)
        let mut receiver_session = HPKESession::new(
            "test-chacha20".to_string(),
            1,
            [1u8; 32],
            *server_public.as_bytes(),
            *client_public.as_bytes(),
            [3u8; 12],
            3600,
        ).unwrap();
        receiver_session.establish(server_secret.as_bytes()).unwrap();

        let decrypted1 = receiver_session.decrypt(&encrypted1).unwrap();
        let decrypted2 = receiver_session.decrypt(&encrypted2).unwrap();
        
        assert_eq!(plaintext, decrypted1.as_slice());
        assert_eq!(plaintext, decrypted2.as_slice());
    }
    
    #[test]
    fn test_session_manager() {
        use x25519_dalek::{StaticSecret, PublicKey};
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = PublicKey::from(&client_secret);
        
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let mut manager = HPKESessionManager::new(10);
        
        let session_id = "test-session".to_string();
        manager.create_session(
            session_id.clone(),
            1,
            [1u8; 32],
            *client_public.as_bytes(),
            *server_public.as_bytes(),
            [3u8; 12],
            3600,
        ).unwrap();
        
        manager.establish_session(&session_id, client_secret.as_bytes()).unwrap();
        
        let plaintext = b"Test message";
        let encrypted = manager.encrypt(&session_id, plaintext).unwrap();

        // Server side
        let mut server_manager = HPKESessionManager::new(10);
        server_manager.create_session(
            session_id.clone(),
            1,
            [1u8; 32],
            *server_public.as_bytes(),
            *client_public.as_bytes(),
            [3u8; 12],
            3600,
        ).unwrap();
        server_manager.establish_session(&session_id, server_secret.as_bytes()).unwrap();

        let decrypted = server_manager.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_replay_protection_failure() {
        use x25519_dalek::{StaticSecret, PublicKey};
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let mut client_session = HPKESession::new(
            "test-replay".to_string(),
            1, [1u8; 32], *client_public.as_bytes(), *server_public.as_bytes(), [3u8; 12], 3600
        ).unwrap();
        client_session.establish(client_secret.as_bytes()).unwrap();
        
        let mut server_session = HPKESession::new(
            "test-replay".to_string(),
            1, [1u8; 32], *server_public.as_bytes(), *client_public.as_bytes(), [3u8; 12], 3600
        ).unwrap();
        server_session.establish(server_secret.as_bytes()).unwrap();
        
        let plaintext = b"Replay me!";
        let encrypted = client_session.encrypt(plaintext).unwrap();
        
        // First decryption should succeed
        let decrypted1 = server_session.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext, decrypted1.as_slice());
        
        // Second decryption of same message should fail due to replay protection
        let result = server_session.decrypt(&encrypted);
        assert!(result.is_err());
        
        // Verify error message mentions replay
        let err = result.err().unwrap();
        assert!(format!("{}", err).contains("Replay or out-of-order"));
    }

    #[test]
    fn test_ciphertext_tampering() {
        use x25519_dalek::{StaticSecret, PublicKey};
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let mut client_session = HPKESession::new(
            "test-tamper".to_string(),
            1, [0u8; 32], *client_public.as_bytes(), *server_public.as_bytes(), [0u8; 12], 3600
        ).unwrap();
        client_session.establish(client_secret.as_bytes()).unwrap();
        
        let mut server_session = HPKESession::new(
            "test-tamper".to_string(),
            1, [0u8; 32], *server_public.as_bytes(), *client_public.as_bytes(), [0u8; 12], 3600
        ).unwrap();
        server_session.establish(server_secret.as_bytes()).unwrap();

        let plaintext = b"Sensitive data";
        let mut encrypted = client_session.encrypt(plaintext).unwrap();
        
        // Flip one bit in ciphertext
        encrypted.ciphertext[0] ^= 0x01;
        
        let result = server_session.decrypt(&encrypted);
        assert!(result.is_err());
        assert!(format!("{:?}", result.err().unwrap()).contains("Decryption failed"));
    }

    #[test]
    fn test_auth_tag_tampering() {
        use x25519_dalek::{StaticSecret, PublicKey};
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let mut client_session = HPKESession::new(
            "test-tag-tamper".to_string(),
            1, [0u8; 32], *client_public.as_bytes(), *server_public.as_bytes(), [0u8; 12], 3600
        ).unwrap();
        client_session.establish(client_secret.as_bytes()).unwrap();
        
        let mut server_session = HPKESession::new(
            "test-tag-tamper".to_string(),
            1, [0u8; 32], *server_public.as_bytes(), *client_public.as_bytes(), [0u8; 12], 3600
        ).unwrap();
        server_session.establish(server_secret.as_bytes()).unwrap();

        let mut encrypted = client_session.encrypt(b"data").unwrap();
        
        // Flip one bit in auth tag
        encrypted.auth_tag[0] ^= 0x01;
        
        assert!(server_session.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_header_tampering() {
        use x25519_dalek::{StaticSecret, PublicKey};
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_public = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_public = PublicKey::from(&server_secret);

        let mut client_session = HPKESession::new(
            "test-header".to_string(),
            1, [0u8; 32], *client_public.as_bytes(), *server_public.as_bytes(), [0u8; 12], 3600
        ).unwrap();
        client_session.establish(client_secret.as_bytes()).unwrap();
        
        let mut server_session = HPKESession::new(
            "test-header".to_string(),
            1, [0u8; 32], *server_public.as_bytes(), *client_public.as_bytes(), [0u8; 12], 3600
        ).unwrap();
        server_session.establish(server_secret.as_bytes()).unwrap();

        let encrypted = client_session.encrypt(b"data").unwrap();
        
        // Tamper with sequence number in the header (unencrypted part of struct)
        let mut bad_seq = encrypted.clone();
        bad_seq.sequence_number = 999;
        assert!(server_session.decrypt(&bad_seq).is_err());
        
        // Tamper with session_id
        let mut bad_session = encrypted.clone();
        bad_session.session_id = "wrong".to_string();
        assert!(server_session.decrypt(&bad_session).is_err());
    }

    mod prop_tests {
        use super::*;
        use proptest::prelude::*;
        use x25519_dalek::{StaticSecret, PublicKey};

        proptest! {
            #[test]
            fn test_hpke_roundtrip_prop(
                session_id in ".*",
                protocol_version in 0..100u32,
                attestation_hash in any::<[u8; 32]>(),
                local_key_seed in any::<[u8; 32]>(),
                peer_key_seed in any::<[u8; 32]>(),
                client_nonce in any::<[u8; 12]>(),
                payload in any::<Vec<u8>>()
            ) {
                let local_secret = StaticSecret::from(local_key_seed);
                let local_public = PublicKey::from(&local_secret);
                
                let peer_secret = StaticSecret::from(peer_key_seed);
                let peer_public = PublicKey::from(&peer_secret);

                let mut client_session = HPKESession::new(
                    session_id.clone(),
                    protocol_version,
                    attestation_hash,
                    *local_public.as_bytes(),
                    *peer_public.as_bytes(),
                    client_nonce,
                    3600,
                ).unwrap();
                client_session.establish(local_secret.as_bytes()).unwrap();

                let mut server_session = HPKESession::new(
                    session_id,
                    protocol_version,
                    attestation_hash,
                    *peer_public.as_bytes(),
                    *local_public.as_bytes(),
                    client_nonce,
                    3600,
                ).unwrap();
                server_session.establish(peer_secret.as_bytes()).unwrap();

                let encrypted = client_session.encrypt(&payload).unwrap();
                let decrypted = server_session.decrypt(&encrypted).unwrap();
                prop_assert_eq!(payload, decrypted);
            }

            #[test]
            fn test_transcript_hash_uniqueness(
                attestation_hash in any::<[u8; 32]>(),
                local_public_key in any::<[u8; 32]>(),
                peer_public_key in any::<[u8; 32]>(),
                client_nonce in any::<[u8; 12]>(),
                protocol_version in any::<u32>(),
                different_attestation_hash in any::<[u8; 32]>(),
            ) {
                prop_assume!(attestation_hash != different_attestation_hash);
                
                let hash1 = HPKESession::derive_transcript_hash(
                    &attestation_hash,
                    &local_public_key,
                    &peer_public_key,
                    &client_nonce,
                    protocol_version
                ).unwrap();
                
                let hash2 = HPKESession::derive_transcript_hash(
                    &different_attestation_hash,
                    &local_public_key,
                    &peer_public_key,
                    &client_nonce,
                    protocol_version
                ).unwrap();
                
                prop_assert_ne!(hash1, hash2);
            }

            #[test]
            fn test_replay_protection_prop(payload in any::<Vec<u8>>()) {
                let local_secret = StaticSecret::from([1u8; 32]);
                let local_public = PublicKey::from(&local_secret);
                let peer_secret = StaticSecret::from([2u8; 32]);
                let peer_public = PublicKey::from(&peer_secret);

                let mut client_session = HPKESession::new(
                    "test".into(), 1, [0u8; 32],
                    *local_public.as_bytes(), *peer_public.as_bytes(), [0u8; 12], 3600
                ).unwrap();
                client_session.establish(local_secret.as_bytes()).unwrap();

                let mut server_session = HPKESession::new(
                    "test".into(), 1, [0u8; 32],
                    *peer_public.as_bytes(), *local_public.as_bytes(), [0u8; 12], 3600
                ).unwrap();
                server_session.establish(peer_secret.as_bytes()).unwrap();

                let encrypted = client_session.encrypt(&payload).unwrap();
                
                // First time ok
                prop_assert!(server_session.decrypt(&encrypted).is_ok());
                
                // Second time (replay) should fail
                prop_assert!(server_session.decrypt(&encrypted).is_err());
            }
        }
    }
}