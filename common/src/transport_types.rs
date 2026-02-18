//! Bridge types for cml-transport integration
//!
//! Contains `EphemeralUserData` for attestation user_data,
//! `ConnectionState` for per-session metadata, and `simple_frame`
//! for KMS/Storage/Audit framing (non-inference channels).

use crate::error::{EphemeralError, Result};
use crate::receipt_signing::ReceiptSigningKey;
use serde::{Deserialize, Serialize};

/// Application-level user data embedded in attestation documents.
///
/// Serialized as CBOR and passed as `user_data` to cml-transport's
/// `AttestationProvider::attest()`. The HPKE public key is handled
/// separately by cml-transport via the `public_key` parameter.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EphemeralUserData {
    /// Ed25519 public key for receipt signature verification
    pub receipt_signing_key: [u8; 32],
    /// Protocol version for compatibility
    pub protocol_version: u32,
    /// Supported features for negotiation
    pub supported_features: Vec<String>,
    /// RSA public key for KMS key wrapping (DER-encoded, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_public_key: Option<Vec<u8>>,
}

impl EphemeralUserData {
    pub fn new(
        receipt_signing_key: [u8; 32],
        protocol_version: u32,
        supported_features: Vec<String>,
    ) -> Self {
        Self {
            receipt_signing_key,
            protocol_version,
            supported_features,
            kms_public_key: None,
        }
    }

    pub fn with_kms_key(mut self, kms_public_key: Vec<u8>) -> Self {
        self.kms_public_key = Some(kms_public_key);
        self
    }

    /// Serialize to CBOR for embedding in attestation document
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        crate::cbor::to_vec(self)
            .map_err(|e| EphemeralError::SerializationError(format!("CBOR encoding failed: {}", e)))
    }

    /// Deserialize from CBOR attestation user data
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        crate::cbor::from_slice(data)
            .map_err(|e| EphemeralError::SerializationError(format!("CBOR decoding failed: {}", e)))
    }
}

/// Confidential Space transport attestation envelope.
///
/// Carries a Launcher JWT (hardware-backed by Confidential Space) plus
/// application-level binding data for the SecureChannel handshake.
/// Unlike `TeeAttestationEnvelope` (which wraps raw TDX quotes from configfs-tsm),
/// this envelope uses the Launcher JWT as the attestation root — no configfs-tsm needed.
///
/// Encoded as deterministic CBOR (sorted map keys) for consistent hashing.
///
/// Wire format (CBOR map):
/// ```text
/// {
///   "handshake_public_key": <32 bytes>,   // X25519 DH key from SecureChannel handshake
///   "launcher_jwt": "<OIDC JWT string>",  // Confidential Space Launcher token
///   "nonce": <bytes>,                     // Handshake nonce (binds attestation to session)
///   "platform": "cs-tdx",                // Platform identifier
///   "protocol_version": 1,               // Protocol version
///   "receipt_signing_key": <32 bytes>,    // Ed25519 public key for receipt verification
/// }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CsTransportAttestation {
    /// Platform identifier. Must be "cs-tdx" for Confidential Space TDX.
    pub platform: String,

    /// Launcher JWT (OIDC token from Confidential Space).
    /// Contains claims: eat_nonce, submods.container.image_digest,
    /// submods.container.image_reference, etc.
    pub launcher_jwt: String,

    /// Ed25519 public key for receipt signature verification (32 bytes).
    #[serde(with = "serde_bytes")]
    pub receipt_signing_key: Vec<u8>,

    /// X25519 public key from the SecureChannel handshake (32 bytes).
    /// Binds this attestation to a specific handshake session.
    #[serde(with = "serde_bytes")]
    pub handshake_public_key: Vec<u8>,

    /// Nonce from the handshake protocol (binds attestation to session).
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,

    /// Protocol version for forward compatibility.
    pub protocol_version: u32,
}

/// Expected platform string for Confidential Space TDX attestation envelopes.
pub const CS_TDX_PLATFORM: &str = "cs-tdx";

impl CsTransportAttestation {
    /// Create a new CS transport attestation envelope.
    ///
    /// # Arguments
    /// * `launcher_jwt` — Launcher JWT from Confidential Space
    /// * `receipt_signing_key` — Ed25519 public key (32 bytes)
    /// * `handshake_public_key` — X25519 DH key from handshake (32 bytes)
    /// * `nonce` — Handshake nonce
    pub fn new(
        launcher_jwt: String,
        receipt_signing_key: [u8; 32],
        handshake_public_key: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Self {
            platform: CS_TDX_PLATFORM.to_string(),
            launcher_jwt,
            receipt_signing_key: receipt_signing_key.to_vec(),
            handshake_public_key,
            nonce,
            protocol_version: 1,
        }
    }

    /// Encode as deterministic CBOR (sorted map keys for consistent hashing).
    pub fn to_cbor_deterministic(&self) -> Result<Vec<u8>> {
        let value = crate::cbor::to_value(self).map_err(|e| {
            EphemeralError::SerializationError(format!(
                "CsTransportAttestation CBOR value conversion failed: {}",
                e
            ))
        })?;
        crate::cbor::to_vec(&value).map_err(|e| {
            EphemeralError::SerializationError(format!(
                "CsTransportAttestation CBOR encoding failed: {}",
                e
            ))
        })
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        crate::cbor::from_slice(data).map_err(|e| {
            EphemeralError::SerializationError(format!(
                "CsTransportAttestation CBOR decoding failed: {}",
                e
            ))
        })
    }

    /// Compute SHA-256 hash of the deterministic CBOR encoding.
    /// Used for attestation_hash in receipts and handshake transcript binding.
    pub fn document_hash(&self) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let cbor = self.to_cbor_deterministic()?;
        Ok(Sha256::digest(&cbor).into())
    }

    /// Validate the envelope structure (does NOT verify the JWT signature).
    /// Returns an error if any field has an invalid length or value.
    pub fn validate_structure(&self) -> Result<()> {
        if self.platform != CS_TDX_PLATFORM {
            return Err(EphemeralError::AttestationError(format!(
                "Invalid platform '{}', expected '{}'",
                self.platform, CS_TDX_PLATFORM
            )));
        }
        if self.launcher_jwt.is_empty() {
            return Err(EphemeralError::AttestationError(
                "launcher_jwt is empty".to_string(),
            ));
        }
        // Basic JWT structure check: must have 3 dot-separated parts
        if self.launcher_jwt.split('.').count() != 3 {
            return Err(EphemeralError::AttestationError(
                "launcher_jwt is not a valid JWT (expected 3 dot-separated parts)".to_string(),
            ));
        }
        if self.receipt_signing_key.len() != 32 {
            return Err(EphemeralError::AttestationError(format!(
                "receipt_signing_key must be 32 bytes, got {}",
                self.receipt_signing_key.len()
            )));
        }
        if self.handshake_public_key.len() != 32 {
            return Err(EphemeralError::AttestationError(format!(
                "handshake_public_key must be 32 bytes, got {}",
                self.handshake_public_key.len()
            )));
        }
        if self.nonce.is_empty() {
            return Err(EphemeralError::AttestationError(
                "nonce is empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// Per-connection session metadata.
///
/// Replaces `EnclaveSession` — the `SecureChannel` handles encryption,
/// so `ConnectionState` only tracks application-level state.
pub struct ConnectionState {
    /// Session identifier (hex-encoded SHA-256 of handshake transcript)
    pub session_id: String,
    /// Ed25519 receipt signing key for this session
    pub receipt_signing_key: ReceiptSigningKey,
    /// SHA-256 hash of the attestation document
    pub attestation_hash: [u8; 32],
    /// Client identifier
    pub client_id: String,
    /// Monotonic sequence number for receipts
    pub next_sequence: u64,
    /// Model being served in this session
    pub model_id: String,
    /// Protocol version negotiated
    pub protocol_version: u32,
}

impl ConnectionState {
    pub fn new(
        session_id: String,
        receipt_signing_key: ReceiptSigningKey,
        attestation_hash: [u8; 32],
        client_id: String,
        protocol_version: u32,
    ) -> Self {
        Self {
            session_id,
            receipt_signing_key,
            attestation_hash,
            client_id,
            next_sequence: 0,
            model_id: String::new(),
            protocol_version,
        }
    }

    /// Increment and return the current sequence number
    pub fn next_seq(&mut self) -> u64 {
        let seq = self.next_sequence;
        self.next_sequence += 1;
        seq
    }
}

/// Simple length-prefixed framing for non-inference channels (KMS, Storage, Audit).
///
/// Wire format: `[4-byte BE length][1-byte tag][payload]`
/// where `length` covers `tag + payload`.
pub mod simple_frame {
    use crate::error::{EphemeralError, Result};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub const TAG_KMS: u8 = 0x01;
    pub const TAG_STORAGE: u8 = 0x02;
    pub const TAG_AUDIT: u8 = 0x03;

    /// Maximum frame size (32 MB, matching cml-transport)
    pub const MAX_FRAME_SIZE: u32 = 32 * 1024 * 1024;

    /// Write a tagged frame to an async writer.
    pub async fn write_frame<W: AsyncWriteExt + Unpin>(
        writer: &mut W,
        tag: u8,
        payload: &[u8],
    ) -> Result<()> {
        let total_len = 1u32 + payload.len() as u32;
        if total_len > MAX_FRAME_SIZE {
            return Err(EphemeralError::CommunicationError(format!(
                "Frame too large: {} bytes (max {})",
                total_len, MAX_FRAME_SIZE
            )));
        }
        writer.write_all(&total_len.to_be_bytes()).await?;
        writer.write_all(&[tag]).await?;
        writer.write_all(payload).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Read a tagged frame from an async reader. Returns `(tag, payload)`.
    pub async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<(u8, Vec<u8>)> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf);

        if total_len == 0 {
            return Err(EphemeralError::CommunicationError(
                "Empty frame".to_string(),
            ));
        }
        if total_len > MAX_FRAME_SIZE {
            return Err(EphemeralError::CommunicationError(format!(
                "Frame too large: {} bytes (max {})",
                total_len, MAX_FRAME_SIZE
            )));
        }

        let mut tag_buf = [0u8; 1];
        reader.read_exact(&mut tag_buf).await?;
        let tag = tag_buf[0];

        let payload_len = (total_len - 1) as usize;
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            reader.read_exact(&mut payload).await?;
        }

        Ok((tag, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_user_data_roundtrip() {
        let data = EphemeralUserData::new([1u8; 32], 1, vec!["feature1".to_string()]);
        let cbor = data.to_cbor().unwrap();
        let decoded = EphemeralUserData::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.receipt_signing_key, [1u8; 32]);
        assert_eq!(decoded.protocol_version, 1);
        assert_eq!(decoded.supported_features, vec!["feature1".to_string()]);
        assert!(decoded.kms_public_key.is_none());
    }

    #[test]
    fn test_ephemeral_user_data_with_kms() {
        let data = EphemeralUserData::new([2u8; 32], 1, vec![]).with_kms_key(vec![0xAA; 128]);
        let cbor = data.to_cbor().unwrap();
        let decoded = EphemeralUserData::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.kms_public_key.unwrap().len(), 128);
    }

    #[test]
    fn test_connection_state_sequence() {
        let key = ReceiptSigningKey::generate().unwrap();
        let mut state = ConnectionState::new(
            "session-1".to_string(),
            key,
            [0u8; 32],
            "client-1".to_string(),
            1,
        );
        assert_eq!(state.next_seq(), 0);
        assert_eq!(state.next_seq(), 1);
        assert_eq!(state.next_seq(), 2);
    }

    fn make_test_jwt() -> String {
        // Minimal valid JWT structure (3 dot-separated base64 parts)
        "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2NvbmZpZGVudGlhbGNvbXB1dGluZy5nb29nbGVhcGlzLmNvbSJ9.signature".to_string()
    }

    #[test]
    fn test_cs_transport_attestation_roundtrip() {
        let att = CsTransportAttestation::new(
            make_test_jwt(),
            [0xAA; 32],
            vec![0xBB; 32],
            vec![0xCC; 16],
        );
        let cbor = att.to_cbor_deterministic().unwrap();
        let decoded = CsTransportAttestation::from_cbor(&cbor).unwrap();
        assert_eq!(att, decoded);
    }

    #[test]
    fn test_cs_transport_attestation_deterministic_encoding() {
        let att = CsTransportAttestation::new(
            make_test_jwt(),
            [0x11; 32],
            vec![0x22; 32],
            vec![0x33; 8],
        );
        // Encode twice — must produce identical bytes
        let cbor1 = att.to_cbor_deterministic().unwrap();
        let cbor2 = att.to_cbor_deterministic().unwrap();
        assert_eq!(cbor1, cbor2, "deterministic CBOR must be identical across calls");

        // Hash must also be deterministic
        let hash1 = att.document_hash().unwrap();
        let hash2 = att.document_hash().unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_cs_transport_attestation_validate_structure() {
        let valid = CsTransportAttestation::new(
            make_test_jwt(),
            [0xAA; 32],
            vec![0xBB; 32],
            vec![0xCC; 16],
        );
        valid.validate_structure().unwrap();

        // Wrong platform
        let mut bad = valid.clone();
        bad.platform = "tdx".to_string();
        assert!(bad.validate_structure().is_err());

        // Empty JWT
        let mut bad = valid.clone();
        bad.launcher_jwt = String::new();
        assert!(bad.validate_structure().is_err());

        // Invalid JWT structure (no dots)
        let mut bad = valid.clone();
        bad.launcher_jwt = "not-a-jwt".to_string();
        assert!(bad.validate_structure().is_err());

        // Wrong key size
        let mut bad = valid.clone();
        bad.receipt_signing_key = vec![0; 16];
        assert!(bad.validate_structure().is_err());

        // Wrong handshake key size
        let mut bad = valid.clone();
        bad.handshake_public_key = vec![0; 16];
        assert!(bad.validate_structure().is_err());

        // Empty nonce
        let mut bad = valid.clone();
        bad.nonce = vec![];
        assert!(bad.validate_structure().is_err());
    }

    #[test]
    fn test_cs_transport_attestation_hash_changes_with_content() {
        let att1 = CsTransportAttestation::new(
            make_test_jwt(),
            [0xAA; 32],
            vec![0xBB; 32],
            vec![0xCC; 16],
        );
        let att2 = CsTransportAttestation::new(
            make_test_jwt(),
            [0xAA; 32],
            vec![0xBB; 32],
            vec![0xDD; 16], // different nonce
        );
        assert_ne!(att1.document_hash().unwrap(), att2.document_hash().unwrap());
    }

    #[test]
    fn test_cs_transport_attestation_from_cbor_garbage() {
        // Random non-CBOR bytes should fail cleanly
        let result = CsTransportAttestation::from_cbor(&[0xFF, 0xFE, 0xFD]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cs_transport_attestation_from_cbor_empty() {
        let result = CsTransportAttestation::from_cbor(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cs_transport_attestation_from_cbor_wrong_type() {
        // Valid CBOR but an integer, not a map
        let cbor = crate::cbor::to_vec(&ciborium::Value::Integer(42.into())).unwrap();
        let result = CsTransportAttestation::from_cbor(&cbor);
        assert!(result.is_err());
    }

    #[test]
    fn test_cs_transport_attestation_validate_two_part_jwt() {
        // JWT with only 2 parts (missing signature)
        let att = CsTransportAttestation::new(
            "header.payload".to_string(),
            [0xAA; 32],
            vec![0xBB; 32],
            vec![0xCC; 16],
        );
        assert!(att.validate_structure().is_err());
    }

    #[test]
    fn test_cs_transport_attestation_validate_four_part_jwt() {
        // JWT with 4 parts (extra section)
        let att = CsTransportAttestation::new(
            "a.b.c.d".to_string(),
            [0xAA; 32],
            vec![0xBB; 32],
            vec![0xCC; 16],
        );
        assert!(att.validate_structure().is_err());
    }

    #[tokio::test]
    async fn test_simple_frame_roundtrip() {
        use simple_frame::*;

        let (mut client, mut server) = tokio::io::duplex(4096);

        let payload = b"hello world";
        write_frame(&mut client, TAG_KMS, payload).await.unwrap();

        let (tag, data) = read_frame(&mut server).await.unwrap();
        assert_eq!(tag, TAG_KMS);
        assert_eq!(data, payload);
    }
}
