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
