use crate::{EphemeralError, Result};
use byteorder::{BigEndian, ByteOrder};

/// Maximum message size (1GB) to prevent DoS while allowing model weights
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 1024;

/// VSock protocol message type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Handshake / Hello
    Hello = 0x01,
    /// Encrypted data payload
    Data = 0x02,
    /// Error notification
    Error = 0x03,
    /// Keepalive / Heartbeat
    Heartbeat = 0x04,
    /// Shutdown signal
    Shutdown = 0x05,
    /// KMS Proxy traffic
    KmsProxy = 0x06,
    /// Storage (S3) traffic
    Storage = 0x07,
    /// Audit Log traffic
    Audit = 0x08,
    /// Encrypted ping (echo round-trip)
    Ping = 0x09,
}

impl TryFrom<u8> for MessageType {
    type Error = EphemeralError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(MessageType::Hello),
            0x02 => Ok(MessageType::Data),
            0x03 => Ok(MessageType::Error),
            0x04 => Ok(MessageType::Heartbeat),
            0x05 => Ok(MessageType::Shutdown),
            0x06 => Ok(MessageType::KmsProxy),
            0x07 => Ok(MessageType::Storage),
            0x08 => Ok(MessageType::Audit),
            0x09 => Ok(MessageType::Ping),
            _ => Err(EphemeralError::Validation(
                crate::ValidationError::InvalidFormat(format!(
                    "Unknown message type: 0x{:02x}",
                    value
                )),
            )),
        }
    }
}

/// Structured VSock message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VSockMessage {
    /// Type of the message
    pub msg_type: MessageType,
    /// Sequence number for reliable ordering
    pub sequence: u32,
    /// Payload data
    pub payload: Vec<u8>,
}

impl VSockMessage {
    pub fn new(msg_type: MessageType, sequence: u32, payload: Vec<u8>) -> Result<Self> {
        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(EphemeralError::Validation(
                crate::ValidationError::SizeLimitExceeded(format!(
                    "Payload size {} exceeds maximum {}",
                    payload.len(),
                    MAX_MESSAGE_SIZE
                )),
            ));
        }
        Ok(Self {
            msg_type,
            sequence,
            payload,
        })
    }

    /// Encode the message into a byte vector for wire transmission
    /// Format: [Length: u32][Type: u8][Sequence: u32][Payload: bytes]
    pub fn encode(&self) -> Vec<u8> {
        let total_len = 1 + 4 + self.payload.len(); // Type (1) + Seq (4) + Payload (N)
        let mut buffer = Vec::with_capacity(4 + total_len);

        // Write total length (excluding the length prefix itself)
        let mut len_buf = [0u8; 4];
        BigEndian::write_u32(&mut len_buf, total_len as u32);
        buffer.extend_from_slice(&len_buf);

        // Write type
        buffer.push(self.msg_type as u8);

        // Write sequence
        let mut seq_buf = [0u8; 4];
        BigEndian::write_u32(&mut seq_buf, self.sequence);
        buffer.extend_from_slice(&seq_buf);

        // Write payload
        buffer.extend_from_slice(&self.payload);

        buffer
    }

    /// Decode a message from a byte buffer
    /// Expects the buffer to contain the full frame including length prefix
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(EphemeralError::Validation(
                crate::ValidationError::InvalidFormat(
                    "Buffer too short for length prefix".to_string(),
                ),
            ));
        }

        let total_len = BigEndian::read_u32(&data[0..4]) as usize;
        if data.len() < 4 + total_len {
            return Err(EphemeralError::Validation(
                crate::ValidationError::InvalidFormat(format!(
                    "Incomplete frame. Expected {} bytes, got {}",
                    4 + total_len,
                    data.len()
                )),
            ));
        }

        let frame_data = &data[4..4 + total_len];
        if frame_data.len() < 5 {
            // Type (1) + Seq (4)
            return Err(EphemeralError::Validation(
                crate::ValidationError::InvalidFormat("Frame too short for header".to_string()),
            ));
        }

        let msg_type = MessageType::try_from(frame_data[0])?;
        let sequence = BigEndian::read_u32(&frame_data[1..5]);
        let payload = frame_data[5..].to_vec();

        // Check payload size again just in case
        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(EphemeralError::Validation(
                crate::ValidationError::SizeLimitExceeded(format!(
                    "Payload size {} exceeds maximum {}",
                    payload.len(),
                    MAX_MESSAGE_SIZE
                )),
            ));
        }

        Ok(Self {
            msg_type,
            sequence,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsock_encoding_roundtrip() {
        let payload = vec![1, 2, 3, 4, 5];
        let msg = VSockMessage::new(MessageType::Data, 42, payload.clone()).unwrap();

        let encoded = msg.encode();
        let decoded = VSockMessage::decode(&encoded).unwrap();

        assert_eq!(msg, decoded);
        assert_eq!(decoded.msg_type, MessageType::Data);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_message_size_limit() {
        let big_payload = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let result = VSockMessage::new(MessageType::Data, 1, big_payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_type() {
        // [Length: 5][Type: 0xFF][Seq: 0][Payload: empty]
        let data = vec![0, 0, 0, 5, 0xFF, 0, 0, 0, 0];
        let result = VSockMessage::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_header() {
        // Only 3 bytes of length prefix
        let data = vec![0, 0, 1];
        assert!(VSockMessage::decode(&data).is_err());

        // Only 4 bytes of length prefix (total_len = 5) but missing body
        let data = vec![0, 0, 0, 5];
        assert!(VSockMessage::decode(&data).is_err());
    }

    #[test]
    fn test_zero_length_prefix() {
        // total_len = 0
        let data = vec![0, 0, 0, 0];
        let result = VSockMessage::decode(&data);
        assert!(result.is_err());
        assert!(format!("{:?}", result.err().unwrap()).contains("Frame too short for header"));
    }

    #[test]
    fn test_huge_length_claimed() {
        // Claim 16MB but give 10 bytes
        let mut data = vec![0u8; 10];
        BigEndian::write_u32(&mut data[0..4], 16 * 1024 * 1024);
        assert!(VSockMessage::decode(&data).is_err());
    }

    #[test]
    fn test_length_exceeds_max() {
        // Claim MAX + 1
        let mut data = vec![0u8; 100];
        BigEndian::write_u32(&mut data[0..4], (MAX_MESSAGE_SIZE + 1) as u32);
        // It might fail either at data.len() check or at MAX_MESSAGE_SIZE check if data was provided.
        // If we provide 100 bytes but claim huge, it fails data.len() check first.
        assert!(VSockMessage::decode(&data).is_err());
    }
}
