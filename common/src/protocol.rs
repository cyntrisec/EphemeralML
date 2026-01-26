//! Protocol message format for Confidential Inference Gateway
//! 
//! This module implements the v1 protocol message format with fixed version 1,
//! ClientHello/ServerHello handshake, and canonical message framing.

use crate::error::{EphemeralError, Result};
use serde::{Deserialize, Serialize};

/// Protocol version - fixed to 1 for v1
pub const PROTOCOL_VERSION_V1: u32 = 1;

/// Maximum supported features in handshake
pub const MAX_FEATURES: usize = 16;

/// Maximum client ID length
pub const MAX_CLIENT_ID_LENGTH: usize = 256;

/// Maximum model ID length  
pub const MAX_MODEL_ID_LENGTH: usize = 256;

/// ClientHello message for handshake initiation
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ClientHello {
    /// Protocol version - fixed to 1 for v1
    pub version: u32,
    /// Supported optional features
    pub supported_features: Vec<String>,
    /// Client nonce for freshness
    pub client_nonce: [u8; 12],
    /// Client identifier
    pub client_id: String,
    /// Ephemeral public key for HPKE
    pub ephemeral_public_key: [u8; 32],
    /// Timestamp for freshness tracking
    pub timestamp: u64,
}

impl ClientHello {
    /// Create new ClientHello with v1 protocol
    pub fn new(client_id: String, supported_features: Vec<String>, ephemeral_public_key: [u8; 32]) -> Result<Self> {
        if client_id.len() > MAX_CLIENT_ID_LENGTH {
            return Err(EphemeralError::InvalidInput(
                format!("Client ID too long: {} > {}", client_id.len(), MAX_CLIENT_ID_LENGTH)
            ));
        }
        
        if supported_features.len() > MAX_FEATURES {
            return Err(EphemeralError::InvalidInput(
                format!("Too many features: {} > {}", supported_features.len(), MAX_FEATURES)
            ));
        }
        
        Ok(Self {
            version: PROTOCOL_VERSION_V1,
            supported_features,
            client_nonce: crate::generate_nonce(),
            client_id,
            ephemeral_public_key,
            timestamp: crate::current_timestamp(),
        })
    }
    
    /// Validate ClientHello message
    pub fn validate(&self) -> Result<()> {
        if self.version != PROTOCOL_VERSION_V1 {
            return Err(EphemeralError::ProtocolError(
                format!("Unsupported protocol version: {}. Only version 1 is supported.", self.version)
            ));
        }
        
        if self.client_id.len() > MAX_CLIENT_ID_LENGTH {
            return Err(EphemeralError::InvalidInput(
                format!("Client ID too long: {}", self.client_id.len())
            ));
        }
        
        if self.supported_features.len() > MAX_FEATURES {
            return Err(EphemeralError::InvalidInput(
                format!("Too many features: {}", self.supported_features.len())
            ));
        }
        
        // Validate feature names (alphanumeric + hyphens only)
        for feature in &self.supported_features {
            if !feature.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                return Err(EphemeralError::InvalidInput(
                    format!("Invalid feature name: {}", feature)
                ));
            }
        }
        
        Ok(())
    }
}

/// ServerHello message for handshake response
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ServerHello {
    /// Protocol version - fixed to 1 for v1
    pub version: u32,
    /// Chosen features from client's supported list
    pub chosen_features: Vec<String>,
    /// Attestation document (CBOR-encoded)
    pub attestation_document: Vec<u8>,
    /// Ephemeral public key for HPKE
    pub ephemeral_public_key: Vec<u8>,
    /// Receipt signing public key
    pub receipt_signing_key: Vec<u8>,
    /// Server timestamp
    pub timestamp: u64,
}

impl ServerHello {
    /// Create new ServerHello with v1 protocol
    pub fn new(
        chosen_features: Vec<String>,
        attestation_document: Vec<u8>,
        ephemeral_public_key: Vec<u8>,
        receipt_signing_key: Vec<u8>,
    ) -> Result<Self> {
        if chosen_features.len() > MAX_FEATURES {
            return Err(EphemeralError::InvalidInput(
                format!("Too many chosen features: {}", chosen_features.len())
            ));
        }
        
        if ephemeral_public_key.len() != 32 {
            return Err(EphemeralError::InvalidInput(
                format!("Invalid ephemeral public key length: {}", ephemeral_public_key.len())
            ));
        }
        
        if receipt_signing_key.len() != 32 {
            return Err(EphemeralError::InvalidInput(
                format!("Invalid receipt signing key length: {}", receipt_signing_key.len())
            ));
        }

        Ok(Self {
            version: PROTOCOL_VERSION_V1,
            chosen_features,
            attestation_document,
            ephemeral_public_key,
            receipt_signing_key,
            timestamp: crate::current_timestamp(),
        })
    }

    /// Validate ServerHello message
    pub fn validate(&self) -> Result<()> {
        if self.version != PROTOCOL_VERSION_V1 {
             return Err(EphemeralError::ProtocolError(
                format!("Unsupported protocol version: {}. Only version 1 is supported.", self.version)
            ));
        }
        
        if self.chosen_features.len() > MAX_FEATURES {
             return Err(EphemeralError::InvalidInput(
                format!("Too many features: {}", self.chosen_features.len())
            ));
        }
        
        if self.ephemeral_public_key.len() != 32 {
             return Err(EphemeralError::InvalidInput("Invalid ephemeral public key length".to_string()));
        }
        
        if self.receipt_signing_key.len() != 32 {
             return Err(EphemeralError::InvalidInput("Invalid receipt signing key length".to_string()));
        }
        
        Ok(())
    }
}