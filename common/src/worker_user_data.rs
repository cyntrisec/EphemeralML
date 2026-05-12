//! Cyntrisec worker identity embedded in TEE attestation `user_data`.
//!
//! `confidential-ml-transport` verifies the generic TEE channel and exposes
//! opaque attestation `user_data` bytes. This module defines Cyntrisec's
//! product-level meaning for those bytes: which receipt key, model id, and
//! model hash the worker binds into the attested channel.
//!
//! Wire format v1 is deterministic CBOR array:
//! `[schema_version, receipt_signing_pubkey, model_id, model_hash]`.

use serde::{Deserialize, Serialize};

use crate::error::{EphemeralError, Result};

pub const WORKER_ATTESTATION_USER_DATA_V1: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerAttestationUserData {
    pub schema_version: u8,
    pub receipt_signing_pubkey: [u8; 32],
    pub model_id: String,
    pub model_hash: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkerAttestationUserDataWire(
    u8,
    #[serde(with = "serde_bytes")] Vec<u8>,
    String,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

impl WorkerAttestationUserData {
    pub fn new(
        receipt_signing_pubkey: [u8; 32],
        model_id: impl Into<String>,
        model_hash: [u8; 32],
    ) -> Self {
        Self {
            schema_version: WORKER_ATTESTATION_USER_DATA_V1,
            receipt_signing_pubkey,
            model_id: model_id.into(),
            model_hash,
        }
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        if self.schema_version != WORKER_ATTESTATION_USER_DATA_V1 {
            return Err(EphemeralError::AttestationError(format!(
                "unsupported WorkerAttestationUserData schema_version: {}",
                self.schema_version
            )));
        }

        let wire = WorkerAttestationUserDataWire(
            self.schema_version,
            self.receipt_signing_pubkey.to_vec(),
            self.model_id.clone(),
            self.model_hash.to_vec(),
        );
        crate::cbor::to_vec(&wire).map_err(|e| {
            EphemeralError::SerializationError(format!(
                "WorkerAttestationUserData CBOR encoding failed: {}",
                e
            ))
        })
    }

    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        let wire: WorkerAttestationUserDataWire = crate::cbor::from_slice(data).map_err(|e| {
            EphemeralError::SerializationError(format!(
                "WorkerAttestationUserData CBOR decoding failed: {}",
                e
            ))
        })?;

        if wire.0 != WORKER_ATTESTATION_USER_DATA_V1 {
            return Err(EphemeralError::AttestationError(format!(
                "unsupported WorkerAttestationUserData schema_version: {}",
                wire.0
            )));
        }

        Ok(Self {
            schema_version: wire.0,
            receipt_signing_pubkey: fixed_32("receipt_signing_pubkey", wire.1)?,
            model_id: wire.2,
            model_hash: fixed_32("model_hash", wire.3)?,
        })
    }
}

fn fixed_32(label: &str, bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        EphemeralError::AttestationError(format!("{label} must be 32 bytes, got {}", bytes.len()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WorkerAttestationUserData {
        WorkerAttestationUserData::new([0x11; 32], "llama-3.1-8b", [0x22; 32])
    }

    #[test]
    fn worker_user_data_roundtrips() {
        let encoded = sample().to_cbor().unwrap();
        let decoded = WorkerAttestationUserData::from_cbor(&encoded).unwrap();

        assert_eq!(decoded.schema_version, WORKER_ATTESTATION_USER_DATA_V1);
        assert_eq!(decoded.receipt_signing_pubkey, [0x11; 32]);
        assert_eq!(decoded.model_id, "llama-3.1-8b");
        assert_eq!(decoded.model_hash, [0x22; 32]);
    }

    #[test]
    fn worker_user_data_encoding_is_deterministic_and_version_first() {
        let first = sample().to_cbor().unwrap();
        let second = sample().to_cbor().unwrap();

        assert_eq!(first, second);
        assert_eq!(first[0], 0x84); // CBOR array of 4 items.
        assert_eq!(first[1], WORKER_ATTESTATION_USER_DATA_V1);
    }

    #[test]
    fn worker_user_data_rejects_unknown_schema_version() {
        let mut encoded = sample().to_cbor().unwrap();
        encoded[1] = 2;

        let err = WorkerAttestationUserData::from_cbor(&encoded).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported WorkerAttestationUserData schema_version: 2"));
    }

    #[test]
    fn worker_user_data_rejects_wrong_key_lengths() {
        let bad = WorkerAttestationUserDataWire(
            WORKER_ATTESTATION_USER_DATA_V1,
            vec![0u8; 31],
            "model".to_string(),
            vec![0u8; 32],
        );
        let encoded = crate::cbor::to_vec(&bad).unwrap();

        let err = WorkerAttestationUserData::from_cbor(&encoded).unwrap_err();
        assert!(err
            .to_string()
            .contains("receipt_signing_pubkey must be 32 bytes, got 31"));
    }
}
